//! `sm` — a minimal terminal session manager, a from-scratch Rust
//! reimplementation of abduco. One binary is both the client and the daemonized
//! server; see the module docs for the split.

mod cli;
mod client;
mod protocol;
mod pty;
mod server;
mod signals;
mod sockdir;
mod sys;
mod term;

use std::ffi::CString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

use cli::{Action, Cli, Command, ListFormat, SessionArgs};
use client::{AttachOptions, Connection, Liveness, Outcome};
use server::ServerConfig;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let cli = match cli::parse(std::env::args().skip(1)) {
        Ok(cli) => cli,
        Err(msg) => {
            eprintln!("sm: {msg}");
            eprintln!("{}", cli::USAGE);
            exit(1);
        }
    };
    let code = run(&cli).unwrap_or_else(|msg| {
        eprintln!("sm: {msg}");
        1
    });
    exit(code);
}

/// Carry out the invocation; returns the process exit code, or an error
/// message for the user.
fn run(cli: &Cli) -> Result<i32, String> {
    match &cli.command {
        Command::Version => {
            println!("sm {VERSION} — a Rust reimplementation of abduco");
            Ok(0)
        }
        Command::List(format) => list(*format),
        Command::Kill { name } => kill(name, cli.quiet),
        Command::Rename { from, to } => rename(from, to, cli.quiet),
        Command::Session(args) => session(args, cli.quiet),
    }
}

fn session(args: &SessionArgs, quiet: bool) -> Result<i32, String> {
    let name = &args.name;
    let dir = socket_dir()?;
    let path = sockdir::socket_path(&dir, name).map_err(|e| e.to_string())?;

    match args.action {
        Action::Attach => attach(&path, name, &args.attach, quiet),
        Action::AttachOrCreate => match client::probe(&path) {
            Liveness::Alive { .. } => attach(&path, name, &args.attach, quiet),
            Liveness::Unresponsive(e) => Err(cannot_connect(name, &e)),
            Liveness::Dead => {
                // Nothing is listening, so any socket file there is stale.
                remove_stale_socket(&path)?;
                create(args, &path, quiet)
            }
        },
        Action::Create | Action::CreateDetached => match client::probe(&path) {
            Liveness::Alive { .. } => Err(format!("session already exists: {name}")),
            Liveness::Unresponsive(e) => Err(cannot_connect(name, &e)),
            Liveness::Dead => {
                if path.symlink_metadata().is_ok() {
                    if !args.force {
                        return Err(format!(
                            "stale session '{name}' exists; use -f to replace it"
                        ));
                    }
                    remove_stale_socket(&path)?;
                }
                create(args, &path, quiet)
            }
        },
    }
}

fn attach(path: &Path, name: &str, opts: &AttachOptions, quiet: bool) -> Result<i32, String> {
    run_attached(connect(path, name)?, opts, quiet)
}

fn run_attached(conn: Connection, opts: &AttachOptions, quiet: bool) -> Result<i32, String> {
    match conn.attach(opts) {
        Ok(Outcome::Detached) => {
            if !quiet {
                eprintln!("sm: detached");
            }
            Ok(0)
        }
        Ok(Outcome::Displaced) => {
            if !quiet {
                eprintln!("sm: detached (session attached elsewhere with -d)");
            }
            Ok(0)
        }
        Ok(Outcome::Exited(status)) => Ok(status),
        Err(e) => Err(format!("attach failed: {e}")),
    }
}

/// End a session: `sm -k name`. Returns once it has ended.
fn kill(name: &str, quiet: bool) -> Result<i32, String> {
    let dir = socket_dir()?;
    let path = sockdir::socket_path(&dir, name).map_err(|e| e.to_string())?;
    connect(&path, name)?
        .kill()
        .map_err(|e| format!("kill failed: {e}"))?;
    if !quiet {
        eprintln!("sm: killed '{name}'");
    }
    Ok(0)
}

/// Rename an existing session: `sm -R oldname newname`.
fn rename(from: &str, to: &str, quiet: bool) -> Result<i32, String> {
    let dir = socket_dir()?;
    let path = sockdir::socket_path(&dir, from).map_err(|e| e.to_string())?;
    let new_path = sockdir::socket_path(&dir, to).map_err(|e| e.to_string())?;

    let conn = connect(&path, from)?;
    if from == to {
        return Ok(0);
    }
    match client::probe(&new_path) {
        Liveness::Alive { .. } => return Err(format!("a session named '{to}' already exists")),
        Liveness::Unresponsive(e) => return Err(cannot_connect(to, &e)),
        // Clear a stale socket so the name is free; the server's rename still
        // refuses to replace anything that appears there in the meantime.
        Liveness::Dead => remove_stale_socket(&new_path)?,
    }

    conn.rename(to).map_err(|e| format!("rename failed: {e}"))?;
    if !quiet {
        eprintln!("sm: renamed '{from}' -> '{to}'");
    }
    Ok(0)
}

/// Build the command vector: explicit CLI args, else $SM_CMD, else $SHELL, else /bin/sh.
fn resolve_command(args: &[String]) -> Vec<String> {
    if !args.is_empty() {
        return args.to_vec();
    }
    ["SM_CMD", "SHELL"]
        .into_iter()
        .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()))
        .map_or_else(|| vec!["/bin/sh".to_string()], |cmd| vec![cmd])
}

/// Create the session (daemonize + spawn the server) and, unless asked not to,
/// attach to it afterward. Returns the process exit code.
fn create(args: &SessionArgs, path: &Path, quiet: bool) -> Result<i32, String> {
    let argv = resolve_command(&args.command)
        .into_iter()
        .map(CString::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid command: arguments must not contain NUL bytes".to_string())?;

    // To attach, connect before the command starts rather than through the
    // socket afterwards, which a short-lived command could already have left.
    let (ours, creator) = if args.action == Action::CreateDetached {
        (None, None)
    } else {
        let (ours, theirs) =
            UnixStream::pair().map_err(|e| format!("cannot create connection: {e}"))?;
        (Some(ours), Some(theirs))
    };

    server::spawn(ServerConfig {
        socket_path: path.to_path_buf(),
        session_name: args.name.clone(),
        argv,
        // Start the pty matching the current terminal's size and modes.
        winsize: pty::get_winsize(libc::STDIN_FILENO),
        termios: term::current_termios(),
        workdir: std::env::current_dir().ok(),
        creator,
    })?;

    let Some(ours) = ours else {
        if !quiet {
            eprintln!("sm: session '{}' started", args.name);
        }
        return Ok(0);
    };
    let conn = Connection::establish(ours).map_err(|e| format!("attach failed: {e}"))?;
    run_attached(conn, &args.attach, quiet)
}

fn list(format: ListFormat) -> Result<i32, String> {
    let dir = socket_dir()?;
    let sessions =
        sockdir::list_sessions(&dir).map_err(|e| format!("cannot list sessions: {e}"))?;
    if sessions.is_empty() && format == ListFormat::Table {
        eprintln!("sm: no sessions");
        return Ok(0);
    }
    let mut out = io::stdout().lock();
    for s in sessions {
        // `*` attached, `-` detached, `?` stale or not responding.
        let (status, pid) = match client::probe(&s.path) {
            Liveness::Alive { pid } => (if s.attached { '*' } else { '-' }, pid.to_string()),
            Liveness::Unresponsive(_) | Liveness::Dead => ('?', "-".to_string()),
        };
        let written = match format {
            ListFormat::Table => {
                let when = s.mtime.map(format_time).unwrap_or_default();
                writeln!(out, "{status}  {:<20} {pid:>8}  {when}", s.name)
            }
            ListFormat::NulTerminated => write!(out, "{status} {}\0", s.name),
        };
        written.map_err(|e| format!("cannot write session list: {e}"))?;
    }
    out.flush()
        .map_err(|e| format!("cannot write session list: {e}"))?;
    Ok(0)
}

fn socket_dir() -> Result<std::path::PathBuf, String> {
    sockdir::resolve_socket_dir().map_err(|e| format!("cannot prepare socket directory: {e}"))
}

fn remove_stale_socket(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "cannot remove stale socket {}: {e}",
            path.display()
        )),
    }
}

/// Connect to the session `name` at `path`, with user-facing errors.
fn connect(path: &Path, name: &str) -> Result<Connection, String> {
    Connection::open(path).map_err(|e| {
        if client::is_absent(&e) {
            format!("no such session: {name}")
        } else {
            cannot_connect(name, &e)
        }
    })
}

fn cannot_connect(name: &str, err: &io::Error) -> String {
    format!("cannot connect to session '{name}': {err}")
}

fn format_time(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| {
        libc::time_t::try_from(d.as_secs()).unwrap_or(libc::time_t::MAX)
    });
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
        return String::new();
    }
    let mut buf = [0u8; 64];
    let n = unsafe {
        libc::strftime(
            buf.as_mut_ptr().cast(),
            buf.len(),
            c"%Y-%m-%d %H:%M:%S".as_ptr(),
            &tm,
        )
    };
    String::from_utf8_lossy(&buf[..n]).into_owned()
}
