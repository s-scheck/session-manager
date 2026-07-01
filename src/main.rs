//! `sm` — a minimal terminal session manager, a from-scratch Rust
//! reimplementation of abduco. One binary is both the client and the daemonized
//! server; see the module docs for the split.

mod client;
mod protocol;
mod pty;
mod server;
mod signals;
mod sockdir;
mod sys;
mod term;

use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::process::exit;

use nix::sys::wait::waitpid;
use nix::unistd::{ForkResult, chdir, fork, setsid};

use client::{ClientConfig, Outcome};
use server::ServerConfig;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_DETACH_KEY: u8 = 0x0f; // Ctrl-o (^o); easy to type on any layout

#[derive(Clone, Copy, PartialEq)]
enum Action {
    /// -a: attach to an existing session (error if absent).
    Attach,
    /// -A: attach if present, else create and attach.
    AttachOrCreate,
    /// -c: create a new session and attach.
    Create,
    /// -n: create a new session, do not attach.
    CreateNoAttach,
}

struct Options {
    action: Option<Action>,
    list: bool,
    force: bool,
    readonly: bool,
    lowpriority: bool,
    passthrough: bool,
    quiet: bool,
    detach_key: u8,
    name: Option<String>,
    command: Vec<String>,
}

fn main() {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("sm: {msg}");
            }
            usage();
            exit(1);
        }
    };
    exit(run(opts));
}

fn usage() {
    eprintln!(
        "usage: sm [-a|-A|-c|-n] [-p] [-r] [-q] [-l] [-L] [-f] [-e detachkey] name [command ...]\n\
         \x20      sm -l                     list sessions\n\
         \x20      sm -v                     print version"
    );
}

fn run(opts: Options) -> i32 {
    // Listing: explicit -l, or a bare invocation with nothing to act on.
    if opts.list || (opts.action.is_none() && opts.name.is_none()) {
        return do_list();
    }

    let name = match &opts.name {
        Some(n) => n.clone(),
        None => {
            eprintln!("sm: a session name is required");
            usage();
            return 1;
        }
    };

    // No explicit action but a name was given => attach-or-create (friendly default).
    let action = opts.action.unwrap_or(Action::AttachOrCreate);

    let dir = match sockdir::resolve_socket_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("sm: cannot prepare socket directory: {e}");
            return 1;
        }
    };
    let path = match sockdir::socket_path(&dir, &name) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sm: {e}");
            return 1;
        }
    };

    let alive = sockdir::session_alive(&path);

    match action {
        Action::Attach => {
            if !alive {
                eprintln!("sm: no such session: {name}");
                return 1;
            }
            attach(&opts, &path)
        }
        Action::AttachOrCreate => {
            if alive {
                attach(&opts, &path)
            } else {
                // Stale socket (if any) is safe to clear for attach-or-create.
                let _ = std::fs::remove_file(&path);
                create(&opts, &name, &path, true)
            }
        }
        Action::Create | Action::CreateNoAttach => {
            if alive {
                eprintln!("sm: session already exists: {name}");
                return 1;
            }
            if path.exists() {
                // A leftover socket from a dead server.
                if !opts.force {
                    eprintln!("sm: stale session '{name}' exists; use -f to replace it");
                    return 1;
                }
                let _ = std::fs::remove_file(&path);
            }
            create(&opts, &name, &path, action == Action::Create)
        }
    }
}

fn attach(opts: &Options, path: &Path) -> i32 {
    let cfg = ClientConfig {
        socket_path: path,
        readonly: opts.readonly,
        lowpriority: opts.lowpriority,
        detach_key: opts.detach_key,
        passthrough: opts.passthrough,
    };
    match client::attach(cfg) {
        Ok(Outcome::Detached) => {
            if !opts.quiet {
                eprintln!("sm: detached");
            }
            0
        }
        Ok(Outcome::Exited(status)) => status,
        Ok(Outcome::ServerGone) => {
            eprintln!("sm: session ended unexpectedly");
            1
        }
        Err(e) => {
            eprintln!("sm: attach failed: {e}");
            1
        }
    }
}

/// Build the command vector: explicit CLI args, else $SM_CMD, else $SHELL, else /bin/sh.
fn resolve_command(opts: &Options) -> Vec<String> {
    if !opts.command.is_empty() {
        return opts.command.clone();
    }
    if let Ok(cmd) = std::env::var("SM_CMD")
        && !cmd.is_empty()
    {
        return vec![cmd];
    }
    if let Ok(shell) = std::env::var("SHELL")
        && !shell.is_empty()
    {
        return vec![shell];
    }
    vec!["/bin/sh".to_string()]
}

/// Create the session (daemonize + spawn the server) and, if `do_attach`,
/// attach to it afterward. Returns the process exit code.
fn create(opts: &Options, name: &str, path: &Path, do_attach: bool) -> i32 {
    let command = resolve_command(opts);
    let argv: Result<Vec<CString>, _> = command.iter().map(|s| CString::new(s.as_str())).collect();
    let argv = match argv {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("sm: invalid command");
            return 1;
        }
    };

    // Capture the current terminal size and modes so the pty starts matching.
    let winsize = pty::get_winsize(libc::STDIN_FILENO);
    let termios = client::current_termios();

    let server_cfg = ServerConfig {
        socket_path: path.to_path_buf(),
        session_name: name.to_string(),
        argv,
        winsize,
        termios,
    };

    // Error-reporting pipe: the exec'd command's write end is CLOEXEC, so a
    // successful exec closes it (we read EOF => success); a failed exec writes a
    // message we relay to the user.
    let (err_read, err_write) = match nix::unistd::pipe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sm: pipe failed: {e}");
            return 1;
        }
    };
    set_cloexec(&err_write);

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Intermediate process: become a session leader, then fork the real
            // daemon so it can never re-acquire a controlling terminal.
            drop(err_read);
            let _ = setsid();
            match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    let _ = chdir("/");
                    server::run_server(server_cfg, err_write); // never returns
                }
                _ => exit(0), // intermediate parent exits immediately
            }
        }
        Ok(ForkResult::Parent { child }) => {
            drop(err_write);
            // Reap the short-lived intermediate child.
            let _ = waitpid(child, None);

            // Block until the server either execs the command (EOF) or reports
            // a startup error (message bytes).
            let mut msg = String::new();
            let mut reader = std::fs::File::from(err_read);
            let _ = reader.read_to_string(&mut msg);
            if !msg.is_empty() {
                eprintln!("sm: {msg}");
                return 1;
            }

            if do_attach {
                attach(opts, path)
            } else {
                if !opts.quiet {
                    eprintln!("sm: session '{name}' started");
                }
                0
            }
        }
        Err(e) => {
            eprintln!("sm: fork failed: {e}");
            1
        }
    }
}

fn do_list() -> i32 {
    let dir = match sockdir::resolve_socket_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("sm: cannot access socket directory: {e}");
            return 1;
        }
    };
    let sessions = match sockdir::list_sessions(&dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sm: cannot list sessions: {e}");
            return 1;
        }
    };
    if sessions.is_empty() {
        eprintln!("sm: no sessions");
        return 0;
    }
    for s in sessions {
        let pid = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());
        let when = s.mtime.map(format_time).unwrap_or_default();
        println!("{}  {:<20} {:>8}  {}", s.status, s.name, pid, when);
    }
    0
}

fn format_time(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as libc::time_t)
        .unwrap_or(0);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&secs, &mut tm) };
    let mut buf = [0u8; 64];
    let fmt = CString::new("%Y-%m-%d %H:%M:%S").unwrap();
    let n = unsafe { libc::strftime(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), &tm) };
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

fn set_cloexec(fd: &OwnedFd) {
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFD);
        if flags != -1 {
            libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

// ---- argument parsing -------------------------------------------------------

fn parse_args() -> Result<Options, String> {
    let mut opts = Options {
        action: None,
        list: false,
        force: false,
        readonly: false,
        lowpriority: false,
        passthrough: false,
        quiet: false,
        detach_key: DEFAULT_DETACH_KEY,
        name: None,
        command: Vec::new(),
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let mut positional_started = false;

    while i < args.len() {
        let tok = &args[i];
        // Once the first positional (the name) is seen, everything else is the
        // command line verbatim — including tokens that start with '-'.
        if positional_started {
            opts.command.push(tok.clone());
            i += 1;
            continue;
        }
        if tok == "--" {
            positional_started = true;
            i += 1;
            continue;
        }
        if tok.len() >= 2 && tok.starts_with('-') {
            let chars: Vec<char> = tok[1..].chars().collect();
            let mut j = 0;
            while j < chars.len() {
                match chars[j] {
                    'a' => set_action(&mut opts, Action::Attach)?,
                    'A' => set_action(&mut opts, Action::AttachOrCreate)?,
                    'c' => set_action(&mut opts, Action::Create)?,
                    'n' => set_action(&mut opts, Action::CreateNoAttach)?,
                    'f' => opts.force = true,
                    'l' => opts.list = true,
                    'L' => opts.lowpriority = true,
                    'p' => opts.passthrough = true,
                    'q' => opts.quiet = true,
                    'r' => opts.readonly = true,
                    'v' => {
                        println!("sm {VERSION} — a Rust reimplementation of abduco");
                        exit(0);
                    }
                    'e' => {
                        // Value is the rest of this token, or the next argument.
                        let rest: String = chars[j + 1..].iter().collect();
                        let spec = if !rest.is_empty() {
                            rest
                        } else {
                            i += 1;
                            args.get(i)
                                .cloned()
                                .ok_or_else(|| "-e requires a key argument".to_string())?
                        };
                        opts.detach_key = parse_detach_key(&spec)?;
                        break; // consumed the remainder of this token
                    }
                    other => return Err(format!("unknown option -{other}")),
                }
                j += 1;
            }
        } else {
            // First positional = session name; the remainder is the command.
            opts.name = Some(tok.clone());
            positional_started = true;
        }
        i += 1;
    }

    Ok(opts)
}

fn set_action(opts: &mut Options, action: Action) -> Result<(), String> {
    if opts.action.is_some() {
        return Err("only one of -a/-A/-c/-n may be given".to_string());
    }
    opts.action = Some(action);
    Ok(())
}

/// Parse a detach-key spec: `^x` (Ctrl-x), a single character, or a decimal
/// byte value.
fn parse_detach_key(spec: &str) -> Result<u8, String> {
    let chars: Vec<char> = spec.chars().collect();
    if chars.len() == 2 && chars[0] == '^' {
        let c = chars[1].to_ascii_uppercase() as u32;
        return Ok((c & 0x1f) as u8);
    }
    if chars.len() == 1 {
        let c = chars[0] as u32;
        if c < 128 {
            return Ok(c as u8);
        }
    }
    if let Ok(n) = spec.parse::<u8>() {
        return Ok(n);
    }
    Err(format!("invalid detach key: {spec}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detach_key_ctrl_backslash() {
        assert_eq!(parse_detach_key("^\\").unwrap(), 0x1c);
    }

    #[test]
    fn detach_key_ctrl_o() {
        assert_eq!(parse_detach_key("^o").unwrap(), 0x0f);
        assert_eq!(parse_detach_key("^O").unwrap(), 0x0f);
    }

    #[test]
    fn detach_key_single_char() {
        assert_eq!(parse_detach_key("q").unwrap(), b'q');
    }

    #[test]
    fn detach_key_decimal() {
        assert_eq!(parse_detach_key("28").unwrap(), 28);
    }

    #[test]
    fn detach_key_invalid() {
        assert!(parse_detach_key("abc").is_err());
    }
}
