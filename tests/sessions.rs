//! End-to-end tests: drive the real `sm` binary against real sessions, each
//! test in its own private socket directory.

use std::fs::{self, DirBuilder};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(10);

/// A private socket directory, removed (with any leftover sessions' sockets)
/// when the test ends.
struct Sessions {
    dir: PathBuf,
}

impl Sessions {
    fn new(test: &str) -> Sessions {
        // Socket paths are short-limited (104 bytes on macOS), so keep it short.
        let dir = std::env::temp_dir().join(format!("sm-{}-{test}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Sessions { dir }
    }

    fn sm(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sm"));
        cmd.args(args)
            .env("SM_SOCKET_DIR", &self.dir)
            .env_remove("SM_CMD");
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.sm(args).stdin(Stdio::null()).output().unwrap()
    }

    /// Start a detached session running `sh -c script`.
    fn create(&self, name: &str, script: &str) {
        let out = self.run(&["-n", "-q", name, "sh", "-c", script]);
        assert!(out.status.success(), "create failed: {}", stderr(&out));
    }

    /// Attach in passthrough mode, feed `input`, and collect everything until
    /// the session ends.
    fn attach_with_input(&self, name: &str, input: &[u8]) -> Output {
        let mut child = self.attach_piped(name);
        child.stdin.take().unwrap().write_all(input).unwrap();
        wait_with_timeout(child)
    }

    /// Attach in passthrough mode with stdin left open for the caller.
    fn attach_piped(&self, name: &str) -> Child {
        self.attach_command(name, &[]).spawn().unwrap()
    }

    /// Attach in passthrough mode (plus `flags`), collecting the client's
    /// output in the background so the test can wait for it while the client
    /// keeps running.
    fn attach_watched(&self, name: &str, flags: &[&str]) -> Watched {
        let mut child = self.attach_command(name, flags).spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&output);
        let reader = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n @ 1..) = stdout.read(&mut buf) {
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Watched {
            child,
            stdin,
            output,
            reader,
        }
    }

    fn attach_command(&self, name: &str, flags: &[&str]) -> Command {
        let mut cmd = self.sm(&[flags, &["-p", "-a", name]].concat());
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// `sm -l` output as (status, name, pid) rows.
    fn list(&self) -> Vec<(String, String, String)> {
        let out = self.run(&["-l"]);
        stdout(&out)
            .lines()
            .map(|line| {
                let mut cols = line.split_whitespace().map(str::to_owned);
                let mut next = || cols.next().unwrap_or_default();
                (next(), next(), next())
            })
            .collect()
    }

    fn socket(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Sessions {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A running client whose stdout is being collected.
struct Watched {
    child: Child,
    stdin: ChildStdin,
    output: Arc<Mutex<Vec<u8>>>,
    reader: thread::JoinHandle<()>,
}

impl Watched {
    fn output(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
    }

    /// Wait until the client has printed `marker`. Since every attaching client
    /// first receives the session's recent output, this also confirms that it
    /// has attached.
    fn wait_for(&self, marker: &str) {
        wait_until(&format!("{marker:?} in the client's output"), || {
            self.output().contains(marker)
        });
    }

    fn send(&mut self, input: &[u8]) {
        self.stdin.write_all(input).unwrap();
    }

    /// Wait for the client to exit: (exit code, stdout, stderr).
    fn finish(self) -> (Option<i32>, String, String) {
        let Watched {
            child,
            stdin,
            output,
            reader,
        } = self;
        drop(stdin);
        let out = wait_with_timeout(child);
        reader.join().unwrap();
        let stdout = String::from_utf8_lossy(&output.lock().unwrap()).into_owned();
        (out.status.code(), stdout, stderr(&out))
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn wait_with_timeout(mut child: Child) -> Output {
    let deadline = Instant::now() + TIMEOUT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("sm did not finish within {TIMEOUT:?}");
        }
        thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn kill(signal: &str, pid: &str) {
    let status = Command::new("kill").args([signal, pid]).status().unwrap();
    assert!(status.success(), "kill {signal} {pid} failed");
}

#[test]
fn exit_status_and_final_output_reach_the_client() {
    let s = Sessions::new("exit");
    s.create("job", r#"read x; echo "got:$x"; exit 3"#);
    let out = s.attach_with_input("job", b"hello\n");
    assert!(
        stdout(&out).contains("got:hello"),
        "output: {}",
        stdout(&out)
    );
    assert_eq!(out.status.code(), Some(3));
    assert!(!s.socket("job").exists(), "socket must be removed");
}

#[test]
fn create_and_attach_sees_even_an_instant_command() {
    let s = Sessions::new("instant");
    for i in 0..10 {
        let out = s.run(&[
            "-p",
            "-c",
            &format!("i{i}"),
            "sh",
            "-c",
            "printf done; exit 5",
        ]);
        assert!(stdout(&out).contains("done"), "run {i}: {}", stderr(&out));
        assert_eq!(out.status.code(), Some(5), "run {i}: {}", stderr(&out));
    }
}

#[test]
fn command_starts_with_default_signal_dispositions() {
    // With SIGPIPE inherited as ignored, the shell would survive this.
    let s = Sessions::new("sigpipe");
    s.create("pipe", "read x; kill -PIPE $$; echo survived");
    let out = s.attach_with_input("pipe", b"\n");
    assert!(!stdout(&out).contains("survived"));
    assert_eq!(out.status.code(), Some(128 + 13));
}

#[test]
fn rename_moves_a_live_session() {
    let s = Sessions::new("rename");
    s.create("old", "read x; exit 7");
    s.create("taken", "read x");

    let out = s.run(&["-R", "old", "new"]);
    assert!(out.status.success(), "rename failed: {}", stderr(&out));
    let names: Vec<_> = s.list().into_iter().map(|(_, name, _)| name).collect();
    assert_eq!(names, ["new", "taken"]);

    // Renaming onto a live session is refused and changes nothing.
    let out = s.run(&["-R", "new", "taken"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("already exists"), "{}", stderr(&out));
    assert!(s.socket("new").exists() && s.socket("taken").exists());

    assert_eq!(s.run(&["-R", "missing", "x"]).status.code(), Some(1));
    assert!(s.run(&["-R", "new", "new"]).status.success());

    assert_eq!(s.attach_with_input("new", b"\n").status.code(), Some(7));
    assert_eq!(s.attach_with_input("taken", b"\n").status.code(), Some(0));
}

#[test]
fn program_not_reading_input_does_not_stall_the_server() {
    let s = Sessions::new("flood");
    // Raw mode: the pty accepts only a little input, then pushes back.
    s.create("busy", "stty raw -echo; exec sleep 30");
    thread::sleep(Duration::from_millis(200));

    let mut flood = s.attach_piped("busy");
    let mut stdin = flood.stdin.take().unwrap();
    let writer = thread::spawn(move || {
        let chunk = [b'x'; 64 * 1024];
        for _ in 0..32 {
            if stdin.write_all(&chunk).is_err() {
                break;
            }
        }
    });

    // The server keeps answering while it holds back the input.
    let mut pid = String::new();
    wait_until("the session to report as attached", || {
        let rows = s.list();
        match rows.first() {
            Some((status, name, p)) if status == "*" && name == "busy" => {
                pid = p.clone();
                true
            }
            _ => false,
        }
    });
    writer.join().unwrap();

    // And it is still recognised as alive, not replaced as if it were stale.
    let out = s.run(&["-c", "busy", "true"]);
    assert!(stderr(&out).contains("already exists"), "{}", stderr(&out));

    kill("-TERM", &pid);
    let out = wait_with_timeout(flood);
    assert_eq!(out.status.code(), Some(128 + 15));
}

#[test]
fn connections_that_never_attach_are_not_counted_as_attached() {
    let s = Sessions::new("probe");
    s.create("idle", "read x");
    let socket = s.socket("idle");

    let mut conn = UnixStream::connect(&socket).unwrap();
    let mut hello = [0u8; 16];
    conn.read_exact(&mut hello).unwrap();
    thread::sleep(Duration::from_millis(100));

    let mode = fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket marked attached by a mere connection");
    assert_eq!(s.list()[0].0, "-");
    drop(conn);

    assert!(s.attach_with_input("idle", b"\n").status.success());
}

#[test]
fn termination_signal_hangs_up_the_session() {
    let s = Sessions::new("term");
    let pidfile = s.dir.join("server.pid");
    // The command's parent is the session server.
    s.create(
        "victim",
        &format!("echo $PPID > {}; read x", pidfile.display()),
    );
    wait_until("the pid file", || {
        fs::read_to_string(&pidfile).is_ok_and(|p| p.ends_with('\n'))
    });
    let server = fs::read_to_string(&pidfile).unwrap().trim().to_owned();

    let attached = s.attach_piped("victim");
    wait_until("the client to attach", || {
        s.list().first().is_some_and(|row| row.0 == "*")
    });

    kill("-TERM", &server);
    let out = wait_with_timeout(attached);
    assert_eq!(out.status.code(), Some(128 + 1), "{}", stderr(&out));
    wait_until("the socket to disappear", || !s.socket("victim").exists());
}

#[test]
fn kill_ends_the_session_for_every_client() {
    let s = Sessions::new("kill");
    s.create("doomed", "echo ready; read x");
    let attached = s.attach_watched("doomed", &[]);
    attached.wait_for("ready");

    let out = s.run(&["-k", "doomed"]);
    assert!(out.status.success(), "{}", stderr(&out));
    // `sm -k` returns only once the session is gone.
    assert!(!s.socket("doomed").exists());
    let (code, _, err) = attached.finish();
    assert_eq!(code, Some(128 + 1), "{err}");

    let out = s.run(&["-k", "doomed"]);
    assert!(stderr(&out).contains("no such session"), "{}", stderr(&out));
}

#[test]
fn kill_escalates_when_the_hangup_is_ignored() {
    let s = Sessions::new("stubborn");
    s.create("stubborn", "trap '' HUP; echo ready; exec sleep 60");
    let attached = s.attach_watched("stubborn", &[]);
    // Once "ready" is printed, the hangup is ignored by the command.
    attached.wait_for("ready");

    let out = s.run(&["-k", "stubborn"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let (code, _, err) = attached.finish();
    assert_eq!(code, Some(128 + 9), "killed after the grace period: {err}");
}

#[test]
fn attaching_with_d_detaches_the_other_clients() {
    let s = Sessions::new("takeover");
    s.create("shared", r#"echo ready; read x; echo "got:$x"; exit 2"#);
    let first = s.attach_watched("shared", &[]);
    let second = s.attach_watched("shared", &["-r"]);
    first.wait_for("ready");
    second.wait_for("ready");

    let mut taker = s.attach_watched("shared", &["-d"]);
    for displaced in [first, second] {
        let (code, _, err) = displaced.finish();
        assert_eq!(code, Some(0), "{err}");
        assert!(err.contains("attached elsewhere"), "{err}");
    }

    // The session itself is unaffected and now serves the new client.
    taker.send(b"hi\n");
    let (code, out, err) = taker.finish();
    assert_eq!(code, Some(2), "{err}");
    assert!(out.contains("got:hi"), "{out}");
}

#[test]
fn stale_sockets_need_force_or_attach_or_create() {
    let s = Sessions::new("stale");
    let stale = || drop(UnixListener::bind(s.socket("old")).unwrap());

    stale();
    assert_eq!(s.list()[0].0, "?");
    let out = s.run(&["-a", "old"]);
    assert!(stderr(&out).contains("no such session"), "{}", stderr(&out));

    let out = s.run(&["-n", "old", "true"]);
    assert!(stderr(&out).contains("use -f"), "{}", stderr(&out));
    assert!(s.socket("old").exists());

    let out = s.run(&["-n", "-f", "-q", "old", "sh", "-c", "read x"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(s.attach_with_input("old", b"\n").status.success());

    stale();
    let out = s.run(&["-A", "-p", "old", "sh", "-c", "exit 4"]);
    assert_eq!(out.status.code(), Some(4), "{}", stderr(&out));
}

#[test]
fn incompatible_server_is_reported_and_left_alone() {
    let s = Sessions::new("compat");
    // A pre-versioning server greeted with a bare 4-byte pid.
    let listener = UnixListener::bind(s.socket("legacy")).unwrap();
    thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let mut greeting = Vec::new();
            greeting.extend_from_slice(&5u32.to_le_bytes());
            greeting.extend_from_slice(&4u32.to_le_bytes());
            greeting.extend_from_slice(&4242u32.to_le_bytes());
            let _ = conn.write_all(&greeting);
        }
    });

    let out = s.run(&["-a", "legacy"]);
    assert!(
        stderr(&out).contains("incompatible version"),
        "{}",
        stderr(&out)
    );

    let out = s.run(&["-A", "legacy"]);
    assert!(
        stderr(&out).contains("cannot connect") && stderr(&out).contains("incompatible version"),
        "{}",
        stderr(&out)
    );
    assert!(
        s.socket("legacy").exists(),
        "a running session must not be replaced"
    );
    assert_eq!(s.list()[0].0, "?");
}
