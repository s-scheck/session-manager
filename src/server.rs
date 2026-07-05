//! The session server: a daemon that owns the pty running the supervised
//! command and multiplexes it to any attached clients over the Unix socket.

use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::exit;

use nix::pty::{ForkptyResult, forkpty};
use nix::sys::signal::Signal;
use nix::sys::termios::Termios;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{Pid, chdir, execvp};

use crate::protocol::{FLAG_LOWPRIORITY, FLAG_READONLY, MAX_PAYLOAD, Packet};
use crate::pty::{self, Winsize};
use crate::signals::{self, SignalPipe};
use crate::sockdir;
use crate::sys::{read_fd, write_all_fd};

/// Everything the server needs to start the session.
pub struct ServerConfig {
    pub socket_path: PathBuf,
    pub session_name: String,
    /// argv[0] is the program; the whole vector is passed to execvp.
    pub argv: Vec<CString>,
    pub winsize: Winsize,
    /// The attaching client's termios, so the pty starts with matching modes.
    pub termios: Option<Termios>,
    /// Directory the command should run in (the caller's cwd). The daemon itself
    /// stays at "/"; only the command chdirs here.
    pub workdir: Option<PathBuf>,
}

struct Client {
    stream: UnixStream,
    readonly: bool,
    lowpriority: bool,
}

/// How many bytes of recent pty output to retain and replay to a client when it
/// attaches, so the screen isn't blank on reattach. Not a full scrollback/VT
/// emulator — just enough raw output that the last screenful(s) repaint.
const REPLAY_CAP: usize = 64 * 1024;

/// Run the server to completion. Never returns: it `exit`s when the supervised
/// command dies (or on SIGTERM/SIGINT). `err_pipe` is the write end of a pipe
/// back to the launching process; on a failure before the child execs we send
/// a message through it, and a successful exec closes it (signalling success).
pub fn run_server(cfg: ServerConfig, err_pipe: OwnedFd) -> ! {
    redirect_std_to_devnull();
    signals::ignore(&[Signal::SIGPIPE, Signal::SIGHUP]);
    let sigpipe = SignalPipe::install(&[Signal::SIGCHLD, Signal::SIGTERM, Signal::SIGINT])
        .unwrap_or_else(|e| fail(&err_pipe, &format!("signal setup failed: {e}")));

    let listener = UnixListener::bind(&cfg.socket_path)
        .unwrap_or_else(|e| fail(&err_pipe, &format!("cannot bind socket: {e}")));
    if let Err(e) = listener.set_nonblocking(true) {
        fail(&err_pipe, &format!("cannot set socket non-blocking: {e}"));
    }
    let _ = sockdir::set_socket_state(&cfg.socket_path, false);

    // Fork the pty child that runs the command.
    let fork = unsafe { forkpty(Some(&cfg.winsize), cfg.termios.as_ref()) }
        .unwrap_or_else(|e| fail(&err_pipe, &format!("forkpty failed: {e}")));

    let (master, child) = match fork {
        ForkptyResult::Child => {
            // In the pty child: restore the caller's working directory (the
            // daemon runs at "/"), export session env, then exec the command.
            // Any failure is reported back through the error pipe.
            if let Some(dir) = &cfg.workdir {
                let _ = chdir(dir.as_path());
            }
            setenv("SM_SESSION", &cfg.session_name);
            setenv("SM_SOCKET", &cfg.socket_path.to_string_lossy());
            let _ = execvp(&cfg.argv[0], &cfg.argv);
            let msg = format!(
                "cannot execute {}: {}",
                cfg.argv[0].to_string_lossy(),
                io::Error::last_os_error()
            );
            let _ = write_all_fd(err_pipe.as_raw_fd(), msg.as_bytes());
            exit(127);
        }
        ForkptyResult::Parent { child, master } => (master, child),
    };

    // Success path: drop our copy of the error pipe so the launcher sees EOF.
    drop(err_pipe);

    let pty_fd = master.as_raw_fd();
    event_loop(cfg, listener, pty_fd, child, sigpipe);
}

fn event_loop(
    cfg: ServerConfig,
    listener: UnixListener,
    pty_fd: RawFd,
    child: Pid,
    sigpipe: SignalPipe,
) -> ! {
    let mut clients: Vec<Client> = Vec::new();
    let listener_fd = listener.as_raw_fd();
    let signal_fd = sigpipe.read_fd();
    // The active socket path. A Rename packet updates this so status updates and
    // cleanup on exit follow the renamed file.
    let mut socket_path = cfg.socket_path.clone();
    // Ring buffer of recent pty output, replayed to clients on attach.
    let mut replay: VecDeque<u8> = VecDeque::with_capacity(REPLAY_CAP);

    loop {
        // Build the poll set: signals, listener, pty, then each client.
        let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(3 + clients.len());
        let mut push = |fd: RawFd| {
            pfds.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
        };
        push(signal_fd);
        push(listener_fd);
        push(pty_fd);
        for c in &clients {
            push(c.stream.as_raw_fd());
        }

        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            shutdown(&socket_path, &mut clients, child);
        }

        let readable =
            |i: usize| pfds[i].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;

        // 1. Signals.
        if readable(0) {
            for sig in sigpipe.drain() {
                if sig == Signal::SIGCHLD as i32
                    || sig == Signal::SIGTERM as i32
                    || sig == Signal::SIGINT as i32
                {
                    shutdown(&socket_path, &mut clients, child);
                }
            }
        }

        // 2. pty output -> broadcast to every client.
        if readable(2) {
            let mut buf = [0u8; MAX_PAYLOAD];
            match read_fd(pty_fd, &mut buf) {
                Ok(0) | Err(_) => shutdown(&socket_path, &mut clients, child),
                Ok(n) => {
                    // Retain recent output for replay-on-attach, trimming the front.
                    replay.extend(&buf[..n]);
                    if replay.len() > REPLAY_CAP {
                        replay.drain(0..replay.len() - REPLAY_CAP);
                    }
                    let packet = Packet::Content(buf[..n].to_vec());
                    clients.retain_mut(|c| packet.write_to(&mut c.stream).is_ok());
                }
            }
        }

        // 3. Existing clients (indices 3..). Capture readiness before we mutate
        //    the vector, then process and prune disconnects.
        let client_base = 3;
        let mut disconnected: Vec<usize> = Vec::new();
        for idx in 0..clients.len() {
            if !readable(client_base + idx) {
                continue;
            }
            if !handle_client_packet(&mut socket_path, &replay, &mut clients, idx, pty_fd) {
                disconnected.push(idx);
            }
        }
        if !disconnected.is_empty() {
            let mut idx = 0;
            clients.retain(|_| {
                let keep = !disconnected.contains(&idx);
                idx += 1;
                keep
            });
        }

        // 4. New connections (append; doesn't disturb earlier indices).
        if readable(1) {
            accept_clients(&listener, &mut clients, child);
        }

        // Reflect attach state in the socket permission bits.
        let _ = sockdir::set_socket_state(&socket_path, !clients.is_empty());
    }
}

/// Process one packet from client `idx`. Returns false if the client
/// disconnected (and should be pruned).
fn handle_client_packet(
    socket_path: &mut PathBuf,
    replay: &VecDeque<u8>,
    clients: &mut [Client],
    idx: usize,
    pty_fd: RawFd,
) -> bool {
    let packet = match Packet::read_from(&mut clients[idx].stream) {
        Ok(p) => p,
        Err(_) => return false, // EOF or error => disconnect
    };
    match packet {
        Packet::Content(bytes) => {
            if !clients[idx].readonly {
                let _ = write_all_fd(pty_fd, &bytes);
            }
            true
        }
        Packet::Resize { rows, cols } => {
            // Only the controlling (highest-priority, non-readonly) client
            // dictates the window size, so a passive viewer can't shrink it.
            if !clients[idx].readonly && idx == controlling_client(clients) {
                let _ = pty::set_winsize(pty_fd, &pty::winsize_from(rows, cols));
            }
            true
        }
        Packet::Attach { flags } => {
            clients[idx].readonly = flags & FLAG_READONLY != 0;
            clients[idx].lowpriority = flags & FLAG_LOWPRIORITY != 0;
            // Replay recent output so the freshly-attached client repaints
            // instead of showing a blank screen.
            let snapshot: Vec<u8> = replay.iter().copied().collect();
            for chunk in snapshot.chunks(MAX_PAYLOAD) {
                if Packet::Content(chunk.to_vec())
                    .write_to(&mut clients[idx].stream)
                    .is_err()
                {
                    return false;
                }
            }
            true
        }
        Packet::Detach => false,
        Packet::Rename(new_name) => {
            // Rename the socket file within its directory and adopt the new
            // path so status updates and cleanup follow it. The sender is a
            // control-only connection, so drop it afterward.
            rename_socket(socket_path, &new_name);
            false
        }
        // Clients never legitimately send Exit/Pid; ignore.
        Packet::Exit(_) | Packet::Pid(_) => true,
    }
}

/// Rename the session's socket to `new_name` within its current directory,
/// updating `socket_path` on success. Invalid names and failed renames are
/// ignored (the client detects failure by the new path not appearing).
fn rename_socket(socket_path: &mut PathBuf, new_name: &str) {
    if new_name.is_empty() || new_name.contains('/') || new_name.contains('\0') {
        return;
    }
    let Some(parent) = socket_path.parent() else {
        return;
    };
    let new_path = parent.join(new_name);
    if std::fs::rename(&*socket_path, &new_path).is_ok() {
        *socket_path = new_path;
    }
}

/// Index of the client that controls window size: the first non-lowpriority
/// client, or 0 if all are lowpriority.
fn controlling_client(clients: &[Client]) -> usize {
    clients.iter().position(|c| !c.lowpriority).unwrap_or(0)
}

fn accept_clients(listener: &UnixListener, clients: &mut Vec<Client>, child: Pid) {
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let mut stream = stream;
                // Announce our pid so probes/listing can confirm liveness.
                let _ = Packet::Pid(child.as_raw() as u32).write_to(&mut stream);
                clients.push(Client {
                    stream,
                    readonly: false,
                    lowpriority: false,
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

/// Reap the child, tell every client the exit status, clean up the socket, and
/// terminate the daemon.
fn shutdown(socket_path: &Path, clients: &mut [Client], child: Pid) -> ! {
    let status = match waitpid(child, None) {
        Ok(WaitStatus::Exited(_, code)) => code,
        Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
        _ => 0,
    };
    let packet = Packet::Exit(status);
    for c in clients.iter_mut() {
        let _ = packet.write_to(&mut c.stream);
    }
    let _ = std::fs::remove_file(socket_path);
    exit(0);
}

fn setenv(key: &str, value: &str) {
    if let (Ok(k), Ok(v)) = (CString::new(key), CString::new(value)) {
        unsafe {
            libc::setenv(k.as_ptr(), v.as_ptr(), 1);
        }
    }
}

/// The daemon has no controlling terminal; point its own stdio at /dev/null so
/// stray reads/writes don't touch the launching terminal. (The command runs on
/// the pty, not on these fds.)
fn redirect_std_to_devnull() {
    let devnull = CString::new("/dev/null").unwrap();
    let fd = unsafe { libc::open(devnull.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return;
    }
    unsafe {
        libc::dup2(fd, libc::STDIN_FILENO);
        libc::dup2(fd, libc::STDOUT_FILENO);
        libc::dup2(fd, libc::STDERR_FILENO);
        if fd > libc::STDERR_FILENO {
            libc::close(fd);
        }
    }
}

/// Report a startup failure through the error pipe and exit. Used before the
/// launcher has detached, so the message reaches the user's terminal.
fn fail(err_pipe: &OwnedFd, msg: &str) -> ! {
    let _ = write_all_fd(err_pipe.as_raw_fd(), msg.as_bytes());
    exit(1);
}
