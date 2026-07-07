//! The session server: a daemon that owns the pty running the supervised
//! command and multiplexes it to any attached clients over the Unix socket.

use std::collections::VecDeque;
use std::ffi::CString;
use std::io::{self, Read, Write};
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

/// How many bytes of recent pty output to retain and replay to a client when it
/// attaches, so the screen isn't blank on reattach. Not a full scrollback/VT
/// emulator — just enough raw output that the last screenful(s) repaint.
const REPLAY_CAP: usize = 64 * 1024;

/// Hard cap on a client's pending output buffer. A client that can't keep up
/// (stuck/gone) is dropped rather than allowed to grow the server's memory
/// without bound. Generous enough that a merely-slow terminal is never dropped.
const OUT_CAP: usize = 8 * 1024 * 1024;

/// A connected client. All socket I/O is non-blocking and buffered, so a slow
/// or stuck client can never block the server or stall the other clients.
struct Client {
    stream: UnixStream,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    readonly: bool,
    lowpriority: bool,
    dead: bool,
}

impl Client {
    fn new(stream: UnixStream) -> Client {
        Client {
            stream,
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            readonly: false,
            lowpriority: false,
            dead: false,
        }
    }

    /// Append a packet to the pending output; try to push it out immediately.
    fn send(&mut self, pkt: &Packet) {
        if self.dead {
            return;
        }
        self.outbuf.extend_from_slice(&pkt.encode());
        if self.outbuf.len() > OUT_CAP {
            self.dead = true; // too far behind; drop it
            return;
        }
        self.flush();
    }

    /// Write as much of the output buffer as the socket will take without
    /// blocking. Marks the client dead on a hard error.
    fn flush(&mut self) {
        while !self.outbuf.is_empty() {
            match self.stream.write(&self.outbuf) {
                Ok(0) => {
                    self.dead = true;
                    break;
                }
                Ok(n) => {
                    self.outbuf.drain(0..n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.dead = true;
                    break;
                }
            }
        }
    }

    fn wants_write(&self) -> bool {
        !self.outbuf.is_empty()
    }

    /// Read whatever is available (non-blocking) into the input buffer. Marks
    /// the client dead on EOF or a hard error.
    fn fill(&mut self) {
        let mut tmp = [0u8; 8192];
        loop {
            match self.stream.read(&mut tmp) {
                Ok(0) => {
                    self.dead = true;
                    break;
                }
                Ok(n) => self.inbuf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.dead = true;
                    break;
                }
            }
        }
    }
}

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
        // Build the poll set: signals, listener, pty, then each client (always
        // watching for input, and for writability when it has pending output).
        let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(3 + clients.len());
        let mut push = |fd: RawFd, events: libc::c_short| {
            pfds.push(libc::pollfd {
                fd,
                events,
                revents: 0,
            })
        };
        push(signal_fd, libc::POLLIN);
        push(listener_fd, libc::POLLIN);
        push(pty_fd, libc::POLLIN);
        for c in &clients {
            let mut events = libc::POLLIN;
            if c.wants_write() {
                events |= libc::POLLOUT;
            }
            push(c.stream.as_raw_fd(), events);
        }

        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            shutdown(&socket_path, &mut clients, child);
        }

        let has = |i: usize, flags: libc::c_short| pfds[i].revents & flags != 0;
        let readable = |i: usize| has(i, libc::POLLIN | libc::POLLHUP | libc::POLLERR);

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

        // 2. pty output -> retain for replay and broadcast to every client.
        if readable(2) {
            let mut buf = [0u8; MAX_PAYLOAD];
            match read_fd(pty_fd, &mut buf) {
                Ok(0) | Err(_) => shutdown(&socket_path, &mut clients, child),
                Ok(n) => {
                    replay.extend(&buf[..n]);
                    if replay.len() > REPLAY_CAP {
                        replay.drain(0..replay.len() - REPLAY_CAP);
                    }
                    let packet = Packet::Content(buf[..n].to_vec());
                    for c in &mut clients {
                        c.send(&packet);
                    }
                }
            }
        }

        // 3. Client sockets: flush writable ones, read readable ones and act on
        //    any complete packets. Indices line up with the push order above.
        let client_base = 3;
        for idx in 0..clients.len() {
            let slot = client_base + idx;
            if has(slot, libc::POLLOUT) {
                clients[idx].flush();
            }
            if readable(slot) {
                clients[idx].fill();
                process_inbuf(&mut socket_path, &replay, &mut clients, idx, pty_fd);
            }
        }

        // 4. New connections (append; doesn't disturb earlier indices).
        if readable(1) {
            accept_clients(&listener, &mut clients, child);
        }

        // Drop clients that hung up or fell too far behind.
        clients.retain(|c| !c.dead);

        // Reflect attach state in the socket permission bits.
        let _ = sockdir::set_socket_state(&socket_path, !clients.is_empty());
    }
}

/// Decode and act on every complete packet buffered for client `idx`. Marks the
/// client dead on a protocol error or an intentional detach.
fn process_inbuf(
    socket_path: &mut PathBuf,
    replay: &VecDeque<u8>,
    clients: &mut [Client],
    idx: usize,
    pty_fd: RawFd,
) {
    loop {
        let packet = match Packet::try_decode(&mut clients[idx].inbuf) {
            Ok(Some(p)) => p,
            Ok(None) => break, // need more bytes
            Err(_) => {
                clients[idx].dead = true; // protocol violation
                break;
            }
        };
        match packet {
            Packet::Content(bytes) => {
                if !clients[idx].readonly {
                    let _ = write_all_fd(pty_fd, &bytes);
                }
            }
            Packet::Resize { rows, cols } => {
                // Only the controlling (highest-priority, non-readonly) client
                // dictates the window size, so a passive viewer can't shrink it.
                if !clients[idx].readonly && idx == controlling_client(clients) {
                    let _ = pty::set_winsize(pty_fd, &pty::winsize_from(rows, cols));
                }
            }
            Packet::Attach { flags } => {
                clients[idx].readonly = flags & FLAG_READONLY != 0;
                clients[idx].lowpriority = flags & FLAG_LOWPRIORITY != 0;
                // Replay recent output so the freshly-attached client repaints
                // instead of showing a blank screen.
                let snapshot: Vec<u8> = replay.iter().copied().collect();
                for chunk in snapshot.chunks(MAX_PAYLOAD) {
                    clients[idx].send(&Packet::Content(chunk.to_vec()));
                }
            }
            Packet::Detach => {
                clients[idx].dead = true;
                break;
            }
            Packet::Rename(new_name) => {
                // Rename the socket within its directory and adopt the new path
                // so status updates and cleanup follow it. The sender is a
                // control-only connection, so drop it afterward.
                rename_socket(socket_path, &new_name);
                clients[idx].dead = true;
                break;
            }
            // Clients never legitimately send Exit/Pid; ignore.
            Packet::Exit(_) | Packet::Pid(_) => {}
        }
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
                if stream.set_nonblocking(true).is_err() {
                    continue;
                }
                let mut client = Client::new(stream);
                // Announce our pid so probes/listing can confirm liveness.
                client.send(&Packet::Pid(child.as_raw() as u32));
                clients.push(client);
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
    let exit_pkt = Packet::Exit(status).encode();
    for c in clients.iter_mut() {
        // Deliver the exit status best-effort. Switch back to blocking so the
        // (small) final write isn't lost to a transient EWOULDBLOCK.
        let _ = c.stream.set_nonblocking(false);
        let _ = c.stream.write_all(&c.outbuf);
        let _ = c.stream.write_all(&exit_pkt);
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
