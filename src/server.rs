//! The session server: a daemon that owns the pty running the supervised
//! command and multiplexes it to any attached clients over the Unix socket.
//!
//! The server is a single-threaded `poll(2)` loop that never blocks: the pty
//! and every client socket are non-blocking with buffered output, so neither a
//! program that stops reading its input nor a client that stops reading its
//! output can stall the session for anyone else.
//!
//! Lifecycle: the session lives exactly as long as the supervised command.
//! When the command exits, the output it left in the pty is drained and
//! delivered, attached clients receive its exit status, and the socket is
//! removed. A termination signal (SIGTERM/SIGINT/SIGHUP) to the server hangs
//! up the terminal, as closing a terminal window would; the command then exits
//! through that same path.

use std::collections::VecDeque;
use std::ffi::CString;
use std::fmt::Display;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::exit;
use std::time::{Duration, Instant};

use nix::pty::{ForkptyResult, forkpty};
use nix::sys::signal::{Signal, killpg};
use nix::sys::termios::Termios;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, chdir, execvp, fork, setsid};

use crate::protocol::{FLAG_LOWPRIORITY, FLAG_READONLY, MAX_PAYLOAD, PROTOCOL_VERSION, Packet};
use crate::pty::{self, Winsize};
use crate::signals::{self, SignalPipe};
use crate::sockdir;
use crate::sys::{self, read_fd, write_all_fd, write_fd};

/// Everything the server needs to start the session.
pub struct ServerConfig {
    pub socket_path: PathBuf,
    pub session_name: String,
    /// argv[0] is the program; the whole vector is passed to execvp.
    pub argv: Vec<CString>,
    pub winsize: Winsize,
    /// The creating terminal's termios, so the pty starts with matching modes.
    pub termios: Option<Termios>,
    /// Directory the command should run in (the caller's cwd). The daemon itself
    /// stays at "/"; only the command chdirs here.
    pub workdir: Option<PathBuf>,
    /// A connection for the creating process to attach through. It exists
    /// before the command starts, so even a command that exits immediately
    /// can't finish before its creator is connected.
    pub creator: Option<UnixStream>,
}

/// How many bytes of recent pty output to retain and replay to a client when it
/// attaches, so the screen isn't blank on reattach. Not a full scrollback/VT
/// emulator — just enough raw output that the last screenful(s) repaint.
const REPLAY_CAP: usize = 64 * 1024;

/// Hard cap on a client's pending output buffer. A client that can't keep up
/// (stuck/gone) is dropped rather than allowed to grow the server's memory
/// without bound. Generous enough that a merely-slow terminal is never dropped.
const CLIENT_OUT_CAP: usize = 8 * 1024 * 1024;

/// Cap on keystrokes buffered for a program that is not reading its input.
/// Input beyond it is discarded, as a full tty input queue would.
const PTY_INPUT_CAP: usize = 1024 * 1024;

/// Upper bound on the output drained from the pty after the command exits.
/// The kernel buffers only a few KiB per pty, so this covers everything the
/// command left behind, while a background process that inherited the terminal
/// and keeps writing cannot hold up the shutdown.
const FINAL_DRAIN_CAP: usize = 64 * 1024;

/// How long an exiting server keeps trying to deliver pending output and the
/// exit status to clients that are slow to read it.
const EXIT_FLUSH_TIMEOUT: Duration = Duration::from_secs(1);

// The signals the server handles; the pty child resets them before exec.
const HANDLED_SIGNALS: [Signal; 4] = [
    Signal::SIGCHLD,
    Signal::SIGTERM,
    Signal::SIGINT,
    Signal::SIGHUP,
];

/// Start the session server as a daemon and wait until the command is running.
/// Returns the startup error reported by the server, if any.
pub fn spawn(cfg: ServerConfig) -> Result<(), String> {
    // Startup reporting: the server and the command hold the write end, which
    // is close-on-exec. A successful exec plus the server dropping its copy
    // yields EOF; a failure writes a message instead.
    let (ready_read, ready_write) = sys::pipe().map_err(|e| format!("pipe failed: {e}"))?;

    // SAFETY: sm is single-threaded, so the child may run arbitrary code.
    match unsafe { fork() }.map_err(|e| format!("fork failed: {e}"))? {
        ForkResult::Child => {
            drop(ready_read);
            // Become a session leader, then fork the real daemon so it is not
            // one and can never acquire a controlling terminal.
            let _ = setsid();
            match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    let _ = chdir("/");
                    run(cfg, ready_write)
                }
                Ok(ForkResult::Parent { .. }) => exit_immediately(0),
                Err(e) => fail(&ready_write, "fork failed", e),
            }
        }
        ForkResult::Parent { child } => {
            drop(ready_write);
            // Reap the short-lived intermediate process.
            let _ = waitpid(child, None);
            let mut msg = String::new();
            File::from(ready_read)
                .read_to_string(&mut msg)
                .map_err(|e| format!("cannot read server status: {e}"))?;
            if msg.is_empty() { Ok(()) } else { Err(msg) }
        }
    }
}

/// The daemon's body. Never returns: it exits once the session has ended.
fn run(cfg: ServerConfig, ready: OwnedFd) -> ! {
    let mut server = Server::start(cfg, &ready);
    // Startup succeeded; EOF on the pipe tells the launcher so.
    drop(ready);
    let status = server.serve();
    server.shut_down(status);
    exit(0);
}

/// A connected client. All socket I/O is non-blocking and buffered, so a slow
/// or stuck client can never block the server or stall the other clients.
struct Client {
    stream: UnixStream,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    state: ClientState,
}

enum ClientState {
    /// Greeted; may now attach or make a one-shot request (rename).
    Connected,
    /// Receiving the session's output.
    Attached(Attachment),
    /// Done; dropped once its pending output has been written.
    Closing,
    /// Gone (hung up, errored, broke protocol, or fell too far behind).
    Dead,
}

struct Attachment {
    readonly: bool,
    lowpriority: bool,
    /// Attach order; the most recent eligible client controls the window size.
    seq: u64,
    /// The window size this client last reported.
    size: Option<(u16, u16)>,
}

impl Client {
    fn new(stream: UnixStream) -> Client {
        Client {
            stream,
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            state: ClientState::Connected,
        }
    }

    fn attachment(&self) -> Option<&Attachment> {
        match &self.state {
            ClientState::Attached(a) => Some(a),
            _ => None,
        }
    }

    fn is_attached(&self) -> bool {
        self.attachment().is_some()
    }

    fn is_finished(&self) -> bool {
        match self.state {
            ClientState::Dead => true,
            ClientState::Closing => self.outbuf.is_empty(),
            _ => false,
        }
    }

    fn send(&mut self, pkt: &Packet) {
        self.send_encoded(&pkt.encode());
    }

    /// Append an encoded packet to the pending output and try to push it out
    /// immediately.
    fn send_encoded(&mut self, bytes: &[u8]) {
        if matches!(self.state, ClientState::Dead) {
            return;
        }
        if self.outbuf.len() + bytes.len() > CLIENT_OUT_CAP {
            self.state = ClientState::Dead; // too far behind; drop it
            return;
        }
        self.outbuf.extend_from_slice(bytes);
        self.flush();
    }

    /// Write as much of the output buffer as the socket will take without
    /// blocking. Marks the client dead on a hard error.
    fn flush(&mut self) {
        while !self.outbuf.is_empty() {
            match self.stream.write(&self.outbuf) {
                Ok(0) => {
                    self.state = ClientState::Dead;
                    break;
                }
                Ok(n) => {
                    self.outbuf.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.state = ClientState::Dead;
                    break;
                }
            }
        }
    }

    /// Read whatever is available (non-blocking) into the input buffer.
    /// Returns false once the peer has closed the connection or it failed;
    /// packets already received should still be processed.
    fn fill(&mut self) -> bool {
        let mut tmp = [0u8; 8192];
        loop {
            match self.stream.read(&mut tmp) {
                Ok(0) => return false,
                Ok(n) => self.inbuf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                Err(_) => return false,
            }
        }
    }
}

struct Server {
    listener: UnixListener,
    signals: SignalPipe,
    /// Master side of the command's pty; `None` once the terminal has closed
    /// (every process let go of it) or the server hung it up.
    pty: Option<OwnedFd>,
    /// Keystrokes waiting for the command to read them.
    pty_input: Vec<u8>,
    child: Pid,
    /// The active socket path. Follows renames so status updates and cleanup
    /// on exit apply to the right file.
    socket_path: PathBuf,
    clients: Vec<Client>,
    /// Ring buffer of recent pty output, replayed to clients on attach.
    replay: VecDeque<u8>,
    /// Attach state last written to the socket's permission bits.
    marked_attached: bool,
    /// Window size last applied to the pty.
    applied_size: Option<(u16, u16)>,
    attach_count: u64,
}

impl Server {
    /// Set up the daemon: detach from the terminal, install signal handling,
    /// bind the socket and spawn the command. Any failure is reported through
    /// `ready` and terminates the process.
    fn start(cfg: ServerConfig, ready: &OwnedFd) -> Server {
        if let Err(e) = sys::redirect_stdio_to_devnull() {
            fail(ready, "cannot redirect stdio", e);
        }
        signals::ignore(&[Signal::SIGPIPE]);
        let signals = SignalPipe::install(&HANDLED_SIGNALS)
            .unwrap_or_else(|e| fail(ready, "signal setup failed", e));

        let listener = UnixListener::bind(&cfg.socket_path)
            .unwrap_or_else(|e| fail(ready, "cannot bind socket", e));
        let setup = listener
            .set_nonblocking(true)
            .and_then(|()| sockdir::set_socket_state(&cfg.socket_path, false))
            .map_err(|e| ("cannot set up socket", e.to_string()))
            .and_then(|()| {
                spawn_command(&cfg, ready).map_err(|e| ("cannot start command", e.to_string()))
            });
        let (pty, child) = match setup {
            Ok(spawned) => spawned,
            Err((what, e)) => {
                // Don't leave a socket behind that nothing will ever serve.
                let _ = fs::remove_file(&cfg.socket_path);
                fail(ready, what, e)
            }
        };

        let mut server = Server {
            listener,
            signals,
            pty: Some(pty),
            pty_input: Vec::new(),
            child,
            socket_path: cfg.socket_path,
            clients: Vec::new(),
            replay: VecDeque::with_capacity(REPLAY_CAP),
            marked_attached: false,
            applied_size: None,
            attach_count: 0,
        };
        if let Some(creator) = cfg.creator {
            server.add_client(creator);
        }
        server
    }

    /// Run the event loop until the command has exited; returns its status.
    fn serve(&mut self) -> i32 {
        const SIGNALS: usize = 0;
        const LISTENER: usize = 1;
        const PTY: usize = 2;
        const CLIENTS: usize = 3;

        loop {
            // Build the poll set: signals, listener, pty, then each client
            // (always watching for input, and for writability when it has
            // pending output). A closed pty keeps its slot as fd -1, which
            // poll(2) ignores, so the indices stay fixed.
            let mut fds = Vec::with_capacity(CLIENTS + self.clients.len());
            fds.push(pollfd(self.signals.read_fd(), libc::POLLIN));
            fds.push(pollfd(self.listener.as_raw_fd(), libc::POLLIN));
            let pty_events = if self.pty_input.is_empty() {
                libc::POLLIN
            } else {
                libc::POLLIN | libc::POLLOUT
            };
            fds.push(pollfd(self.pty_fd().unwrap_or(-1), pty_events));
            for c in &self.clients {
                let events = if c.outbuf.is_empty() {
                    libc::POLLIN
                } else {
                    libc::POLLIN | libc::POLLOUT
                };
                fds.push(pollfd(c.stream.as_raw_fd(), events));
            }

            if sys::poll(&mut fds, None).is_err() {
                // poll(2) only fails on resource exhaustion; the session can't
                // be served any more. End it as a hangup would.
                self.hang_up();
                return self.reap_child().unwrap_or(1);
            }

            if is_readable(&fds[SIGNALS])
                && let Some(status) = self.handle_signals()
            {
                // Deliver what the command printed right before exiting.
                self.drain_pty();
                return status;
            }

            if is_readable(&fds[PTY]) {
                self.read_pty();
            }
            if fds[PTY].revents & libc::POLLOUT != 0 {
                self.write_pty();
            }

            // Indices line up with the push order above; clients accepted below
            // are appended after them.
            for idx in 0..self.clients.len() {
                let slot = &fds[CLIENTS + idx];
                if slot.revents & libc::POLLOUT != 0 {
                    self.clients[idx].flush();
                }
                if is_readable(slot) {
                    let open = self.clients[idx].fill();
                    self.process_client_input(idx);
                    if !open {
                        self.clients[idx].state = ClientState::Dead;
                    }
                }
            }

            if is_readable(&fds[LISTENER]) {
                self.accept_clients();
            }

            self.prune_clients();
        }
    }

    fn pty_fd(&self) -> Option<RawFd> {
        self.pty.as_ref().map(AsRawFd::as_raw_fd)
    }

    /// Act on pending signals. Returns the command's exit status once it has
    /// been reaped.
    fn handle_signals(&mut self) -> Option<i32> {
        let mut status = None;
        for sig in self.signals.drain() {
            match sig {
                Signal::SIGCHLD => status = status.or_else(|| self.reap_child()),
                Signal::SIGTERM | Signal::SIGINT | Signal::SIGHUP => self.hang_up(),
                _ => {}
            }
        }
        status
    }

    fn reap_child(&self) -> Option<i32> {
        match waitpid(self.child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => Some(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => Some(128 + sig as i32),
            _ => None, // still running
        }
    }

    /// Hang up the terminal, as closing a terminal window does: the command's
    /// process group receives SIGHUP and the pty is closed, so anything still
    /// using it sees the hangup too. The command's exit is then handled as
    /// usual.
    fn hang_up(&mut self) {
        let _ = killpg(self.child, Signal::SIGHUP);
        self.close_pty();
    }

    fn close_pty(&mut self) {
        self.pty = None;
        self.pty_input.clear();
    }

    /// pty output -> retain for replay and broadcast to every attached client.
    /// Returns how many bytes were read (0 when nothing is available or the
    /// terminal closed).
    fn read_pty(&mut self) -> usize {
        let Some(fd) = self.pty_fd() else { return 0 };
        let mut buf = [0u8; MAX_PAYLOAD];
        match read_fd(fd, &mut buf) {
            Ok(0) => {
                self.close_pty();
                0
            }
            Ok(n) => {
                self.broadcast(&buf[..n]);
                n
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
            // EIO: every process has closed the terminal (Linux reports this
            // instead of EOF).
            Err(_) => {
                self.close_pty();
                0
            }
        }
    }

    /// Read the output still buffered in the pty after the command exited.
    fn drain_pty(&mut self) {
        let mut drained = 0;
        while drained < FINAL_DRAIN_CAP {
            match self.read_pty() {
                0 => break,
                n => drained += n,
            }
        }
    }

    fn broadcast(&mut self, bytes: &[u8]) {
        self.replay.extend(bytes);
        if self.replay.len() > REPLAY_CAP {
            self.replay.drain(..self.replay.len() - REPLAY_CAP);
        }
        let packet = Packet::Content(bytes.to_vec()).encode();
        for c in self.clients.iter_mut().filter(|c| c.is_attached()) {
            c.send_encoded(&packet);
        }
    }

    /// Queue keystrokes for the command and write as many as it will take.
    fn queue_input(&mut self, bytes: &[u8]) {
        if self.pty.is_none() {
            return;
        }
        let room = PTY_INPUT_CAP.saturating_sub(self.pty_input.len());
        self.pty_input
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
        self.write_pty();
    }

    fn write_pty(&mut self) {
        let Some(fd) = self.pty_fd() else { return };
        while !self.pty_input.is_empty() {
            match write_fd(fd, &self.pty_input) {
                Ok(n) if n > 0 => {
                    self.pty_input.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                // The terminal is gone; the read side notices and closes it.
                _ => {
                    self.pty_input.clear();
                    break;
                }
            }
        }
    }

    /// Decode and act on every complete packet buffered for client `idx`.
    fn process_client_input(&mut self, idx: usize) {
        while matches!(
            self.clients[idx].state,
            ClientState::Connected | ClientState::Attached(_)
        ) {
            match Packet::try_decode(&mut self.clients[idx].inbuf) {
                Ok(Some(packet)) => self.handle_packet(idx, packet),
                Ok(None) => break, // need more bytes
                Err(_) => self.clients[idx].state = ClientState::Dead,
            }
        }
    }

    fn handle_packet(&mut self, idx: usize, packet: Packet) {
        let ClientState::Attached(attachment) = &mut self.clients[idx].state else {
            // A greeted connection may attach, or make one request and leave.
            match packet {
                Packet::Attach { flags } => self.attach(idx, flags),
                Packet::Rename(new_name) => {
                    let reply = match self.rename(&new_name) {
                        Ok(()) => Packet::Renamed,
                        Err(msg) => Packet::Error(msg),
                    };
                    let client = &mut self.clients[idx];
                    client.send(&reply);
                    client.state = ClientState::Closing;
                }
                // Out of order, or server-to-client only.
                _ => self.clients[idx].state = ClientState::Dead,
            }
            return;
        };
        match packet {
            Packet::Content(bytes) => {
                if !attachment.readonly {
                    self.queue_input(&bytes);
                }
            }
            Packet::Resize { rows, cols } => {
                attachment.size = Some((rows, cols));
                self.apply_window_size();
            }
            Packet::Detach => self.clients[idx].state = ClientState::Dead,
            // Out of order, or server-to-client only.
            _ => self.clients[idx].state = ClientState::Dead,
        }
    }

    fn attach(&mut self, idx: usize, flags: u32) {
        self.attach_count += 1;
        let client = &mut self.clients[idx];
        client.state = ClientState::Attached(Attachment {
            readonly: flags & FLAG_READONLY != 0,
            lowpriority: flags & FLAG_LOWPRIORITY != 0,
            seq: self.attach_count,
            size: None,
        });
        // Replay recent output so the freshly-attached client repaints instead
        // of showing a blank screen.
        for chunk in self.replay.make_contiguous().chunks(MAX_PAYLOAD) {
            client.send(&Packet::Content(chunk.to_vec()));
        }
    }

    /// Size the pty to the controlling client: the most recently attached one
    /// that is neither read-only nor low-priority and has reported a size.
    fn apply_window_size(&mut self) {
        let controller = self
            .clients
            .iter()
            .filter_map(Client::attachment)
            .filter(|a| !a.readonly && !a.lowpriority && a.size.is_some())
            .max_by_key(|a| a.seq);
        let Some(size @ (rows, cols)) = controller.and_then(|a| a.size) else {
            return;
        };
        if self.applied_size == Some(size) {
            return;
        }
        if let Some(fd) = self.pty_fd()
            && pty::set_winsize(fd, &pty::winsize(rows, cols)).is_ok()
        {
            self.applied_size = Some(size);
        }
    }

    /// Rename the session's socket to `new_name` within its directory.
    fn rename(&mut self, new_name: &str) -> Result<(), String> {
        let dir = self
            .socket_path
            .parent()
            .ok_or("socket has no parent directory")?;
        let new_path = sockdir::socket_path(dir, new_name).map_err(|e| e.to_string())?;
        // link + unlink rather than rename(2): link fails if the target exists,
        // so a session created under that name meanwhile is never clobbered.
        fs::hard_link(&self.socket_path, &new_path).map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => format!("a session named '{new_name}' already exists"),
            _ => format!("cannot rename socket: {e}"),
        })?;
        if let Err(e) = fs::remove_file(&self.socket_path) {
            let _ = fs::remove_file(&new_path);
            return Err(format!("cannot rename socket: {e}"));
        }
        self.socket_path = new_path;
        Ok(())
    }

    fn accept_clients(&mut self) {
        loop {
            match self.listener.accept() {
                Ok((stream, _addr)) => self.add_client(stream),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                    ) => {}
                // WouldBlock: no more pending connections. Anything else (e.g.
                // EMFILE) is retried on the next wakeup.
                Err(_) => break,
            }
        }
    }

    /// Greet a new connection and start serving it.
    fn add_client(&mut self, stream: UnixStream) {
        if stream.set_nonblocking(true).is_err() {
            return; // dropping it closes the connection
        }
        let mut client = Client::new(stream);
        client.send(&Packet::Hello {
            version: PROTOCOL_VERSION,
            pid: self.child.as_raw().unsigned_abs(),
        });
        self.clients.push(client);
    }

    /// Drop finished clients and bring the window size and the socket's
    /// attach marker up to date.
    fn prune_clients(&mut self) {
        let before = self.clients.len();
        self.clients.retain(|c| !c.is_finished());
        if self.clients.len() != before {
            // The controlling client may have left.
            self.apply_window_size();
        }
        let attached = self.clients.iter().any(Client::is_attached);
        if attached != self.marked_attached {
            self.marked_attached = attached;
            let _ = sockdir::set_socket_state(&self.socket_path, attached);
        }
    }

    /// End the session: unpublish the socket, then tell every attached client
    /// the exit status, giving slow ones a bounded time to receive it.
    fn shut_down(&mut self, status: i32) {
        // Remove the socket first so nobody connects to (or lists) a session
        // that is going away.
        let _ = fs::remove_file(&self.socket_path);

        let exit = Packet::Exit(status).encode();
        for c in &mut self.clients {
            if c.is_attached() {
                c.send_encoded(&exit);
            }
            if !matches!(c.state, ClientState::Dead) {
                c.state = ClientState::Closing;
            }
        }

        let deadline = Instant::now() + EXIT_FLUSH_TIMEOUT;
        loop {
            self.clients.retain(|c| !c.is_finished());
            let remaining = deadline.saturating_duration_since(Instant::now());
            if self.clients.is_empty() || remaining.is_zero() {
                break;
            }
            let mut fds: Vec<_> = self
                .clients
                .iter()
                .map(|c| pollfd(c.stream.as_raw_fd(), libc::POLLOUT))
                .collect();
            if sys::poll(&mut fds, Some(remaining)).is_err() {
                break;
            }
            for (c, fd) in self.clients.iter_mut().zip(&fds) {
                if fd.revents & (libc::POLLOUT | libc::POLLHUP | libc::POLLERR) != 0 {
                    c.flush();
                }
            }
        }
    }
}

/// Fork the supervised command onto a new pty. Returns the master side
/// (non-blocking) and the child's pid.
fn spawn_command(cfg: &ServerConfig, ready: &OwnedFd) -> io::Result<(OwnedFd, Pid)> {
    // SAFETY: the server is single-threaded, so the child may run arbitrary
    // code before exec.
    match unsafe { forkpty(Some(&cfg.winsize), cfg.termios.as_ref()) }? {
        ForkptyResult::Parent { child, master } => {
            sys::set_nonblocking(master.as_raw_fd())?;
            Ok((master, child))
        }
        ForkptyResult::Child => exec_command(cfg, ready),
    }
}

/// In the pty child: prepare the process and exec the command. A failure is
/// reported through `ready`; on success, exec closes it (close-on-exec).
fn exec_command(cfg: &ServerConfig, ready: &OwnedFd) -> ! {
    // The command must start with default signal dispositions, not ours.
    signals::reset_to_default(&HANDLED_SIGNALS);
    signals::reset_to_default(&[Signal::SIGPIPE]);
    // Run where the session was created (the daemon itself sits at "/"). If
    // that directory is gone, the command starts at "/".
    if let Some(dir) = &cfg.workdir {
        let _ = chdir(dir.as_path());
    }
    // SAFETY: this process is single-threaded.
    unsafe {
        std::env::set_var("SM_SESSION", &cfg.session_name);
        std::env::set_var("SM_SOCKET", &cfg.socket_path);
    }
    let Err(err) = execvp(&cfg.argv[0], &cfg.argv);
    let what = format!("cannot execute {}", cfg.argv[0].to_string_lossy());
    let _ = write_all_fd(ready.as_raw_fd(), format!("{what}: {err}").as_bytes());
    exit_immediately(127)
}

/// Report a startup failure through the launcher's pipe and exit.
fn fail(ready: &OwnedFd, what: &str, err: impl Display) -> ! {
    let _ = write_all_fd(ready.as_raw_fd(), format!("{what}: {err}").as_bytes());
    exit_immediately(1)
}

/// Terminate a forked process without running exit handlers or flushing
/// stdio buffers it shares with its parent.
fn exit_immediately(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

fn pollfd(fd: RawFd, events: libc::c_short) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

fn is_readable(fd: &libc::pollfd) -> bool {
    fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
}
