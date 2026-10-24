//! The client side: connecting to a session (with the protocol handshake),
//! probing liveness, renaming, and attaching — putting the real terminal in raw
//! mode and proxying bytes between it and the server.

use std::io::{self, IsTerminal, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;

use crate::protocol::{self, FLAG_LOWPRIORITY, FLAG_READONLY, MAX_PAYLOAD, Packet};
use crate::pty;
use crate::signals::SignalPipe;
use crate::sys::{self, read_fd, write_all_fd};
use crate::term::{OutputFilter, TerminalGuard};

const STDIN: RawFd = libc::STDIN_FILENO;
const STDOUT: RawFd = libc::STDOUT_FILENO;

/// After the prefix key, this key detaches (screen-style `prefix d`). `D` too.
pub const DETACH_KEY: u8 = b'd';
/// How long to wait for the key after the prefix before deciding it was a
/// bare prefix press and forwarding it to the app. Keeps the prefix key usable
/// inside apps when it isn't immediately followed by `d`.
const PREFIX_TIMEOUT: Duration = Duration::from_millis(500);
/// How long to wait for the server's greeting or the reply to a request. A
/// live server answers immediately; this only bounds the wait on a wedged one.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

/// How the attach ended.
pub enum Outcome {
    /// User pressed the detach sequence (or the terminal went away).
    Detached,
    /// The supervised command exited with this status.
    Exited(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachOptions {
    /// Input is not forwarded; output is still shown.
    pub readonly: bool,
    /// Never control the session's window size.
    pub lowpriority: bool,
    /// Forward stdin verbatim: no raw mode, no detach key (`-p`).
    pub passthrough: bool,
    /// Prefix byte; press it then `d` to detach (default Ctrl-a = 0x01). Press
    /// it twice to send one literal prefix byte to the app.
    pub prefix_key: u8,
}

/// What answers on a session socket.
pub enum Liveness {
    /// A compatible server; `pid` is the supervised command's pid.
    Alive { pid: u32 },
    /// Something accepted the connection but did not greet us properly: a
    /// wedged server or one from an incompatible `sm` version. Must not be
    /// treated as stale — the session may well be running.
    Unresponsive(io::Error),
    /// Nothing is listening: the socket is missing, or stale (left behind by a
    /// server that died).
    Dead,
}

/// True if a connect error means no server is listening at the path at all.
pub fn is_absent(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
}

/// Determine whether a live, compatible server owns the socket at `path`.
pub fn probe(path: &Path) -> Liveness {
    match Connection::open(path) {
        Ok(conn) => Liveness::Alive { pid: conn.pid },
        Err(e) if is_absent(&e) => Liveness::Dead,
        Err(e) => Liveness::Unresponsive(e),
    }
}

/// An established connection to a session server, past the handshake.
pub struct Connection {
    stream: UnixStream,
    pid: u32,
}

impl Connection {
    /// Connect to the session at `path` and verify the server's greeting.
    pub fn open(path: &Path) -> io::Result<Connection> {
        Self::establish(UnixStream::connect(path)?)
    }

    /// Verify the server's greeting on an already connected stream.
    pub fn establish(mut stream: UnixStream) -> io::Result<Connection> {
        stream.set_read_timeout(Some(RESPONSE_TIMEOUT))?;
        let pid = protocol::read_hello(&mut stream).map_err(describe_timeout)?;
        stream.set_read_timeout(None)?;
        Ok(Connection { stream, pid })
    }

    /// Ask the server to rename its session (and socket) to `new_name`.
    /// Returns once the server has done so, or with the reason it refused.
    pub fn rename(mut self, new_name: &str) -> io::Result<()> {
        Packet::Rename(new_name.to_owned()).write_to(&mut self.stream)?;
        self.stream.set_read_timeout(Some(RESPONSE_TIMEOUT))?;
        match Packet::read_from(&mut self.stream).map_err(describe_timeout)? {
            Packet::Renamed => Ok(()),
            Packet::Error(msg) => Err(io::Error::other(msg)),
            other => Err(unexpected(&other)),
        }
    }

    /// Attach to the session and proxy the terminal until detach or exit.
    pub fn attach(self, opts: &AttachOptions) -> io::Result<Outcome> {
        let Connection { mut stream, .. } = self;
        let interactive = !opts.passthrough && io::stdin().is_terminal();

        // Without a terminal there is no window size to contribute, so such a
        // client must never be the one controlling it.
        let mut flags = 0;
        if opts.readonly {
            flags |= FLAG_READONLY;
        }
        if opts.lowpriority || !interactive {
            flags |= FLAG_LOWPRIORITY;
        }

        // Install the SIGWINCH handler before the size is first read, so a
        // resize in between is not lost.
        let sigwinch = if interactive {
            Some(SignalPipe::install(&[Signal::SIGWINCH])?)
        } else {
            None
        };
        Packet::Attach { flags }.write_to(&mut stream)?;

        let terminal = match sigwinch {
            Some(sigwinch) => Some(Terminal {
                _guard: TerminalGuard::enter(STDIN, STDOUT)?,
                sigwinch,
                prefix: PrefixDecoder::new(opts.prefix_key),
                filter: OutputFilter::new(),
            }),
            None => None,
        };
        let mut proxy = Proxy {
            sock: stream,
            inbuf: Vec::new(),
            readonly: opts.readonly,
            terminal,
            stdin_open: true,
        };
        if proxy.terminal.is_some() {
            proxy.send_window_size()?;
        }
        proxy.run()
    }
}

/// Client state that only exists when attached from a real terminal. Dropping
/// it restores the terminal and the previous SIGWINCH disposition.
struct Terminal {
    _guard: TerminalGuard,
    sigwinch: SignalPipe,
    prefix: PrefixDecoder,
    filter: OutputFilter,
}

/// The attach loop: shuttles bytes between stdin/stdout and the server.
struct Proxy {
    sock: UnixStream,
    /// Bytes received from the server that don't yet form a whole packet.
    inbuf: Vec<u8>,
    readonly: bool,
    /// `None` when stdin is not a terminal or in passthrough mode: input and
    /// output are then forwarded verbatim.
    terminal: Option<Terminal>,
    stdin_open: bool,
}

impl Proxy {
    fn run(&mut self) -> io::Result<Outcome> {
        const SOCK: usize = 0;
        const STDIN_SLOT: usize = 1;
        const SIGNALS: usize = 2;

        loop {
            // Fixed slots; a negative fd is ignored by poll(2).
            let stdin_fd = if self.stdin_open { STDIN } else { -1 };
            let signal_fd = self.terminal.as_ref().map_or(-1, |t| t.sigwinch.read_fd());
            let mut fds = [
                pollin(self.sock.as_raw_fd()),
                pollin(stdin_fd),
                pollin(signal_fd),
            ];
            // Only wait with a deadline while a prefix press is pending.
            let timeout = self
                .terminal
                .as_ref()
                .and_then(|t| t.prefix.deadline())
                .map(|deadline| deadline.saturating_duration_since(Instant::now()));
            sys::poll(&mut fds, timeout)?;

            // A bare prefix press whose follow-up key never came goes to the app.
            let expired = self
                .terminal
                .as_mut()
                .and_then(|t| t.prefix.expire(Instant::now()));
            if let Some(byte) = expired {
                self.send_input(&[byte])?;
            }

            if is_ready(&fds[SIGNALS]) {
                let resized = self
                    .terminal
                    .as_ref()
                    .is_some_and(|t| t.sigwinch.drain().contains(&Signal::SIGWINCH));
                if resized {
                    self.send_window_size()?;
                }
            }
            if is_ready(&fds[SOCK])
                && let Some(outcome) = self.read_server()?
            {
                return Ok(outcome);
            }
            if is_ready(&fds[STDIN_SLOT])
                && let Some(outcome) = self.read_stdin()?
            {
                return Ok(outcome);
            }
        }
    }

    /// Server -> terminal. Reads what is available and handles every complete
    /// packet in it.
    fn read_server(&mut self) -> io::Result<Option<Outcome>> {
        let mut buf = [0u8; 16 * 1024];
        let n = match self.sock.read(&mut buf) {
            Ok(0) => return Err(connection_lost()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(None),
            Err(_) => return Err(connection_lost()),
        };
        self.inbuf.extend_from_slice(&buf[..n]);
        while let Some(packet) = Packet::try_decode(&mut self.inbuf)? {
            match packet {
                Packet::Content(bytes) => self.write_output(&bytes)?,
                Packet::Exit(status) => return Ok(Some(Outcome::Exited(status))),
                Packet::Error(msg) => return Err(io::Error::other(msg)),
                other => return Err(unexpected(&other)),
            }
        }
        Ok(None)
    }

    /// Terminal -> server.
    fn read_stdin(&mut self) -> io::Result<Option<Outcome>> {
        let mut buf = [0u8; MAX_PAYLOAD];
        let n = match read_fd(STDIN, &mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e),
        };
        if n == 0 {
            // A terminal that closes is gone: detach. Piped input that ends just
            // stops; keep showing output until the session ends.
            if self.terminal.is_some() {
                return Ok(Some(self.detach()));
            }
            self.stdin_open = false;
            return Ok(None);
        }
        let decoded = match &mut self.terminal {
            Some(t) => t.prefix.feed(&buf[..n], Instant::now()),
            None => Decoded {
                forward: buf[..n].to_vec(),
                detach: false,
            },
        };
        // Keystrokes preceding a detach are delivered first.
        self.send_input(&decoded.forward)?;
        Ok(decoded.detach.then(|| self.detach()))
    }

    fn write_output(&mut self, bytes: &[u8]) -> io::Result<()> {
        match &mut self.terminal {
            // Strip keyboard-protocol negotiation so the terminal stays in the
            // classic encoding.
            Some(t) => write_all_fd(STDOUT, &t.filter.filter(bytes)),
            None => write_all_fd(STDOUT, bytes),
        }
    }

    fn send_input(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.readonly {
            return Ok(());
        }
        // The prefix decoder can emit one byte more than it read.
        for chunk in bytes.chunks(MAX_PAYLOAD) {
            self.send(&Packet::Content(chunk.to_vec()))?;
        }
        Ok(())
    }

    fn send_window_size(&mut self) -> io::Result<()> {
        let ws = pty::get_winsize(STDIN);
        self.send(&Packet::Resize {
            rows: ws.ws_row,
            cols: ws.ws_col,
        })
    }

    fn send(&mut self, packet: &Packet) -> io::Result<()> {
        packet
            .write_to(&mut self.sock)
            .map_err(|_| connection_lost())
    }

    fn detach(&mut self) -> Outcome {
        // Best effort: the server also notices the connection closing.
        let _ = self.send(&Packet::Detach);
        Outcome::Detached
    }
}

/// The two-key detach sequence, as a state machine over raw input bytes:
///
/// - `prefix` then `d`/`D` => detach.
/// - `prefix` then `prefix` => one literal prefix byte to the app.
/// - `prefix` then anything else => the prefix byte followed by that byte
///   (so the reserved key still reaches the app when it isn't a command).
/// - `prefix` alone, with no key following within [`PREFIX_TIMEOUT`] =>
///   forwarded as is.
/// - any other byte => forwarded unchanged.
///
/// A prefix at the end of one read resolves against the first byte of the
/// next.
struct PrefixDecoder {
    key: u8,
    /// When the pending prefix press happened, if one is pending.
    armed_at: Option<Instant>,
}

struct Decoded {
    /// Bytes for the app.
    forward: Vec<u8>,
    /// The detach sequence was completed (bytes after it are discarded).
    detach: bool,
}

impl PrefixDecoder {
    fn new(key: u8) -> Self {
        PrefixDecoder {
            key,
            armed_at: None,
        }
    }

    fn feed(&mut self, input: &[u8], now: Instant) -> Decoded {
        let mut forward = Vec::with_capacity(input.len() + 1);
        for &b in input {
            if self.armed_at.take().is_some() {
                if b.eq_ignore_ascii_case(&DETACH_KEY) {
                    return Decoded {
                        forward,
                        detach: true,
                    };
                }
                forward.push(self.key);
                if b != self.key {
                    forward.push(b);
                }
            } else if b == self.key {
                self.armed_at = Some(now);
            } else {
                forward.push(b);
            }
        }
        Decoded {
            forward,
            detach: false,
        }
    }

    /// When a pending prefix press times out, if one is pending.
    fn deadline(&self) -> Option<Instant> {
        self.armed_at.map(|at| at + PREFIX_TIMEOUT)
    }

    /// Disarm a pending prefix press that has timed out by `now`, returning the
    /// prefix byte to forward to the app.
    fn expire(&mut self, now: Instant) -> Option<u8> {
        let expired = self.deadline().is_some_and(|deadline| now >= deadline);
        expired.then(|| {
            self.armed_at = None;
            self.key
        })
    }
}

fn pollin(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

fn is_ready(fd: &libc::pollfd) -> bool {
    fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
}

fn connection_lost() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "lost connection to the session",
    )
}

fn unexpected(packet: &Packet) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected packet from server: {packet:?}"),
    )
}

/// Socket read timeouts surface as EAGAIN; say what actually happened.
fn describe_timeout(err: io::Error) -> io::Error {
    match err.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            io::Error::new(io::ErrorKind::TimedOut, "session server is not responding")
        }
        _ => err,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: u8 = 0x01; // Ctrl-a

    fn run(bytes: &[u8]) -> (Vec<u8>, bool, bool) {
        let mut decoder = PrefixDecoder::new(PREFIX);
        let decoded = decoder.feed(bytes, Instant::now());
        (decoded.forward, decoded.detach, decoder.armed_at.is_some())
    }

    #[test]
    fn plain_bytes_pass_through() {
        assert_eq!(run(b"hello"), (b"hello".to_vec(), false, false));
    }

    #[test]
    fn prefix_then_d_detaches() {
        let (out, detach, _) = run(&[PREFIX, b'd']);
        assert!(detach);
        assert!(out.is_empty());
        // Uppercase D too.
        assert!(run(&[PREFIX, b'D']).1);
    }

    #[test]
    fn double_prefix_sends_one_literal() {
        assert_eq!(run(&[PREFIX, PREFIX]), (vec![PREFIX], false, false));
    }

    #[test]
    fn prefix_then_other_forwards_both() {
        assert_eq!(run(&[PREFIX, b'x']), (vec![PREFIX, b'x'], false, false));
    }

    #[test]
    fn preceding_bytes_flushed_before_detach() {
        let (out, detach, _) = run(&[b'a', b'b', PREFIX, b'd']);
        assert_eq!(out, b"ab".to_vec());
        assert!(detach);
    }

    #[test]
    fn lone_trailing_prefix_stays_armed() {
        let mut decoder = PrefixDecoder::new(PREFIX);
        let now = Instant::now();
        let first = decoder.feed(&[b'z', PREFIX], now);
        assert_eq!(first.forward, b"z".to_vec());
        assert!(!first.detach);
        assert!(decoder.deadline().is_some()); // waiting for the next key
        // Next read resolves it.
        let second = decoder.feed(b"d", now);
        assert!(second.detach);
        assert!(second.forward.is_empty());
        assert!(decoder.deadline().is_none());
    }

    #[test]
    fn bare_prefix_is_forwarded_after_timeout() {
        let mut decoder = PrefixDecoder::new(PREFIX);
        let pressed = Instant::now();
        assert!(decoder.feed(&[PREFIX], pressed).forward.is_empty());
        assert_eq!(decoder.deadline(), Some(pressed + PREFIX_TIMEOUT));

        // Not yet: other activity before the deadline must not forward it…
        assert_eq!(decoder.expire(pressed + PREFIX_TIMEOUT / 2), None);
        // …nor push the deadline back.
        assert_eq!(decoder.deadline(), Some(pressed + PREFIX_TIMEOUT));

        assert_eq!(decoder.expire(pressed + PREFIX_TIMEOUT), Some(PREFIX));
        assert_eq!(decoder.deadline(), None);
        assert_eq!(decoder.expire(pressed + PREFIX_TIMEOUT * 2), None);
    }

    #[test]
    fn full_read_after_pending_prefix_can_exceed_one_packet() {
        // Why send_input chunks: a pending prefix plus a full read yields one
        // byte more than MAX_PAYLOAD.
        let mut decoder = PrefixDecoder::new(PREFIX);
        let now = Instant::now();
        decoder.feed(&[PREFIX], now);
        let decoded = decoder.feed(&[b'x'; MAX_PAYLOAD], now);
        assert_eq!(decoded.forward.len(), MAX_PAYLOAD + 1);
    }
}
