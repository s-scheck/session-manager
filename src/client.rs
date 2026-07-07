//! The client: attaches to a running session, puts the real terminal in raw
//! mode, and proxies bytes between the terminal and the server.

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use nix::sys::signal::Signal;
use nix::sys::termios::{self, Termios};

use crate::protocol::{FLAG_LOWPRIORITY, FLAG_READONLY, MAX_PAYLOAD, Packet};
use crate::pty;
use crate::signals::SignalPipe;
use crate::sys::{read_fd, write_all_fd};
use crate::term::TerminalGuard;

const STDIN: RawFd = libc::STDIN_FILENO;
const STDOUT: RawFd = libc::STDOUT_FILENO;

/// After the prefix key, this byte detaches (screen-style `prefix d`). `D` too.
const DETACH_CMD: u8 = b'd';
/// How long (ms) to wait for the key after the prefix before deciding it was a
/// bare prefix press and forwarding it to the app. Keeps the prefix key usable
/// inside apps when it isn't immediately followed by `d`.
const PREFIX_TIMEOUT_MS: libc::c_int = 500;

/// How the attach ended.
pub enum Outcome {
    /// User pressed the detach key (or stdin closed in interactive mode).
    Detached,
    /// The supervised command exited with this status.
    Exited(i32),
    /// The server went away unexpectedly.
    ServerGone,
}

pub struct ClientConfig<'a> {
    pub socket_path: &'a Path,
    pub readonly: bool,
    pub lowpriority: bool,
    /// Prefix byte; press it then `d` to detach (default Ctrl-a = 0x01). Press
    /// it twice to send one literal prefix byte to the app.
    pub prefix_key: u8,
    /// Passthrough mode (-p): forward stdin verbatim, no raw mode / detach key.
    pub passthrough: bool,
}

/// Capture the terminal's current termios so the pty can be created with the
/// same modes (used by the session creator, not by a plain attach).
pub fn current_termios() -> Option<Termios> {
    if unsafe { libc::isatty(STDIN) } != 1 {
        return None;
    }
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(STDIN) };
    termios::tcgetattr(borrowed).ok()
}

/// Ask the running server to rename its session (and socket) to `new_name`.
/// `new_path` is where the renamed socket should end up; the caller is expected
/// to have already cleared any stale file there and confirmed no live session
/// owns it. Returns once the server has performed the rename.
pub fn rename(old_path: &Path, new_path: &Path, new_name: &str) -> io::Result<()> {
    let mut sock = UnixStream::connect(old_path)?;
    Packet::Rename(new_name.to_string()).write_to(&mut sock)?;
    // The server renames and then drops this control connection. Wait for the
    // new socket path to appear as confirmation.
    for _ in 0..100 {
        if new_path.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "server did not complete the rename",
    ))
}

/// Attach to the session and run the proxy loop until detach or exit.
pub fn attach(cfg: ClientConfig) -> io::Result<Outcome> {
    let mut sock = UnixStream::connect(cfg.socket_path)?;

    // Announce ourselves and our flags.
    let mut flags = 0;
    if cfg.readonly {
        flags |= FLAG_READONLY;
    }
    if cfg.lowpriority || cfg.passthrough {
        flags |= FLAG_LOWPRIORITY;
    }
    Packet::Attach { flags }.write_to(&mut sock)?;

    let interactive = !cfg.passthrough && unsafe { libc::isatty(STDIN) } == 1;

    // Raw mode + alternate screen for the duration of the attach. Dropping the
    // guard restores the terminal no matter how we leave.
    let _guard = if interactive {
        Some(TerminalGuard::enter(STDIN, STDOUT)?)
    } else {
        None
    };

    // Tell the server our size right away so the child matches this terminal.
    if interactive {
        let ws = pty::get_winsize(STDIN);
        let _ = Packet::Resize {
            rows: ws.ws_row,
            cols: ws.ws_col,
        }
        .write_to(&mut sock);
    }

    let sigwinch = SignalPipe::install(&[Signal::SIGWINCH])?;

    run_loop(cfg, &mut sock, &sigwinch, interactive)
}

fn run_loop(
    cfg: ClientConfig,
    sock: &mut UnixStream,
    sigwinch: &SignalPipe,
    interactive: bool,
) -> io::Result<Outcome> {
    let sock_fd = sock.as_raw_fd();
    let signal_fd = sigwinch.read_fd();
    let mut stdin_open = true;
    let mut need_resize = false;
    // True after the prefix key was pressed and we're waiting for the next key.
    let mut prefix_armed = false;
    // Keeps the real terminal in the classic keyboard encoding (see OutputFilter).
    let mut out_filter = OutputFilter::new();

    loop {
        let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(3);
        pfds.push(pollin(signal_fd));
        pfds.push(pollin(sock_fd));
        let stdin_slot = if stdin_open {
            pfds.push(pollin(STDIN));
            Some(pfds.len() - 1)
        } else {
            None
        };

        // Only wait with a deadline while a prefix press is pending; otherwise
        // block indefinitely.
        let timeout = if prefix_armed { PREFIX_TIMEOUT_MS } else { -1 };
        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, timeout) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            // Timed out waiting for the key after the prefix: it was a bare
            // prefix press, so forward it to the app.
            if prefix_armed {
                prefix_armed = false;
                if !cfg.readonly {
                    let _ = Packet::Content(vec![cfg.prefix_key]).write_to(sock);
                }
            }
            continue;
        }

        let ready =
            |i: usize| pfds[i].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;

        // Window-size changes.
        if ready(0) {
            for sig in sigwinch.drain() {
                if sig == Signal::SIGWINCH as i32 {
                    need_resize = true;
                }
            }
        }

        // Server -> terminal.
        if ready(1) {
            match Packet::read_from(sock) {
                Ok(Packet::Content(bytes)) => {
                    if interactive {
                        // Strip keyboard-protocol negotiation so the terminal
                        // stays in the classic encoding.
                        let filtered = out_filter.filter(&bytes);
                        if !filtered.is_empty() {
                            write_all_fd(STDOUT, &filtered)?;
                        }
                    } else {
                        write_all_fd(STDOUT, &bytes)?;
                    }
                }
                Ok(Packet::Exit(status)) => return Ok(Outcome::Exited(status)),
                Ok(_) => {} // Pid / stray control packets: ignore
                Err(_) => return Ok(Outcome::ServerGone),
            }
        }

        // Terminal -> server.
        if let Some(slot) = stdin_slot
            && ready(slot)
        {
            let mut buf = [0u8; MAX_PAYLOAD];
            match read_fd(STDIN, &mut buf) {
                Ok(0) => {
                    // stdin closed. Interactive: treat as detach. Passthrough:
                    // stop reading but keep showing output until the server exits.
                    if interactive {
                        let _ = Packet::Detach.write_to(sock);
                        return Ok(Outcome::Detached);
                    }
                    stdin_open = false;
                }
                Ok(n) => {
                    if interactive {
                        // Run the bytes through the prefix state machine. Any
                        // output is forwarded first, then a detach (if any) so
                        // preceding keystrokes aren't lost.
                        let (out, detach) =
                            process_input(&buf[..n], &mut prefix_armed, cfg.prefix_key);
                        if !cfg.readonly && !out.is_empty() {
                            Packet::Content(out).write_to(sock)?;
                        }
                        if detach {
                            let _ = Packet::Detach.write_to(sock);
                            return Ok(Outcome::Detached);
                        }
                    } else if !cfg.readonly {
                        // Passthrough / non-tty: forward verbatim, no prefix handling.
                        Packet::Content(buf[..n].to_vec()).write_to(sock)?;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }

        // Recompute and push the new size.
        if need_resize {
            need_resize = false;
            let ws = pty::get_winsize(STDIN);
            let _ = Packet::Resize {
                rows: ws.ws_row,
                cols: ws.ws_col,
            }
            .write_to(sock);
        }
    }
}

fn pollin(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// Strips terminal keyboard-protocol negotiation from application output so the
/// real terminal stays in the classic byte encoding.
///
/// A non-emulating session manager can't properly proxy the kitty keyboard
/// protocol or xterm's modifyOtherKeys across attach/detach: if a program
/// (e.g. neovim) enables them, the sequences reach the real terminal, and after
/// detach the outer shell is left receiving `CSI …u` gibberish for Ctrl keys.
/// By dropping the negotiation sequences here, Ctrl keys keep arriving as plain
/// control bytes (so detach detection is reliable) and nothing leaks out.
///
/// Only three tightly-scoped forms are removed, distinguished by a private
/// intro byte and final byte — ordinary SGR/cursor/DEC-mode sequences are
/// untouched:
/// - `CSI > … u`, `CSI = … u`, `CSI ? … u`, `CSI < … u`  (kitty keyboard protocol)
/// - `CSI > … m`                                         (xterm key-modifier options)
///
/// The state persists across calls so a sequence split across reads is handled.
#[derive(Default)]
pub struct OutputFilter {
    state: FilterState,
    marker: u8,
    params: Vec<u8>,
}

#[derive(Default, Clone, Copy)]
enum FilterState {
    #[default]
    Ground,
    Esc,
    Csi,
    Private,
}

impl OutputFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn filter(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            match self.state {
                FilterState::Ground => {
                    if b == 0x1b {
                        self.state = FilterState::Esc;
                    } else {
                        out.push(b);
                    }
                }
                FilterState::Esc => {
                    if b == b'[' {
                        self.state = FilterState::Csi;
                    } else if b == 0x1b {
                        out.push(0x1b); // a pending ESC; keep waiting on this one
                    } else {
                        out.push(0x1b);
                        out.push(b);
                        self.state = FilterState::Ground;
                    }
                }
                FilterState::Csi => {
                    if b == b'>' || b == b'=' || b == b'?' || b == b'<' {
                        self.marker = b;
                        self.params.clear();
                        self.state = FilterState::Private;
                    } else {
                        // Ordinary CSI: not a target, emit prefix + byte verbatim.
                        out.extend_from_slice(b"\x1b[");
                        out.push(b);
                        self.state = FilterState::Ground;
                    }
                }
                FilterState::Private => {
                    if (0x20..=0x3f).contains(&b) {
                        self.params.push(b); // parameter / intermediate byte
                    } else {
                        // Final byte (or a malformed terminator): decide keep/drop.
                        let drop = b == b'u' || (self.marker == b'>' && b == b'm');
                        if !drop {
                            out.extend_from_slice(b"\x1b[");
                            out.push(self.marker);
                            out.extend_from_slice(&self.params);
                            out.push(b);
                        }
                        self.params.clear();
                        self.state = FilterState::Ground;
                    }
                }
            }
        }
        out
    }
}

/// Run raw input bytes through the two-key prefix state machine.
///
/// - `prefix` then `d`/`D` => detach (returns `true` as the second element).
/// - `prefix` then `prefix` => one literal prefix byte to the app.
/// - `prefix` then anything else => the prefix byte followed by that byte
///   (so the reserved key still reaches the app when it isn't a command).
/// - any other byte => forwarded unchanged.
///
/// `armed` carries the "prefix seen, awaiting next key" state across calls, so a
/// prefix at the end of one read resolves against the first byte of the next.
fn process_input(input: &[u8], armed: &mut bool, prefix: u8) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(input.len() + 1);
    for &b in input {
        if *armed {
            *armed = false;
            if b == DETACH_CMD || b == DETACH_CMD.to_ascii_uppercase() {
                return (out, true);
            } else if b == prefix {
                out.push(prefix);
            } else {
                out.push(prefix);
                out.push(b);
            }
        } else if b == prefix {
            *armed = true;
        } else {
            out.push(b);
        }
    }
    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: u8 = 0x01; // Ctrl-a

    fn run(bytes: &[u8]) -> (Vec<u8>, bool, bool) {
        let mut armed = false;
        let (out, detach) = process_input(bytes, &mut armed, PREFIX);
        (out, detach, armed)
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

    fn filtered(input: &[u8]) -> Vec<u8> {
        OutputFilter::new().filter(input)
    }

    #[test]
    fn filter_passes_plain_and_sgr() {
        assert_eq!(filtered(b"hello"), b"hello".to_vec());
        // SGR color has no private intro byte -> untouched.
        assert_eq!(
            filtered(b"\x1b[31mred\x1b[0m"),
            b"\x1b[31mred\x1b[0m".to_vec()
        );
    }

    #[test]
    fn filter_keeps_dec_private_modes() {
        // DEC private modes end in h/l and must pass (cursor, alt screen, paste).
        assert_eq!(filtered(b"\x1b[?25h"), b"\x1b[?25h".to_vec());
        assert_eq!(filtered(b"\x1b[?1049l"), b"\x1b[?1049l".to_vec());
        assert_eq!(filtered(b"\x1b[?2004h"), b"\x1b[?2004h".to_vec());
    }

    #[test]
    fn filter_drops_kitty_keyboard() {
        assert_eq!(filtered(b"\x1b[>1u"), b"".to_vec()); // push
        assert_eq!(filtered(b"\x1b[<1u"), b"".to_vec()); // pop
        assert_eq!(filtered(b"\x1b[=5;1u"), b"".to_vec()); // set
        assert_eq!(filtered(b"\x1b[?u"), b"".to_vec()); // query
        assert_eq!(filtered(b"a\x1b[>1ub"), b"ab".to_vec()); // surrounded
    }

    #[test]
    fn filter_drops_modify_other_keys() {
        assert_eq!(filtered(b"\x1b[>4;0m"), b"".to_vec());
        assert_eq!(filtered(b"\x1b[>4;2m"), b"".to_vec());
        // SGR (no '>') is not affected even though it ends in 'm'.
        assert_eq!(filtered(b"\x1b[1;31m"), b"\x1b[1;31m".to_vec());
    }

    #[test]
    fn filter_handles_split_sequence() {
        let mut f = OutputFilter::new();
        let mut out = f.filter(b"x\x1b[>1");
        out.extend(f.filter(b"u y"));
        assert_eq!(out, b"x y".to_vec());
    }

    #[test]
    fn lone_trailing_prefix_stays_armed() {
        let mut armed = false;
        let (out, detach) = process_input(&[b'z', PREFIX], &mut armed, PREFIX);
        assert_eq!(out, b"z".to_vec());
        assert!(!detach);
        assert!(armed); // waiting for the next key
        // Next read resolves it.
        let (out2, detach2) = process_input(b"d", &mut armed, PREFIX);
        assert!(detach2);
        assert!(out2.is_empty());
    }
}
