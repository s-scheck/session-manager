//! Real-terminal handling for the client: raw mode + alternate screen, with
//! guaranteed restoration on every exit path via `Drop`, and the filter that
//! keeps the terminal in the classic keyboard encoding while attached.

use std::io::{self, IsTerminal};
use std::os::fd::{BorrowedFd, RawFd};

use nix::sys::termios::{self, SetArg, Termios};

use crate::sys::write_all_fd;

// Enter the alternate screen buffer and home the cursor.
const ENTER_ALT: &[u8] = b"\x1b[?1049h\x1b[H";

// Force the classic keyboard encoding on attach: pop any kitty keyboard
// protocol entry and turn off xterm's modifyOtherKeys. Combined with filtering
// these out of application output (see OutputFilter), this keeps Ctrl keys
// arriving as plain control bytes so detach detection is reliable.
const DISABLE_KBD: &[u8] = b"\x1b[<1u\x1b[>4;0m";

// Full cleanup on detach: leave the alternate screen, show the cursor, and turn
// off input modes a program inside the session may have enabled (enhanced
// keyboard, mouse reporting, bracketed paste) so the outer shell is left clean
// even when you detach from inside that program.
const RESET_MODES: &[u8] = b"\x1b[?25h\x1b[?1049l\x1b[<1u\x1b[>4;0m\
\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l";

/// Capture stdin's terminal modes, if it is a terminal, so a new session's pty
/// can start out matching the user's terminal.
pub fn current_termios() -> Option<Termios> {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return None;
    }
    termios::tcgetattr(stdin).ok()
}

/// Puts the controlling terminal into raw mode + alternate screen for the
/// duration of an attach, restoring the original state when dropped. Restoring
/// on `Drop` means a panic or early return can't leave the user's terminal
/// wedged — the Rust equivalent of abduco's `atexit` handler.
pub struct TerminalGuard {
    tty: RawFd,
    stdout: RawFd,
    original: Termios,
}

impl TerminalGuard {
    /// Save the current termios of `tty`, switch to raw mode, and enter the
    /// alternate screen (output written to `stdout`).
    pub fn enter(tty: RawFd, stdout: RawFd) -> io::Result<TerminalGuard> {
        let borrowed = unsafe { BorrowedFd::borrow_raw(tty) };
        let original = termios::tcgetattr(borrowed)?;

        let mut raw = original.clone();
        // cfmakeraw clears ECHO/ICANON/ISIG/IEXTEN, the input translation and
        // XON/XOFF flow control, and OPOST, and sets VMIN=1/VTIME=0 — exactly
        // the flag surgery abduco does by hand.
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(borrowed, SetArg::TCSANOW, &raw)?;

        // From here on the terminal is modified, so the guard must exist: if a
        // write below fails, dropping it restores the terminal.
        let guard = TerminalGuard {
            tty,
            stdout,
            original,
        };
        write_all_fd(stdout, ENTER_ALT)?;
        write_all_fd(stdout, DISABLE_KBD)?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort restore; nothing useful to do if these fail while tearing
        // down.
        let _ = write_all_fd(self.stdout, RESET_MODES);
        let borrowed = unsafe { BorrowedFd::borrow_raw(self.tty) };
        let _ = termios::tcsetattr(borrowed, SetArg::TCSADRAIN, &self.original);
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
