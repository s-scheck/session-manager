//! Real-terminal handling for the client: raw mode + alternate screen, with
//! guaranteed restoration on every exit path via `Drop`.

use std::io;
use std::os::fd::{BorrowedFd, RawFd};

use nix::sys::termios::{self, SetArg, Termios};

use crate::sys::write_all_fd;

// Enter the alternate screen buffer and home the cursor.
const ENTER_ALT: &[u8] = b"\x1b[?1049h\x1b[H";

// Force the classic keyboard encoding on attach: pop any kitty keyboard
// protocol entry and turn off xterm's modifyOtherKeys. Combined with filtering
// these out of application output (see client::OutputFilter), this keeps Ctrl
// keys arriving as plain control bytes so detach detection is reliable.
const DISABLE_KBD: &[u8] = b"\x1b[<1u\x1b[>4;0m";

// Full cleanup on detach: leave the alternate screen, show the cursor, and turn
// off input modes a program inside the session may have enabled (enhanced
// keyboard, mouse reporting, bracketed paste) so the outer shell is left clean
// even when you detach from inside that program.
const RESET_MODES: &[u8] = b"\x1b[?25h\x1b[?1049l\x1b[<1u\x1b[>4;0m\
\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l";

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

        write_all_fd(stdout, ENTER_ALT)?;
        write_all_fd(stdout, DISABLE_KBD)?;

        Ok(TerminalGuard {
            tty,
            stdout,
            original,
        })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort restore; nothing useful to do if these fail while tearing
        // down.
        let borrowed = unsafe { BorrowedFd::borrow_raw(self.tty) };
        let _ = termios::tcsetattr(borrowed, SetArg::TCSANOW, &self.original);
        let _ = write_all_fd(self.stdout, RESET_MODES);
    }
}
