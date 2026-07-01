//! Pseudo-terminal creation and window-size helpers.

use std::io;
use std::os::fd::RawFd;

/// A window size, matching `struct winsize` / `nix::pty::Winsize`.
pub type Winsize = libc::winsize;

/// Query the window size of the terminal on `fd` (TIOCGWINSZ). Falls back to a
/// sane 80x24 if the fd is not a terminal.
pub fn get_winsize(fd: RawFd) -> Winsize {
    let mut ws: Winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    if rc == -1 || ws.ws_row == 0 || ws.ws_col == 0 {
        ws.ws_row = 24;
        ws.ws_col = 80;
    }
    ws
}

/// Build a `Winsize` from explicit rows/cols (as carried by a Resize packet).
pub fn winsize_from(rows: u16, cols: u16) -> Winsize {
    let mut ws: Winsize = unsafe { std::mem::zeroed() };
    ws.ws_row = rows;
    ws.ws_col = cols;
    ws
}

/// Apply a window size to the pty master (TIOCSWINSZ). Errors are non-fatal to
/// the caller (the child just keeps its old size).
pub fn set_winsize(fd: RawFd, ws: &Winsize) -> io::Result<()> {
    let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, ws) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
