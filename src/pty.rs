//! Window-size helpers for terminals and the pty master.

use std::io;
use std::os::fd::RawFd;

/// A window size, matching `struct winsize` / `nix::pty::Winsize`.
pub type Winsize = libc::winsize;

/// Query the window size of the terminal on `fd` (TIOCGWINSZ). Falls back to a
/// sane 80x24 if the fd is not a terminal.
pub fn get_winsize(fd: RawFd) -> Winsize {
    let mut ws = winsize(0, 0);
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &raw mut ws) };
    if rc == -1 || ws.ws_row == 0 || ws.ws_col == 0 {
        ws.ws_row = 24;
        ws.ws_col = 80;
    }
    ws
}

/// Build a `Winsize` from explicit rows/cols (as carried by a Resize packet).
pub fn winsize(rows: u16, cols: u16) -> Winsize {
    Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// Apply a window size to the pty master (TIOCSWINSZ); the kernel delivers
/// SIGWINCH to the terminal's foreground process group if it changed.
pub fn set_winsize(fd: RawFd, ws: &Winsize) -> io::Result<()> {
    let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, ws) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
