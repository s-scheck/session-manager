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
    /// Byte that triggers a detach (default Ctrl-o = 0x0F).
    pub detach_key: u8,
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

        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
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
                Ok(Packet::Content(bytes)) => write_all_fd(STDOUT, &bytes)?,
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
                    // Detach key is checked on the first byte of a read, as in abduco.
                    if interactive && n >= 1 && buf[0] == cfg.detach_key {
                        let _ = Packet::Detach.write_to(sock);
                        return Ok(Outcome::Detached);
                    }
                    if !cfg.readonly {
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
