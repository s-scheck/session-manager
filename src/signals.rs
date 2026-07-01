//! Signal handling via the self-pipe trick.
//!
//! Doing real work inside a signal handler is not sound in Rust (allocation,
//! locks, most of std are not async-signal-safe). Instead each handler does the
//! one thing that *is* async-signal-safe — `write()` a single byte (the signal
//! number) into a pipe. The read end lives in the process's `poll` set, so the
//! event loop wakes up and handles the signal in normal code.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
use nix::unistd::pipe;

// Write end of the self-pipe, published for the signal handler to find. -1
// until installed.
static SIGNAL_PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn handler(sig: libc::c_int) {
    let fd = SIGNAL_PIPE_WRITE.load(Ordering::SeqCst);
    if fd >= 0 {
        let byte = [sig as u8];
        // Async-signal-safe. Ignore the result: a full pipe just means the
        // event loop hasn't drained yet, and it will see this signal's kind
        // from an earlier byte anyway.
        unsafe {
            libc::write(fd, byte.as_ptr().cast(), 1);
        }
    }
}

/// Owns the self-pipe. The read end is polled; signals arrive as bytes.
pub struct SignalPipe {
    read: OwnedFd,
    _write: OwnedFd,
}

impl SignalPipe {
    /// Install `handler` for each of `signals` and return the pipe to poll.
    pub fn install(signals: &[Signal]) -> nix::Result<SignalPipe> {
        let (read, write) = pipe()?;
        set_nonblock(read.as_raw_fd());
        set_nonblock(write.as_raw_fd());
        SIGNAL_PIPE_WRITE.store(write.as_raw_fd(), Ordering::SeqCst);

        let action = SigAction::new(
            SigHandler::Handler(handler),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );
        for &sig in signals {
            unsafe { sigaction(sig, &action)? };
        }
        Ok(SignalPipe {
            read,
            _write: write,
        })
    }

    pub fn read_fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }

    /// Drain and return every pending signal number.
    pub fn drain(&self) -> Vec<i32> {
        let mut buf = [0u8; 64];
        let mut sigs = Vec::new();
        loop {
            match crate::sys::read_fd(self.read.as_raw_fd(), &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    sigs.extend(buf[..n].iter().map(|&b| b as i32));
                    if n < buf.len() {
                        break;
                    }
                }
                Err(_) => break, // EWOULDBLOCK (pipe empty) or a transient error
            }
        }
        sigs
    }
}

/// Set a handful of signals to be ignored (SIG_IGN) — e.g. SIGPIPE/SIGHUP.
pub fn ignore(signals: &[Signal]) {
    let action = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
    for &sig in signals {
        let _ = unsafe { sigaction(sig, &action) };
    }
}

fn set_nonblock(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags != -1 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}
