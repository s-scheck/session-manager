//! Signal handling via the self-pipe trick.
//!
//! Doing real work inside a signal handler is not sound in Rust (allocation,
//! locks, most of std are not async-signal-safe). Instead each handler does the
//! one thing that *is* async-signal-safe — `write()` a single byte (the signal
//! number) into a pipe. The read end lives in the process's `poll` set, so the
//! event loop wakes up and handles the signal in normal code.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

use nix::errno::Errno;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};

use crate::sys;

// Write end of the active self-pipe, published for the signal handler to find.
// -1 while no `SignalPipe` is installed.
static SIGNAL_PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn handler(sig: libc::c_int) {
    // The interrupted code may be about to inspect errno; don't clobber it.
    let saved_errno = Errno::last_raw();
    let fd = SIGNAL_PIPE_WRITE.load(Ordering::SeqCst);
    if fd >= 0 {
        // Signal numbers are small positive integers, so the cast is lossless.
        let byte = [sig as u8];
        // Async-signal-safe. Ignore the result: a full pipe just means the
        // event loop hasn't drained yet, and it will see this signal's kind
        // from an earlier byte anyway.
        unsafe {
            libc::write(fd, byte.as_ptr().cast(), 1);
        }
    }
    Errno::set_raw(saved_errno);
}

/// Owns the self-pipe and the handlers routed into it. Only one may be
/// installed per process at a time; dropping it restores the previous
/// dispositions of its signals.
pub struct SignalPipe {
    read: OwnedFd,
    _write: OwnedFd,
    previous: Vec<(Signal, SigAction)>,
}

impl SignalPipe {
    /// Route each of `signals` into a new self-pipe and return it for polling.
    pub fn install(signals: &[Signal]) -> io::Result<SignalPipe> {
        let (read, write) = sys::pipe()?;
        sys::set_nonblocking(read.as_raw_fd())?;
        sys::set_nonblocking(write.as_raw_fd())?;
        SIGNAL_PIPE_WRITE
            .compare_exchange(-1, write.as_raw_fd(), Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "signal pipe already installed",
                )
            })?;

        // Constructed before installing any handler, so that a failure part-way
        // through still restores whatever was installed (via Drop).
        let mut pipe = SignalPipe {
            read,
            _write: write,
            previous: Vec::with_capacity(signals.len()),
        };
        let action = SigAction::new(
            SigHandler::Handler(handler),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );
        for &sig in signals {
            let previous = unsafe { sigaction(sig, &action)? };
            pipe.previous.push((sig, previous));
        }
        Ok(pipe)
    }

    pub fn read_fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }

    /// Drain and return every pending signal.
    pub fn drain(&self) -> Vec<Signal> {
        let mut buf = [0u8; 64];
        let mut sigs = Vec::new();
        // Stops at EOF, at EWOULDBLOCK (pipe empty) or on any other error.
        while let Ok(n @ 1..) = sys::read_fd(self.read.as_raw_fd(), &mut buf) {
            sigs.extend(
                buf[..n]
                    .iter()
                    .filter_map(|&b| Signal::try_from(i32::from(b)).ok()),
            );
        }
        sigs
    }
}

impl Drop for SignalPipe {
    fn drop(&mut self) {
        for (sig, previous) in self.previous.iter().rev() {
            let _ = unsafe { sigaction(*sig, previous) };
        }
        // Unpublish only after no handler can fire into the pipe any more; the
        // fds themselves are closed after this, when the fields drop.
        SIGNAL_PIPE_WRITE.store(-1, Ordering::SeqCst);
    }
}

/// Set signals to be ignored (`SIG_IGN`).
pub fn ignore(signals: &[Signal]) {
    set_disposition(signals, SigHandler::SigIgn);
}

/// Restore the default disposition (`SIG_DFL`) of signals. Used in a child
/// before `exec`: exec resets *handled* signals but keeps *ignored* ones (Rust's
/// runtime ignores SIGPIPE), which the new program must not inherit.
pub fn reset_to_default(signals: &[Signal]) {
    set_disposition(signals, SigHandler::SigDfl);
}

fn set_disposition(signals: &[Signal], handler: SigHandler) {
    let action = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
    for &sig in signals {
        let _ = unsafe { sigaction(sig, &action) };
    }
}
