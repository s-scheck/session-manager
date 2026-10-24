//! Thin, EINTR-safe wrappers over raw-fd syscalls. Used for the pty master and
//! the real terminal (stdin/stdout), which carry unframed byte streams rather
//! than protocol packets, and for the `poll(2)` event loops.

use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::time::Duration;

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};

/// Read once into `buf`, retrying on EINTR. Returns 0 at EOF.
pub fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if let Ok(n) = usize::try_from(n) {
            return Ok(n);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Write once from `buf`, retrying on EINTR. Returns how many bytes were
/// written, which may be fewer than `buf.len()` on a non-blocking fd.
pub fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if let Ok(n) = usize::try_from(n) {
            return Ok(n);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Write the whole buffer, retrying on EINTR and short writes.
pub fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match write_fd(fd, buf)? {
            0 => return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0")),
            n => buf = &buf[n..],
        }
    }
    Ok(())
}

/// `poll(2)` with an optional timeout (`None` waits indefinitely). An
/// interrupted call reports zero ready descriptors, so callers simply
/// re-evaluate their state and poll again.
pub fn poll(fds: &mut [libc::pollfd], timeout: Option<Duration>) -> io::Result<usize> {
    let timeout_ms = timeout.map_or(-1, |t| {
        // Round up so a sub-millisecond remainder doesn't turn into a busy loop.
        libc::c_int::try_from(t.as_nanos().div_ceil(1_000_000)).unwrap_or(libc::c_int::MAX)
    });
    let nfds = libc::nfds_t::try_from(fds.len()).map_err(io::Error::other)?;
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), nfds, timeout_ms) };
    if let Ok(ready) = usize::try_from(rc) {
        return Ok(ready);
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::Interrupted {
        Ok(0)
    } else {
        Err(err)
    }
}

/// A pipe whose ends are both close-on-exec, so neither leaks into the
/// supervised command.
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (read, write) = nix::unistd::pipe()?;
    set_cloexec(read.as_raw_fd())?;
    set_cloexec(write.as_raw_fd())?;
    Ok((read, write))
}

pub fn set_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD)?);
    fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))?;
    Ok(())
}

pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}

/// Point stdin/stdout/stderr at /dev/null. Used by the daemon, which has no
/// terminal of its own, so stray reads/writes never touch the launching one.
pub fn redirect_stdio_to_devnull() -> io::Result<()> {
    let devnull = OwnedFd::from(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?,
    );
    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        nix::unistd::dup2(devnull.as_raw_fd(), target)?;
    }
    if devnull.as_raw_fd() <= libc::STDERR_FILENO {
        // A closed stdio slot was reused for /dev/null itself; it now *is* one
        // of the standard streams and must stay open.
        let _ = devnull.into_raw_fd();
    }
    Ok(())
}
