//! Socket-directory resolution and the security model around it, plus session
//! listing and liveness probing.
//!
//! Session state is encoded in the socket file's permission bits (an attached
//! session gets the owner-execute bit set), so `list_sessions` can read status
//! from `stat(2)` alone without connecting. Liveness (is the server still
//! there?) is confirmed by connecting and reading the server's `Pid` packet.

use std::ffi::CString;
use std::fs;
use std::io::{self, ErrorKind};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::protocol::Packet;

/// Application directory name used inside shared/base directories.
const APP: &str = "sm";
/// Personal directory name created under $HOME.
const HOME_DIR: &str = ".session_manager";

/// macOS/BSD `sun_path` holds 104 bytes including the NUL terminator.
const SUN_PATH_MAX: usize = 103;

// Owner-execute bit toggled to mark a session as "attached".
const ATTACHED_BIT: u32 = 0o100;
const BASE_MODE: u32 = 0o600;

/// Resolve the directory in which session sockets live, creating it with
/// hardened permissions. Tries, in order: `$SM_SOCKET_DIR`, `$HOME/.session_manager`,
/// `$TMPDIR/sm/$USER`, `/tmp/sm/$USER` — returning the first that can be created
/// and verified as owned by us with no group/other access.
pub fn resolve_socket_dir() -> io::Result<PathBuf> {
    let mut last_err: Option<io::Error> = None;
    let user = username();

    // (candidate personal dir, is it created directly vs. via a shared parent)
    let mut candidates: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();

    if let Some(dir) = env_nonempty("SM_SOCKET_DIR") {
        candidates.push((PathBuf::from(dir), None));
    }
    if let Some(home) = env_nonempty("HOME") {
        candidates.push((Path::new(&home).join(HOME_DIR), None));
    }
    if let Some(tmp) = env_nonempty("TMPDIR") {
        let base = Path::new(&tmp).join(APP);
        candidates.push((base.join(&user), Some(base)));
    }
    {
        let base = PathBuf::from("/tmp").join(APP);
        candidates.push((base.join(&user), Some(base)));
    }

    for (dir, shared_parent) in candidates {
        match ensure_dir(&dir, shared_parent.as_deref()) {
            Ok(()) => return Ok(dir),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("no usable socket directory")))
}

/// Full path of the socket for `name` inside `dir`, validating the session name
/// and the resulting path length (Unix socket paths are tightly bounded).
pub fn socket_path(dir: &Path, name: &str) -> io::Result<PathBuf> {
    if name.is_empty() || name.contains('/') || name.contains('\0') {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid session name",
        ));
    }
    let path = dir.join(name);
    if path.as_os_str().len() > SUN_PATH_MAX {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "socket path too long ({} > {SUN_PATH_MAX}); set SM_SOCKET_DIR to a shorter path",
                path.as_os_str().len()
            ),
        ));
    }
    Ok(path)
}

/// Mark a session socket as attached (owner-execute set) or detached.
pub fn set_socket_state(path: &Path, attached: bool) -> io::Result<()> {
    let mode = if attached {
        BASE_MODE | ATTACHED_BIT
    } else {
        BASE_MODE
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

/// One entry in the session listing.
pub struct SessionInfo {
    pub name: String,
    /// `*` attached, `-` detached, `?` stale/unresponsive.
    pub status: char,
    pub mtime: Option<SystemTime>,
    pub pid: Option<u32>,
}

/// Enumerate sessions in `dir`, deriving attached/detached from the socket mode
/// and liveness from a connect+Pid probe.
pub fn list_sessions(dir: &Path) -> io::Result<Vec<SessionInfo>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.file_type().is_socket() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let mode = meta.permissions().mode();
        let pid = probe(&path);
        let status = if pid.is_none() {
            '?'
        } else if mode & ATTACHED_BIT != 0 {
            '*'
        } else {
            '-'
        };
        out.push(SessionInfo {
            name,
            status,
            mtime: meta.modified().ok(),
            pid,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// True if a live server answers on this socket.
pub fn session_alive(path: &Path) -> bool {
    probe(path).is_some()
}

/// Connect to the socket and read the server's `Pid` packet, returning the pid
/// if the server is alive and responsive. Short timeouts keep listing snappy
/// even against a wedged socket.
fn probe(path: &Path) -> Option<u32> {
    let mut stream = UnixStream::connect(path).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .ok()?;
    match Packet::read_from(&mut stream) {
        Ok(Packet::Pid(pid)) => Some(pid),
        _ => None,
    }
}

// ---- internal helpers -------------------------------------------------------

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn username() -> String {
    if let Some(u) = env_nonempty("USER") {
        return u;
    }
    // Fall back to the numeric uid if $USER is unset.
    format!("{}", unsafe { libc::getuid() })
}

/// Ensure `dir` exists as a 0700 directory owned by us. If `shared_parent` is
/// given, first create that parent world-writable + sticky (like `/tmp`) so
/// multiple users can each own a private subdirectory beneath it.
fn ensure_dir(dir: &Path, shared_parent: Option<&Path>) -> io::Result<()> {
    let prev_umask = unsafe { libc::umask(0) };
    let result = (|| {
        if let Some(parent) = shared_parent {
            // 0777 | sticky; ignore EEXIST.
            mkdir(parent, 0o1777)?;
        }
        mkdir(dir, 0o700)?;
        verify_owned_private(dir)
    })();
    unsafe { libc::umask(prev_umask) };
    result
}

/// mkdir(path, mode); treats an existing directory as success.
fn mkdir(path: &Path, mode: libc::mode_t) -> io::Result<()> {
    let c = cpath(path)?;
    let rc = unsafe { libc::mkdir(c.as_ptr(), mode) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.kind() == ErrorKind::AlreadyExists {
        return Ok(());
    }
    Err(err)
}

/// Reject a directory unless it is owned by the current uid and has no group or
/// other access — this is what stops another user from planting a directory (or
/// socket) we'd otherwise trust and connect to.
fn verify_owned_private(path: &Path) -> io::Result<()> {
    let c = cpath(path)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::stat(c.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if st.st_uid != unsafe { libc::getuid() } {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{} is not owned by the current user", path.display()),
        ));
    }
    if st.st_mode & 0o077 != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("{} is accessible by group/other", path.display()),
        ));
    }
    Ok(())
}

fn cpath(path: &Path) -> io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "path contains NUL"))
}
