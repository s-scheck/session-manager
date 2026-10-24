//! Socket-directory resolution and the security model around it, session-name
//! validation, and enumeration of the session sockets in a directory.
//!
//! Session state is encoded in the socket file's permission bits (an attached
//! session gets the owner-execute bit set), so listing can read status from
//! `stat(2)` alone. Whether a server is actually alive behind a socket is a
//! protocol question, answered by `client::probe`.

use std::fs::{self, DirBuilder, Metadata};
use std::io::{self, ErrorKind};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use nix::unistd::{Uid, User};

/// Application directory name used inside shared/base directories.
const APP: &str = "sm";
/// Personal directory name created under $HOME.
const HOME_DIR: &str = ".session_manager";

// Owner-execute bit toggled to mark a session as "attached".
const ATTACHED_BIT: u32 = 0o100;
const BASE_MODE: u32 = 0o600;

/// Resolve the directory in which session sockets live, creating it with
/// hardened permissions. Tries, in order: `$SM_SOCKET_DIR`, `$HOME/.session_manager`,
/// `$TMPDIR/sm/$USER`, `/tmp/sm/$USER` — returning the first that can be created
/// and verified as owned by us with no group/other access.
pub fn resolve_socket_dir() -> io::Result<PathBuf> {
    let mut last_err = None;

    // Directories the user chose (or owns the parent of) directly.
    let personal = [
        env_nonempty("SM_SOCKET_DIR").map(PathBuf::from),
        env_nonempty("HOME").map(|home| Path::new(&home).join(HOME_DIR)),
    ];
    for dir in personal.into_iter().flatten() {
        match ensure_private_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) => last_err = Some(e),
        }
    }

    // A per-user directory beneath a shared, world-writable base.
    let user = username();
    let shared_bases = [
        env_nonempty("TMPDIR").map(|tmp| Path::new(&tmp).join(APP)),
        Some(Path::new("/tmp").join(APP)),
    ];
    for base in shared_bases.into_iter().flatten() {
        let dir = base.join(&user);
        match ensure_dir_in_shared_base(&base, &dir) {
            Ok(()) => return Ok(dir),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err.unwrap_or_else(|| io::Error::other("no usable socket directory")))
}

/// Check that `name` can be used as a session name: a single, ordinary path
/// component.
pub fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid session name: {name:?}"),
        ));
    }
    Ok(())
}

/// Full path of the socket for `name` inside `dir`, validating the session name
/// and the resulting path length (Unix socket paths are tightly bounded).
pub fn socket_path(dir: &Path, name: &str) -> io::Result<PathBuf> {
    validate_name(name)?;
    let path = dir.join(name);
    let max = max_socket_path_len();
    if path.as_os_str().len() > max {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "socket path too long ({} > {max}); set SM_SOCKET_DIR to a shorter path",
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

/// One session socket found in the socket directory.
pub struct SessionEntry {
    pub name: String,
    pub path: PathBuf,
    /// Whether the server last marked the session as having a client attached.
    pub attached: bool,
    pub mtime: Option<SystemTime>,
}

/// Enumerate the session sockets in `dir`, sorted by name. This only reads the
/// file system; liveness is the caller's concern.
pub fn list_sessions(dir: &Path) -> io::Result<Vec<SessionEntry>> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut sessions: Vec<SessionEntry> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let meta = fs::metadata(&path).ok()?;
            meta.file_type().is_socket().then(|| SessionEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                attached: meta.permissions().mode() & ATTACHED_BIT != 0,
                mtime: meta.modified().ok(),
                path,
            })
        })
        .collect();
    sessions.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(sessions)
}

// ---- internal helpers -------------------------------------------------------

/// Longest socket path the platform accepts (`sun_path` minus its NUL).
fn max_socket_path_len() -> usize {
    // SAFETY: sockaddr_un is plain old data; all-zeroes is a valid value.
    let addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_path.len() - 1
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// The current user's login name from the password database, falling back to
/// the numeric uid. Unlike `$USER`, this can't disagree with the uid that the
/// directory ownership checks compare against.
fn username() -> String {
    let uid = Uid::current();
    match User::from_uid(uid) {
        Ok(Some(user)) => user.name,
        _ => uid.to_string(),
    }
}

/// Ensure `dir` exists as a directory owned by us with no group/other access.
/// The path may be a symlink: the location was chosen by the user.
fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    create_dir_with_mode(dir, 0o700)?;
    verify_private(dir, &fs::metadata(dir)?)
}

/// Ensure `dir`, a per-user directory inside the shared `base` (like
/// `/tmp/sm`), exists and is private to us. The base is created world-writable
/// and sticky so several users can each own a subdirectory, and is verified to
/// be safe to build on; `dir` itself must be a real directory, not a symlink
/// someone else planted under our name.
fn ensure_dir_in_shared_base(base: &Path, dir: &Path) -> io::Result<()> {
    create_dir_with_mode(base, 0o1777)?;
    verify_shared_base(base, &fs::symlink_metadata(base)?)?;
    create_dir_with_mode(dir, 0o700)?;
    verify_private(dir, &fs::symlink_metadata(dir)?)
}

/// Create a directory with exactly `mode` (the umask notwithstanding). An
/// existing entry is left untouched for the caller to verify.
fn create_dir_with_mode(path: &Path, mode: u32) -> io::Result<()> {
    match DirBuilder::new().mode(mode).create(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(mode)),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// Reject a directory unless it is owned by the current uid and has no group or
/// other access — this is what stops another user from planting a directory (or
/// socket) we'd otherwise trust and connect to.
fn verify_private(path: &Path, meta: &Metadata) -> io::Result<()> {
    if !meta.is_dir() {
        return Err(insecure(path, "is not a directory"));
    }
    if meta.uid() != Uid::current().as_raw() {
        return Err(insecure(path, "is not owned by the current user"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(insecure(path, "is accessible by group/other"));
    }
    Ok(())
}

/// Reject a shared base directory that would let another user rename or
/// replace our private directory inside it: it must be a real directory owned
/// by root or us, and sticky if others can write to it.
fn verify_shared_base(path: &Path, meta: &Metadata) -> io::Result<()> {
    if !meta.is_dir() {
        return Err(insecure(path, "is not a directory"));
    }
    if meta.uid() != 0 && meta.uid() != Uid::current().as_raw() {
        return Err(insecure(path, "is owned by another user"));
    }
    if meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0 {
        return Err(insecure(path, "is writable by others but not sticky"));
    }
    Ok(())
}

fn insecure(path: &Path, problem: &str) -> io::Error {
    io::Error::new(
        ErrorKind::PermissionDenied,
        format!("{} {problem}", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_names() {
        for ok in ["work", "a.b", ".hidden", "with space", "ümlaut"] {
            assert!(validate_name(ok).is_ok(), "{ok:?} should be valid");
        }
        for bad in ["", ".", "..", "a/b", "/abs", "nul\0byte"] {
            assert!(validate_name(bad).is_err(), "{bad:?} should be invalid");
        }
    }

    #[test]
    fn socket_path_length_is_bounded() {
        let dir = Path::new("/tmp");
        assert!(socket_path(dir, "short").is_ok());
        let long = "x".repeat(max_socket_path_len());
        assert!(socket_path(dir, &long).is_err());
    }
}
