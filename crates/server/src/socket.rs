use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use noted::error::{Result, rejected, unavailable};

const LOCK_ATTEMPTS: u8 = 8;

pub fn lock_path(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

#[derive(Debug)]
struct SocketLock {
    path: PathBuf,
    file: std::fs::File,
}

impl SocketLock {
    fn acquire(socket: &Path) -> Result<SocketLock> {
        let path = lock_path(socket);
        for _ in 0..LOCK_ATTEMPTS {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .mode(0o600)
                .open(&path)
                .map_err(|e| unavailable(format!("socket: lock file {}: {e}", path.display())))?;
            match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {}
                Err(rustix::io::Errno::WOULDBLOCK) => {
                    return Err(rejected(format!(
                        "socket: server already running at {}",
                        socket.display()
                    )));
                }
                Err(e) => {
                    return Err(unavailable(format!("socket: lock {}: {e}", path.display())));
                }
            }
            let locked = file
                .metadata()
                .map_err(|e| unavailable(format!("socket: lock file {}: {e}", path.display())))?;
            let named = match std::fs::metadata(&path) {
                Ok(m) => Some(m),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => {
                    return Err(unavailable(format!(
                        "socket: lock file {}: {e}",
                        path.display()
                    )));
                }
            };
            // An exiting owner can unlink the lock file between this open and
            // the flock, leaving the lock on an inode the path no longer names.
            if named.is_some_and(|m| m.dev() == locked.dev() && m.ino() == locked.ino()) {
                if !locked.file_type().is_file() {
                    return Err(rejected(format!(
                        "socket: lock file {} is not a regular file",
                        path.display()
                    )));
                }
                return Ok(SocketLock { path, file });
            }
        }
        Err(unavailable(format!(
            "socket: lock file {} keeps being replaced",
            path.display()
        )))
    }
}

impl Drop for SocketLock {
    fn drop(&mut self) {
        // Unlink before unlocking, or another acquirer wins the lock on this
        // inode and has it unlinked out from under them.
        let _ = std::fs::remove_file(&self.path);
        let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

#[must_use = "the socket and its lock file are unlinked when this guard is dropped"]
#[derive(Debug)]
pub struct SocketGuard {
    socket: PathBuf,
    lock: SocketLock,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

impl SocketGuard {
    pub fn lock_path(&self) -> &Path {
        &self.lock.path
    }
}

pub fn staging_dir(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_os_string();
    name.push(".bind");
    PathBuf::from(name)
}

// A longer name can push the staged path past the `sun_path` budget a bindable
// final path still fits in.
const STAGED_ENTRY: &str = "s";

pub fn staging_socket(socket: &Path) -> PathBuf {
    staging_dir(socket).join(STAGED_ENTRY)
}

#[derive(Debug)]
struct Staging {
    dir: PathBuf,
}

impl Staging {
    fn open(socket: &Path) -> Result<Staging> {
        let dir = staging_dir(socket);
        // 0700 keeps the staged socket unreachable between the bind, which uses
        // the umask mode, and the chmod that narrows it.
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = std::fs::symlink_metadata(&dir)
                    .map_err(|e| unavailable(format!("socket: stage {}: {e}", socket.display())))?;
                if !meta.file_type().is_dir() {
                    return Err(rejected(format!(
                        "socket: {} cannot be staged: its staging path is occupied",
                        socket.display()
                    )));
                }
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| unavailable(format!("socket: stage {}: {e}", socket.display())))?;
            }
            Err(e) => {
                return Err(unavailable(format!(
                    "socket: stage {}: {e}",
                    socket.display()
                )));
            }
        }
        let staged = staging_socket(socket);
        match std::fs::symlink_metadata(&staged) {
            Ok(meta) => {
                if !meta.file_type().is_socket() {
                    return Err(rejected(format!(
                        "socket: {} cannot be staged: its staging directory is occupied",
                        socket.display()
                    )));
                }
                std::fs::remove_file(&staged)
                    .map_err(|e| unavailable(format!("socket: stage {}: {e}", socket.display())))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(unavailable(format!(
                    "socket: stage {}: {e}",
                    socket.display()
                )));
            }
        }
        let staging = Staging { dir };
        Ok(staging)
    }

    fn socket(&self) -> PathBuf {
        self.dir.join(STAGED_ENTRY)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.socket());
        let _ = std::fs::remove_dir(&self.dir);
    }
}

fn occupant_is_stale_socket(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(rejected(format!(
                    "socket: {} exists and is not a socket",
                    path.display()
                )));
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(unavailable(format!("socket: {}: {e}", path.display()))),
    }
}

/// The blocking I/O here and in the guard's drop is the sanctioned
/// startup/shutdown exception to the non-blocking rule.
pub fn bind_unix_socket(
    path: &Path,
    mode: Option<u32>,
) -> Result<(tokio::net::UnixListener, SocketGuard)> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| unavailable(format!("socket: {}: {e}", parent.display())))?;
    }
    occupant_is_stale_socket(path)?;
    let lock = SocketLock::acquire(path)?;
    if occupant_is_stale_socket(path)? {
        tracing::warn!(socket = %path.display(), "removing a socket left by an unclean stop");
        std::fs::remove_file(path)
            .map_err(|e| unavailable(format!("socket: remove {}: {e}", path.display())))?;
    }
    let staged = staging_socket(path);
    rustix::net::SocketAddrUnix::new(&staged)
        .map_err(|_| rejected(format!("socket: {} is too long to bind", path.display())))?;
    let staging = Staging::open(path)?;
    let listener = tokio::net::UnixListener::bind(&staged)
        .map_err(|e| rejected(format!("socket: bind {}: {e}", path.display())))?;
    if let Some(mode) = mode {
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode))
            .map_err(|e| unavailable(format!("socket: chmod {}: {e}", path.display())))?;
    }
    std::fs::rename(&staged, path)
        .map_err(|e| unavailable(format!("socket: place {}: {e}", path.display())))?;
    drop(staging);
    Ok((
        listener,
        SocketGuard {
            socket: path.to_path_buf(),
            lock,
        },
    ))
}
