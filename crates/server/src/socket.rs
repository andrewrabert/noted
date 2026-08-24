use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use noted::error::{Result, io_error, rejected, unavailable};
use rand::RngExt;

const LOCK_ATTEMPTS: u8 = 8;
const PICK_ATTEMPTS: u8 = 8;
const PICK_NAME_LEN: usize = 8;
const PICK_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const PICK_SUFFIX: &str = ".sock";
const BASE_DIR_NAME: &str = noted::APP_NAME;
const BASE_DIR_MODE: u32 = 0o700;
const PICKED_SOCKET_MODE: u32 = 0o600;
const FALLBACK_ROOT: &str = "/tmp";

/// The environment a picked socket path is selected from.
#[derive(Clone, Debug, Default)]
pub struct SocketEnv {
    pub runtime_dir: Option<PathBuf>,
    pub tmpdir: Option<PathBuf>,
}

impl SocketEnv {
    pub fn capture() -> SocketEnv {
        SocketEnv {
            runtime_dir: std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            tmpdir: std::env::var_os("TMPDIR").map(PathBuf::from),
        }
    }
}

/// Which path a socket server binds.
#[derive(Clone, Debug)]
pub enum SocketBind {
    /// The absolute path a caller named.
    Explicit(PathBuf),
    /// A name picked under the base directory [`SocketEnv`] selects.
    Picked(SocketEnv),
}

impl SocketBind {
    pub fn bind(&self) -> Result<(tokio::net::UnixListener, SocketGuard)> {
        match self {
            SocketBind::Explicit(path) => bind_unix_socket(path, None),
            SocketBind::Picked(env) => {
                let base = socket_base_dir(env)?;
                for _ in 0..PICK_ATTEMPTS {
                    let socket = base.join(pick_name());
                    if path_exists(&socket)?
                        || path_exists(&lock_path(&socket))?
                        || path_exists(&staging_dir(&socket))?
                    {
                        continue;
                    }
                    return bind_unix_socket(&socket, Some(PICKED_SOCKET_MODE));
                }
                Err(unavailable(format!(
                    "socket: no free name under {}",
                    base.display()
                )))
            }
        }
    }
}

fn pick_name() -> String {
    let mut rng = rand::rng();
    let name: String = (0..PICK_NAME_LEN)
        .map(|_| PICK_ALPHABET[rng.random_range(0..PICK_ALPHABET.len())] as char)
        .collect();
    format!("{name}{PICK_SUFFIX}")
}

fn path_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(unavailable(format!("socket: {}: {e}", path.display()))),
    }
}

/// The directory picked sockets are named under, before the `noted` component.
pub fn socket_root(env: &SocketEnv) -> Result<PathBuf> {
    let candidates = [
        env.runtime_dir.as_deref(),
        env.tmpdir.as_deref(),
        Some(Path::new(FALLBACK_ROOT)),
    ];
    let root = candidates
        .into_iter()
        .flatten()
        .find(|p| {
            !p.as_os_str().is_empty()
                && p.is_absolute()
                && std::fs::metadata(p).is_ok_and(|m| m.is_dir())
        })
        .ok_or_else(|| rejected("socket: no usable directory to pick a socket under"))?;
    if root.as_os_str().as_bytes().contains(&b'\n') {
        return Err(rejected(format!(
            "socket: {} holds a newline",
            root.display()
        )));
    }
    Ok(root.to_path_buf())
}

/// The `noted` directory under [`socket_root`], created at 0700 when absent.
pub fn socket_base_dir(env: &SocketEnv) -> Result<PathBuf> {
    let dir = socket_root(env)?.join(BASE_DIR_NAME);
    // mkdir(2) applies `mode & !umask`, so an owner-restricting umask would
    // leave the fresh directory below BASE_DIR_MODE and fail every later run.
    match std::fs::DirBuilder::new().mode(BASE_DIR_MODE).create(&dir) {
        Ok(()) => {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(BASE_DIR_MODE))
                .map_err(|e| unavailable(format!("socket: {}: {e}", dir.display())))?;
            return Ok(dir);
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(unavailable(format!("socket: {}: {e}", dir.display())));
        }
    }
    let meta = std::fs::symlink_metadata(&dir)
        .map_err(|e| unavailable(format!("socket: {}: {e}", dir.display())))?;
    if !meta.file_type().is_dir() {
        return Err(rejected(format!(
            "socket: {} is not a directory",
            dir.display()
        )));
    }
    let owner = rustix::process::getuid().as_raw();
    if meta.uid() != owner {
        return Err(rejected(format!(
            "socket: {} is owned by another user",
            dir.display()
        )));
    }
    if meta.permissions().mode() & 0o777 != BASE_DIR_MODE {
        return Err(rejected(format!(
            "socket: {} is not at mode 0700",
            dir.display()
        )));
    }
    Ok(dir)
}

/// The one line a socket server writes to stdout.
pub fn write_endpoint_line(out: &mut dyn std::io::Write, path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(rejected(format!(
            "a bound unix socket is named by an absolute path: {}",
            path.display()
        )));
    }
    let mut line = b"unix://".to_vec();
    line.extend_from_slice(path.as_os_str().as_bytes());
    line.push(b'\n');
    out.write_all(&line)
        .and_then(|()| out.flush())
        .map_err(|e| io_error("socket: endpoint line", e))
}

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

    /// The path the socket was bound at.
    pub fn path(&self) -> &Path {
        &self.socket
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
            Ok(()) => {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| unavailable(format!("socket: stage {}: {e}", socket.display())))?;
            }
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
