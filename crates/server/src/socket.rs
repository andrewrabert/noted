//! The Unix socket the HTTP app listens on.
//!
//! The contract: the path must be free — an occupied path, even a socket
//! left by an unclean stop, refuses to bind and the occupant is kept. The
//! returned guard unlinks the socket path when dropped, so a graceful
//! shutdown leaves no file behind. Access control is the caller's: the
//! socket is born at umask mode, and requests are gated by bearer auth.

use std::path::{Path, PathBuf};

use noted::error::{Result, rejected};

/// Unlinks the socket path when dropped, errors ignored: at drop time the
/// listener is gone and a missing or replaced file is not worth failing
/// over. The one syscall of blocking I/O is accepted in `Drop` as the
/// pragmatic shutdown norm.
#[must_use = "the socket file is unlinked when this guard is dropped"]
#[derive(Debug)]
pub struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Binds a Unix stream listener at `path`. Must be called inside a tokio
/// runtime; the one-shot blocking bind at startup is the accepted exception
/// to the non-blocking I/O rule.
pub fn bind_unix_socket(path: &Path) -> Result<(tokio::net::UnixListener, SocketGuard)> {
    let listener = tokio::net::UnixListener::bind(path)
        .map_err(|e| rejected(format!("socket: bind {}: {e}", path.display())))?;
    Ok((listener, SocketGuard(path.to_path_buf())))
}
