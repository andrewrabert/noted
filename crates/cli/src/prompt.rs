use std::io::Write;

use noted::error::{Result, rejected, unavailable};

/// Reads a password from stdin, prompting on stderr.
pub(crate) async fn password() -> Result<String> {
    blocking(|| {
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "password: ");
        let _ = stderr.flush();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| rejected(format!("read password: {e}")))?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    })
    .await
}

async fn blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| unavailable(format!("terminal read failed: {e}")))?
}
