use std::io::{IsTerminal, Write};

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

/// Asks `question` on stderr; anything but `y`/`yes` is no, and an
/// unreadable stdin is no.
pub(crate) async fn confirm(question: &str) -> bool {
    let question = question.to_string();
    let answered = blocking(move || {
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "{question} ");
        let _ = stderr.flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return Ok(false);
        }
        Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
    })
    .await;
    answered.unwrap_or(false)
}

/// Reads one line from stdin. `None` when stdin is a terminal.
pub(crate) async fn piped_line() -> Result<Option<String>> {
    blocking(|| {
        if std::io::stdin().is_terminal() {
            return Ok(None);
        }
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| rejected(format!("read stdin: {e}")))?;
        Ok(Some(line.trim().to_string()))
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
