use std::path::{Path, PathBuf};

use noted::error::{Result, io_error, rejected};
use tracing_subscriber::EnvFilter;

/// Flushes the file writer when dropped; the prologue owns it for the life of
/// the process.
pub struct LogGuard(#[allow(dead_code)] Option<tracing_appender::non_blocking::WorkerGuard>);

/// Initializes tracing with `filter`, writing to `file` when one is named and
/// stderr otherwise. A filter that does not parse is rejected.
pub fn init(filter: &str, file: Option<&Path>) -> Result<LogGuard> {
    let env_filter = EnvFilter::try_new(filter)
        .map_err(|_| rejected(format!("invalid log filter: {filter} (--log-level)")))?;
    let builder = tracing_subscriber::fmt().with_env_filter(env_filter);

    match file {
        Some(path) => {
            let dir = match path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            let name = path
                .file_name()
                .ok_or_else(|| rejected("log file has no name"))?;
            std::fs::create_dir_all(&dir).map_err(|e| io_error("cannot open log file", e))?;
            let (writer, guard) =
                tracing_appender::non_blocking(tracing_appender::rolling::never(&dir, name));
            let _ = builder.with_ansi(false).with_writer(writer).try_init();
            Ok(LogGuard(Some(guard)))
        }
        None => {
            let _ = builder.with_writer(std::io::stderr).try_init();
            Ok(LogGuard(None))
        }
    }
}
