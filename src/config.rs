use std::future::Future;
use std::path::{Path, PathBuf};

use crate::error::{io_error, rejected, Result};

pub fn expand_home(path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => match dirs::home_dir() {
            Some(home) => home.join(rest),
            None => PathBuf::from(path),
        },
        None => PathBuf::from(path),
    }
}

pub fn block_on<F, T>(fut: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let runtime = tokio::runtime::Runtime::new().map_err(|e| io_error("runtime", e))?;
    runtime.block_on(fut)
}

pub fn resolve_root(dir: Option<&str>) -> Result<PathBuf> {
    let dir = dir
        .filter(|s| !s.is_empty())
        .ok_or_else(|| rejected("no notes dir set (set NOTED_DIR)"))?;
    Ok(expand_home(dir))
}

pub fn parse_ttl(s: &str) -> std::result::Result<crate::types::Ttl, String> {
    humantime::parse_duration(s)
        .map(|d| crate::types::Ttl::from_secs(d.as_secs()))
        .map_err(|e| e.to_string())
}

fn env_file_path() -> Option<PathBuf> {
    if let Ok(override_) = std::env::var("NOTED_ENV_FILE") {
        if !override_.is_empty() {
            return Some(expand_home(&override_));
        }
    }
    Some(dirs::config_dir()?.join("noted.env"))
}

pub fn load_env_file() {
    let Some(path) = env_file_path() else { return };
    let _ = dotenvy::from_path(&path);
}

pub fn setup_logging(
    level: &str,
    file: Option<&Path>,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .map_err(|_| rejected(format!("invalid log level: {level} (set NOTED_LOG_LEVEL)")))?;
    let builder = tracing_subscriber::fmt().with_env_filter(filter);

    match file {
        Some(path) => {
            let path = expand_home(&path.to_string_lossy());
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
            Ok(Some(guard))
        }
        None => {
            let _ = builder.with_writer(std::io::stderr).try_init();
            Ok(None)
        }
    }
}
