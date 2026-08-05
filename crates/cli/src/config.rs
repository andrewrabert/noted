use std::path::{Path, PathBuf};

use noted::error::{Result, io_error, rejected};
use noted::types::Ttl;
use noted_client::credentials::{CredentialStoreConfig, SecretStorage};

pub fn block_on<F, T>(fut: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let runtime = tokio::runtime::Runtime::new().map_err(|e| io_error("runtime", e))?;
    runtime.block_on(fut)
}

/// Replaces a leading `~` component with the invoking user's home directory. A
/// path with no leading `~`, and any path when no home is known, is taken as
/// written.
pub fn expand_home(path: &Path) -> PathBuf {
    let mut parts = path.components();
    let Some(std::path::Component::Normal(first)) = parts.next() else {
        return path.to_path_buf();
    };
    if first != "~" {
        return path.to_path_buf();
    }
    match dirs::home_dir() {
        Some(home) => home.join(parts.as_path()),
        None => path.to_path_buf(),
    }
}

pub fn parse_ttl(s: &str) -> std::result::Result<Ttl, String> {
    humantime::parse_duration(s)
        .map(|d| Ttl::from_secs(d.as_secs()))
        .map_err(|e| e.to_string())
}

/// Where credentials live. An explicit `NOTED_HOSTS_FILE` also forces plaintext
/// secret storage.
pub fn credential_store_config() -> Result<CredentialStoreConfig> {
    match std::env::var("NOTED_HOSTS_FILE") {
        Ok(p) if !p.is_empty() => Ok(CredentialStoreConfig {
            hosts_path: expand_home(Path::new(&p)),
            storage: SecretStorage::Plaintext,
        }),
        _ => {
            let dir = dirs::config_dir().ok_or_else(|| rejected("cannot determine config dir"))?;
            Ok(CredentialStoreConfig {
                hosts_path: dir.join("noted").join("hosts.json"),
                storage: SecretStorage::Auto,
            })
        }
    }
}

fn env_file_path() -> Option<PathBuf> {
    if let Ok(override_) = std::env::var("NOTED_ENV_FILE")
        && !override_.is_empty()
    {
        return Some(expand_home(Path::new(&override_)));
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
            let path = expand_home(path);
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
