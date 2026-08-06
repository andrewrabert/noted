use std::path::PathBuf;

use clap::Args;

use noted::types::Ttl;

/// The dotenv file the prologue loads. Learned from argv before the real
/// parse, so a binding for it inside the file itself is inert.
#[derive(Args)]
pub struct EnvFileArg {
    #[arg(long = "env-file", env = "NOTED_ENV_FILE", global = true)]
    pub(crate) env_file: Option<PathBuf>,
}

#[derive(Args)]
pub struct GlobalArgs {
    #[command(flatten)]
    pub(crate) env_file: EnvFileArg,
    /// Credential metadata path; setting it forces plaintext secret storage
    #[arg(long = "hosts-file", env = "NOTED_HOSTS_FILE", global = true)]
    pub(crate) hosts_file: Option<PathBuf>,
    #[arg(long, env = "NOTED_DIR", global = true)]
    pub(crate) dir: Option<String>,
    #[arg(long, env = "NOTED_URL", global = true)]
    pub(crate) url: Option<String>,
    #[arg(long, env = "NOTED_TOKEN", global = true)]
    pub(crate) token: Option<String>,
    /// Provenance recorded on log entries
    #[arg(short = 's', long, env = "NOTED_SOURCE", global = true)]
    pub(crate) source: Option<String>,
    #[arg(
        long = "log-level",
        env = "NOTED_LOG_LEVEL",
        global = true,
        default_value = "INFO"
    )]
    pub(crate) log_level: String,
    #[arg(long = "log-file", env = "NOTED_LOG_FILE", global = true)]
    pub(crate) log_file: Option<String>,
    #[arg(long, env = "NOTED_POLICY", global = true)]
    pub(crate) policy: Option<String>,
    #[arg(long, env = "NOTED_SCOPE", global = true)]
    pub(crate) scope: Option<String>,
}

#[derive(Args, Default)]
pub struct EntryFlags {
    #[arg(long = "in", value_name = "PATH[=MODES]")]
    pub(crate) in_: Vec<String>,
}

/// The auth database and admin socket, declared once for the served commands
/// and the admin commands alike.
#[derive(Args)]
pub struct AuthPaths {
    #[arg(long = "auth-db", env = "NOTED_AUTH_DB", global = true)]
    pub(crate) auth_db: Option<PathBuf>,
    #[cfg(unix)]
    #[arg(long = "admin-socket", env = "NOTED_ADMIN_SOCKET", global = true)]
    pub(crate) admin_socket: Option<PathBuf>,
}

pub fn parse_ttl(s: &str) -> std::result::Result<Ttl, String> {
    humantime::parse_duration(s)
        .map(|d| Ttl::from_secs(d.as_secs()))
        .map_err(|e| e.to_string())
}
