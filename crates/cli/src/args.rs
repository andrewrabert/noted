use std::path::PathBuf;

use clap::Args;

use noted::types::Ttl;

use crate::settings::{Flags, Layer, Variable};

/// Every setting arrives through a layer, so no argument here reads the
/// environment or carries a default.
#[derive(Args)]
pub struct GlobalArgs {
    /// Dotenv file read as the furthest settings layer
    #[arg(long = "env-file", global = true)]
    pub(crate) env_file: Option<PathBuf>,
    /// Credential metadata path; setting it forces plaintext secret storage
    #[arg(long = "hosts-file", global = true)]
    pub(crate) hosts_file: Option<PathBuf>,
    #[arg(long, global = true)]
    pub(crate) dir: Option<String>,
    #[arg(long, global = true)]
    pub(crate) url: Option<String>,
    #[arg(long, global = true)]
    pub(crate) token: Option<String>,
    /// Provenance recorded on log entries
    #[arg(short = 's', long, global = true)]
    pub(crate) source: Option<String>,
    #[arg(long = "log-level", global = true)]
    pub(crate) log_level: Option<String>,
    #[arg(long = "log-file", global = true)]
    pub(crate) log_file: Option<String>,
    #[arg(long, global = true)]
    pub(crate) policy: Option<String>,
    #[arg(long, global = true)]
    pub(crate) scope: Option<String>,
}

fn path_of(path: &Option<PathBuf>) -> Option<String> {
    path.as_ref().map(|p| p.display().to_string())
}

impl Flags for GlobalArgs {
    fn write(&self, layer: &mut Layer) {
        layer.set(Variable::EnvFile, path_of(&self.env_file).as_deref());
        layer.set(Variable::HostsFile, path_of(&self.hosts_file).as_deref());
        layer.set(Variable::Dir, self.dir.as_deref());
        layer.set(Variable::Url, self.url.as_deref());
        layer.set(Variable::Token, self.token.as_deref());
        layer.set(Variable::Source, self.source.as_deref());
        layer.set(Variable::LogLevel, self.log_level.as_deref());
        layer.set(Variable::LogFile, self.log_file.as_deref());
        layer.set(Variable::Policy, self.policy.as_deref());
        layer.set(Variable::Scope, self.scope.as_deref());
    }
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
    #[arg(long = "auth-db", global = true)]
    pub(crate) auth_db: Option<PathBuf>,
    #[cfg(unix)]
    #[arg(long = "admin-socket", global = true)]
    pub(crate) admin_socket: Option<PathBuf>,
}

impl Flags for AuthPaths {
    fn write(&self, layer: &mut Layer) {
        layer.set(Variable::AuthDb, path_of(&self.auth_db).as_deref());
        #[cfg(unix)]
        layer.set(
            Variable::AdminSocket,
            path_of(&self.admin_socket).as_deref(),
        );
    }
}

pub fn parse_ttl(s: &str) -> std::result::Result<Ttl, String> {
    humantime::parse_duration(s)
        .map(|d| Ttl::from_secs(d.as_secs()))
        .map_err(|e| e.to_string())
}
