use std::path::{Path, PathBuf};

use noted::authorization::Bearer;
use noted::error::{Result, rejected};
use noted::{Backend, BackendArgs, Endpoint, HttpUrl, PolicyArgs, PolicyFragment};
use noted_client::authclient::Session;
use noted_client::credentials::{CredentialStore, CredentialStoreConfig, SecretStorage};

use crate::args::{EntryFlags, GlobalArgs};

/// The dotenv file loaded before clap reads the environment.
pub struct EnvFile {
    path: PathBuf,
}

impl EnvFile {
    /// The file `arg` names, else `<config_dir>/noted.env`.
    pub fn locate(arg: Option<&Path>) -> Option<EnvFile> {
        EnvFile::resolve(arg, dirs::config_dir().as_deref())
    }

    /// `arg` when given and non-empty, else `<config_dir>/noted.env`. No
    /// argument and no config dir means no env file.
    pub fn resolve(arg: Option<&Path>, config_dir: Option<&Path>) -> Option<EnvFile> {
        match arg.filter(|p| !p.as_os_str().is_empty()) {
            Some(path) => Some(EnvFile {
                path: path.to_path_buf(),
            }),
            None => config_dir.map(|dir| EnvFile {
                path: dir.join("noted.env"),
            }),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The file's bindings in file order.
    /// A malformed line is rejected, naming the file and the line.
    pub fn parse(&self, text: &str) -> Result<Vec<(String, String)>> {
        dotenvy::from_read_iter(text.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| self.reject(e))
    }

    /// Applies the file to the process environment, already-set variables
    /// winning. A missing file is fine; an unreadable or malformed one is
    /// rejected.
    pub fn load(&self) -> Result<()> {
        match dotenvy::from_path_iter(&self.path) {
            Ok(iter) => iter.load().map_err(|e| self.reject(e)),
            Err(e) if e.not_found() => Ok(()),
            Err(e) => Err(self.reject(e)),
        }
    }

    fn reject(&self, e: dotenvy::Error) -> noted::error::NotedError {
        rejected(format!("{}: {e}", self.path.display()))
    }
}

/// Where logins live. An explicit hosts file also forces plaintext secret
/// storage; the default is `<config_dir>/noted/hosts.json` with automatic
/// storage. An empty path counts as unset.
/// An unknown config dir with no explicit path is rejected.
pub fn credential_store_config(
    hosts_file: Option<&Path>,
    config_dir: Option<&Path>,
) -> Result<CredentialStoreConfig> {
    match hosts_file.filter(|p| !p.as_os_str().is_empty()) {
        Some(path) => Ok(CredentialStoreConfig {
            hosts_path: path.to_path_buf(),
            storage: SecretStorage::Plaintext,
        }),
        None => {
            let dir = config_dir.ok_or_else(|| rejected("cannot determine config dir"))?;
            Ok(CredentialStoreConfig {
                hosts_path: dir.join("noted").join("hosts.json"),
                storage: SecretStorage::Auto,
            })
        }
    }
}

/// The editor chain and the user's config dir: all the CLI reads for itself,
/// every settings variable arriving through clap.
#[derive(Clone, Debug, Default)]
pub struct Environment {
    pub visual: Option<String>,
    pub editor: Option<String>,
    pub config_dir: Option<PathBuf>,
}

impl Environment {
    /// Captures the process environment the CLI reads for itself.
    pub fn capture() -> Environment {
        Environment {
            visual: std::env::var("VISUAL").ok(),
            editor: std::env::var("EDITOR").ok(),
            config_dir: dirs::config_dir(),
        }
    }

    /// Most preferred first, empty values dropped.
    pub fn editor_preference(&self) -> EditorPreference {
        EditorPreference(
            [self.visual.as_deref(), self.editor.as_deref()]
                .into_iter()
                .flatten()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        )
    }
}

/// The editor commands the environment names, most preferred first.
#[derive(Clone, Debug, Default)]
pub struct EditorPreference(Vec<String>);

impl EditorPreference {
    pub fn commands(&self) -> &[String] {
        &self.0
    }
}

/// The whole CLI configuration, resolved once: nothing below reads the
/// environment or a flag spelling.
pub struct Config {
    globals: GlobalArgs,
    env: Environment,
}

impl Config {
    pub fn new(globals: GlobalArgs, env: Environment) -> Config {
        Config { globals, env }
    }

    /// The tracing filter the prologue initializes logging with: the log level
    /// flag, `EnvFilter` directives included.
    pub fn log_filter(&self) -> &str {
        &self.globals.log_level
    }

    pub fn log_file(&self) -> Option<&Path> {
        self.globals.log_file.as_deref().map(Path::new)
    }

    pub fn editor(&self) -> EditorPreference {
        self.env.editor_preference()
    }

    /// The policy fragment the global flags and entry flags describe.
    pub fn policy_fragment(&self, entries: &EntryFlags) -> Result<PolicyFragment> {
        Ok(self
            .policy_args(entries)
            .fragments()?
            .into_iter()
            .next()
            .unwrap_or_default())
    }

    /// What a served backend stands on. It carries no bearer: a server holds
    /// its own credentials.
    /// Rejects when neither a notes dir nor an endpoint is set.
    pub fn backend_args(&self, entries: &EntryFlags) -> Result<BackendArgs> {
        let dir = self.globals.dir.clone().filter(|s| !s.is_empty());
        let endpoint = self.endpoint()?;
        if dir.is_none() && endpoint.is_none() {
            return Err(rejected("no notes dir set (--dir)"));
        }
        Ok(BackendArgs {
            dir,
            endpoint,
            token: None,
            source: self.globals.source.clone(),
            policy: self.policy_args(entries),
            transport: None,
        })
    }

    /// The store logins are read from and written to.
    pub fn credential_store(&self) -> Result<CredentialStore> {
        Ok(CredentialStore::open(credential_store_config(
            self.globals.hosts_file.as_deref(),
            self.env.config_dir.as_deref(),
        )?))
    }

    /// The login URL: the subcommand's explicit URL, else the global one.
    pub fn login_url(&self, explicit: Option<&str>) -> Result<HttpUrl> {
        let raw = explicit
            .filter(|s| !s.is_empty())
            .or_else(|| self.globals.url.as_deref().filter(|s| !s.is_empty()))
            .ok_or_else(|| rejected("a server URL is required (--url)"))?;
        raw.parse::<Endpoint>()?.login_url()
    }

    /// The client's backend. An http(s) endpoint takes the explicit token,
    /// else the bearer of the stored login; every other endpoint takes the
    /// explicit token alone.
    pub async fn connect(&self) -> Result<Backend> {
        let mut args = self.backend_args(&EntryFlags::default())?;
        args.token = match args.endpoint.as_ref().and_then(Endpoint::tcp) {
            Some(url) => {
                let session =
                    Session::open(url, self.globals.token.as_deref(), self.credential_store()?);
                session.bearer().await?.map(Bearer::new)
            }
            None => self
                .globals
                .token
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(Bearer::new),
        };
        Backend::new(args)
    }

    fn policy_args(&self, entries: &EntryFlags) -> PolicyArgs {
        PolicyArgs {
            policy: self.globals.policy.clone(),
            scope: self.globals.scope.clone(),
            inside: entries.in_.clone(),
        }
    }

    /// The URL parsed once: an http(s) server or a unix socket.
    fn endpoint(&self) -> Result<Option<Endpoint>> {
        match self.globals.url.as_deref().filter(|s| !s.is_empty()) {
            None => Ok(None),
            Some(raw) => Ok(Some(raw.parse()?)),
        }
    }
}
