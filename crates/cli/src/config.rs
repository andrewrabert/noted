use std::path::{Path, PathBuf};

use noted::error::{Result, rejected};
use noted::store::NotedDir;
use noted::types::Source;
use noted::{Backend, BackendArgs, Endpoint, HttpUrl, PolicyArgs, PolicyFragment, Transport};
use noted_client::credentials::{CredentialStore, CredentialStoreConfig, SecretStorage};
use noted_server::serve::ServedConfig;

use crate::args::EntryFlags;
use crate::settings::{Layer, Location, Settings, Variable};

/// The dotenv file read as a layer of its own: the one the nearer layers name,
/// else a `.notedenv` discovered at or above the working directory, else
/// `<config_dir>/noted.env`. Exactly one file is ever read.
pub struct EnvFile {
    path: PathBuf,
}

impl EnvFile {
    /// The file `arg` names, else the discovered `.notedenv`, else
    /// `<config_dir>/noted.env`.
    pub fn locate(arg: Option<&Path>) -> Option<EnvFile> {
        EnvFile::resolve(
            arg,
            std::env::current_dir().ok().as_deref(),
            dirs::config_dir().as_deref(),
        )
    }

    /// `arg` when given and non-empty, else the nearest `.notedenv` at or
    /// above `cwd`, else `<config_dir>/noted.env`. Nothing resolved means no
    /// env file.
    pub fn resolve(
        arg: Option<&Path>,
        cwd: Option<&Path>,
        config_dir: Option<&Path>,
    ) -> Option<EnvFile> {
        match arg.filter(|p| !p.as_os_str().is_empty()) {
            Some(path) => Some(EnvFile {
                path: path.to_path_buf(),
            }),
            None => cwd
                .and_then(EnvFile::discover)
                .or_else(|| config_dir.map(|dir| dir.join("noted.env")))
                .map(|path| EnvFile { path }),
        }
    }

    /// The nearest `.notedenv` at or above `start`. An ancestor that cannot
    /// be inspected ends the walk with nothing found.
    fn discover(start: &Path) -> Option<PathBuf> {
        for dir in start.ancestors() {
            let candidate = dir.join(".notedenv");
            match candidate.symlink_metadata() {
                Ok(_) => return Some(candidate),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return None,
            }
        }
        None
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The file as a settings layer. An absent file yields an empty layer; an
    /// unreadable or malformed one is rejected, naming the file.
    pub fn layer(&self) -> Result<Layer> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Layer::file(&self.path, &text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Layer::file(&self.path, ""),
            Err(e) => Err(rejected(format!("{}: {e}", self.path.display()))),
        }
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
                hosts_path: dir.join(noted::APP_NAME).join("hosts.json"),
                storage: SecretStorage::Auto,
            })
        }
    }
}

/// The editor commands the settings name, most preferred first.
#[derive(Clone, Debug, Default)]
pub struct EditorPreference(Vec<String>);

impl EditorPreference {
    pub fn commands(&self) -> &[String] {
        &self.0
    }
}

/// What the CLI learns for itself rather than from a layer.
#[derive(Clone, Debug, Default)]
pub struct Environment {
    pub config_dir: Option<PathBuf>,
}

/// The whole CLI configuration, resolved once: nothing below reads the
/// environment or a flag spelling.
pub struct Config {
    settings: Settings,
    config_dir: Option<PathBuf>,
}

impl Config {
    pub fn new(settings: Settings, config_dir: Option<PathBuf>) -> Config {
        Config {
            settings,
            config_dir,
        }
    }

    /// The tracing filter the prologue initializes logging with:
    /// `EnvFilter` directives included.
    pub fn log_filter(&self) -> &str {
        self.settings.get(Variable::LogLevel).unwrap_or("INFO")
    }

    pub fn log_file(&self) -> Option<&Path> {
        self.settings.get(Variable::LogFile).map(Path::new)
    }

    /// Most preferred first, empty values dropped.
    pub fn editor(&self) -> EditorPreference {
        EditorPreference(
            [Variable::Visual, Variable::Editor]
                .into_iter()
                .filter_map(|var| self.settings.get(var))
                .map(str::to_string)
                .collect(),
        )
    }

    pub fn policy_args(&self, entries: &EntryFlags) -> PolicyArgs {
        PolicyArgs {
            policy: self.setting(Variable::Policy).map(str::to_string),
            scope: self.setting(Variable::Scope).map(str::to_string),
            inside: entries.in_.clone(),
        }
    }

    /// The policy fragment the settings and entry flags describe.
    pub fn policy_fragment(&self, entries: &EntryFlags) -> Result<PolicyFragment> {
        Ok(self
            .policy_args(entries)
            .fragments()?
            .into_iter()
            .next()
            .unwrap_or_default())
    }

    /// The store logins are read from and written to.
    pub fn credential_store(&self) -> Result<CredentialStore> {
        Ok(CredentialStore::open(credential_store_config(
            self.setting(Variable::HostsFile).map(Path::new),
            self.config_dir.as_deref(),
        )?))
    }

    /// The url the location names. A notes directory holds no stored login.
    pub fn login_url(&self) -> Result<HttpUrl> {
        self.endpoint()?
            .ok_or_else(|| rejected("a server URL is required (--url)"))?
            .login_url()
    }

    /// An origin over the notes directory, else a relay on the url.
    pub async fn served(&self, entries: &EntryFlags) -> Result<ServedConfig> {
        let policy = self.policy_args(entries);
        match self.location()? {
            Place::Dir(dir) => Ok(ServedConfig::Origin {
                dir,
                source: self.source(),
                policy,
            }),
            Place::Endpoint(endpoint) => {
                let bearer = crate::credential::held(
                    &endpoint,
                    self.setting(Variable::Token),
                    &self.credential_store()?,
                )
                .await?
                .map(|held| noted::Bearer::new(held.expose()));
                Ok(ServedConfig::Relay {
                    endpoint,
                    bearer,
                    policy,
                    transport: Transport::Real,
                })
            }
        }
    }

    /// Local files, else the endpoint under the bearer this invocation
    /// carries.
    pub async fn connect(&self) -> Result<Backend> {
        let entries = EntryFlags::default();
        match self.location()? {
            Place::Dir(dir) => Backend::new(BackendArgs::Local {
                dir,
                source: self.source(),
                policy: self.policy_args(&entries),
            }),
            Place::Endpoint(endpoint) => {
                let bearer = crate::credential::client_bearer(
                    &endpoint,
                    self.setting(Variable::Token),
                    &self.policy_fragment(&entries)?,
                    &self.credential_store()?,
                )
                .await?;
                Backend::new(BackendArgs::Remote {
                    endpoint,
                    bearer,
                    transport: Transport::Real,
                })
            }
        }
    }

    pub fn setting(&self, var: Variable) -> Option<&str> {
        self.settings.get(var)
    }

    fn source(&self) -> Option<Source> {
        Source::from_opt(self.setting(Variable::Source).map(str::to_string))
    }

    /// The url parsed once, where the location names one.
    fn endpoint(&self) -> Result<Option<Endpoint>> {
        match self.settings.location() {
            Some(Location::Url(raw)) => Ok(Some(raw.parse()?)),
            _ => Ok(None),
        }
    }

    /// What this invocation stands on. Neither spelling set is rejected.
    fn location(&self) -> Result<Place> {
        match self.settings.location() {
            Some(Location::Dir(dir)) => Ok(Place::Dir(NotedDir::new(dir))),
            Some(Location::Url(raw)) => Ok(Place::Endpoint(raw.parse()?)),
            None => Err(rejected("no notes dir set (--dir)")),
        }
    }
}

/// The location, resolved into what it names.
enum Place {
    Dir(NotedDir),
    Endpoint(Endpoint),
}
