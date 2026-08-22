use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use noted::error::{Result, rejected};

/// Every setting the CLI resolves, whatever layer carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variable {
    AdminSocket,
    AuthDb,
    DefaultTtl,
    Dir,
    Editor,
    EnvFile,
    Host,
    HostsFile,
    LogFile,
    LogLevel,
    Policy,
    Port,
    PublicUrl,
    Scope,
    Source,
    Token,
    Url,
    Visual,
}

const ALL: &[Variable] = &[
    Variable::AdminSocket,
    Variable::AuthDb,
    Variable::DefaultTtl,
    Variable::Dir,
    Variable::Editor,
    Variable::EnvFile,
    Variable::Host,
    Variable::HostsFile,
    Variable::LogFile,
    Variable::LogLevel,
    Variable::Policy,
    Variable::Port,
    Variable::PublicUrl,
    Variable::Scope,
    Variable::Source,
    Variable::Token,
    Variable::Url,
    Variable::Visual,
];

impl Variable {
    pub fn name(self) -> &'static str {
        match self {
            Variable::AdminSocket => "NOTED_ADMIN_SOCKET",
            Variable::AuthDb => "NOTED_AUTH_DB",
            Variable::DefaultTtl => "NOTED_DEFAULT_TTL",
            Variable::Dir => "NOTED_DIR",
            Variable::Editor => "EDITOR",
            Variable::EnvFile => "NOTED_ENV_FILE",
            Variable::Host => "NOTED_HOST",
            Variable::HostsFile => "NOTED_HOSTS_FILE",
            Variable::LogFile => "NOTED_LOG_FILE",
            Variable::LogLevel => "NOTED_LOG_LEVEL",
            Variable::Policy => "NOTED_POLICY",
            Variable::Port => "NOTED_PORT",
            Variable::PublicUrl => "NOTED_PUBLIC_URL",
            Variable::Scope => "NOTED_SCOPE",
            Variable::Source => "NOTED_SOURCE",
            Variable::Token => "NOTED_TOKEN",
            Variable::Url => "NOTED_URL",
            Variable::Visual => "VISUAL",
        }
    }

    /// The flag an error names it by, where one spells it.
    pub fn flag(self) -> Option<&'static str> {
        match self {
            Variable::AdminSocket => Some("--admin-socket"),
            Variable::AuthDb => Some("--auth-db"),
            Variable::DefaultTtl => Some("--default-ttl"),
            Variable::Dir => Some("--dir"),
            Variable::Editor => None,
            Variable::EnvFile => Some("--env-file"),
            Variable::Host => Some("--host"),
            Variable::HostsFile => Some("--hosts-file"),
            Variable::LogFile => Some("--log-file"),
            Variable::LogLevel => Some("--log-level"),
            Variable::Policy => Some("--policy"),
            Variable::Port => Some("--port"),
            Variable::PublicUrl => Some("--public-url"),
            Variable::Scope => Some("--scope"),
            Variable::Source => Some("-s"),
            Variable::Token => Some("--token"),
            Variable::Url => Some("--url"),
            Variable::Visual => None,
        }
    }

    pub fn named(name: &str) -> Option<Variable> {
        ALL.iter().copied().find(|var| var.name() == name)
    }
}

/// Where a layer's bindings came from.
#[derive(Clone, Debug)]
pub enum Origin {
    Flags,
    Environment,
    File(PathBuf),
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Flags => f.write_str("the command line"),
            Origin::Environment => f.write_str("the environment"),
            Origin::File(path) => write!(f, "{}", path.display()),
        }
    }
}

/// One source of settings, read whole before anything resolves.
#[derive(Clone, Debug)]
pub struct Layer {
    origin: Origin,
    bindings: BTreeMap<Variable, String>,
}

impl Layer {
    pub fn flags() -> Layer {
        Layer {
            origin: Origin::Flags,
            bindings: BTreeMap::new(),
        }
    }

    pub fn environment() -> Layer {
        let mut layer = Layer {
            origin: Origin::Environment,
            bindings: BTreeMap::new(),
        };
        for var in ALL {
            layer.set(*var, std::env::var(var.name()).ok().as_deref());
        }
        layer
    }

    /// The file's bindings. A binding naming no setting is ignored; a
    /// malformed line is rejected, naming the file and the line.
    pub fn file(path: &Path, text: &str) -> Result<Layer> {
        let mut layer = Layer {
            origin: Origin::File(path.to_path_buf()),
            bindings: BTreeMap::new(),
        };
        let bindings = dotenvy::from_read_iter(text.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| rejected(format!("{}: {e}", path.display())))?;
        for (name, value) in bindings {
            if let Some(var) = Variable::named(&name) {
                layer.set(var, Some(&value));
            }
        }
        Ok(layer)
    }

    pub fn set(&mut self, var: Variable, value: Option<&str>) {
        if let Some(value) = value {
            self.bindings.insert(var, value.to_string());
        }
    }

    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// The value this layer binds. An empty value binds nothing.
    pub fn get(&self, var: Variable) -> Option<&str> {
        self.bindings
            .get(&var)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }
}

/// The one setting `NOTED_DIR` and `NOTED_URL` spell two ways.
pub enum Location {
    Dir(String),
    Url(String),
}

/// Every layer, nearest first.
pub struct Settings {
    layers: Vec<Layer>,
}

impl Settings {
    /// Nearest layer first. A layer setting both location spellings is
    /// refused, naming both and it; `EnvFile` in a file layer is dropped.
    pub fn resolve(layers: Vec<Layer>) -> Result<Settings> {
        let mut resolved = Vec::with_capacity(layers.len());
        for mut layer in layers {
            if layer.get(Variable::Dir).is_some() && layer.get(Variable::Url).is_some() {
                return Err(rejected(format!(
                    "{} and {} are one setting spelled two ways: {} sets both",
                    Variable::Dir.name(),
                    Variable::Url.name(),
                    layer.origin()
                )));
            }
            if matches!(layer.origin(), Origin::File(_)) {
                layer.bindings.remove(&Variable::EnvFile);
            }
            resolved.push(layer);
        }
        Ok(Settings { layers: resolved })
    }

    pub fn get(&self, var: Variable) -> Option<&str> {
        match var {
            Variable::Dir | Variable::Url => self.located().and_then(|layer| layer.get(var)),
            _ => self.layers.iter().find_map(|layer| layer.get(var)),
        }
    }

    /// The nearest layer that sets either spelling, discarding both from every
    /// layer below it.
    pub fn location(&self) -> Option<Location> {
        let layer = self.located()?;
        match (layer.get(Variable::Dir), layer.get(Variable::Url)) {
            (Some(dir), _) => Some(Location::Dir(dir.to_string())),
            (None, Some(url)) => Some(Location::Url(url.to_string())),
            (None, None) => None,
        }
    }

    fn located(&self) -> Option<&Layer> {
        self.layers
            .iter()
            .find(|layer| layer.get(Variable::Dir).is_some() || layer.get(Variable::Url).is_some())
    }
}

/// What a clap args struct writes into the command-line layer.
pub trait Flags {
    fn write(&self, layer: &mut Layer);
}
