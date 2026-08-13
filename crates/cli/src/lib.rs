use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};

use noted::error::{Result, io_error, rejected, unavailable};
use noted::tools::{DeleteArgs, EditArgs, MoveArgs, ReadArgs, SearchNotesArgs, WriteArgs};
use noted_auth::service::DEFAULT_CREDENTIAL_TTL;
use noted_server::serve::{Bind, HttpConfig, StdioConfig};
#[cfg(unix)]
use noted_server::socket::{SocketBind, SocketEnv};

use crate::args::{AuthPaths, EntryFlags, GlobalArgs};
use crate::config::{Config, EnvFile};
use crate::settings::{Flags, Layer, Settings, Variable};

mod admin;
pub mod args;
mod auth;
pub mod config;
mod credential;
mod dispatch;
pub mod logging;
mod open;
mod picker;
mod prompt;
pub mod settings;
mod text_editor;

use admin::{KeyCmd, UserCmd};
use auth::AuthCmd;
use dispatch::{LogCmd, TaskCmd};

pub fn main() -> ExitCode {
    match start() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn start() -> Result<ExitCode> {
    let cli = Cli::parse();
    let flags = cli.flags();
    let near = Settings::resolve(vec![flags.clone(), Layer::environment()])?;
    let settings = match EnvFile::locate(near.get(Variable::EnvFile).map(Path::new)) {
        Some(file) => Settings::resolve(vec![flags, Layer::environment(), file.layer()?])?,
        None => near,
    };
    let config = Config::new(settings, dirs::config_dir());
    let _log = logging::init(config.log_filter(), config.log_file())?;
    let runtime = tokio::runtime::Runtime::new().map_err(|e| io_error("runtime", e))?;
    runtime.block_on(run(cli.command, &config))
}

#[derive(Parser)]
#[command(
    name = "noted",
    about = "A tree of .md notes as a CLI, MCP server, and HTTP API",
    version
)]
struct Cli {
    #[command(flatten)]
    globals: GlobalArgs,
    #[command(subcommand)]
    command: Option<Command>,
}

impl Cli {
    /// Everything the command line binds, whatever spells it: the global
    /// flags and every flag a subcommand carries for itself.
    fn flags(&self) -> Layer {
        let mut layer = Layer::flags();
        self.globals.write(&mut layer);
        match &self.command {
            Some(Command::Auth(c)) => c.write(&mut layer),
            Some(Command::Server(c)) => match &c.sub {
                ServerSub::Http(c) => c.write(&mut layer),
                #[cfg(unix)]
                ServerSub::Socket(c) => c.write(&mut layer),
                ServerSub::Mcp(c) => c.write(&mut layer),
                ServerSub::User(c) => c.write(&mut layer),
                ServerSub::Key(c) => c.write(&mut layer),
            },
            _ => {}
        }
        layer
    }
}

#[derive(Subcommand)]
enum Command {
    /// Find notes by regex
    Search(SearchNotesArgs),
    /// Read a note's text by relative path
    Read(ReadArgs),
    /// Write a note, overwriting it
    Write(WriteArgs),
    /// Revise a note in place via string-replace
    Edit(EditArgs),
    /// Open a note in your editor
    Open(open::OpenArgs),
    /// Move or rename a note or folder
    #[command(name = "move")]
    Move(MoveArgs),
    /// Move a note to trash
    Delete(DeleteArgs),
    /// Immutable, timestamped log entries
    Log(LogCmd),
    /// Task tracker
    Task(TaskCmd),
    /// Log in to a remote server and mint agent credentials
    Auth(AuthCmd),
    /// Run and manage the server
    Server(ServerCmd),
}

#[derive(Args)]
struct ServerCmd {
    #[command(subcommand)]
    sub: ServerSub,
}

#[derive(Subcommand)]
enum ServerSub {
    Http(ServeCmd),
    #[cfg(unix)]
    Socket(SocketCmd),
    Mcp(McpCmd),
    User(UserCmd),
    Key(KeyCmd),
}

/// What every served backend takes, whatever it binds
#[derive(Args)]
struct ServerArgs {
    #[command(flatten)]
    auth: AuthPaths,
    #[arg(long = "default-ttl")]
    default_ttl: Option<String>,
    #[command(flatten)]
    entries: EntryFlags,
}

impl Flags for ServerArgs {
    fn write(&self, layer: &mut Layer) {
        self.auth.write(layer);
        layer.set(Variable::DefaultTtl, self.default_ttl.as_deref());
    }
}

impl ServerArgs {
    /// The sole adapter from settings to the server's own config.
    /// Validations whose messages name CLI flags belong here.
    async fn into_config(
        self,
        config: &Config,
        bind: Bind,
        public_url: Option<String>,
    ) -> Result<HttpConfig> {
        let auth_db = config.setting(Variable::AuthDb).map(PathBuf::from);
        #[cfg(unix)]
        let admin_socket = config.setting(Variable::AdminSocket).map(PathBuf::from);
        #[cfg(unix)]
        if admin_socket.is_some() && auth_db.is_none() {
            return Err(rejected("--admin-socket requires --auth-db"));
        }
        Ok(HttpConfig {
            served: config.served(&self.entries).await?,
            bind,
            public_url,
            auth_db,
            #[cfg(unix)]
            admin_socket,
            default_ttl: config.ttl(Variable::DefaultTtl, DEFAULT_CREDENTIAL_TTL)?,
        })
    }
}

#[derive(Args)]
struct ServeCmd {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<String>,
    #[arg(long = "public-url")]
    public_url: Option<String>,
    #[command(flatten)]
    server: ServerArgs,
}

impl Flags for ServeCmd {
    fn write(&self, layer: &mut Layer) {
        layer.set(Variable::Host, self.host.as_deref());
        layer.set(Variable::Port, self.port.as_deref());
        layer.set(Variable::PublicUrl, self.public_url.as_deref());
        self.server.write(layer);
    }
}

impl ServeCmd {
    async fn into_config(self, config: &Config) -> Result<HttpConfig> {
        let public_url = config.setting(Variable::PublicUrl).map(str::to_string);
        if public_url.is_some() && config.setting(Variable::AuthDb).is_none() {
            return Err(rejected("--public-url requires --auth-db"));
        }
        let bind = Bind::Tcp {
            host: config
                .setting(Variable::Host)
                .unwrap_or("127.0.0.1")
                .to_string(),
            port: match config.setting(Variable::Port) {
                None => 8000,
                Some(raw) => raw
                    .parse()
                    .map_err(|e| rejected(format!("{}: {e}", Variable::Port.name())))?,
            },
        };
        self.server.into_config(config, bind, public_url).await
    }
}

/// Serve the HTTP app on a Unix socket
#[cfg(unix)]
#[derive(Args)]
struct SocketCmd {
    /// Socket to bind; one is picked under $XDG_RUNTIME_DIR when omitted
    path: Option<PathBuf>,
    #[command(flatten)]
    server: ServerArgs,
}

#[cfg(unix)]
impl Flags for SocketCmd {
    fn write(&self, layer: &mut Layer) {
        self.server.write(layer);
    }
}

#[cfg(unix)]
impl SocketCmd {
    async fn into_config(self, config: &Config) -> Result<HttpConfig> {
        let spec = match &self.path {
            Some(path) => SocketBind::Explicit(
                std::path::absolute(path)
                    .map_err(|e| rejected(format!("socket path {}: {e}", path.display())))?,
            ),
            None => SocketBind::Picked(SocketEnv::capture()),
        };
        self.server
            .into_config(config, Bind::Socket(spec), None)
            .await
    }
}

#[derive(Args)]
struct McpCmd {
    #[command(flatten)]
    entries: EntryFlags,
}

impl Flags for McpCmd {
    fn write(&self, _layer: &mut Layer) {}
}

impl McpCmd {
    async fn into_config(self, config: &Config) -> Result<StdioConfig> {
        Ok(StdioConfig {
            served: config.served(&self.entries).await?,
        })
    }
}

async fn run(command: Option<Command>, config: &Config) -> Result<ExitCode> {
    let Some(command) = command else {
        // No subcommand: emit the exact help output (clap's own rendering,
        // to stdout, exit 0) rather than crafting a second help path.
        Cli::command()
            .print_help()
            .map_err(|e| unavailable(e.to_string()))?;
        return Ok(ExitCode::SUCCESS);
    };
    match command {
        Command::Search(c) => dispatch::run_dispatch(config, dispatch::search(c)?).await,
        Command::Read(c) => dispatch::run_dispatch(config, dispatch::passthrough_of(c)?).await,
        Command::Write(c) => dispatch::run_dispatch(config, dispatch::passthrough_of(c)?).await,
        Command::Edit(c) => dispatch::run_dispatch(config, dispatch::passthrough_of(c)?).await,
        Command::Open(c) => open::run_open(config, c).await,
        Command::Move(c) => dispatch::run_dispatch(config, dispatch::passthrough_of(c)?).await,
        Command::Delete(c) => dispatch::run_dispatch(config, dispatch::passthrough_of(c)?).await,
        Command::Log(c) => dispatch::run_dispatch(config, dispatch::build_log(c)?).await,
        Command::Task(c) => dispatch::run_dispatch(config, dispatch::build_task(c)?).await,
        Command::Auth(c) => auth::run_auth(c, config).await,
        Command::Server(c) => run_server(c, config).await,
    }
}

async fn run_server(cmd: ServerCmd, config: &Config) -> Result<ExitCode> {
    match cmd.sub {
        ServerSub::Http(c) => noted_server::serve::serve_http(c.into_config(config).await?)
            .await
            .map(|()| ExitCode::SUCCESS),
        #[cfg(unix)]
        ServerSub::Socket(c) => noted_server::serve::serve_http(c.into_config(config).await?)
            .await
            .map(|()| ExitCode::SUCCESS),
        ServerSub::Mcp(c) => noted_server::serve::serve_stdio(c.into_config(config).await?)
            .await
            .map(|()| ExitCode::SUCCESS),
        ServerSub::User(c) => admin::run_user(c, config).await.map(|()| ExitCode::SUCCESS),
        ServerSub::Key(c) => admin::run_key(c, config).await.map(|()| ExitCode::SUCCESS),
    }
}
