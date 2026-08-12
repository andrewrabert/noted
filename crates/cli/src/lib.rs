use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};

use noted::error::{Result, io_error, rejected, unavailable};
use noted::tools::{DeleteArgs, EditArgs, MoveArgs, ReadArgs, SearchNotesArgs, WriteArgs};
use noted::types::Ttl;
use noted_auth::oauth::service::DEFAULT_CREDENTIAL_TTL_HUMAN;
use noted_server::serve::{Bind, HttpConfig, StdioConfig};

use crate::args::{AuthPaths, EntryFlags, EnvFileArg, GlobalArgs, parse_ttl};
use crate::config::{Config, EnvFile, Environment};

mod admin;
pub mod args;
mod auth;
pub mod config;
mod dispatch;
pub mod logging;
mod open;
mod picker;
mod prompt;
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

/// The env file argv names, learned before the real parse. Help, version and
/// every parse error are left to that parse: this one neither prints nor
/// exits.
pub fn env_file_arg<I, T>(argv: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = Cli::command()
        .ignore_errors(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .disable_help_subcommand(true)
        .try_get_matches_from(argv)
        .ok()?;
    EnvFileArg::from_arg_matches(&matches).ok()?.env_file
}

fn start() -> Result<ExitCode> {
    if let Some(env_file) = EnvFile::locate(env_file_arg(std::env::args_os()).as_deref()) {
        env_file.load()?;
    }
    let cli = Cli::parse();
    let config = Config::new(cli.globals, Environment::capture());
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
    #[arg(
        long = "default-ttl",
        env = "NOTED_DEFAULT_TTL",
        default_value = DEFAULT_CREDENTIAL_TTL_HUMAN,
        value_parser = parse_ttl
    )]
    default_ttl: Ttl,
    #[command(flatten)]
    entries: EntryFlags,
}

impl ServerArgs {
    /// The sole adapter from flags to core's server config. Validations whose
    /// messages name CLI flags belong here, not in core.
    fn into_config(
        self,
        config: &Config,
        bind: Bind,
        public_url: Option<String>,
    ) -> Result<HttpConfig> {
        #[cfg(unix)]
        if self.auth.admin_socket.is_some() && self.auth.auth_db.is_none() {
            return Err(rejected("--admin-socket requires --auth-db"));
        }
        Ok(HttpConfig {
            backend: config.backend_args(&self.entries)?,
            bind,
            public_url,
            auth_db: self.auth.auth_db,
            #[cfg(unix)]
            admin_socket: self.auth.admin_socket,
            default_ttl: self.default_ttl,
        })
    }
}

#[derive(Args)]
struct ServeCmd {
    #[arg(long, env = "NOTED_HOST", default_value = "127.0.0.1")]
    host: String,
    #[arg(long, env = "NOTED_PORT", default_value_t = 8000)]
    port: u16,
    #[arg(long = "public-url", env = "NOTED_PUBLIC_URL")]
    public_url: Option<String>,
    #[command(flatten)]
    server: ServerArgs,
}

impl ServeCmd {
    fn into_config(self, config: &Config) -> Result<HttpConfig> {
        if self.public_url.is_some() && self.server.auth.auth_db.is_none() {
            return Err(rejected("--public-url requires --auth-db"));
        }
        let bind = Bind::Tcp {
            host: self.host,
            port: self.port,
        };
        self.server.into_config(config, bind, self.public_url)
    }
}

/// Serve the HTTP app on a Unix socket
#[cfg(unix)]
#[derive(Args)]
struct SocketCmd {
    /// Socket to bind
    path: PathBuf,
    #[command(flatten)]
    server: ServerArgs,
}

#[cfg(unix)]
impl SocketCmd {
    fn into_config(self, config: &Config) -> Result<HttpConfig> {
        let path = std::path::absolute(&self.path)
            .map_err(|e| rejected(format!("socket path {}: {e}", self.path.display())))?;
        let bind = Bind::Socket(path);
        self.server.into_config(config, bind, None)
    }
}

#[derive(Args)]
struct McpCmd {
    #[command(flatten)]
    entries: EntryFlags,
}

impl McpCmd {
    fn into_config(self, config: &Config) -> Result<StdioConfig> {
        Ok(StdioConfig {
            backend: config.backend_args(&self.entries)?,
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
        ServerSub::Http(c) => noted_server::serve::serve_http(c.into_config(config)?)
            .await
            .map(|()| ExitCode::SUCCESS),
        #[cfg(unix)]
        ServerSub::Socket(c) => noted_server::serve::serve_http(c.into_config(config)?)
            .await
            .map(|()| ExitCode::SUCCESS),
        ServerSub::Mcp(c) => noted_server::serve::serve_stdio(c.into_config(config)?)
            .await
            .map(|()| ExitCode::SUCCESS),
        ServerSub::User(c) => admin::run_user(c, config).await.map(|()| ExitCode::SUCCESS),
        ServerSub::Key(c) => admin::run_key(c, config).await.map(|()| ExitCode::SUCCESS),
    }
}
