use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};

use noted::error::{Result, rejected, unavailable};
use noted::tools::{DeleteArgs, EditArgs, MoveArgs, ReadArgs, SearchNotesArgs, WriteArgs};
use noted::types::Ttl;
use noted::{BackendArgs, PolicyArgs};
use noted_auth::oauth::service::DEFAULT_CREDENTIAL_TTL_HUMAN;
use noted_server::serve::{HttpConfig, StdioConfig};

use crate::config::{parse_ttl, setup_logging};

mod admin;
mod auth;
mod config;
mod dispatch;
mod open;
mod picker;
mod text_editor;

use admin::{KeyCmd, UserCmd};
use auth::AuthCmd;
use dispatch::{LogCmd, TaskCmd};

pub fn main() -> ExitCode {
    config::load_env_file();
    let cli = Cli::parse();
    let _log_guard = match setup_logging(
        &cli.globals.log_level,
        cli.globals.log_file.as_deref().map(std::path::Path::new),
    ) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
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

#[derive(Args)]
struct GlobalArgs {
    #[arg(long, env = "NOTED_DIR", global = true)]
    dir: Option<String>,
    #[arg(long, env = "NOTED_URL", global = true)]
    url: Option<String>,
    #[arg(long, env = "NOTED_TOKEN", global = true)]
    token: Option<String>,
    /// Provenance recorded on log entries
    #[arg(short = 's', long, env = "NOTED_SOURCE", global = true)]
    source: Option<String>,
    #[arg(
        long = "log-level",
        env = "NOTED_LOG_LEVEL",
        global = true,
        default_value = "INFO"
    )]
    log_level: String,
    #[arg(long = "log-file", env = "NOTED_LOG_FILE", global = true)]
    log_file: Option<String>,
    #[arg(long, env = "NOTED_POLICY", global = true)]
    policy: Option<String>,
    #[arg(long, env = "NOTED_SCOPE", global = true)]
    scope: Option<String>,
}

impl GlobalArgs {
    pub(crate) fn policy_args(&self, entries: &EntryFlags) -> PolicyArgs {
        PolicyArgs {
            policy: self
                .policy
                .as_deref()
                .map(|raw| match raw.strip_prefix('@') {
                    Some(path) => format!("@{}", config::expand_home(path).display()),
                    None => raw.to_string(),
                }),
            scope: self.scope.clone(),
            inside: entries.in_.clone(),
        }
    }

    pub(crate) fn backend_args(&self, entries: &EntryFlags) -> BackendArgs {
        BackendArgs {
            dir: self
                .dir
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|dir| config::expand_home(dir).to_string_lossy().into_owned()),
            url: self.url.clone(),
            token: None,
            source: self.source.clone(),
            policy: self.policy_args(entries),
            transport: None,
        }
    }
}

#[derive(Args, Default)]
pub(crate) struct EntryFlags {
    #[arg(long = "in", value_name = "PATH[=MODES]")]
    in_: Vec<String>,
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
    /// Open a note in $EDITOR
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
    Mcp(McpCmd),
    User(UserCmd),
    Key(KeyCmd),
}

#[derive(Args)]
struct ServeCmd {
    #[arg(long, env = "NOTED_HOST", default_value = "127.0.0.1")]
    host: String,
    #[arg(long, env = "NOTED_PORT", default_value_t = 8000)]
    port: u16,
    #[arg(long = "public-url", env = "NOTED_PUBLIC_URL")]
    public_url: Option<String>,
    #[arg(long = "auth-db", env = "NOTED_AUTH_DB")]
    auth_db: Option<PathBuf>,
    #[cfg(unix)]
    #[arg(long = "admin-socket", env = "NOTED_ADMIN_SOCKET")]
    admin_socket: Option<PathBuf>,
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

impl ServeCmd {
    /// The sole adapter from flags to core's server config. Validations whose
    /// messages name CLI flags belong here, not in core.
    fn into_config(self, globals: &GlobalArgs) -> Result<HttpConfig> {
        #[cfg(unix)]
        if self.admin_socket.is_some() && self.auth_db.is_none() {
            return Err(rejected("--admin-socket requires --auth-db"));
        }
        if self.public_url.is_some() && self.auth_db.is_none() {
            return Err(rejected("--public-url requires --auth-db"));
        }
        Ok(HttpConfig {
            backend: globals.backend_args(&self.entries),
            host: self.host,
            port: self.port,
            public_url: self.public_url,
            auth_db: self
                .auth_db
                .map(|p| config::expand_home(&p.to_string_lossy())),
            #[cfg(unix)]
            admin_socket: self.admin_socket,
            default_ttl: self.default_ttl,
        })
    }
}

#[derive(Args)]
struct McpCmd {
    #[command(flatten)]
    entries: EntryFlags,
}

impl McpCmd {
    fn into_config(self, globals: &GlobalArgs) -> Result<StdioConfig> {
        Ok(StdioConfig {
            backend: globals.backend_args(&self.entries),
        })
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let globals = cli.globals;
    let Some(command) = cli.command else {
        // No subcommand: emit the exact `--help` output (clap's own rendering,
        // to stdout, exit 0) rather than crafting a second help path.
        Cli::command()
            .print_help()
            .map_err(|e| unavailable(e.to_string()))?;
        return Ok(ExitCode::SUCCESS);
    };
    match command {
        Command::Search(c) => dispatch::run_dispatch(&globals, dispatch::search(c)?),
        Command::Read(c) => dispatch::run_dispatch(&globals, dispatch::passthrough_of(c)?),
        Command::Write(c) => dispatch::run_dispatch(&globals, dispatch::passthrough_of(c)?),
        Command::Edit(c) => dispatch::run_dispatch(&globals, dispatch::passthrough_of(c)?),
        Command::Open(c) => open::run_open(&globals, c),
        Command::Move(c) => dispatch::run_dispatch(&globals, dispatch::passthrough_of(c)?),
        Command::Delete(c) => dispatch::run_dispatch(&globals, dispatch::passthrough_of(c)?),
        Command::Log(c) => dispatch::run_dispatch(&globals, dispatch::build_log(c)?),
        Command::Task(c) => dispatch::run_dispatch(&globals, dispatch::build_task(c)?),
        Command::Auth(c) => auth::run_auth(c, &globals),
        Command::Server(c) => run_server(c, &globals),
    }
}

fn run_server(cmd: ServerCmd, globals: &GlobalArgs) -> Result<ExitCode> {
    match cmd.sub {
        ServerSub::Http(c) => {
            noted_server::serve::serve_http(c.into_config(globals)?).map(|()| ExitCode::SUCCESS)
        }
        ServerSub::Mcp(c) => {
            noted_server::serve::serve_stdio(c.into_config(globals)?).map(|()| ExitCode::SUCCESS)
        }
        ServerSub::User(c) => admin::run_user(c, globals).map(|()| ExitCode::SUCCESS),
        ServerSub::Key(c) => admin::run_key(c, globals).map(|()| ExitCode::SUCCESS),
    }
}
