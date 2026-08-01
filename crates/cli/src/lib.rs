use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};

use noted::error::{Result, rejected, unavailable};
use noted::mcp::CallScope;
use noted::oauth::service::DEFAULT_CREDENTIAL_TTL_HUMAN;
use noted::scope::RuleSpec;
use noted::serve::{HttpConfig, StdioConfig};
use noted::store::NotedDir;
use noted::tools::{DeleteArgs, EditArgs, MoveArgs, ReadArgs, SearchNotesArgs, WriteArgs};
use noted::types::{Source, Ttl};

use crate::config::{parse_ttl, resolve_root, setup_logging};

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
struct RuleFlags {
    #[arg(long)]
    tools: Option<String>,
    #[arg(long)]
    path: Option<String>,
    #[arg(long, conflicts_with_all = ["tools", "path"])]
    rules: Option<String>,
}

impl RuleFlags {
    fn to_specs(&self) -> Result<Option<Vec<RuleSpec>>> {
        if let Some(json) = &self.rules {
            let specs: Vec<RuleSpec> = serde_json::from_str(json)
                .map_err(|e| rejected(format!("bad --rules JSON: {e}")))?;
            return Ok(Some(specs));
        }
        if self.tools.is_none() && self.path.is_none() {
            return Ok(None);
        }
        Ok(Some(vec![RuleSpec {
            tools: self.tools.as_ref().map(|list| {
                list.split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            }),
            paths: self.path.clone().map(|p| vec![p]),
        }]))
    }

    fn to_call_scope(&self) -> Result<CallScope> {
        match self.to_specs()? {
            None => Ok(CallScope::Unconfined),
            Some(specs) => Ok(CallScope::Scoped(noted::scope::compile_rules(&specs)?)),
        }
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
    scope: RuleFlags,
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
            dir: NotedDir::new(resolve_root(globals.dir.as_deref())?),
            source: Source::from_opt(globals.source.clone()),
            host: self.host,
            port: self.port,
            public_url: self.public_url,
            auth_db: self
                .auth_db
                .map(|p| config::expand_home(&p.to_string_lossy())),
            #[cfg(unix)]
            admin_socket: self.admin_socket,
            default_ttl: self.default_ttl,
            scope: self.scope.to_call_scope()?,
        })
    }
}

#[derive(Args)]
struct McpCmd {
    #[command(flatten)]
    scope: RuleFlags,
}

impl McpCmd {
    fn into_config(self, globals: &GlobalArgs) -> Result<StdioConfig> {
        Ok(StdioConfig {
            dir: NotedDir::new(resolve_root(globals.dir.as_deref())?),
            source: Source::from_opt(globals.source.clone()),
            scope: self.scope.to_call_scope()?,
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
        Command::Search(c) => dispatch::run_dispatch(&globals, dispatch::search("SearchNotes", c)),
        Command::Read(c) => {
            dispatch::run_dispatch(&globals, dispatch::passthrough_of("ReadNote", c))
        }
        Command::Write(c) => {
            dispatch::run_dispatch(&globals, dispatch::passthrough_of("WriteNote", c))
        }
        Command::Edit(c) => {
            dispatch::run_dispatch(&globals, dispatch::passthrough_of("EditNote", c))
        }
        Command::Open(c) => open::run_open(&globals, c),
        Command::Move(c) => {
            dispatch::run_dispatch(&globals, dispatch::passthrough_of("MoveNote", c))
        }
        Command::Delete(c) => {
            dispatch::run_dispatch(&globals, dispatch::passthrough_of("DeleteNote", c))
        }
        Command::Log(c) => dispatch::run_dispatch(&globals, dispatch::build_log(c)),
        Command::Task(c) => dispatch::run_dispatch(&globals, dispatch::build_task(c)),
        Command::Auth(c) => auth::run_auth(c, &globals),
        Command::Server(c) => run_server(c, &globals),
    }
}

fn run_server(cmd: ServerCmd, globals: &GlobalArgs) -> Result<ExitCode> {
    match cmd.sub {
        ServerSub::Http(c) => {
            noted::serve::serve_http(c.into_config(globals)?).map(|()| ExitCode::SUCCESS)
        }
        ServerSub::Mcp(c) => {
            noted::serve::serve_stdio(c.into_config(globals)?).map(|()| ExitCode::SUCCESS)
        }
        ServerSub::User(c) => admin::run_user(c).map(|()| ExitCode::SUCCESS),
        ServerSub::Key(c) => admin::run_key(c).map(|()| ExitCode::SUCCESS),
    }
}

#[cfg(test)]
mod tests {
    use noted::caller::Policy;
    use noted::path::RelPath;

    use super::*;

    fn within(paths: &[&str]) -> Policy {
        Policy::within(paths.iter().map(|p| RelPath::new(*p).unwrap()).collect())
    }

    fn flags(tools: Option<&str>, path: Option<&str>, rules: Option<&str>) -> RuleFlags {
        RuleFlags {
            tools: tools.map(str::to_string),
            path: path.map(str::to_string),
            rules: rules.map(str::to_string),
        }
    }

    #[test]
    fn scope_flags_no_args_is_unconfined() {
        assert!(matches!(
            flags(None, None, None).to_call_scope().unwrap(),
            CallScope::Unconfined
        ));
    }

    #[test]
    fn scope_flags_tools_only_narrows_tools_whole_tree() {
        let CallScope::Scoped(s) = flags(Some("ReadNote"), None, None).to_call_scope().unwrap()
        else {
            panic!("expected a scoped process scope");
        };
        assert!(s.allows("ReadNote") && !s.allows("WriteNote"));
        assert_eq!(s.policy_for("ReadNote"), Policy::any());
    }

    #[test]
    fn scope_flags_path_only_confines_all_tools() {
        let CallScope::Scoped(s) = flags(None, Some("projects"), None).to_call_scope().unwrap()
        else {
            panic!("expected a scoped process scope");
        };
        assert!(s.allows("WriteNote"));
        assert_eq!(s.policy_for("WriteNote"), within(&["projects"]));
    }

    #[test]
    fn scope_flags_rules_json_carries_multiple_rules() {
        let json = r#"[{"tools": ["ReadNote"], "paths": ["projects"]},
                       {"tools": ["CreateTask"], "paths": ["Tasks/dev"]}]"#;
        let CallScope::Scoped(s) = flags(None, None, Some(json)).to_call_scope().unwrap() else {
            panic!("expected a scoped process scope");
        };
        assert!(s.allows("ReadNote") && s.allows("CreateTask") && !s.allows("WriteNote"));
        assert_eq!(s.policy_for("CreateTask"), within(&["Tasks/dev"]));
    }

    #[test]
    fn scope_flags_reject_unknown_tool_and_bad_json() {
        assert!(flags(Some("Nope"), None, None).to_call_scope().is_err());
        assert!(flags(None, None, Some("not json")).to_call_scope().is_err());
        assert!(
            flags(None, None, Some(r#"[{"path": ["a"]}]"#))
                .to_call_scope()
                .is_err()
        );
    }
}
