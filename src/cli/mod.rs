use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};

use crate::config::setup_logging;
use crate::error::{rejected, unavailable, Result};
use crate::mcp::CallScope;
use crate::oauth::service::DEFAULT_CREDENTIAL_TTL_HUMAN;
use crate::scope::RuleSpec;
use crate::tools::{DeleteArgs, EditArgs, LogArgs, MoveArgs, ReadArgs, SearchArgs, WriteArgs};

mod admin;
mod auth;
mod dispatch;

use admin::{KeyCmd, UserCmd};
use auth::AuthCmd;
use dispatch::TaskCmd;

pub fn main() -> ExitCode {
    crate::config::load_env_file();
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
    Search(SearchArgs),
    /// Read a note's text by relative path
    Read(ReadArgs),
    /// Write a note, overwriting it
    Write(WriteArgs),
    /// Revise a note in place via string-replace
    Edit(EditArgs),
    /// Move or rename a note or folder
    #[command(name = "move")]
    Move(MoveArgs),
    /// Move a note to trash
    Delete(DeleteArgs),
    /// Append an immutable, timestamped log entry
    Log(LogArgs),
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
pub(crate) struct RuleFlags {
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

    pub(crate) fn to_call_scope(&self) -> Result<CallScope> {
        match self.to_specs()? {
            None => Ok(CallScope::Unconfined),
            Some(specs) => Ok(CallScope::Scoped(crate::scope::compile_rules(&specs)?)),
        }
    }
}

#[derive(Args)]
pub(crate) struct ServeCmd {
    #[arg(long, env = "NOTED_HOST", default_value = "127.0.0.1")]
    pub(crate) host: String,
    #[arg(long, env = "NOTED_PORT", default_value_t = 8000)]
    pub(crate) port: u16,
    #[arg(long = "public-url", env = "NOTED_PUBLIC_URL")]
    pub(crate) public_url: Option<String>,
    #[arg(long = "auth-db", env = "NOTED_AUTH_DB")]
    pub(crate) auth_db: Option<PathBuf>,
    #[arg(long = "admin-socket", env = "NOTED_ADMIN_SOCKET")]
    pub(crate) admin_socket: Option<PathBuf>,
    #[arg(
        long = "default-ttl",
        env = "NOTED_DEFAULT_TTL",
        default_value = DEFAULT_CREDENTIAL_TTL_HUMAN,
        value_parser = crate::config::parse_ttl
    )]
    pub(crate) default_ttl: crate::types::Ttl,
    #[command(flatten)]
    pub(crate) scope: RuleFlags,
    #[arg(short = 's', long, env = "NOTED_SOURCE")]
    pub(crate) source: Option<String>,
}

#[derive(Args)]
pub(crate) struct McpCmd {
    #[command(flatten)]
    pub(crate) scope: RuleFlags,
    #[arg(short = 's', long, env = "NOTED_SOURCE")]
    pub(crate) source: Option<String>,
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
        Command::Search(c) => dispatch::run_dispatch(&globals, dispatch::search(c)),
        Command::Read(c) => {
            dispatch::run_dispatch(&globals, dispatch::passthrough_of("ReadNote", c))
        }
        Command::Write(c) => {
            dispatch::run_dispatch(&globals, dispatch::passthrough_of("WriteNote", c))
        }
        Command::Edit(c) => {
            dispatch::run_dispatch(&globals, dispatch::passthrough_of("EditNote", c))
        }
        Command::Move(c) => {
            dispatch::run_dispatch(&globals, dispatch::passthrough_of("MoveNote", c))
        }
        Command::Delete(c) => {
            dispatch::run_dispatch(&globals, dispatch::passthrough_of("DeleteNote", c))
        }
        Command::Log(c) => dispatch::run_dispatch(&globals, dispatch::passthrough_of("LogNote", c)),
        Command::Task(c) => dispatch::run_dispatch(&globals, dispatch::build_task(c)),
        Command::Auth(c) => auth::run_auth(c, &globals),
        Command::Server(c) => run_server(c, globals.dir),
    }
}

fn run_server(cmd: ServerCmd, dir: Option<String>) -> Result<ExitCode> {
    match cmd.sub {
        ServerSub::Http(c) => crate::serve::serve(c, dir).map(|()| ExitCode::SUCCESS),
        ServerSub::Mcp(c) => crate::serve::mcp_stdio(c, dir).map(|()| ExitCode::SUCCESS),
        ServerSub::User(c) => admin::run_user(c).map(|()| ExitCode::SUCCESS),
        ServerSub::Key(c) => admin::run_key(c).map(|()| ExitCode::SUCCESS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(s.folders_for("ReadNote"), None);
    }

    #[test]
    fn scope_flags_path_only_confines_all_tools() {
        let CallScope::Scoped(s) = flags(None, Some("projects"), None).to_call_scope().unwrap()
        else {
            panic!("expected a scoped process scope");
        };
        assert!(s.allows("WriteNote"));
        assert_eq!(
            s.folders_for("WriteNote"),
            Some(vec!["projects".to_string()])
        );
    }

    #[test]
    fn scope_flags_rules_json_carries_multiple_rules() {
        let json = r#"[{"tools": ["ReadNote"], "paths": ["projects"]},
                       {"tools": ["CreateTask"], "paths": ["Tasks/dev"]}]"#;
        let CallScope::Scoped(s) = flags(None, None, Some(json)).to_call_scope().unwrap() else {
            panic!("expected a scoped process scope");
        };
        assert!(s.allows("ReadNote") && s.allows("CreateTask") && !s.allows("WriteNote"));
        assert_eq!(
            s.folders_for("CreateTask"),
            Some(vec!["Tasks/dev".to_string()])
        );
    }

    #[test]
    fn scope_flags_reject_unknown_tool_and_bad_json() {
        assert!(flags(Some("Nope"), None, None).to_call_scope().is_err());
        assert!(flags(None, None, Some("not json")).to_call_scope().is_err());
        assert!(flags(None, None, Some(r#"[{"path": ["a"]}]"#))
            .to_call_scope()
            .is_err());
    }
}
