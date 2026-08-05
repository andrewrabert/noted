use std::process::ExitCode;

use anstyle::{AnsiColor, Style};
use clap::{Args, Subcommand};
use serde_json::Value;

use noted::authorization::Bearer;
use noted::error::Result;
use noted::tasks::TaskState;
use noted::tools::{
    AttachToTaskArgs, CreateTaskArgs, GetLogArgs, GetTasksArgs, LogArgs, MoveTaskArgs,
    SearchLogArgs, SearchTasksArgs, ToolArgs, ToolOutput, UpdateTaskArgs,
};
use noted::{Backend, Endpoint, ToolCall};
use noted_client::authclient::Session;
use noted_client::credentials::CredentialStore;

use crate::GlobalArgs;
use crate::config::{block_on, credential_store_config};

#[derive(Args)]
pub(crate) struct TaskCmd {
    #[command(subcommand)]
    sub: TaskSub,
}

#[derive(Subcommand)]
enum TaskSub {
    Create(CreateTaskArgs),
    #[command(alias = "list")]
    Get(TaskGetCmd),
    Update(UpdateTaskArgs),
    #[command(name = "move")]
    Move(MoveTaskArgs),
    Attach(AttachToTaskArgs),
    Search(SearchTasksArgs),
}

#[derive(Args)]
struct TaskGetCmd {
    #[command(flatten)]
    args: GetTasksArgs,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub(crate) struct LogCmd {
    #[command(subcommand)]
    sub: LogSub,
}

#[derive(Subcommand)]
enum LogSub {
    Create(LogArgs),
    #[command(alias = "list")]
    Get(LogGetCmd),
    Search(SearchLogArgs),
}

#[derive(Args)]
struct LogGetCmd {
    #[command(flatten)]
    args: GetLogArgs,
    #[arg(long)]
    json: bool,
}

pub(crate) struct Dispatch {
    call: ToolCall,
    render: Render,
    empty_is_failure: bool,
}

enum Render {
    Passthrough,
    Tasks { as_json: bool },
    Log { as_json: bool },
}

pub(crate) fn passthrough_of<A: ToolArgs>(args: A) -> Result<Dispatch> {
    Ok(Dispatch {
        call: ToolCall::new(args)?,
        render: Render::Passthrough,
        empty_is_failure: false,
    })
}

pub(crate) fn search<A: ToolArgs>(args: A) -> Result<Dispatch> {
    let mut d = passthrough_of(args)?;
    d.empty_is_failure = true;
    Ok(d)
}

pub(crate) fn build_task(cmd: TaskCmd) -> Result<Dispatch> {
    Ok(match cmd.sub {
        TaskSub::Create(c) => passthrough_of(c)?,
        TaskSub::Get(c) => Dispatch {
            call: ToolCall::new(c.args)?,
            render: Render::Tasks { as_json: c.json },
            empty_is_failure: false,
        },
        TaskSub::Update(c) => passthrough_of(c)?,
        TaskSub::Move(c) => passthrough_of(c)?,
        TaskSub::Attach(c) => passthrough_of(c)?,
        TaskSub::Search(c) => search(c)?,
    })
}

pub(crate) fn build_log(cmd: LogCmd) -> Result<Dispatch> {
    Ok(match cmd.sub {
        LogSub::Create(c) => passthrough_of(c)?,
        LogSub::Get(c) => Dispatch {
            call: ToolCall::new(c.args)?,
            render: Render::Log { as_json: c.json },
            empty_is_failure: false,
        },
        LogSub::Search(c) => search(c)?,
    })
}

pub(crate) fn run_dispatch(globals: &GlobalArgs, dispatch: Dispatch) -> Result<ExitCode> {
    use std::io::IsTerminal;
    let backend = build_backend(globals)?;
    let backend = backend.with_authority(None)?;
    tracing::debug!(tool = %dispatch.call.name(), "dispatching");
    let result = block_on(backend.invoke(&dispatch.call))?;
    let color = std::io::stdout().is_terminal();
    let out = render(&dispatch.render, &result, color);
    if out.is_empty() && dispatch.empty_is_failure {
        return Ok(ExitCode::FAILURE);
    }
    println!("{out}");
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn build_backend(globals: &GlobalArgs) -> Result<Backend> {
    let mut args = globals.backend_args(&crate::EntryFlags::default())?;
    let token = match args.endpoint.as_ref().and_then(Endpoint::tcp) {
        Some(url) => {
            let store = CredentialStore::open(credential_store_config()?);
            let session = Session::open(url, globals.token.as_deref(), store);
            block_on(session.bearer())?.map(Bearer::new)
        }
        None => globals
            .token
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(Bearer::new),
    };
    args.token = token;
    Backend::new(args)
}

fn render(render: &Render, result: &ToolOutput, color: bool) -> String {
    let (as_json, format): (bool, fn(&Value, bool) -> String) = match render {
        Render::Passthrough => return result.render(),
        Render::Tasks { as_json } => (*as_json, format_tasks),
        Render::Log { as_json } => (*as_json, format_log),
    };
    match result.record() {
        Some(records) if as_json => serde_json::to_string_pretty(records).unwrap_or_default(),
        Some(records) => format(records, color),
        None => result.render(),
    }
}

fn state_style(state: Option<TaskState>) -> Style {
    let color = match state {
        Some(TaskState::Created) => AnsiColor::White,
        Some(TaskState::Started) => AnsiColor::Cyan,
        Some(TaskState::Blocked) => AnsiColor::Yellow,
        Some(TaskState::Completed) => AnsiColor::Green,
        Some(TaskState::Rejected) => AnsiColor::Red,
        Some(TaskState::Invalid) => AnsiColor::Magenta,
        None => return Style::new(),
    };
    Style::new().fg_color(Some(color.into()))
}

fn paint(text: &str, style: Style, color: bool) -> String {
    if color {
        format!("{style}{text}{style:#}")
    } else {
        text.to_string()
    }
}

fn format_log(records: &Value, color: bool) -> String {
    let items = records.as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        return "no log entries".to_string();
    }
    let dim = Style::new().dimmed();
    let mut lines = Vec::new();
    for r in &items {
        let created = r["created"].as_str().unwrap_or("");
        let path = paint(r["path"].as_str().unwrap_or(""), Style::new().bold(), color);
        lines.push(format!("{} {path}", paint(created, dim, color)));
        if let Some(body) = r.get("body").and_then(|b| b.as_str())
            && !body.trim().is_empty()
        {
            for line in body.trim_end_matches('\n').lines() {
                lines.push(paint(&format!("    {line}"), dim, color));
            }
        }
    }
    lines.join("\n")
}

fn format_tasks(records: &Value, color: bool) -> String {
    let items = records.as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        return "no tasks".to_string();
    }
    let dim = Style::new().dimmed();
    let mut lines = Vec::new();
    for r in &items {
        let state = r["state"].as_str().unwrap_or("");
        let label = paint(
            &format!("{state:<9}"),
            state_style(state.parse::<TaskState>().ok()),
            color,
        );
        let path = paint(r["path"].as_str().unwrap_or(""), Style::new().bold(), color);
        let task = r["task"].as_str().unwrap_or("");
        lines.push(format!("{label} {path}  {task}"));
        let updated = r["updated_at"].as_str().unwrap_or("");
        lines.push(paint(&format!("          updated {updated}"), dim, color));
        if let Some(body) = r.get("body").and_then(|b| b.as_str())
            && !body.trim().is_empty()
        {
            for line in body.trim_end_matches('\n').lines() {
                lines.push(paint(&format!("          {line}"), dim, color));
            }
        }
    }
    lines.join("\n")
}
