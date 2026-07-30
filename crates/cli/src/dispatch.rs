use std::process::ExitCode;

use anstyle::{AnsiColor, Style};
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::Value;

use noted::authclient::Session;
use noted::backend::{Backend, ToolCall};
use noted::credentials::CredentialStore;
use noted::error::Result;
use noted::httpurl::HttpUrl;
use noted::notes::Notes;
use noted::tasks::{TaskState, Tasks};
use noted::tools::{CreateTaskArgs, GetTasksArgs, MoveTaskArgs, ToolOutput, UpdateTaskArgs};

use crate::GlobalArgs;
use crate::config::{block_on, credential_store_config, resolve_root};

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
}

#[derive(Args)]
struct TaskGetCmd {
    #[command(flatten)]
    args: GetTasksArgs,
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
}

pub(crate) fn call_of(name: &str, args: impl Serialize) -> ToolCall {
    ToolCall {
        name: name.to_string(),
        args: serde_json::to_value(args).expect("cli args serialize to json"),
    }
}

pub(crate) fn passthrough_of(name: &str, args: impl Serialize) -> Dispatch {
    Dispatch {
        call: call_of(name, args),
        render: Render::Passthrough,
        empty_is_failure: false,
    }
}

pub(crate) fn search(args: impl Serialize) -> Dispatch {
    let mut d = passthrough_of("SearchNotes", args);
    d.empty_is_failure = true;
    d
}

pub(crate) fn build_task(cmd: TaskCmd) -> Dispatch {
    match cmd.sub {
        TaskSub::Create(c) => passthrough_of("CreateTask", c),
        TaskSub::Get(c) => Dispatch {
            call: ToolCall {
                name: "GetTasks".into(),
                args: serde_json::to_value(c.args).expect("cli args serialize to json"),
            },
            render: Render::Tasks { as_json: c.json },
            empty_is_failure: false,
        },
        TaskSub::Update(c) => passthrough_of("UpdateTask", c),
        TaskSub::Move(c) => passthrough_of("MoveTask", c),
    }
}

pub(crate) fn run_dispatch(globals: &GlobalArgs, dispatch: Dispatch) -> Result<ExitCode> {
    use std::io::IsTerminal;
    let backend = build_backend(globals)?;
    tracing::debug!(tool = %dispatch.call.name, "dispatching");
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
    if let Some(url) = remote_url(globals)? {
        let store = CredentialStore::open(credential_store_config()?);
        let session = Session::open(&url, globals.token.as_deref(), store);
        let token = block_on(session.bearer())?;
        return Ok(Backend::http(&url, token));
    }
    let root = resolve_root(globals.dir.as_deref())?;
    let notes = Notes::new(&root, None)?;
    let tasks = Tasks::new(notes.root());
    Ok(Backend::filesystem(notes, tasks))
}

pub(crate) fn remote_url(globals: &GlobalArgs) -> Result<Option<HttpUrl>> {
    match globals.url.as_deref().filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => Ok(Some(s.parse()?)),
    }
}

fn render(render: &Render, result: &ToolOutput, color: bool) -> String {
    match render {
        Render::Passthrough => result.render(),
        Render::Tasks { as_json } => match result.record() {
            Some(records) if *as_json => serde_json::to_string_pretty(records).unwrap_or_default(),
            Some(records) => format_tasks(records, color),
            None => result.render(),
        },
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
