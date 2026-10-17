use std::process::ExitCode;

use anstyle::{AnsiColor, Style};
use clap::{Args, Subcommand};
use serde_json::{Value, json};

use noted::error::Result;
use noted::search::{Hit, SearchMode};
use noted::tasks::{TaskNote, TaskState};
use noted::tools::{
    CreateTaskArgs, DeleteArgs, EditArgs, GetLogArgs, GetTasksArgs, LogArgs, MoveArgs,
    MoveTaskArgs, ReadArgs, SearchLogArgs, SearchNotesArgs, SearchTasksArgs, Tools, UpdateTaskArgs,
    WriteArgs,
};
use noted::util::slice_lines;
use noted::{LogNote, NotePath};

use crate::config::Config;

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

pub(crate) async fn search_notes(config: &Config, args: SearchNotesArgs) -> Result<ExitCode> {
    let mode = args.mode;
    let hits = config.connect().await?.search_notes(args).await?;
    let out = render_search(mode, &hits);
    if out.is_empty() {
        return Ok(ExitCode::FAILURE);
    }
    println!("{out}");
    Ok(ExitCode::SUCCESS)
}

pub(crate) async fn read_note(config: &Config, args: ReadArgs) -> Result<ExitCode> {
    let (offset, limit) = (args.offset, args.limit);
    let note = config.connect().await?.read_note(args).await?;
    println!("{}", slice_lines(note.body().as_str(), offset, limit));
    Ok(ExitCode::SUCCESS)
}

pub(crate) async fn write_note(config: &Config, args: WriteArgs) -> Result<ExitCode> {
    let path: NotePath = args.path.as_ref().clone();
    config.connect().await?.write_note(args).await?;
    println!("wrote {path}");
    Ok(ExitCode::SUCCESS)
}

pub(crate) async fn edit_note(config: &Config, args: EditArgs) -> Result<ExitCode> {
    let path: NotePath = args.path.as_ref().clone();
    config.connect().await?.edit_note(args).await?;
    println!("edited {path}");
    Ok(ExitCode::SUCCESS)
}

pub(crate) async fn move_note(config: &Config, args: MoveArgs) -> Result<ExitCode> {
    let from: NotePath = args.path.as_ref().clone();
    let to: NotePath = args.dest.as_ref().clone();
    config.connect().await?.move_note(args).await?;
    println!("moved {from} -> {to}");
    Ok(ExitCode::SUCCESS)
}

pub(crate) async fn delete_note(config: &Config, args: DeleteArgs) -> Result<ExitCode> {
    let path: NotePath = args.path.as_ref().clone();
    config.connect().await?.delete_note(args).await?;
    println!("deleted {path}");
    Ok(ExitCode::SUCCESS)
}

pub(crate) async fn run_log(config: &Config, cmd: LogCmd) -> Result<ExitCode> {
    use std::io::IsTerminal;
    let backend = config.connect().await?;
    let out = match cmd.sub {
        LogSub::Create(c) => {
            let entry = backend.log_note(c).await?;
            let path: &NotePath = entry.path().as_ref();
            format!("logged {path}")
        }
        LogSub::Get(c) => {
            let entries = backend.get_log(c.args).await?;
            match c.json {
                true => serde_json::to_string_pretty(&entries).unwrap_or_default(),
                false => format_log(&entries, std::io::stdout().is_terminal()),
            }
        }
        LogSub::Search(c) => {
            let mode = c.mode;
            let out = render_search(mode, &backend.search_log(c).await?);
            if out.is_empty() {
                return Ok(ExitCode::FAILURE);
            }
            out
        }
    };
    println!("{out}");
    Ok(ExitCode::SUCCESS)
}

pub(crate) async fn run_task(config: &Config, cmd: TaskCmd) -> Result<ExitCode> {
    use std::io::IsTerminal;
    let backend = config.connect().await?;
    let task = match cmd.sub {
        TaskSub::Create(c) => backend.create_task(c).await?,
        TaskSub::Update(c) => backend.update_task(c).await?,
        TaskSub::Move(c) => backend.move_task(c).await?,
        TaskSub::Get(c) => {
            let tasks = backend.get_tasks(c.args).await?;
            let out = match c.json {
                true => serde_json::to_string_pretty(&tasks).unwrap_or_default(),
                false => format_tasks(&tasks, std::io::stdout().is_terminal()),
            };
            println!("{out}");
            return Ok(ExitCode::SUCCESS);
        }
        TaskSub::Search(c) => {
            let mode = c.mode;
            let out = render_search(mode, &backend.search_tasks(c).await?);
            if out.is_empty() {
                return Ok(ExitCode::FAILURE);
            }
            println!("{out}");
            return Ok(ExitCode::SUCCESS);
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&task).unwrap_or_default()
    );
    Ok(ExitCode::SUCCESS)
}

// paths only, unless the search asked for lines: then `path:num:text`, `--` between hits
fn render_search<A: std::fmt::Display>(mode: SearchMode, hits: &[Hit<A>]) -> String {
    if !matches!(mode, SearchMode::Line) {
        let paths: Vec<String> = hits.iter().map(|hit| hit.path.to_string()).collect();
        return paths.join("\n");
    }

    use std::fmt::Write;
    let mut out = String::new();
    for (i, hit) in hits.iter().enumerate() {
        if i > 0 {
            out.push_str("\n--\n");
        }
        for (j, (num, text)) in hit.lines().enumerate() {
            if j > 0 {
                out.push('\n');
            }
            let _ = write!(out, "{}:{num}:{text}", hit.path);
        }
    }
    out
}

fn state_style(state: TaskState) -> Style {
    let color = match state {
        TaskState::Created => AnsiColor::White,
        TaskState::Started => AnsiColor::Cyan,
        TaskState::Blocked => AnsiColor::Yellow,
        TaskState::Completed => AnsiColor::Green,
        TaskState::Rejected => AnsiColor::Red,
        TaskState::Invalid => AnsiColor::Magenta,
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

// the wire spelling of a value: what the JSON records carried
fn format_log(entries: &[LogNote], color: bool) -> String {
    if entries.is_empty() {
        return "no log entries".to_string();
    }
    let spelled = |v: Value| v.as_str().unwrap_or("").to_string();
    let dim = Style::new().dimmed();
    let mut lines = Vec::new();
    for entry in entries {
        let created = spelled(json!(entry.front().created));
        let path = paint(&spelled(json!(entry.path())), Style::new().bold(), color);
        lines.push(format!("{} {path}", paint(&created, dim, color)));
        if !entry.body().trim().is_empty() {
            for line in entry.body().trim_end_matches('\n').lines() {
                lines.push(paint(&format!("    {line}"), dim, color));
            }
        }
    }
    lines.join("\n")
}

fn format_tasks(tasks: &[TaskNote], color: bool) -> String {
    if tasks.is_empty() {
        return "no tasks".to_string();
    }
    let spelled = |v: Value| v.as_str().unwrap_or("").to_string();
    let dim = Style::new().dimmed();
    let mut lines = Vec::new();
    for task in tasks {
        let front = task.front();
        let state = spelled(json!(front.state));
        let label = paint(&format!("{state:<9}"), state_style(front.state), color);
        let path = paint(&spelled(json!(task.path())), Style::new().bold(), color);
        let title = spelled(json!(front.task));
        lines.push(format!("{label} {path}  {title}"));
        let updated = spelled(json!(front.updated_at));
        lines.push(paint(&format!("          updated {updated}"), dim, color));
        let text = spelled(json!(task.body()));
        if !text.trim().is_empty() {
            for line in text.trim_end_matches('\n').lines() {
                lines.push(paint(&format!("          {line}"), dim, color));
            }
        }
    }
    lines.join("\n")
}
