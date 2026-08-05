use base64::Engine;
use noted::search::{SearchMode, SearchOrder};
use noted::tools::ToolOutput;
use noted::{Backend, BackendArgs, ToolCall};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct SearchNotesArgs {
    pub pattern: String,
    pub mode: SearchMode,
    pub sort: SearchOrder,
}

#[derive(Clone, Serialize)]
pub struct SearchLogArgs {
    pub pattern: String,
    pub mode: SearchMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    pub limit: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchTasksArgs {
    pub pattern: String,
    pub prefix: String,
    pub include_completed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetLogArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    pub body: bool,
    pub limit: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadArgs {
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WriteArgs {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EditArgs {
    pub path: String,
    pub old_string: String,
    pub new_string: String,
    pub replace_all: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MoveArgs {
    pub path: String,
    pub dest: String,
    pub overwrite: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeleteArgs {
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogArgs {
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateTaskArgs {
    pub task: String,
    pub group: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetTasksArgs {
    pub prefix: String,
    pub body: bool,
    pub include_completed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateTaskArgs {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MoveTaskArgs {
    pub path: String,
    pub group: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttachToTaskArgs {
    pub path: String,
    pub name: String,
    pub content: String,
}

fn raw(name: &str, args: impl Serialize) -> noted::Result<ToolCall> {
    ToolCall::raw(
        name,
        serde_json::to_value(args).unwrap_or(serde_json::Value::Null),
    )
}

fn pattern_or_all(pattern: &str) -> String {
    if pattern.trim().is_empty() {
        ".".to_string()
    } else {
        pattern.to_string()
    }
}

/// An empty bound is omitted rather than sent: the tool reads a missing bound as
/// unbounded and an empty string as a malformed instant.
fn bound(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

pub fn search_notes(pattern: &str, mode: SearchMode, sort: SearchOrder) -> noted::Result<ToolCall> {
    raw(
        "SearchNotes",
        SearchNotesArgs {
            pattern: pattern_or_all(pattern),
            mode,
            sort,
        },
    )
}

pub fn search_log(pattern: &str, since: &str, until: &str, limit: i64) -> noted::Result<ToolCall> {
    raw(
        "SearchLog",
        SearchLogArgs {
            pattern: pattern_or_all(pattern),
            mode: SearchMode::Line,
            since: bound(since),
            until: bound(until),
            limit,
        },
    )
}

pub fn search_tasks(
    pattern: &str,
    prefix: &str,
    include_completed: bool,
) -> noted::Result<ToolCall> {
    raw(
        "SearchTasks",
        SearchTasksArgs {
            pattern: pattern_or_all(pattern),
            prefix: prefix.to_string(),
            include_completed,
        },
    )
}

pub fn get_log(since: &str, until: &str, limit: i64) -> noted::Result<ToolCall> {
    raw(
        "GetLog",
        GetLogArgs {
            since: bound(since),
            until: bound(until),
            body: true,
            limit,
        },
    )
}

pub fn read_note(path: &str) -> noted::Result<ToolCall> {
    raw(
        "ReadNote",
        ReadArgs {
            path: path.to_string(),
        },
    )
}

pub fn write_note(path: &str, content: &str) -> noted::Result<ToolCall> {
    raw(
        "WriteNote",
        WriteArgs {
            path: path.to_string(),
            content: content.to_string(),
        },
    )
}

pub fn edit_note(
    path: &str,
    old_string: &str,
    new_string: &str,
    replace_all: bool,
) -> noted::Result<ToolCall> {
    raw(
        "EditNote",
        EditArgs {
            path: path.to_string(),
            old_string: old_string.to_string(),
            new_string: new_string.to_string(),
            replace_all,
        },
    )
}

pub fn move_note(path: &str, dest: &str, overwrite: bool) -> noted::Result<ToolCall> {
    raw(
        "MoveNote",
        MoveArgs {
            path: path.to_string(),
            dest: dest.to_string(),
            overwrite,
        },
    )
}

pub fn delete_note(path: &str) -> noted::Result<ToolCall> {
    raw(
        "DeleteNote",
        DeleteArgs {
            path: path.to_string(),
        },
    )
}

pub fn log_note(body: &str) -> noted::Result<ToolCall> {
    raw(
        "LogNote",
        LogArgs {
            body: body.to_string(),
        },
    )
}

pub fn create_task(task: &str, group: &str, notes: &str) -> noted::Result<ToolCall> {
    raw(
        "CreateTask",
        CreateTaskArgs {
            task: task.to_string(),
            group: group.to_string(),
            notes: notes.to_string(),
        },
    )
}

pub fn get_tasks(prefix: &str, body: bool, include_completed: bool) -> noted::Result<ToolCall> {
    raw(
        "GetTasks",
        GetTasksArgs {
            prefix: prefix.to_string(),
            body,
            include_completed,
        },
    )
}

pub fn update_task(
    path: &str,
    state: Option<&str>,
    notes: Option<&str>,
    task: Option<&str>,
) -> noted::Result<ToolCall> {
    raw(
        "UpdateTask",
        UpdateTaskArgs {
            path: path.to_string(),
            state: state.map(str::to_string),
            notes: notes.map(str::to_string),
            task: task.map(str::to_string),
        },
    )
}

pub fn move_task(path: &str, group: &str) -> noted::Result<ToolCall> {
    raw(
        "MoveTask",
        MoveTaskArgs {
            path: path.to_string(),
            group: group.to_string(),
        },
    )
}

pub fn attach_to_task(path: &str, name: &str, text: &str) -> noted::Result<ToolCall> {
    raw(
        "AttachToTask",
        AttachToTaskArgs {
            path: path.to_string(),
            name: name.to_string(),
            content: base64::engine::general_purpose::STANDARD.encode(text.as_bytes()),
        },
    )
}

pub fn paths(output: &ToolOutput) -> Vec<String> {
    match output {
        ToolOutput::Text(s) => s
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

pub fn text(output: ToolOutput) -> String {
    match output {
        ToolOutput::Text(s) => s,
        other => other.render(),
    }
}

pub fn record(output: ToolOutput) -> serde_json::Value {
    match output {
        ToolOutput::Record(v) => v,
        _ => serde_json::Value::Null,
    }
}

pub async fn invoke(call: noted::Result<ToolCall>) -> Result<ToolOutput, String> {
    let call = call.map_err(message)?;
    let backend = Backend::new(BackendArgs {
        url: Some(origin()?),
        ..Default::default()
    })
    .map_err(message)?;
    backend
        .with_authority(None)
        .map_err(message)?
        .invoke(&call)
        .await
        .map_err(message)
}

#[cfg(target_arch = "wasm32")]
fn origin() -> Result<String, String> {
    web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .ok_or_else(|| "the page has no origin".to_string())
}

#[cfg(not(target_arch = "wasm32"))]
fn origin() -> Result<String, String> {
    Err("the noted web UI runs in a browser".to_string())
}

fn message(error: noted::NotedError) -> String {
    error.message().into_owned()
}
