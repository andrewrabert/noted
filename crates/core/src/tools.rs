use clap::Args;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{Result, rejected, unavailable};
use crate::note::{Condition, Edit, TextNote};
use crate::path::RelPath;
use crate::root::NotedRoot;
use crate::scope::TokenScope;
use crate::search::{CaseMode, FileType, GlobPattern, SearchMode, SearchPattern, SearchQuery};
use crate::tasks::{GroupPath, TaskChange, TaskNote, TaskQuery, TaskRef, TaskState, TaskTitle};
use crate::types::{LogBody, NoteBody, TaskBody};
use crate::util::slice_lines;

pub struct ToolDef {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ToolOutput {
    Text(String),
    Written { path: String },
    Edited { path: String },
    Moved { from: String, to: String },
    Deleted { path: String },
    Logged { path: String },
    Record(Value),
}

impl ToolOutput {
    pub fn render(&self) -> String {
        match self {
            ToolOutput::Text(s) => s.clone(),
            ToolOutput::Written { path } => format!("wrote {path}"),
            ToolOutput::Edited { path } => format!("edited {path}"),
            ToolOutput::Moved { from, to } => format!("moved {from} -> {to}"),
            ToolOutput::Deleted { path } => format!("deleted {path}"),
            ToolOutput::Logged { path } => format!("logged {path}"),
            ToolOutput::Record(v) => serde_json::to_string_pretty(v).unwrap_or_default(),
        }
    }

    pub fn record(&self) -> Option<&Value> {
        match self {
            ToolOutput::Record(v) => Some(v),
            _ => None,
        }
    }
}

struct ToolSpec {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    schema: fn() -> Value,
}

const TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "SearchNotes",
        title: "Search notes",
        description: D_SEARCH,
        schema: schema_of::<SearchArgs>,
    },
    ToolSpec {
        name: "ReadNote",
        title: "Read note",
        description: D_READ,
        schema: schema_of::<ReadArgs>,
    },
    ToolSpec {
        name: "WriteNote",
        title: "Write note",
        description: D_WRITE,
        schema: schema_of::<WriteArgs>,
    },
    ToolSpec {
        name: "EditNote",
        title: "Edit note",
        description: D_EDIT,
        schema: schema_of::<EditArgs>,
    },
    ToolSpec {
        name: "MoveNote",
        title: "Move note",
        description: D_MOVE,
        schema: schema_of::<MoveArgs>,
    },
    ToolSpec {
        name: "DeleteNote",
        title: "Delete note",
        description: D_DELETE,
        schema: schema_of::<DeleteArgs>,
    },
    ToolSpec {
        name: "LogNote",
        title: "Log entry",
        description: D_LOG,
        schema: schema_of::<LogArgs>,
    },
    ToolSpec {
        name: "CreateTask",
        title: "Create task",
        description: D_CREATE_TASK,
        schema: schema_of::<CreateTaskArgs>,
    },
    ToolSpec {
        name: "GetTasks",
        title: "Get tasks",
        description: D_GET_TASKS,
        schema: schema_of::<GetTasksArgs>,
    },
    ToolSpec {
        name: "UpdateTask",
        title: "Update task",
        description: D_UPDATE_TASK,
        schema: schema_of::<UpdateTaskArgs>,
    },
    ToolSpec {
        name: "MoveTask",
        title: "Move task",
        description: D_MOVE_TASK,
        schema: schema_of::<MoveTaskArgs>,
    },
];

pub fn is_tool(name: &str) -> bool {
    TOOLS.iter().any(|t| t.name == name)
}

pub fn allowed_tools(scope: &TokenScope) -> Vec<&'static str> {
    TOOLS
        .iter()
        .filter(|t| scope.allows(t.name))
        .map(|t| t.name)
        .collect()
}

const D_SEARCH: &str = "Find notes by regular expression. 'pattern' is smart-case by default (case-insensitive unless it contains an uppercase letter; use '(?i)'/'(?-i)' to force) and defaults to '.' (matches everything, i.e. lists). 'mode' picks the result: 'any' (default) returns files matching by contents or path; 'line' returns 'path:lineno:text' matches ('--' between files) with 'context' surrounding lines; 'file' returns files whose contents match; 'path' returns files whose path matches. 'fixed' matches the pattern literally instead of as a regex. 'glob' restricts which paths are searched: a bare name scopes to that subtree/file, a '!'-prefixed entry excludes (repeatable).";
const D_READ: &str = "Read a note's text by relative path. Use offset/limit to page.";
const D_WRITE: &str = "Write a note, overwriting it. Creates parent directories. Never use for logging or timestamped entries — those must go through LogNote. Writing a path under Tasks/ edits an existing task: the write is normalized to the task frontmatter schema (task, state, created_at, updated_at) and cannot create a new task — use CreateTask for that.";
const D_EDIT: &str = "Revise a note in place via string-replace.";
const D_MOVE: &str = "Move or rename a note or folder within the tree. A folder moves its whole subtree. Creates missing parent dirs. 'overwrite' replaces an existing file; a non-empty destination folder is refused.";
const D_DELETE: &str = "Delete a note by relative path. Removal is recoverable by an operator but not undoable through these tools.";
const D_LOG: &str = "Append an immutable, timestamped log entry. 'body' is free-form; all metadata (created time with offset, cwd, host) is captured automatically into a YAML sidecar — nothing to fill in. Entries are written under Log/YYYY/MM/ and CANNOT be edited, moved, or deleted through these tools; they are write-once. They still appear in SearchNotes.";
const D_CREATE_TASK: &str = "START HERE for any non-trivial unit of work. Opens a task as a searchable note under Tasks/, returning its summary record (path, state). 'task' is a one-line statement of the work; optional 'notes' seeds the markdown body; optional 'group' places it in a (nested, auto-created) subdirectory under Tasks/ — e.g. group='dev/noted'. noted assigns the filename automatically (the next 'task_NNNN' in that group); the task is thereafter identified by its Tasks-relative path minus '.md' (e.g. 'dev/noted/task_0001'). Group and task names must start with a letter and use only letters/digits/'-'/'_'. State starts 'created'. Afterward, change a task with UpdateTask (state/notes) or MoveTask (group); do NOT use WriteNote/EditNote — they are refused under Tasks/. States: created (not started), started (in progress), blocked (stuck), completed (work finished), rejected (declined/refused), invalid (task was ill-posed or moot). 'completed' means the work is genuinely finished; if you are giving up, use rejected/invalid — never mark 'completed'. blocked/completed/rejected/invalid require a non-empty body explaining why.";
const D_GET_TASKS: &str = "Check this BEFORE starting new work to recover existing tasks. Reads tasks as summary records, newest-updated first. 'prefix' is a Tasks-relative scope: empty = the whole tree; a group (e.g. 'dev') = that subtree; an exact task path (e.g. 'dev/noted/task_0001') = just that one task. 'body' attaches each task's markdown notes (the working body) to the record — use it to read a specific task in full. Closed tasks (completed/rejected/invalid) are hidden unless include_completed is set (an exact task path is always returned). Always returns a JSON array. Change a task with UpdateTask/MoveTask.";
const D_UPDATE_TASK: &str = "Change an existing task, identified by its Tasks-relative path (e.g. 'dev/noted/task_0001'). Set 'state' to advance it, 'notes' to replace the working body, and/or 'task' to reword the one-liner; omitted fields are left as-is. Returns the updated summary. States: created (not started), started (in progress), blocked (stuck), completed (work finished), rejected (declined/refused), invalid (ill-posed/moot); blocked/completed/rejected/invalid require a non-empty body explaining why. created_at is immutable; updated_at is stamped for you.";
const D_MOVE_TASK: &str = "Change a task's group. Re-homes the task (identified by its current Tasks-relative path) into another group under Tasks/; a numbered task is given a fresh 'task_NNNN' in the destination (so its path changes), a custom-named task keeps its name. 'group' is the destination subdirectory (nested, auto-created); '' moves it to the top of Tasks/. updated_at is re-stamped. Returns the summary at its new path.";

fn default_pattern() -> SearchPattern {
    SearchPattern::everything()
}
fn default_context() -> i64 {
    1
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct SearchArgs {
    #[arg(default_value = ".")]
    #[serde(default = "default_pattern")]
    pattern: SearchPattern,
    #[arg(long, default_value = "any")]
    #[serde(default)]
    mode: SearchMode,
    #[arg(long, default_value_t = 1)]
    #[serde(default = "default_context")]
    context: i64,
    #[arg(long)]
    #[serde(default)]
    fixed: bool,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    glob: Vec<GlobPattern>,
    #[arg(long, default_value = "smart")]
    #[serde(default)]
    #[schemars(skip)]
    case: CaseMode,
    #[arg(long)]
    #[serde(default)]
    #[schemars(skip)]
    word: bool,
    #[arg(long)]
    #[serde(default)]
    #[schemars(skip)]
    multiline: bool,
    #[arg(long = "type")]
    #[serde(rename = "type", default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(skip)]
    type_: Vec<FileType>,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct ReadArgs {
    path: RelPath,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    offset: Option<i64>,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limit: Option<i64>,
}

impl ReadArgs {
    pub fn new(path: RelPath) -> ReadArgs {
        ReadArgs {
            path,
            offset: None,
            limit: None,
        }
    }
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct WriteArgs {
    path: RelPath,
    content: NoteBody,
    #[arg(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(skip)]
    when: Option<Condition>,
}

impl WriteArgs {
    pub fn new(path: RelPath, content: impl Into<NoteBody>) -> WriteArgs {
        WriteArgs {
            path,
            content: content.into(),
            when: None,
        }
    }

    pub fn when(mut self, when: Condition) -> WriteArgs {
        self.when = Some(when);
        self
    }
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct EditArgs {
    path: RelPath,
    old_string: String,
    new_string: String,
    #[arg(long = "replace-all")]
    #[serde(default)]
    replace_all: bool,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct MoveArgs {
    path: RelPath,
    dest: RelPath,
    #[arg(long)]
    #[serde(default)]
    overwrite: bool,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct DeleteArgs {
    path: RelPath,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct LogArgs {
    body: LogBody,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct CreateTaskArgs {
    task: TaskTitle,
    #[arg(long, default_value = "")]
    #[serde(default)]
    group: GroupPath,
    #[arg(long, default_value = "")]
    #[serde(default)]
    notes: TaskBody,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct GetTasksArgs {
    #[arg(default_value = "")]
    #[serde(default)]
    prefix: TaskRef,
    #[arg(long)]
    #[serde(default)]
    body: bool,
    #[arg(long = "include-completed")]
    #[serde(default)]
    include_completed: bool,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct UpdateTaskArgs {
    path: TaskRef,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<TaskState>,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<TaskBody>,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    task: Option<TaskTitle>,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct MoveTaskArgs {
    path: TaskRef,
    #[arg(default_value = "")]
    #[serde(default)]
    group: GroupPath,
}

fn schema_of<T: JsonSchema>() -> Value {
    let generator = schemars::generate::SchemaSettings::draft07()
        .with(|s| s.inline_subschemas = true)
        .into_generator();
    let mut v =
        serde_json::to_value(generator.into_root_schema_for::<T>()).unwrap_or_else(|_| json!({}));
    if let Value::Object(m) = &mut v {
        m.remove("$schema");
        m.remove("title");
        m.remove("definitions");
    }
    v
}

pub fn tool_defs() -> Vec<ToolDef> {
    TOOLS
        .iter()
        .map(|t| ToolDef {
            name: t.name,
            title: t.title,
            description: t.description,
            input_schema: (t.schema)(),
        })
        .collect()
}

fn parse<T: serde::de::DeserializeOwned>(args: &Value) -> Result<T> {
    serde_json::from_value(args.clone()).map_err(|e| rejected(e.to_string()))
}

pub async fn run_tool(name: &str, args: &Value, root: &NotedRoot) -> Result<ToolOutput> {
    if !TOOLS.iter().any(|t| t.name == name) {
        return Err(rejected(format!("Unknown tool: {name}")));
    }
    if name == "SearchNotes" {
        return run_search(parse(args)?, root).await;
    }
    let name = name.to_string();
    let args = args.clone();
    let root = root.clone();
    tokio::task::spawn_blocking(move || run_tool_sync(&name, &args, &root))
        .await
        .map_err(|e| unavailable(format!("tool task failed: {e}")))?
}

fn run_tool_sync(name: &str, args: &Value, root: &NotedRoot) -> Result<ToolOutput> {
    match name {
        "ReadNote" => {
            let a: ReadArgs = parse(args)?;
            let note = root.note_read(&a.path)?;
            Ok(ToolOutput::Text(slice_lines(
                note.body().as_str(),
                a.offset,
                a.limit,
            )))
        }
        "WriteNote" => {
            let a: WriteArgs = parse(args)?;
            let note = TextNote::new(a.path, a.content);
            root.note_write(&note, a.when.unwrap_or_default())?;
            Ok(ToolOutput::Written {
                path: note.path().to_string(),
            })
        }
        "EditNote" => {
            let a: EditArgs = parse(args)?;
            let edit = Edit::new(a.old_string, a.new_string, a.replace_all);
            root.note_edit(&a.path, &edit)?;
            Ok(ToolOutput::Edited {
                path: a.path.to_string(),
            })
        }
        "MoveNote" => {
            let a: MoveArgs = parse(args)?;
            root.note_move(&a.path, &a.dest, a.overwrite)?;
            Ok(ToolOutput::Moved {
                from: a.path.to_string(),
                to: a.dest.to_string(),
            })
        }
        "DeleteNote" => {
            let a: DeleteArgs = parse(args)?;
            root.note_delete(&a.path)?;
            Ok(ToolOutput::Deleted {
                path: a.path.to_string(),
            })
        }
        "LogNote" => {
            let a: LogArgs = parse(args)?;
            let note = root.log_note(&a.body)?;
            Ok(ToolOutput::Logged {
                path: note.path().to_string(),
            })
        }
        "CreateTask" => {
            let a: CreateTaskArgs = parse(args)?;
            let task = root.task_create(&a.task, &a.group, &a.notes)?;
            Ok(ToolOutput::Record(summary(&task, false)))
        }
        "GetTasks" => {
            let a: GetTasksArgs = parse(args)?;
            let query = TaskQuery {
                prefix: a.prefix,
                include_completed: a.include_completed,
            };
            let records: Vec<Value> = root
                .task_get(&query)?
                .iter()
                .map(|task| summary(task, a.body))
                .collect();
            Ok(ToolOutput::Record(Value::Array(records)))
        }
        "UpdateTask" => {
            let a: UpdateTaskArgs = parse(args)?;
            let change = TaskChange {
                state: a.state,
                notes: a.notes,
                task: a.task,
            };
            let task = root.task_update(&a.path, &change)?;
            Ok(ToolOutput::Record(summary(&task, false)))
        }
        "MoveTask" => {
            let a: MoveTaskArgs = parse(args)?;
            let task = root.task_move(&a.path, &a.group)?;
            Ok(ToolOutput::Record(summary(&task, false)))
        }
        _ => Err(rejected(format!("Unknown tool: {name}"))),
    }
}

fn summary(task: &TaskNote, body: bool) -> Value {
    let front = task.front();
    let mut record = json!({
        "path": task.path(),
        "task": front.task,
        "state": front.state,
        "created_at": front.created_at,
        "updated_at": front.updated_at,
    });
    if body {
        record["body"] = json!(task.body());
    }
    record
}

async fn run_search(a: SearchArgs, root: &NotedRoot) -> Result<ToolOutput> {
    let mode = a.mode;
    let query = SearchQuery {
        pattern: a.pattern,
        mode,
        context: a.context.max(0) as u32,
        fixed: a.fixed,
        case: a.case,
        word: a.word,
        multiline: a.multiline,
        globs: a.glob,
        types: a.type_,
    };
    let hits = root.search(&query).await?;

    if !matches!(mode, SearchMode::Line) {
        let paths: Vec<&str> = hits.iter().map(|hit| hit.path.as_str()).collect();
        return Ok(ToolOutput::Text(paths.join("\n")));
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
    Ok(ToolOutput::Text(out))
}
