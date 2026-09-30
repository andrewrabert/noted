use clap::Args;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::domain::{DirPath, LogPath, NotePath, TaskPath, TextPath};
use crate::error::{Result, rejected};
use crate::note::{Condition, Edit, LogNote, LogQuery, TextNote};
use crate::policy::Policy;
use crate::root::NotedRoot;
use crate::search::{
    CaseMode, FileType, GlobPattern, Hit, SearchMode, SearchOrder, SearchPattern, SearchQuery,
};
use crate::tasks::{TaskChange, TaskNote, TaskQuery, TaskSearch, TaskState, TaskTitle};
use crate::timerange::{TimeRange, TimeRangeBound};
use crate::types::{LogBody, NoteBody, TaskBody};
use crate::util::slice_lines;

// Clap's derive resolves NotePath fields through this factory; parsing
// still enters through the one NotePath::new gate.
impl clap::builder::ValueParserFactory for NotePath {
    type Parser = clap::builder::ValueParser;
    fn value_parser() -> Self::Parser {
        clap::builder::ValueParser::new(|s: &str| NotePath::new(s))
    }
}

impl clap::builder::ValueParserFactory for DirPath {
    type Parser = clap::builder::ValueParser;
    fn value_parser() -> Self::Parser {
        clap::builder::ValueParser::new(|s: &str| NotePath::new(s).and_then(DirPath::try_from))
    }
}

impl clap::builder::ValueParserFactory for TextPath {
    type Parser = clap::builder::ValueParser;
    fn value_parser() -> Self::Parser {
        clap::builder::ValueParser::new(|s: &str| NotePath::new(s).and_then(TextPath::try_from))
    }
}

impl clap::builder::ValueParserFactory for TaskPath {
    type Parser = clap::builder::ValueParser;
    fn value_parser() -> Self::Parser {
        clap::builder::ValueParser::new(|s: &str| NotePath::new(s).and_then(TaskPath::try_from))
    }
}

impl clap::builder::ValueParserFactory for LogPath {
    type Parser = clap::builder::ValueParser;
    fn value_parser() -> Self::Parser {
        clap::builder::ValueParser::new(|s: &str| NotePath::new(s).and_then(LogPath::try_from))
    }
}

pub struct ToolDef {
    pub name: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

impl ToolDef {
    // the description, followed by the scope for a scoped holder
    pub(crate) fn described(&self, scope: &NotePath) -> String {
        let text = self.description;
        match scope == &NotePath::default() {
            true => text.to_string(),
            false => format!("{text} Paths are relative to {scope}."),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ToolOutput {
    Text(String),
    Written { path: NotePath },
    Edited { path: NotePath },
    Moved { from: NotePath, to: NotePath },
    Deleted { path: NotePath },
    Logged { path: NotePath },
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
    mode: Mode,
    schema: fn() -> Value,
}

const TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "SearchNotes",
        title: "Search notes",
        description: D_SEARCH_NOTES,
        mode: Mode::Read,
        schema: schema_of::<SearchNotesArgs>,
    },
    ToolSpec {
        name: "SearchLog",
        title: "Search log",
        description: D_SEARCH_LOG,
        mode: Mode::Read,
        schema: schema_of::<SearchLogArgs>,
    },
    ToolSpec {
        name: "SearchTasks",
        title: "Search tasks",
        description: D_SEARCH_TASKS,
        mode: Mode::Read,
        schema: schema_of::<SearchTasksArgs>,
    },
    ToolSpec {
        name: "ReadNote",
        title: "Read note",
        description: D_READ,
        mode: Mode::Read,
        schema: schema_of::<ReadArgs>,
    },
    ToolSpec {
        name: "WriteNote",
        title: "Write note",
        description: D_WRITE,
        mode: Mode::Write,
        schema: schema_of::<WriteArgs>,
    },
    ToolSpec {
        name: "EditNote",
        title: "Edit note",
        description: D_EDIT,
        mode: Mode::Write,
        schema: schema_of::<EditArgs>,
    },
    ToolSpec {
        name: "MoveNote",
        title: "Move note",
        description: D_MOVE,
        mode: Mode::Write,
        schema: schema_of::<MoveArgs>,
    },
    ToolSpec {
        name: "DeleteNote",
        title: "Delete note",
        description: D_DELETE,
        mode: Mode::Write,
        schema: schema_of::<DeleteArgs>,
    },
    ToolSpec {
        name: "LogNote",
        title: "Log entry",
        description: D_LOG,
        mode: Mode::Write,
        schema: schema_of::<LogArgs>,
    },
    ToolSpec {
        name: "GetLog",
        title: "Get log entries",
        description: D_GET_LOG,
        mode: Mode::Read,
        schema: schema_of::<GetLogArgs>,
    },
    ToolSpec {
        name: "CreateTask",
        title: "Create task",
        description: D_CREATE_TASK,
        mode: Mode::Write,
        schema: schema_of::<CreateTaskArgs>,
    },
    ToolSpec {
        name: "GetTasks",
        title: "Get tasks",
        description: D_GET_TASKS,
        mode: Mode::Read,
        schema: schema_of::<GetTasksArgs>,
    },
    ToolSpec {
        name: "UpdateTask",
        title: "Update task",
        description: D_UPDATE_TASK,
        mode: Mode::Write,
        schema: schema_of::<UpdateTaskArgs>,
    },
    ToolSpec {
        name: "MoveTask",
        title: "Move task",
        description: D_MOVE_TASK,
        mode: Mode::Write,
        schema: schema_of::<MoveTaskArgs>,
    },
];

pub trait ToolArgs: Serialize {
    const TOOL: &'static str;
}

macro_rules! tool_args {
    ($($args:ident => $name:literal;)*) => {
        $(
            impl ToolArgs for $args {
                const TOOL: &'static str = $name;
            }
        )*
    };
}

tool_args! {
    SearchNotesArgs => "SearchNotes";
    SearchLogArgs => "SearchLog";
    SearchTasksArgs => "SearchTasks";
    ReadArgs => "ReadNote";
    WriteArgs => "WriteNote";
    EditArgs => "EditNote";
    MoveArgs => "MoveNote";
    DeleteArgs => "DeleteNote";
    LogArgs => "LogNote";
    GetLogArgs => "GetLog";
    CreateTaskArgs => "CreateTask";
    GetTasksArgs => "GetTasks";
    UpdateTaskArgs => "UpdateTask";
    MoveTaskArgs => "MoveTask";
}

pub(crate) fn is_tool(name: &str) -> bool {
    TOOLS.iter().any(|t| t.name == name)
}

pub(crate) fn permitted(policy: &Policy) -> Vec<&'static str> {
    let access = policy.access();
    TOOLS
        .iter()
        .filter(|t| match t.mode {
            Mode::Read => access.read,
            Mode::Write => access.write,
        })
        .map(|t| t.name)
        .collect()
}

const D_SEARCH_NOTES: &str = "Find notes by regular expression. 'pattern' is smart-case by default (case-insensitive unless it contains an uppercase letter; use '(?i)'/'(?-i)' to force) and defaults to '.' (matches everything, i.e. lists). 'mode' picks the result: 'any' (default) returns files matching by contents or path; 'line' returns 'path:lineno:text' matches ('--' between files) with 'context' surrounding lines; 'file' returns files whose contents match; 'path' returns files whose path matches. 'fixed' matches the pattern literally instead of as a regex. 'glob' restricts which paths are searched: a bare name scopes to that subtree/file, a '!'-prefixed entry excludes (repeatable). 'sort' orders the result: 'path' (default) is path order — at each level tasks by number, then log entries by instant, then names case-insensitively; 'modified' puts the most recently modified note first. Notes kept inside a task or log entry (e.g. 'dev/#2/plan.md') are searched like any other; the tasks and entries themselves are not — use SearchTasks and SearchLog for those.";
const D_SEARCH_LOG: &str = "Find log entries by regular expression. Searches entry records and nothing else — notes kept inside an entry are not searched here; results come back newest entry first, one entry path per line (e.g. '/dev/@2026-08-03T09:15:30.123456-07:00'). 'pattern', 'mode', 'context' and 'fixed' work as in SearchNotes, except 'mode' defaults to 'line'. 'prefix' narrows to a subtree — a directory such as 'dev', or a task or entry path to search the entries scoped inside it — and defaults to the whole tree. 'since', 'until' and 'limit' bound which entries are considered, exactly as in GetLog. There is no 'glob' — the prefix is the only narrowing.";
const D_SEARCH_TASKS: &str = "Find tasks by regular expression. Searches task records and nothing else — notes kept inside a task are not searched here; results come back newest-updated first, one task path per line (e.g. '/dev/#2'). 'pattern', 'mode', 'context' and 'fixed' work as in SearchNotes. 'prefix' narrows to a subtree — a directory such as 'dev', or a task or entry path to search the tasks scoped inside it — and defaults to the whole tree. Closed tasks (completed/rejected/invalid) are hidden unless include_completed is set. There is no 'glob' — the prefix is the only narrowing. Read a matched task in full with GetTasks.";
const D_GET_LOG: &str = "Read log entries as summary records, newest first, without a pattern. 'prefix' narrows the tree: '/' (the default) = every entry at any depth; a directory (e.g. 'dev') or a task or entry path = every entry under it, entries scoped inside tasks and other entries included. 'since' and 'until' are inclusive bounds, each an iso8601 datetime ('2026-07-01T09:15'), a date ('2026-07-01'), a year or month ('2026', '2026-07'), or a duration back from now ('P7D', 'PT36H'); a coarse bound widens to its span. 'body' attaches each entry's text to the record. 'limit' caps the result (default 20, max 1000). Page by passing the oldest returned entry's 'created' back as 'until'. Always returns a JSON array. Use SearchLog to match text instead.";
const D_READ: &str = "Read a note's text by relative path. Use offset/limit to page.";
const D_WRITE: &str = "Write a note, overwriting it. Creates parent directories. Never use for logging or timestamped entries — those must go through LogNote. A task or log entry path is refused: a task is created with CreateTask and changed with UpdateTask/MoveTask, and an entry is write-once; but notes inside either (e.g. 'dev/#2/plan.md') are ordinary notes and may be written here.";
const D_EDIT: &str = "Revise a note in place via string-replace.";
const D_MOVE: &str = "Move or rename a note.";
const D_DELETE: &str = "Delete a note file by relative path (e.g. 'proj/ideas.md'). A task or log entry path is refused: a task changes only through the task tools, and entries are write-once. Removal is recoverable by an operator but not undoable through these tools.";
const D_LOG: &str = "Append an immutable, timestamped log entry. 'body' is free-form; all metadata (created time with offset, cwd, host) is captured automatically into the entry's front matter — nothing to fill in. Optional 'dir' is the directory to write it in: a folder (auto-created, e.g. 'dev') or a task or entry path (e.g. 'dev/#2') to scope it inside that task or entry; it defaults to the top of the tree. The entry's path is 'dir' plus '@' and the instant it was written (e.g. 'dev/@2026-08-03T09:15:30.123456-07:00'); it CANNOT be edited, moved, or deleted through these tools — entries are write-once. An entry is a directory: notes may be written inside it with the note tools. Read entries back with GetLog or SearchLog.";
const D_CREATE_TASK: &str = "START HERE for any non-trivial unit of work. Opens a task, returning its summary record (path, state). 'task' is a one-line statement of the work; optional 'notes' seeds the markdown body; optional 'dir' is the directory to create it in: a folder (auto-created, e.g. 'dev/noted'), another task's path (e.g. 'dev/#2') or a log entry's path, to scope the new task inside it; it defaults to the top of the tree. noted numbers the task for you: its path is 'dir' plus '#N', where N is one more than the largest task number already in that directory (e.g. 'dev/noted/#3'). State starts 'created'. A task is a directory: write notes inside it with the note tools (e.g. 'dev/noted/#3/plan.md'), but change the task itself only with UpdateTask (state/notes/title) or MoveTask (directory) — WriteNote/EditNote/MoveNote are refused on a task path. States: created (not started), started (in progress), blocked (stuck), completed (work finished), rejected (declined/refused), invalid (task was ill-posed or moot). 'completed' means the work is genuinely finished; if you are giving up, use rejected/invalid — never mark 'completed'. blocked/completed/rejected/invalid require a non-empty body explaining why.";
const D_GET_TASKS: &str = "Check this BEFORE starting new work to recover existing tasks. Reads tasks as summary records, newest-updated first. 'prefix' narrows the tree: '/' (the default) = every task at any depth; a directory (e.g. 'dev') or an entry path = every task under it, tasks scoped inside other tasks included; an exact task path (e.g. 'dev/#2') = just that one task. 'body' attaches each task's markdown notes (the working body) to the record — use it to read a specific task in full. Closed tasks (completed/rejected/invalid) are hidden unless include_completed is set (an exact task path is always returned). Always returns a JSON array. Change a task with UpdateTask/MoveTask.";
const D_UPDATE_TASK: &str = "Change an existing task, identified by its path (e.g. 'dev/#2'). Set 'state' to advance it, 'notes' to replace the working body, and/or 'task' to reword the one-liner; omitted fields are left as-is. Returns the updated summary. States: created (not started), started (in progress), blocked (stuck), completed (work finished), rejected (declined/refused), invalid (ill-posed/moot); blocked/completed/rejected/invalid require a non-empty body explaining why. created_at is immutable; updated_at is set to now.";
const D_MOVE_TASK: &str = "Move a task into another directory. 'path' is the task's current path; 'dest' is the directory to move it into: a folder (auto-created), another task's path or a log entry's path; '/' (the default) moves it to the top of the tree. The task is given the next free number in 'dest', so its path changes; everything inside it — its notes, and the tasks and entries scoped under it — moves with it, and each inner task keeps its own number. Moving a task into the directory it is already in, into itself, or beneath itself is refused. Returns the summary at its new path.";

fn default_pattern() -> SearchPattern {
    SearchPattern::everything()
}
fn default_context() -> i64 {
    1
}
fn default_line_mode() -> SearchMode {
    SearchMode::Line
}
fn default_limit() -> i64 {
    20
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct SearchNotesArgs {
    #[arg(default_value = ".")]
    #[serde(default = "default_pattern")]
    pattern: SearchPattern,
    #[arg(long, default_value = "any")]
    #[serde(default)]
    mode: SearchMode,
    #[arg(long, default_value = "path")]
    #[serde(default)]
    sort: SearchOrder,
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

impl SearchNotesArgs {
    pub fn recent() -> SearchNotesArgs {
        SearchNotesArgs {
            pattern: default_pattern(),
            mode: SearchMode::Path,
            sort: SearchOrder::Modified,
            context: default_context(),
            fixed: false,
            glob: Vec::new(),
            case: CaseMode::default(),
            word: false,
            multiline: false,
            type_: Vec::new(),
        }
    }

    fn into_query(self) -> SearchQuery {
        SearchQuery::new(self.pattern, self.mode)
            .order(self.sort)
            .context(self.context.max(0) as u32)
            .fixed(self.fixed)
            .case(self.case)
            .word(self.word)
            .multiline(self.multiline)
            .globs(self.glob)
            .types(self.type_)
    }
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct SearchLogArgs {
    #[arg(default_value = ".")]
    #[serde(default = "default_pattern")]
    pattern: SearchPattern,
    #[arg(long, default_value = "line")]
    #[serde(default = "default_line_mode")]
    mode: SearchMode,
    #[arg(long, default_value_t = 1)]
    #[serde(default = "default_context")]
    context: i64,
    #[arg(long)]
    #[serde(default)]
    fixed: bool,
    #[arg(default_value = "/")]
    #[serde(default)]
    prefix: DirPath,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    since: Option<TimeRangeBound>,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    until: Option<TimeRangeBound>,
    #[arg(long, default_value_t = 20)]
    #[serde(default = "default_limit")]
    limit: i64,
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
}

impl SearchLogArgs {
    fn query(self) -> Result<LogQuery> {
        Ok(LogQuery {
            prefix: self.prefix,
            range: TimeRange::new(self.since, self.until)?,
            query: SearchQuery::new(self.pattern, self.mode)
                .context(self.context.max(0) as u32)
                .fixed(self.fixed)
                .case(self.case)
                .word(self.word)
                .multiline(self.multiline),
            limit: self.limit.clamp(1, 1000) as u32,
        })
    }
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct SearchTasksArgs {
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
    #[arg(default_value = "/")]
    #[serde(default)]
    prefix: DirPath,
    #[arg(long = "include-completed")]
    #[serde(default)]
    include_completed: bool,
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
}

impl SearchTasksArgs {
    fn into_search(self) -> TaskSearch {
        TaskSearch {
            prefix: self.prefix,
            include_completed: self.include_completed,
            query: SearchQuery::new(self.pattern, self.mode)
                .context(self.context.max(0) as u32)
                .fixed(self.fixed)
                .case(self.case)
                .word(self.word)
                .multiline(self.multiline),
        }
    }
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct GetLogArgs {
    #[arg(default_value = "/")]
    #[serde(default)]
    prefix: DirPath,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    since: Option<TimeRangeBound>,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    until: Option<TimeRangeBound>,
    #[arg(long)]
    #[serde(default)]
    body: bool,
    #[arg(long, default_value_t = 20)]
    #[serde(default = "default_limit")]
    limit: i64,
}

impl GetLogArgs {
    fn query(self) -> Result<LogQuery> {
        Ok(LogQuery {
            prefix: self.prefix,
            range: TimeRange::new(self.since, self.until)?,
            query: SearchQuery::default(),
            limit: self.limit.clamp(1, 1000) as u32,
        })
    }
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct ReadArgs {
    path: TextPath,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    offset: Option<i64>,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limit: Option<i64>,
}

impl ReadArgs {
    pub fn new(path: TextPath) -> ReadArgs {
        ReadArgs {
            path,
            offset: None,
            limit: None,
        }
    }
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct WriteArgs {
    path: TextPath,
    content: NoteBody,
    #[arg(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(skip)]
    when: Option<Condition>,
}

impl WriteArgs {
    pub fn new(path: TextPath, content: impl Into<NoteBody>) -> WriteArgs {
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
    path: TextPath,
    old_string: String,
    new_string: String,
    #[arg(long = "replace-all")]
    #[serde(default)]
    replace_all: bool,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct MoveArgs {
    path: TextPath,
    dest: TextPath,
    #[arg(long)]
    #[serde(default)]
    overwrite: bool,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct DeleteArgs {
    path: TextPath,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct LogArgs {
    #[arg(id = "path", value_name = "PATH")]
    #[serde(default)]
    dir: DirPath,
    body: LogBody,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct CreateTaskArgs {
    #[arg(id = "path", value_name = "PATH")]
    #[serde(default)]
    dir: DirPath,
    task: TaskTitle,
    #[arg(long, default_value = "")]
    #[serde(default)]
    notes: TaskBody,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct GetTasksArgs {
    #[arg(default_value = "/")]
    #[serde(default)]
    prefix: DirPath,
    #[arg(long)]
    #[serde(default)]
    body: bool,
    #[arg(long = "include-completed")]
    #[serde(default)]
    include_completed: bool,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
pub struct UpdateTaskArgs {
    path: TaskPath,
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
    path: TaskPath,
    #[arg(default_value = "/")]
    #[serde(default)]
    dest: DirPath,
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

pub(crate) fn tool_defs() -> Vec<ToolDef> {
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

/// One arm per tool, split only by how the arm reaches the tree: the three
/// searches render hits, everything else is a note, log or task operation.
/// `run_local` owns the remaining names, so an unknown name is refused in
/// exactly one place.
pub(crate) async fn run_tool(name: &str, args: &Value, root: &NotedRoot) -> Result<ToolOutput> {
    match name {
        "SearchNotes" => {
            let query = parse::<SearchNotesArgs>(args)?.into_query();
            Ok(render_hits(&query, &root.note_search(&query).await?))
        }
        "SearchLog" => {
            let query = parse::<SearchLogArgs>(args)?.query()?;
            let hits = root.log_search(&query).await?;
            Ok(render_hits(&query.query, &hits))
        }
        "SearchTasks" => {
            let search = parse::<SearchTasksArgs>(args)?.into_search();
            let hits = root.task_search(&search).await?;
            Ok(render_hits(&search.query, &hits))
        }
        _ => run_local(name, args, root).await,
    }
}

async fn run_local(name: &str, args: &Value, root: &NotedRoot) -> Result<ToolOutput> {
    match name {
        "ReadNote" => {
            let a: ReadArgs = parse(args)?;
            let note = root.note_read(&a.path).await?;
            Ok(ToolOutput::Text(slice_lines(
                note.body().as_str(),
                a.offset,
                a.limit,
            )))
        }
        "WriteNote" => {
            let a: WriteArgs = parse(args)?;
            let note = TextNote::new(a.path, a.content);
            root.note_write(&note, a.when.unwrap_or_default()).await?;
            Ok(ToolOutput::Written {
                path: note.path().as_ref().clone(),
            })
        }
        "EditNote" => {
            let a: EditArgs = parse(args)?;
            let edit = Edit::new(a.old_string, a.new_string, a.replace_all);
            root.note_edit(&a.path, &edit).await?;
            Ok(ToolOutput::Edited {
                path: a.path.as_ref().clone(),
            })
        }
        "MoveNote" => {
            let a: MoveArgs = parse(args)?;
            root.note_move(&a.path, &a.dest, a.overwrite).await?;
            Ok(ToolOutput::Moved {
                from: a.path.as_ref().clone(),
                to: a.dest.as_ref().clone(),
            })
        }
        "DeleteNote" => {
            let a: DeleteArgs = parse(args)?;
            root.note_delete(&a.path).await?;
            Ok(ToolOutput::Deleted {
                path: a.path.as_ref().clone(),
            })
        }
        "LogNote" => {
            let a: LogArgs = parse(args)?;
            let note = root.log_note(&a.dir, &a.body).await?;
            Ok(ToolOutput::Logged {
                path: note.path().as_ref().clone(),
            })
        }
        "GetLog" => {
            let a: GetLogArgs = parse(args)?;
            let body = a.body;
            let records: Vec<Value> = root
                .log_get(&a.query()?)
                .await?
                .iter()
                .map(|entry| entry_summary(entry, body))
                .collect();
            Ok(ToolOutput::Record(Value::Array(records)))
        }
        "CreateTask" => {
            let a: CreateTaskArgs = parse(args)?;
            let task = root.task_create(&a.task, &a.dir, &a.notes).await?;
            Ok(ToolOutput::Record(summary(&task, false)))
        }
        "GetTasks" => {
            let a: GetTasksArgs = parse(args)?;
            let query = TaskQuery {
                prefix: a.prefix,
                include_completed: a.include_completed,
            };
            let records: Vec<Value> = root
                .task_get(&query)
                .await?
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
            let task = root.task_update(&a.path, &change).await?;
            Ok(ToolOutput::Record(summary(&task, false)))
        }
        "MoveTask" => {
            let a: MoveTaskArgs = parse(args)?;
            let task = root.task_move(&a.path, &a.dest).await?;
            Ok(ToolOutput::Record(summary(&task, false)))
        }
        _ => Err(rejected(format!("Unknown tool: {name}"))),
    }
}

fn entry_summary(entry: &LogNote, body: bool) -> Value {
    let front = entry.front();
    let mut record = json!({
        "path": entry.path(),
        "created": front.created,
        "cwd": front.cwd,
        "host": front.host,
        "source": front.source,
    });
    if body {
        record["body"] = json!(entry.body());
    }
    record
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

fn render_hits<A: std::fmt::Display>(query: &SearchQuery, hits: &[Hit<A>]) -> ToolOutput {
    if !matches!(query.mode, SearchMode::Line) {
        let paths: Vec<String> = hits.iter().map(|hit| hit.path.to_string()).collect();
        return ToolOutput::Text(paths.join("\n"));
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
    ToolOutput::Text(out)
}
