use clap::Args;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::{DirPath, LogPath, NotePath, TaskPath, TextPath};
use crate::error::Result;
use crate::note::{Condition, Edit, LogNote, LogQuery, TextNote, Trashed};
use crate::root::NotedRoot;
use crate::search::{
    CaseMode, FileType, GlobPattern, Hit, SearchMode, SearchOrder, SearchPattern, SearchQuery,
};
use crate::tasks::{TaskChange, TaskDue, TaskNote, TaskQuery, TaskSearch, TaskState, TaskTitle};
use crate::timerange::{TimeRange, TimeRangeBound};
use crate::types::{LogBody, NoteBody, TaskBody};

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

// the CLI has no null: an empty --due spells no due date
impl clap::builder::ValueParserFactory for TaskDue {
    type Parser = clap::builder::ValueParser;
    fn value_parser() -> Self::Parser {
        clap::builder::ValueParser::new(|s: &str| match s.is_empty() {
            true => Ok(TaskDue::none()),
            false => s.parse(),
        })
    }
}

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
#[serde(deny_unknown_fields)]
pub struct SearchNotesArgs {
    #[arg(default_value = ".")]
    #[serde(default = "default_pattern")]
    pub pattern: SearchPattern,
    #[arg(long, default_value = "any")]
    #[serde(default)]
    pub mode: SearchMode,
    #[arg(long, default_value = "path")]
    #[serde(default)]
    pub sort: SearchOrder,
    #[arg(long, default_value_t = 1)]
    #[serde(default = "default_context")]
    pub context: i64,
    #[arg(long)]
    #[serde(default)]
    pub fixed: bool,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub glob: Vec<GlobPattern>,
    #[arg(long, default_value = "smart")]
    #[serde(default)]
    #[schemars(skip)]
    pub case: CaseMode,
    #[arg(long)]
    #[serde(default)]
    #[schemars(skip)]
    pub word: bool,
    #[arg(long)]
    #[serde(default)]
    #[schemars(skip)]
    pub multiline: bool,
    #[arg(long = "type")]
    #[serde(rename = "type", default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(skip)]
    pub type_: Vec<FileType>,
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
#[serde(deny_unknown_fields)]
pub struct SearchLogArgs {
    #[arg(default_value = ".")]
    #[serde(default = "default_pattern")]
    pub pattern: SearchPattern,
    #[arg(long, default_value = "line")]
    #[serde(default = "default_line_mode")]
    pub mode: SearchMode,
    #[arg(long, default_value_t = 1)]
    #[serde(default = "default_context")]
    pub context: i64,
    #[arg(long)]
    #[serde(default)]
    pub fixed: bool,
    #[arg(default_value = "/")]
    #[serde(default)]
    pub prefix: DirPath,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<TimeRangeBound>,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<TimeRangeBound>,
    #[arg(long, default_value_t = 20)]
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[arg(long, default_value = "smart")]
    #[serde(default)]
    #[schemars(skip)]
    pub case: CaseMode,
    #[arg(long)]
    #[serde(default)]
    #[schemars(skip)]
    pub word: bool,
    #[arg(long)]
    #[serde(default)]
    #[schemars(skip)]
    pub multiline: bool,
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
#[serde(deny_unknown_fields)]
pub struct SearchTasksArgs {
    #[arg(default_value = ".")]
    #[serde(default = "default_pattern")]
    pub pattern: SearchPattern,
    #[arg(long, default_value = "any")]
    #[serde(default)]
    pub mode: SearchMode,
    #[arg(long, default_value_t = 1)]
    #[serde(default = "default_context")]
    pub context: i64,
    #[arg(long)]
    #[serde(default)]
    pub fixed: bool,
    #[arg(default_value = "/")]
    #[serde(default)]
    pub prefix: DirPath,
    #[arg(long = "include-completed")]
    #[serde(default)]
    pub include_completed: bool,
    #[arg(long, default_value = "smart")]
    #[serde(default)]
    #[schemars(skip)]
    pub case: CaseMode,
    #[arg(long)]
    #[serde(default)]
    #[schemars(skip)]
    pub word: bool,
    #[arg(long)]
    #[serde(default)]
    #[schemars(skip)]
    pub multiline: bool,
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
#[serde(deny_unknown_fields)]
pub struct GetLogArgs {
    #[arg(default_value = "/")]
    #[serde(default)]
    pub prefix: DirPath,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<TimeRangeBound>,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<TimeRangeBound>,
    #[arg(long, default_value_t = 20)]
    #[serde(default = "default_limit")]
    pub limit: i64,
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
#[serde(deny_unknown_fields)]
pub struct ReadArgs {
    pub path: TextPath,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
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
#[serde(deny_unknown_fields)]
pub struct WriteArgs {
    pub path: TextPath,
    pub content: NoteBody,
    #[arg(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(skip)]
    pub when: Option<Condition>,
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
#[serde(deny_unknown_fields)]
pub struct EditArgs {
    pub path: TextPath,
    pub old_string: String,
    pub new_string: String,
    #[arg(long = "replace-all")]
    #[serde(default)]
    pub replace_all: bool,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveArgs {
    pub path: TextPath,
    pub dest: TextPath,
    #[arg(long)]
    #[serde(default)]
    pub overwrite: bool,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteArgs {
    pub path: TextPath,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LogArgs {
    #[arg(id = "path", value_name = "PATH")]
    #[serde(default)]
    pub dir: DirPath,
    pub body: LogBody,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTaskArgs {
    #[arg(id = "path", value_name = "PATH")]
    #[serde(default)]
    pub dir: DirPath,
    pub task: TaskTitle,
    #[arg(long, default_value = "")]
    #[serde(default)]
    pub notes: TaskBody,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due: Option<TaskDue>,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetTasksArgs {
    #[arg(default_value = "/")]
    #[serde(default)]
    pub prefix: DirPath,
    #[arg(long = "include-completed")]
    #[serde(default)]
    pub include_completed: bool,
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateTaskArgs {
    pub path: TaskPath,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<TaskState>,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<TaskBody>,
    #[arg(long)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<TaskTitle>,
    #[arg(long)]
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub due: Option<TaskDue>,
}

// a passed value, null included, is Some; only a missing field is None, via `default`
fn present<'de, T, D>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    T::deserialize(d).map(Some)
}

#[derive(Args, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveTaskArgs {
    pub path: TaskPath,
    #[arg(default_value = "/")]
    #[serde(default)]
    pub dest: DirPath,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "name", content = "args")]
pub enum Tool {
    SearchNotes(SearchNotesArgs),
    SearchLog(SearchLogArgs),
    SearchTasks(SearchTasksArgs),
    ReadNote(ReadArgs),
    WriteNote(WriteArgs),
    EditNote(EditArgs),
    MoveNote(MoveArgs),
    DeleteNote(DeleteArgs),
    LogNote(LogArgs),
    GetLog(GetLogArgs),
    CreateTask(CreateTaskArgs),
    GetTasks(GetTasksArgs),
    UpdateTask(UpdateTaskArgs),
    MoveTask(MoveTaskArgs),
}

#[allow(async_fn_in_trait)]
pub trait Tools {
    async fn search_notes(&self, args: SearchNotesArgs) -> Result<Vec<Hit<TextPath>>>;
    async fn search_log(&self, args: SearchLogArgs) -> Result<Vec<Hit<LogPath>>>;
    async fn search_tasks(&self, args: SearchTasksArgs) -> Result<Vec<Hit<TaskPath>>>;
    async fn read_note(&self, args: ReadArgs) -> Result<TextNote>;
    async fn write_note(&self, args: WriteArgs) -> Result<()>;
    async fn edit_note(&self, args: EditArgs) -> Result<TextNote>;
    async fn move_note(&self, args: MoveArgs) -> Result<()>;
    async fn delete_note(&self, args: DeleteArgs) -> Result<Trashed>;
    async fn log_note(&self, args: LogArgs) -> Result<LogNote>;
    async fn get_log(&self, args: GetLogArgs) -> Result<Vec<LogNote>>;
    async fn create_task(&self, args: CreateTaskArgs) -> Result<TaskNote>;
    async fn get_tasks(&self, args: GetTasksArgs) -> Result<Vec<TaskNote>>;
    async fn update_task(&self, args: UpdateTaskArgs) -> Result<TaskNote>;
    async fn move_task(&self, args: MoveTaskArgs) -> Result<TaskNote>;
}

// core returns full domain values; presentation (body, offset/limit) is the caller's
impl Tools for NotedRoot {
    async fn search_notes(&self, args: SearchNotesArgs) -> Result<Vec<Hit<TextPath>>> {
        self.note_search(&args.into_query()).await
    }

    async fn search_log(&self, args: SearchLogArgs) -> Result<Vec<Hit<LogPath>>> {
        self.log_search(&args.query()?).await
    }

    async fn search_tasks(&self, args: SearchTasksArgs) -> Result<Vec<Hit<TaskPath>>> {
        self.task_search(&args.into_search()).await
    }

    async fn read_note(&self, args: ReadArgs) -> Result<TextNote> {
        self.note_read(&args.path).await
    }

    async fn write_note(&self, args: WriteArgs) -> Result<()> {
        let note = TextNote::new(args.path, args.content);
        self.note_write(&note, args.when.unwrap_or_default()).await
    }

    async fn edit_note(&self, args: EditArgs) -> Result<TextNote> {
        let edit = Edit::new(args.old_string, args.new_string, args.replace_all);
        self.note_edit(&args.path, &edit).await
    }

    async fn move_note(&self, args: MoveArgs) -> Result<()> {
        self.note_move(&args.path, &args.dest, args.overwrite).await
    }

    async fn delete_note(&self, args: DeleteArgs) -> Result<Trashed> {
        self.note_delete(&args.path).await
    }

    async fn log_note(&self, args: LogArgs) -> Result<LogNote> {
        NotedRoot::log_note(self, &args.dir, &args.body).await
    }

    async fn get_log(&self, args: GetLogArgs) -> Result<Vec<LogNote>> {
        self.log_get(&args.query()?).await
    }

    async fn create_task(&self, args: CreateTaskArgs) -> Result<TaskNote> {
        let due = args.due.unwrap_or(TaskDue::none());
        self.task_create(&args.task, &args.dir, due, &args.notes)
            .await
    }

    async fn get_tasks(&self, args: GetTasksArgs) -> Result<Vec<TaskNote>> {
        let query = TaskQuery {
            prefix: args.prefix,
            include_completed: args.include_completed,
        };
        self.task_get(&query).await
    }

    async fn update_task(&self, args: UpdateTaskArgs) -> Result<TaskNote> {
        let change = TaskChange {
            state: args.state,
            notes: args.notes,
            task: args.task,
            due: args.due,
        };
        self.task_update(&args.path, &change).await
    }

    async fn move_task(&self, args: MoveTaskArgs) -> Result<TaskNote> {
        self.task_move(&args.path, &args.dest).await
    }
}
