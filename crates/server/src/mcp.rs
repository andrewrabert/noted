use rmcp::ErrorData;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::IntoCallToolResult;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResponse, CallToolResult, ContentBlock, Implementation, InitializeResult,
    ServerCapabilities, ServerConfig,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};

use noted::search::{Hit, SearchMode};
use noted::tools::{
    CreateTaskArgs, DeleteArgs, EditArgs, GetLogArgs, GetTasksArgs, LogArgs, MoveArgs,
    MoveTaskArgs, ReadArgs, SearchLogArgs, SearchNotesArgs, SearchTasksArgs, Tools, UpdateTaskArgs,
    WriteArgs,
};
use noted::util::slice_lines;
use noted::{NotePath, NotedError, NotedRoot, PolicyFragment};
use noted_auth::Verified;

const D_SEARCH_NOTES: &str = "Find notes by regular expression. 'pattern' is smart-case by default (case-insensitive unless it contains an uppercase letter; use '(?i)'/'(?-i)' to force) and defaults to '.' (matches everything, i.e. lists). 'mode' picks the result: 'any' (default) returns files matching by contents or path; 'line' returns 'path:lineno:text' matches ('--' between files) with 'context' surrounding lines; 'file' returns files whose contents match; 'path' returns files whose path matches. 'fixed' matches the pattern literally instead of as a regex. 'glob' restricts which paths are searched: a bare name scopes to that subtree/file, a '!'-prefixed entry excludes (repeatable). 'sort' orders the result: 'path' (default) is path order — at each level tasks by number, then log entries by instant, then names case-insensitively; 'modified' puts the most recently modified note first. Notes kept inside a task or log entry (e.g. 'dev/#2/plan.md') are searched like any other; the tasks and entries themselves are not — use SearchTasks and SearchLog for those.";
const D_SEARCH_LOG: &str = "Find log entries by regular expression. Searches entry records and nothing else — notes kept inside an entry are not searched here; results come back newest entry first, one entry path per line (e.g. '/dev/@2026-08-03T09:15:30.123456-07:00'). 'pattern', 'mode', 'context' and 'fixed' work as in SearchNotes, except 'mode' defaults to 'line'. 'prefix' narrows to a subtree — a directory such as 'dev', or a task or entry path to search the entries scoped inside it — and defaults to the whole tree. 'since', 'until' and 'limit' bound which entries are considered, exactly as in GetLog. There is no 'glob' — the prefix is the only narrowing.";
const D_SEARCH_TASKS: &str = "Find tasks by regular expression. Searches task records and nothing else — notes kept inside a task are not searched here; results come back newest-updated first, one task path per line (e.g. '/dev/#2'). 'pattern', 'mode', 'context' and 'fixed' work as in SearchNotes. 'prefix' narrows to a subtree — a directory such as 'dev', or a task or entry path to search the tasks scoped inside it — and defaults to the whole tree. Closed tasks (completed/rejected/invalid) are hidden unless include_completed is set. There is no 'glob' — the prefix is the only narrowing. Read a matched task in full with GetTasks.";
const D_GET_LOG: &str = "Read log entries as records {path, front: {created, cwd, host, source}, body}, newest first, without a pattern. 'prefix' narrows the tree: '/' (the default) = every entry at any depth; a directory (e.g. 'dev') or a task or entry path = every entry under it, entries scoped inside tasks and other entries included. 'since' and 'until' are inclusive bounds, each an iso8601 datetime ('2026-07-01T09:15'), a date ('2026-07-01'), a year or month ('2026', '2026-07'), or a duration back from now ('P7D', 'PT36H'); a coarse bound widens to its span. 'limit' caps the result (default 20, max 1000). Page by passing the oldest returned entry's 'created' back as 'until'. Always returns a JSON array. Use SearchLog to match text instead.";
const D_READ: &str = "Read a note's text by relative path. Use offset/limit to page.";
const D_WRITE: &str = "Write a note, overwriting it. Creates parent directories. Never use for logging or timestamped entries — those must go through LogNote. A task or log entry path is refused: a task is created with CreateTask and changed with UpdateTask/MoveTask, and an entry is write-once; but notes inside either (e.g. 'dev/#2/plan.md') are ordinary notes and may be written here.";
const D_EDIT: &str = "Revise a note in place via string-replace.";
const D_MOVE: &str = "Move or rename a note.";
const D_DELETE: &str = "Delete a note file by relative path (e.g. 'proj/ideas.md'). A task or log entry path is refused: a task changes only through the task tools, and entries are write-once. Removal is recoverable by an operator but not undoable through these tools.";
const D_LOG: &str = "Append an immutable, timestamped log entry. 'body' is free-form; all metadata (created time with offset, cwd, host) is captured automatically into the entry's front matter — nothing to fill in. Optional 'dir' is the directory to write it in: a folder (auto-created, e.g. 'dev') or a task or entry path (e.g. 'dev/#2') to scope it inside that task or entry; it defaults to the top of the tree. The entry's path is 'dir' plus '@' and the instant it was written (e.g. 'dev/@2026-08-03T09:15:30.123456-07:00'); it CANNOT be edited, moved, or deleted through these tools — entries are write-once. An entry is a directory: notes may be written inside it with the note tools. Read entries back with GetLog or SearchLog.";
const D_CREATE_TASK: &str = "START HERE for any non-trivial unit of work. Opens a task, returning its record (as in GetTasks). 'task' is a one-line statement of the work; optional 'notes' seeds the markdown body; optional 'due' is a due date 'YYYY-MM-DD' (date only, no time); optional 'dir' is the directory to create it in: a folder (auto-created, e.g. 'dev/noted'), another task's path (e.g. 'dev/#2') or a log entry's path, to scope the new task inside it; it defaults to the top of the tree. noted numbers the task for you: its path is 'dir' plus '#N', where N is one more than the largest task number already in that directory (e.g. 'dev/noted/#3'). State starts 'created'. A task is a directory: write notes inside it with the note tools (e.g. 'dev/noted/#3/plan.md'), but change the task itself only with UpdateTask (state/notes/title) or MoveTask (directory) — WriteNote/EditNote/MoveNote are refused on a task path. States: created (not started), started (in progress), blocked (stuck), completed (work finished), rejected (declined/refused), invalid (task was ill-posed or moot). 'completed' means the work is genuinely finished; if you are giving up, use rejected/invalid — never mark 'completed'. blocked/completed/rejected/invalid require a non-empty body explaining why.";
const D_GET_TASKS: &str = "Check this BEFORE starting new work to recover existing tasks. Reads tasks as records {path, front: {task, state, due (null when none), created_at, updated_at}, body}, newest-updated first; body is the task's markdown notes. 'prefix' narrows the tree: '/' (the default) = every task at any depth; a directory (e.g. 'dev') or an entry path = every task under it, tasks scoped inside other tasks included; an exact task path (e.g. 'dev/#2') = just that one task. Closed tasks (completed/rejected/invalid) are hidden unless include_completed is set (an exact task path is always returned). Always returns a JSON array. Change a task with UpdateTask/MoveTask.";
const D_UPDATE_TASK: &str = "Change an existing task, identified by its path (e.g. 'dev/#2'). Set 'state' to advance it, 'notes' to replace the working body, 'task' to reword the one-liner, and/or 'due' to set the due date ('YYYY-MM-DD') or null to clear it; omitted fields are left as-is, and changing 'state' never touches 'due'. Returns the updated record. States: created (not started), started (in progress), blocked (stuck), completed (work finished), rejected (declined/refused), invalid (ill-posed/moot); blocked/completed/rejected/invalid require a non-empty body explaining why. created_at is immutable; updated_at is set to now.";
const D_MOVE_TASK: &str = "Move a task into another directory. 'path' is the task's current path; 'dest' is the directory to move it into: a folder (auto-created), another task's path or a log entry's path; '/' (the default) moves it to the top of the tree. The task is given the next free number in 'dest', so its path changes; everything inside it — its notes, and the tasks and entries scoped under it — moves with it, and each inner task keeps its own number. Moving a task into the directory it is already in, into itself, or beneath itself is refused. Returns the record at its new path.";

#[derive(Clone)]
pub struct McpContext {
    pub root: NotedRoot,
    tool_router: ToolRouter<McpContext>,
}

impl McpContext {
    fn caller(&self, context: &RequestContext<RoleServer>) -> Verified {
        context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<Verified>().cloned())
            .unwrap_or_else(Verified::anonymous)
    }

    /// The policy the request carrying this call asked to be held to. A call
    /// that reached no request narrows nothing.
    fn query_policy(&self, context: &RequestContext<RoleServer>) -> Vec<PolicyFragment> {
        context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<Vec<PolicyFragment>>().cloned())
            .unwrap_or_default()
    }

    fn confined(&self, context: &RequestContext<RoleServer>) -> noted::Result<NotedRoot> {
        self.root
            .with_authority(self.caller(context).fragments())?
            .with_authority(&self.query_policy(context))
    }
}

#[tool_router]
impl McpContext {
    #[tool(name = "SearchNotes", title = "Search notes", description = D_SEARCH_NOTES)]
    async fn search_notes(
        &self,
        Parameters(args): Parameters<SearchNotesArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let mode = args.mode;
        let hits = self.confined(&context)?.search_notes(args).await?;
        Ok(render_search(mode, &hits))
    }

    #[tool(name = "SearchLog", title = "Search log", description = D_SEARCH_LOG)]
    async fn search_log(
        &self,
        Parameters(args): Parameters<SearchLogArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let mode = args.mode;
        let hits = self.confined(&context)?.search_log(args).await?;
        Ok(render_search(mode, &hits))
    }

    #[tool(name = "SearchTasks", title = "Search tasks", description = D_SEARCH_TASKS)]
    async fn search_tasks(
        &self,
        Parameters(args): Parameters<SearchTasksArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let mode = args.mode;
        let hits = self.confined(&context)?.search_tasks(args).await?;
        Ok(render_search(mode, &hits))
    }

    #[tool(name = "ReadNote", title = "Read note", description = D_READ)]
    async fn read_note(
        &self,
        Parameters(args): Parameters<ReadArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let (offset, limit) = (args.offset, args.limit);
        let note = self.confined(&context)?.read_note(args).await?;
        Ok(slice_lines(note.body().as_str(), offset, limit))
    }

    #[tool(name = "WriteNote", title = "Write note", description = D_WRITE)]
    async fn write_note(
        &self,
        Parameters(args): Parameters<WriteArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let path: NotePath = args.path.as_ref().clone();
        self.confined(&context)?.write_note(args).await?;
        Ok(format!("wrote {path}"))
    }

    #[tool(name = "EditNote", title = "Edit note", description = D_EDIT)]
    async fn edit_note(
        &self,
        Parameters(args): Parameters<EditArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let path: NotePath = args.path.as_ref().clone();
        self.confined(&context)?.edit_note(args).await?;
        Ok(format!("edited {path}"))
    }

    #[tool(name = "MoveNote", title = "Move note", description = D_MOVE)]
    async fn move_note(
        &self,
        Parameters(args): Parameters<MoveArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let from: NotePath = args.path.as_ref().clone();
        let to: NotePath = args.dest.as_ref().clone();
        self.confined(&context)?.move_note(args).await?;
        Ok(format!("moved {from} -> {to}"))
    }

    #[tool(name = "DeleteNote", title = "Delete note", description = D_DELETE)]
    async fn delete_note(
        &self,
        Parameters(args): Parameters<DeleteArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let path: NotePath = args.path.as_ref().clone();
        self.confined(&context)?.delete_note(args).await?;
        Ok(format!("deleted {path}"))
    }

    #[tool(name = "LogNote", title = "Log entry", description = D_LOG)]
    async fn log_note(
        &self,
        Parameters(args): Parameters<LogArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let entry = Tools::log_note(&self.confined(&context)?, args).await?;
        let path: &NotePath = entry.path().as_ref();
        Ok(format!("logged {path}"))
    }

    #[tool(name = "GetLog", title = "Get log entries", description = D_GET_LOG)]
    async fn get_log(
        &self,
        Parameters(args): Parameters<GetLogArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let entries = self.confined(&context)?.get_log(args).await?;
        Ok(serde_json::to_string_pretty(&entries)?)
    }

    #[tool(name = "CreateTask", title = "Create task", description = D_CREATE_TASK)]
    async fn create_task(
        &self,
        Parameters(args): Parameters<CreateTaskArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let task = self.confined(&context)?.create_task(args).await?;
        Ok(serde_json::to_string_pretty(&task)?)
    }

    #[tool(name = "GetTasks", title = "Get tasks", description = D_GET_TASKS)]
    async fn get_tasks(
        &self,
        Parameters(args): Parameters<GetTasksArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let tasks = self.confined(&context)?.get_tasks(args).await?;
        Ok(serde_json::to_string_pretty(&tasks)?)
    }

    #[tool(name = "UpdateTask", title = "Update task", description = D_UPDATE_TASK)]
    async fn update_task(
        &self,
        Parameters(args): Parameters<UpdateTaskArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let task = self.confined(&context)?.update_task(args).await?;
        Ok(serde_json::to_string_pretty(&task)?)
    }

    #[tool(name = "MoveTask", title = "Move task", description = D_MOVE_TASK)]
    async fn move_task(
        &self,
        Parameters(args): Parameters<MoveTaskArgs>,
        context: RequestContext<RoleServer>,
    ) -> Result<String, ToolError> {
        let task = self.confined(&context)?.move_task(args).await?;
        Ok(serde_json::to_string_pretty(&task)?)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpContext {
    fn get_info(&self) -> ServerConfig {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(noted::APP_NAME, noted::APP_VERSION))
            .with_instructions(self.root.instructions())
    }
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

enum ToolError {
    ToolExecutionError(NotedError),
    ProtocolError(ErrorData),
}

impl From<NotedError> for ToolError {
    fn from(e: NotedError) -> Self {
        ToolError::ToolExecutionError(e)
    }
}

impl From<serde_json::Error> for ToolError {
    fn from(e: serde_json::Error) -> Self {
        ToolError::ProtocolError(ErrorData::internal_error(
            format!("serialize result: {e}"),
            None,
        ))
    }
}

impl IntoCallToolResult for ToolError {
    fn into_call_tool_result(self) -> Result<CallToolResponse, ErrorData> {
        match self {
            ToolError::ToolExecutionError(e) => {
                Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "error: {}",
                    e.message()
                ))])
                .into())
            }
            ToolError::ProtocolError(e) => Err(e),
        }
    }
}

pub fn context(root: NotedRoot) -> McpContext {
    McpContext {
        root,
        tool_router: McpContext::tool_router(),
    }
}
