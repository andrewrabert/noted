use std::borrow::Cow;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, Implementation, InitializeResult,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler};
use serde_json::Value;

use crate::error::NotedError;
use crate::notes::Notes;
use crate::scope::TokenScope;
use crate::tasks::Tasks;
use crate::tools::{allowed_tools, is_tool, run_tool, tool_defs, ToolOutput};

pub const INSTRUCTIONS: &str = "This is the user's personal notes — the canonical place where they keep and organize their own notes, ideas, todos, and log entries as a nested tree of Markdown (.md) files. Whenever the user refers to 'my notes', asks to look something up, record or jot something down, or check what they've written before, use these tools instead of guessing or answering from memory. Search, read, write, edit, move, and delete notes by relative path (e.g. 'proj/ideas.md'). Use LogNote to quickly capture an immutable, timestamped log entry (its metadata is auto-generated and it cannot be edited or deleted). Track units of work with the task tools: CreateTask opens a task (optionally in a nested 'group' under Tasks/, e.g. group='dev/noted'); GetTasks reads them (by group prefix, or an exact task path with body=true); UpdateTask advances one (state=created/started/blocked/completed/rejected/invalid); MoveTask changes a task's group. A task is identified by its Tasks-relative path minus '.md' (e.g. 'dev/noted/task_0001'); tasks are searchable notes, but are managed only through these tools — WriteNote/EditNote are refused under Tasks/.";

pub const SERVER_NAME: &str = "noted";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub enum CallScope {
    Unconfined,
    Scoped(TokenScope),
    Invalid(String),
}

#[derive(Clone)]
pub struct McpContext {
    pub notes: Notes,
    pub tasks: Tasks,
    pub process_scope: CallScope,
}

pub enum Dispatch {
    Ok(ToolOutput),
    Unknown,
    Forbidden,
    Invalid(String),
    Failed(NotedError),
}

pub async fn authorize_and_run(
    ctx: &McpContext,
    name: &str,
    args: &Value,
    scope: &CallScope,
) -> Dispatch {
    if !is_tool(name) {
        return Dispatch::Unknown;
    }
    let (notes, tasks);
    let (target_notes, target_tasks) = match scope {
        CallScope::Invalid(msg) => return Dispatch::Invalid(msg.clone()),
        CallScope::Scoped(scope) => {
            if !scope.allows(name) {
                return Dispatch::Forbidden;
            }
            notes = ctx.notes.confined(scope.folders_for(name));
            tasks = ctx.tasks.confined(scope.folders_for(name));
            (&notes, &tasks)
        }
        CallScope::Unconfined => (&ctx.notes, &ctx.tasks),
    };
    match run_tool(name, args, target_notes, target_tasks).await {
        Ok(output) => Dispatch::Ok(output),
        Err(e) => Dispatch::Failed(e),
    }
}

impl McpContext {
    fn call_scope(&self, context: &RequestContext<RoleServer>) -> CallScope {
        context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<CallScope>().cloned())
            .unwrap_or_else(|| self.process_scope.clone())
    }

    async fn dispatch(&self, params: CallToolRequestParams, scope: CallScope) -> CallToolResult {
        let name = params.name.as_ref();
        let arguments = params
            .arguments
            .map(Value::Object)
            .unwrap_or(Value::Object(Default::default()));

        match authorize_and_run(self, name, &arguments, &scope).await {
            Dispatch::Ok(output) => tool_ok(output.render()),
            Dispatch::Unknown => tool_error(format!("Unknown tool: {name}")),
            Dispatch::Forbidden => {
                tool_error("error: tool not permitted for this token".to_string())
            }
            Dispatch::Invalid(msg) => tool_error(format!("error: {msg}")),
            Dispatch::Failed(e) => tool_error(format!("error: {}", e.message())),
        }
    }
}

impl ServerHandler for McpContext {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(SERVER_NAME, SERVER_VERSION))
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let allowed: Option<Vec<&'static str>> = match self.call_scope(&context) {
            CallScope::Scoped(scope) => Some(allowed_tools(&scope)),
            CallScope::Invalid(_) => Some(Vec::new()),
            CallScope::Unconfined => None,
        };
        let tools: Vec<Tool> = tool_defs()
            .into_iter()
            .filter(|def| allowed.as_ref().is_none_or(|a| a.contains(&def.name)))
            .map(|def| {
                Tool::new(
                    Cow::Borrowed(def.name),
                    Cow::Borrowed(def.description),
                    Arc::new(schema_object(def.input_schema)),
                )
                .with_title(def.title)
            })
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let scope = self.call_scope(&context);
        Ok(self.dispatch(params, scope).await)
    }
}

fn schema_object(schema: Value) -> serde_json::Map<String, Value> {
    match schema {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    }
}

fn tool_ok(text: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text)])
}

fn tool_error(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

pub fn context(notes: Notes, tasks: Tasks) -> McpContext {
    McpContext {
        notes,
        tasks,
        process_scope: CallScope::Unconfined,
    }
}
