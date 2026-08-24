use std::borrow::Cow;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    InitializeResult, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo,
    Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler};
use serde_json::Value;

use noted::{NotedRoot, PolicyFragment, ToolCall};
use noted_auth::Verified;

#[derive(Clone)]
pub struct McpContext {
    pub root: NotedRoot,
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

    async fn dispatch(
        &self,
        params: CallToolRequestParams,
        context: &RequestContext<RoleServer>,
    ) -> CallToolResult {
        let name = params.name.as_ref();
        let arguments = params
            .arguments
            .map(Value::Object)
            .unwrap_or(Value::Object(Default::default()));

        match self.invoke(name, arguments, context).await {
            Ok(output) => tool_ok(output),
            Err(e) => tool_error(format!("error: {}", e.message())),
        }
    }

    async fn invoke(
        &self,
        name: &str,
        arguments: Value,
        context: &RequestContext<RoleServer>,
    ) -> noted::Result<String> {
        let call = ToolCall::raw(name, arguments)?;
        Ok(self.confined(context)?.invoke(&call).await?.render())
    }
}

impl ServerHandler for McpContext {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(noted::APP_NAME, noted::APP_VERSION))
            .with_instructions(self.root.instructions())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tools: Vec<Tool> = self
            .confined(&context)
            .map_err(|e| McpError::internal_error(e.message().into_owned(), None))?
            .tools()
            .into_iter()
            .map(|listing| {
                Tool::new(
                    Cow::Borrowed(listing.name),
                    Cow::Owned(listing.description),
                    Arc::new(schema_object(listing.input_schema)),
                )
                .with_title(listing.title)
            })
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        Ok(self.dispatch(params, &context).await.into())
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

pub fn context(root: NotedRoot) -> McpContext {
    McpContext { root }
}
