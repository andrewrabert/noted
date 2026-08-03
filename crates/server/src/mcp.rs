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

use noted::authorization::Authorization;
use noted::{Backend, ToolCall};

pub const SERVER_NAME: &str = "noted";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct McpContext {
    pub backend: Arc<Backend>,
}

impl McpContext {
    fn call_authorization(&self, context: &RequestContext<RoleServer>) -> Option<Authorization> {
        context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<Option<Authorization>>().cloned())
            .flatten()
    }

    async fn dispatch(
        &self,
        params: CallToolRequestParams,
        authorization: Option<Authorization>,
    ) -> CallToolResult {
        let name = params.name.as_ref();
        let arguments = params
            .arguments
            .map(Value::Object)
            .unwrap_or(Value::Object(Default::default()));

        match self.invoke(name, arguments, authorization).await {
            Ok(output) => tool_ok(output),
            Err(e) => tool_error(format!("error: {}", e.message())),
        }
    }

    async fn invoke(
        &self,
        name: &str,
        arguments: Value,
        authorization: Option<Authorization>,
    ) -> noted::Result<String> {
        let call = ToolCall::raw(name, arguments)?;
        let backend = self.backend.with_authority(authorization.as_ref())?;
        Ok(backend.invoke(&call).await?.render())
    }
}

impl ServerHandler for McpContext {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(SERVER_NAME, SERVER_VERSION))
            .with_instructions(
                self.backend
                    .with_authority(None)
                    .map(|backend| backend.instructions())
                    .unwrap_or_default(),
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let authorization = self.call_authorization(&context);
        let backend = self
            .backend
            .with_authority(authorization.as_ref())
            .map_err(|e| McpError::internal_error(e.message().into_owned(), None))?;
        let tools: Vec<Tool> = backend
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
        let authorization = self.call_authorization(&context);
        Ok(self.dispatch(params, authorization).await.into())
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

pub fn context(backend: Arc<Backend>) -> McpContext {
    McpContext { backend }
}
