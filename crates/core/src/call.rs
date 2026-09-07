use crate::error::{NotedError, Result, json_error};
use crate::tools::{ToolArgs, is_tool};
use serde_json::Value;

pub struct ToolCall {
    name: String,
    args: Value,
}

impl ToolCall {
    pub fn new<A: ToolArgs>(args: A) -> Result<ToolCall> {
        Ok(ToolCall {
            name: A::TOOL.to_string(),
            args: serde_json::to_value(args).map_err(|e| json_error("tool arguments", e))?,
        })
    }

    pub fn raw(name: &str, args: Value) -> Result<ToolCall> {
        if !is_tool(name) {
            return Err(NotedError::NotFound);
        }
        Ok(ToolCall {
            name: name.to_string(),
            args,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn args(&self) -> &Value {
        &self.args
    }
}

pub struct ToolListing {
    pub name: &'static str,
    pub title: &'static str,
    pub description: String,
    pub input_schema: Value,
}
