mod common;

use common::{fixture_dir, root};
use serde_json::json;

/// Must match `run_tool`'s unknown-tool sentinel message verbatim.
const UNKNOWN_PREFIX: &str = "Unknown tool:";

/// Empty args may legitimately yield a validation `Rejected`; only the
/// unknown-tool sentinel indicates a missing dispatch arm.
#[tokio::test]
async fn every_registry_name_is_dispatchable() {
    let dir = fixture_dir();
    let root = root(&dir);
    for def in noted::tools::tool_defs() {
        let name = def.name;
        let result = noted::tools::run_tool(name, &json!({}), &root).await;
        if let Err(e) = &result {
            assert!(
                !e.message().starts_with(UNKNOWN_PREFIX),
                "registry tool {name:?} has no run_tool arm: {}",
                e.message()
            );
        }
    }
}

#[test]
fn arg_schemas_carry_no_prose() {
    for def in noted::tools::tool_defs() {
        let props = def.input_schema["properties"].as_object().unwrap();
        for (field, schema) in props {
            assert!(
                schema.get("description").is_none(),
                "{}.{field} leaks a description into the tool schema: {schema}",
                def.name
            );
        }
    }
}

#[test]
fn arg_schema_defaults_are_pinned() {
    let by_name: std::collections::HashMap<&str, serde_json::Value> = noted::tools::tool_defs()
        .into_iter()
        .map(|d| (d.name, d.input_schema))
        .collect();
    for (tool, field, want) in [
        ("SearchNotes", "pattern", json!(".")),
        ("SearchNotes", "mode", json!("any")),
        ("SearchNotes", "context", json!(1)),
        ("SearchNotes", "fixed", json!(false)),
        ("EditNote", "replace_all", json!(false)),
        ("MoveNote", "overwrite", json!(false)),
        ("CreateTask", "group", json!("")),
        ("CreateTask", "notes", json!("")),
        ("GetTasks", "prefix", json!("")),
        ("GetTasks", "body", json!(false)),
        ("GetTasks", "include_completed", json!(false)),
        ("MoveTask", "group", json!("")),
    ] {
        assert_eq!(
            by_name[tool]["properties"][field]["default"], want,
            "{tool}.{field} default changed"
        );
    }
}

#[tokio::test]
async fn unregistered_name_is_rejected() {
    let dir = fixture_dir();
    let root = root(&dir);
    let result = noted::tools::run_tool("NotARealTool", &json!({}), &root).await;
    let err = result.expect_err("unknown tool must be rejected");
    assert!(
        err.message().starts_with(UNKNOWN_PREFIX),
        "expected the unknown-tool sentinel, got: {}",
        err.message()
    );
}
