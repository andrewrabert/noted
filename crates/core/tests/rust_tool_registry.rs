mod common;

use common::{backend, fixture_dir, invoke};
use noted::Backend;
use noted::authorization::Authorization;
use serde_json::json;

/// Must match `run_tool`'s unknown-tool sentinel message verbatim.
const UNKNOWN_PREFIX: &str = "Unknown tool:";

fn tool_names(backend: &Backend) -> Vec<&'static str> {
    backend
        .with_authority(None)
        .unwrap()
        .tools()
        .iter()
        .map(|t| t.name)
        .collect()
}

fn tool_listings(dir: &tempfile::TempDir) -> Vec<noted::ToolListing> {
    let backend = backend(dir);
    let authorization = Authorization::new(vec![], None).unwrap();
    backend
        .with_authority(Some(&authorization))
        .unwrap()
        .tools()
}

/// Empty args may legitimately yield a validation `Rejected`; only the
/// unknown-tool sentinel indicates a missing dispatch arm.
#[tokio::test]
async fn every_registry_name_is_dispatchable() {
    let dir = fixture_dir();
    let bknd = backend(&dir);
    for name in tool_names(&bknd) {
        let result = invoke(&bknd, name, json!({})).await;
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
    let dir = fixture_dir();
    for def in tool_listings(&dir) {
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
    let dir = fixture_dir();
    let by_name: std::collections::HashMap<&str, serde_json::Value> = tool_listings(&dir)
        .into_iter()
        .map(|d| (d.name, d.input_schema))
        .collect();
    for (tool, field, want) in [
        ("SearchNotes", "pattern", json!(".")),
        ("SearchNotes", "mode", json!("any")),
        ("SearchNotes", "sort", json!("path")),
        ("SearchNotes", "context", json!(1)),
        ("SearchNotes", "fixed", json!(false)),
        ("SearchLog", "pattern", json!(".")),
        ("SearchLog", "mode", json!("line")),
        ("SearchLog", "context", json!(1)),
        ("SearchLog", "fixed", json!(false)),
        ("SearchTasks", "pattern", json!(".")),
        ("SearchTasks", "mode", json!("any")),
        ("SearchTasks", "prefix", json!("")),
        ("SearchTasks", "include_completed", json!(false)),
        ("GetLog", "body", json!(false)),
        ("GetLog", "limit", json!(20)),
        ("SearchLog", "limit", json!(20)),
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

#[test]
fn the_registry_is_the_fifteen_tools() {
    let dir = fixture_dir();
    let names = tool_names(&backend(&dir));
    assert_eq!(
        names,
        vec![
            "SearchNotes",
            "SearchLog",
            "SearchTasks",
            "ReadNote",
            "WriteNote",
            "EditNote",
            "MoveNote",
            "DeleteNote",
            "LogNote",
            "GetLog",
            "CreateTask",
            "GetTasks",
            "UpdateTask",
            "MoveTask",
            "AttachToTask",
        ]
    );
}

#[test]
fn only_the_open_region_search_takes_a_glob() {
    let dir = fixture_dir();
    for def in tool_listings(&dir) {
        let props = def.input_schema["properties"].as_object().unwrap();
        assert_eq!(
            props.contains_key("glob"),
            def.name == "SearchNotes",
            "{} disagrees with the spec about carrying a glob field",
            def.name
        );
    }
}

#[tokio::test]
async fn unregistered_name_is_rejected() {
    let dir = fixture_dir();
    let bknd = backend(&dir);
    let result = invoke(&bknd, "NotARealTool", json!({})).await;
    let err = result.expect_err("unknown tool must be rejected");
    assert!(
        matches!(err, noted::NotedError::NotFound),
        "expected an unknown tool name to be not-found, got: {err:?}"
    );
}

#[test]
fn the_picker_query_asks_for_recency() {
    let args = serde_json::to_value(noted::tools::SearchNotesArgs::recent()).unwrap();
    assert_eq!(args["mode"], json!("path"));
    assert_eq!(args["sort"], json!("modified"));
}
