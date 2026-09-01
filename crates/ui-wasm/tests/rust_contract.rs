// A wasm `--all-targets` build has no `noted` dependency to resolve.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeSet;

use noted::search::{SearchMode, SearchOrder};
use noted::store::NotedDir;
use noted::tools::ToolOutput;
use noted::types::Source;
use noted::{NotePath, NotedRoot, ToolCall, ToolListing};
use noted_ui_wasm::api;
use serde_json::Value;

fn listings(dir: &tempfile::TempDir) -> Vec<ToolListing> {
    root(dir).tools()
}

fn root(dir: &tempfile::TempDir) -> NotedRoot {
    NotedRoot::open(
        NotedDir::new(dir.path().to_path_buf()),
        Some(Source::new("test")),
    )
    .expect("root")
}

fn schema_of(dir: &tempfile::TempDir, name: &str) -> Value {
    listings(dir)
        .into_iter()
        .find(|def| def.name == name)
        .unwrap_or_else(|| panic!("{name} is not a tool"))
        .input_schema
}

fn properties(schema: &Value) -> BTreeSet<String> {
    schema["properties"]
        .as_object()
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default()
}

fn required(schema: &Value) -> BTreeSet<String> {
    schema["required"]
        .as_array()
        .map(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn fields(args: &Value) -> BTreeSet<String> {
    args.as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default()
}

fn every_call() -> Vec<ToolCall> {
    vec![
        api::search_notes("x", SearchMode::Any, SearchOrder::Modified),
        api::search_log("x", "2026-01-01", "2026-12-31", 50),
        api::search_tasks("x", "dev", false),
        api::get_log("2026-01-01", "2026-12-31", 50),
        api::read_note("Inbox.md"),
        api::write_note("Inbox.md", "body"),
        api::edit_note("Inbox.md", "old", "new", true),
        api::move_note("Inbox.md", "Archive.md", false),
        api::delete_note("Inbox.md"),
        api::log_note("something happened"),
        api::create_task("do it", "dev/noted", "notes"),
        api::get_tasks("dev", true, false),
        api::update_task("dev/noted/task_0001", Some("started"), None, None),
        api::move_task("dev/noted/task_0001", "ops"),
    ]
    .into_iter()
    .map(|call| call.expect("a registered tool"))
    .collect()
}

fn args_of(args: impl serde::Serialize) -> Value {
    serde_json::to_value(args).expect("serialize")
}

// the argument shapes, as the UI serializes them onto the wire
fn every_payload() -> Vec<(&'static str, Value)> {
    vec![
        (
            "SearchNotes",
            args_of(api::SearchNotesArgs {
                pattern: "x".into(),
                mode: SearchMode::Any,
                sort: SearchOrder::Modified,
            }),
        ),
        (
            "SearchLog",
            args_of(api::SearchLogArgs {
                pattern: "x".into(),
                mode: SearchMode::Line,
                since: Some("2026-01-01".into()),
                until: Some("2026-12-31".into()),
                limit: 50,
            }),
        ),
        (
            "SearchTasks",
            args_of(api::SearchTasksArgs {
                pattern: "x".into(),
                prefix: "dev".into(),
                include_completed: false,
            }),
        ),
        (
            "GetLog",
            args_of(api::GetLogArgs {
                since: Some("2026-01-01".into()),
                until: Some("2026-12-31".into()),
                body: true,
                limit: 50,
            }),
        ),
        (
            "ReadNote",
            args_of(api::ReadArgs {
                path: "Inbox.md".into(),
            }),
        ),
        (
            "WriteNote",
            args_of(api::WriteArgs {
                path: "Inbox.md".into(),
                content: "body".into(),
            }),
        ),
        (
            "EditNote",
            args_of(api::EditArgs {
                path: "Inbox.md".into(),
                old_string: "old".into(),
                new_string: "new".into(),
                replace_all: true,
            }),
        ),
        (
            "MoveNote",
            args_of(api::MoveArgs {
                path: "Inbox.md".into(),
                dest: "Archive.md".into(),
                overwrite: false,
            }),
        ),
        (
            "DeleteNote",
            args_of(api::DeleteArgs {
                path: "Inbox.md".into(),
            }),
        ),
        (
            "LogNote",
            args_of(api::LogArgs {
                body: "something happened".into(),
            }),
        ),
        (
            "CreateTask",
            args_of(api::CreateTaskArgs {
                task: "do it".into(),
                group: "dev/noted".into(),
                notes: "notes".into(),
            }),
        ),
        (
            "GetTasks",
            args_of(api::GetTasksArgs {
                prefix: "dev".into(),
                body: true,
                include_completed: false,
            }),
        ),
        (
            "UpdateTask",
            args_of(api::UpdateTaskArgs {
                path: "dev/noted/task_0001".into(),
                state: Some("started".into()),
                notes: None,
                task: None,
            }),
        ),
        (
            "MoveTask",
            args_of(api::MoveTaskArgs {
                path: "dev/noted/task_0001".into(),
                group: "ops".into(),
            }),
        ),
    ]
}

#[test]
fn every_tool_is_reachable_from_the_ui() {
    let dir = tempfile::tempdir().expect("temp dir");
    let calls = every_call();
    let called: BTreeSet<&str> = calls.iter().map(|call| call.name()).collect();
    let registered: BTreeSet<&str> = listings(&dir).iter().map(|def| def.name).collect();
    assert_eq!(
        called, registered,
        "the UI must cover the whole tool surface"
    );
}

#[test]
fn every_payload_names_a_call_the_ui_makes() {
    let calls = every_call();
    let called: BTreeSet<&str> = calls.iter().map(|call| call.name()).collect();
    let payloads = every_payload();
    let carried: BTreeSet<&str> = payloads.iter().map(|(name, _)| *name).collect();
    assert_eq!(called, carried);
}

#[test]
fn every_field_the_ui_sends_exists_in_the_schema() {
    let dir = tempfile::tempdir().expect("temp dir");
    for (name, args) in every_payload() {
        let schema = schema_of(&dir, name);
        let known = properties(&schema);
        for field in fields(&args) {
            assert!(
                known.contains(&field),
                "{name}: sends unknown field '{field}'; schema has {known:?}"
            );
        }
    }
}

#[test]
fn every_required_argument_is_sent() {
    let dir = tempfile::tempdir().expect("temp dir");
    for (name, args) in every_payload() {
        let schema = schema_of(&dir, name);
        let sent = fields(&args);
        for field in required(&schema) {
            assert!(
                sent.contains(&field),
                "{name}: omits required field '{field}'"
            );
        }
    }
}

#[test]
fn every_payload_deserializes_as_the_tools_own_args() {
    let dir = tempfile::tempdir().expect("temp dir");
    let authorized = root(&dir);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    for call in every_call() {
        let name = call.name().to_string();
        if let Err(e) = runtime.block_on(authorized.invoke(&call)) {
            let message = e.message();
            assert!(
                !message.contains("unknown field")
                    && !message.contains("missing field")
                    && !message.contains("invalid type"),
                "{name}: payload does not deserialize: {message}"
            );
        }
    }
}

#[test]
fn the_response_envelope_is_the_one_the_ui_decodes() {
    let path = |s: &str| NotePath::new(s).expect("a note path");
    let outputs = [
        ToolOutput::Text("hi".into()),
        ToolOutput::Written { path: path("a.md") },
        ToolOutput::Edited { path: path("a.md") },
        ToolOutput::Moved {
            from: path("a.md"),
            to: path("b.md"),
        },
        ToolOutput::Deleted { path: path("a.md") },
        ToolOutput::Logged {
            path: path("2026/07/x.md"),
        },
        ToolOutput::Record(serde_json::json!([{"path": "dev/task_0001"}])),
    ];

    for output in outputs {
        let wire = serde_json::to_value(&output).expect("serialize");
        assert!(wire.get("kind").is_some(), "no kind tag in {wire}");
        let decoded: ToolOutput =
            serde_json::from_value(wire.clone()).unwrap_or_else(|e| panic!("{wire}: {e}"));
        assert_eq!(
            api::text(decoded),
            output.render(),
            "{wire} renders differently in the UI"
        );
    }
}
