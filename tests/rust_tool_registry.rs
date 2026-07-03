mod common;

use common::{cores, fixture_dir};
use serde_json::json;

/// Must match `run_tool`'s unknown-tool sentinel message verbatim.
const UNKNOWN_PREFIX: &str = "Unknown tool:";

/// Empty args may legitimately yield a validation `Rejected`; only the
/// unknown-tool sentinel indicates a missing dispatch arm.
#[tokio::test]
async fn every_registry_name_is_dispatchable() {
    let dir = fixture_dir();
    let (notes, tasks) = cores(&dir);
    for def in noted::tools::tool_defs() {
        let name = def.name;
        let result = noted::tools::run_tool(name, &json!({}), &notes, &tasks).await;
        if let Err(e) = &result {
            assert!(
                !e.message().starts_with(UNKNOWN_PREFIX),
                "registry tool {name:?} has no run_tool arm: {}",
                e.message()
            );
        }
    }
}

#[tokio::test]
async fn unregistered_name_is_rejected() {
    let dir = fixture_dir();
    let (notes, tasks) = cores(&dir);
    let result = noted::tools::run_tool("NotARealTool", &json!({}), &notes, &tasks).await;
    let err = result.expect_err("unknown tool must be rejected");
    assert!(
        err.message().starts_with(UNKNOWN_PREFIX),
        "expected the unknown-tool sentinel, got: {}",
        err.message()
    );
}
