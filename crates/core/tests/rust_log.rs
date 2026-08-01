mod common;

use common::{confined, fixture_dir, root};
use noted::root::NotedRoot;
use serde_json::{Value, json};

const JUNE: &str = "Log/2026/06/2026-06-15T08-30-00.000000.md";
const JULY: &str = "Log/2026/07/2026-07-01T09-00-00.000000.md";

async fn records(root: &NotedRoot, args: Value) -> Vec<Value> {
    let out = noted::tools::run_tool("GetLog", &args, root).await.unwrap();
    out.record()
        .and_then(|v| v.as_array())
        .expect("GetLog always returns an array")
        .clone()
}

async fn paths(root: &NotedRoot, args: Value) -> Vec<String> {
    records(root, args)
        .await
        .iter()
        .map(|r| r["path"].as_str().unwrap_or_default().to_string())
        .collect()
}

async fn search(root: &NotedRoot, args: Value) -> String {
    noted::tools::run_tool("SearchLog", &args, root)
        .await
        .unwrap()
        .render()
}

#[tokio::test]
async fn get_lists_the_window_newest_first() {
    let dir = fixture_dir();
    let root = root(&dir);
    assert_eq!(paths(&root, json!({})).await, vec![JULY, JUNE]);
}

#[tokio::test]
async fn get_summaries_carry_the_minted_metadata() {
    let dir = fixture_dir();
    let root = root(&dir);
    let bare = &records(&root, json!({})).await[0];
    assert_eq!(bare["created"], json!("2026-07-01T09:00:00.000000-07:00"));
    assert_eq!(bare["host"], json!("testhost"));
    assert_eq!(bare["source"], json!("seed"));
    assert!(bare.get("body").is_none(), "body is opt-in");

    let full = &records(&root, json!({"body": true})).await[0];
    assert!(
        full["body"].as_str().unwrap().contains("notes-mcp"),
        "{full}"
    );
}

#[tokio::test]
async fn get_window_bounds_are_inclusive_local_dates() {
    let dir = fixture_dir();
    let root = root(&dir);
    assert_eq!(
        paths(&root, json!({"since": "2026-07-01"})).await,
        vec![JULY]
    );
    assert_eq!(
        paths(&root, json!({"until": "2026-06-30"})).await,
        vec![JUNE]
    );
    assert_eq!(
        paths(&root, json!({"since": "2026-06-15", "until": "2026-06-15"})).await,
        vec![JUNE]
    );
    assert!(
        paths(&root, json!({"since": "2027-01-01"}))
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn get_refuses_a_backwards_window_and_bad_dates() {
    let dir = fixture_dir();
    let root = root(&dir);
    for args in [
        json!({"since": "2026-08-01", "until": "2026-07-01"}),
        json!({"since": "yesterday"}),
        json!({"until": "2026-13-40"}),
    ] {
        assert!(
            noted::tools::run_tool("GetLog", &args, &root)
                .await
                .is_err(),
            "{args} should be rejected"
        );
    }
}

#[tokio::test]
async fn get_pages_the_ordered_result() {
    let dir = fixture_dir();
    let root = root(&dir);
    assert_eq!(paths(&root, json!({"limit": 1})).await, vec![JULY]);
    assert_eq!(
        paths(&root, json!({"offset": 1, "limit": 1})).await,
        vec![JUNE]
    );
    assert!(paths(&root, json!({"offset": 99})).await.is_empty());
    assert_eq!(paths(&root, json!({"limit": 0})).await.len(), 1);
    assert_eq!(paths(&root, json!({"limit": 99_999})).await.len(), 2);
}

#[tokio::test]
async fn get_applies_the_grant_per_file_instead_of_refusing() {
    let dir = fixture_dir();
    assert!(
        paths(&confined(&dir, &["people"]), json!({}))
            .await
            .is_empty()
    );
    assert_eq!(
        paths(&confined(&dir, &["Log/2026/06"]), json!({})).await,
        vec![JUNE]
    );
}

#[tokio::test]
async fn search_matches_log_text_newest_first() {
    let dir = fixture_dir();
    let root = root(&dir);
    let out = search(&root, json!({"pattern": "claude-code"})).await;
    let first = out.lines().next().unwrap();
    assert!(first.starts_with(JULY), "{out}");
    assert!(out.contains(JUNE), "{out}");
    assert!(out.contains("\n--\n"), "line mode separates files: {out}");
}

#[tokio::test]
async fn search_is_scoped_to_the_log() {
    let dir = fixture_dir();
    let root = root(&dir);
    // "contacts" appears only in the open region
    assert!(
        search(&root, json!({"pattern": "contacts"}))
            .await
            .is_empty()
    );
    let listed = search(&root, json!({"mode": "path"})).await;
    assert!(listed.lines().all(|p| p.starts_with("Log/")), "{listed}");
}

#[tokio::test]
async fn search_narrows_by_the_same_window_as_get() {
    let dir = fixture_dir();
    let root = root(&dir);
    let june = search(
        &root,
        json!({"pattern": "claude-code", "until": "2026-06-30"}),
    )
    .await;
    assert!(june.contains(JUNE) && !june.contains(JULY), "{june}");
    assert!(
        noted::tools::run_tool(
            "SearchLog",
            &json!({"since": "2026-08-01", "until": "2026-07-01"}),
            &root,
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn search_refuses_an_unusable_pattern() {
    let dir = fixture_dir();
    let root = root(&dir);
    assert!(
        noted::tools::run_tool("SearchLog", &json!({"pattern": "("}), &root)
            .await
            .is_err()
    );
}
