mod common;

use common::{backend, confined_backend, fixture_dir, invoke, root};
use noted::{Backend, Note as _};
use serde_json::{Value, json};

const JUNE: &str = "/2026-06-15T08-30-00.000000-0700.md";
const JULY: &str = "/2026-07-01T09-00-00.000000-0700.md";

async fn records(backend: &Backend, args: Value) -> Vec<Value> {
    let out = invoke(backend, "GetLog", args).await.unwrap();
    out.record()
        .and_then(|v| v.as_array())
        .expect("GetLog always returns an array")
        .clone()
}

async fn paths(backend: &Backend, args: Value) -> Vec<String> {
    records(backend, args)
        .await
        .iter()
        .map(|r| r["path"].as_str().unwrap_or_default().to_string())
        .collect()
}

async fn search(backend: &Backend, args: Value) -> String {
    invoke(backend, "SearchLog", args).await.unwrap().render()
}

#[tokio::test]
async fn get_lists_the_log_newest_first() {
    let dir = fixture_dir();
    let root = backend(&dir);
    assert_eq!(paths(&root, json!({})).await, vec![JULY, JUNE]);
}

#[tokio::test]
async fn an_entry_stamped_with_garbage_is_skipped() {
    let dir = fixture_dir();
    let root = backend(&dir);
    let garbage = "2026-07-02T09-00-00.000000-0700.md";
    std::fs::write(
        common::notes_root(&dir).join(".logs").join(garbage),
        "---\ncreated: X\ncwd: /tmp\nhost: testhost\nsource: seed\n---\nnotes-mcp garbage\n",
    )
    .unwrap();
    assert_eq!(paths(&root, json!({})).await, vec![JULY, JUNE]);
    assert!(
        !search(&root, json!({"query": "garbage"}))
            .await
            .contains(garbage)
    );
}

#[tokio::test]
async fn get_summaries_carry_the_minted_metadata() {
    let dir = fixture_dir();
    let root = backend(&dir);
    let bare = &records(&root, json!({})).await[0];
    assert_eq!(bare["created"], json!("2026-07-01T09:00:00.000000-07:00"));
    assert_eq!(bare["host"], json!("testhost"));
    assert_eq!(bare["source"], json!("seed"));
    assert!(bare.get("body").is_none(), "body is opt-in");
    assert!(bare.get("scope").is_none(), "an entry records no scope");

    let full = &records(&root, json!({"body": true})).await[0];
    assert!(
        full["body"].as_str().unwrap().contains("notes-mcp"),
        "{full}"
    );
}

#[tokio::test]
async fn the_bounds_take_every_iso8601_shape() {
    let dir = fixture_dir();
    let root = backend(&dir);
    for since in [
        "2026-07",
        "2026-07-01",
        "2026-07-01T09:00:00-07:00",
        "2026-182",
    ] {
        assert_eq!(
            paths(&root, json!({"since": since})).await,
            vec![JULY],
            "since {since}"
        );
    }
    assert_eq!(paths(&root, json!({"until": "2026-06"})).await, vec![JUNE]);
    assert_eq!(
        paths(&root, json!({"since": "2026-06-15", "until": "2026-06-15"})).await,
        vec![JUNE]
    );
    assert_eq!(paths(&root, json!({"since": "2026"})).await.len(), 2);
    assert!(paths(&root, json!({"since": "P1D"})).await.is_empty());
    assert!(
        paths(&root, json!({"since": "2027-01-01"}))
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn get_refuses_a_backwards_range_and_bad_bounds() {
    let dir = fixture_dir();
    let root = backend(&dir);
    for args in [
        json!({"since": "2026-08-01", "until": "2026-07-01"}),
        json!({"since": "yesterday"}),
        json!({"until": "2026-13-01"}),
    ] {
        assert!(
            invoke(&root, "GetLog", args.clone()).await.is_err(),
            "{args} should be rejected"
        );
    }
}

#[tokio::test]
async fn limit_pages_from_the_newest_entry() {
    let dir = fixture_dir();
    let root = backend(&dir);
    assert_eq!(paths(&root, json!({"limit": 1})).await, vec![JULY]);
    assert_eq!(paths(&root, json!({"limit": 0})).await.len(), 1);
    assert_eq!(paths(&root, json!({"limit": 99_999})).await.len(), 2);

    let newest = &records(&root, json!({"limit": 1})).await[0];
    let oldest_seen = newest["created"].as_str().unwrap().to_string();
    let next = paths(&root, json!({"until": oldest_seen, "limit": 1})).await;
    assert_eq!(next, vec![JULY], "the bound is inclusive of its own entry");
    assert_eq!(
        paths(&root, json!({"until": "2026-06-30", "limit": 1})).await,
        vec![JUNE]
    );
}

#[tokio::test]
async fn a_denied_entry_leaves_the_rest_of_the_log() {
    let dir = fixture_dir();
    assert!(
        paths(
            &confined_backend(&dir, r#"{"access":{"read":false,"write":false}}"#),
            json!({})
        )
        .await
        .is_empty()
    );

    let denied = format!(r#"{{"paths":{{"{JULY}":{{"read":false,"write":false}}}}}}"#);
    let root = confined_backend(&dir, &denied);
    assert_eq!(paths(&root, json!({})).await, vec![JUNE]);
    assert!(
        !search(&root, json!({"pattern": "claude-code"}))
            .await
            .contains(JULY)
    );
}

#[tokio::test]
async fn search_matches_log_text_newest_first() {
    let dir = fixture_dir();
    let root = backend(&dir);
    let out = search(&root, json!({"pattern": "claude-code"})).await;
    let first = out.lines().next().unwrap();
    assert!(first.starts_with(JULY), "{out}");
    assert!(out.contains(JUNE), "{out}");
    assert!(out.contains("\n--\n"), "line mode separates files: {out}");
}

#[tokio::test]
async fn search_is_scoped_to_the_log() {
    let dir = fixture_dir();
    let root = backend(&dir);
    // "contacts" appears only in the open region
    assert!(
        search(&root, json!({"pattern": "contacts"}))
            .await
            .is_empty()
    );
    let listed = search(&root, json!({"mode": "path"})).await;
    assert!(listed.lines().all(|p| p.starts_with("/20")), "{listed}");
    assert_eq!(listed.lines().count(), 2, "{listed}");
}

#[tokio::test]
async fn search_narrows_by_the_same_bounds_as_get() {
    let dir = fixture_dir();
    let root = backend(&dir);
    let june = search(
        &root,
        json!({"pattern": "claude-code", "until": "2026-06-30"}),
    )
    .await;
    assert!(june.contains(JUNE) && !june.contains(JULY), "{june}");
    assert_eq!(
        search(&root, json!({"mode": "path", "limit": 1}))
            .await
            .lines()
            .count(),
        1
    );
    assert!(
        invoke(
            &root,
            "SearchLog",
            json!({"since": "2026-08-01", "until": "2026-07-01"}),
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn search_refuses_an_unusable_pattern() {
    let dir = fixture_dir();
    let root = backend(&dir);
    assert!(
        invoke(&root, "SearchLog", json!({"pattern": "("}))
            .await
            .is_err()
    );
}

// created, cwd, host, source, each on its own plain line
#[tokio::test]
async fn a_minted_entry_writes_the_fields_in_order() {
    let dir = fixture_dir();
    let entry = root(&dir).log_note(&"minted\n".into()).await.unwrap();
    let text = String::from_utf8(entry.to_bytes()).unwrap();
    let block = text
        .strip_prefix("---\n")
        .and_then(|rest| rest.split_once("\n---\n"))
        .expect("an entry frames its front matter")
        .0;
    let keys: Vec<&str> = block
        .lines()
        .map(|line| line.split_once(": ").expect("a plain pair").0)
        .collect();
    assert_eq!(keys, vec!["created", "cwd", "host", "source"], "{block}");
    assert!(block.contains("source: test"), "{block}");
}
