mod common;

use noted::notes::Notes;
use noted::scope::{compile_rules, RuleSpec, StoredScope, TokenScope};
use noted::search::{MatchOpts, WalkOpts};
use noted::tasks::Tasks;

fn folders(list: &[&str]) -> Option<Vec<String>> {
    Some(list.iter().map(|s| s.to_string()).collect())
}

fn specs(json: &str) -> Vec<RuleSpec> {
    serde_json::from_str(json).unwrap()
}

#[test]
fn rule_json_compiles_to_per_tool_scopes() {
    let scope = compile_rules(&specs(
        r#"[{"tools": ["SearchNotes", "ReadNote"]},
            {"tools": ["WriteNote"], "paths": ["proj", "/notes/ideas/"]}]"#,
    ))
    .unwrap();
    assert!(scope.allows("SearchNotes") && scope.allows("ReadNote"));
    assert_eq!(scope.folders_for("ReadNote"), None);
    assert_eq!(
        scope.folders_for("WriteNote"),
        folders(&["proj", "notes/ideas"])
    );
    assert!(!scope.allows("DeleteNote"));
}

#[test]
fn rule_json_is_fail_closed() {
    assert!(compile_rules(&specs(r#"[{"tools": ["Bogus"]}]"#)).is_err());
    assert!(compile_rules(&specs(r#"[{"paths": ["../evil"]}]"#)).is_err());
    // "path" is a deliberate misspelling of "paths": an unknown key must be a
    // deserialization error, or a typo would silently widen a credential
    assert!(serde_json::from_str::<Vec<RuleSpec>>(r#"[{"path": ["a"]}]"#).is_err());
    assert!(serde_json::from_str::<Vec<RuleSpec>>(r#"[{"tools": "ReadNote"}]"#).is_err());
    let scope = compile_rules(&specs(r#"[{"tools": []}]"#)).unwrap();
    assert!(!scope.allows("ReadNote"));
}

#[test]
fn stored_scope_modes_are_distinct() {
    assert!(StoredScope::Unrestricted
        .compile()
        .unwrap()
        .allows("DeleteNote"));
    assert_eq!(
        StoredScope::Unrestricted.compile().unwrap(),
        TokenScope::full()
    );
    let none = StoredScope::Grants(Vec::new()).compile().unwrap();
    assert!(!none.allows("ReadNote") && !none.allows("LogNote"));
}

#[test]
fn notes_confine_allows_inside_rejects_outside() {
    let dir = common::fixture_dir();
    let notes = Notes::new(&common::notes_root(&dir), None)
        .unwrap()
        .confined(folders(&["projects"]));
    assert!(notes.read(&rp("projects/ideas.md")).is_ok());
    assert!(notes
        .read(&rp("Inbox.md"))
        .unwrap_err()
        .to_string()
        .contains("allowed folders"));
    assert!(notes
        .write(&rp("people/x.md"), "y")
        .unwrap_err()
        .to_string()
        .contains("allowed folders"));
}

#[test]
fn notes_confine_allows_log_writes() {
    let dir = common::fixture_dir();
    let notes = Notes::new(&common::notes_root(&dir), Some("test".into()))
        .unwrap()
        .confined(folders(&["projects"]));
    let rel = notes.create_log("entry\n-- t · s", None).unwrap();
    assert!(rel.starts_with("Log/"));
}

#[test]
fn notes_confine_move_guarded_both_ends() {
    let dir = common::fixture_dir();
    let notes = Notes::new(&common::notes_root(&dir), None)
        .unwrap()
        .confined(folders(&["projects"]));
    assert!(notes
        .move_note(&rp("projects/ideas.md"), &rp("people/moved.md"), false)
        .unwrap_err()
        .to_string()
        .contains("allowed folders"));
    assert!(notes
        .move_note(&rp("projects/ideas.md"), &rp("projects/moved.md"), false)
        .is_ok());
}

#[tokio::test]
async fn notes_confine_search_only_returns_inside() {
    let dir = common::fixture_dir();
    let notes = Notes::new(&common::notes_root(&dir), None)
        .unwrap()
        .confined(folders(&["projects"]));
    let m = MatchOpts::default();
    let w = WalkOpts::default();
    let paths = notes.match_path(".", &m, &w).await.unwrap();
    assert!(!paths.is_empty() && paths.iter().all(|p| p.starts_with("projects/")));
    let grep = notes.grep(".", 1, &m, &w).await.unwrap();
    assert!(grep.iter().all(|h| h.rel().starts_with("projects/")));
}

#[test]
fn notes_confined_none_is_full() {
    let dir = common::fixture_dir();
    let notes = Notes::new(&common::notes_root(&dir), None).unwrap();
    assert!(notes.confined(None).read(&rp("Inbox.md")).is_ok());
}

#[test]
fn tasks_confine_create_and_reject() {
    let dir = common::fixture_dir();
    let root = common::notes_root(&dir);
    Tasks::new(&root)
        .create(&tt("seed"), &gp("dev"), "")
        .unwrap();
    let tasks = Tasks::new(&root).confined(folders(&["dev"]));
    let made = tasks.create(&tt("scoped work"), &gp("dev"), "").unwrap();
    assert!(made["path"].as_str().unwrap().starts_with("dev/"));
    assert!(tasks
        .create(&tt("nope"), &gp("ops"), "")
        .unwrap_err()
        .to_string()
        .contains("allowed folders"));
    assert!(tasks
        .create(&tt("nope"), &gp(""), "")
        .unwrap_err()
        .to_string()
        .contains("allowed folders"));
}

#[test]
fn tasks_confine_query_filters() {
    let dir = common::fixture_dir();
    let root = common::notes_root(&dir);
    let seed = Tasks::new(&root);
    seed.create(&tt("in dev"), &gp("dev"), "").unwrap();
    seed.create(&tt("in ops"), &gp("ops"), "").unwrap();
    let tasks = Tasks::new(&root).confined(folders(&["dev"]));
    let listed = tasks.query("", false, false).unwrap();
    let paths: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["path"].as_str().unwrap())
        .collect();
    assert!(!paths.is_empty() && paths.iter().all(|p| p.starts_with("dev/")));
}

#[allow(dead_code)]
fn rp(s: &str) -> noted::notes::RelPath {
    s.parse().unwrap()
}
#[allow(dead_code)]
fn gp(s: &str) -> noted::tasks::GroupPath {
    s.parse().unwrap()
}
#[allow(dead_code)]
fn tt(s: &str) -> noted::tasks::TaskTitle {
    s.parse().unwrap()
}
#[allow(dead_code)]
fn ts(s: &str) -> noted::tasks::TaskState {
    s.parse().unwrap()
}
