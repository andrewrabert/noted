mod common;

use common::{confined, found, grep, note, read, rp, write};
use noted::caller::Policy;
use noted::scope::{RuleSpec, StoredScope, TokenScope, compile_rules};
use noted::tasks::{GroupPath, TaskNote, TaskQuery, TaskRef, TaskTitle};

fn policy(list: &[&str]) -> Policy {
    Policy::within(list.iter().map(|p| rp(p)).collect())
}

fn specs(json: &str) -> Vec<RuleSpec> {
    serde_json::from_str(json).unwrap()
}

fn gp(s: &str) -> GroupPath {
    s.parse().unwrap()
}
fn tt(s: &str) -> TaskTitle {
    s.parse().unwrap()
}

fn create(root: &noted::root::NotedRoot, task: &str, group: &str) -> noted::Result<TaskNote> {
    root.task_create(&tt(task), &gp(group), &"".into())
}

fn all_tasks(root: &noted::root::NotedRoot) -> Vec<String> {
    root.task_get(&TaskQuery::default())
        .unwrap()
        .iter()
        .map(|t| t.path().to_string())
        .collect()
}

#[test]
fn rule_json_compiles_to_per_tool_scopes() {
    let scope = compile_rules(&specs(
        r#"[{"tools": ["SearchNotes", "ReadNote"]},
            {"tools": ["WriteNote"], "paths": ["proj", "/notes/ideas/"]}]"#,
    ))
    .unwrap();
    assert!(scope.allows("SearchNotes") && scope.allows("ReadNote"));
    assert_eq!(scope.policy_for("ReadNote"), Policy::any());
    assert_eq!(
        scope.policy_for("WriteNote"),
        policy(&["proj", "notes/ideas"])
    );
    assert!(!scope.allows("DeleteNote"));
}

#[test]
fn rule_json_is_fail_closed() {
    assert!(compile_rules(&specs(r#"[{"tools": ["Bogus"]}]"#)).is_err());
    assert!(compile_rules(&specs(r#"[{"paths": ["../evil"]}]"#)).is_err());
    assert!(compile_rules(&specs(r#"[{"paths": [".hidden"]}]"#)).is_err());
    // "path" is a deliberate misspelling of "paths": an unknown key must be a
    // deserialization error, or a typo would silently widen a credential
    assert!(serde_json::from_str::<Vec<RuleSpec>>(r#"[{"path": ["a"]}]"#).is_err());
    assert!(serde_json::from_str::<Vec<RuleSpec>>(r#"[{"tools": "ReadNote"}]"#).is_err());
    let scope = compile_rules(&specs(r#"[{"tools": []}]"#)).unwrap();
    assert!(!scope.allows("ReadNote"));
}

#[test]
fn an_empty_grant_admits_nothing_and_the_identity_admits_everything() {
    assert!(Policy::any().admits(&rp("anything/at/all.md")));
    let none = Policy::within(Vec::new());
    assert!(!none.admits(&rp("Inbox.md")));
}

#[test]
fn stored_scope_modes_are_distinct() {
    assert!(
        StoredScope::Unrestricted
            .compile()
            .unwrap()
            .allows("DeleteNote")
    );
    assert_eq!(
        StoredScope::Unrestricted.compile().unwrap(),
        TokenScope::full()
    );
    let none = StoredScope::Grants(Vec::new()).compile().unwrap();
    assert!(!none.allows("ReadNote") && !none.allows("LogNote"));
}

#[test]
fn confine_allows_inside_rejects_outside() {
    let dir = common::fixture_dir();
    let root = confined(&dir, &["projects"]);
    assert!(read(&root, "projects/ideas.md").is_ok());
    assert!(
        read(&root, "Inbox.md")
            .unwrap_err()
            .to_string()
            .contains("allowed folders")
    );
    assert!(
        write(&root, &note("people/x.md", "y"))
            .unwrap_err()
            .to_string()
            .contains("allowed folders")
    );
}

#[test]
fn confine_never_blocks_a_log_entry() {
    let dir = common::fixture_dir();
    let root = confined(&dir, &["projects"]);
    let logged = root.log_note(&"entry\n-- t · s".into()).unwrap();
    assert!(logged.path().starts_with("Log/"));
}

#[test]
fn confine_move_guarded_both_ends() {
    let dir = common::fixture_dir();
    let root = confined(&dir, &["projects"]);
    assert!(
        root.note_move(&rp("projects/ideas.md"), &rp("people/moved.md"), false)
            .unwrap_err()
            .to_string()
            .contains("allowed folders")
    );
    assert!(
        root.note_move(&rp("projects/ideas.md"), &rp("projects/moved.md"), false)
            .is_ok()
    );
}

#[tokio::test]
async fn confine_search_only_returns_inside() {
    let dir = common::fixture_dir();
    let root = confined(&dir, &["projects"]);
    let paths = found(&root, ".").await.unwrap();
    assert!(!paths.is_empty() && paths.iter().all(|p| p.starts_with("projects/")));
    let hits = grep(&root, ".").await.unwrap();
    assert!(hits.iter().all(|h| h.path.starts_with("projects/")));
}

#[test]
fn a_task_grant_is_spelled_root_relative() {
    let dir = common::fixture_dir();
    create(&common::root(&dir), "seed", "dev").unwrap();

    let root = confined(&dir, &["Tasks/dev"]);
    let made = create(&root, "scoped work", "dev").unwrap();
    assert!(made.path().as_str().starts_with("dev/"));

    assert!(
        create(&root, "nope", "ops")
            .unwrap_err()
            .to_string()
            .contains("allowed folders")
    );
    assert!(
        create(&root, "nope", "")
            .unwrap_err()
            .to_string()
            .contains("allowed folders")
    );
    assert!(
        root.task_update(&TaskRef::new("ops/task_0001").unwrap(), &Default::default())
            .unwrap_err()
            .to_string()
            .contains("allowed folders")
    );
}

#[test]
fn a_task_grant_filters_a_listing() {
    let dir = common::fixture_dir();
    let seed = common::root(&dir);
    create(&seed, "in dev", "dev").unwrap();
    create(&seed, "in ops", "ops").unwrap();

    let paths = all_tasks(&confined(&dir, &["Tasks/dev"]));
    assert!(!paths.is_empty() && paths.iter().all(|p| p.starts_with("dev/")));
}
