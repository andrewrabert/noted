mod common;

use common::{confined, found, grep, held, note, notes_root, read, rp, write};
use noted::authorization::Authorization;
use noted::note::LogQuery;
use noted::search::LogWindow;
use noted::store::NotedDir;
use noted::tasks::{GroupPath, TaskNote, TaskQuery, TaskRef, TaskTitle};
use noted::{Authority, NotedRoot};

fn gp(s: &str) -> GroupPath {
    s.parse().unwrap()
}

fn tt(s: &str) -> TaskTitle {
    s.parse().unwrap()
}

fn create(root: &NotedRoot, task: &str, group: &str) -> noted::Result<TaskNote> {
    root.task_create(&tt(task), &gp(group), &"".into())
}

fn all_tasks(root: &NotedRoot) -> Vec<String> {
    root.task_get(&TaskQuery::default())
        .unwrap()
        .iter()
        .map(|t| t.path().to_string())
        .collect()
}

fn log_paths(root: &NotedRoot) -> Vec<String> {
    root.log_get(&LogQuery {
        window: LogWindow::default(),
        offset: 0,
        limit: 100,
    })
    .unwrap()
    .iter()
    .map(|e| e.path().to_string())
    .collect()
}

#[test]
fn a_policy_travels_as_canonical_json() {
    let text = r#"{"scope":"dev","access":{"read":true,"write":false},"paths":{"vendor":{"read":false,"write":false}},"extra":{"finance":{"read":true,"write":false}}}"#;
    assert_eq!(held(text).to_string(), text);
    assert!("{\"nope\": 1}".parse::<Authority>().is_err());
    assert!(r#"{"paths":{"a":"rw"}}"#.parse::<Authority>().is_err());
}

fn chained(dir: &tempfile::TempDir, chain: &[&str]) -> noted::Result<NotedRoot> {
    let chain: Vec<Authority> = chain.iter().map(|text| held(text)).collect();
    NotedRoot::open(NotedDir::new(notes_root(dir)), &chain, None)
}

#[test]
fn a_link_only_narrows() {
    let dir = common::fixture_dir();
    let scoped = r#"{"scope":"projects","access":{"read":true,"write":false}}"#;

    assert!(chained(&dir, &[scoped]).is_ok());
    assert!(chained(&dir, &[scoped, r#"{"access":{"read":true,"write":true}}"#]).is_err());
    assert!(chained(&dir, &[r#"{"scope":"projects"}"#, r#"{"scope":"people"}"#]).is_err());
    assert!(
        chained(
            &dir,
            &[
                r#"{"scope":"projects","paths":{"secrets":{"read":false,"write":false}}}"#,
                r#"{"paths":{"secrets":{"read":true,"write":false}}}"#,
            ],
        )
        .is_err()
    );
}

#[test]
fn a_denied_path_refuses_both_ends_of_a_move() {
    let dir = common::fixture_dir();
    let root = confined(&dir, r#"{"paths":{"people":{"read":false,"write":false}}}"#);
    assert!(read(&root, "projects/ideas.md").is_ok());
    assert!(read(&root, "people/contacts.md").is_err());
    assert!(write(&root, &note("people/x.md", "y")).is_err());
    assert!(
        root.note_move(&rp("projects/ideas.md"), &rp("people/moved.md"), false)
            .is_err()
    );
    assert!(
        root.note_move(&rp("projects/ideas.md"), &rp("projects/moved.md"), false)
            .is_ok()
    );
}

#[test]
fn write_does_not_imply_read() {
    let dir = common::fixture_dir();
    let root = confined(&dir, r#"{"access":{"read":false,"write":true}}"#);
    assert!(write(&root, &note("drop/box.md", "y")).is_ok());
    assert!(read(&root, "drop/box.md").is_err());
}

#[test]
fn a_scope_addresses_the_notes_region_relatively() {
    let dir = common::fixture_dir();
    let root = confined(&dir, r#"{"scope":"projects"}"#);

    assert!(read(&root, "ideas.md").is_ok());
    assert!(read(&root, "projects/ideas.md").is_err());
    write(&root, &note("fresh.md", "new")).unwrap();
    assert!(common::notes_root(&dir).join("projects/fresh.md").is_file());
}

#[tokio::test]
async fn a_search_lists_only_what_the_policy_admits() {
    let dir = common::fixture_dir();
    let root = confined(&dir, r#"{"scope":"projects"}"#);
    let paths = found(&root, ".").await.unwrap();
    assert!(!paths.is_empty());
    assert!(paths.iter().all(|p| !p.contains('/')));
    assert!(paths.contains(&"ideas.md".to_string()));

    let hits = grep(&root, ".").await.unwrap();
    assert!(hits.iter().all(|h| !h.path.to_string().contains('/')));

    let denied = confined(
        &dir,
        r#"{"paths":{"Inbox.md":{"read":false,"write":false},"people":{"read":false,"write":false}}}"#,
    );
    let paths = found(&denied, ".").await.unwrap();
    assert!(!paths.iter().any(|p| p.starts_with("people/")));
    assert!(!paths.contains(&"Inbox.md".to_string()));
    assert!(paths.contains(&"projects/ideas.md".to_string()));
}

#[test]
fn the_task_region_mirrors_the_scope() {
    let dir = common::fixture_dir();
    create(&common::root(&dir), "seed", "dev").unwrap();

    let root = confined(&dir, r#"{"scope":"dev"}"#);
    let made = create(&root, "scoped work", "").unwrap();
    assert_eq!(made.path().to_string(), "task_0002");
    assert!(
        common::notes_root(&dir)
            .join("Tasks/dev/task_0002.md")
            .is_file()
    );

    let mut paths = all_tasks(&root);
    paths.sort();
    assert_eq!(paths, vec!["task_0001", "task_0002"]);
    assert!(all_tasks(&common::root(&dir)).contains(&"dev/task_0002".to_string()));
}

#[test]
fn a_single_task_can_be_granted_inside_a_denied_region() {
    let dir = common::fixture_dir();
    let seed = common::root(&dir);
    create(&seed, "one", "").unwrap();
    create(&seed, "two", "").unwrap();

    let root = confined(
        &dir,
        r#"{"paths":{"Tasks":{"read":true,"write":false},"Tasks/task_0001.md":{"read":true,"write":true}}}"#,
    );
    assert!(
        root.task_update(&TaskRef::new("task_0001").unwrap(), &Default::default())
            .is_ok()
    );
    assert!(
        root.task_update(&TaskRef::new("task_0002").unwrap(), &Default::default())
            .is_err()
    );
    assert_eq!(all_tasks(&root).len(), 2);
}

#[test]
fn a_log_entry_records_the_scope_it_was_written_at() {
    let dir = common::fixture_dir();
    let scoped = confined(&dir, r#"{"scope":"projects"}"#);
    let entry = scoped.log_note(&"scoped entry\n-- t · s".into()).unwrap();
    assert_eq!(entry.front().scope, Some(rp("projects")));
    assert!(!entry.path().to_string().starts_with("Log/"));
    assert!(
        common::notes_root(&dir)
            .join("Log")
            .join(entry.path().to_string())
            .is_file()
    );

    let unscoped = common::root(&dir);
    assert_eq!(
        unscoped
            .log_note(&"root entry\n-- t · s".into())
            .unwrap()
            .front()
            .scope,
        None
    );
}

#[test]
fn a_scoped_holder_sees_only_its_own_log() {
    let dir = common::fixture_dir();
    let projects = confined(&dir, r#"{"scope":"projects"}"#);
    let people = confined(&dir, r#"{"scope":"people"}"#);
    projects
        .log_note(&"from projects\n-- t · s".into())
        .unwrap();
    people.log_note(&"from people\n-- t · s".into()).unwrap();

    assert_eq!(log_paths(&projects).len(), 1);
    assert_eq!(log_paths(&people).len(), 1);
    assert_eq!(log_paths(&common::root(&dir)).len(), 4);
}

#[test]
fn a_denied_log_region_still_leaves_the_notes_region_open() {
    let dir = common::fixture_dir();
    let root = confined(&dir, r#"{"paths":{"Log":{"read":false,"write":false}}}"#);
    assert!(root.log_note(&"nope\n-- t · s".into()).is_err());
    assert!(log_paths(&root).is_empty());
    assert!(read(&root, "Inbox.md").is_ok());
}

fn tool_names(dir: &tempfile::TempDir, grants: Vec<Authority>) -> Vec<&'static str> {
    let backend = common::backend(dir);
    let authorization = Authorization::new(grants, None).unwrap();
    backend
        .with_authority(Some(&authorization))
        .unwrap()
        .tools()
        .iter()
        .map(|t| t.name)
        .collect()
}

fn described(dir: &tempfile::TempDir, name: &str, grants: Vec<Authority>) -> String {
    let backend = common::backend(dir);
    let authorization = Authorization::new(grants, None).unwrap();
    backend
        .with_authority(Some(&authorization))
        .unwrap()
        .tools()
        .into_iter()
        .find(|t| t.name == name)
        .unwrap()
        .description
}

#[test]
fn allowed_tools_follow_the_regions() {
    let dir = common::fixture_dir();
    let all = tool_names(&dir, vec![]);
    assert!(all.contains(&"LogNote") && all.contains(&"DeleteNote"));

    let names = tool_names(&dir, vec![held(r#"{"access":{"read":true,"write":false}}"#)]);
    assert!(names.contains(&"ReadNote") && names.contains(&"SearchLog"));
    assert!(!names.contains(&"WriteNote") && !names.contains(&"LogNote"));

    let names = tool_names(
        &dir,
        vec![held(r#"{"paths":{"Log":{"read":false,"write":false}}}"#)],
    );
    assert!(!names.contains(&"LogNote") && !names.contains(&"SearchLog"));
    assert!(names.contains(&"WriteNote"));
}

#[test]
fn a_tool_description_tells_a_scoped_client_where_things_land() {
    let dir = common::fixture_dir();
    let scoped = || vec![held(r#"{"scope":"projects"}"#)];
    assert!(described(&dir, "CreateTask", scoped()).ends_with("Tasks are stored under projects."));
    assert!(described(&dir, "LogNote", scoped()).ends_with("stamped projects."));
    assert!(described(&dir, "WriteNote", scoped()).ends_with("Paths are relative to projects."));
    assert!(!described(&dir, "WriteNote", vec![]).contains("Paths are relative to"));
}

#[test]
fn the_reserved_regions_are_reserved_only_at_the_whole_tree_scope() {
    let dir = common::fixture_dir();
    let root = common::root(&dir);
    assert!(write(&root, &note("Log/2026/07/hand-written.md", "x")).is_err());
    assert!(write(&root, &note("Tasks/hand-written.md", "x")).is_err());

    let scoped = confined(&dir, r#"{"scope":"projects"}"#);
    assert!(write(&scoped, &note("Log/notes.md", "x")).is_ok());
    assert!(
        common::notes_root(&dir)
            .join("projects/Log/notes.md")
            .is_file()
    );
}

#[test]
fn access_survives_all_four_combinations() {
    for access in [
        r#"{"read":false,"write":false}"#,
        r#"{"read":true,"write":false}"#,
        r#"{"read":false,"write":true}"#,
        r#"{"read":true,"write":true}"#,
    ] {
        let text = format!(r#"{{"paths":{{"a":{access}}}}}"#);
        assert_eq!(held(&text).to_string(), text);
    }
    assert!(r#"{"paths":{"a":{"read":true}}}"#.parse::<Authority>().is_err());
}
