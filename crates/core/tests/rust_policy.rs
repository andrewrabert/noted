mod common;

use common::{confined, dp, found, grep, held, note, notes_root, read, rp, write};
use noted::note::LogQuery;
use noted::store::NotedDir;
use noted::tasks::{TaskNote, TaskQuery, TaskTitle};
use noted::{NotePath, NotedRoot, PolicyFragment, TaskPath, TextPath};

fn tt(s: &str) -> TaskTitle {
    s.parse().unwrap()
}

async fn create(root: &NotedRoot, task: &str, dir: &str) -> noted::Result<TaskNote> {
    root.task_create(&tt(task), &dp(dir), &"".into()).await
}

async fn all_tasks(root: &NotedRoot) -> Vec<String> {
    root.task_get(&TaskQuery::default())
        .await
        .unwrap()
        .iter()
        .map(|t| t.path().to_string())
        .collect()
}

async fn log_paths(root: &NotedRoot) -> Vec<String> {
    root.log_get(&LogQuery {
        prefix: Default::default(),
        range: Default::default(),
        query: Default::default(),
        limit: 100,
    })
    .await
    .unwrap()
    .iter()
    .map(|e| e.path().to_string())
    .collect()
}

#[test]
fn a_policy_travels_as_canonical_json() {
    let text = r#"{"scope":"/dev","access":{"read":true,"write":false},"paths":{"/vendor":{"read":false,"write":false}}}"#;
    assert_eq!(held(text).to_string(), text);
    assert!("{\"nope\": 1}".parse::<PolicyFragment>().is_err());
    assert!(r#"{"paths":{"/a":"rw"}}"#.parse::<PolicyFragment>().is_err());
}

fn chained(dir: &tempfile::TempDir, chain: &[&str]) -> noted::Result<NotedRoot> {
    let chain: Vec<PolicyFragment> = chain.iter().map(|text| held(text)).collect();
    NotedRoot::open(NotedDir::new(notes_root(dir)), None)?.with_authority(&chain)
}

#[tokio::test]
async fn a_link_only_narrows() {
    let dir = common::fixture_dir();
    let scoped = r#"{"scope":"/projects","access":{"read":true,"write":false}}"#;

    assert!(chained(&dir, &[scoped]).is_ok());
    assert!(chained(&dir, &[scoped, r#"{"access":{"read":true,"write":true}}"#]).is_err());

    // a scope chained onto a scope deepens it: 'projects/people' names nothing
    let root = chained(
        &dir,
        &[r#"{"scope":"/projects"}"#, r#"{"scope":"/people"}"#],
    )
    .unwrap();
    assert!(read(&root, "/notes.md").await.is_err());

    assert!(
        chained(
            &dir,
            &[
                r#"{"scope":"/projects","paths":{"/secrets":{"read":false,"write":false}}}"#,
                r#"{"paths":{"/secrets":{"read":true,"write":false}}}"#,
            ],
        )
        .is_err()
    );
}

#[tokio::test]
async fn a_denied_path_refuses_both_ends_of_a_move() {
    let dir = common::fixture_dir();
    let root = confined(
        &dir,
        r#"{"paths":{"/people":{"read":false,"write":false}}}"#,
    );
    assert!(read(&root, "/projects/ideas.md").await.is_ok());
    assert!(read(&root, "/people/contacts.md").await.is_err());
    assert!(write(&root, &note("/people/x.md", "y")).await.is_err());
    assert!(
        root.note_move(
            &TextPath::try_from(rp("/projects/ideas.md")).unwrap(),
            &TextPath::try_from(rp("/people/moved.md")).unwrap(),
            false
        )
        .await
        .is_err()
    );
    assert!(
        root.note_move(
            &TextPath::try_from(rp("/projects/ideas.md")).unwrap(),
            &TextPath::try_from(rp("/projects/moved.md")).unwrap(),
            false
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn write_does_not_imply_read() {
    let dir = common::fixture_dir();
    let root = confined(&dir, r#"{"access":{"read":false,"write":true}}"#);
    assert!(write(&root, &note("/drop/box.md", "y")).await.is_ok());
    assert!(read(&root, "/drop/box.md").await.is_err());
}

#[tokio::test]
async fn a_scope_addresses_notes_relatively() {
    let dir = common::fixture_dir();
    let root = confined(&dir, r#"{"scope":"/projects"}"#);

    assert!(read(&root, "/ideas.md").await.is_ok());
    assert!(read(&root, "/projects/ideas.md").await.is_err());
    write(&root, &note("/fresh.md", "new")).await.unwrap();
    assert!(common::notes_root(&dir).join("projects/fresh.md").is_file());
}

#[tokio::test]
async fn a_search_lists_only_what_the_policy_admits() {
    let dir = common::fixture_dir();
    let root = confined(&dir, r#"{"scope":"/projects"}"#);
    let paths = found(&root, ".").await.unwrap();
    assert!(!paths.is_empty());
    assert!(paths.iter().all(|p| !p.starts_with("/projects/")));
    assert!(paths.contains(&"/ideas.md".to_string()));
    assert!(paths.contains(&"/alpha/notes.md".to_string()));

    let hits = grep(&root, ".").await.unwrap();
    assert!(
        hits.iter()
            .all(|h| !h.path.to_string().starts_with("/projects/"))
    );

    let denied = confined(
        &dir,
        r#"{"paths":{"/Inbox.md":{"read":false,"write":false},"/people":{"read":false,"write":false}}}"#,
    );
    let paths = found(&denied, ".").await.unwrap();
    assert!(!paths.iter().any(|p| p.starts_with("/people/")));
    assert!(!paths.contains(&"/Inbox.md".to_string()));
    assert!(paths.contains(&"/projects/ideas.md".to_string()));
}

#[tokio::test]
async fn tasks_mirror_the_scope() {
    let dir = common::fixture_dir();
    create(&common::root(&dir), "seed", "dev").await.unwrap();

    let root = confined(&dir, r#"{"scope":"/dev"}"#);
    let made = create(&root, "scoped work", "/").await.unwrap();
    assert_eq!(made.path().to_string(), "/#2");
    assert!(
        common::notes_root(&dir)
            .join("dev/.tasks/2/.task.md")
            .is_file()
    );

    let mut paths = all_tasks(&root).await;
    paths.sort();
    assert_eq!(paths, vec!["/#1", "/#2"]);
    assert!(
        all_tasks(&common::root(&dir))
            .await
            .contains(&"/dev/#2".to_string())
    );
}

#[tokio::test]
async fn a_single_task_can_be_granted_inside_a_read_only_scope() {
    let dir = common::fixture_dir();
    let seed = common::root(&dir);
    create(&seed, "one", "/").await.unwrap();
    create(&seed, "two", "/").await.unwrap();

    let root = confined(
        &dir,
        r#"{"access":{"read":true,"write":false},"paths":{"/#1":{"read":true,"write":true}}}"#,
    );
    assert!(
        root.task_update(
            &TaskPath::try_from(NotePath::new("/#1").unwrap()).unwrap(),
            &Default::default()
        )
        .await
        .is_ok()
    );
    assert!(
        root.task_update(
            &TaskPath::try_from(NotePath::new("/#2").unwrap()).unwrap(),
            &Default::default()
        )
        .await
        .is_err()
    );
    assert_eq!(all_tasks(&root).await.len(), 2);
}

#[tokio::test]
async fn a_scoped_holder_sees_only_its_own_log() {
    let dir = common::fixture_dir();
    let projects = confined(&dir, r#"{"scope":"/projects"}"#);
    let people = confined(&dir, r#"{"scope":"/people"}"#);
    let entry = projects
        .log_note(&dp("/"), &"from projects\n-- t · s".into())
        .await
        .unwrap();
    people
        .log_note(&dp("/"), &"from people\n-- t · s".into())
        .await
        .unwrap();

    assert!(
        common::notes_root(&dir)
            .join("projects/.logs")
            .join(entry.path().to_string().trim_start_matches("/@"))
            .join(".log.md")
            .is_file(),
        "a scoped entry lands in its scope's own .logs directory"
    );
    assert_eq!(log_paths(&projects).await, vec![entry.path().to_string()]);
    assert_eq!(log_paths(&people).await.len(), 1);
    assert_eq!(log_paths(&common::root(&dir)).await.len(), 4);
}

#[tokio::test]
async fn a_scope_is_cumulative_across_notes_logs_and_tasks() {
    let dir = common::fixture_dir();
    let root = confined(&dir, r#"{"scope":"/a/b"}"#);
    write(&root, &note("/kept.md", "x")).await.unwrap();
    let entry = root
        .log_note(&dp("/"), &"scoped\n-- t · s".into())
        .await
        .unwrap();
    create(&root, "scoped work", "/").await.unwrap();

    let notes = common::notes_root(&dir);
    assert!(notes.join("a/b/kept.md").is_file());
    assert!(
        notes
            .join("a/b/.logs")
            .join(entry.path().to_string().trim_start_matches("/@"))
            .join(".log.md")
            .is_file()
    );
    assert!(notes.join("a/b/.tasks/1/.task.md").is_file());
}

// a key is read from the scope and applies the same way to notes and tasks
#[tokio::test]
async fn a_key_applies_uniformly_to_notes_and_tasks() {
    let dir = common::fixture_dir();
    let root = confined(
        &dir,
        r#"{"scope":"/dev","paths":{"/x":{"read":false,"write":false}}}"#,
    );
    assert!(create(&root, "refused", "x").await.is_err());
    assert!(create(&root, "kept", "y").await.is_ok());
    assert!(write(&root, &note("/x/a.md", "x")).await.is_err());
    assert!(write(&root, &note("/y/a.md", "x")).await.is_ok());
}

#[tokio::test]
async fn a_scope_cannot_widen_a_denial() {
    let dir = common::fixture_dir();
    let chain = &[
        r#"{"access":{"read":false,"write":false}}"#,
        r#"{"scope":"/dev"}"#,
    ];
    let root = chained(&dir, chain).unwrap();
    assert!(
        root.log_note(&dp("/"), &"nope\n-- t · s".into())
            .await
            .is_err()
    );
    assert!(log_paths(&root).await.is_empty());
    assert!(create(&root, "nope", "/").await.is_err());

    let names = tool_names(&dir, chain.iter().map(|text| held(text)).collect());
    assert!(names.is_empty(), "{names:?}");
}

#[tokio::test]
async fn a_scope_cannot_widen_a_denied_task_group() {
    let dir = common::fixture_dir();
    let root = chained(
        &dir,
        &[
            r#"{"paths":{"/dev/x":{"read":false,"write":false}}}"#,
            r#"{"scope":"/dev"}"#,
        ],
    )
    .unwrap();
    assert!(create(&root, "refused", "x").await.is_err());
    assert!(create(&root, "kept", "y").await.is_ok());
}

// the dot directories and records have no wire spelling: no scope, key, or
// note path can name them
#[test]
fn reserved_names_are_unspellable() {
    for text in [
        r#"{"scope":"/.logs"}"#,
        r#"{"scope":"/.tasks/dev"}"#,
        r#"{"paths":{"/.logs":{"read":false}}}"#,
    ] {
        assert!(text.parse::<PolicyFragment>().is_err(), "accepted {text}");
    }
    for spelled in [
        "/.logs/x",
        "/.tasks/x",
        "/#1/.task.md",
        "/dev/.log.md",
        "/.trash/x",
        "/a/.hidden",
    ] {
        assert!(noted::NotePath::new(spelled).is_err(), "accepted {spelled}");
    }
}

fn listings(dir: &tempfile::TempDir, grants: Vec<PolicyFragment>) -> Vec<noted::ToolListing> {
    common::root(dir).with_authority(&grants).unwrap().tools()
}

fn tool_names(dir: &tempfile::TempDir, grants: Vec<PolicyFragment>) -> Vec<&'static str> {
    listings(dir, grants).iter().map(|t| t.name).collect()
}

fn described(dir: &tempfile::TempDir, name: &str, grants: Vec<PolicyFragment>) -> String {
    listings(dir, grants)
        .into_iter()
        .find(|t| t.name == name)
        .unwrap()
        .description
}

#[test]
fn allowed_tools_follow_access() {
    let dir = common::fixture_dir();
    let all = tool_names(&dir, vec![]);
    assert!(all.contains(&"LogNote") && all.contains(&"DeleteNote"));

    let names = tool_names(
        &dir,
        vec![held(r#"{"access":{"read":true,"write":false}}"#)],
    );
    assert!(names.contains(&"ReadNote") && names.contains(&"SearchLog"));
    assert!(!names.contains(&"WriteNote") && !names.contains(&"LogNote"));
}

#[test]
fn a_tool_description_tells_a_scoped_client_where_things_land() {
    let dir = common::fixture_dir();
    let scoped = || vec![held(r#"{"scope":"/projects"}"#)];
    assert!(described(&dir, "CreateTask", scoped()).ends_with("Paths are relative to /projects."));
    assert!(described(&dir, "LogNote", scoped()).ends_with("Paths are relative to /projects."));
    assert!(described(&dir, "WriteNote", scoped()).ends_with("Paths are relative to /projects."));
    assert!(!described(&dir, "WriteNote", vec![]).contains("Paths are relative to"));
}

#[test]
fn access_survives_all_four_combinations() {
    for access in [
        r#"{"read":false,"write":false}"#,
        r#"{"read":true,"write":false}"#,
        r#"{"read":false,"write":true}"#,
        r#"{"read":true,"write":true}"#,
    ] {
        let text = format!(r#"{{"paths":{{"/a":{access}}}}}"#);
        assert_eq!(held(&text).to_string(), text);
    }
    assert_eq!(
        held(r#"{"paths":{"/a":{"read":true}}}"#).to_string(),
        r#"{"paths":{"/a":{"read":true}}}"#
    );
}

#[tokio::test]
async fn a_fragment_is_read_against_the_policy_it_lands_on() {
    let dir = common::fixture_dir();
    let root = confined(&dir, r#"{"scope":"/projects","access":{"write":false}}"#);

    assert!(read(&root, "/a.md").await.is_ok());
    assert!(write(&root, &note("/a.md", "x")).await.is_err());
    assert!(
        root.with_authority(&[held(r#"{"access":{"write":true}}"#)])
            .is_err()
    );

    let deeper = root
        .with_authority(&[held(r#"{"scope":"/alpha"}"#)])
        .unwrap();
    assert!(read(&deeper, "/a.md").await.is_err());
    assert!(read(&deeper, "/notes.md").await.is_ok());
    assert!(read(&root, "/alpha/notes.md").await.is_ok());
}

#[tokio::test]
async fn an_absent_flag_keeps_what_the_policy_already_says() {
    let dir = common::fixture_dir();
    let root = confined(
        &dir,
        r#"{"access":{"write":false},"paths":{"/vendor":{"read":false}}}"#,
    );

    assert!(read(&root, "/Inbox.md").await.is_ok());
    assert!(write(&root, &note("/Inbox.md", "x")).await.is_err());
    assert!(read(&root, "/vendor/x.md").await.is_err());
    assert!(write(&root, &note("/vendor/x.md", "x")).await.is_err());
}

#[tokio::test]
async fn a_name_never_matches_across_a_name_boundary() {
    let dir = common::fixture_dir();
    let root = confined(&dir, r#"{"paths":{"/work":{"read":false}}}"#);

    assert!(read(&root, "/work/a.md").await.is_err());
    assert!(read(&root, "/workshop/a.md").await.is_ok());
}

#[test]
fn a_yaml_fragment_is_refused() {
    assert!("scope: dev\n".parse::<PolicyFragment>().is_err());
    assert!("access:\n  read: true\n".parse::<PolicyFragment>().is_err());
}
