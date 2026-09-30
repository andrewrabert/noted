mod common;

use common::{backend, confined_backend, fixture_dir, invoke, note, notes_root, read, root, write};
use noted::tasks::{TaskChange, TaskNote, TaskQuery, TaskState, TaskTitle, parse_task_file};
use noted::{DirPath, NotePath, NotedRoot, TaskPath};

// the on-disk directory of task `n` under the directory `under` ('' = top)
fn task_dir(dir: &tempfile::TempDir, under: &str, n: u64) -> std::path::PathBuf {
    let mut at = notes_root(dir);
    for part in under.split('/').filter(|p| !p.is_empty()) {
        at.push(part);
    }
    at.join(".tasks").join(n.to_string())
}

fn task_file(dir: &tempfile::TempDir, under: &str, n: u64) -> std::path::PathBuf {
    task_dir(dir, under, n).join(".task.md")
}

fn seed(dir: &tempfile::TempDir, under: &str, n: u64, front: &str) {
    let path = task_file(dir, under, n);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, front).unwrap();
}

const CREATED: &str = "---\ntask: x\nstate: created\ncreated_at: 2026-07-05T00:00:00.000000+00:00\nupdated_at: 2026-07-05T00:00:00.000000+00:00\n---\nb\n";

fn np(s: &str) -> NotePath {
    NotePath::new(s).unwrap()
}
fn dp(s: &str) -> DirPath {
    DirPath::try_from(np(s)).unwrap()
}
fn tt(s: &str) -> TaskTitle {
    s.parse().unwrap()
}
fn tr(s: &str) -> TaskPath {
    TaskPath::try_from(np(s)).unwrap()
}
fn ts(s: &str) -> TaskState {
    s.parse().unwrap()
}

async fn create(root: &NotedRoot, task: &str, dir: &str, notes: &str) -> noted::Result<TaskNote> {
    root.task_create(&tt(task), &dp(dir), &notes.into()).await
}

async fn get(
    root: &NotedRoot,
    prefix: &str,
    include_completed: bool,
) -> noted::Result<Vec<TaskNote>> {
    root.task_get(&TaskQuery {
        prefix: dp(prefix),
        include_completed,
    })
    .await
}

async fn state_of(root: &NotedRoot, prefix: &str) -> TaskState {
    get(root, prefix, true).await.unwrap()[0].front().state
}

fn path_of(task: &TaskNote) -> String {
    task.path().to_string()
}

fn paths(tasks: &[TaskNote]) -> Vec<String> {
    tasks.iter().map(path_of).collect()
}

async fn advance(
    root: &NotedRoot,
    reference: &str,
    state: &str,
    notes: Option<&str>,
) -> noted::Result<TaskNote> {
    root.task_update(
        &tr(reference),
        &TaskChange {
            state: Some(ts(state)),
            notes: notes.map(Into::into),
            task: None,
        },
    )
    .await
}

#[tokio::test]
async fn create_summary_and_per_directory_numbering() {
    let dir = fixture_dir();
    let root = root(&dir);

    let a = create(&root, "write the parser", "/", "").await.unwrap();
    assert_eq!(path_of(&a), "/#1");
    assert_eq!(a.front().task, "write the parser");
    assert_eq!(a.front().state, TaskState::Created);

    assert_eq!(path_of(&create(&root, "b", "/", "").await.unwrap()), "/#2");
    assert_eq!(
        path_of(&create(&root, "c", "dev", "").await.unwrap()),
        "/dev/#1"
    );
    assert_eq!(
        path_of(&create(&root, "d", "dev", "").await.unwrap()),
        "/dev/#2"
    );
    assert!(task_file(&dir, "dev", 2).is_file());
}

#[tokio::test]
async fn create_nested_directory_auto_created_and_seeds_body() {
    let dir = fixture_dir();
    let root = root(&dir);
    let made = create(&root, "fix resize", "dev/myapp-desktop", "initial notes")
        .await
        .unwrap();
    assert_eq!(path_of(&made), "/dev/myapp-desktop/#1");
    let body = std::fs::read_to_string(task_file(&dir, "dev/myapp-desktop", 1)).unwrap();
    assert!(body.contains("initial notes"));
}

#[tokio::test]
async fn tasks_nest_inside_tasks_and_entries() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "outer", "dev", "").await.unwrap();
    let inner = create(&root, "inner", "dev/#1", "").await.unwrap();
    assert_eq!(path_of(&inner), "/dev/#1/#1");
    assert!(task_file(&dir, "dev/.tasks/1", 1).is_file());

    let entry = root.log_note(&dp("dev"), &"x\n".into()).await.unwrap();
    let scoped = create(&root, "in an entry", &entry.path().to_string(), "")
        .await
        .unwrap();
    assert_eq!(path_of(&scoped), format!("{}/#1", entry.path()));

    assert_eq!(get(&root, "dev", false).await.unwrap().len(), 3);
    assert_eq!(
        paths(&get(&root, "dev/#1", false).await.unwrap()),
        vec!["/dev/#1"],
        "an exact task path is that one task"
    );
}

#[tokio::test]
async fn numbering_continues_from_the_largest_task_number() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "a", "/", "").await.unwrap();
    seed(&dir, "", 5, CREATED);
    assert_eq!(path_of(&create(&root, "b", "/", "").await.unwrap()), "/#6");
}

#[test]
fn create_requires_task() {
    assert!(
        "".parse::<TaskTitle>()
            .unwrap_err()
            .to_string()
            .contains("task is required")
    );
    assert!("   ".parse::<TaskTitle>().is_err());
}

#[tokio::test]
async fn a_task_stamped_with_garbage_is_not_a_task() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "real", "/", "").await.unwrap();
    seed(
        &dir,
        "",
        7,
        "---\ntask: x\nstate: created\ncreated_at: X\nupdated_at: X\n---\nb\n",
    );
    assert!(
        advance(&root, "/#7", "started", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("not a task")
    );
    assert_eq!(paths(&get(&root, "/", true).await.unwrap()), vec!["/#1"]);
}

#[tokio::test]
async fn a_task_directory_without_its_record_is_not_a_task() {
    let dir = fixture_dir();
    let root = root(&dir);
    std::fs::create_dir_all(task_dir(&dir, "", 9)).unwrap();
    std::fs::write(task_dir(&dir, "", 9).join("note.md"), "x").unwrap();
    assert!(get(&root, "/", true).await.unwrap().is_empty());
    // the recordless directory does not inflate numbering
    assert_eq!(path_of(&create(&root, "a", "/", "").await.unwrap()), "/#1");
}

#[tokio::test]
async fn headless_task_rejected() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "real", "/", "").await.unwrap();
    seed(
        &dir,
        "",
        3,
        "---\nstate: created\ncreated_at: 2026-07-05T00:00:00.000000+00:00\nupdated_at: 2026-07-05T00:00:00.000000+00:00\n---\nb\n",
    );
    assert!(
        advance(&root, "/#3", "started", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("not a task")
    );
}

#[tokio::test]
async fn query_scoping_body_and_hidden_closed() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "eggs", "shopping", "").await.unwrap();
    create(&root, "milk", "shopping", "").await.unwrap();
    create(&root, "resize", "dev/myapp-desktop", "the working notes")
        .await
        .unwrap();

    assert_eq!(get(&root, "/", false).await.unwrap().len(), 3);
    assert_eq!(get(&root, "shopping", false).await.unwrap().len(), 2);
    assert_eq!(
        paths(&get(&root, "dev", false).await.unwrap()),
        vec!["/dev/myapp-desktop/#1"]
    );

    let exact = get(&root, "shopping/#1", false).await.unwrap();
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].front().task, "eggs");
    let with_body = get(&root, "dev/myapp-desktop/#1", false).await.unwrap();
    assert_eq!(with_body[0].body().as_str().trim(), "the working notes");
}

#[tokio::test]
async fn query_hides_closed_but_exact_always_returned() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "live", "/", "").await.unwrap();
    create(&root, "done", "/", "").await.unwrap();
    advance(&root, "/#2", "completed", Some("finished"))
        .await
        .unwrap();

    assert_eq!(paths(&get(&root, "/", false).await.unwrap()), vec!["/#1"]);
    assert_eq!(get(&root, "/", true).await.unwrap().len(), 2);
    assert_eq!(
        get(&root, "/#2", false).await.unwrap()[0].front().state,
        TaskState::Completed
    );
}

#[tokio::test]
async fn query_newest_updated_first() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "first", "/", "").await.unwrap();
    create(&root, "second", "/", "").await.unwrap();
    advance(&root, "/#1", "started", None).await.unwrap(); // bumps updated_at
    assert_eq!(
        paths(&get(&root, "/", false).await.unwrap()),
        vec!["/#1", "/#2"]
    );
}

#[tokio::test]
async fn query_sorts_by_instant_not_string_across_offsets() {
    let dir = fixture_dir();
    let root = root(&dir);
    // `#1` is chronologically newer (16:00Z) than `#2` (10:00Z), but its
    // updated_at string sorts BEFORE `#2`'s lexically ("09:" < "10:"). A
    // string-compare sort would return them newest-first as [#2, #1];
    // parsing to an instant must return [#1, #2].
    seed(
        &dir,
        "",
        1,
        "---\ntask: later\nstate: started\ncreated_at: 2026-07-05T00:00:00.000000-07:00\nupdated_at: 2026-07-05T09:00:00.000000-07:00\n---\nb\n",
    );
    seed(
        &dir,
        "",
        2,
        "---\ntask: earlier\nstate: started\ncreated_at: 2026-07-05T00:00:00.000000+00:00\nupdated_at: 2026-07-05T10:00:00.000000+00:00\n---\nb\n",
    );
    assert_eq!(
        paths(&get(&root, "/", false).await.unwrap()),
        vec!["/#1", "/#2"]
    );
}

#[tokio::test]
async fn query_tiebreaks_equal_timestamps_by_task_number() {
    let dir = fixture_dir();
    let root = root(&dir);
    // same updated_at for all three: ordering falls to the path tiebreak,
    // where tasks order by number, not by spelling ('#10' after '#9')
    let front = |task: &str| {
        format!(
            "---\ntask: {task}\nstate: started\ncreated_at: 2026-07-05T00:00:00.000000+00:00\nupdated_at: 2026-07-05T10:00:00.000000+00:00\n---\nb\n"
        )
    };
    for n in [10, 9, 2] {
        seed(&dir, "", n, &front("t"));
    }
    assert_eq!(
        paths(&get(&root, "/", false).await.unwrap()),
        vec!["/#2", "/#9", "/#10"]
    );
}

#[tokio::test]
async fn create_stamps_local_offset_timestamp() {
    let dir = fixture_dir();
    let root = root(&dir);
    let made = create(&root, "t", "/", "").await.unwrap();
    let created = made.front().created_at.to_string();
    assert!(
        chrono::DateTime::parse_from_rfc3339(&created).is_ok(),
        "{created}"
    );
    assert!(created.contains('.'), "expected microseconds: {created}");
    assert!(
        !created.ends_with('Z'),
        "expected an explicit offset, not Z: {created}"
    );
}

#[tokio::test]
async fn update_preserves_created_bumps_updated_and_rewords() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "old wording", "/", "").await.unwrap();
    let before = get(&root, "/#1", false).await.unwrap();
    let before = before[0].front().clone();

    let after = advance(&root, "/#1", "started", None).await.unwrap();
    assert_eq!(after.front().state, TaskState::Started);
    assert_eq!(after.front().created_at, before.created_at);
    assert!(after.front().updated_at >= before.updated_at);

    root.task_update(
        &tr("/#1"),
        &TaskChange {
            state: None,
            notes: Some("new notes".into()),
            task: Some(tt("new wording")),
        },
    )
    .await
    .unwrap();
    let reread = get(&root, "/#1", false).await.unwrap();
    assert_eq!(reread[0].front().task, "new wording");
    assert_eq!(reread[0].body().as_str().trim(), "new notes");
}

#[tokio::test]
async fn update_state_and_body_rules() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "t", "/", "").await.unwrap();

    assert!(
        "bogus"
            .parse::<TaskState>()
            .unwrap_err()
            .to_string()
            .contains("unknown state")
    );
    assert!(
        advance(&root, "/#1", "completed", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("non-empty")
    );
    assert_eq!(
        advance(&root, "/#1", "completed", Some("fixed it"))
            .await
            .unwrap()
            .front()
            .state,
        TaskState::Completed
    );
    assert_eq!(state_of(&root, "/#1").await, TaskState::Completed);
}

#[tokio::test]
async fn update_missing_and_non_task_record() {
    let dir = fixture_dir();
    let root = root(&dir);
    assert!(matches!(
        advance(&root, "nope/#1", "started", None)
            .await
            .unwrap_err(),
        noted::NotedError::NotFound
    ));

    create(&root, "real", "/", "").await.unwrap();
    seed(&dir, "", 4, "no frontmatter here\n");
    assert!(
        advance(&root, "/#4", "started", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("not a task")
    );
}

#[tokio::test]
async fn move_renumbers_bumps_updated_and_carries_its_contents() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "a", "shopping", "").await.unwrap();
    create(&root, "inner", "shopping/#1", "").await.unwrap();
    write(&root, &note("/shopping/#1/plan.md", "the plan"))
        .await
        .unwrap();
    let before = create(&root, "keep", "dev", "").await.unwrap(); // dev/#1 forces a renumber

    let moved = root
        .task_move(&tr("shopping/#1"), &dp("dev"))
        .await
        .unwrap();
    assert_eq!(path_of(&moved), "/dev/#2");
    assert!(moved.front().updated_at >= before.front().updated_at);
    assert!(get(&root, "shopping", false).await.unwrap().is_empty());
    assert_eq!(read(&root, "/dev/#2/plan.md").await.unwrap(), "the plan");
    assert_eq!(
        paths(&get(&root, "dev/#2/#1", false).await.unwrap()),
        vec!["/dev/#2/#1"],
        "an inner task keeps its own number"
    );
}

#[tokio::test]
async fn move_same_directory_into_itself_and_missing_refused() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "a", "shopping", "").await.unwrap();
    assert!(
        root.task_move(&tr("shopping/#1"), &dp("shopping"))
            .await
            .unwrap_err()
            .to_string()
            .contains("already in")
    );
    assert!(
        root.task_move(&tr("shopping/#1"), &dp("shopping/#1/deeper"))
            .await
            .unwrap_err()
            .to_string()
            .contains("into itself")
    );
    assert!(matches!(
        root.task_move(&tr("ghost/#1"), &dp("dev"))
            .await
            .unwrap_err(),
        noted::NotedError::NotFound
    ));
}

#[tokio::test]
async fn task_records_are_managed() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "t", "/", "").await.unwrap();
    write(&root, &note("/loose.md", "x")).await.unwrap();

    for spelled in ["/.tasks/1/.task.md", "/#1/.task.md", "/.tasks/1"] {
        assert!(
            NotePath::new(spelled).is_err(),
            "a task record is not a note path: {spelled}"
        );
    }
    assert!(read(&root, "/#1").await.is_err());
    assert!(write(&root, &note("/#1", "x")).await.is_err());
    write(&root, &note("/#1/plan.md", "a note inside"))
        .await
        .unwrap();
}

#[test]
fn parse_task_file_edges() {
    let (front, body) = parse_task_file("---\nnever closes\n");
    assert!(front.is_none());
    assert_eq!(body, "---\nnever closes\n");

    assert!(
        parse_task_file("---\nfoo: [unclosed\n---\nbody\n")
            .0
            .is_none()
    );
    assert!(
        parse_task_file("---\njust a scalar\n---\nbody\n")
            .0
            .is_none()
    );

    let (front, body) = parse_task_file(CREATED);
    let front = front.unwrap();
    assert_eq!(front.task, "x");
    assert_eq!(body, "b\n");
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_task_record_is_ignored() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "real", "grp", "").await.unwrap();

    let outside = notes_root(&dir).join("outside.md");
    std::fs::write(&outside, CREATED).unwrap();
    std::fs::create_dir_all(task_dir(&dir, "grp", 5)).unwrap();
    std::os::unix::fs::symlink(&outside, task_file(&dir, "grp", 5)).unwrap();

    assert_eq!(
        paths(&get(&root, "grp", false).await.unwrap()),
        vec!["/grp/#1"]
    );
    assert!(get(&root, "grp/#5", false).await.unwrap().is_empty());
    assert!(advance(&root, "grp/#5", "started", None).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_task_dir_is_ignored() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "real", "/", "").await.unwrap(); // makes .tasks/

    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join(".task.md"), CREATED).unwrap();
    std::os::unix::fs::symlink(outside.path(), notes_root(&dir).join(".tasks/7")).unwrap();

    assert!(get(&root, "/#7", false).await.unwrap().is_empty());
    assert_eq!(paths(&get(&root, "/", true).await.unwrap()), vec!["/#1"]);
}

async fn find(backend: &NotedRoot, args: serde_json::Value) -> String {
    invoke(backend, "SearchTasks", args).await.unwrap().render()
}

#[tokio::test]
async fn search_returns_task_paths_newest_updated_first() {
    let dir = fixture_dir();
    let root = root(&dir);
    let bknd = backend(&dir);
    create(&root, "older", "dev", "SHARED marker\n")
        .await
        .unwrap();
    create(&root, "newer", "dev", "SHARED marker\n")
        .await
        .unwrap();
    advance(&root, "dev/#2", "started", None).await.unwrap();

    let out = find(&bknd, serde_json::json!({"pattern": "SHARED"})).await;
    assert_eq!(out.lines().collect::<Vec<_>>(), vec!["/dev/#2", "/dev/#1"]);

    let listed = find(&bknd, serde_json::json!({"mode": "path"})).await;
    assert_eq!(
        listed.lines().collect::<Vec<_>>(),
        vec!["/dev/#2", "/dev/#1"],
        "the most recently updated task comes first"
    );
}

#[tokio::test]
async fn search_covers_task_records_only() {
    let dir = fixture_dir();
    let root = root(&dir);
    let bknd = backend(&dir);
    create(&root, "t", "dev", "NEEDLE here\n").await.unwrap();
    write(&root, &note("/dev/#1/plan.md", "NEEDLE in a note"))
        .await
        .unwrap();

    let out = find(
        &bknd,
        serde_json::json!({"pattern": "NEEDLE", "mode": "line"}),
    )
    .await;
    assert!(out.starts_with("/dev/#1:"), "{out}");
    assert!(!out.contains("plan.md"), "{out}");
    assert!(!out.contains(".tasks/"), "{out}");
    assert!(!out.contains(".task.md"), "{out}");
}

#[tokio::test]
async fn search_narrows_to_a_directory_and_hides_closed_tasks() {
    let dir = fixture_dir();
    let root = root(&dir);
    let bknd = backend(&dir);
    create(&root, "kept", "dev", "MARK\n").await.unwrap();
    create(&root, "elsewhere", "ops", "MARK\n").await.unwrap();
    create(&root, "done", "dev", "MARK\n").await.unwrap();
    advance(&root, "dev/#2", "completed", Some("MARK finished\n"))
        .await
        .unwrap();

    let scoped = find(
        &bknd,
        serde_json::json!({"pattern": "MARK", "prefix": "dev"}),
    )
    .await;
    assert_eq!(scoped.lines().collect::<Vec<_>>(), vec!["/dev/#1"]);

    let closed = find(
        &bknd,
        serde_json::json!({"pattern": "MARK", "prefix": "dev", "include_completed": true}),
    )
    .await;
    assert_eq!(closed.lines().count(), 2, "{closed}");

    let everywhere = find(&bknd, serde_json::json!({"pattern": "MARK"})).await;
    assert!(everywhere.contains("/ops/#1"), "{everywhere}");
}

#[tokio::test]
async fn search_skips_notes_and_validates_its_prefix() {
    let dir = fixture_dir();
    let root = root(&dir);
    let bknd = backend(&dir);
    create(&root, "t", "dev", "body\n").await.unwrap();

    // "contacts" appears only in ordinary notes
    assert!(
        find(&bknd, serde_json::json!({"pattern": "contacts"}))
            .await
            .is_empty()
    );
    for args in [
        serde_json::json!({"prefix": "../escape"}),
        serde_json::json!({"prefix": "/.tasks"}),
        serde_json::json!({"pattern": "("}),
    ] {
        assert!(
            invoke(&bknd, "SearchTasks", args.clone()).await.is_err(),
            "{args} should be rejected"
        );
    }
}

#[tokio::test]
async fn search_admits_only_what_the_grant_allows() {
    let dir = fixture_dir();
    let root = root(&dir);
    let bknd = backend(&dir);
    create(&root, "visible", "dev", "MARK\n").await.unwrap();
    create(&root, "hidden", "ops", "MARK\n").await.unwrap();

    let confined = confined_backend(&dir, r#"{"paths":{"/ops":{"read":false,"write":false}}}"#);
    let out = find(&confined, serde_json::json!({"pattern": "MARK"})).await;
    assert_eq!(out.lines().collect::<Vec<_>>(), vec!["/dev/#1"]);
    assert_eq!(
        find(&bknd, serde_json::json!({"pattern": "MARK"}))
            .await
            .lines()
            .count(),
        2,
        "the unconfined caller sees both"
    );
    assert!(
        invoke(
            &confined,
            "SearchTasks",
            serde_json::json!({"prefix": "ops"}),
        )
        .await
        .is_err(),
        "a prefix the policy denies outright is refused"
    );
}

// 'Fix: it', "don't", '- dash', 'naïve 🎉'
#[tokio::test]
async fn a_tricky_title_round_trips_through_the_file() {
    let dir = fixture_dir();
    let root = root(&dir);
    for (n, title) in ["Fix: it", "don't", "- dash", "naïve 🎉", "#1", "true"]
        .iter()
        .enumerate()
    {
        let under = format!("g{n}");
        let made = create(&root, title, &under, "").await.unwrap();
        assert_eq!(made.front().task, tt(title));
        let read = get(&root, &under, true).await.unwrap();
        assert_eq!(read[0].front().task, tt(title), "title {title:?}");
    }
}

#[test]
fn task_refs_order_by_number_within_a_directory() {
    let mut refs = vec![tr("/#10"), tr("/#2"), tr("/#9")];
    refs.sort();
    assert_eq!(refs, vec![tr("/#2"), tr("/#9"), tr("/#10")]);
    assert!(tr("/a/#1") < tr("/b/#1"));
}
