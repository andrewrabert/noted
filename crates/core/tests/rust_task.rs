mod common;

use common::{backend, confined_backend, fixture_dir, invoke, note, notes_root, root, rp, write};
use noted::tasks::{
    GroupPath, TaskChange, TaskNote, TaskQuery, TaskRef, TaskState, TaskTitle, parse_task_file,
};
use noted::{Backend, NotedRoot};

fn task_file(dir: &tempfile::TempDir, rel: &str) -> std::path::PathBuf {
    notes_root(dir).join("Tasks").join(format!("{rel}.md"))
}

fn seed(dir: &tempfile::TempDir, rel: &str, front: &str) {
    let path = task_file(dir, rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, front).unwrap();
}

const CREATED: &str = "---\ntask: x\nstate: created\ncreated_at: 2026-07-05T00:00:00.000000+00:00\nupdated_at: 2026-07-05T00:00:00.000000+00:00\n---\nb\n";

fn gp(s: &str) -> GroupPath {
    s.parse().unwrap()
}
fn tt(s: &str) -> TaskTitle {
    s.parse().unwrap()
}
fn tr(s: &str) -> TaskRef {
    s.parse().unwrap()
}
fn ts(s: &str) -> TaskState {
    s.parse().unwrap()
}

async fn create(root: &NotedRoot, task: &str, group: &str, notes: &str) -> noted::Result<TaskNote> {
    root.task_create(&tt(task), &gp(group), &notes.into()).await
}

async fn get(
    root: &NotedRoot,
    prefix: &str,
    include_completed: bool,
) -> noted::Result<Vec<TaskNote>> {
    root.task_get(&TaskQuery {
        prefix: tr(prefix),
        include_completed,
    })
    .await
}

async fn state_of(root: &NotedRoot, prefix: &str) -> TaskState {
    get(root, prefix, true).await.unwrap()[0].front().state
}

fn paths(tasks: &[TaskNote]) -> Vec<String> {
    tasks.iter().map(|t| t.path().to_string()).collect()
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
async fn create_summary_and_per_folder_numbering() {
    let dir = fixture_dir();
    let root = root(&dir);

    let a = create(&root, "write the parser", "", "").await.unwrap();
    assert_eq!(a.path(), "task_0001");
    assert_eq!(a.front().task, "write the parser");
    assert_eq!(a.front().state, TaskState::Created);

    assert_eq!(
        create(&root, "b", "", "").await.unwrap().path(),
        "task_0002"
    );
    assert_eq!(
        create(&root, "c", "dev", "").await.unwrap().path(),
        "dev/task_0001"
    );
    assert_eq!(
        create(&root, "d", "dev", "").await.unwrap().path(),
        "dev/task_0002"
    );
}

#[tokio::test]
async fn create_nested_group_auto_created_and_seeds_body() {
    let dir = fixture_dir();
    let root = root(&dir);
    let made = create(&root, "fix resize", "dev/myapp-desktop", "initial notes")
        .await
        .unwrap();
    assert_eq!(made.path(), "dev/myapp-desktop/task_0001");
    let body = std::fs::read_to_string(task_file(&dir, "dev/myapp-desktop/task_0001")).unwrap();
    assert!(body.contains("initial notes"));
}

#[tokio::test]
async fn numbering_from_max_and_tolerates_hand_named() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "a", "", "").await.unwrap();
    seed(&dir, "task_0005", CREATED);
    assert_eq!(
        create(&root, "b", "", "").await.unwrap().path(),
        "task_0006"
    );

    seed(&dir, "build-a-fart-machine", CREATED);
    assert_eq!(
        create(&root, "c", "", "").await.unwrap().path(),
        "task_0007"
    );
    assert!(
        paths(&get(&root, "", true).await.unwrap())
            .iter()
            .any(|p| p == "build-a-fart-machine")
    );
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

#[test]
fn bad_group_and_reference_names_are_unrepresentable() {
    for name in ["bad name", "1foo", "a.b", "dev/bad!", "../escape"] {
        assert!(
            name.parse::<GroupPath>()
                .unwrap_err()
                .to_string()
                .contains("invalid name"),
            "group {name:?} should be rejected"
        );
        assert!(name.parse::<TaskRef>().is_err(), "ref {name:?}");
    }
    assert!("ok-group_2".parse::<GroupPath>().is_ok());
    assert!("dev/noted/task_0001".parse::<TaskRef>().is_ok());
}

#[tokio::test]
async fn a_task_stamped_with_garbage_is_not_a_task() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "real", "", "").await.unwrap(); // makes the Tasks dir
    seed(
        &dir,
        "garbage",
        "---\ntask: x\nstate: created\ncreated_at: X\nupdated_at: X\n---\nb\n",
    );
    assert!(
        advance(&root, "garbage", "started", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("not a task")
    );
    assert_eq!(
        paths(&get(&root, "", true).await.unwrap()),
        vec!["task_0001"]
    );
}

#[tokio::test]
async fn empty_task_ref_and_headless_task_rejected() {
    let dir = fixture_dir();
    let root = root(&dir);
    assert!(
        advance(&root, "", "started", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("task path required")
    );

    create(&root, "real", "", "").await.unwrap(); // makes the Tasks dir
    seed(
        &dir,
        "headless",
        "---\nstate: created\ncreated_at: 2026-07-05T00:00:00.000000+00:00\nupdated_at: 2026-07-05T00:00:00.000000+00:00\n---\nb\n",
    );
    assert!(
        advance(&root, "headless", "started", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("not a task")
    );
}

#[tokio::test]
async fn ignored_tasks_are_unreachable_and_ignored_by_numbering() {
    let dir = fixture_dir();
    let root = root(&dir);
    std::fs::create_dir_all(notes_root(&dir).join("Tasks")).unwrap();
    std::fs::write(
        notes_root(&dir).join("Tasks").join(".ignore"),
        "task_0009.md\n",
    )
    .unwrap();
    create(&root, "real", "", "").await.unwrap();
    seed(&dir, "task_0009", CREATED);

    assert!(!paths(&get(&root, "", false).await.unwrap()).contains(&"task_0009".to_string()));
    assert!(advance(&root, "task_0009", "started", None).await.is_err());
    // task_0009 was seeded high so it would inflate numbering if it counted
    assert_eq!(
        create(&root, "b", "", "").await.unwrap().path(),
        "task_0002"
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

    assert_eq!(get(&root, "", false).await.unwrap().len(), 3);
    assert_eq!(get(&root, "shopping", false).await.unwrap().len(), 2);
    assert_eq!(
        paths(&get(&root, "dev", false).await.unwrap()),
        vec!["dev/myapp-desktop/task_0001"]
    );

    let exact = get(&root, "shopping/task_0001", false).await.unwrap();
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].front().task, "eggs");
    let with_body = get(&root, "dev/myapp-desktop/task_0001", false)
        .await
        .unwrap();
    assert_eq!(with_body[0].body().as_str().trim(), "the working notes");
}

#[tokio::test]
async fn query_hides_closed_but_exact_always_returned() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "live", "", "").await.unwrap();
    create(&root, "done", "", "").await.unwrap();
    advance(&root, "task_0002", "completed", Some("finished"))
        .await
        .unwrap();

    assert_eq!(
        paths(&get(&root, "", false).await.unwrap()),
        vec!["task_0001"]
    );
    assert_eq!(get(&root, "", true).await.unwrap().len(), 2);
    assert_eq!(
        get(&root, "task_0002", false).await.unwrap()[0]
            .front()
            .state,
        TaskState::Completed
    );
}

#[tokio::test]
async fn query_newest_updated_first() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "first", "", "").await.unwrap();
    create(&root, "second", "", "").await.unwrap();
    advance(&root, "task_0001", "started", None).await.unwrap(); // bumps updated_at
    assert_eq!(
        paths(&get(&root, "", false).await.unwrap()),
        vec!["task_0001", "task_0002"]
    );
}

#[tokio::test]
async fn query_sorts_by_instant_not_string_across_offsets() {
    let dir = fixture_dir();
    let root = root(&dir);
    // `later` is chronologically newer (16:00Z) than `earlier` (10:00Z), but its
    // updated_at string sorts BEFORE `earlier`'s lexically ("09:" < "10:"). A
    // string-compare sort would return them newest-first as [earlier, later];
    // parsing to an instant must return [later, earlier].
    seed(
        &dir,
        "later",
        "---\ntask: later\nstate: started\ncreated_at: 2026-07-05T00:00:00.000000-07:00\nupdated_at: 2026-07-05T09:00:00.000000-07:00\n---\nb\n",
    );
    seed(
        &dir,
        "earlier",
        "---\ntask: earlier\nstate: started\ncreated_at: 2026-07-05T00:00:00.000000+00:00\nupdated_at: 2026-07-05T10:00:00.000000+00:00\n---\nb\n",
    );
    assert_eq!(
        paths(&get(&root, "", false).await.unwrap()),
        vec!["later", "earlier"]
    );
}

#[tokio::test]
async fn query_tiebreaks_equal_timestamps_case_insensitively() {
    let dir = fixture_dir();
    let root = root(&dir);
    // same updated_at for all three: ordering falls to the case-insensitive
    // path tiebreak (raw-byte order would put the capitalized names first)
    let front = |task: &str| {
        format!(
            "---\ntask: {task}\nstate: started\ncreated_at: 2026-07-05T00:00:00.000000+00:00\nupdated_at: 2026-07-05T10:00:00.000000+00:00\n---\nb\n"
        )
    };
    for name in ["Cherry", "apple", "Banana"] {
        seed(&dir, name, &front(name));
    }
    assert_eq!(
        paths(&get(&root, "", false).await.unwrap()),
        vec!["apple", "Banana", "Cherry"]
    );
}

#[tokio::test]
async fn create_stamps_local_offset_timestamp() {
    let dir = fixture_dir();
    let root = root(&dir);
    let made = create(&root, "t", "", "").await.unwrap();
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
    create(&root, "old wording", "", "").await.unwrap();
    let before = get(&root, "task_0001", false).await.unwrap();
    let before = before[0].front().clone();

    let after = advance(&root, "task_0001", "started", None).await.unwrap();
    assert_eq!(after.front().state, TaskState::Started);
    assert_eq!(after.front().created_at, before.created_at);
    assert!(after.front().updated_at >= before.updated_at);

    root.task_update(
        &tr("task_0001"),
        &TaskChange {
            state: None,
            notes: Some("new notes".into()),
            task: Some(tt("new wording")),
        },
    )
    .await
    .unwrap();
    let reread = get(&root, "task_0001", false).await.unwrap();
    assert_eq!(reread[0].front().task, "new wording");
    assert_eq!(reread[0].body().as_str().trim(), "new notes");
}

#[tokio::test]
async fn update_state_and_body_rules() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "t", "", "").await.unwrap();

    assert!(
        "bogus"
            .parse::<TaskState>()
            .unwrap_err()
            .to_string()
            .contains("unknown state")
    );
    assert!(
        advance(&root, "task_0001", "completed", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("non-empty")
    );
    assert_eq!(
        advance(&root, "task_0001", "completed", Some("fixed it"))
            .await
            .unwrap()
            .front()
            .state,
        TaskState::Completed
    );
    assert_eq!(state_of(&root, "task_0001").await, TaskState::Completed);
}

#[tokio::test]
async fn update_missing_and_non_task_file() {
    let dir = fixture_dir();
    let root = root(&dir);
    assert!(matches!(
        advance(&root, "nope/task_0001", "started", None)
            .await
            .unwrap_err(),
        noted::NotedError::NotFound
    ));

    create(&root, "real", "", "").await.unwrap();
    seed(&dir, "stray", "no frontmatter here\n");
    assert!(
        advance(&root, "stray", "started", None)
            .await
            .unwrap_err()
            .to_string()
            .contains("not a task")
    );
}

#[tokio::test]
async fn move_renumbers_bumps_updated_and_removes_source() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "a", "shopping", "").await.unwrap();
    let before = create(&root, "keep", "dev", "").await.unwrap(); // dev/task_0001 forces a renumber

    let moved = root
        .task_move(&tr("shopping/task_0001"), &gp("dev"))
        .await
        .unwrap();
    assert_eq!(moved.path(), "dev/task_0002");
    assert!(moved.front().updated_at >= before.front().updated_at);
    assert!(get(&root, "shopping", false).await.unwrap().is_empty());
}

#[tokio::test]
async fn move_same_group_and_missing_refused() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "a", "shopping", "").await.unwrap();
    assert!(
        root.task_move(&tr("shopping/task_0001"), &gp("shopping"))
            .await
            .unwrap_err()
            .to_string()
            .contains("already in that group")
    );
    assert!(matches!(
        root.task_move(&tr("ghost/task_0001"), &gp("dev"))
            .await
            .unwrap_err(),
        noted::NotedError::NotFound
    ));
}

#[tokio::test]
async fn move_custom_name_preserved_and_clash_refused() {
    let dir = fixture_dir();
    let root = root(&dir);
    seed(&dir, "shopping/buy-eggs", CREATED);
    assert_eq!(
        root.task_move(&tr("shopping/buy-eggs"), &gp("dev"))
            .await
            .unwrap()
            .path(),
        "dev/buy-eggs"
    );
    seed(&dir, "other/buy-eggs", CREATED);
    seed(&dir, "dev/buy-eggs", CREATED);
    assert!(matches!(
        root.task_move(&tr("other/buy-eggs"), &gp("dev"))
            .await
            .unwrap_err(),
        noted::NotedError::Conflict
    ));
}

#[tokio::test]
async fn tasks_subtree_is_managed() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "t", "", "").await.unwrap();
    write(&root, &note("loose.md", "x")).await.unwrap();

    for err in [
        write(&root, &note("Tasks/task_0009.md", "nope"))
            .await
            .unwrap_err(),
        root.note_delete(&rp("Tasks/task_0001.md"))
            .await
            .unwrap_err(),
        root.note_move(&rp("Tasks/task_0001.md"), &rp("elsewhere.md"), false)
            .await
            .unwrap_err(),
        root.note_move(&rp("loose.md"), &rp("Tasks/task_0002.md"), false)
            .await
            .unwrap_err(),
    ] {
        assert!(
            matches!(err, noted::NotedError::Forbidden),
            "expected a policy refusal, got {err}"
        );
    }
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
async fn symlinked_task_file_is_ignored() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "real", "grp", "").await.unwrap();

    let outside = notes_root(&dir).join("outside.md");
    std::fs::write(&outside, CREATED).unwrap();
    let group_dir = notes_root(&dir).join("Tasks/grp");
    std::os::unix::fs::symlink(&outside, group_dir.join("task_0005.md")).unwrap();

    assert_eq!(
        paths(&get(&root, "grp", false).await.unwrap()),
        vec!["grp/task_0001"]
    );
    assert!(get(&root, "grp/task_0005", false).await.unwrap().is_empty());
    assert!(
        advance(&root, "grp/task_0005", "started", None)
            .await
            .is_err()
    );
    // the symlink was named task_0005 precisely so it would inflate numbering
    // if it counted
    assert_eq!(
        create(&root, "next", "grp", "").await.unwrap().path(),
        "grp/task_0002"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_group_dir_is_ignored() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "real", "", "").await.unwrap(); // makes Tasks/

    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("task_0001.md"), CREATED).unwrap();
    std::os::unix::fs::symlink(outside.path(), notes_root(&dir).join("Tasks/escape")).unwrap();

    assert!(get(&root, "escape", false).await.unwrap().is_empty());
    assert_eq!(
        paths(&get(&root, "", true).await.unwrap()),
        vec!["task_0001"]
    );
}

async fn find(backend: &Backend, args: serde_json::Value) -> String {
    invoke(backend, "SearchTasks", args).await.unwrap().render()
}

#[tokio::test]
async fn search_returns_task_refs_newest_updated_first() {
    let dir = fixture_dir();
    let root = root(&dir);
    let bknd = backend(&dir);
    create(&root, "older", "dev", "SHARED marker\n")
        .await
        .unwrap();
    create(&root, "newer", "dev", "SHARED marker\n")
        .await
        .unwrap();
    advance(&root, "dev/task_0002", "started", None)
        .await
        .unwrap();

    let out = find(&bknd, serde_json::json!({"pattern": "SHARED"})).await;
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        vec!["dev/task_0002", "dev/task_0001"]
    );

    let listed = find(&bknd, serde_json::json!({"mode": "path"})).await;
    assert_eq!(
        listed.lines().collect::<Vec<_>>(),
        vec!["dev/task_0002", "dev/task_0001"],
        "the most recently updated task comes first"
    );
}

#[tokio::test]
async fn search_line_mode_addresses_matches_by_task_ref() {
    let dir = fixture_dir();
    let root = root(&dir);
    let bknd = backend(&dir);
    create(&root, "t", "dev", "NEEDLE here\n").await.unwrap();

    let out = find(
        &bknd,
        serde_json::json!({"pattern": "NEEDLE", "mode": "line"}),
    )
    .await;
    assert!(out.starts_with("dev/task_0001:"), "{out}");
    assert!(!out.contains("Tasks/"), "{out}");
    assert!(!out.contains(".md"), "{out}");
}

#[tokio::test]
async fn search_narrows_to_a_group_and_hides_closed_tasks() {
    let dir = fixture_dir();
    let root = root(&dir);
    let bknd = backend(&dir);
    create(&root, "kept", "dev", "MARK\n").await.unwrap();
    create(&root, "elsewhere", "ops", "MARK\n").await.unwrap();
    create(&root, "done", "dev", "MARK\n").await.unwrap();
    advance(&root, "dev/task_0002", "completed", Some("MARK finished\n"))
        .await
        .unwrap();

    let scoped = find(
        &bknd,
        serde_json::json!({"pattern": "MARK", "prefix": "dev"}),
    )
    .await;
    assert_eq!(scoped.lines().collect::<Vec<_>>(), vec!["dev/task_0001"]);

    let closed = find(
        &bknd,
        serde_json::json!({"pattern": "MARK", "prefix": "dev", "include_completed": true}),
    )
    .await;
    assert_eq!(closed.lines().count(), 2, "{closed}");

    let everywhere = find(&bknd, serde_json::json!({"pattern": "MARK"})).await;
    assert!(everywhere.contains("ops/task_0001"), "{everywhere}");
}

#[tokio::test]
async fn search_is_scoped_to_tasks_and_validates_its_prefix() {
    let dir = fixture_dir();
    let root = root(&dir);
    let bknd = backend(&dir);
    create(&root, "t", "dev", "body\n").await.unwrap();

    // "contacts" appears only in the open region
    assert!(
        find(&bknd, serde_json::json!({"pattern": "contacts"}))
            .await
            .is_empty()
    );
    for args in [
        serde_json::json!({"prefix": "../escape"}),
        serde_json::json!({"prefix": "0bad"}),
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

    let confined = confined_backend(
        &dir,
        r#"{"paths":{"Tasks/ops":{"read":false,"write":false}}}"#,
    );
    let out = find(&confined, serde_json::json!({"pattern": "MARK"})).await;
    assert_eq!(out.lines().collect::<Vec<_>>(), vec!["dev/task_0001"]);
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
        let group = format!("g{n}");
        let made = create(&root, title, &group, "").await.unwrap();
        assert_eq!(made.front().task, tt(title));
        let read = get(&root, &group, true).await.unwrap();
        assert_eq!(read[0].front().task, tt(title), "title {title:?}");
    }
}

#[test]
fn task_refs_order_case_insensitively_then_by_bytes() {
    let tr = |s: &str| TaskRef::new(s).unwrap();
    let mut refs = vec![tr("Cherry"), tr("apple"), tr("Banana")];
    refs.sort();
    assert_eq!(refs, vec![tr("apple"), tr("Banana"), tr("Cherry")]);
    assert!(tr("g/A") < tr("g/a"));
}
