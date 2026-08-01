mod common;

use common::{fixture_dir, note, notes_root, root, rp, write};
use noted::root::NotedRoot;
use noted::tasks::{
    GroupPath, TaskChange, TaskNote, TaskQuery, TaskRef, TaskState, TaskTitle, parse_task_file,
};

fn task_file(dir: &tempfile::TempDir, rel: &str) -> std::path::PathBuf {
    notes_root(dir).join("Tasks").join(format!("{rel}.md"))
}

fn seed(dir: &tempfile::TempDir, rel: &str, front: &str) {
    let path = task_file(dir, rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, front).unwrap();
}

const CREATED: &str = "---\ntask: x\nstate: created\ncreated_at: X\nupdated_at: X\n---\nb\n";

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

fn create(root: &NotedRoot, task: &str, group: &str, notes: &str) -> noted::Result<TaskNote> {
    root.task_create(&tt(task), &gp(group), &notes.into())
}

fn get(root: &NotedRoot, prefix: &str, include_completed: bool) -> noted::Result<Vec<TaskNote>> {
    root.task_get(&TaskQuery {
        prefix: tr(prefix),
        include_completed,
    })
}

fn state_of(root: &NotedRoot, prefix: &str) -> TaskState {
    get(root, prefix, true).unwrap()[0].front().state
}

fn paths(tasks: &[TaskNote]) -> Vec<String> {
    tasks.iter().map(|t| t.path().to_string()).collect()
}

fn advance(
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
}

#[test]
fn create_summary_and_per_folder_numbering() {
    let dir = fixture_dir();
    let root = root(&dir);

    let a = create(&root, "write the parser", "", "").unwrap();
    assert_eq!(a.path(), "task_0001");
    assert_eq!(a.front().task, "write the parser");
    assert_eq!(a.front().state, TaskState::Created);

    assert_eq!(create(&root, "b", "", "").unwrap().path(), "task_0002");
    assert_eq!(
        create(&root, "c", "dev", "").unwrap().path(),
        "dev/task_0001"
    );
    assert_eq!(
        create(&root, "d", "dev", "").unwrap().path(),
        "dev/task_0002"
    );
}

#[test]
fn create_nested_group_auto_created_and_seeds_body() {
    let dir = fixture_dir();
    let root = root(&dir);
    let made = create(&root, "fix resize", "dev/myapp-desktop", "initial notes").unwrap();
    assert_eq!(made.path(), "dev/myapp-desktop/task_0001");
    let body = std::fs::read_to_string(task_file(&dir, "dev/myapp-desktop/task_0001")).unwrap();
    assert!(body.contains("initial notes"));
}

#[test]
fn numbering_from_max_and_tolerates_hand_named() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "a", "", "").unwrap();
    seed(&dir, "task_0005", CREATED);
    assert_eq!(create(&root, "b", "", "").unwrap().path(), "task_0006");

    seed(&dir, "build-a-fart-machine", CREATED);
    assert_eq!(create(&root, "c", "", "").unwrap().path(), "task_0007");
    assert!(
        paths(&get(&root, "", true).unwrap())
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

#[test]
fn empty_task_ref_and_headless_task_rejected() {
    let dir = fixture_dir();
    let root = root(&dir);
    assert!(
        advance(&root, "", "started", None)
            .unwrap_err()
            .to_string()
            .contains("task path required")
    );

    create(&root, "real", "", "").unwrap(); // makes the Tasks dir
    seed(
        &dir,
        "headless",
        "---\nstate: created\ncreated_at: X\nupdated_at: X\n---\nb\n",
    );
    assert!(
        advance(&root, "headless", "started", None)
            .unwrap_err()
            .to_string()
            .contains("not a task")
    );
}

#[test]
fn ignored_tasks_are_unreachable_and_ignored_by_numbering() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "real", "", "").unwrap(); // makes the Tasks dir → task_0001

    std::fs::write(
        notes_root(&dir).join("Tasks").join(".ignore"),
        "task_0009.md\n",
    )
    .unwrap();
    seed(&dir, "task_0009", CREATED);

    assert!(!paths(&get(&root, "", false).unwrap()).contains(&"task_0009".to_string()));
    assert!(advance(&root, "task_0009", "started", None).is_err());
    // task_0009 was seeded high so it would inflate numbering if it counted
    assert_eq!(create(&root, "b", "", "").unwrap().path(), "task_0002");
}

#[test]
fn query_scoping_body_and_hidden_closed() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "eggs", "shopping", "").unwrap();
    create(&root, "milk", "shopping", "").unwrap();
    create(&root, "resize", "dev/myapp-desktop", "the working notes").unwrap();

    assert_eq!(get(&root, "", false).unwrap().len(), 3);
    assert_eq!(get(&root, "shopping", false).unwrap().len(), 2);
    assert_eq!(
        paths(&get(&root, "dev", false).unwrap()),
        vec!["dev/myapp-desktop/task_0001"]
    );

    let exact = get(&root, "shopping/task_0001", false).unwrap();
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].front().task, "eggs");
    let with_body = get(&root, "dev/myapp-desktop/task_0001", false).unwrap();
    assert_eq!(with_body[0].body().as_str().trim(), "the working notes");
}

#[test]
fn query_hides_closed_but_exact_always_returned() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "live", "", "").unwrap();
    create(&root, "done", "", "").unwrap();
    advance(&root, "task_0002", "completed", Some("finished")).unwrap();

    assert_eq!(paths(&get(&root, "", false).unwrap()), vec!["task_0001"]);
    assert_eq!(get(&root, "", true).unwrap().len(), 2);
    assert_eq!(
        get(&root, "task_0002", false).unwrap()[0].front().state,
        TaskState::Completed
    );
}

#[test]
fn query_newest_updated_first() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "first", "", "").unwrap();
    create(&root, "second", "", "").unwrap();
    advance(&root, "task_0001", "started", None).unwrap(); // bumps updated_at
    assert_eq!(
        paths(&get(&root, "", false).unwrap()),
        vec!["task_0001", "task_0002"]
    );
}

#[test]
fn query_sorts_by_instant_not_string_across_offsets() {
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
        paths(&get(&root, "", false).unwrap()),
        vec!["later", "earlier"]
    );
}

#[test]
fn query_tiebreaks_equal_timestamps_case_insensitively() {
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
        paths(&get(&root, "", false).unwrap()),
        vec!["apple", "Banana", "Cherry"]
    );
}

#[test]
fn create_stamps_local_offset_timestamp() {
    let dir = fixture_dir();
    let root = root(&dir);
    let made = create(&root, "t", "", "").unwrap();
    let created = made.front().created_at.as_str().to_string();
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

#[test]
fn update_preserves_created_bumps_updated_and_rewords() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "old wording", "", "").unwrap();
    let before = get(&root, "task_0001", false).unwrap();
    let before = before[0].front().clone();

    let after = advance(&root, "task_0001", "started", None).unwrap();
    assert_eq!(after.front().state, TaskState::Started);
    assert_eq!(after.front().created_at, before.created_at);
    assert!(after.front().updated_at.as_str() >= before.updated_at.as_str());

    root.task_update(
        &tr("task_0001"),
        &TaskChange {
            state: None,
            notes: Some("new notes".into()),
            task: Some(tt("new wording")),
        },
    )
    .unwrap();
    let reread = get(&root, "task_0001", false).unwrap();
    assert_eq!(reread[0].front().task, "new wording");
    assert_eq!(reread[0].body().as_str().trim(), "new notes");
}

#[test]
fn update_state_and_body_rules() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "t", "", "").unwrap();

    assert!(
        "bogus"
            .parse::<TaskState>()
            .unwrap_err()
            .to_string()
            .contains("unknown state")
    );
    assert!(
        advance(&root, "task_0001", "completed", None)
            .unwrap_err()
            .to_string()
            .contains("non-empty")
    );
    assert_eq!(
        advance(&root, "task_0001", "completed", Some("fixed it"))
            .unwrap()
            .front()
            .state,
        TaskState::Completed
    );
    assert_eq!(state_of(&root, "task_0001"), TaskState::Completed);
}

#[test]
fn update_missing_and_non_task_file() {
    let dir = fixture_dir();
    let root = root(&dir);
    assert!(
        advance(&root, "nope/task_0001", "started", None)
            .unwrap_err()
            .to_string()
            .contains("no task at")
    );

    create(&root, "real", "", "").unwrap();
    seed(&dir, "stray", "no frontmatter here\n");
    assert!(
        advance(&root, "stray", "started", None)
            .unwrap_err()
            .to_string()
            .contains("not a task")
    );
}

#[test]
fn move_renumbers_bumps_updated_and_removes_source() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "a", "shopping", "").unwrap();
    let before = create(&root, "keep", "dev", "").unwrap(); // dev/task_0001 forces a renumber

    let moved = root
        .task_move(&tr("shopping/task_0001"), &gp("dev"))
        .unwrap();
    assert_eq!(moved.path(), "dev/task_0002");
    assert!(moved.front().updated_at.as_str() >= before.front().updated_at.as_str());
    assert!(get(&root, "shopping", false).unwrap().is_empty());
}

#[test]
fn move_same_group_and_missing_refused() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "a", "shopping", "").unwrap();
    assert!(
        root.task_move(&tr("shopping/task_0001"), &gp("shopping"))
            .unwrap_err()
            .to_string()
            .contains("already in that group")
    );
    assert!(
        root.task_move(&tr("ghost/task_0001"), &gp("dev"))
            .unwrap_err()
            .to_string()
            .contains("no task at")
    );
}

#[test]
fn move_custom_name_preserved_and_clash_refused() {
    let dir = fixture_dir();
    let root = root(&dir);
    seed(&dir, "shopping/buy-eggs", CREATED);
    assert_eq!(
        root.task_move(&tr("shopping/buy-eggs"), &gp("dev"))
            .unwrap()
            .path(),
        "dev/buy-eggs"
    );
    seed(&dir, "other/buy-eggs", CREATED);
    seed(&dir, "dev/buy-eggs", CREATED);
    assert!(
        root.task_move(&tr("other/buy-eggs"), &gp("dev"))
            .unwrap_err()
            .to_string()
            .contains("destination exists")
    );
}

#[test]
fn tasks_subtree_is_managed() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "t", "", "").unwrap();

    assert!(
        write(&root, &note("Tasks/task_0009.md", "nope"))
            .unwrap_err()
            .to_string()
            .contains("managed")
    );
    assert!(
        root.note_delete(&rp("Tasks/task_0001.md"))
            .unwrap_err()
            .to_string()
            .contains("cannot be deleted")
    );
    assert!(
        root.note_move(&rp("Tasks/task_0001.md"), &rp("elsewhere.md"), false)
            .unwrap_err()
            .to_string()
            .contains("cannot be moved")
    );
    write(&root, &note("loose.md", "x")).unwrap();
    assert!(
        root.note_move(&rp("loose.md"), &rp("Tasks/task_0002.md"), false)
            .unwrap_err()
            .to_string()
            .contains("cannot be moved")
    );
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
#[test]
fn symlinked_task_file_is_ignored() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "real", "grp", "").unwrap();

    let outside = notes_root(&dir).join("outside.md");
    std::fs::write(&outside, CREATED).unwrap();
    let group_dir = notes_root(&dir).join("Tasks/grp");
    std::os::unix::fs::symlink(&outside, group_dir.join("task_0005.md")).unwrap();

    assert_eq!(
        paths(&get(&root, "grp", false).unwrap()),
        vec!["grp/task_0001"]
    );
    assert!(get(&root, "grp/task_0005", false).unwrap().is_empty());
    assert!(advance(&root, "grp/task_0005", "started", None).is_err());
    // the symlink was named task_0005 precisely so it would inflate numbering
    // if it counted
    assert_eq!(
        create(&root, "next", "grp", "").unwrap().path(),
        "grp/task_0002"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_group_dir_is_ignored() {
    let dir = fixture_dir();
    let root = root(&dir);
    create(&root, "real", "", "").unwrap(); // makes Tasks/

    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("task_0001.md"), CREATED).unwrap();
    std::os::unix::fs::symlink(outside.path(), notes_root(&dir).join("Tasks/escape")).unwrap();

    assert!(get(&root, "escape", false).unwrap().is_empty());
    assert_eq!(paths(&get(&root, "", true).unwrap()), vec!["task_0001"]);
}
