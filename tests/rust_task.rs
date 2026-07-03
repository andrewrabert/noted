mod common;

use common::{cores, fixture_dir, notes_root};
use noted::tasks::parse_task_file;

fn task_file(dir: &tempfile::TempDir, rel: &str) -> std::path::PathBuf {
    notes_root(dir).join("Tasks").join(format!("{rel}.md"))
}

fn seed(dir: &tempfile::TempDir, rel: &str, front: &str) {
    let path = task_file(dir, rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, front).unwrap();
}

const CREATED: &str = "---\ntask: x\nstate: created\ncreated_at: X\nupdated_at: X\n---\nb\n";

#[test]
fn create_summary_and_per_folder_numbering() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);

    let a = tasks.create(&tt("write the parser"), &gp(""), "").unwrap();
    assert_eq!(a["path"], "task_0001");
    assert_eq!(a["task"], "write the parser");
    assert_eq!(a["state"], "created");

    assert_eq!(
        tasks.create(&tt("b"), &gp(""), "").unwrap()["path"],
        "task_0002"
    );
    assert_eq!(
        tasks.create(&tt("c"), &gp("dev"), "").unwrap()["path"],
        "dev/task_0001"
    );
    assert_eq!(
        tasks.create(&tt("d"), &gp("dev"), "").unwrap()["path"],
        "dev/task_0002"
    );
}

#[test]
fn create_nested_group_auto_created_and_seeds_body() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    let s = tasks
        .create(&tt("fix resize"), &gp("dev/myapp-desktop"), "initial notes")
        .unwrap();
    assert_eq!(s["path"], "dev/myapp-desktop/task_0001");
    let body = std::fs::read_to_string(task_file(&dir, "dev/myapp-desktop/task_0001")).unwrap();
    assert!(body.contains("initial notes"));
}

#[test]
fn numbering_from_max_and_tolerates_hand_named() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    tasks.create(&tt("a"), &gp(""), "").unwrap();
    seed(&dir, "task_0005", CREATED);
    assert_eq!(
        tasks.create(&tt("b"), &gp(""), "").unwrap()["path"],
        "task_0006"
    );

    seed(&dir, "build-a-fart-machine", CREATED);
    assert_eq!(
        tasks.create(&tt("c"), &gp(""), "").unwrap()["path"],
        "task_0007"
    );
    let paths: Vec<String> = tasks
        .query("", false, true)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["path"].as_str().unwrap().to_string())
        .collect();
    assert!(paths.iter().any(|p| p == "build-a-fart-machine"));
}

#[test]
fn create_requires_task() {
    assert!(""
        .parse::<noted::tasks::TaskTitle>()
        .unwrap_err()
        .to_string()
        .contains("task is required"));
    assert!("   ".parse::<noted::tasks::TaskTitle>().is_err());
}

#[test]
fn bad_group_names_and_escapes_rejected() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    for group in ["bad name", "1foo", "a.b", "dev/bad!", "../escape"] {
        assert!(
            tasks
                .create(&tt("t"), &gp(group), "")
                .unwrap_err()
                .to_string()
                .contains("invalid name"),
            "group {group:?} should be rejected"
        );
    }
    assert!(tasks.create(&tt("t"), &gp("ok-group_2"), "").is_ok());
    assert!(tasks
        .query("../secrets", false, false)
        .unwrap_err()
        .to_string()
        .contains("invalid name"));
}

#[test]
fn empty_task_ref_and_headless_task_rejected() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    assert!(tasks
        .update(&rp(""), None, None, None)
        .unwrap_err()
        .to_string()
        .contains("task path required"));

    tasks.create(&tt("real"), &gp(""), "").unwrap(); // makes the Tasks dir
    seed(
        &dir,
        "headless",
        "---\nstate: created\ncreated_at: X\nupdated_at: X\n---\nb\n",
    );
    assert!(tasks
        .update(&rp("headless"), Some(ts("started")), None, None)
        .unwrap_err()
        .to_string()
        .contains("not a task"));
}

#[test]
fn ignored_tasks_are_unreachable_and_ignored_by_numbering() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    tasks.create(&tt("real"), &gp(""), "").unwrap(); // makes the Tasks dir → task_0001

    std::fs::write(
        notes_root(&dir).join("Tasks").join(".ignore"),
        "task_0009.md\n",
    )
    .unwrap();
    seed(&dir, "task_0009", CREATED);

    assert!(!paths(&tasks.query("", false, false).unwrap()).contains(&"task_0009".to_string()));
    assert!(tasks
        .update(&rp("task_0009"), Some(ts("started")), None, None)
        .is_err());
    // task_0009 was seeded high so it would inflate numbering if it counted
    assert_eq!(
        tasks.create(&tt("b"), &gp(""), "").unwrap()["path"],
        "task_0002"
    );
}

fn paths(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|r| r["path"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn query_scoping_body_and_hidden_closed() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    tasks.create(&tt("eggs"), &gp("shopping"), "").unwrap();
    tasks.create(&tt("milk"), &gp("shopping"), "").unwrap();
    tasks
        .create(&tt("resize"), &gp("dev/myapp-desktop"), "the working notes")
        .unwrap();

    assert_eq!(
        tasks
            .query("", false, false)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let shopping = paths(&tasks.query("shopping", false, false).unwrap());
    assert_eq!(shopping.len(), 2);
    assert_eq!(
        paths(&tasks.query("dev", false, false).unwrap()),
        vec!["dev/myapp-desktop/task_0001"]
    );

    let exact = tasks.query("shopping/task_0001", false, false).unwrap();
    assert_eq!(exact.as_array().unwrap().len(), 1);
    assert_eq!(exact[0]["task"], "eggs");
    assert!(exact[0].get("body").is_none());
    let with_body = tasks
        .query("dev/myapp-desktop/task_0001", true, false)
        .unwrap();
    assert_eq!(
        with_body[0]["body"].as_str().unwrap().trim(),
        "the working notes"
    );
}

#[test]
fn query_hides_closed_but_exact_always_returned() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    tasks.create(&tt("live"), &gp(""), "").unwrap();
    tasks.create(&tt("done"), &gp(""), "").unwrap();
    tasks
        .update(
            &rp("task_0002"),
            Some(ts("completed")),
            Some("finished"),
            None,
        )
        .unwrap();

    assert_eq!(
        paths(&tasks.query("", false, false).unwrap()),
        vec!["task_0001"]
    );
    assert_eq!(
        tasks
            .query("", false, true)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        tasks.query("task_0002", false, false).unwrap()[0]["state"],
        "completed"
    );
}

#[test]
fn query_newest_updated_first() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    tasks.create(&tt("first"), &gp(""), "").unwrap();
    tasks.create(&tt("second"), &gp(""), "").unwrap();
    tasks
        .update(&rp("task_0001"), Some(ts("started")), None, None)
        .unwrap(); // bumps updated_at
    assert_eq!(
        paths(&tasks.query("", false, false).unwrap()),
        vec!["task_0001", "task_0002"]
    );
}

#[test]
fn query_sorts_by_instant_not_string_across_offsets() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
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
        paths(&tasks.query("", false, false).unwrap()),
        vec!["later", "earlier"]
    );
}

#[test]
fn query_tiebreaks_equal_timestamps_case_insensitively() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
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
        paths(&tasks.query("", false, false).unwrap()),
        vec!["apple", "Banana", "Cherry"]
    );
}

#[test]
fn create_stamps_local_offset_timestamp() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    let made = tasks.create(&tt("t"), &gp(""), "").unwrap();
    let created = made["created_at"].as_str().unwrap();
    assert!(
        chrono::DateTime::parse_from_rfc3339(created).is_ok(),
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
    let (_, tasks) = cores(&dir);
    tasks.create(&tt("old wording"), &gp(""), "").unwrap();
    let before = tasks.query("task_0001", false, false).unwrap()[0].clone();

    let after = tasks
        .update(&rp("task_0001"), Some(ts("started")), None, None)
        .unwrap();
    assert_eq!(after["state"], "started");
    assert_eq!(after["created_at"], before["created_at"]);
    assert!(after["updated_at"].as_str().unwrap() >= before["updated_at"].as_str().unwrap());

    tasks
        .update(
            &rp("task_0001"),
            None,
            Some("new notes"),
            Some(&tt("new wording")),
        )
        .unwrap();
    let front = tasks.query("task_0001", true, false).unwrap()[0].clone();
    assert_eq!(front["task"], "new wording");
    assert_eq!(front["body"].as_str().unwrap().trim(), "new notes");
}

#[test]
fn update_state_and_body_rules() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    tasks.create(&tt("t"), &gp(""), "").unwrap();

    // Unknown states are now unrepresentable in the core: rejection happens when
    // the string is parsed into a `TaskState` (CLI/HTTP boundary).
    assert!("bogus"
        .parse::<noted::tasks::TaskState>()
        .unwrap_err()
        .to_string()
        .contains("unknown state"));
    assert!(tasks
        .update(&rp("task_0001"), Some(ts("completed")), None, None)
        .unwrap_err()
        .to_string()
        .contains("non-empty"));
    assert_eq!(
        tasks
            .update(
                &rp("task_0001"),
                Some(ts("completed")),
                Some("fixed it"),
                None
            )
            .unwrap()["state"],
        "completed"
    );
}

#[test]
fn update_missing_and_non_task_file() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    assert!(tasks
        .update(&rp("nope/task_0001"), Some(ts("started")), None, None)
        .unwrap_err()
        .to_string()
        .contains("no task at"));

    tasks.create(&tt("real"), &gp(""), "").unwrap();
    seed(&dir, "stray", "no frontmatter here\n");
    assert!(tasks
        .update(&rp("stray"), Some(ts("started")), None, None)
        .unwrap_err()
        .to_string()
        .contains("not a task"));
}

#[test]
fn move_renumbers_bumps_updated_and_removes_source() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    tasks.create(&tt("a"), &gp("shopping"), "").unwrap();
    let before = tasks.create(&tt("keep"), &gp("dev"), "").unwrap(); // dev/task_0001 forces a renumber

    let moved = tasks
        .move_task(&rp("shopping/task_0001"), &gp("dev"))
        .unwrap();
    assert_eq!(moved["path"], "dev/task_0002");
    assert!(moved["updated_at"].as_str().unwrap() >= before["updated_at"].as_str().unwrap());
    assert!(tasks
        .query("shopping", false, false)
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn move_same_group_and_missing_refused() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    tasks.create(&tt("a"), &gp("shopping"), "").unwrap();
    assert!(tasks
        .move_task(&rp("shopping/task_0001"), &gp("shopping"))
        .unwrap_err()
        .to_string()
        .contains("already in that group"));
    assert!(tasks
        .move_task(&rp("ghost/task_0001"), &gp("dev"))
        .unwrap_err()
        .to_string()
        .contains("no task at"));
}

#[test]
fn move_custom_name_preserved_and_clash_refused() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    seed(&dir, "shopping/buy-eggs", CREATED);
    assert_eq!(
        tasks
            .move_task(&rp("shopping/buy-eggs"), &gp("dev"))
            .unwrap()["path"],
        "dev/buy-eggs"
    );
    seed(&dir, "other/buy-eggs", CREATED);
    seed(&dir, "dev/buy-eggs", CREATED);
    assert!(tasks
        .move_task(&rp("other/buy-eggs"), &gp("dev"))
        .unwrap_err()
        .to_string()
        .contains("destination exists"));
}

#[test]
fn tasks_subtree_is_managed() {
    let dir = fixture_dir();
    let (notes, tasks) = cores(&dir);
    tasks.create(&tt("t"), &gp(""), "").unwrap();

    assert!(notes
        .write(&rp("Tasks/task_0009.md"), "nope")
        .unwrap_err()
        .to_string()
        .contains("managed"));
    assert!(notes
        .delete(&rp("Tasks/task_0001.md"))
        .unwrap_err()
        .to_string()
        .contains("cannot be deleted"));
    assert!(notes
        .move_note(&rp("Tasks/task_0001.md"), &rp("elsewhere.md"), false)
        .unwrap_err()
        .to_string()
        .contains("cannot be moved"));
    notes.write(&rp("loose.md"), "x").unwrap();
    assert!(notes
        .move_note(&rp("loose.md"), &rp("Tasks/task_0002.md"), false)
        .unwrap_err()
        .to_string()
        .contains("cannot be moved"));
}

#[test]
fn parse_task_file_edges() {
    let (front, body) = parse_task_file("---\nnever closes\n");
    assert!(front.is_none());
    assert_eq!(body, "---\nnever closes\n");

    assert!(parse_task_file("---\nfoo: [unclosed\n---\nbody\n")
        .0
        .is_none());
    assert!(parse_task_file("---\njust a scalar\n---\nbody\n")
        .0
        .is_none());

    let (front, body) = parse_task_file(CREATED);
    let front = front.unwrap();
    assert_eq!(front.task, "x");
    assert_eq!(body, "b\n");
}

#[cfg(unix)]
#[test]
fn symlinked_task_file_is_ignored() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    tasks.create(&tt("real"), &gp("grp"), "").unwrap();

    let outside = notes_root(&dir).join("outside.md");
    std::fs::write(&outside, CREATED).unwrap();
    let group_dir = notes_root(&dir).join("Tasks/grp");
    std::os::unix::fs::symlink(&outside, group_dir.join("task_0005.md")).unwrap();

    let listed = paths(&tasks.query("grp", false, false).unwrap());
    assert_eq!(listed, vec!["grp/task_0001"]);
    assert!(tasks
        .query("grp/task_0005", false, false)
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    assert!(tasks
        .update(&rp("grp/task_0005"), Some(ts("started")), None, None)
        .is_err());
    // the symlink was named task_0005 precisely so it would inflate numbering
    // if it counted
    assert_eq!(
        tasks.create(&tt("next"), &gp("grp"), "").unwrap()["path"],
        "grp/task_0002"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_group_dir_is_ignored() {
    let dir = fixture_dir();
    let (_, tasks) = cores(&dir);
    tasks.create(&tt("real"), &gp(""), "").unwrap(); // makes Tasks/

    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("task_0001.md"), CREATED).unwrap();
    std::os::unix::fs::symlink(outside.path(), notes_root(&dir).join("Tasks/escape")).unwrap();

    assert!(tasks
        .query("escape", false, false)
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        paths(&tasks.query("", false, true).unwrap()),
        vec!["task_0001"]
    );
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
