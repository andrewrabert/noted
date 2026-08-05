mod common;

use common::{fixture_dir, found, grep, note, notes_root, query, read, root, rp, write};
use noted::search::SearchMode;
use noted::tasks::{TaskQuery, TaskSearch};

// a '!' rule resolves the same through a search, a listing and a direct read
#[tokio::test]
async fn a_whitelist_resolves_the_same_everywhere() {
    let dir = fixture_dir();
    let root = root(&dir);
    let notes = notes_root(&dir);

    std::fs::write(notes.join(".ignore"), "wip-*.md\n!wip-keep.md\n").unwrap();
    std::fs::write(notes.join("wip-x.md"), "TOPSECRET token").unwrap();
    std::fs::write(notes.join("wip-keep.md"), "TOPSECRET token").unwrap();
    std::fs::write(notes.join("visible.md"), "TOPSECRET token").unwrap();

    let hits: Vec<String> = grep(&root, "TOPSECRET")
        .await
        .unwrap()
        .iter()
        .map(|h| h.path.to_string())
        .collect();
    assert!(hits.contains(&"visible.md".to_string()));
    assert!(hits.contains(&"wip-keep.md".to_string()));
    assert!(!hits.contains(&"wip-x.md".to_string()));

    assert_eq!(found(&root, "wip").await.unwrap(), vec!["wip-keep.md"]);

    assert!(read(&root, "wip-keep.md").await.is_ok());
    assert!(read(&root, "visible.md").await.is_ok());
    assert!(read(&root, "wip-x.md").await.is_err());
}

// '.ignore' in a directory outranks '.gitignore' in that same directory
#[tokio::test]
async fn a_dot_ignore_rule_outranks_a_gitignore_rule() {
    let dir = fixture_dir();
    let root = root(&dir);
    let notes = notes_root(&dir);

    std::fs::write(notes.join(".gitignore"), "contested.md\n").unwrap();
    std::fs::write(notes.join(".ignore"), "!contested.md\n").unwrap();
    std::fs::write(notes.join("contested.md"), "NEEDLE").unwrap();

    let hits: Vec<String> = grep(&root, "NEEDLE")
        .await
        .unwrap()
        .iter()
        .map(|h| h.path.to_string())
        .collect();
    assert!(hits.contains(&"contested.md".to_string()));
    assert!(read(&root, "contested.md").await.is_ok());
}

// '.ignore' at the notes root outranks a '!' rule in a nested '.gitignore'
#[tokio::test]
async fn a_higher_dot_ignore_outranks_a_deeper_gitignore_whitelist() {
    let dir = fixture_dir();
    let root = root(&dir);
    let notes = notes_root(&dir);

    std::fs::write(notes.join(".ignore"), "*.log\n").unwrap();
    std::fs::create_dir(notes.join("area")).unwrap();
    std::fs::write(notes.join("area/.gitignore"), "!keep.log\n").unwrap();
    std::fs::write(notes.join("area/keep.log"), "NEEDLE").unwrap();
    std::fs::write(notes.join("area/ok.md"), "NEEDLE").unwrap();

    let hits: Vec<String> = grep(&root, "NEEDLE")
        .await
        .unwrap()
        .iter()
        .map(|h| h.path.to_string())
        .collect();
    assert!(hits.contains(&"area/ok.md".to_string()));
    assert!(!hits.contains(&"area/keep.log".to_string()));
    assert!(read(&root, "area/keep.log").await.is_err());
}

// a rule at the notes root hides a task from both task_search and task_get,
// though the Tasks region search starts below the notes root
#[tokio::test]
async fn an_ancestor_rule_reaches_a_region_search() {
    let dir = fixture_dir();
    let root = root(&dir);
    let notes = notes_root(&dir);

    let task = root
        .task_create(
            &"a hidden chore".parse().unwrap(),
            &"".parse().unwrap(),
            &"NEEDLE".into(),
        )
        .await
        .unwrap();
    let rel = task.path().to_string();
    std::fs::write(
        notes.join(".ignore"),
        format!("Tasks/{rel}.md\nTasks/{rel}/\n"),
    )
    .unwrap();

    let found = root
        .task_search(&TaskSearch {
            prefix: "".parse().unwrap(),
            include_completed: true,
            query: query("NEEDLE", SearchMode::Line),
        })
        .await
        .unwrap();
    assert!(found.is_empty(), "{found:?}");

    let listed = root
        .task_get(&TaskQuery {
            prefix: "".parse().unwrap(),
            include_completed: true,
        })
        .await
        .unwrap();
    assert!(listed.is_empty(), "{listed:?}");
}

// an ignored path is refused for read, write, move and delete
#[tokio::test]
async fn an_ignored_path_is_unaddressable() {
    let dir = fixture_dir();
    let root = root(&dir);
    let notes = notes_root(&dir);

    std::fs::write(notes.join(".ignore"), "hidden-note.md\ndrafts/\n").unwrap();
    std::fs::write(notes.join("hidden-note.md"), "x").unwrap();
    std::fs::create_dir(notes.join("drafts")).unwrap();
    std::fs::write(notes.join("drafts/note.md"), "x").unwrap();

    let err = read(&root, "hidden-note.md").await.unwrap_err().to_string();
    assert!(err.contains("invalid path"), "{err}");

    for rel in ["hidden-note.md", "drafts/note.md"] {
        assert!(read(&root, rel).await.is_err(), "read {rel} should reject");
        assert!(
            write(&root, &note(rel, "x")).await.is_err(),
            "write {rel} should reject"
        );
        assert!(
            root.note_delete(&rp(rel)).await.is_err(),
            "delete {rel} should reject"
        );
        assert!(
            root.note_move(&rp(rel), &rp("moved.md"), false)
                .await
                .is_err(),
            "move {rel} should reject"
        );
    }
    assert!(write(&root, &note("drafts/new.md", "x")).await.is_err());
}

// a rule written after the root was opened takes effect on the next operation
#[tokio::test]
async fn a_new_rule_needs_no_reopen() {
    let dir = fixture_dir();
    let root = root(&dir);
    let notes = notes_root(&dir);

    std::fs::write(notes.join("later.md"), "NEEDLE").unwrap();
    assert!(read(&root, "later.md").await.is_ok());
    assert!(
        grep(&root, "NEEDLE")
            .await
            .unwrap()
            .iter()
            .any(|h| h.path == rp("later.md"))
    );

    std::fs::write(notes.join(".ignore"), "later.md\n").unwrap();

    assert!(read(&root, "later.md").await.is_err());
    assert!(
        !grep(&root, "NEEDLE")
            .await
            .unwrap()
            .iter()
            .any(|h| h.path == rp("later.md"))
    );
}

// '.gitignore' rules apply in a tree that holds no '.git'
#[tokio::test]
async fn gitignore_rules_do_not_need_a_repository() {
    let dir = fixture_dir();
    let root = root(&dir);
    let notes = notes_root(&dir);

    assert!(!notes.join(".git").exists());
    std::fs::write(notes.join(".gitignore"), "drafts/\n").unwrap();
    std::fs::create_dir(notes.join("drafts")).unwrap();
    std::fs::write(notes.join("drafts/note.md"), "NEEDLE").unwrap();
    std::fs::write(notes.join("visible.md"), "NEEDLE").unwrap();

    let hits: Vec<String> = grep(&root, "NEEDLE")
        .await
        .unwrap()
        .iter()
        .map(|h| h.path.to_string())
        .collect();
    assert!(hits.contains(&"visible.md".to_string()));
    assert!(!hits.contains(&"drafts/note.md".to_string()));
    assert!(read(&root, "drafts/note.md").await.is_err());
}
