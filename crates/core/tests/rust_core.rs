mod common;

use common::{
    backend, fixture_dir, found, grep, invoke, note, notes_root, query, read, root, rp, write,
};
use noted::note::{Condition, Etag, Note};
use noted::search::{CaseMode, SearchMode, SearchQuery};
use noted::util::{atomic_write, slice_lines};
use serde_json::json;

#[test]
fn read_edge_cases() {
    let dir = fixture_dir();
    let root = root(&dir);
    assert!(matches!(
        read(&root, "nope.md").unwrap_err(),
        noted::NotedError::NotFound
    ));

    std::fs::write(notes_root(&dir).join("bad.md"), [0xff, 0xfe, 0x00]).unwrap();
    assert!(
        read(&root, "bad.md")
            .unwrap_err()
            .to_string()
            .contains("utf-8")
    );
}

#[test]
fn write_creates_parents_and_leaves_no_temp() {
    let dir = fixture_dir();
    let root = root(&dir);
    write(&root, &note("deep/nested/new.md", "hello\n")).unwrap();
    assert_eq!(read(&root, "deep/nested/new.md").unwrap(), "hello\n");

    write(&root, &note("a.md", "x")).unwrap();
    let leftovers: Vec<_> = std::fs::read_dir(notes_root(&dir))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".noted-tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "atomic_write left a temp file");
}

#[test]
fn the_log_region_is_unreachable_through_the_note_tools() {
    let dir = fixture_dir();
    let root = root(&dir);
    let entry = "Log/2026-07-01T09-00-00.000000-0700.md";
    for err in [
        write(&root, &note(entry, "nope")).unwrap_err(),
        root.note_delete(&rp(entry)).unwrap_err(),
        root.note_move(&rp(entry), &rp("moved.md"), false)
            .unwrap_err(),
    ] {
        assert!(
            matches!(err, noted::NotedError::Forbidden),
            "expected a policy refusal, got {err}"
        );
    }
}

#[test]
fn log_note_writes_one_file_with_front_matter() {
    let dir = fixture_dir();
    let root = root(&dir);
    let logged = root.log_note(&"did a thing\n-- t · s".into()).unwrap();
    let rel = logged.path().to_string();
    assert!(rel.starts_with("20"), "{rel}");
    let on_disk = std::fs::read_to_string(notes_root(&dir).join("Log").join(&rel)).unwrap();
    let text = String::from_utf8(logged.to_bytes().unwrap()).unwrap();
    assert_eq!(text, on_disk);
    assert_eq!(logged.etag().unwrap(), note(&rel, &on_disk).etag());

    assert!(text.starts_with("---\n"));
    assert!(text.ends_with('\n'));
    for key in ["created", "cwd", "host", "source"] {
        assert!(text.contains(key), "front matter missing {key}");
    }
    assert!(text.contains("source: test"));
    assert!(text.contains("did a thing"));

    let entry = notes_root(&dir).join("Log").join(&rel);
    let mut written: Vec<String> = std::fs::read_dir(entry.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    written.sort();
    assert_eq!(
        written,
        vec![
            "2026-06-15T08-30-00.000000-0700.md".to_string(),
            "2026-07-01T09-00-00.000000-0700.md".to_string(),
            rel.clone(),
        ],
        "the entry lands flat beside the others, leaving no temp file"
    );
}

#[test]
fn log_note_records_no_source_when_the_caller_has_none() {
    let dir = fixture_dir();
    let root = noted::NotedRoot::open(noted::store::NotedDir::new(notes_root(&dir)), None).unwrap();
    let logged = root.log_note(&"anonymous\n".into()).unwrap();
    let text = String::from_utf8(logged.to_bytes().unwrap()).unwrap();
    assert!(!text.contains("source:"), "{text}");
}

#[test]
fn delete_moves_to_trash_and_uniquifies() {
    let dir = fixture_dir();
    let root = root(&dir);

    let original = read(&root, "Inbox.md").unwrap();
    let trashed = root.note_delete(&rp("Inbox.md")).unwrap();
    assert_eq!(trashed.path().to_string(), "Inbox.md");
    assert!(read(&root, "Inbox.md").is_err());
    assert_eq!(
        std::fs::read_to_string(notes_root(&dir).join(".trash").join("Inbox.md")).unwrap(),
        original
    );

    // .trash/old-idea.md already exists in the fixture → a same-named delete
    // must uniquify rather than clobber it.
    write(&root, &note("old-idea.md", "different\n")).unwrap();
    let uniq = root.note_delete(&rp("old-idea.md")).unwrap();
    assert_eq!(uniq.path().to_string(), "old-idea.md");
    assert_eq!(
        std::fs::read_to_string(notes_root(&dir).join(".trash").join("old-idea 1.md")).unwrap(),
        "different\n"
    );

    assert!(matches!(
        root.note_delete(&rp("ghost.md")).unwrap_err(),
        noted::NotedError::NotFound
    ));
}

#[test]
fn move_semantics() {
    let dir = fixture_dir();
    let root = root(&dir);

    let body = read(&root, "Inbox.md").unwrap();
    root.note_move(&rp("Inbox.md"), &rp("Inbox2.md"), false)
        .unwrap();
    assert_eq!(read(&root, "Inbox2.md").unwrap(), body);

    assert!(matches!(
        root.note_move(&rp("Inbox2.md"), &rp("projects/ideas.md"), false)
            .unwrap_err(),
        noted::NotedError::Conflict
    ));
    root.note_move(&rp("Inbox2.md"), &rp("projects/ideas.md"), true)
        .unwrap();
    assert_eq!(read(&root, "projects/ideas.md").unwrap(), body);

    assert!(matches!(
        root.note_move(&rp("ghost.md"), &rp("d.md"), false)
            .unwrap_err(),
        noted::NotedError::NotFound
    ));
    assert!(
        root.note_move(&rp("daily"), &rp("daily"), false)
            .unwrap_err()
            .to_string()
            .contains("same")
    );
    assert!(
        root.note_move(&rp("projects"), &rp("projects/sub"), false)
            .unwrap_err()
            .to_string()
            .contains("into itself")
    );
}

#[test]
fn move_onto_nonempty_folder_is_rejected() {
    let dir = fixture_dir();
    let root = root(&dir);
    write(&root, &note("srcd/a.md", "a")).unwrap();
    write(&root, &note("dstd/b.md", "b")).unwrap();
    assert!(
        root.note_move(&rp("srcd"), &rp("dstd"), true)
            .unwrap_err()
            .to_string()
            .contains("non-empty folder")
    );
}

#[tokio::test]
async fn note_search_walks_the_open_region_only() {
    let dir = fixture_dir();
    let root = root(&dir);

    // FROBNICATE appears only in the fixture's trashed note
    assert!(grep(&root, "FROBNICATE").await.unwrap().is_empty());

    // testhost appears only in the fixture's log entries
    assert!(grep(&root, "testhost").await.unwrap().is_empty());
    assert!(found(&root, "Log").await.unwrap().is_empty());

    root.task_create(
        &"reserved from notes".parse().unwrap(),
        &Default::default(),
        &"UNIQUETASKBODY\n".into(),
    )
    .unwrap();
    assert!(grep(&root, "UNIQUETASKBODY").await.unwrap().is_empty());
    assert!(found(&root, "Tasks").await.unwrap().is_empty());

    let contacts = found(&root, "contacts").await.unwrap();
    assert!(contacts.iter().any(|p| p == "people/contacts.md"));
    // old-idea.md exists only under the fixture's .trash/
    assert!(found(&root, "old-idea").await.unwrap().is_empty());
}

#[tokio::test]
async fn ignore_files_hide_paths_everywhere() {
    let dir = fixture_dir();
    let root = root(&dir);
    let notes = notes_root(&dir);

    std::fs::write(notes.join(".ignore"), "wip-*.md\n!wip-keep.md\n").unwrap();
    std::fs::write(notes.join(".gitignore"), "drafts/\n").unwrap();
    std::fs::write(notes.join("wip-x.md"), "TOPSECRET token").unwrap();
    std::fs::write(notes.join("wip-keep.md"), "TOPSECRET token").unwrap();
    std::fs::create_dir(notes.join("drafts")).unwrap();
    std::fs::write(notes.join("drafts/note.md"), "TOPSECRET token").unwrap();
    std::fs::write(notes.join("visible.md"), "TOPSECRET token").unwrap();

    let hits = grep(&root, "TOPSECRET").await.unwrap();
    let rels: Vec<String> = hits.iter().map(|h| h.path.to_string()).collect();
    let rels: Vec<&str> = rels.iter().map(String::as_str).collect();
    assert!(rels.contains(&"visible.md"));
    assert!(rels.contains(&"wip-keep.md"));
    assert!(!rels.contains(&"wip-x.md"));
    assert!(!rels.contains(&"drafts/note.md"));

    assert_eq!(found(&root, "wip").await.unwrap(), vec!["wip-keep.md"]);

    for rel in ["wip-x.md", "drafts/note.md"] {
        assert!(read(&root, rel).is_err(), "read {rel} should reject");
        assert!(
            write(&root, &note(rel, "x")).is_err(),
            "write {rel} should reject"
        );
        assert!(
            root.note_delete(&rp(rel)).is_err(),
            "delete {rel} should reject"
        );
        assert!(
            root.note_move(&rp(rel), &rp("moved.md"), false).is_err(),
            "move {rel} should reject"
        );
    }

    assert!(read(&root, "wip-keep.md").is_ok());
    assert!(read(&root, "visible.md").is_ok());
    assert!(write(&root, &note("drafts/new.md", "x")).is_err());
}

#[tokio::test]
async fn search_orders_paths_case_insensitively() {
    let dir = fixture_dir();
    let bknd = backend(&dir);
    let notes = notes_root(&dir);
    for name in ["apple.md", "Banana.md", "cherry.md", "Foo.md", "foo.md"] {
        std::fs::write(notes.join(name), "needle\n").unwrap();
    }
    let want = ["apple.md", "Banana.md", "cherry.md", "Foo.md", "foo.md"];

    for mode in ["path", "file"] {
        let pattern = if mode == "path" { "." } else { "needle" };
        let out = invoke(
            &bknd,
            "SearchNotes",
            json!({"pattern": pattern, "mode": mode}),
        )
        .await
        .unwrap();
        let out = out.render();
        let got: Vec<&str> = out.lines().filter(|l| !l.contains('/')).collect();
        for name in want {
            assert!(got.contains(&name), "{mode}: missing {name} in {got:?}");
        }
        let idx = |n: &str| got.iter().position(|g| *g == n).unwrap();
        assert!(idx("apple.md") < idx("Banana.md"), "{mode}: {got:?}");
        assert!(idx("Banana.md") < idx("cherry.md"), "{mode}: {got:?}");
    }
}

#[tokio::test]
async fn walk_and_direct_access_agree_on_nested_ignores() {
    let dir = fixture_dir();
    let root = root(&dir);
    let notes = notes_root(&dir);

    std::fs::write(notes.join(".gitignore"), "*.log\n").unwrap();
    std::fs::create_dir(notes.join("area")).unwrap();
    std::fs::write(notes.join("area/.gitignore"), "!keep.log\ndrop.md\n").unwrap();
    let files = [
        "top.log",
        "area/keep.log",
        "area/other.log",
        "area/drop.md",
        "area/ok.md",
    ];
    for f in files {
        std::fs::write(notes.join(f), "NEEDLE").unwrap();
    }

    let hits = grep(&root, "NEEDLE").await.unwrap();
    let hit: std::collections::HashSet<String> = hits.iter().map(|h| h.path.to_string()).collect();
    for f in files {
        assert_eq!(
            hit.contains(f),
            read(&root, f).is_ok(),
            "walk/read disagree on {f}"
        );
    }
    assert!(hit.contains("area/keep.log"));
    assert!(hit.contains("area/ok.md"));
    assert!(!hit.contains("top.log"));
    assert!(!hit.contains("area/other.log"));
    assert!(!hit.contains("area/drop.md"));
}

#[tokio::test]
async fn search_pattern_and_glob_edges() {
    let dir = fixture_dir();
    let root = root(&dir);

    assert!("".parse::<noted::search::SearchPattern>().is_err());
    assert!("/abs".parse::<noted::search::GlobPattern>().is_err());
    assert!("../up".parse::<noted::search::GlobPattern>().is_err());

    assert!(grep(&root, "NOSUCHTOKEN_ZZZ").await.unwrap().is_empty());

    assert!(grep(&root, "(").await.is_err());
    assert!(found(&root, "(").await.is_err());

    std::fs::create_dir(notes_root(&dir).join("emptydir")).unwrap();
    let scoped = |glob: &str, pattern: &str| SearchQuery {
        globs: vec![glob.parse().unwrap()],
        ..query(pattern, SearchMode::Path)
    };
    assert!(
        root.note_search(&scoped("emptydir", "x"))
            .await
            .unwrap()
            .is_empty()
    );
    let hits = root
        .note_search(&scoped("Inbox.md", "Inbox"))
        .await
        .unwrap();
    assert!(hits.iter().any(|h| h.path == "Inbox.md"));
}

#[tokio::test]
async fn search_feature_flags() {
    let dir = fixture_dir();
    let root = root(&dir);

    std::fs::write(notes_root(&dir).join("lit.md"), "a.b\naxb\n").unwrap();
    let lines = |hits: &[noted::search::Hit]| -> usize {
        hits.iter()
            .filter(|h| h.path == "lit.md")
            .map(|h| h.lines.len())
            .sum()
    };
    assert_eq!(lines(&grep(&root, "a.b").await.unwrap()), 2);
    let fixed = SearchQuery {
        fixed: true,
        ..query("a.b", SearchMode::Line)
    };
    assert_eq!(lines(&root.note_search(&fixed).await.unwrap()), 1);

    let word = SearchQuery {
        word: true,
        ..query("Inbo", SearchMode::Line)
    };
    assert!(root.note_search(&word).await.unwrap().is_empty());

    std::fs::write(notes_root(&dir).join("case.md"), "Hello\n").unwrap();
    let sensitive = SearchQuery {
        case: CaseMode::Sensitive,
        ..query("HELLO", SearchMode::Line)
    };
    assert!(root.note_search(&sensitive).await.unwrap().is_empty());
    let insensitive = SearchQuery {
        case: CaseMode::Insensitive,
        ..query("HELLO", SearchMode::Line)
    };
    assert!(!root.note_search(&insensitive).await.unwrap().is_empty());

    let excluded = SearchQuery {
        globs: vec!["!people/**".parse().unwrap()],
        ..query(".", SearchMode::Path)
    };
    let paths = root.note_search(&excluded).await.unwrap();
    assert!(
        !paths
            .iter()
            .any(|h| h.path.to_string().starts_with("people/"))
    );
    assert!(paths.iter().any(|h| h.path == "Inbox.md"));

    let markdown = SearchQuery {
        types: vec!["md".parse().unwrap()],
        ..query(".", SearchMode::Path)
    };
    let md_paths = root.note_search(&markdown).await.unwrap();
    assert!(md_paths.iter().any(|h| h.path == "Inbox.md"));
}

#[test]
fn slice_lines_windows() {
    let text = "l1\nl2\nl3\nl4";
    assert_eq!(slice_lines(text, None, None), text);
    assert_eq!(slice_lines(text, Some(2), Some(1)), "l2");
    assert_eq!(slice_lines(text, Some(3), None), "l3\nl4");
    assert_eq!(slice_lines(text, Some(99), Some(5)), "");
}

#[test]
fn atomic_write_replaces_in_place() {
    let dir = fixture_dir();
    let target = notes_root(&dir).join("nested/atomic.md");
    atomic_write(&target, "first".as_bytes()).unwrap();
    atomic_write(&target, "second".as_bytes()).unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "second");
}

#[test]
fn matching_condition_is_a_compare_and_swap() {
    let dir = fixture_dir();
    let root = root(&dir);
    let original = note("cw.md", "one");
    write(&root, &original).unwrap();

    let updated = original.clone().with_body("two");
    root.note_write(&updated, Condition::Matching(original.etag()))
        .unwrap();
    assert_eq!(read(&root, "cw.md").unwrap(), "two");

    let stale = original.clone().with_body("three");
    let err = root
        .note_write(&stale, Condition::Matching(original.etag()))
        .unwrap_err();
    assert!(matches!(err, noted::error::NotedError::Conflict));
    assert_eq!(read(&root, "cw.md").unwrap(), "two");

    root.note_write(
        &note("cw.md", "four"),
        Condition::Matching(note("cw.md", "two").etag()),
    )
    .unwrap();
    assert_eq!(read(&root, "cw.md").unwrap(), "four");
}

#[test]
fn create_and_replace_conditions() {
    let dir = fixture_dir();
    let root = root(&dir);

    root.note_write(&note("m.md", "hi"), Condition::Missing)
        .unwrap();
    assert!(matches!(
        root.note_write(&note("m.md", "again"), Condition::Missing)
            .unwrap_err(),
        noted::error::NotedError::Conflict
    ));

    root.note_write(&note("m.md", "edited"), Condition::Exists)
        .unwrap();
    assert!(matches!(
        root.note_write(&note("absent.md", "x"), Condition::Exists)
            .unwrap_err(),
        noted::error::NotedError::NotFound
    ));
}

#[test]
fn conflict_message_never_mentions_sha256() {
    let dir = fixture_dir();
    let root = root(&dir);
    write(&root, &note("c.md", "v1")).unwrap();
    let err = root
        .note_write(
            &note("c.md", "v2"),
            Condition::Matching(note("c.md", "other").etag()),
        )
        .unwrap_err();
    assert!(!err.to_string().to_lowercase().contains("sha256"));
}

#[test]
fn edit_replaces_and_refuses_ambiguity() {
    let dir = fixture_dir();
    let root = root(&dir);
    write(&root, &note("e.md", "one two one\n")).unwrap();

    assert!(
        root.note_edit(&rp("e.md"), &noted::note::Edit::new("one", "1", false))
            .unwrap_err()
            .to_string()
            .contains("not unique")
    );
    assert!(
        root.note_edit(&rp("e.md"), &noted::note::Edit::new("zzz", "1", false))
            .unwrap_err()
            .to_string()
            .contains("not found")
    );
    root.note_edit(&rp("e.md"), &noted::note::Edit::new("one", "1", true))
        .unwrap();
    assert_eq!(read(&root, "e.md").unwrap(), "1 two 1\n");
}

#[test]
fn condition_from_str_and_etag_roundtrip() {
    assert!(matches!(
        "always".parse::<Condition>(),
        Ok(Condition::Always)
    ));
    assert!(matches!(
        "missing".parse::<Condition>(),
        Ok(Condition::Missing)
    ));
    assert!(matches!(
        "exists".parse::<Condition>(),
        Ok(Condition::Exists)
    ));
    assert!("exists:".parse::<Condition>().is_err());
    assert!("bogus".parse::<Condition>().is_err());

    let h = note("p.md", "payload").etag();
    let round: Etag = h.to_string().parse().unwrap();
    assert!(h == round);
    assert!("zz".parse::<Etag>().is_err());
    assert!(format!("exists:{h}").parse::<Condition>().is_ok());
}
