mod common;

use common::{
    backend, fixture_dir, found, grep, invoke, note, notes_root, query, read, root, rp, write,
};
use noted::note::{Condition, Etag, Note};
use noted::search::{CaseMode, SearchMode, SearchQuery};
use noted::util::{atomic_write, slice_lines};
use serde_json::json;

#[tokio::test]
async fn read_edge_cases() {
    let dir = fixture_dir();
    let root = root(&dir);
    assert!(matches!(
        read(&root, "nope.md").await.unwrap_err(),
        noted::NotedError::NotFound
    ));

    std::fs::write(notes_root(&dir).join("bad.md"), [0xff, 0xfe, 0x00]).unwrap();
    assert!(
        read(&root, "bad.md")
            .await
            .unwrap_err()
            .to_string()
            .contains("utf-8")
    );
}

#[tokio::test]
async fn write_creates_parents_and_leaves_no_temp() {
    let dir = fixture_dir();
    let root = root(&dir);
    write(&root, &note("deep/nested/new.md", "hello\n"))
        .await
        .unwrap();
    assert_eq!(read(&root, "deep/nested/new.md").await.unwrap(), "hello\n");

    write(&root, &note("a.md", "x")).await.unwrap();
    let leftovers: Vec<_> = std::fs::read_dir(notes_root(&dir))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".noted-tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "atomic_write left a temp file");
}

#[tokio::test]
async fn the_log_region_is_unreachable_through_the_note_tools() {
    let dir = fixture_dir();
    let root = root(&dir);
    let entry = ".logs/2026-07-01T09-00-00.000000-0700.md";
    for err in [
        write(&root, &note(entry, "nope")).await.unwrap_err(),
        root.note_delete(&rp(entry)).await.unwrap_err(),
        root.note_move(&rp(entry), &rp("moved.md"), false)
            .await
            .unwrap_err(),
    ] {
        assert!(
            matches!(err, noted::NotedError::Forbidden),
            "expected a policy refusal, got {err}"
        );
    }
}

#[tokio::test]
async fn log_note_writes_one_file_with_front_matter() {
    let dir = fixture_dir();
    let root = root(&dir);
    let logged = root
        .log_note(&"did a thing\n-- t · s".into())
        .await
        .unwrap();
    let rel = logged.path().to_string();
    assert!(rel.starts_with("20"), "{rel}");
    let on_disk = std::fs::read_to_string(notes_root(&dir).join(".logs").join(&rel)).unwrap();
    let text = String::from_utf8(logged.to_bytes()).unwrap();
    assert_eq!(text, on_disk);
    assert_eq!(logged.etag(), note(&rel, &on_disk).etag());

    assert!(text.starts_with("---\n"));
    assert!(text.ends_with('\n'));
    for key in ["created", "cwd", "host", "source"] {
        assert!(text.contains(key), "front matter missing {key}");
    }
    assert!(text.contains("source: test"));
    assert!(text.contains("did a thing"));

    let entry = notes_root(&dir).join(".logs").join(&rel);
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

#[tokio::test]
async fn log_note_records_no_source_when_the_caller_has_none() {
    let dir = fixture_dir();
    let root = noted::NotedRoot::open(noted::store::NotedDir::new(notes_root(&dir)), None).unwrap();
    let logged = root.log_note(&"anonymous\n".into()).await.unwrap();
    let text = String::from_utf8(logged.to_bytes()).unwrap();
    assert!(!text.contains("source:"), "{text}");
}

#[tokio::test]
async fn delete_moves_to_trash_and_uniquifies() {
    let dir = fixture_dir();
    let root = root(&dir);

    let original = read(&root, "Inbox.md").await.unwrap();
    let trashed = root.note_delete(&rp("Inbox.md")).await.unwrap();
    assert_eq!(trashed.path().to_string(), "Inbox.md");
    assert!(read(&root, "Inbox.md").await.is_err());
    assert_eq!(
        std::fs::read_to_string(notes_root(&dir).join(".trash").join("Inbox.md")).unwrap(),
        original
    );

    // .trash/old-idea.md already exists in the fixture → a same-named delete
    // must uniquify rather than clobber it.
    write(&root, &note("old-idea.md", "different\n"))
        .await
        .unwrap();
    let uniq = root.note_delete(&rp("old-idea.md")).await.unwrap();
    assert_eq!(uniq.path().to_string(), "old-idea.md");
    assert_eq!(
        std::fs::read_to_string(notes_root(&dir).join(".trash").join("old-idea 1.md")).unwrap(),
        "different\n"
    );

    assert!(matches!(
        root.note_delete(&rp("ghost.md")).await.unwrap_err(),
        noted::NotedError::NotFound
    ));
}

#[tokio::test]
async fn move_semantics() {
    let dir = fixture_dir();
    let root = root(&dir);

    let body = read(&root, "Inbox.md").await.unwrap();
    root.note_move(&rp("Inbox.md"), &rp("Inbox2.md"), false)
        .await
        .unwrap();
    assert_eq!(read(&root, "Inbox2.md").await.unwrap(), body);

    assert!(matches!(
        root.note_move(&rp("Inbox2.md"), &rp("projects/ideas.md"), false)
            .await
            .unwrap_err(),
        noted::NotedError::Conflict
    ));
    root.note_move(&rp("Inbox2.md"), &rp("projects/ideas.md"), true)
        .await
        .unwrap();
    assert_eq!(read(&root, "projects/ideas.md").await.unwrap(), body);

    assert!(matches!(
        root.note_move(&rp("ghost.md"), &rp("d.md"), false)
            .await
            .unwrap_err(),
        noted::NotedError::NotFound
    ));
    assert!(
        root.note_move(&rp("daily"), &rp("daily"), false)
            .await
            .unwrap_err()
            .to_string()
            .contains("same")
    );
    assert!(
        root.note_move(&rp("projects"), &rp("projects/sub"), false)
            .await
            .unwrap_err()
            .to_string()
            .contains("into itself")
    );
}

#[tokio::test]
async fn move_onto_nonempty_folder_is_rejected() {
    let dir = fixture_dir();
    let root = root(&dir);
    write(&root, &note("srcd/a.md", "a")).await.unwrap();
    write(&root, &note("dstd/b.md", "b")).await.unwrap();
    assert!(
        root.note_move(&rp("srcd"), &rp("dstd"), true)
            .await
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
    assert!(found(&root, ".logs").await.unwrap().is_empty());

    root.task_create(
        &"reserved from notes".parse().unwrap(),
        &Default::default(),
        &"UNIQUETASKBODY\n".into(),
    )
    .await
    .unwrap();
    assert!(grep(&root, "UNIQUETASKBODY").await.unwrap().is_empty());
    assert!(found(&root, ".tasks").await.unwrap().is_empty());

    let contacts = found(&root, "contacts").await.unwrap();
    assert!(contacts.iter().any(|p| p == "people/contacts.md"));
    // old-idea.md exists only under the fixture's .trash/
    assert!(found(&root, "old-idea").await.unwrap().is_empty());
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

#[tokio::test]
async fn matching_condition_is_a_compare_and_swap() {
    let dir = fixture_dir();
    let root = root(&dir);
    let original = note("cw.md", "one");
    write(&root, &original).await.unwrap();

    let updated = original.clone().with_body("two");
    root.note_write(&updated, Condition::Matching(original.etag()))
        .await
        .unwrap();
    assert_eq!(read(&root, "cw.md").await.unwrap(), "two");

    let stale = original.clone().with_body("three");
    let err = root
        .note_write(&stale, Condition::Matching(original.etag()))
        .await
        .unwrap_err();
    assert!(matches!(err, noted::error::NotedError::Conflict));
    assert_eq!(read(&root, "cw.md").await.unwrap(), "two");

    root.note_write(
        &note("cw.md", "four"),
        Condition::Matching(note("cw.md", "two").etag()),
    )
    .await
    .unwrap();
    assert_eq!(read(&root, "cw.md").await.unwrap(), "four");
}

#[tokio::test]
async fn create_and_replace_conditions() {
    let dir = fixture_dir();
    let root = root(&dir);

    root.note_write(&note("m.md", "hi"), Condition::Missing)
        .await
        .unwrap();
    assert!(matches!(
        root.note_write(&note("m.md", "again"), Condition::Missing)
            .await
            .unwrap_err(),
        noted::error::NotedError::Conflict
    ));

    root.note_write(&note("m.md", "edited"), Condition::Exists)
        .await
        .unwrap();
    assert!(matches!(
        root.note_write(&note("absent.md", "x"), Condition::Exists)
            .await
            .unwrap_err(),
        noted::error::NotedError::NotFound
    ));
}

#[tokio::test]
async fn conflict_message_never_mentions_sha256() {
    let dir = fixture_dir();
    let root = root(&dir);
    write(&root, &note("c.md", "v1")).await.unwrap();
    let err = root
        .note_write(
            &note("c.md", "v2"),
            Condition::Matching(note("c.md", "other").etag()),
        )
        .await
        .unwrap_err();
    assert!(!err.to_string().to_lowercase().contains("sha256"));
}

#[tokio::test]
async fn edit_replaces_and_refuses_ambiguity() {
    let dir = fixture_dir();
    let root = root(&dir);
    write(&root, &note("e.md", "one two one\n")).await.unwrap();

    assert!(
        root.note_edit(&rp("e.md"), &noted::note::Edit::new("one", "1", false))
            .await
            .unwrap_err()
            .to_string()
            .contains("not unique")
    );
    assert!(
        root.note_edit(&rp("e.md"), &noted::note::Edit::new("zzz", "1", false))
            .await
            .unwrap_err()
            .to_string()
            .contains("not found")
    );
    root.note_edit(&rp("e.md"), &noted::note::Edit::new("one", "1", true))
        .await
        .unwrap();
    assert_eq!(read(&root, "e.md").await.unwrap(), "1 two 1\n");
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

fn stamp(dir: &tempfile::TempDir, rel: &str, body: &str, seconds: u64) {
    let path = notes_root(dir).join(rel);
    std::fs::write(&path, body).unwrap();
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds))
        .unwrap();
}

#[tokio::test]
async fn search_sorted_by_modified_lists_newest_first() {
    let dir = fixture_dir();
    let root = root(&dir);
    stamp(&dir, "sorta.md", "sortable\n", 1_000);
    stamp(&dir, "sortb.md", "sortable\n", 2_000);
    stamp(&dir, "sortc.md", "sortable\n", 3_000);

    let recent = SearchQuery {
        order: noted::search::SearchOrder::Modified,
        ..query("sortable", SearchMode::File)
    };
    let paths: Vec<String> = root
        .note_search(&recent)
        .await
        .unwrap()
        .iter()
        .map(|h| h.path.to_string())
        .collect();
    assert_eq!(paths, vec!["sortc.md", "sortb.md", "sorta.md"]);
}

#[tokio::test]
async fn search_without_sort_keeps_path_order() {
    let dir = fixture_dir();
    let root = root(&dir);
    stamp(&dir, "sorta.md", "sortable\n", 3_000);
    stamp(&dir, "sortb.md", "sortable\n", 2_000);
    stamp(&dir, "sortc.md", "sortable\n", 1_000);

    for mode in [SearchMode::Path, SearchMode::File, SearchMode::Line] {
        let pattern = match mode {
            SearchMode::Path => "sort",
            _ => "sortable",
        };
        let paths: Vec<String> = root
            .note_search(&query(pattern, mode))
            .await
            .unwrap()
            .iter()
            .map(|h| h.path.to_string())
            .filter(|p| p.starts_with("sort"))
            .collect();
        assert_eq!(paths, vec!["sorta.md", "sortb.md", "sortc.md"]);
    }
}
