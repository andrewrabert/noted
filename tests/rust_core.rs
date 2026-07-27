mod common;

use common::{cores, fixture_dir, note, notes_root, read, rp};
use noted::note::{Etag, Note};
use noted::search::{MatchOpts, WalkOpts};
use noted::tools::WriteWhen;
use noted::util::{atomic_write, slice_lines};
use serde_json::json;

#[test]
fn path_escapes_are_rejected() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    for escape in ["../evil.md", "../../etc/passwd", "/etc/passwd"] {
        assert!(read(&notes, escape).is_err(), "read {escape} should reject");
        assert!(
            notes.put(&note(escape, "x")).is_err(),
            "write {escape} should reject"
        );
    }
}

#[test]
fn hidden_paths_are_rejected_everywhere() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    for hidden in [".trash/x.md", ".git/config", "secret/.env", ".hidden"] {
        let err = read(&notes, hidden).unwrap_err().to_string();
        assert!(err.contains("invalid path"), "read {hidden}: {err}");
        assert!(
            !err.contains("recover") && !err.contains("already in"),
            "read {hidden} used trash-recovery language: {err}"
        );
        assert!(notes.put(&note(hidden, "x")).is_err(), "write {hidden}");
        assert!(notes.delete(&rp(hidden)).is_err(), "delete {hidden}");
        assert!(
            notes.move_note(&rp(hidden), &rp("ok.md"), false).is_err(),
            "move {hidden}"
        );
    }
    assert!(notes.delete(&rp("Inbox.md")).is_ok());
    assert!(read(&notes, "Inbox.md").is_err());
}

#[test]
fn read_edge_cases() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    assert!(read(&notes, "")
        .unwrap_err()
        .to_string()
        .contains("required"));
    assert!(read(&notes, "foo/")
        .unwrap_err()
        .to_string()
        .contains("must be a file"));
    assert!(read(&notes, "nope.md")
        .unwrap_err()
        .to_string()
        .contains("no note at"));

    std::fs::write(notes_root(&dir).join("bad.md"), [0xff, 0xfe, 0x00]).unwrap();
    assert!(read(&notes, "bad.md")
        .unwrap_err()
        .to_string()
        .contains("utf-8"));
}

#[test]
fn write_creates_parents_and_leaves_no_temp() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    notes.put(&note("deep/nested/new.md", "hello\n")).unwrap();
    assert_eq!(read(&notes, "deep/nested/new.md").unwrap(), "hello\n");

    notes.put(&note("a.md", "x")).unwrap();
    let leftovers: Vec<_> = std::fs::read_dir(notes_root(&dir))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".noted-tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "atomic_write left a temp file");
}

#[test]
fn log_entries_are_immutable() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    let entry = "Log/2026/07/2026-07-01T09-00-00.000000.md";
    assert!(notes
        .put(&note(entry, "nope"))
        .unwrap_err()
        .to_string()
        .contains("immutable"));
    assert!(notes
        .delete(&rp(entry))
        .unwrap_err()
        .to_string()
        .contains("immutable"));
    assert!(notes
        .move_note(&rp(entry), &rp("moved.md"), false)
        .unwrap_err()
        .to_string()
        .contains("immutable"));
}

#[test]
fn create_log_writes_front_matter_no_sidecar() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    let logged = notes.create_log("did a thing\n-- t · s", None).unwrap();
    let rel = logged.path().to_string();
    assert!(rel.starts_with("Log/"));
    let text = String::from_utf8(logged.to_bytes().unwrap()).unwrap();
    assert_eq!(text, read(&notes, &rel).unwrap());
    assert_eq!(
        logged.etag().unwrap(),
        note(&rel, &read(&notes, &rel).unwrap()).etag()
    );

    assert!(text.starts_with("---\n"));
    assert!(text.ends_with('\n'));
    for key in ["created", "cwd", "host", "source"] {
        assert!(text.contains(key), "front matter missing {key}");
    }
    assert!(text.contains("source: test"));
    assert!(text.contains("did a thing"));

    assert!(!notes_root(&dir).join(format!("{rel}.meta")).exists());
}

#[test]
fn delete_moves_to_trash_and_uniquifies() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);

    let original = read(&notes, "Inbox.md").unwrap();
    let trash_rel = notes.delete(&rp("Inbox.md")).unwrap();
    assert!(trash_rel.starts_with(".trash/"));
    assert!(read(&notes, "Inbox.md").is_err());
    assert_eq!(
        std::fs::read_to_string(notes_root(&dir).join(&trash_rel)).unwrap(),
        original
    );

    // .trash/old-idea.md already exists in the fixture → a same-named delete
    // must uniquify rather than clobber it.
    notes.put(&note("old-idea.md", "different\n")).unwrap();
    let uniq = notes.delete(&rp("old-idea.md")).unwrap();
    assert_ne!(uniq, ".trash/old-idea.md");
    assert_eq!(
        std::fs::read_to_string(notes_root(&dir).join(&uniq)).unwrap(),
        "different\n"
    );

    let err = notes
        .delete(&rp(".trash/old-idea.md"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("invalid path") && !err.contains("already in"));
    assert!(notes
        .delete(&rp("ghost.md"))
        .unwrap_err()
        .to_string()
        .contains("no note at"));
}

#[test]
fn move_semantics() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);

    let body = read(&notes, "Inbox.md").unwrap();
    notes
        .move_note(&rp("Inbox.md"), &rp("Inbox2.md"), false)
        .unwrap();
    assert_eq!(read(&notes, "Inbox2.md").unwrap(), body);

    assert!(notes
        .move_note(&rp("Inbox2.md"), &rp("projects/ideas.md"), false)
        .unwrap_err()
        .to_string()
        .contains("destination exists"));
    notes
        .move_note(&rp("Inbox2.md"), &rp("projects/ideas.md"), true)
        .unwrap();
    assert_eq!(read(&notes, "projects/ideas.md").unwrap(), body);

    assert!(notes.move_note(&rp(""), &rp("d.md"), false).is_err());
    assert!(notes
        .move_note(&rp("ghost.md"), &rp("d.md"), false)
        .unwrap_err()
        .to_string()
        .contains("no note or folder"));
    assert!(notes
        .move_note(&rp("daily"), &rp("daily"), false)
        .unwrap_err()
        .to_string()
        .contains("same"));
    assert!(notes
        .move_note(&rp("projects"), &rp("projects/sub"), false)
        .unwrap_err()
        .to_string()
        .contains("into itself"));
}

#[test]
fn move_onto_nonempty_folder_is_rejected() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    notes.put(&note("srcd/a.md", "a")).unwrap();
    notes.put(&note("dstd/b.md", "b")).unwrap();
    assert!(notes
        .move_note(&rp("srcd"), &rp("dstd"), true)
        .unwrap_err()
        .to_string()
        .contains("non-empty folder"));
}

#[tokio::test]
async fn search_excludes_trash_but_meta_is_ordinary() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    let m = MatchOpts::default();
    let w = WalkOpts::default();

    // FROBNICATE appears only in the fixture's trashed note
    assert!(notes
        .grep("FROBNICATE", 1, &m, &w)
        .await
        .unwrap()
        .is_empty());

    let meta_hits = notes.grep("testhost", 1, &m, &w).await.unwrap();
    assert!(meta_hits.iter().any(|h| h.rel().ends_with(".md.meta")));

    let contacts = notes.match_path("contacts", &m, &w).await.unwrap();
    assert!(contacts.iter().any(|p| p == "people/contacts.md"));
    // old-idea.md exists only under the fixture's .trash/
    let normal = notes.match_path("old-idea", &m, &w).await.unwrap();
    assert!(normal.is_empty());
}

#[tokio::test]
async fn ignore_files_hide_paths_everywhere() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    let root = notes_root(&dir);
    let m = MatchOpts::default();
    let w = WalkOpts::default();

    std::fs::write(root.join(".ignore"), "wip-*.md\n!wip-keep.md\n").unwrap();
    std::fs::write(root.join(".gitignore"), "drafts/\n").unwrap();
    std::fs::write(root.join("wip-x.md"), "TOPSECRET token").unwrap();
    std::fs::write(root.join("wip-keep.md"), "TOPSECRET token").unwrap();
    std::fs::create_dir(root.join("drafts")).unwrap();
    std::fs::write(root.join("drafts/note.md"), "TOPSECRET token").unwrap();
    std::fs::write(root.join("visible.md"), "TOPSECRET token").unwrap();

    let hits = notes.grep("TOPSECRET", 1, &m, &w).await.unwrap();
    let rels: Vec<&str> = hits.iter().map(|h| h.rel().as_str()).collect();
    assert!(rels.contains(&"visible.md"));
    assert!(rels.contains(&"wip-keep.md"));
    assert!(!rels.contains(&"wip-x.md"));
    assert!(!rels.contains(&"drafts/note.md"));

    let paths = notes.match_path("wip", &m, &w).await.unwrap();
    assert_eq!(paths, vec!["wip-keep.md".to_string()]);

    for rel in ["wip-x.md", "drafts/note.md"] {
        assert!(read(&notes, rel).is_err(), "read {rel} should reject");
        assert!(
            notes.put(&note(rel, "x")).is_err(),
            "write {rel} should reject"
        );
        assert!(
            notes.delete(&rp(rel)).is_err(),
            "delete {rel} should reject"
        );
        assert!(
            notes.move_note(&rp(rel), &rp("moved.md"), false).is_err(),
            "move {rel} should reject"
        );
    }

    assert!(read(&notes, "wip-keep.md").is_ok());
    assert!(read(&notes, "visible.md").is_ok());
    assert!(notes.put(&note("drafts/new.md", "x")).is_err());
}

#[tokio::test]
async fn search_orders_paths_case_insensitively() {
    let dir = fixture_dir();
    let (notes, tasks) = cores(&dir);
    let root = notes_root(&dir);
    for name in ["apple.md", "Banana.md", "cherry.md", "Foo.md", "foo.md"] {
        std::fs::write(root.join(name), "needle\n").unwrap();
    }
    let want = ["apple.md", "Banana.md", "cherry.md", "Foo.md", "foo.md"];

    for mode in ["path", "file"] {
        let pattern = if mode == "path" { "." } else { "needle" };
        let out = noted::tools::run_tool(
            "SearchNotes",
            &json!({"pattern": pattern, "mode": mode}),
            &notes,
            &tasks,
        )
        .await
        .unwrap();
        let out = out.render();
        let got: Vec<&str> = out.lines().filter(|l| !l.contains('/')).collect();
        // Case-only duplicates (Foo.md/foo.md) both survive the BTreeSet dedup.
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
    let (notes, _) = cores(&dir);
    let root = notes_root(&dir);
    let m = MatchOpts::default();
    let w = WalkOpts::default();

    std::fs::write(root.join(".gitignore"), "*.log\n").unwrap();
    std::fs::create_dir(root.join("area")).unwrap();
    std::fs::write(root.join("area/.gitignore"), "!keep.log\ndrop.md\n").unwrap();
    let files = [
        "top.log",
        "area/keep.log",
        "area/other.log",
        "area/drop.md",
        "area/ok.md",
    ];
    for f in files {
        std::fs::write(root.join(f), "NEEDLE").unwrap();
    }

    let hits = notes.grep("NEEDLE", 1, &m, &w).await.unwrap();
    let found: std::collections::HashSet<&str> = hits.iter().map(|h| h.rel().as_str()).collect();
    for f in files {
        assert_eq!(
            found.contains(f),
            read(&notes, f).is_ok(),
            "walk/read disagree on {f}"
        );
    }
    assert!(found.contains("area/keep.log"));
    assert!(found.contains("area/ok.md"));
    assert!(!found.contains("top.log"));
    assert!(!found.contains("area/other.log"));
    assert!(!found.contains("area/drop.md"));
}

#[tokio::test]
async fn search_pattern_and_glob_edges() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    let m = MatchOpts::default();
    let w = WalkOpts::default();

    assert!(notes.grep("", 1, &m, &w).await.is_err());
    assert!(notes.match_path("", &m, &w).await.is_err());

    assert!(notes
        .grep("NOSUCHTOKEN_ZZZ", 1, &m, &w)
        .await
        .unwrap()
        .is_empty());

    assert!(notes.grep("(", 1, &m, &w).await.is_err());
    assert!(notes.match_path("(", &m, &w).await.is_err());

    std::fs::create_dir(notes_root(&dir).join("emptydir")).unwrap();
    let empty_scope = WalkOpts {
        globs: vec!["emptydir".into()],
        types: vec![],
    };
    assert!(notes
        .match_path("x", &m, &empty_scope)
        .await
        .unwrap()
        .is_empty());
    let file_scope = WalkOpts {
        globs: vec!["Inbox.md".into()],
        types: vec![],
    };
    let scoped = notes.match_path("Inbox", &m, &file_scope).await.unwrap();
    assert!(scoped.iter().any(|p| p == "Inbox.md"));
}

#[tokio::test]
async fn search_feature_flags() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    let w = WalkOpts::default();

    std::fs::write(notes_root(&dir).join("lit.md"), "a.b\naxb\n").unwrap();
    let regex_hits = notes
        .grep("a.b", 0, &MatchOpts::default(), &w)
        .await
        .unwrap();
    let regex_lines: usize = regex_hits
        .iter()
        .filter(|h| h.rel().as_str() == "lit.md")
        .map(|h| h.lines().count())
        .sum();
    assert_eq!(regex_lines, 2);
    let fixed = MatchOpts {
        fixed_strings: true,
        ..Default::default()
    };
    let fixed_hits = notes.grep("a.b", 0, &fixed, &w).await.unwrap();
    let fixed_lines: usize = fixed_hits
        .iter()
        .filter(|h| h.rel().as_str() == "lit.md")
        .map(|h| h.lines().count())
        .sum();
    assert_eq!(fixed_lines, 1);

    let word = MatchOpts {
        word: true,
        ..Default::default()
    };
    assert!(notes.grep("Inbo", 0, &word, &w).await.unwrap().is_empty());

    let sensitive = MatchOpts {
        case: noted::search::CaseMode::Sensitive,
        ..Default::default()
    };
    std::fs::write(notes_root(&dir).join("case.md"), "Hello\n").unwrap();
    assert!(notes
        .grep("HELLO", 0, &sensitive, &w)
        .await
        .unwrap()
        .is_empty());
    let insensitive = MatchOpts {
        case: noted::search::CaseMode::Insensitive,
        ..Default::default()
    };
    assert!(!notes
        .grep("HELLO", 0, &insensitive, &w)
        .await
        .unwrap()
        .is_empty());

    let excl = WalkOpts {
        globs: vec!["!people/**".into()],
        types: vec![],
    };
    let paths = notes
        .match_path(".", &MatchOpts::default(), &excl)
        .await
        .unwrap();
    assert!(!paths.iter().any(|p| p.starts_with("people/")));
    assert!(paths.iter().any(|p| p == "Inbox.md"));

    let md = WalkOpts {
        globs: vec![],
        types: vec!["md".into()],
    };
    let md_paths = notes
        .match_path(".", &MatchOpts::default(), &md)
        .await
        .unwrap();
    assert!(md_paths.iter().any(|p| p == "Inbox.md"));
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
fn replace_if_unchanged_and_replace_matching() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    let original = note("cw.md", "one");
    notes.put(&original).unwrap();

    let updated = original.clone().with_content("two");
    notes.replace_if_unchanged(&original, &updated).unwrap();
    assert_eq!(read(&notes, "cw.md").unwrap(), "two");

    let err = notes
        .replace_if_unchanged(&original, &original.clone().with_content("three"))
        .unwrap_err();
    assert!(matches!(err, noted::error::NotedError::Conflict(_)));
    assert_eq!(read(&notes, "cw.md").unwrap(), "two");

    let err = notes
        .replace_if_unchanged(&note("cw.md", "x"), &note("other.md", "x"))
        .unwrap_err();
    assert!(matches!(err, noted::error::NotedError::InvalidInput(_)));

    notes
        .replace_matching(&note("cw.md", "four"), note("cw.md", "two").etag())
        .unwrap();
    assert_eq!(read(&notes, "cw.md").unwrap(), "four");
    assert!(matches!(
        notes
            .replace_matching(&note("cw.md", "five"), note("cw.md", "stale").etag())
            .unwrap_err(),
        noted::error::NotedError::Conflict(_)
    ));
}

#[test]
fn create_and_replace_conditions() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);

    notes.create(&note("m.md", "hi")).unwrap();
    assert!(matches!(
        notes.create(&note("m.md", "again")).unwrap_err(),
        noted::error::NotedError::Conflict(_)
    ));

    notes.replace(&note("m.md", "edited")).unwrap();
    assert!(matches!(
        notes.replace(&note("absent.md", "x")).unwrap_err(),
        noted::error::NotedError::Conflict(_)
    ));
}

#[test]
fn conflict_message_never_mentions_sha256() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    notes.put(&note("c.md", "v1")).unwrap();
    let err = notes
        .replace_matching(&note("c.md", "v2"), note("c.md", "other").etag())
        .unwrap_err();
    assert!(!err.to_string().to_lowercase().contains("sha256"));
}

#[test]
fn write_when_from_str_and_etag_roundtrip() {
    assert!(matches!(
        "always".parse::<WriteWhen>(),
        Ok(WriteWhen::Always)
    ));
    assert!(matches!(
        "missing".parse::<WriteWhen>(),
        Ok(WriteWhen::Missing)
    ));
    assert!(matches!(
        "exists".parse::<WriteWhen>(),
        Ok(WriteWhen::Exists)
    ));
    assert!("exists:".parse::<WriteWhen>().is_err());
    assert!("bogus".parse::<WriteWhen>().is_err());

    let h = note("p.md", "payload").etag();
    let round: Etag = h.to_string().parse().unwrap();
    assert!(h == round);
    assert!("zz".parse::<Etag>().is_err());
    assert!(format!("exists:{}", h).parse::<WriteWhen>().is_ok());
}
