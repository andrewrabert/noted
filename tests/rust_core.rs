mod common;

use common::{cores, fixture_dir, notes_root};
use noted::search::{MatchOpts, WalkOpts};
use noted::util::{atomic_write, slice_lines};
use serde_json::json;

#[test]
fn path_escapes_are_rejected() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    for escape in ["../evil.md", "../../etc/passwd", "/etc/passwd"] {
        assert!(
            notes.read(&rp(escape)).is_err(),
            "read {escape} should reject"
        );
        assert!(
            notes.write(&rp(escape), "x").is_err(),
            "write {escape} should reject"
        );
    }
}

#[test]
fn hidden_paths_are_rejected_everywhere() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    for hidden in [".trash/x.md", ".git/config", "secret/.env", ".hidden"] {
        let err = notes.read(&rp(hidden)).unwrap_err().to_string();
        assert!(err.contains("invalid path"), "read {hidden}: {err}");
        assert!(
            !err.contains("recover") && !err.contains("already in"),
            "read {hidden} used trash-recovery language: {err}"
        );
        assert!(notes.write(&rp(hidden), "x").is_err(), "write {hidden}");
        assert!(notes.delete(&rp(hidden)).is_err(), "delete {hidden}");
        assert!(
            notes.move_note(&rp(hidden), &rp("ok.md"), false).is_err(),
            "move {hidden}"
        );
    }
    assert!(notes.delete(&rp("Inbox.md")).is_ok());
    assert!(notes.read(&rp("Inbox.md")).is_err());
}

#[test]
fn read_edge_cases() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    assert!(notes
        .read(&rp(""))
        .unwrap_err()
        .to_string()
        .contains("required"));
    assert!(notes
        .read(&rp("foo/"))
        .unwrap_err()
        .to_string()
        .contains("must be a file"));
    assert!(notes
        .read(&rp("nope.md"))
        .unwrap_err()
        .to_string()
        .contains("no note at"));

    std::fs::write(notes_root(&dir).join("bad.md"), [0xff, 0xfe, 0x00]).unwrap();
    assert!(notes
        .read(&rp("bad.md"))
        .unwrap_err()
        .to_string()
        .contains("utf-8"));
}

#[test]
fn write_creates_parents_and_leaves_no_temp() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    notes.write(&rp("deep/nested/new.md"), "hello\n").unwrap();
    assert_eq!(notes.read(&rp("deep/nested/new.md")).unwrap(), "hello\n");

    notes.write(&rp("a.md"), "x").unwrap();
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
        .write(&rp(entry), "nope")
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
    let rel = notes.create_log("did a thing\n-- t · s", None).unwrap();
    assert!(rel.starts_with("Log/"));

    let text = notes.read(&rp(&rel)).unwrap();
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

    let original = notes.read(&rp("Inbox.md")).unwrap();
    let trash_rel = notes.delete(&rp("Inbox.md")).unwrap();
    assert!(trash_rel.starts_with(".trash/"));
    assert!(notes.read(&rp("Inbox.md")).is_err());
    assert_eq!(
        std::fs::read_to_string(notes_root(&dir).join(&trash_rel)).unwrap(),
        original
    );

    // .trash/old-idea.md already exists in the fixture → a same-named delete
    // must uniquify rather than clobber it.
    notes.write(&rp("old-idea.md"), "different\n").unwrap();
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

    let body = notes.read(&rp("Inbox.md")).unwrap();
    notes
        .move_note(&rp("Inbox.md"), &rp("Inbox2.md"), false)
        .unwrap();
    assert_eq!(notes.read(&rp("Inbox2.md")).unwrap(), body);

    assert!(notes
        .move_note(&rp("Inbox2.md"), &rp("projects/ideas.md"), false)
        .unwrap_err()
        .to_string()
        .contains("destination exists"));
    notes
        .move_note(&rp("Inbox2.md"), &rp("projects/ideas.md"), true)
        .unwrap();
    assert_eq!(notes.read(&rp("projects/ideas.md")).unwrap(), body);

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
    notes.write(&rp("srcd/a.md"), "a").unwrap();
    notes.write(&rp("dstd/b.md"), "b").unwrap();
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
        assert!(notes.read(&rp(rel)).is_err(), "read {rel} should reject");
        assert!(
            notes.write(&rp(rel), "x").is_err(),
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

    assert!(notes.read(&rp("wip-keep.md")).is_ok());
    assert!(notes.read(&rp("visible.md")).is_ok());
    assert!(notes.write(&rp("drafts/new.md"), "x").is_err());
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
            notes.read(&rp(f)).is_ok(),
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
    atomic_write(&target, "first").unwrap();
    atomic_write(&target, "second").unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "second");
}

#[allow(dead_code)]
fn rp(s: &str) -> noted::notes::RelPath {
    s.parse().unwrap()
}
