mod common;

use common::{fixture_dir, note, notes_root, read, root, rp, write};
use noted::path::{RelPath, Segment};

#[test]
fn escapes_are_unrepresentable() {
    for escape in ["../evil.md", "../../etc/passwd", "a/../b.md"] {
        let err = RelPath::new(escape).unwrap_err().to_string();
        assert!(err.contains("escapes notes root"), "{escape}: {err}");
    }
    let err = RelPath::new("/etc/passwd").unwrap_err().to_string();
    assert!(err.contains("escapes notes root"), "{err}");
}

#[test]
fn dotted_and_malformed_paths_are_unrepresentable() {
    for bad in [
        ".trash/old-idea.md",
        ".git/config",
        "secret/.env",
        ".hidden",
        "foo/",
        "a//b.md",
    ] {
        let err = RelPath::new(bad).unwrap_err().to_string();
        assert!(err.contains("invalid path"), "{bad}: {err}");
        assert!(
            !err.contains("recover") && !err.contains("already in"),
            "{bad} used trash-recovery language: {err}"
        );
    }
}

#[test]
fn the_root_is_a_path_and_ordinary_paths_survive() {
    assert!(RelPath::new("").unwrap().is_empty());
    assert_eq!(
        RelPath::new("projects/ideas.md").unwrap(),
        "projects/ideas.md"
    );
}

#[test]
fn paths_order_case_insensitively_then_by_bytes() {
    let mut paths = vec![
        rp("cherry.md"),
        rp("Banana.md"),
        rp("apple.md"),
        rp("Apple.md"),
    ];
    paths.sort();
    assert_eq!(
        paths,
        vec![
            rp("Apple.md"),
            rp("apple.md"),
            rp("Banana.md"),
            rp("cherry.md")
        ]
    );
}

#[test]
fn a_segment_is_one_plain_component() {
    assert_eq!(Segment::new("notes").unwrap().as_str(), "notes");
    for bad in ["", ".", "..", ".hidden", "a/b"] {
        assert!(Segment::new(bad).is_err(), "{bad} should be rejected");
    }
}

#[test]
fn a_representable_path_is_still_subject_to_the_trees_ignore_rules() {
    let dir = fixture_dir();
    let root = root(&dir);
    std::fs::write(notes_root(&dir).join(".ignore"), "hidden-note.md\n").unwrap();
    std::fs::write(notes_root(&dir).join("hidden-note.md"), "x").unwrap();

    let err = read(&root, "hidden-note.md").unwrap_err().to_string();
    assert!(err.contains("invalid path"), "{err}");
    assert!(write(&root, &note("hidden-note.md", "y")).is_err());
}
