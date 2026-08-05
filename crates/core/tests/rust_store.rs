mod common;

use common::rp;
use noted::path::{Path, Segment};

#[test]
fn escapes_are_unrepresentable() {
    for escape in ["../evil.md", "../../etc/passwd", "a/../b.md"] {
        let err = Path::new(escape).unwrap_err().to_string();
        assert!(err.contains("escapes notes root"), "{escape}: {err}");
    }
    let err = Path::new("/etc/passwd").unwrap_err().to_string();
    assert!(err.contains("escapes notes root"), "{err}");
}

#[test]
fn dotted_and_malformed_paths_are_unrepresentable() {
    for bad in [
        ".trash/old-idea.md",
        ".git/config",
        "secret/.env",
        ".hidden",
    ] {
        let err = Path::new(bad).unwrap_err().to_string();
        assert!(err.contains("invalid path"), "{bad}: {err}");
        assert!(
            !err.contains("recover") && !err.contains("already in"),
            "{bad} used trash-recovery language: {err}"
        );
    }
}

#[test]
fn every_path_has_exactly_one_spelling() {
    for (written, canonical) in [
        ("foo/", "foo"),
        ("a//b.md", "a/b.md"),
        ("./a/./b.md", "a/b.md"),
    ] {
        assert_eq!(Path::new(written).unwrap(), canonical, "{written}");
    }
    for empty in ["", ".", "./."] {
        assert!(Path::new(empty).is_err(), "accepted '{empty}'");
    }
}

#[test]
fn the_root_is_no_path_and_ordinary_paths_survive() {
    assert!(Path::new("").is_err());
    assert_eq!(Path::new("projects/ideas.md").unwrap(), "projects/ideas.md");
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
