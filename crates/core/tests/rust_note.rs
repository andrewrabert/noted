mod common;

use common::{fixture_dir, note, read, root, rp, write};
use noted::note::{Etag, TextNote};

#[test]
fn same_content_yields_same_etag() {
    let content = "---\ntask: x\n---\nbody line\n";
    let n = TextNote::new(rp("/a.md"), content);
    assert_eq!(n.path(), &rp("/a.md"));
    assert_eq!(n.body(), content);
    assert_eq!(n.etag(), TextNote::new(rp("/other.md"), content).etag());
}

#[test]
fn etag_is_sensitive_to_frontmatter_and_whitespace() {
    let base = TextNote::new(rp("/a.md"), "---\nk: 1\n---\nbody\n");
    let front = TextNote::new(rp("/a.md"), "---\nk: 2\n---\nbody\n");
    assert_ne!(base.etag(), front.etag());
    let ws = TextNote::new(rp("/a.md"), "---\nk: 1\n---\nbody \n");
    assert_ne!(base.etag(), ws.etag());
    let nl = TextNote::new(rp("/a.md"), "---\nk: 1\n---\nbody");
    assert_ne!(base.etag(), nl.etag());
}

#[test]
fn body_replacement_recomputes_etag() {
    let original = TextNote::new(rp("/a.md"), "one");
    let replaced = original.clone().with_body("two");
    assert_eq!(replaced.body(), "two");
    assert_eq!(replaced.etag(), TextNote::new(rp("/a.md"), "two").etag());
    assert_ne!(original.etag(), replaced.etag());
}

#[test]
fn path_only_change_and_clone_preserve_etag() {
    let original = TextNote::new(rp("/a.md"), "same content\n");
    let moved = original.clone().with_path(rp("/b/c.md"));
    assert_eq!(moved.path(), &rp("/b/c.md"));
    assert_eq!(moved.body(), original.body());
    assert_eq!(moved.etag(), original.etag());

    let cloned = original.clone();
    assert_eq!(cloned.etag(), original.etag());
}

#[test]
fn etag_wire_roundtrip() {
    let etag = TextNote::new(rp("/a.md"), "payload").etag();
    let round: Etag = etag.to_string().parse().unwrap();
    assert_eq!(etag, round);
    assert!("zz".parse::<Etag>().is_err());
}

#[tokio::test]
async fn read_returns_a_note_matching_the_file() {
    let dir = fixture_dir();
    let root = root(&dir);
    write(&root, &note("/g.md", "hello world\n")).await.unwrap();
    let got = root.note_read(&rp("/g.md")).await.unwrap();
    assert_eq!(got.path(), &rp("/g.md"));
    assert_eq!(got.body(), "hello world\n");
    assert_eq!(read(&root, "/g.md").await.unwrap(), "hello world\n");
    assert_eq!(
        got.etag(),
        TextNote::new(rp("/g.md"), "hello world\n").etag()
    );
}

#[test]
fn etag_parses_either_case_and_rejects_malformed_tokens() {
    let etag = TextNote::new(rp("/a.md"), "payload").etag();
    let lower = etag.to_string();
    let upper: Etag = lower.to_uppercase().parse().unwrap();
    assert_eq!(upper, lower.parse::<Etag>().unwrap());

    for bad in [&lower[..63], &format!("{lower}0")[..], "", &"z".repeat(64)] {
        assert!(bad.parse::<Etag>().is_err(), "accepted {bad:?}");
    }
}
