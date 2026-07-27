mod common;

use common::{cores, fixture_dir, note, rp};
use noted::note::{Etag, TextNote};

#[test]
fn same_content_yields_same_etag() {
    let content = "---\ntask: x\n---\nbody line\n";
    let n = TextNote::new(rp("a.md"), content);
    assert_eq!(n.path(), &rp("a.md"));
    assert_eq!(n.content(), content);
    assert_eq!(n.etag(), TextNote::new(rp("other.md"), content).etag());
}

#[test]
fn etag_is_sensitive_to_frontmatter_and_whitespace() {
    let base = TextNote::new(rp("a.md"), "---\nk: 1\n---\nbody\n");
    let front = TextNote::new(rp("a.md"), "---\nk: 2\n---\nbody\n");
    assert_ne!(base.etag(), front.etag());
    let ws = TextNote::new(rp("a.md"), "---\nk: 1\n---\nbody \n");
    assert_ne!(base.etag(), ws.etag());
    let nl = TextNote::new(rp("a.md"), "---\nk: 1\n---\nbody");
    assert_ne!(base.etag(), nl.etag());
}

#[test]
fn content_replacement_recomputes_etag() {
    let original = TextNote::new(rp("a.md"), "one");
    let replaced = original.clone().with_content("two");
    assert_eq!(replaced.content(), "two");
    assert_eq!(replaced.etag(), TextNote::new(rp("a.md"), "two").etag());
    assert_ne!(original.etag(), replaced.etag());

    let mut mutable = TextNote::new(rp("a.md"), "one");
    mutable.set_content("three");
    assert_eq!(mutable.etag(), TextNote::new(rp("a.md"), "three").etag());
}

#[test]
fn path_only_change_and_clone_preserve_etag() {
    let original = TextNote::new(rp("a.md"), "same content\n");
    let moved = original.clone().with_path(rp("b/c.md"));
    assert_eq!(moved.path(), &rp("b/c.md"));
    assert_eq!(moved.content(), original.content());
    assert_eq!(moved.etag(), original.etag());

    let cloned = original.clone();
    assert_eq!(cloned.etag(), original.etag());
}

#[test]
fn etag_wire_roundtrip() {
    let etag = TextNote::new(rp("a.md"), "payload").etag();
    let round: Etag = etag.to_string().parse().unwrap();
    assert_eq!(etag, round);
    assert!("zz".parse::<Etag>().is_err());
}

#[test]
fn get_returns_a_note_matching_the_file() {
    let dir = fixture_dir();
    let (notes, _) = cores(&dir);
    notes.put(&note("g.md", "hello world\n")).unwrap();
    let got = notes.get(&rp("g.md")).unwrap();
    assert_eq!(got.path(), &rp("g.md"));
    assert_eq!(got.content(), "hello world\n");
    assert_eq!(
        got.etag(),
        TextNote::new(rp("g.md"), "hello world\n").etag()
    );
}
