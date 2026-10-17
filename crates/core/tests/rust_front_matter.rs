use noted::front_matter::{FrontMatter, split_front};
use noted::types::Timestamp;

#[test]
fn a_repeated_key_is_refused() {
    assert!(FrontMatter::parse("k: a\nk: b\n").is_err());
}

#[test]
fn a_body_is_framed_below_the_block() {
    let mut front = FrontMatter::default();
    front.set("a", "1");
    front.set_opt("b", Some("2"));
    front.set_opt("c", None::<String>);
    let text = front.dump("hello");
    assert!(text.starts_with("---\n"));
    assert!(text.ends_with("---\nhello\n"));
    let (block, _) = split_front(&text).expect("dump always frames a block");
    let parsed = FrontMatter::parse(block).unwrap();
    assert_eq!(parsed.get("a"), Some("1"));
    assert_eq!(parsed.get("b"), Some("2"));
}

#[test]
fn a_missing_key_and_a_refused_value_are_distinct_errors() {
    let front = FrontMatter::parse("created: nope\n").unwrap();
    let missing = front.field::<Timestamp>("updated").unwrap_err();
    let refused = front.field::<Timestamp>("created").unwrap_err();
    assert!(missing.message().contains("missing field 'updated'"));
    assert!(refused.message().contains("not a timestamp"));
    assert!(front.opt_field::<Timestamp>("updated").unwrap().is_none());
    assert!(front.opt_field::<Timestamp>("created").is_err());
}
