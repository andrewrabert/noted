use noted::front_matter::{FrontMatter, split_front};
use noted::types::Timestamp;

fn one(key: &str, value: &str) -> String {
    let mut front = FrontMatter::default();
    front.set(key, value);
    let text = front.dump("body\n");
    let (block, _) = split_front(&text).expect("dump always frames a block");
    block.to_string()
}

fn round_trip(value: &str) -> String {
    let text = one("k", value);
    FrontMatter::parse(&text)
        .expect("emitted text parses")
        .get("k")
        .expect("the key survives")
        .to_string()
}

// emitted lines match, byte for byte, what the old YAML emitter wrote
#[test]
fn a_scalar_is_quoted_exactly_where_yaml_quoted_it() {
    for (value, line) in [
        ("plain", "k: plain"),
        ("two words", "k: two words"),
        ("naïve 🎉", "k: naïve 🎉"),
        ("a#b", "k: a#b"),
        ("a:b", "k: a:b"),
        ("", "k: ''"),
        ("true", "k: 'true'"),
        ("False", "k: 'False'"),
        ("null", "k: 'null'"),
        ("~", "k: '~'"),
        ("123", "k: '123'"),
        ("-4", "k: '-4'"),
        ("1.5e3", "k: '1.5e3'"),
        (".inf", "k: '.inf'"),
        ("0x1f", "k: '0x1f'"),
        ("Fix: it", "k: 'Fix: it'"),
        ("ends:", "k: 'ends:'"),
        ("- dash", "k: '- dash'"),
        ("#hash", "k: '#hash'"),
        ("a # b", "k: 'a # b'"),
        (" lead", "k: ' lead'"),
        ("trail ", "k: 'trail '"),
        ("don't", "k: don't"),
        ("'quoted'", "k: '''quoted'''"),
        ("\"quoted\"", "k: '\"quoted\"'"),
        ("---", "k: '---'"),
        ("a\tb", "k: \"a\\tb\""),
        ("a\nb", "k: \"a\\nb\""),
    ] {
        assert_eq!(one("k", value), line, "value {value:?}");
    }
}

// colons, quotes, '#', leading '-', leading/trailing space, empty, unicode,
// tab, newline, control characters
#[test]
fn every_tricky_value_round_trips() {
    for value in [
        "plain",
        "",
        " ",
        "Fix: it",
        "don't",
        "it's a 'quote'",
        "\"double\"",
        "- dash",
        "#hash",
        "a # b",
        " lead",
        "trail ",
        "naïve 🎉",
        "a\tb",
        "a\nb\nc",
        "bell\u{7} and del\u{7f}",
        "true",
        "0x1f",
        "---",
        "{}",
        "[a, b]",
        "%directive",
        "back`tick",
    ] {
        assert_eq!(round_trip(value), value, "value {value:?}");
    }
}

#[test]
fn a_body_is_framed_below_the_block() {
    let mut front = FrontMatter::default();
    front.set("a", "1");
    front.set_opt("b", Some("2"));
    front.set_opt("c", None::<String>);
    assert_eq!(front.dump("hello"), "---\na: '1'\nb: '2'\n---\nhello\n");
}

// 'created: '2026-07-01T09:00:00.000000-07:00'', "a\tb", |- blocks, comments
#[test]
fn a_block_written_by_yaml_still_parses() {
    let block = concat!(
        "# a leading comment\n",
        "created: '2026-07-01T09:00:00.000000-07:00'\n",
        "cwd: /tmp\n",
        "host: testhost\n",
        "escaped: \"a\\tb\\u00e9\"\n",
        "empty: ''\n",
        "bare:\n",
        "commented: value # trailing\n",
        "\n",
        "clipped: |\n",
        "  one\n",
        "  two\n",
        "stripped: |-\n",
        "  only\n",
        "kept: |+\n",
        "  text\n",
        "\n",
        "last: done\n",
    );
    let front = FrontMatter::parse(block).unwrap();
    assert_eq!(
        front.get("created"),
        Some("2026-07-01T09:00:00.000000-07:00")
    );
    assert_eq!(front.get("cwd"), Some("/tmp"));
    assert_eq!(front.get("escaped"), Some("a\tbé"));
    assert_eq!(front.get("empty"), Some(""));
    assert_eq!(front.get("bare"), Some(""));
    assert_eq!(front.get("commented"), Some("value"));
    assert_eq!(front.get("clipped"), Some("one\ntwo\n"));
    assert_eq!(front.get("stripped"), Some("only"));
    assert_eq!(front.get("kept"), Some("text\n\n"));
    assert_eq!(front.get("last"), Some("done"));
    assert!(front.field::<Timestamp>("created").is_ok());
}

#[test]
fn a_line_that_is_not_a_pair_is_refused() {
    assert!(FrontMatter::parse("just text\n").is_err());
    assert!(FrontMatter::parse(": nokey\n").is_err());
    assert!(FrontMatter::parse("k: 'unterminated\n").is_err());
    assert!(FrontMatter::parse("k: \"bad \\q escape\"\n").is_err());
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
