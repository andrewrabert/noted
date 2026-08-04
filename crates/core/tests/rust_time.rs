use noted::types::Timestamp;

fn ts(s: &str) -> Timestamp {
    s.parse().unwrap()
}

#[test]
fn a_canonical_stamp_round_trips() {
    let text = "2026-07-01T09:15:30.123456-07:00";
    assert_eq!(ts(text).to_string(), text);
    assert_eq!(
        serde_json::to_string(&ts(text)).unwrap(),
        format!("\"{text}\"")
    );
}

#[test]
fn text_that_is_not_an_instant_is_refused() {
    for bad in ["X", "", "2026-07-01", "2026-07-01T09:15:30"] {
        assert!(bad.parse::<Timestamp>().is_err(), "{bad}");
        assert!(Timestamp::try_from(bad.to_string()).is_err(), "{bad}");
    }
}

#[test]
fn serde_refuses_a_bad_stamp() {
    assert!(serde_json::from_str::<Timestamp>("\"X\"").is_err());
    assert!(serde_json::from_str::<Timestamp>("\"X\"").is_err());
}

#[test]
fn sub_microseconds_are_dropped() {
    assert_eq!(
        ts("2026-07-01T09:15:30.123456789Z").to_string(),
        "2026-07-01T09:15:30.123456+00:00"
    );
}

#[test]
fn ordering_is_by_instant_across_offsets() {
    let later = ts("2026-07-05T09:00:00.000000-07:00");
    let earlier = ts("2026-07-05T10:00:00.000000+00:00");
    assert!(later > earlier);
    assert_eq!(ts("2026-07-05T10:00:00.000000+00:00"), earlier);
    assert_eq!(
        ts("2026-07-05T03:00:00.000000-07:00"),
        ts("2026-07-05T10:00:00.000000+00:00")
    );
}

#[test]
fn now_carries_microseconds_and_an_explicit_offset() {
    let text = Timestamp::now().to_string();
    assert_eq!(text.parse::<Timestamp>().unwrap().to_string(), text);
    let (head, offset) = text.split_at(26);
    assert_eq!(head.len(), 26, "{text}");
    assert_eq!(&head[19..20], ".", "{text}");
    assert!(
        offset.starts_with(['+', '-']) && offset.len() == 6,
        "{text}"
    );
}
