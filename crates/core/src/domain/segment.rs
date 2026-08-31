//! The invariant every segment has, whatever frame it belongs to. Opaque:
//! no extension concept, no separator concept, no filesystem meaning.
//! Built only here; read anywhere in the crate through `as_str`.

/// One part of a segment list.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Segment(String);

impl Segment {
    pub(super) fn new(part: &str) -> Result<Segment, &'static str> {
        if part.is_empty() {
            return Err("empty segment");
        }
        if part == "." || part == ".." {
            return Err("segment is '.' or '..'");
        }
        if part.trim() != part {
            return Err("segment has leading or trailing whitespace");
        }
        if part.contains('\0') {
            return Err("segment contains NUL");
        }
        if part.len() > 255 {
            return Err("segment is longer than 255 bytes");
        }
        Ok(Segment(part.to_string()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_segment_is_one_plain_part() {
        assert_eq!(Segment::new("a b.md").unwrap().as_str(), "a b.md");
        assert_eq!(Segment::new(".hidden").unwrap().as_str(), ".hidden");
        let long = "x".repeat(256);
        for bad in [
            "",
            ".",
            "..",
            " a",
            "a ",
            "\u{2003}a",
            "a\u{3000}",
            "a\0b",
            long.as_str(),
        ] {
            assert!(Segment::new(bad).is_err(), "accepted {bad:?}");
        }
    }
}
