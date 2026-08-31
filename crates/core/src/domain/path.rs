//! The base path: a list of Segments with one spelling. Every frame composes
//! it and adds its own rule; none restates the spelling.
//!
//! Spelling: `/` alone is the root (zero segments); otherwise exactly one
//! separator between segments and none after the last. The leading separator
//! is optional on input (`a/b` reads as `/a/b`) and always present on output.
//! Never empty: the empty string is malformed, not the root. No OS meaning.

use std::fmt;

use super::segment::Segment;
use crate::error::{Result, rejected};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Path {
    segments: Vec<Segment>,
}

impl Path {
    pub(crate) const SEPARATOR: &str = "/";

    pub(super) fn new(raw: &str) -> Result<Path> {
        Path::parse(raw)
            .map(|segments| Path { segments })
            .map_err(|reason| rejected(format!("{raw}: {reason}")))
    }

    fn parse(raw: &str) -> std::result::Result<Vec<Segment>, &'static str> {
        if raw.is_empty() {
            return Err("must not be empty");
        }
        let rest = raw.strip_prefix(Path::SEPARATOR).unwrap_or(raw);
        if rest.is_empty() {
            return Ok(Vec::new());
        }
        rest.split(Path::SEPARATOR).map(Segment::new).collect()
    }

    pub(crate) fn segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter()
    }

    pub(super) fn join(&self, deeper: &Path) -> Path {
        Path {
            segments: self
                .segments
                .iter()
                .chain(&deeper.segments)
                .cloned()
                .collect(),
        }
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.segments.is_empty() {
            return f.write_str(Path::SEPARATOR);
        }
        for part in &self.segments {
            f.write_str(Path::SEPARATOR)?;
            f.write_str(part.as_str())?;
        }
        Ok(())
    }
}

impl fmt::Debug for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> Path {
        Path::new(s).unwrap()
    }

    #[test]
    fn a_path_has_exactly_one_spelling() {
        for good in ["/", "/a", "/a/b c", "/.logs/x.md"] {
            assert_eq!(at(good).to_string(), good);
            assert_eq!(Path::new(&at(good).to_string()).unwrap(), at(good));
        }
        assert_eq!(at("/").segments().count(), 0);
        assert_eq!(
            at("/a/b")
                .segments()
                .map(Segment::as_str)
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        for (loose, strict) in [
            ("a", "/a"),
            ("a/b c", "/a/b c"),
            (".logs/x.md", "/.logs/x.md"),
        ] {
            assert_eq!(at(loose), at(strict));
            assert_eq!(at(loose).to_string(), strict);
        }
        for bad in [
            "", "//", "/a/", "a/", "/a//b", "a//b", "/ a", "/a ", "/.", "/..",
        ] {
            let err = Path::new(bad).unwrap_err().to_string();
            assert!(err.starts_with(&format!("{bad}: ")), "'{bad}' gave: {err}");
        }
    }

    #[test]
    fn join_concatenates_and_the_root_is_the_identity() {
        assert_eq!(at("/a").join(&at("/b/c")), at("/a/b/c"));
        assert_eq!(at("/").join(&at("/x")), at("/x"));
        assert_eq!(at("/x").join(&at("/")), at("/x"));
        assert_eq!(at("/").join(&at("/")), at("/"));
    }

    #[test]
    fn order_is_segment_wise() {
        assert!(at("/a/b") < at("/a-b"));
        assert!(at("/") < at("/a"));
        assert_eq!(format!("{:?}", at("/a/b")), "\"/a/b\"");
    }
}
