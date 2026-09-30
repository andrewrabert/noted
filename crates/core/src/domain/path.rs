//! The base path: a list of Segments with one spelling. Every frame composes
//! it and adds its own rule; none restates the spelling.
//!
//! Spelling: `/` alone is the root (zero segments); otherwise exactly one
//! separator between segments and none after the last. The leading separator
//! is optional on input (`a/b` reads as `/a/b`) and always present on output.
//! Never empty: the empty string is malformed, not the root. No OS meaning.

use std::fmt;

use super::segment::{Segment, Segments};
use crate::error::{Result, rejected};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Path {
    segments: Segments,
}

impl Path {
    pub(crate) const SEPARATOR: &str = "/";

    pub(super) fn new(raw: &str) -> Result<Path> {
        Path::parse(raw)
            .map(|segments| Path {
                segments: Segments(segments),
            })
            .map_err(|reason| rejected(format!("{raw}: {reason}")))
    }

    fn parse(raw: &str) -> Result<Vec<Segment>> {
        if raw.is_empty() {
            return Err(rejected("must not be empty"));
        }
        let rest = raw.strip_prefix(Path::SEPARATOR).unwrap_or(raw);
        if rest.is_empty() {
            return Ok(Vec::new());
        }
        let segments: Vec<Segment> = rest
            .split(Path::SEPARATOR)
            .map(str::parse)
            .collect::<Result<_>>()?;
        if let Some((_, dirs)) = segments.split_last() {
            if dirs
                .iter()
                .any(|s| matches!(s, Segment::TaskDir(_) | Segment::LogDir(_)))
            {
                return Err(rejected("nothing follows a task or log directory"));
            }
            if dirs.iter().any(|s| matches!(s, Segment::Note(_))) {
                return Err(rejected("nothing follows a note file"));
            }
        }
        Ok(segments)
    }

    pub(super) fn segments(&self) -> &Segments {
        &self.segments
    }
}

impl From<Segments> for Path {
    fn from(segments: Segments) -> Path {
        Path { segments }
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.segments.0.is_empty() {
            return f.write_str(Path::SEPARATOR);
        }
        for part in &self.segments {
            f.write_str(Path::SEPARATOR)?;
            write!(f, "{part}")?;
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
        for good in ["/", "/a", "/a.md", "/a/b c", "/a/b c.md", "/dev/#2/note.md"] {
            assert_eq!(at(good).to_string(), good);
            assert_eq!(Path::new(&at(good).to_string()).unwrap(), at(good));
        }
        assert_eq!(at("/").segments().into_iter().count(), 0);
        assert_eq!(
            at("/a/b")
                .segments()
                .into_iter()
                .map(Segment::to_string)
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        for (loose, strict) in [("a", "/a"), ("a/b c", "/a/b c")] {
            assert_eq!(at(loose), at(strict));
            assert_eq!(at(loose).to_string(), strict);
        }
        for bad in [
            "",
            "//",
            "/a/",
            "a/",
            "/a//b",
            "a//b",
            "/ a",
            "/a ",
            "/.",
            "/..",
            "/#0",
            "/a/#/b",
            "/a/@/b",
            "/a.md/b",
            "/a/b.md/c.md",
        ] {
            let err = Path::new(bad).unwrap_err().to_string();
            assert!(err.starts_with(&format!("{bad}: ")), "'{bad}' gave: {err}");
        }
    }

    #[test]
    fn order_is_segment_wise() {
        assert!(at("/a/b") < at("/a-b"));
        assert!(at("/") < at("/a"));
        assert!(at("/#2") < at("/a"));
        assert_eq!(format!("{:?}", at("/a/b")), "\"/a/b\"");
    }
}
