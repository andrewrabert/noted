use std::fmt;
use std::path::{Component, Path as StdPath, PathBuf};
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{NotedError, Result, rejected};
use crate::util::case_order;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Segment(String);

impl Segment {
    pub fn new(s: impl Into<String>) -> Result<Segment> {
        let s = s.into();
        let mut components = StdPath::new(&s).components();
        let valid = matches!(
            (components.next(), components.next()),
            (Some(Component::Normal(part)), None) if part.to_str() == Some(s.as_str())
        ) && !s.starts_with('.');
        if !valid {
            return Err(rejected(format!("invalid path segment: '{s}'")));
        }
        Ok(Segment(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Segment {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<Segment> {
        Segment::new(s)
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// the hidden leaf names noted addresses; nothing caller-supplied names one
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reserved {
    TaskBody,
}

impl Reserved {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Reserved::TaskBody => ".task.md",
        }
    }
}

// Tool-schema field: a rustdoc comment here ships as the wire description.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct Path(PathBuf);

impl Path {
    pub fn new(s: impl AsRef<str>) -> Result<Path> {
        let raw = s.as_ref();
        let mut out = PathBuf::new();
        for component in StdPath::new(raw).components() {
            let part = match component {
                Component::CurDir => continue,
                Component::Normal(part) => part
                    .to_str()
                    .ok_or_else(|| rejected(format!("invalid path: '{raw}'")))?,
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(rejected(format!("path escapes notes root: '{raw}'")));
                }
            };
            if part.starts_with('.') {
                return Err(rejected(format!("invalid path: '{raw}'")));
            }
            out.push(part);
        }
        if out.as_os_str().is_empty() {
            return Err(rejected("path cannot be empty"));
        }
        Ok(Path(out))
    }

    // parses a path read back off disk, admitting a trailing reserved leaf;
    // every other dotted component is still refused
    pub(crate) fn stored(s: &str) -> Result<Path> {
        for leaf in [Reserved::TaskBody] {
            if let Some(head) = s.strip_suffix(leaf.as_str())
                && let Some(head) = head.strip_suffix('/')
            {
                return Ok(Path::new(head)?.joined_reserved(leaf));
            }
        }
        Path::new(s)
    }

    // appends a reserved leaf; the only way a Path names a dotted file
    pub(crate) fn joined_reserved(&self, leaf: Reserved) -> Path {
        Path(self.0.join(leaf.as_str()))
    }

    pub fn as_str(&self) -> &str {
        match self.0.to_str() {
            Some(path) => path,
            None => unreachable!("Path is always constructed from UTF-8"),
        }
    }

    pub(crate) fn under(&self, base: &Path) -> bool {
        self.0.starts_with(&base.0)
    }

    pub(crate) fn join(&self, rest: &Path) -> Path {
        Path(self.0.join(&rest.0))
    }

    pub(crate) fn joined(&self, rest: &str) -> Result<Path> {
        Ok(self.join(&Path::new(rest)?))
    }

    pub(crate) fn file_name(&self) -> &str {
        match self.0.file_name().and_then(|name| name.to_str()) {
            Some(name) => name,
            None => unreachable!("Path is non-empty UTF-8"),
        }
    }

    pub(crate) fn parent(&self) -> Option<Path> {
        self.0
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(|parent| Path(parent.to_path_buf()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DirPath(String);

impl DirPath {
    pub fn root() -> DirPath {
        DirPath("/".to_string())
    }

    pub(crate) fn child(&self, name: &str) -> DirPath {
        DirPath(format!("{}{name}/", self.0))
    }

    pub fn join(&self, rel: &Path) -> DirPath {
        self.child(rel.as_str())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    // None for the notes root, whose trimmed form is the empty path
    pub fn to_path(&self) -> Option<Path> {
        Path::stored(self.0.trim_matches('/')).ok()
    }

    pub fn relative(&self, at: &Path) -> Option<Path> {
        let full = format!("/{}", at.as_str());
        Path::stored(full.strip_prefix(&self.0)?).ok()
    }
}

impl fmt::Display for DirPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Path {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<Path> {
        Path::new(s)
    }
}

impl TryFrom<String> for Path {
    type Error = NotedError;
    fn try_from(s: String) -> Result<Path> {
        Path::new(s)
    }
}

impl Ord for Path {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        case_order(self.as_str(), other.as_str())
    }
}

impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<Path> for String {
    fn from(p: Path) -> String {
        p.0.to_string_lossy().into_owned()
    }
}

impl PartialEq<str> for Path {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Path {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separators_and_cur_dirs_collapse() {
        assert_eq!(Path::new("a//b/./c").unwrap(), "a/b/c");
        assert_eq!(Path::new("./a").unwrap(), "a");
        assert!(Path::new(".").is_err());
        assert!(Path::new("").is_err());
    }

    #[test]
    fn escapes_and_hidden_are_refused() {
        for bad in ["..", "a/../b", "/a", "a/.hidden", ".trash"] {
            assert!(Path::new(bad).is_err(), "accepted '{bad}'");
        }
    }

    #[test]
    fn under_is_component_wise() {
        let docs = Path::new("docs").unwrap();
        assert!(Path::new("docs/a").unwrap().under(&docs));
        assert!(docs.under(&docs));
        assert!(!Path::new("docsX").unwrap().under(&docs));
    }

    #[test]
    fn a_directory_always_closes_with_a_separator() {
        let root = DirPath::root();
        assert_eq!(root.as_str(), "/");
        assert_eq!(root.to_path(), None);

        let log = root.child("Log");
        assert_eq!(log.as_str(), "/Log/");
        assert_eq!(log.to_path().unwrap(), "Log");
        assert_eq!(log.join(&Path::new("a/b").unwrap()).as_str(), "/Log/a/b/");
    }

    #[test]
    fn relative_re_expresses_only_what_lies_inside() {
        let work = DirPath::root().child("work");
        assert_eq!(
            work.relative(&Path::new("work/a.md").unwrap()).unwrap(),
            "a.md"
        );
        assert_eq!(work.relative(&Path::new("workshop/a.md").unwrap()), None);
        assert_eq!(work.relative(&Path::new("work").unwrap()), None);
    }
}
