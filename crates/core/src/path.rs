use std::fmt;
use std::path::{Component, Path as StdPath, PathBuf};
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{NotedError, Result, rejected};

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

    pub fn as_str(&self) -> &str {
        match self.0.to_str() {
            Some(path) => path,
            None => unreachable!("Path is always constructed from UTF-8"),
        }
    }

    pub(crate) fn under(&self, base: &Path) -> bool {
        self.0.starts_with(&base.0)
    }

    pub(crate) fn ancestors(&self) -> impl Iterator<Item = Path> + '_ {
        self.0
            .ancestors()
            .take_while(|path| !path.as_os_str().is_empty())
            .map(|path| Path(path.to_path_buf()))
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
        self.as_str()
            .to_lowercase()
            .cmp(&other.as_str().to_lowercase())
            .then_with(|| self.0.cmp(&other.0))
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
    fn ancestors_run_nearest_first_to_the_top_level() {
        let path = Path::new("a/b/c").unwrap();
        let seen: Vec<String> = path.ancestors().map(|p| p.to_string()).collect();
        assert_eq!(seen, ["a/b/c", "a/b", "a"]);
    }
}
