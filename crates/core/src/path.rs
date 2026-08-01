use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{NotedError, Result, rejected};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Segment(String);

impl Segment {
    pub fn new(s: impl Into<String>) -> Result<Segment> {
        let s = s.into();
        if s.is_empty() || s.contains('/') || s.starts_with('.') {
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
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct RelPath(String);

impl RelPath {
    pub fn new(s: impl Into<String>) -> Result<RelPath> {
        let s = s.into();
        if s.is_empty() {
            return Ok(RelPath(s));
        }
        if s.starts_with('/') {
            return Err(rejected(format!("path escapes notes root: '{s}'")));
        }
        for part in s.split('/') {
            if part == ".." {
                return Err(rejected(format!("path escapes notes root: '{s}'")));
            }
            if part.is_empty() || part.starts_with('.') {
                return Err(rejected(format!("invalid path: '{s}'")));
            }
        }
        Ok(RelPath(s))
    }

    pub(crate) fn trusted(s: impl Into<String>) -> RelPath {
        RelPath(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn under(&self, base: &RelPath) -> bool {
        base.0.is_empty() || self.0 == base.0 || self.0.starts_with(&format!("{}/", base.0))
    }

    pub(crate) fn joined(&self, rest: &str) -> RelPath {
        match (self.0.is_empty(), rest.is_empty()) {
            (true, _) => RelPath(rest.to_string()),
            (false, true) => self.clone(),
            (false, false) => RelPath(format!("{}/{rest}", self.0)),
        }
    }

    pub(crate) fn join(&self, rest: &RelPath) -> RelPath {
        self.joined(&rest.0)
    }

    pub(crate) fn file_name(&self) -> &str {
        match self.0.rsplit_once('/') {
            Some((_, name)) => name,
            None => &self.0,
        }
    }

    pub(crate) fn parent(&self) -> RelPath {
        match self.0.rsplit_once('/') {
            Some((dir, _)) => RelPath(dir.to_string()),
            None => RelPath(String::new()),
        }
    }

    pub(crate) fn with_file_name(&self, name: &str) -> RelPath {
        self.parent().joined(name)
    }
}

impl FromStr for RelPath {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<RelPath> {
        RelPath::new(s)
    }
}

impl TryFrom<String> for RelPath {
    type Error = NotedError;
    fn try_from(s: String) -> Result<RelPath> {
        RelPath::new(s)
    }
}

impl Ord for RelPath {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .to_lowercase()
            .cmp(&other.0.to_lowercase())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for RelPath {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::ops::Deref for RelPath {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<RelPath> for String {
    fn from(r: RelPath) -> String {
        r.0
    }
}

impl AsRef<str> for RelPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for RelPath {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for RelPath {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for RelPath {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}
