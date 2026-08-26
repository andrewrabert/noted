use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{NotedError, Result, rejected};
use crate::front_matter::{FrontMatter, split_front};
use crate::path::Path;
use crate::search::SearchQuery;
use crate::timerange::TimeRange;
use crate::types::{NoteBody, Source, Timestamp};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Etag([u8; 32]);

impl Etag {
    pub(crate) fn of(bytes: &[u8]) -> Etag {
        Etag(Sha256::digest(bytes).into())
    }
}

impl fmt::Display for Etag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for Etag {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<Etag> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|_| rejected("invalid write condition token"))?;
        Ok(Etag(out))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Condition {
    #[default]
    Always,
    Missing,
    Exists,
    Matching(Etag),
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Condition::Always => f.write_str("always"),
            Condition::Missing => f.write_str("missing"),
            Condition::Exists => f.write_str("exists"),
            Condition::Matching(token) => write!(f, "exists:{token}"),
        }
    }
}

impl FromStr for Condition {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<Condition> {
        match s.split_once(':') {
            Some(("exists", token)) => Ok(Condition::Matching(token.parse()?)),
            None | Some(_) => match s {
                "always" => Ok(Condition::Always),
                "missing" => Ok(Condition::Missing),
                "exists" => Ok(Condition::Exists),
                other => Err(rejected(format!("unknown write condition: '{other}'"))),
            },
        }
    }
}

impl TryFrom<String> for Condition {
    type Error = NotedError;
    fn try_from(s: String) -> Result<Condition> {
        s.parse()
    }
}

impl From<Condition> for String {
    fn from(c: Condition) -> String {
        c.to_string()
    }
}

pub struct Edit {
    old: String,
    new: String,
    replace_all: bool,
}

impl Edit {
    pub fn new(old: impl Into<String>, new: impl Into<String>, replace_all: bool) -> Edit {
        Edit {
            old: old.into(),
            new: new.into(),
            replace_all,
        }
    }

    pub(crate) fn apply(&self, body: &NoteBody) -> Result<NoteBody> {
        let count = body.as_str().matches(&self.old).count();
        if count == 0 {
            return Err(rejected("old string not found"));
        }
        if count > 1 && !self.replace_all {
            return Err(rejected(format!(
                "old string not unique ({count} matches); pass replace_all"
            )));
        }
        Ok(NoteBody::new(body.as_str().replace(&self.old, &self.new)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trashed(Path);

impl Trashed {
    pub(crate) fn new(path: Path) -> Trashed {
        Trashed(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl fmt::Display for Trashed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The one contract every note kind shares: it can serialize itself to the exact
/// bytes it persists as. Everything else — mutability, schema, immutability — is
/// the concern of the specific kind.
pub trait Note {
    fn to_bytes(&self) -> Vec<u8>;
}

/// A freeform, mutable, unstructured markdown note — the default kind. No schema,
/// no lifecycle. It is what remains once you take away a task's state machine and
/// a log's immutability.
#[derive(Clone, Debug)]
pub struct TextNote {
    path: Path,
    body: NoteBody,
}

impl TextNote {
    pub fn new(path: Path, body: impl Into<NoteBody>) -> TextNote {
        TextNote {
            path,
            body: body.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn body(&self) -> &NoteBody {
        &self.body
    }

    pub fn etag(&self) -> Etag {
        Etag::of(self.body.as_str().as_bytes())
    }

    pub fn with_body(mut self, body: impl Into<NoteBody>) -> TextNote {
        self.body = body.into();
        self
    }

    pub fn with_path(mut self, path: Path) -> TextNote {
        self.path = path;
        self
    }
}

impl Note for TextNote {
    fn to_bytes(&self) -> Vec<u8> {
        self.body.as_str().as_bytes().to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct LogFront {
    pub created: Timestamp,
    pub cwd: String,
    pub host: String,
    pub source: Option<Source>,
}

impl LogFront {
    pub(crate) fn read(front: &FrontMatter) -> Result<LogFront> {
        Ok(LogFront {
            created: front.field("created")?,
            cwd: front.get("cwd").unwrap_or_default().to_string(),
            host: front.get("host").unwrap_or_default().to_string(),
            source: front.opt_field("source")?,
        })
    }

    pub(crate) fn write(&self) -> FrontMatter {
        let mut front = FrontMatter::default();
        front.set("created", self.created.to_string());
        front.set("cwd", self.cwd.clone());
        front.set("host", self.host.clone());
        front.set_opt("source", self.source.clone().map(String::from));
        front
    }
}

pub struct LogQuery {
    pub range: TimeRange,
    pub query: SearchQuery,
    pub limit: u32,
}

#[derive(Debug)]
pub struct LogNote {
    path: Path,
    front: LogFront,
    body: String,
}

impl LogNote {
    pub(crate) fn new(path: Path, front: LogFront, body: impl Into<String>) -> LogNote {
        LogNote {
            path,
            front,
            body: body.into(),
        }
    }

    pub(crate) fn from_bytes(path: Path, bytes: &[u8]) -> Result<LogNote> {
        let text = std::str::from_utf8(bytes).map_err(|_| rejected("not a log entry"))?;
        let (block, body) = split_front(text).ok_or_else(|| rejected("not a log entry"))?;
        let front = FrontMatter::parse(block).map_err(|_| rejected("not a log entry"))?;
        let front = LogFront::read(&front).map_err(|_| rejected("not a log entry"))?;
        Ok(LogNote::new(path, front, body))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn front(&self) -> &LogFront {
        &self.front
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn etag(&self) -> Etag {
        Etag::of(&self.to_bytes())
    }
}

impl Note for LogNote {
    fn to_bytes(&self) -> Vec<u8> {
        self.front.write().dump(&self.body).into_bytes()
    }
}
