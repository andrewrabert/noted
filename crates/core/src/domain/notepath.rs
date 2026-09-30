//! Which note. Measured from the holder's scope. The segment
//! grammar already keeps every name free of a leading `.`, so the store's own
//! directories, `.trash` and every dotfile are unspellable. `NotePath::new` is
//! the crate's only public parse door; serde enters through it.

use std::borrow::Cow;
use std::fmt;
use std::num::NonZeroU64;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::path::Path;
use super::segment::{Log, Segment, Segments, Task, TaskDir};
use crate::error::{NotedError, Result, rejected};
use crate::types::Timestamp;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NotePath(Path);

impl NotePath {
    pub fn new(raw: &str) -> Result<NotePath> {
        Path::new(raw).map(NotePath)
    }

    pub(super) fn segments(&self) -> &Segments {
        self.0.segments()
    }

    pub(crate) fn starts_with(&self, other: &NotePath) -> bool {
        self.segments().0.starts_with(&other.segments().0)
    }

    pub(crate) fn from_store(store_path: &str) -> Result<NotePath> {
        Segments::from_store(store_path).map(|segments| NotePath(Path::from(segments)))
    }

    pub(crate) fn to_store_file(&self) -> Result<Vec<String>> {
        self.segments().to_store_file()
    }

    pub(crate) fn to_store_dir(&self) -> Result<Vec<String>> {
        self.segments().to_store_dir()
    }

    // `rel` measured from this path; nothing follows a task or log directory
    pub(crate) fn join(&self, rel: &NotePath) -> Result<NotePath> {
        rel.segments()
            .into_iter()
            .try_fold(self.clone(), |at, part| at.with(part.clone()))
    }

    // this path without its last segment; the root has none to drop. A note
    // is only ever last, so what remains is a directory
    pub(crate) fn parent(&self) -> Result<DirPath> {
        let mut parts = self.segments().0.clone();
        parts
            .pop()
            .ok_or_else(|| rejected(format!("{self}: the root has no parent")))?;
        Ok(DirPath(NotePath(Path::from(Segments(parts)))))
    }

    // this path with one more segment; nothing follows a task or log
    // directory, nor a note file
    fn with(&self, last: Segment) -> Result<NotePath> {
        match self.last() {
            Some(Segment::TaskDir(_) | Segment::LogDir(_)) => {
                return Err(rejected(format!(
                    "{self}: nothing follows a task or log directory"
                )));
            }
            Some(Segment::Note(_)) => {
                return Err(rejected(format!("{self}: nothing follows a note file")));
            }
            _ => {}
        }
        let mut parts = self.segments().0.clone();
        parts.push(last);
        Ok(NotePath(Path::from(Segments(parts))))
    }

    fn last(&self) -> Option<&Segment> {
        self.segments().0.last()
    }
}

#[derive(
    Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(try_from = "NotePath")]
#[schemars(with = "NotePath")]
pub struct DirPath(NotePath);

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(try_from = "NotePath")]
#[schemars(with = "NotePath")]
pub struct TextPath(NotePath);

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(try_from = "NotePath")]
#[schemars(with = "NotePath")]
pub struct TaskPath(NotePath);

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(try_from = "NotePath")]
#[schemars(with = "NotePath")]
pub struct LogPath(NotePath);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TaskDirPath(NotePath);

impl AsRef<NotePath> for NotePath {
    fn as_ref(&self) -> &NotePath {
        self
    }
}

// the root, or any path not ending in a note file
impl TryFrom<NotePath> for DirPath {
    type Error = NotedError;

    fn try_from(at: NotePath) -> Result<DirPath> {
        match at.last() {
            Some(Segment::Note(_)) => Err(rejected(format!("{at}: not a directory"))),
            _ => Ok(DirPath(at)),
        }
    }
}

impl AsRef<NotePath> for DirPath {
    fn as_ref(&self) -> &NotePath {
        &self.0
    }
}

impl fmt::Display for DirPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// a note file, and only that
impl TryFrom<NotePath> for TextPath {
    type Error = NotedError;

    fn try_from(at: NotePath) -> Result<TextPath> {
        match at.last() {
            Some(Segment::Note(_)) => Ok(TextPath(at)),
            _ => Err(rejected(format!("{at}: not a note"))),
        }
    }
}

impl AsRef<NotePath> for TextPath {
    fn as_ref(&self) -> &NotePath {
        &self.0
    }
}

impl fmt::Display for TextPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TaskPath {
    pub(crate) fn new(dir: &DirPath, number: NonZeroU64) -> Result<TaskPath> {
        dir.0.with(Segment::Task(Task::new(number))).map(TaskPath)
    }

    // the number its last segment carries
    pub(crate) fn number(&self) -> NonZeroU64 {
        match self.0.last() {
            Some(Segment::Task(task)) => task.number(),
            _ => unreachable!("a task path ends in a task"),
        }
    }
}

impl TryFrom<NotePath> for TaskPath {
    type Error = NotedError;

    fn try_from(at: NotePath) -> Result<TaskPath> {
        match at.last() {
            Some(Segment::Task(_)) => Ok(TaskPath(at)),
            _ => Err(rejected(format!("{at}: not a task"))),
        }
    }
}

impl AsRef<NotePath> for TaskPath {
    fn as_ref(&self) -> &NotePath {
        &self.0
    }
}

impl fmt::Display for TaskPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl LogPath {
    pub(crate) fn new(dir: &DirPath, created: Timestamp) -> Result<LogPath> {
        dir.0.with(Segment::Log(Log::new(created))).map(LogPath)
    }

    // the instant its last segment carries
    pub(crate) fn created(&self) -> Timestamp {
        match self.0.last() {
            Some(Segment::Log(log)) => log.created(),
            _ => unreachable!("a log path ends in a log entry"),
        }
    }
}

impl TryFrom<NotePath> for LogPath {
    type Error = NotedError;

    fn try_from(at: NotePath) -> Result<LogPath> {
        match at.last() {
            Some(Segment::Log(_)) => Ok(LogPath(at)),
            _ => Err(rejected(format!("{at}: not a log entry"))),
        }
    }
}

impl AsRef<NotePath> for LogPath {
    fn as_ref(&self) -> &NotePath {
        &self.0
    }
}

impl fmt::Display for LogPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TaskDirPath {
    pub(crate) fn new(dir: &DirPath) -> Result<TaskDirPath> {
        dir.0.with(Segment::TaskDir(TaskDir)).map(TaskDirPath)
    }
}

impl AsRef<NotePath> for TaskDirPath {
    fn as_ref(&self) -> &NotePath {
        &self.0
    }
}

impl Default for NotePath {
    fn default() -> NotePath {
        NotePath::new(Path::SEPARATOR).expect("the root is a note path")
    }
}

/// A list of spelled segments, as a walk reports them; each part goes through
/// the one parse door.
impl TryFrom<Vec<String>> for NotePath {
    type Error = crate::error::NotedError;

    fn try_from(parts: Vec<String>) -> Result<NotePath> {
        NotePath::new(&format!(
            "{}{}",
            Path::SEPARATOR,
            parts.join(Path::SEPARATOR)
        ))
    }
}

impl fmt::Display for NotePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for NotePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_string())
    }
}

impl Serialize for NotePath {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for NotePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        NotePath::new(&raw).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for NotePath {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("NotePath")
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "default": Path::SEPARATOR,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NotePath {
        NotePath::new(s).unwrap()
    }

    #[test]
    fn a_note_path_never_has_a_dotted_segment() {
        assert_eq!(at("/a/b").to_string(), "/a/b");
        assert_eq!(at("/"), NotePath::default());
        assert_eq!(at("a/b"), at("/a/b"));
        assert_eq!(at("/a/b.md").to_string(), "/a/b.md");
        for bad in [
            "/.logs",
            ".logs",
            "/.tasks",
            "/a/.hidden",
            "",
            "/a/",
            "/a/b.md/c",
            "/a.md/b.md",
        ] {
            assert!(NotePath::new(bad).is_err(), "accepted '{bad}'");
        }
    }

    #[test]
    fn hash_prefixes_are_tasks_at_every_depth() {
        for good in ["/#42", "/a/#42/note.md", "/a/#2/#1"] {
            assert_eq!(at(good).to_string(), good);
        }
        for bad in ["#", "#042", "/#ideas", "/a/#note"] {
            assert!(NotePath::new(bad).is_err(), "accepted '{bad}'");
            let json = serde_json::to_string(bad).unwrap();
            assert!(serde_json::from_str::<NotePath>(&json).is_err());
        }
        for good in ["/a#42", "/a#b/note.md"] {
            assert_eq!(at(good).to_string(), good);
        }
    }

    #[test]
    fn the_store_spelling_round_trips() {
        for good in ["/a/b.md", "/dev/#2", "/dev/#2/plan.md"] {
            let file = at(good).to_store_file().unwrap();
            let file = format!("/{}", file.join("/"));
            assert_eq!(NotePath::from_store(&file).unwrap(), at(good));
        }
        assert!(TaskPath::try_from(at("/dev/#2")).is_ok());
        assert!(TaskPath::try_from(at("/dev/plan.md")).is_err());
        assert!(TextPath::try_from(NotePath::default()).is_err());
        assert!(TextPath::try_from(at("/dev/plan")).is_err());
        assert!(DirPath::try_from(at("/dev/plan")).is_ok());
        assert!(DirPath::try_from(at("/dev/plan.md")).is_err());
        assert_eq!(
            at("/dev/plan.md").parent().unwrap(),
            DirPath::try_from(at("/dev")).unwrap()
        );
        assert!(serde_json::from_str::<TextPath>("\"/dev/#2\"").is_err());
    }

    #[test]
    fn serde_goes_through_the_one_door() {
        assert_eq!(serde_json::to_string(&at("/a/b")).unwrap(), "\"/a/b\"");
        assert_eq!(
            serde_json::from_str::<NotePath>("\"/\"").unwrap(),
            NotePath::default()
        );
        assert!(serde_json::from_str::<NotePath>("\"/.logs\"").is_err());
        assert!(serde_json::from_str::<NotePath>("\"\"").is_err());
        let schema = serde_json::to_value(schemars::schema_for!(NotePath)).unwrap();
        assert_eq!(schema["type"], "string");
        assert_eq!(schema["default"], "/");
        assert!(schema.get("pattern").is_none());
    }
}
