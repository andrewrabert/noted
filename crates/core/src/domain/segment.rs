//! The one grammar that tells the three sorts of segment apart (a task, a log
//! entry, anything else is a name) and the one place a segment list is
//! translated to and from its store spelling.

use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;

use super::path::Path;
use crate::error::{NotedError, Result, rejected};
use crate::types::Timestamp;

/// One part of a segment list. Ordered a group's task directory first, then
/// tasks (by number), then its log directory, then entries (by instant), then
/// names.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Segment {
    TaskDir(TaskDir),
    Task(Task),
    LogDir(LogDir),
    Log(Log),
    Dir(Dir),
    Note(Note),
}

/// The directory holding a group's tasks; nothing follows it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct TaskDir;

/// The directory holding a group's log entries; nothing follows it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct LogDir;

/// A task: a positive number with no leading zero.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct Task(NonZeroU64);

/// The instant a write-once entry was created.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct Log(Timestamp);

/// A plain directory, spelled as given; it has no file.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct Dir(String);

/// A note file, stored as its stem; spelled with the note suffix; always last.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct Note(String);

/// A list of segments; the body of every path frame.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct Segments(pub(super) Vec<Segment>);

impl TaskDir {
    pub(crate) const PREFIX: char = '#';
    const DIR: &str = ".tasks";

    fn write_dir(&self, out: &mut Vec<String>) {
        out.push(TaskDir::DIR.to_string());
    }
}

impl FromStr for TaskDir {
    type Err = &'static str;

    fn from_str(part: &str) -> std::result::Result<TaskDir, Self::Err> {
        (part.strip_prefix(TaskDir::PREFIX) == Some(""))
            .then_some(TaskDir)
            .ok_or("a task directory is its prefix alone")
    }
}

impl fmt::Display for TaskDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", TaskDir::PREFIX)
    }
}

impl Task {
    const FILE: &str = ".task.md";

    pub(super) fn new(number: NonZeroU64) -> Task {
        Task(number)
    }

    pub(super) fn number(&self) -> NonZeroU64 {
        self.0
    }

    // the number, then either the task's file as the very last part or
    // whatever lives inside the task
    fn from_store<'a, 'b>(parts: &'a [&'b str]) -> Result<(Segment, &'a [&'b str])> {
        let [number, rest @ ..] = parts else {
            return Err(rejected("a task directory holds a number"));
        };
        let task = number
            .parse::<NonZeroU64>()
            .ok()
            .filter(|n| n.to_string() == *number)
            .map(Task)
            .ok_or_else(|| rejected(format!("{number}: not a task number")))?;
        match rest {
            [Task::FILE] => Ok((Segment::Task(task), &[])),
            [Task::FILE, ..] => Err(rejected("a task file is the last part")),
            _ => Ok((Segment::Task(task), rest)),
        }
    }

    fn write_dir(&self, out: &mut Vec<String>) {
        out.push(TaskDir::DIR.to_string());
        out.push(self.0.to_string());
    }

    fn write_file(&self, out: &mut Vec<String>) {
        self.write_dir(out);
        out.push(Task::FILE.to_string());
    }
}

impl FromStr for Task {
    type Err = &'static str;

    fn from_str(part: &str) -> std::result::Result<Task, Self::Err> {
        part.strip_prefix(TaskDir::PREFIX)
            .and_then(|task| task.parse::<NonZeroU64>().ok())
            .map(Task)
            .filter(|task| task.to_string() == part)
            .ok_or("a task is its prefix and a positive number with no leading zero")
    }
}

impl fmt::Display for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", TaskDir::PREFIX, self.0)
    }
}

impl LogDir {
    pub(crate) const PREFIX: char = '@';
    const DIR: &str = ".logs";

    fn write_dir(&self, out: &mut Vec<String>) {
        out.push(LogDir::DIR.to_string());
    }
}

impl FromStr for LogDir {
    type Err = &'static str;

    fn from_str(part: &str) -> std::result::Result<LogDir, Self::Err> {
        (part.strip_prefix(LogDir::PREFIX) == Some(""))
            .then_some(LogDir)
            .ok_or("a log directory is its prefix alone")
    }
}

impl fmt::Display for LogDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", LogDir::PREFIX)
    }
}

impl Log {
    const FILE: &str = ".log.md";

    pub(super) fn new(created: Timestamp) -> Log {
        Log(created)
    }

    pub(super) fn created(&self) -> Timestamp {
        self.0
    }

    // the instant, then either the entry's file as the very last part or
    // whatever lives inside the entry
    fn from_store<'a, 'b>(parts: &'a [&'b str]) -> Result<(Segment, &'a [&'b str])> {
        let [stamp, rest @ ..] = parts else {
            return Err(rejected("a log directory holds an instant"));
        };
        let log = stamp
            .parse::<Timestamp>()
            .ok()
            .filter(|at| at.to_string() == *stamp)
            .map(Log)
            .ok_or_else(|| rejected(format!("{stamp}: not a log instant")))?;
        match rest {
            [Log::FILE] => Ok((Segment::Log(log), &[])),
            [Log::FILE, ..] => Err(rejected("a log file is the last part")),
            _ => Ok((Segment::Log(log), rest)),
        }
    }

    fn write_dir(&self, out: &mut Vec<String>) {
        out.push(LogDir::DIR.to_string());
        out.push(self.0.to_string());
    }

    fn write_file(&self, out: &mut Vec<String>) {
        self.write_dir(out);
        out.push(Log::FILE.to_string());
    }
}

impl FromStr for Log {
    type Err = &'static str;

    fn from_str(part: &str) -> std::result::Result<Log, Self::Err> {
        part.strip_prefix(LogDir::PREFIX)
            .and_then(|log| log.parse::<Timestamp>().ok())
            .map(Log)
            .filter(|log| log.to_string() == part)
            .ok_or("a log entry is its prefix and a canonical timestamp")
    }
}

impl fmt::Display for Log {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", LogDir::PREFIX, self.0)
    }
}

// the name rules shared by a directory and a note stem
fn check_name(name: &str) -> std::result::Result<(), &'static str> {
    let reason = match name {
        "" => "a segment has at least one character",
        "." | ".." => "a segment is a name other than '.' or '..'",
        _ if name.starts_with('.') => "a name does not start with '.'",
        _ if name.trim() != name => "a segment starts and ends with a visible character",
        _ if name.contains('\0') => "a segment is free of NUL",
        _ if name.len() > 255 => "a segment is at most 255 bytes",
        _ if name.ends_with(Note::SUFFIX) => "a name does not carry the note file suffix",
        _ if name.starts_with(TaskDir::PREFIX) => "a name does not start with the task prefix",
        _ if name.starts_with(LogDir::PREFIX) => "a name does not start with the log prefix",
        _ => return Ok(()),
    };
    Err(reason)
}

impl Dir {
    fn write_dir(&self, out: &mut Vec<String>) {
        out.push(self.0.clone());
    }
}

impl FromStr for Dir {
    type Err = &'static str;

    fn from_str(part: &str) -> std::result::Result<Dir, Self::Err> {
        check_name(part).map(|()| Dir(part.to_string()))
    }
}

impl fmt::Display for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Note {
    const SUFFIX: &str = ".md";

    pub(super) fn new(name: &str) -> Result<Note> {
        check_name(name)
            .map(|()| Note(name.to_string()))
            .map_err(rejected)
    }

    // a last part is a note file, its suffix stripped; any other part is a
    // directory
    fn from_store<'a, 'b>(parts: &'a [&'b str]) -> Result<(Segment, &'a [&'b str])> {
        match parts {
            [] => Err(rejected("a note has a name")),
            [file] => {
                let name = file
                    .strip_suffix(Note::SUFFIX)
                    .ok_or_else(|| rejected(format!("{file}: not a note file")))?;
                Ok((Segment::Note(Note::new(name)?), &[]))
            }
            [dir, rest @ ..] => Ok((Segment::Dir(dir.parse().map_err(rejected)?), rest)),
        }
    }

    fn write_file(&self, out: &mut Vec<String>) {
        out.push(format!("{}{}", self.0, Note::SUFFIX));
    }
}

impl Segment {
    fn write_dir(&self, out: &mut Vec<String>) {
        match self {
            Segment::TaskDir(tasks) => tasks.write_dir(out),
            Segment::Task(task) => task.write_dir(out),
            Segment::LogDir(logs) => logs.write_dir(out),
            Segment::Log(log) => log.write_dir(out),
            Segment::Dir(dir) => dir.write_dir(out),
            Segment::Note(_) => unreachable!("nothing follows a note file"),
        }
    }

    fn write_file(&self, out: &mut Vec<String>) {
        match self {
            Segment::TaskDir(_) | Segment::LogDir(_) | Segment::Dir(_) => {
                unreachable!("a directory has no file")
            }
            Segment::Task(task) => task.write_file(out),
            Segment::Log(log) => log.write_file(out),
            Segment::Note(note) => note.write_file(out),
        }
    }
}

impl FromStr for Segment {
    type Err = NotedError;

    fn from_str(part: &str) -> Result<Segment> {
        match part {
            _ if part.parse::<TaskDir>().is_ok() => Ok(Segment::TaskDir(TaskDir)),
            _ if part.starts_with(TaskDir::PREFIX) => {
                part.parse().map(Segment::Task).map_err(rejected)
            }
            _ if part.parse::<LogDir>().is_ok() => Ok(Segment::LogDir(LogDir)),
            _ if part.starts_with(LogDir::PREFIX) => {
                part.parse().map(Segment::Log).map_err(rejected)
            }
            _ => match part.strip_suffix(Note::SUFFIX) {
                Some(stem) => Note::new(stem).map(Segment::Note),
                None => part.parse().map(Segment::Dir).map_err(rejected),
            },
        }
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Segment::TaskDir(tasks) => tasks.fmt(f),
            Segment::Task(task) => task.fmt(f),
            Segment::LogDir(logs) => logs.fmt(f),
            Segment::Log(log) => log.fmt(f),
            Segment::Dir(dir) => dir.fmt(f),
            Segment::Note(Note(note)) => write!(f, "{note}{}", Note::SUFFIX),
        }
    }
}

impl Segments {
    // dispatch on the head only; each sort reads its own parts and hands back
    // the rest
    pub(super) fn from_store(store_path: &str) -> Result<Segments> {
        let raw = store_path
            .strip_prefix(Path::SEPARATOR)
            .unwrap_or(store_path);
        let parts: Vec<&str> = raw.split(Path::SEPARATOR).collect();
        let mut rest: &[&str] = &parts;
        let mut out = Vec::new();
        while !rest.is_empty() {
            let (segment, tail) = match rest {
                [TaskDir::DIR] => (Segment::TaskDir(TaskDir), &[][..]),
                [TaskDir::DIR, tail @ ..] => Task::from_store(tail)?,
                [LogDir::DIR] => (Segment::LogDir(LogDir), &[][..]),
                [LogDir::DIR, tail @ ..] => Log::from_store(tail)?,
                _ => Note::from_store(rest)?,
            };
            out.push(segment);
            rest = tail;
        }
        Ok(Segments(out))
    }

    pub(super) fn to_store_file(&self) -> Result<Vec<String>> {
        let Some((last, dirs)) = self.0.split_last() else {
            return Err(rejected("the root has no file"));
        };
        if matches!(
            last,
            Segment::TaskDir(_) | Segment::LogDir(_) | Segment::Dir(_)
        ) {
            return Err(rejected("a directory has no file"));
        }
        let mut parts = Vec::new();
        for segment in dirs {
            segment.write_dir(&mut parts);
        }
        last.write_file(&mut parts);
        Ok(parts)
    }

    pub(super) fn to_store_dir(&self) -> Result<Vec<String>> {
        if let Some(Segment::Note(_)) = self.0.last() {
            return Err(rejected("a note file has no directory"));
        }
        let mut parts = Vec::new();
        for segment in &self.0 {
            segment.write_dir(&mut parts);
        }
        Ok(parts)
    }
}

impl<'a> IntoIterator for &'a Segments {
    type Item = &'a Segment;
    type IntoIter = std::slice::Iter<'a, Segment>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_segment_is_one_plain_part() {
        assert_eq!("a b".parse::<Segment>().unwrap().to_string(), "a b");
        assert!(matches!("a b".parse::<Segment>(), Ok(Segment::Dir(_))));
        assert!(matches!("a.md".parse::<Segment>(), Ok(Segment::Note(_))));
        assert_eq!("a.md".parse::<Segment>().unwrap().to_string(), "a.md");
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
            ".hidden",
            ".md",
            "a.md.md",
            long.as_str(),
        ] {
            assert!(bad.parse::<Segment>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn tasks_and_entries_have_one_spelling() {
        assert!(matches!("#2".parse::<Segment>(), Ok(Segment::Task(_))));
        assert!(matches!("#".parse::<Segment>(), Ok(Segment::TaskDir(_))));
        assert!(matches!("@".parse::<Segment>(), Ok(Segment::LogDir(_))));
        for bad in ["#0", "#02", "#-1", "#+2", "#x"] {
            assert!(bad.parse::<Segment>().is_err(), "accepted {bad:?}");
        }
        assert_eq!(
            "@2026-08-03T09:15:30.123456-07:00"
                .parse::<Segment>()
                .unwrap()
                .to_string(),
            "@2026-08-03T09:15:30.123456-07:00"
        );
        assert!("@2026".parse::<Segment>().is_err());
    }

    #[test]
    fn tasks_come_first_then_entries_then_names() {
        let task = "#10".parse::<Segment>().unwrap();
        let log = "@2026-08-03T09:15:30.123456-07:00"
            .parse::<Segment>()
            .unwrap();
        let note = "a".parse::<Segment>().unwrap();
        assert!("#2".parse::<Segment>().unwrap() < task);
        assert!(task < log);
        assert!(log < note);
    }

    fn stored(raw: &str) -> Result<Vec<String>> {
        Segments::from_store(raw).map(|s| s.0.iter().map(Segment::to_string).collect())
    }

    #[test]
    fn the_store_spelling_reads_back_by_its_head() {
        assert_eq!(stored("/dev/.tasks/2/.task.md").unwrap(), ["dev", "#2"]);
        assert_eq!(
            stored("/dev/.tasks/2/plan.md").unwrap(),
            ["dev", "#2", "plan.md"]
        );
        assert_eq!(stored("/a/b/c.md").unwrap(), ["a", "b", "c.md"]);
        assert_eq!(stored("/dev/.tasks").unwrap(), ["dev", "#"]);
        assert_eq!(stored("/dev/.logs").unwrap(), ["dev", "@"]);
        for bad in [
            "/a/.tasks/fartburger.md",
            "/a/.tasks/2/.task.md/x",
            "/image.png",
        ] {
            assert!(stored(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_file_is_the_directory_plus_the_last_segment_file() {
        let at = Segments::from_store("/dev/.tasks/2/.task.md").unwrap();
        assert_eq!(at.to_store_dir().unwrap(), ["dev", ".tasks", "2"]);
        assert_eq!(
            at.to_store_file().unwrap(),
            ["dev", ".tasks", "2", ".task.md"]
        );
        assert_eq!(
            Segments(Vec::new()).to_store_dir().unwrap(),
            Vec::<String>::new()
        );
        assert!(
            Segments::from_store("/a/b.md")
                .unwrap()
                .to_store_dir()
                .is_err()
        );
        assert!(Segments::from_store("/a/b").is_err());
        assert!(Segments(Vec::new()).to_store_file().is_err());
        let tasks = Segments::from_store("/dev/.tasks").unwrap();
        assert!(tasks.to_store_file().is_err());
        assert_eq!(tasks.to_store_dir().unwrap(), ["dev", ".tasks"]);
    }
}
