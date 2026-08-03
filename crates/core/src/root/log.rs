use std::cmp::Reverse;

use chrono::{DateTime, FixedOffset, Local};

use crate::areas::Area;
use crate::error::{NotedError, Result, rejected};
use crate::note::{LogFront, LogNote, LogQuery, Note as _};
use crate::path::Path;
use crate::search::{Hit, LogWindow, SearchQuery, assemble};
use crate::types::{LogBody, Source, Timestamp};

pub(super) struct LogTools {
    area: Area,
    source: Option<Source>,
    scope: Option<Path>,
}

impl LogTools {
    pub(super) fn new(area: Area, source: Option<Source>, scope: Option<Path>) -> LogTools {
        LogTools {
            area,
            source,
            scope,
        }
    }

    pub(super) fn note(&self, body: &LogBody) -> Result<LogNote> {
        let now = Local::now();
        let front = LogFront {
            created: Timestamp::from_local(now),
            scope: self.scope.clone(),
            cwd: std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            host: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_default(),
            source: self.source.clone(),
        };

        let dir = Path::new(format!("{}/{}", now.format("%Y"), now.format("%m")))?;
        let stamp = now.format("%Y-%m-%dT%H-%M-%S.%6f").to_string();
        for name in LogTools::spare_stamps(&stamp) {
            let entry = LogNote::new(dir.joined(&name)?, front.clone(), body.as_str());
            match self.area.write(
                entry.path(),
                &entry.to_bytes()?,
                crate::note::Condition::Missing,
            ) {
                Ok(()) => return Ok(entry),
                Err(NotedError::Conflict) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(rejected("could not allocate a log entry name"))
    }

    fn spare_stamps(stamp: &str) -> impl Iterator<Item = String> {
        let stamp = stamp.to_string();
        (0u64..1000).map(move |n| match n {
            0 => format!("{stamp}.md"),
            n => format!("{stamp}-{n}.md"),
        })
    }

    pub(super) fn get(&self, query: &LogQuery) -> Result<Vec<LogNote>> {
        let mut found = Vec::new();
        for path in self.walk(&query.window) {
            let Ok(bytes) = self.area.read(&path) else {
                continue;
            };
            let Ok(entry) = LogNote::from_bytes(path, &bytes) else {
                continue;
            };
            if self.admits(&entry, &query.window) {
                found.push(entry);
            }
        }
        found.sort_by_cached_key(LogTools::newest_first);
        Ok(found
            .into_iter()
            .skip(query.offset as usize)
            .take(query.limit as usize)
            .collect())
    }

    pub(super) async fn search(&self, window: &LogWindow, query: &SearchQuery) -> Result<Vec<Hit>> {
        let window = *window;
        let hits = self
            .area
            .search(None, query, move |dir| window.admits_dir(&dir.to_string()))
            .await?;

        let mut dated = Vec::new();
        for hit in assemble(query, hits)? {
            let Ok(bytes) = self.area.read(&hit.path) else {
                continue;
            };
            let Ok(entry) = LogNote::from_bytes(hit.path.clone(), &bytes) else {
                continue;
            };
            if self.admits(&entry, &window) {
                dated.push((LogTools::newest_first(&entry), hit));
            }
        }
        dated.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(dated.into_iter().map(|(_, hit)| hit).collect())
    }

    fn walk(&self, window: &LogWindow) -> Vec<Path> {
        let window = *window;
        self.area
            .walk(None, move |dir| window.admits_dir(&dir.to_string()))
    }

    fn admits(&self, entry: &LogNote, window: &LogWindow) -> bool {
        let within = match (&self.scope, &entry.front().scope) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(held), Some(stamped)) => stamped.under(held),
        };
        if !within {
            return false;
        }
        window.is_open()
            || entry
                .front()
                .created
                .date()
                .is_some_and(|d| window.admits(d))
    }

    fn newest_first(entry: &LogNote) -> (Reverse<Option<DateTime<FixedOffset>>>, Path) {
        (
            Reverse(entry.front().created.parse_rfc3339()),
            entry.path().clone(),
        )
    }
}
