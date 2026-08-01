use std::cmp::Reverse;

use chrono::{DateTime, FixedOffset, Local};

use crate::areas::Areas;
use crate::caller::Caller;
use crate::error::Result;
use crate::note::{LogFront, LogNote, LogQuery, Note as _};
use crate::path::RelPath;
use crate::search::{Hit, LogWindow, SearchQuery, assemble};
use crate::store::{Store, Sweep};
use crate::types::{LogBody, Timestamp};

use super::find::Find;

#[derive(Clone)]
pub(super) struct Log {
    store: Store,
    areas: Areas,
    caller: Caller,
    find: Find,
}

impl Log {
    pub(super) fn new(store: Store, areas: Areas, caller: Caller, find: Find) -> Log {
        Log {
            store,
            areas,
            caller,
            find,
        }
    }

    pub(super) fn note(&self, body: &LogBody) -> Result<LogNote> {
        let now = Local::now();
        let front = LogFront {
            created: Timestamp::from_local(now),
            cwd: std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            host: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_default(),
            source: self.caller.source().cloned(),
        };

        let dir = self
            .areas
            .log
            .joined(&format!("{}/{}", now.format("%Y"), now.format("%m")));
        let stamp = now.format("%Y-%m-%dT%H-%M-%S.%6f").to_string();
        let path = self.store.unique(&dir.joined(&format!("{stamp}.md")), "-");

        let entry = LogNote::new(path, front, body.as_str());
        self.store.write(entry.path(), &entry.to_bytes()?)?;
        Ok(entry)
    }

    pub(super) fn get(&self, query: &LogQuery) -> Result<Vec<LogNote>> {
        let mut found = Vec::new();
        for path in self.store.walk(&self.areas.log) {
            if !self.caller.admits(&path) || !self.in_window(&path, &query.window) {
                continue;
            }
            let Ok(bytes) = self.store.read(&path) else {
                continue;
            };
            let Ok(entry) = LogNote::from_bytes(path, &bytes) else {
                continue;
            };
            if self.admits(&entry, &query.window) {
                found.push(entry);
            }
        }
        found.sort_by_cached_key(Self::newest_first);
        Ok(found
            .into_iter()
            .skip(query.offset as usize)
            .take(query.limit as usize)
            .collect())
    }

    pub(super) async fn search(&self, window: &LogWindow, query: &SearchQuery) -> Result<Vec<Hit>> {
        let sweep = self.sweep(window, query);
        let hits = self.find.content(&sweep).await?;
        let walked = self.find.paths(&sweep).await?;
        let hits = assemble(query, hits, walked)?;

        let mut dated = Vec::new();
        for hit in hits {
            let Ok(bytes) = self.store.read(&hit.path) else {
                continue;
            };
            let Ok(entry) = LogNote::from_bytes(hit.path.clone(), &bytes) else {
                continue;
            };
            if self.admits(&entry, window) {
                dated.push((Self::newest_first(&entry), hit));
            }
        }
        dated.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(dated.into_iter().map(|(_, hit)| hit).collect())
    }

    fn sweep(&self, window: &LogWindow, query: &SearchQuery) -> Sweep {
        let areas = self.areas.clone();
        let window = *window;
        Sweep::new(self.areas.log.clone(), query).descending(move |path| {
            match path.as_str().strip_prefix(areas.log.as_str()) {
                Some(rest) => window.admits_dir(rest.trim_start_matches('/')),
                None => true,
            }
        })
    }

    fn in_window(&self, path: &RelPath, window: &LogWindow) -> bool {
        match path.as_str().strip_prefix(self.areas.log.as_str()) {
            Some(rest) => window.admits_dir(rest.trim_start_matches('/')),
            None => true,
        }
    }

    fn admits(&self, entry: &LogNote, window: &LogWindow) -> bool {
        window.is_open()
            || entry
                .front()
                .created
                .date()
                .is_some_and(|d| window.admits(d))
    }

    fn newest_first(entry: &LogNote) -> (Reverse<Option<DateTime<FixedOffset>>>, RelPath) {
        (
            Reverse(entry.front().created.parse_rfc3339()),
            entry.path().clone(),
        )
    }
}
