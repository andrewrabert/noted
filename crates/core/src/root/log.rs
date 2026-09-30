use std::cmp::Reverse;
use std::ops::RangeBounds as _;

use chrono::{DateTime, FixedOffset, Local, TimeDelta};

use crate::domain::{DirPath, LogPath};
use crate::error::{NotedError, Result, rejected};
use crate::note::{LogFront, LogNote, LogQuery, Note as _};
use crate::policy_store::PolicyStore;
use crate::search::Hit;
use crate::types::{LogBody, Source, Timestamp};

pub(super) struct LogTools {
    store: PolicyStore,
    source: Option<Source>,
}

impl LogTools {
    pub(super) fn new(store: PolicyStore, source: Option<Source>) -> LogTools {
        LogTools { store, source }
    }

    pub(super) async fn note(&self, dir: &DirPath, body: &LogBody) -> Result<LogNote> {
        let created = Timestamp::at(Local::now().fixed_offset());
        let front = LogFront {
            created,
            cwd: std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            host: crate::platform::host(),
            source: self.source.clone(),
        };

        // the instant itself, then each following microsecond, for a directory
        // that already holds an entry at it
        let start = DateTime::<FixedOffset>::from(created);
        for n in 0i64..1000 {
            let at = Timestamp::at(start + TimeDelta::microseconds(n));
            let entry = LogNote::new(LogPath::new(dir, at)?, front.clone(), body.as_str());
            let file = self
                .store
                .policy()
                .writeable(entry.path().as_ref())?
                .file()?;
            match self
                .store
                .write(&file, &entry.to_bytes(), crate::note::Condition::Missing)
                .await
            {
                Ok(()) => return Ok(entry),
                Err(NotedError::Conflict) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(rejected("could not allocate a log entry name"))
    }

    async fn read(&self, path: &LogPath) -> Result<Vec<u8>> {
        let file = self.store.policy().readable(path.as_ref())?.file()?;
        self.store.read(&file).await
    }

    pub(super) async fn get(&self, query: &LogQuery) -> Result<Vec<LogNote>> {
        let mut found = Vec::new();
        for path in self.within(query).await {
            let Ok(bytes) = self.read(&path).await else {
                continue;
            };
            let Ok(entry) = LogNote::from_bytes(path, &bytes) else {
                continue;
            };
            found.push(entry);
        }
        found.sort_by_cached_key(LogTools::newest_first);
        Ok(found.into_iter().take(query.limit as usize).collect())
    }

    pub(super) async fn search(&self, query: &LogQuery) -> Result<Vec<Hit<LogPath>>> {
        let hits = self
            .store
            .search(&query.prefix, &query.query)
            .await?
            .into_iter()
            .filter_map(|hit| {
                Some(Hit {
                    path: LogPath::try_from(hit.path).ok()?,
                    lines: hit.lines,
                })
            })
            .collect();

        let mut dated = Vec::new();
        for hit in query.query.assemble(hits)? {
            if !query
                .range
                .contains(&DateTime::<FixedOffset>::from(hit.path.created()))
            {
                continue;
            }
            let Ok(bytes) = self.read(&hit.path).await else {
                continue;
            };
            let Ok(entry) = LogNote::from_bytes(hit.path.clone(), &bytes) else {
                continue;
            };
            dated.push((LogTools::newest_first(&entry), hit));
        }
        dated.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(dated
            .into_iter()
            .map(|(_, hit)| hit)
            .take(query.limit as usize)
            .collect())
    }

    async fn within(&self, query: &LogQuery) -> Vec<LogPath> {
        self.store
            .walk(&query.prefix, None)
            .await
            .into_iter()
            .filter_map(|at| LogPath::try_from(at).ok())
            .filter(|path| {
                query
                    .range
                    .contains(&DateTime::<FixedOffset>::from(path.created()))
            })
            .collect()
    }

    fn newest_first(entry: &LogNote) -> (Reverse<Timestamp>, LogPath) {
        (Reverse(entry.front().created), entry.path().clone())
    }
}
