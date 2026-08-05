use std::cmp::Reverse;
use std::ops::RangeBounds as _;

use chrono::{DateTime, FixedOffset, Local};

use crate::error::{NotedError, Result, rejected};
use crate::note::{LogFront, LogNote, LogQuery, Note as _};
use crate::path::Path;
use crate::regions::RegionStore;
use crate::search::{Hit, assemble};
use crate::types::{LogBody, Source, Timestamp};

/// 2026-08-03T09-15-30.123456-0700
const STAMP: &str = "%Y-%m-%dT%H-%M-%S.%6f%z";

fn stamp_of(name: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_str(name.get(..31)?, STAMP).ok()
}

pub(super) struct LogTools {
    region: RegionStore,
    source: Option<Source>,
}

impl LogTools {
    pub(super) fn new(region: RegionStore, source: Option<Source>) -> LogTools {
        LogTools { region, source }
    }

    pub(super) async fn note(&self, body: &LogBody) -> Result<LogNote> {
        let now = Local::now();
        let front = LogFront {
            created: Timestamp::at(now.fixed_offset()),
            cwd: std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            host: crate::platform::host(),
            source: self.source.clone(),
        };

        let stamp = now.format(STAMP).to_string();
        for name in LogTools::spare_stamps(&stamp) {
            let entry = LogNote::new(Path::new(&name)?, front.clone(), body.as_str());
            match self
                .region
                .write(
                    entry.path(),
                    &entry.to_bytes(),
                    crate::note::Condition::Missing,
                )
                .await
            {
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

    pub(super) async fn get(&self, query: &LogQuery) -> Result<Vec<LogNote>> {
        let mut found = Vec::new();
        for path in self.within(query).await {
            let Ok(bytes) = self.region.read(&path).await else {
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

    pub(super) async fn search(&self, query: &LogQuery) -> Result<Vec<Hit>> {
        let hits = self.region.search(None, &query.query).await?;

        let mut dated = Vec::new();
        for hit in assemble(&query.query, hits)? {
            if stamp_of(hit.path.file_name()).is_none_or(|at| !query.range.contains(&at)) {
                continue;
            }
            let Ok(bytes) = self.region.read(&hit.path).await else {
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

    async fn within(&self, query: &LogQuery) -> Vec<Path> {
        let names = self.region.walk(None).await;
        names
            .into_iter()
            .filter(|path| stamp_of(path.file_name()).is_some_and(|at| query.range.contains(&at)))
            .collect()
    }

    fn newest_first(entry: &LogNote) -> (Reverse<Timestamp>, Path) {
        (Reverse(entry.front().created), entry.path().clone())
    }
}
