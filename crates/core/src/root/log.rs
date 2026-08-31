use std::cmp::Reverse;
use std::ops::RangeBounds as _;

use chrono::{DateTime, FixedOffset, Local};

use crate::domain::NotePath;
use crate::error::{NotedError, Result, rejected};
use crate::note::{LogFront, LogNote, LogQuery, Note as _};
use crate::regions::RegionStore;
use crate::search::Hit;
use crate::types::{LogBody, Source, Timestamp};

/// 2026-08-03T09-15-30.123456-0700
const STAMP: &str = "%Y-%m-%dT%H-%M-%S.%6f%z";

fn stamp_of(name: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_str(name.get(..31)?, STAMP).ok()
}

// the instant an entry's name carries, read from its last segment
fn stamped(path: &NotePath) -> Result<DateTime<FixedOffset>> {
    path.segments()
        .last()
        .and_then(|name| stamp_of(name.as_str()))
        .ok_or_else(|| rejected(format!("{path}: not a log entry name")))
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
            let entry = LogNote::new(NotePath::new(&name)?, front.clone(), body.as_str());
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
            0 => format!("/{stamp}.md"),
            n => format!("/{stamp}-{n}.md"),
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
        let hits = self
            .region
            .search(&NotePath::default(), &query.query)
            .await?;

        let mut dated = Vec::new();
        for hit in query.query.assemble(hits)? {
            if !stamped(&hit.path).is_ok_and(|at| query.range.contains(&at)) {
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

    async fn within(&self, query: &LogQuery) -> Vec<NotePath> {
        let names = self.region.walk(&NotePath::default()).await;
        names
            .into_iter()
            .filter(|path| stamped(path).is_ok_and(|at| query.range.contains(&at)))
            .collect()
    }

    fn newest_first(entry: &LogNote) -> (Reverse<Timestamp>, NotePath) {
        (Reverse(entry.front().created), entry.path().clone())
    }
}
