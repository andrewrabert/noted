use std::collections::BTreeMap;
use std::path::{Path as StdPath, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use grep_searcher::{Searcher, SearcherBuilder, SinkContext, SinkMatch};
use ignore::overrides::OverrideBuilder;
use ignore::types::TypesBuilder;
use ignore::{WalkBuilder, WalkState};

use crate::disk::{atomic_create, atomic_write, normalize};
use crate::error::{NotedError, Result, io_error, rejected, unavailable};
use crate::search::{GlobPattern, SearchMode, SearchOrder, SearchQuery};
use crate::store::RawHit;
use crate::util::case_order;

pub(crate) struct Lock(tokio::sync::Mutex<()>);

impl Lock {
    pub(crate) fn new() -> Lock {
        Lock(tokio::sync::Mutex::new(()))
    }

    pub(crate) async fn hold(&self) -> impl Drop + '_ {
        self.0.lock().await
    }
}

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| unavailable(format!("filesystem task failed: {e}")))
}

pub(crate) async fn read(abs: &StdPath) -> Result<Vec<u8>> {
    let abs = abs.to_path_buf();
    blocking(move || match std::fs::read(&abs) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(NotedError::NotFound),
        Err(e) => Err(io_error("no note", e)),
    })
    .await?
}

pub(crate) async fn write(abs: &StdPath, data: &[u8]) -> Result<()> {
    let abs = abs.to_path_buf();
    let data = data.to_vec();
    blocking(move || atomic_write(&abs, &data)).await?
}

pub(crate) async fn create(abs: &StdPath, data: &[u8]) -> Result<()> {
    let abs = abs.to_path_buf();
    let data = data.to_vec();
    blocking(move || {
        if std::fs::symlink_metadata(&abs).is_ok() {
            return Err(NotedError::Conflict);
        }
        atomic_create(&abs, &data).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => NotedError::Conflict,
            _ => io_error("write failed", e),
        })
    })
    .await?
}

pub(crate) async fn rename(from: &StdPath, to: &StdPath, overwrite: bool) -> Result<()> {
    let from = from.to_path_buf();
    let to = to.to_path_buf();
    blocking(move || {
        if std::fs::symlink_metadata(&from).is_err() {
            return Err(NotedError::NotFound);
        }
        if !overwrite && std::fs::symlink_metadata(&to).is_ok() {
            return Err(NotedError::Conflict);
        }
        parented(&to, "cannot rename")?;
        std::fs::rename(&from, &to).map_err(|e| io_error("cannot rename", e))
    })
    .await?
}

pub(crate) async fn relocate(from: &StdPath, to: &StdPath) -> Result<()> {
    let from = from.to_path_buf();
    let to = to.to_path_buf();
    blocking(move || {
        if std::fs::symlink_metadata(&from).is_err() {
            return Err(NotedError::NotFound);
        }
        if std::fs::symlink_metadata(&to).is_ok() {
            return Err(NotedError::Conflict);
        }
        parented(&to, "delete failed")?;
        std::fs::rename(&from, &to).map_err(|e| io_error("delete failed", e))
    })
    .await?
}

fn parented(at: &StdPath, context: &'static str) -> Result<()> {
    match at.parent() {
        Some(parent) => std::fs::create_dir_all(parent).map_err(|e| io_error(context, e)),
        None => Ok(()),
    }
}

pub(crate) async fn exists(abs: &StdPath) -> bool {
    let abs = abs.to_path_buf();
    blocking(move || abs.exists()).await.unwrap_or(false)
}

pub(crate) async fn walk(dir: &StdPath, max_depth: Option<usize>) -> Result<Vec<PathBuf>> {
    let dir = dir.to_path_buf();
    blocking(move || {
        walk_builder(&dir)
            .max_depth(max_depth)
            .build()
            .flatten()
            .filter(|entry| entry.depth() > 0)
            .filter_map(|entry| {
                entry
                    .path()
                    .strip_prefix(&dir)
                    .ok()
                    .map(StdPath::to_path_buf)
            })
            .collect()
    })
    .await
}

pub(crate) fn host() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default()
}

// the tree's walk configuration, rooted at the notes root; '.ignore' and
// '.gitignore' files are not honored
fn walk_builder(base: &StdPath) -> WalkBuilder {
    let mut wb = WalkBuilder::new(base);
    wb.hidden(false)
        .parents(false)
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .require_git(false);
    wb
}

pub(crate) async fn grep(
    base: &StdPath,
    from: &StdPath,
    query: &SearchQuery,
) -> Result<Vec<RawHit>> {
    let matcher = match query.mode {
        SearchMode::Path => None,
        _ => Some(query.matcher()?),
    };
    let base = base.to_path_buf();
    let from = from.to_path_buf();
    let query = query.clone();

    blocking(move || {
        let matched: Mutex<Vec<RawHit>> = Mutex::new(Vec::new());
        let walked: Mutex<Vec<RawHit>> = Mutex::new(Vec::new());

        let mut wb = walk_builder(&base);
        confine(&mut wb, &from);
        narrow(&mut wb, &from, &query)?;
        wb.build_parallel().run(|| {
            let mut searcher = SearcherBuilder::new()
                .line_number(true)
                .multi_line(query.multiline)
                .before_context(query.context as usize)
                .after_context(query.context as usize)
                .build();
            let matcher = matcher.as_ref();
            let matched = &matched;
            let walked = &walked;
            let from = &from;
            Box::new(move |entry| {
                let Ok(entry) = entry else {
                    return WalkState::Continue;
                };
                match entry.file_type() {
                    Some(kind) if kind.is_file() => {}
                    _ => return WalkState::Continue,
                }
                let modified = entry
                    .metadata()
                    .and_then(|meta| meta.modified().map_err(ignore::Error::from))
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                let path = entry.into_path();
                let Ok(rel) = relative(from, &path) else {
                    return WalkState::Continue;
                };
                if let Some(matcher) = matcher {
                    let mut sink = LineSink::new();
                    if searcher.search_path(matcher, &path, &mut sink).is_err() {
                        return WalkState::Continue;
                    }
                    if !sink.lines.is_empty() {
                        matched
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(RawHit {
                                path: rel,
                                modified,
                                lines: sink.lines,
                            });
                        return WalkState::Continue;
                    }
                }
                walked
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(RawHit {
                        path: rel,
                        modified,
                        lines: BTreeMap::new(),
                    });
                WalkState::Continue
            })
        });

        let mut hits = matched.into_inner().unwrap_or_else(|e| e.into_inner());
        if matches!(query.mode, SearchMode::Any | SearchMode::Path) {
            hits.extend(walked.into_inner().unwrap_or_else(|e| e.into_inner()));
        }
        ordered(&mut hits, query.order);
        Ok(hits)
    })
    .await?
}

fn relative(from: &StdPath, abs: &StdPath) -> Result<String> {
    let cleaned = normalize(abs);
    let under = cleaned
        .strip_prefix(from)
        .map_err(|_| rejected("outside the search root"))?;
    let mut spelled = String::new();
    for component in under.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(rejected("not a plain path"));
        };
        spelled.push('/');
        spelled.push_str(part.to_str().ok_or_else(|| rejected("not utf-8"))?);
    }
    Ok(spelled)
}

// 'path' order is case-insensitive over the spelled name
fn ordered(hits: &mut [RawHit], order: SearchOrder) {
    let by_name = |a: &RawHit, b: &RawHit| case_order(&a.path, &b.path);
    match order {
        SearchOrder::Path => hits.sort_by(by_name),
        SearchOrder::Modified => {
            hits.sort_by(|a, b| b.modified.cmp(&a.modified).then_with(|| by_name(a, b)))
        }
    }
}

// the walk starts at the notes root so the root's ignore rules apply, and is
// held to the subtree the search asked for
fn confine(wb: &mut WalkBuilder, from: &StdPath) {
    let from = from.to_path_buf();
    wb.filter_entry(move |entry| {
        let path = entry.path();
        let toward = from.starts_with(path);
        (toward || path.starts_with(&from)) && !entry.path_is_symlink()
    });
}

fn expand_glob(entry: &GlobPattern) -> Vec<String> {
    let raw = entry.as_str();
    let (bang, path) = match raw.strip_prefix('!') {
        Some(rest) => ("!", rest),
        None => ("", raw),
    };
    let has_meta = path
        .chars()
        .any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}'));
    if has_meta {
        vec![raw.to_string()]
    } else {
        let p = path.trim_end_matches('/');
        vec![format!("{bang}{p}"), format!("{bang}{p}/**")]
    }
}

fn narrow(wb: &mut WalkBuilder, base: &StdPath, query: &SearchQuery) -> Result<()> {
    if !query.globs.is_empty() {
        let mut ob = OverrideBuilder::new(base);
        for entry in &query.globs {
            for g in expand_glob(entry) {
                ob.add(&g)
                    .map_err(|e| rejected(format!("invalid glob: '{entry}': {e}")))?;
            }
        }
        let overrides = ob
            .build()
            .map_err(|e| rejected(format!("invalid glob: {e}")))?;
        wb.overrides(overrides);
    }

    if !query.types.is_empty() {
        let mut tb = TypesBuilder::new();
        tb.add_defaults();
        for t in &query.types {
            tb.select(t.as_str());
        }
        let types = tb
            .build()
            .map_err(|e| rejected(format!("invalid file type: {e}")))?;
        wb.types(types);
    }

    Ok(())
}

struct LineSink {
    lines: BTreeMap<u64, String>,
}

impl LineSink {
    fn new() -> LineSink {
        LineSink {
            lines: BTreeMap::new(),
        }
    }
}

fn record(lines: &mut BTreeMap<u64, String>, line_number: Option<u64>, bytes: &[u8]) {
    if let Some(n) = line_number {
        let text = String::from_utf8_lossy(bytes)
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string();
        lines.insert(n, text);
    }
}

impl grep_searcher::Sink for LineSink {
    type Error = std::io::Error;

    fn matched(&mut self, _searcher: &Searcher, m: &SinkMatch<'_>) -> std::io::Result<bool> {
        record(&mut self.lines, m.line_number(), m.bytes());
        Ok(true)
    }

    fn context(&mut self, _searcher: &Searcher, c: &SinkContext<'_>) -> std::io::Result<bool> {
        record(&mut self.lines, c.line_number(), c.bytes());
        Ok(true)
    }
}
