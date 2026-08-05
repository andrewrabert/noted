use std::collections::BTreeMap;
use std::path::Path as StdPath;
use std::sync::Mutex;
use std::time::SystemTime;

use grep_searcher::{Searcher, SearcherBuilder, SinkContext, SinkMatch};
use ignore::overrides::OverrideBuilder;
use ignore::types::TypesBuilder;
use ignore::{IncrementalIgnore, WalkBuilder, WalkState};

use crate::error::{NotedError, Result, io_error, rejected, unavailable};
use crate::httpurl::HttpUrl;
use crate::path::{Path, Reserved};
use crate::platform::Entry;
use crate::search::{GlobPattern, SearchMode, SearchOrder, SearchQuery, build_matcher};
use crate::store::RawHit;
use crate::util::{atomic_create, atomic_write, normalize};

pub(crate) type Router = axum::Router;

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

pub(crate) async fn entries(base: &StdPath, dir: &StdPath, deep: bool) -> Result<Vec<Entry>> {
    let base = base.to_path_buf();
    let dir = dir.to_path_buf();
    blocking(move || {
        let mut gate = gate(&base);
        let mut out = Vec::new();
        listed(&mut gate, &base, &dir, deep, "", &mut out);
        out
    })
    .await
}

fn listed(
    gate: &mut IncrementalIgnore,
    base: &StdPath,
    dir: &StdPath,
    deep: bool,
    prefix: &str,
    out: &mut Vec<Entry>,
) {
    let Ok(found) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in found.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        let path = entry.path();
        let Some(rel) = path.strip_prefix(base).ok().map(|at| at.to_string_lossy()) else {
            continue;
        };
        if gate.matched(rel.as_ref(), kind.is_dir()).is_ignore() {
            continue;
        }
        let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
        out.push(Entry {
            is_dir: kind.is_dir(),
            modified: entry.metadata().ok().and_then(|meta| meta.modified().ok()),
            name: name.clone(),
        });
        if deep && kind.is_dir() {
            listed(gate, base, &path, deep, &format!("{name}/"), out);
        }
    }
}

pub(crate) async fn ignored(base: &StdPath, abs: &StdPath) -> Result<bool> {
    let base = base.to_path_buf();
    let abs = abs.to_path_buf();
    blocking(move || {
        let Ok(rel) = abs.strip_prefix(&base) else {
            return true;
        };
        gate(&base)
            .matched(rel.to_string_lossy().as_ref(), abs.is_dir())
            .is_ignore()
    })
    .await
}

pub(crate) fn crosses_symlink(base: &StdPath, abs: &StdPath) -> bool {
    let Ok(rel) = normalize(abs).strip_prefix(base).map(StdPath::to_path_buf) else {
        return true;
    };
    let mut walked = base.to_path_buf();
    for part in rel.components() {
        walked.push(part);
        if std::fs::symlink_metadata(&walked).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return true;
        }
    }
    false
}

pub(crate) fn host() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub(crate) async fn route(
    router: &Router,
    target: &HttpUrl,
    token: Option<&str>,
    body: Vec<u8>,
) -> std::result::Result<(u16, Vec<u8>), String> {
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let mut builder = Request::builder()
        .method("POST")
        .uri(target.path_and_query())
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder
        .body(axum::body::Body::from(body))
        .map_err(|e| e.to_string())?;
    let resp = router
        .clone()
        .oneshot(request)
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((status, bytes.to_vec()))
}

// the tree's only ignore configuration: '.ignore' and '.gitignore' as the
// ignore crate reads them, rooted at the notes root
fn walk_builder(base: &StdPath) -> WalkBuilder {
    let mut wb = WalkBuilder::new(base);
    wb.hidden(false)
        .parents(false)
        .ignore(true)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(false)
        .require_git(false);
    wb
}

// that same configuration as a matcher for a path reached without a walk
fn gate(base: &StdPath) -> IncrementalIgnore {
    match walk_builder(base).build_matchers().into_iter().next() {
        Some(gate) => gate,
        None => unreachable!("a walk builder always carries its root"),
    }
}

pub(crate) async fn grep(
    base: &StdPath,
    from: &StdPath,
    query: &SearchQuery,
) -> Result<Vec<RawHit>> {
    let matcher = match query.mode {
        SearchMode::Path => None,
        _ => Some(build_matcher(query)?),
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
            let base = &base;
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
                let Some(rel) = relative(base, &path) else {
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

fn relative(base: &StdPath, abs: &StdPath) -> Option<Path> {
    let cleaned = normalize(abs);
    let under = cleaned.strip_prefix(base).ok()?;
    Path::stored(under.to_string_lossy().as_ref()).ok()
}

fn ordered(hits: &mut [RawHit], order: SearchOrder) {
    match order {
        SearchOrder::Path => hits.sort_by(|a, b| a.path.cmp(&b.path)),
        SearchOrder::Modified => hits.sort_by(|a, b| {
            b.modified
                .cmp(&a.modified)
                .then_with(|| a.path.cmp(&b.path))
        }),
    }
}

// the walk starts at the notes root so the root's ignore rules apply, and is
// held to the subtree the search asked for
fn confine(wb: &mut WalkBuilder, from: &StdPath) {
    let from = from.to_path_buf();
    wb.filter_entry(move |entry| {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy();
        let toward = from.starts_with(path);
        let visible = toward || !name.starts_with('.') || name == Reserved::TaskBody.as_str();
        (toward || path.starts_with(&from)) && visible && !entry.path_is_symlink()
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
