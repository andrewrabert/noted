use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use grep::searcher::SearcherBuilder;
use ignore::{WalkBuilder, WalkState};

use crate::error::{Result, io_error, unavailable};
use crate::path::RelPath;
use crate::search::{Hit, LineSink, SearchQuery, build_matcher, narrow};
use crate::util::{IgnoreFilter, atomic_create, atomic_write, normalize};

pub struct NotedDir(PathBuf);

impl NotedDir {
    pub fn new(path: impl Into<PathBuf>) -> NotedDir {
        NotedDir(path.into())
    }
}

#[derive(Clone)]
pub(crate) struct Sweep {
    base: RelPath,
    query: SearchQuery,
    admits: Arc<dyn Fn(&RelPath) -> bool + Send + Sync>,
}

impl Sweep {
    pub(crate) fn new(base: RelPath, query: &SearchQuery) -> Sweep {
        Sweep {
            base,
            query: query.clone(),
            admits: Arc::new(|_| true),
        }
    }

    pub(crate) fn descending(
        mut self,
        admits: impl Fn(&RelPath) -> bool + Send + Sync + 'static,
    ) -> Sweep {
        self.admits = Arc::new(admits);
        self
    }

    pub(crate) fn query(&self) -> &SearchQuery {
        &self.query
    }
}

struct StoreInner {
    root: PathBuf,
    writes: Mutex<()>,
    ignore: IgnoreFilter,
}

#[derive(Clone)]
pub struct Store(Arc<StoreInner>);

impl Store {
    pub fn open(dir: NotedDir) -> Result<Store> {
        let root = dir
            .0
            .canonicalize()
            .map_err(|e| io_error("notes dir unusable", e))?;
        let ignore = IgnoreFilter::new(&root);
        Ok(Store(Arc::new(StoreInner {
            root,
            writes: Mutex::new(()),
            ignore,
        })))
    }

    fn abs(&self, path: &RelPath) -> PathBuf {
        if path.is_empty() {
            self.0.root.clone()
        } else {
            self.0.root.join(path.as_str())
        }
    }

    fn rel(&self, path: &Path) -> Option<RelPath> {
        let cleaned = normalize(path);
        let under = cleaned.strip_prefix(&self.0.root).ok()?;
        Some(RelPath::trusted(under.to_string_lossy().into_owned()))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.0.writes.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn read(&self, path: &RelPath) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.abs(path))
    }

    pub(crate) fn write(&self, path: &RelPath, data: &[u8]) -> Result<()> {
        let _guard = self.lock();
        atomic_write(&self.abs(path), data)
    }

    pub(crate) fn create(&self, path: &RelPath, data: &[u8]) -> std::io::Result<()> {
        let _guard = self.lock();
        atomic_create(&self.abs(path), data)
    }

    pub(crate) fn swap(
        &self,
        path: &RelPath,
        data: &[u8],
        check: impl FnOnce(Option<&[u8]>) -> Result<()>,
    ) -> Result<()> {
        let abs = self.abs(path);
        let _guard = self.lock();
        let current = match std::fs::read(&abs) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_error(format!("cannot read note: '{path}'"), e)),
        };
        check(current.as_deref())?;
        atomic_write(&abs, data)
    }

    pub(crate) fn rename(&self, from: &RelPath, to: &RelPath) -> std::io::Result<()> {
        let _guard = self.lock();
        let target = self.abs(to);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(self.abs(from), target)
    }

    pub(crate) fn remove(&self, path: &RelPath) -> std::io::Result<()> {
        let _guard = self.lock();
        std::fs::remove_file(self.abs(path))
    }

    pub(crate) fn exists(&self, path: &RelPath) -> bool {
        self.abs(path).exists()
    }

    pub(crate) fn is_file(&self, path: &RelPath) -> bool {
        self.abs(path).is_file()
    }

    pub(crate) fn is_dir(&self, path: &RelPath) -> bool {
        self.abs(path).is_dir()
    }

    pub(crate) fn is_ignored(&self, path: &RelPath) -> bool {
        self.0.ignore.is_ignored(&self.abs(path))
    }

    pub(crate) fn has_symlink(&self, path: &RelPath) -> bool {
        let mut cur = self.0.root.clone();
        for part in path.as_str().split('/').filter(|p| !p.is_empty()) {
            cur.push(part);
            if let Ok(meta) = std::fs::symlink_metadata(&cur)
                && meta.file_type().is_symlink()
            {
                return true;
            }
        }
        false
    }

    pub(crate) fn children(&self, path: &RelPath) -> Vec<RelPath> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(self.abs(path)) else {
            return out;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if !ft.is_file() {
                continue;
            }
            let Some(rel) = self.rel(&entry.path()) else {
                continue;
            };
            if self.is_ignored(&rel) {
                continue;
            }
            out.push(rel);
        }
        out
    }

    pub(crate) fn walk(&self, path: &RelPath) -> Vec<RelPath> {
        let mut out = Vec::new();
        self.collect_md(&self.abs(path), &mut out);
        out.retain(|p| !self.is_ignored(p));
        out
    }

    fn collect_md(&self, dir: &Path, out: &mut Vec<RelPath>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                self.collect_md(&path, out);
            } else if ft.is_file()
                && path.extension().and_then(|e| e.to_str()) == Some("md")
                && let Some(rel) = self.rel(&path)
            {
                out.push(rel);
            }
        }
    }

    pub(crate) fn unique(&self, base: &RelPath, sep: &str) -> RelPath {
        if !self.exists(base) {
            return base.clone();
        }
        let name = base.file_name();
        let (stem, ext) = match name.rsplit_once('.') {
            Some((stem, ext)) if !stem.is_empty() => (stem, Some(ext)),
            _ => (name, None),
        };
        let mut count = 0u64;
        loop {
            count += 1;
            let candidate = base.with_file_name(&match ext {
                Some(ext) => format!("{stem}{sep}{count}.{ext}"),
                None => format!("{stem}{sep}{count}"),
            });
            if !self.exists(&candidate) {
                return candidate;
            }
        }
    }

    fn walk_builder(&self, sweep: &Sweep) -> WalkBuilder {
        let filter = self.0.ignore.clone();
        let store = self.clone();
        let admits = sweep.admits.clone();
        let mut wb = WalkBuilder::new(self.abs(&sweep.base));
        wb.hidden(true)
            .ignore(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .parents(false)
            .filter_entry(move |entry| {
                !filter.is_ignored(entry.path())
                    && store.rel(entry.path()).is_some_and(|rel| admits(&rel))
            });
        wb
    }

    pub(crate) async fn walk_search(&self, sweep: &Sweep) -> Result<Vec<RelPath>> {
        let store = self.clone();
        let sweep = sweep.clone();
        tokio::task::spawn_blocking(move || store.walk_files(&sweep))
            .await
            .map_err(|e| unavailable(format!("search: {e}")))?
    }

    fn walk_files(&self, sweep: &Sweep) -> Result<Vec<RelPath>> {
        let mut wb = self.walk_builder(sweep);
        narrow(&mut wb, &self.abs(&sweep.base), sweep.query())?;
        Ok(wb
            .build()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                match entry.file_type() {
                    Some(ft) if ft.is_file() => self.rel(&entry.into_path()),
                    _ => None,
                }
            })
            .collect())
    }

    pub(crate) async fn grep(&self, sweep: &Sweep) -> Result<Vec<Hit>> {
        let matcher = build_matcher(sweep.query())?;
        let store = self.clone();
        let sweep = sweep.clone();

        tokio::task::spawn_blocking(move || {
            let query = sweep.query().clone();
            let mut wb = store.walk_builder(&sweep);
            narrow(&mut wb, &store.abs(&sweep.base), &query)?;
            let hits: Mutex<HashMap<RelPath, BTreeMap<u64, String>>> = Mutex::new(HashMap::new());

            wb.build_parallel().run(|| {
                let mut searcher = SearcherBuilder::new()
                    .line_number(true)
                    .multi_line(query.multiline)
                    .before_context(query.context as usize)
                    .after_context(query.context as usize)
                    .build();
                let matcher = &matcher;
                let hits = &hits;
                let store = &store;
                Box::new(move |entry| {
                    let Ok(entry) = entry else {
                        return WalkState::Continue;
                    };
                    match entry.file_type() {
                        Some(ft) if ft.is_file() => {}
                        _ => return WalkState::Continue,
                    }
                    let path = entry.into_path();
                    let mut sink = LineSink::new();
                    if searcher.search_path(matcher, &path, &mut sink).is_err() {
                        return WalkState::Continue;
                    }
                    if sink.lines.is_empty() {
                        return WalkState::Continue;
                    }
                    if let Some(rel) = store.rel(&path) {
                        hits.lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .entry(rel)
                            .or_default()
                            .extend(sink.lines);
                    }
                    WalkState::Continue
                })
            });

            Ok(hits
                .into_inner()
                .unwrap_or_else(|e| e.into_inner())
                .into_iter()
                .map(|(path, lines)| Hit { path, lines })
                .collect())
        })
        .await
        .map_err(|e| unavailable(format!("search: {e}")))?
    }
}
