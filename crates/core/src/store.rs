use std::collections::{BTreeMap, HashMap};
use std::path::{Path as StdPath, PathBuf};
use std::sync::{Arc, Mutex};

use grep::searcher::SearcherBuilder;
use ignore::{WalkBuilder, WalkState};

use crate::error::{NotedError, Result, io_error, rejected, unavailable};
use crate::note::{Condition, Etag};
use crate::path::{DirPath, Path};
use crate::policy::{Readable, Writeable};
use crate::search::{Hit, LineSink, SearchMode, SearchQuery, build_matcher, narrow};
use crate::util::{IgnoreFilter, atomic_write, normalize};

const TRASH: &str = ".trash";

pub struct NotedDir(PathBuf);

impl NotedDir {
    pub fn new(path: impl Into<PathBuf>) -> NotedDir {
        NotedDir(path.into())
    }
}

pub(crate) struct RawHit {
    path: Path,
    lines: BTreeMap<u64, String>,
}

impl RawHit {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn into_hit(self, at: Readable) -> Result<Hit> {
        match at.0 == self.path {
            true => Ok(Hit {
                path: self.path,
                lines: self.lines,
            }),
            false => Err(crate::error::rejected(
                "search hit unlocked by another path",
            )),
        }
    }
}

fn spare_names(at: &Path) -> impl Iterator<Item = String> + use<> {
    let full = at.to_string();
    let name = at.file_name().to_string();
    let dir = match full.strip_suffix(&name) {
        Some(dir) => dir.to_string(),
        None => String::new(),
    };
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem.to_string(), Some(ext.to_string())),
        _ => (name, None),
    };
    std::iter::once(full).chain((1u64..1000).map(move |n| match &ext {
        Some(ext) => format!("{dir}{stem} {n}.{ext}"),
        None => format!("{dir}{stem} {n}"),
    }))
}

struct StoreInner {
    root: PathBuf,
    writes: Mutex<()>,
    ignore: IgnoreFilter,
}

#[derive(Clone)]
pub(crate) struct Store(Arc<StoreInner>);

impl Store {
    pub(crate) fn open(dir: NotedDir) -> Result<Store> {
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

    fn absolute(&self, at: &Path) -> PathBuf {
        self.0.root.join(at.as_str())
    }

    fn directory(&self, from: &DirPath) -> PathBuf {
        match from.to_path() {
            Some(at) => self.absolute(&at),
            None => self.0.root.clone(),
        }
    }

    fn rel(&self, abs: &StdPath) -> Option<Path> {
        let cleaned = normalize(abs);
        let under = cleaned.strip_prefix(&self.0.root).ok()?;
        Path::new(under.to_string_lossy()).ok()
    }

    fn addressable(&self, at: &Path) -> Result<PathBuf> {
        let abs = self.absolute(at);
        if self.0.ignore.is_ignored(&abs) || self.crosses_symlink(at.as_str()) {
            return Err(rejected("invalid path"));
        }
        Ok(abs)
    }

    fn crosses_symlink(&self, at: &str) -> bool {
        let mut walked = self.0.root.clone();
        for part in at.split('/').filter(|p| !p.is_empty()) {
            walked.push(part);
            if let Ok(meta) = std::fs::symlink_metadata(&walked)
                && meta.file_type().is_symlink()
            {
                return true;
            }
        }
        false
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.0.writes.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn current(&self, abs: &StdPath) -> Result<Option<Vec<u8>>> {
        match std::fs::read(abs) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error("cannot read note", e)),
        }
    }

    fn precondition(&self, abs: &StdPath, when: &Condition) -> Result<()> {
        match when {
            Condition::Always => Ok(()),
            Condition::Missing => match self.current(abs)? {
                None => Ok(()),
                Some(_) => Err(NotedError::Conflict),
            },
            Condition::Exists => match self.current(abs)? {
                Some(_) => Ok(()),
                None => Err(NotedError::NotFound),
            },
            Condition::Matching(token) => match self.current(abs)? {
                Some(bytes) if &Etag::of(&bytes) == token => Ok(()),
                Some(_) => Err(NotedError::Conflict),
                None => Err(NotedError::Conflict),
            },
        }
    }

    pub(crate) fn read(&self, at: &Readable) -> Result<Vec<u8>> {
        std::fs::read(self.addressable(&at.0)?).map_err(|e| io_error("no note", e))
    }

    pub(crate) fn write(&self, at: &Writeable, data: &[u8], when: Condition) -> Result<()> {
        let abs = self.addressable(&at.0)?;
        let _guard = self.lock();
        self.precondition(&abs, &when)?;
        atomic_write(&abs, data)
    }

    pub(crate) fn rename(&self, from: &Writeable, to: &Writeable, when: Condition) -> Result<()> {
        let source = self.addressable(&from.0)?;
        let target = self.addressable(&to.0)?;
        let _guard = self.lock();
        if !source.exists() {
            return Err(NotedError::NotFound);
        }
        self.precondition(&target, &when)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_error("cannot create folder", e))?;
        }
        std::fs::rename(&source, &target).map_err(|e| io_error("cannot rename", e))
    }

    pub(crate) fn remove(&self, at: &Writeable) -> Result<()> {
        let at = &at.0;
        let source = self.addressable(at)?;
        let _guard = self.lock();
        if !source.exists() {
            return Err(NotedError::NotFound);
        }
        for candidate in spare_names(at) {
            let target = self.0.root.join(TRASH).join(&candidate);
            if target.exists() {
                continue;
            }
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| io_error("delete failed", e))?;
            }
            return match std::fs::rename(&source, &target) {
                Ok(()) => Ok(()),
                Err(e) => Err(io_error("delete failed", e)),
            };
        }
        Err(NotedError::Conflict)
    }

    pub(crate) fn walk(&self, from: &DirPath) -> Vec<Path> {
        let mut out = Vec::new();
        self.collect(&self.directory(from), true, &mut out);
        out
    }

    pub(crate) fn children(&self, from: &DirPath) -> Vec<Path> {
        let mut out = Vec::new();
        self.collect(&self.directory(from), false, &mut out);
        out
    }

    fn collect(&self, dir: &StdPath, deep: bool, out: &mut Vec<Path>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() || entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let path = entry.path();
            if self.0.ignore.is_ignored(&path) {
                continue;
            }
            let Some(rel) = self.rel(&path) else { continue };
            if kind.is_dir() {
                if deep {
                    self.collect(&path, deep, out);
                }
            } else if kind.is_file() && path.extension().and_then(|e| e.to_str()) == Some("md") {
                out.push(rel);
            }
        }
    }

    pub(crate) async fn search(&self, from: &DirPath, query: &SearchQuery) -> Result<Vec<RawHit>> {
        let matcher = match query.mode {
            SearchMode::Path => None,
            _ => Some(build_matcher(query)?),
        };
        let store = self.clone();
        let base = self.directory(from);
        let query = query.clone();

        tokio::task::spawn_blocking(move || {
            let lines: Mutex<HashMap<Path, BTreeMap<u64, String>>> = Mutex::new(HashMap::new());
            let walked: Mutex<Vec<Path>> = Mutex::new(Vec::new());

            let mut wb = store.walk_builder(&base);
            narrow(&mut wb, &base, &query)?;
            wb.build_parallel().run(|| {
                let mut searcher = SearcherBuilder::new()
                    .line_number(true)
                    .multi_line(query.multiline)
                    .before_context(query.context as usize)
                    .after_context(query.context as usize)
                    .build();
                let matcher = matcher.as_ref();
                let lines = &lines;
                let walked = &walked;
                let store = &store;
                Box::new(move |entry| {
                    let Ok(entry) = entry else {
                        return WalkState::Continue;
                    };
                    match entry.file_type() {
                        Some(kind) if kind.is_file() => {}
                        _ => return WalkState::Continue,
                    }
                    let path = entry.into_path();
                    let Some(rel) = store.rel(&path) else {
                        return WalkState::Continue;
                    };
                    if let Some(matcher) = matcher {
                        let mut sink = LineSink::new();
                        if searcher.search_path(matcher, &path, &mut sink).is_err() {
                            return WalkState::Continue;
                        }
                        if !sink.lines.is_empty() {
                            lines
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .entry(rel)
                                .or_default()
                                .extend(sink.lines);
                            return WalkState::Continue;
                        }
                    }
                    walked.lock().unwrap_or_else(|e| e.into_inner()).push(rel);
                    WalkState::Continue
                })
            });

            let mut hits: Vec<RawHit> = lines
                .into_inner()
                .unwrap_or_else(|e| e.into_inner())
                .into_iter()
                .map(|(path, lines)| RawHit { path, lines })
                .collect();
            if matches!(query.mode, SearchMode::Any | SearchMode::Path) {
                hits.extend(
                    walked
                        .into_inner()
                        .unwrap_or_else(|e| e.into_inner())
                        .into_iter()
                        .map(|path| RawHit {
                            path,
                            lines: BTreeMap::new(),
                        }),
                );
            }
            Ok(hits)
        })
        .await
        .map_err(|e| unavailable(format!("search: {e}")))?
    }

    fn walk_builder(&self, base: &StdPath) -> WalkBuilder {
        let filter = self.0.ignore.clone();
        let mut wb = WalkBuilder::new(base);
        wb.hidden(true)
            .ignore(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .parents(false)
            .filter_entry(move |entry| !filter.is_ignored(entry.path()));
        wb
    }
}
