use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use chrono::Local;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{forbidden, io_error, not_found, rejected, Result};
use crate::front_matter::dump_front;
use crate::search::{match_paths, ripgrep, walk_search, MatchOpts, WalkOpts};
use crate::types::{Source, Timestamp};
use crate::util::{atomic_write, normalize, IgnoreFilter};

#[derive(Clone, Serialize)]
pub struct LogFront {
    pub created: Timestamp,
    pub cwd: String,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
}

const TRASH: &str = ".trash";
const LOG: &str = "Log";
const TASKS: &str = "Tasks";

#[derive(Clone)]
pub struct Notes {
    root: PathBuf,
    pub source: Option<String>,
    confine: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct RelPath(String);

impl RelPath {
    pub fn new(s: impl Into<String>) -> RelPath {
        RelPath(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for RelPath {
    type Err = crate::error::NotedError;
    fn from_str(s: &str) -> Result<RelPath> {
        Ok(RelPath::new(s))
    }
}

impl Ord for RelPath {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .to_lowercase()
            .cmp(&other.0.to_lowercase())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for RelPath {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::ops::Deref for RelPath {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<RelPath> for String {
    fn from(r: RelPath) -> String {
        r.0
    }
}

impl AsRef<str> for RelPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for RelPath {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for RelPath {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for RelPath {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

pub struct ContentHit {
    rel: RelPath,
    lines: BTreeMap<u64, String>,
}

impl ContentHit {
    pub fn rel(&self) -> &RelPath {
        &self.rel
    }

    pub fn into_rel(self) -> RelPath {
        self.rel
    }

    pub fn lines(&self) -> impl Iterator<Item = (u64, &str)> {
        self.lines.iter().map(|(n, t)| (*n, t.as_str()))
    }
}

impl Notes {
    pub fn new(root: &Path, source: Option<String>) -> Result<Notes> {
        let root = root
            .canonicalize()
            .map_err(|e| io_error("notes dir unusable", e))?;
        Ok(Notes {
            root,
            source,
            confine: None,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn confined(&self, folders: Option<Vec<String>>) -> Notes {
        match folders {
            None => self.clone(),
            Some(folders) => Notes {
                root: self.root.clone(),
                source: self.source.clone(),
                confine: Some(folders),
            },
        }
    }

    fn within_confine(&self, path: &Path) -> bool {
        match &self.confine {
            None => true,
            Some(folders) => folders.iter().any(|folder| {
                let base = normalize(&self.root.join(folder));
                path == base || path.starts_with(&base)
            }),
        }
    }

    fn guard_confine(&self, path: &Path, rel: &str) -> Result<()> {
        if self.confine.is_none() || self.under_log(path) {
            return Ok(());
        }
        if !self.within_confine(path) {
            return Err(forbidden(format!("path outside allowed folders: '{rel}'")));
        }
        Ok(())
    }

    fn filter_confine(&self, path: &Path) -> bool {
        self.confine.is_none() || self.within_confine(path)
    }

    fn trash_path(&self) -> PathBuf {
        self.root.join(TRASH)
    }

    fn log_path(&self) -> PathBuf {
        self.root.join(LOG)
    }

    fn tasks_path(&self) -> PathBuf {
        self.root.join(TASKS)
    }

    fn get_path(&self, rel: &str) -> Result<PathBuf> {
        let resolved = normalize(&self.root.join(rel));
        if resolved != self.root && !resolved.starts_with(&self.root) {
            return Err(rejected(format!("path escapes notes root: '{rel}'")));
        }
        if let Ok(under) = resolved.strip_prefix(&self.root) {
            if under
                .components()
                .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
            {
                return Err(rejected(format!("invalid path: '{rel}'")));
            }
        }
        if IgnoreFilter::new(&self.root).is_ignored(&resolved) {
            return Err(rejected(format!("invalid path: '{rel}'")));
        }
        Ok(resolved)
    }

    fn under_log(&self, path: &Path) -> bool {
        path.starts_with(self.log_path())
    }

    fn under_tasks(&self, path: &Path) -> bool {
        path.starts_with(self.tasks_path())
    }

    fn guard_log(&self, path: &Path, rel: &str) -> Result<()> {
        if self.under_log(path) {
            return Err(rejected(format!("log entries are immutable: '{rel}'")));
        }
        Ok(())
    }

    fn rel_to(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    }

    fn resolve_file(&self, rel: &str) -> Result<PathBuf> {
        if rel.is_empty() {
            return Err(rejected("path required"));
        }
        if rel.ends_with('/') {
            return Err(rejected(format!("path must be a file: '{rel}'")));
        }
        let path = self.get_path(rel)?;
        self.guard_confine(&path, rel)?;
        Ok(path)
    }

    fn resolve_movable(&self, rel: &str) -> Result<PathBuf> {
        let stripped = rel.trim_end_matches('/');
        if stripped.is_empty() {
            return Err(rejected("path required"));
        }
        let path = self.get_path(stripped)?;
        self.guard_confine(&path, stripped)?;
        Ok(path)
    }

    pub fn read(&self, rel: &RelPath) -> Result<String> {
        let path = self.resolve_file(rel)?;
        if !path.is_file() {
            return Err(not_found(format!("no note at '{rel}'")));
        }
        match std::fs::read(&path) {
            Ok(bytes) => String::from_utf8(bytes)
                .map_err(|_| rejected(format!("note is not valid utf-8: '{rel}'"))),
            Err(e) => Err(io_error(format!("no note at '{rel}'"), e)),
        }
    }

    pub fn write(&self, rel: &RelPath, content: &str) -> Result<()> {
        let path = self.resolve_file(rel)?;
        self.guard_log(&path, rel)?;
        if self.under_tasks(&path) {
            return Err(rejected(format!(
                "tasks are managed: '{rel}' (use CreateTask/UpdateTask/MoveTask)"
            )));
        }
        atomic_write(&path, content)
    }

    pub fn create_log(&self, body: &str, source: Option<&Source>) -> Result<String> {
        let now = Local::now();
        let source = source
            .map(|s| s.to_string())
            .or_else(|| self.source.clone());

        let front = LogFront {
            created: Timestamp::from_local(now),
            cwd: std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            host: hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_default(),
            source: Source::from_opt(source),
        };

        let rel_dir = format!("{LOG}/{}/{}", now.format("%Y"), now.format("%m"));
        let stamp = now.format("%Y-%m-%dT%H-%M-%S.%6f").to_string();
        let rel_md = self.unique_log(&rel_dir, &stamp);

        atomic_write(&self.get_path(&rel_md)?, &dump_front(&front, body)?)?;
        Ok(rel_md)
    }

    fn unique_log(&self, rel_dir: &str, stamp: &str) -> String {
        let dir = self.root.join(rel_dir);
        let base = dir.join(format!("{stamp}.md"));
        let md = uniquify(&base, "-", |p| p.exists());
        md.strip_prefix(&self.root)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    pub fn move_note(&self, rel: &RelPath, dest: &RelPath, overwrite: bool) -> Result<()> {
        let src = self.resolve_movable(rel)?;
        if !src.exists() {
            return Err(not_found(format!("no note or folder at '{rel}'")));
        }
        let target = self.resolve_movable(dest)?;
        self.guard_log(&src, rel)?;
        self.guard_log(&target, dest)?;
        if self.under_tasks(&src) {
            return Err(rejected(format!("tasks cannot be moved: '{rel}'")));
        }
        if self.under_tasks(&target) {
            return Err(rejected(format!("tasks cannot be moved: '{dest}'")));
        }
        if target == src {
            return Err(rejected("source and destination are the same"));
        }
        if target.starts_with(&src) {
            return Err(rejected(format!(
                "cannot move a folder into itself: '{rel}'"
            )));
        }
        if target.exists() && !overwrite {
            return Err(rejected(format!(
                "destination exists: '{dest}' (pass overwrite)"
            )));
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_error("mkdir failed", e))?;
        }
        std::fs::rename(&src, &target)
            .map_err(|e| io_error(format!("cannot overwrite non-empty folder: '{dest}'"), e))
    }

    pub fn delete(&self, rel: &RelPath) -> Result<String> {
        let path = self.resolve_file(rel)?;
        if !path.is_file() {
            return Err(not_found(format!("no note at '{rel}'")));
        }
        self.guard_log(&path, rel)?;
        if self.under_tasks(&path) {
            return Err(rejected(format!("tasks cannot be deleted: '{rel}'")));
        }
        let base = self.trash_path().join(rel.as_str());
        let trash = uniquify(&base, " ", |p| p.exists());
        if let Some(parent) = trash.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_error("mkdir failed", e))?;
        }
        std::fs::rename(&path, &trash).map_err(|e| io_error("delete failed", e))?;
        Ok(trash
            .strip_prefix(&self.root)
            .unwrap()
            .to_string_lossy()
            .into_owned())
    }

    pub async fn grep(
        &self,
        pattern: &str,
        context: i64,
        match_opts: &MatchOpts,
        walk_opts: &WalkOpts,
    ) -> Result<Vec<ContentHit>> {
        if pattern.is_empty() {
            return Err(rejected("pattern required"));
        }
        let hits = ripgrep(pattern, &self.root, context, match_opts, walk_opts).await?;
        let mut out = Vec::new();
        for (path, lines) in hits {
            if !self.filter_confine(&path) {
                continue;
            }
            out.push(ContentHit {
                rel: RelPath::new(self.rel_to(&path)),
                lines,
            });
        }
        Ok(out)
    }

    pub async fn match_path(
        &self,
        pattern: &str,
        match_opts: &MatchOpts,
        walk_opts: &WalkOpts,
    ) -> Result<Vec<RelPath>> {
        if pattern.is_empty() {
            return Err(rejected("pattern required"));
        }
        let mut by_rel: HashMap<String, ()> = HashMap::new();
        for path in walk_search(&self.root, walk_opts)? {
            if !self.filter_confine(&path) {
                continue;
            }
            by_rel.insert(self.rel_to(&path), ());
        }
        let rels: Vec<String> = by_rel.keys().cloned().collect();
        let matched = match_paths(pattern, &rels, match_opts).await?;
        Ok(matched
            .into_iter()
            .filter(|r| by_rel.contains_key(r))
            .map(RelPath::new)
            .collect())
    }
}

fn uniquify(base: &Path, sep: &str, taken: impl Fn(&Path) -> bool) -> PathBuf {
    if !taken(base) {
        return base.to_path_buf();
    }
    let stem = base
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = base.extension().map(|s| s.to_string_lossy().into_owned());
    let mut count = 0u64;
    loop {
        count += 1;
        let name = match &ext {
            Some(ext) => format!("{stem}{sep}{count}.{ext}"),
            None => format!("{stem}{sep}{count}"),
        };
        let candidate = base.with_file_name(name);
        if !taken(&candidate) {
            return candidate;
        }
    }
}
