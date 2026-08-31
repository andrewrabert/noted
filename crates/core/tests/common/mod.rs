#![allow(dead_code)]

use std::path::{Path as StdPath, PathBuf};

use noted::NotePath;
use noted::note::{Condition, TextNote};
use noted::search::{Hit, SearchMode, SearchQuery};
use noted::store::NotedDir;
use noted::tools::ToolOutput;
use noted::types::Source;
use noted::{Backend, BackendArgs, NotedRoot, PolicyArgs, PolicyFragment, ToolCall};
use serde_json::Value;

pub fn rp(s: &str) -> NotePath {
    NotePath::new(s).unwrap()
}

pub fn note(rel: &str, content: &str) -> TextNote {
    TextNote::new(rp(rel), content)
}

pub async fn read(root: &NotedRoot, rel: &str) -> noted::Result<String> {
    root.note_read(&rp(rel))
        .await
        .map(|n| n.body().as_str().to_string())
}

pub async fn write(root: &NotedRoot, note: &TextNote) -> noted::Result<()> {
    root.note_write(note, Condition::Always).await
}

pub fn held(text: &str) -> PolicyFragment {
    text.parse().unwrap()
}

pub fn query(pattern: &str, mode: SearchMode) -> SearchQuery {
    SearchQuery::new(pattern.parse().unwrap(), mode)
}

pub async fn grep(root: &NotedRoot, pattern: &str) -> noted::Result<Vec<Hit>> {
    root.note_search(&query(pattern, SearchMode::Line)).await
}

pub async fn found(root: &NotedRoot, pattern: &str) -> noted::Result<Vec<String>> {
    Ok(root
        .note_search(&query(pattern, SearchMode::Path))
        .await?
        .into_iter()
        .map(|hit| hit.path.to_string())
        .collect())
}

pub fn copy_tree(src: &StdPath, dst: &StdPath) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

pub fn fixture_dir() -> tempfile::TempDir {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/notes");
    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join("notes");
    copy_tree(&src, &dst);
    tmp
}

pub fn notes_root(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("notes")
}

pub fn root(dir: &tempfile::TempDir) -> NotedRoot {
    policed_root(dir, PolicyFragment::default())
}

pub fn confined(dir: &tempfile::TempDir, policy: &str) -> NotedRoot {
    policed_root(dir, held(policy))
}

pub fn policed_root(dir: &tempfile::TempDir, policy: PolicyFragment) -> NotedRoot {
    NotedRoot::open(NotedDir::new(notes_root(dir)), Some(Source::new("test")))
        .unwrap()
        .with_authority(&[policy])
        .unwrap()
}

pub fn backend(dir: &tempfile::TempDir) -> Backend {
    policed_backend(dir, PolicyFragment::default())
}

pub fn confined_backend(dir: &tempfile::TempDir, policy: &str) -> Backend {
    policed_backend(dir, held(policy))
}

pub fn policed_backend(dir: &tempfile::TempDir, policy: PolicyFragment) -> Backend {
    Backend::new(BackendArgs::Local {
        dir: NotedDir::new(notes_root(dir)),
        source: Some(Source::new("test")),
        policy: PolicyArgs {
            policy: Some(policy.to_string()),
            ..Default::default()
        },
    })
    .unwrap()
}

pub async fn invoke(backend: &Backend, name: &str, args: Value) -> noted::Result<ToolOutput> {
    let call = ToolCall::raw(name, args)?;
    backend.invoke(&call).await
}
