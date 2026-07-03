use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use grep::matcher::Matcher;
use grep::regex::{RegexMatcher, RegexMatcherBuilder};
use grep::searcher::{Searcher, SearcherBuilder, Sink, SinkContext, SinkMatch};
use ignore::overrides::OverrideBuilder;
use ignore::types::TypesBuilder;
use ignore::{WalkBuilder, WalkState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{rejected, unavailable, Result};
use crate::util::normalize;

#[derive(Serialize, Deserialize, JsonSchema, ValueEnum, Default, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CaseMode {
    #[default]
    Smart,
    Insensitive,
    Sensitive,
}

#[derive(Clone, Default)]
pub struct MatchOpts {
    pub fixed_strings: bool,
    pub case: CaseMode,
    pub word: bool,
    pub multiline: bool,
}

#[derive(Clone, Default)]
pub struct WalkOpts {
    pub globs: Vec<String>,
    pub types: Vec<String>,
}

fn build_matcher(pattern: &str, opts: &MatchOpts) -> Result<RegexMatcher> {
    let mut b = RegexMatcherBuilder::new();
    match opts.case {
        CaseMode::Smart => b.case_smart(true),
        CaseMode::Insensitive => b.case_insensitive(true),
        CaseMode::Sensitive => b.case_smart(false),
    };
    b.fixed_strings(opts.fixed_strings)
        .word(opts.word)
        .multi_line(opts.multiline)
        .build(pattern)
        .map_err(|e| rejected(format!("invalid search pattern: {e}")))
}

fn expand_glob(entry: &str) -> Result<Vec<String>> {
    let (bang, path) = match entry.strip_prefix('!') {
        Some(rest) => ("!", rest),
        None => ("", entry),
    };
    if path.starts_with('/') || path.split('/').any(|seg| seg == "..") {
        return Err(rejected(format!("invalid glob: '{entry}'")));
    }
    let has_meta = path
        .chars()
        .any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}'));
    if has_meta {
        Ok(vec![entry.to_string()])
    } else {
        let p = path.trim_end_matches('/');
        Ok(vec![format!("{bang}{p}"), format!("{bang}{p}/**")])
    }
}

fn build_walker(base: &Path, opts: &WalkOpts) -> Result<WalkBuilder> {
    let mut wb = crate::util::walk_builder(base);

    if !opts.globs.is_empty() {
        let mut ob = OverrideBuilder::new(base);
        for entry in &opts.globs {
            for g in expand_glob(entry)? {
                ob.add(&g)
                    .map_err(|e| rejected(format!("invalid glob: '{entry}': {e}")))?;
            }
        }
        let overrides = ob
            .build()
            .map_err(|e| rejected(format!("invalid glob: {e}")))?;
        wb.overrides(overrides);
    }

    if !opts.types.is_empty() {
        let mut tb = TypesBuilder::new();
        tb.add_defaults();
        for t in &opts.types {
            tb.select(t);
        }
        let types = tb
            .build()
            .map_err(|e| rejected(format!("invalid file type: {e}")))?;
        wb.types(types);
    }

    Ok(wb)
}

pub fn walk_search(base: &Path, opts: &WalkOpts) -> Result<Vec<PathBuf>> {
    Ok(build_walker(base, opts)?
        .build()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            match entry.file_type() {
                Some(ft) if ft.is_file() => Some(entry.into_path()),
                _ => None,
            }
        })
        .collect())
}

struct LineSink {
    lines: BTreeMap<u64, String>,
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

impl Sink for LineSink {
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

pub async fn ripgrep(
    pattern: &str,
    base: &Path,
    context: i64,
    match_opts: &MatchOpts,
    walk_opts: &WalkOpts,
) -> Result<HashMap<PathBuf, BTreeMap<u64, String>>> {
    let matcher = build_matcher(pattern, match_opts)?;
    let multiline = match_opts.multiline;
    let base = base.to_path_buf();
    let walk_opts = walk_opts.clone();
    let ctx = if context > 0 { context as usize } else { 0 };

    tokio::task::spawn_blocking(move || {
        let walker = build_walker(&base, &walk_opts)?.build_parallel();
        let hits: std::sync::Mutex<HashMap<PathBuf, BTreeMap<u64, String>>> =
            std::sync::Mutex::new(HashMap::new());

        walker.run(|| {
            let mut searcher = SearcherBuilder::new()
                .line_number(true)
                .multi_line(multiline)
                .before_context(ctx)
                .after_context(ctx)
                .build();
            let matcher = &matcher;
            let hits = &hits;
            Box::new(move |entry| {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => return WalkState::Continue,
                };
                match entry.file_type() {
                    Some(ft) if ft.is_file() => {}
                    _ => return WalkState::Continue,
                }
                let path = entry.into_path();
                let mut sink = LineSink {
                    lines: BTreeMap::new(),
                };
                if searcher.search_path(matcher, &path, &mut sink).is_err() {
                    return WalkState::Continue;
                }
                if !sink.lines.is_empty() {
                    hits.lock()
                        .unwrap()
                        .entry(normalize(&path))
                        .or_default()
                        .extend(sink.lines);
                }
                WalkState::Continue
            })
        });

        Ok(hits.into_inner().unwrap())
    })
    .await
    .map_err(|e| unavailable(format!("search: {e}")))?
}

pub async fn match_paths(
    pattern: &str,
    rel_paths: &[String],
    match_opts: &MatchOpts,
) -> Result<HashSet<String>> {
    if rel_paths.is_empty() {
        return Ok(HashSet::new());
    }
    let matcher = build_matcher(pattern, match_opts)?;
    let mut out = HashSet::new();
    for rel in rel_paths {
        if matcher.is_match(rel.as_bytes()).unwrap_or(false) {
            out.insert(rel.clone());
        }
    }
    Ok(out)
}
