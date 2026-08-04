use std::collections::{BTreeMap, HashSet};
use std::hash::Hash;
use std::path::Path as StdPath;

use clap::ValueEnum;
use grep::matcher::Matcher;
use grep::regex::{RegexMatcher, RegexMatcherBuilder};
use grep::searcher::{Searcher, SinkContext, SinkMatch};
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use ignore::types::TypesBuilder;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Result, rejected};
use crate::newtype::str_newtype_validated;
use crate::path::Path;

#[derive(Serialize, Deserialize, JsonSchema, ValueEnum, Default, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CaseMode {
    #[default]
    Smart,
    Insensitive,
    Sensitive,
}

// Tool-schema field: a rustdoc comment here ships as the wire description.
#[derive(Serialize, Deserialize, JsonSchema, ValueEnum, Default, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SearchMode {
    #[default]
    Any,
    Line,
    File,
    Path,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct SearchPattern(String);
str_newtype_validated!(SearchPattern, validate_pattern);

fn validate_pattern(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(rejected("pattern required"));
    }
    Ok(())
}

impl SearchPattern {
    pub fn everything() -> SearchPattern {
        SearchPattern(".".to_string())
    }
}

impl Default for SearchPattern {
    fn default() -> SearchPattern {
        SearchPattern::everything()
    }
}

// Tool-schema field: a rustdoc comment here ships as the wire description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct GlobPattern(String);
str_newtype_validated!(GlobPattern, validate_glob);

fn validate_glob(s: &str) -> Result<()> {
    let path = s.strip_prefix('!').unwrap_or(s);
    if path.is_empty() || path.starts_with('/') || path.split('/').any(|seg| seg == "..") {
        return Err(rejected(format!("invalid glob: '{s}'")));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct FileType(String);
str_newtype_validated!(FileType, validate_file_type);

fn validate_file_type(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(rejected("file type required"));
    }
    Ok(())
}

// 'path' is case-insensitive path order
// 'modified' puts the most recently modified file first, ties broken by path
#[derive(Serialize, Deserialize, JsonSchema, ValueEnum, Default, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SearchOrder {
    #[default]
    Path,
    Modified,
}

#[derive(Clone, Default)]
pub struct SearchQuery {
    pub pattern: SearchPattern,
    pub mode: SearchMode,
    pub order: SearchOrder,
    pub context: u32,
    pub fixed: bool,
    pub case: CaseMode,
    pub word: bool,
    pub multiline: bool,
    pub globs: Vec<GlobPattern>,
    pub types: Vec<FileType>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit<A = Path> {
    pub path: A,
    pub lines: BTreeMap<u64, String>,
}

impl<A> Hit<A> {
    pub fn lines(&self) -> impl Iterator<Item = (u64, &str)> {
        self.lines.iter().map(|(n, t)| (*n, t.as_str()))
    }
}

pub(crate) fn build_matcher(query: &SearchQuery) -> Result<RegexMatcher> {
    let mut b = RegexMatcherBuilder::new();
    match query.case {
        CaseMode::Smart => b.case_smart(true),
        CaseMode::Insensitive => b.case_insensitive(true),
        CaseMode::Sensitive => b.case_smart(false),
    };
    b.fixed_strings(query.fixed)
        .word(query.word)
        .multi_line(query.multiline)
        .build(query.pattern.as_str())
        .map_err(|e| rejected(format!("invalid search pattern: {e}")))
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

pub(crate) fn narrow(wb: &mut WalkBuilder, base: &StdPath, query: &SearchQuery) -> Result<()> {
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

pub(crate) fn assemble<A>(query: &SearchQuery, hits: Vec<Hit<A>>) -> Result<Vec<Hit<A>>>
where
    A: std::fmt::Display + Clone + Eq + Hash,
{
    if !matches!(query.mode, SearchMode::Any | SearchMode::Path) {
        return Ok(hits);
    }
    let matcher = build_matcher(query)?;
    let mut seen: HashSet<A> = HashSet::new();
    let mut out = Vec::new();
    for hit in hits {
        let keep = !hit.lines.is_empty()
            || matcher
                .is_match(hit.path.to_string().as_bytes())
                .unwrap_or(false);
        if keep && seen.insert(hit.path.clone()) {
            out.push(hit);
        }
    }
    Ok(out)
}

pub(crate) struct LineSink {
    pub(crate) lines: BTreeMap<u64, String>,
}

impl LineSink {
    pub(crate) fn new() -> LineSink {
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

impl grep::searcher::Sink for LineSink {
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
