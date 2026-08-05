use std::collections::{BTreeMap, HashSet};
use std::hash::Hash;

use clap::ValueEnum;
use grep_matcher::Matcher;
use grep_regex::{RegexMatcher, RegexMatcherBuilder};
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
