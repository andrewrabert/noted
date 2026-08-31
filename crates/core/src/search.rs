use std::collections::{BTreeMap, HashSet};
use std::hash::Hash;

use clap::ValueEnum;
use grep_matcher::Matcher;
use grep_regex::{RegexMatcher, RegexMatcherBuilder};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::NotePath;
use crate::error::{Result, rejected};
use crate::newtype::str_newtype_validated;

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

#[derive(Clone)]
pub struct SearchQuery {
    pub(crate) pattern: SearchPattern,
    pub(crate) mode: SearchMode,
    pub(crate) order: SearchOrder,
    pub(crate) context: u32,
    pub(crate) fixed: bool,
    pub(crate) case: CaseMode,
    pub(crate) word: bool,
    pub(crate) multiline: bool,
    pub(crate) globs: Vec<GlobPattern>,
    pub(crate) types: Vec<FileType>,
}

impl SearchQuery {
    pub fn new(pattern: SearchPattern, mode: SearchMode) -> SearchQuery {
        SearchQuery {
            pattern,
            mode,
            order: SearchOrder::default(),
            context: 0,
            fixed: false,
            case: CaseMode::default(),
            word: false,
            multiline: false,
            globs: Vec::new(),
            types: Vec::new(),
        }
    }

    pub fn order(mut self, order: SearchOrder) -> SearchQuery {
        self.order = order;
        self
    }

    pub fn context(mut self, context: u32) -> SearchQuery {
        self.context = context;
        self
    }

    pub fn fixed(mut self, fixed: bool) -> SearchQuery {
        self.fixed = fixed;
        self
    }

    pub fn case(mut self, case: CaseMode) -> SearchQuery {
        self.case = case;
        self
    }

    pub fn word(mut self, word: bool) -> SearchQuery {
        self.word = word;
        self
    }

    pub fn multiline(mut self, multiline: bool) -> SearchQuery {
        self.multiline = multiline;
        self
    }

    pub fn globs(mut self, globs: Vec<GlobPattern>) -> SearchQuery {
        self.globs = globs;
        self
    }

    pub fn types(mut self, types: Vec<FileType>) -> SearchQuery {
        self.types = types;
        self
    }
}

impl Default for SearchQuery {
    fn default() -> SearchQuery {
        SearchQuery::new(SearchPattern::default(), SearchMode::default())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit<A = NotePath> {
    pub path: A,
    pub lines: BTreeMap<u64, String>,
}

impl<A> Hit<A> {
    pub fn lines(&self) -> impl Iterator<Item = (u64, &str)> {
        self.lines.iter().map(|(n, t)| (*n, t.as_str()))
    }
}

impl SearchQuery {
    pub(crate) fn matcher(&self) -> Result<RegexMatcher> {
        let mut b = RegexMatcherBuilder::new();
        match self.case {
            CaseMode::Smart => b.case_smart(true),
            CaseMode::Insensitive => b.case_insensitive(true),
            CaseMode::Sensitive => b.case_smart(false),
        };
        b.fixed_strings(self.fixed)
            .word(self.word)
            .multi_line(self.multiline)
            .build(self.pattern.as_str())
            .map_err(|e| rejected(format!("invalid search pattern: {e}")))
    }

    pub(crate) fn assemble<A>(&self, hits: Vec<Hit<A>>) -> Result<Vec<Hit<A>>>
    where
        A: std::fmt::Display + Clone + Eq + Hash,
    {
        if !matches!(self.mode, SearchMode::Any | SearchMode::Path) {
            return Ok(hits);
        }
        let matcher = self.matcher()?;
        let mut seen: HashSet<A> = HashSet::new();
        let mut out = Vec::new();
        for hit in hits {
            let keep = !hit.lines.is_empty() || {
                let name = hit.path.to_string();
                matcher
                    .is_match(name.as_bytes())
                    .map_err(|e| rejected(format!("search match failed: {e}")))?
            };
            if keep && seen.insert(hit.path.clone()) {
                out.push(hit);
            }
        }
        Ok(out)
    }
}
