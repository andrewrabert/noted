use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{rejected, Result};
use crate::tools::is_tool;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub tools: Option<BTreeSet<String>>,
    pub paths: Option<Vec<String>>,
}

impl Rule {
    fn grants_tool(&self, tool: &str) -> bool {
        match &self.tools {
            None => true,
            Some(set) => set.contains(tool),
        }
    }

    fn intersect(&self, other: &Rule) -> Option<Rule> {
        let tools = match (&self.tools, &other.tools) {
            (None, None) => None,
            (Some(s), None) | (None, Some(s)) => Some(s.clone()),
            (Some(x), Some(y)) => {
                let inter: BTreeSet<String> = x.intersection(y).cloned().collect();
                if inter.is_empty() {
                    return None;
                }
                Some(inter)
            }
        };
        let paths = match (&self.paths, &other.paths) {
            (None, None) => None,
            (Some(p), None) | (None, Some(p)) => Some(p.clone()),
            (Some(pa), Some(pb)) => {
                let inter = intersect_prefixes(pa, pb);
                if inter.is_empty() {
                    return None;
                }
                Some(inter)
            }
        };
        Some(Rule { tools, paths })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenScope {
    pub rules: Vec<Rule>,
}

impl TokenScope {
    pub fn full() -> TokenScope {
        TokenScope {
            rules: vec![Rule {
                tools: None,
                paths: None,
            }],
        }
    }

    pub fn allows(&self, tool: &str) -> bool {
        self.rules.iter().any(|r| r.grants_tool(tool))
    }

    pub fn folders_for(&self, tool: &str) -> Option<Vec<String>> {
        let mut acc = Vec::new();
        for r in &self.rules {
            if !r.grants_tool(tool) {
                continue;
            }
            let ps = r.paths.as_ref()?;
            acc.extend(ps.iter().cloned());
        }
        Some(acc)
    }

    pub fn single_rule(
        tools: Option<Vec<String>>,
        paths: Option<Vec<String>>,
    ) -> Result<TokenScope> {
        Ok(TokenScope {
            rules: vec![build_rule(tools.as_deref(), paths.as_deref())?],
        })
    }

    pub fn intersect(&self, other: &TokenScope) -> TokenScope {
        let mut rules = Vec::new();
        for a in &self.rules {
            for b in &other.rules {
                if let Some(r) = a.intersect(b) {
                    rules.push(r);
                }
            }
        }
        TokenScope { rules }
    }
}

fn intersect_prefixes(a: &[String], b: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for x in a {
        for y in b {
            let pick = if is_within(x, y) {
                Some(x)
            } else if is_within(y, x) {
                Some(y)
            } else {
                None
            };
            if let Some(p) = pick {
                if seen.insert(p.as_str()) {
                    out.push(p.clone());
                }
            }
        }
    }
    out
}

fn is_within(path: &str, base: &str) -> bool {
    path == base || path.starts_with(&format!("{base}/"))
}

pub fn compile_rules(specs: &[RuleSpec]) -> Result<TokenScope> {
    let rules = specs
        .iter()
        .map(|r| build_rule(r.tools.as_deref(), r.paths.as_deref()))
        .collect::<Result<Vec<_>>>()?;
    Ok(TokenScope { rules })
}

pub fn normalize_folder(raw: &str) -> Result<String> {
    let rel = raw.trim().trim_matches('/');
    let parts: Vec<&str> = if rel.is_empty() {
        Vec::new()
    } else {
        rel.split('/').collect()
    };
    if parts.is_empty()
        || parts
            .iter()
            .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return Err(rejected(format!("invalid folder in policy: '{raw}'")));
    }
    Ok(parts.join("/"))
}

fn build_rule(tools: Option<&[String]>, paths: Option<&[String]>) -> Result<Rule> {
    let tools = match tools {
        None => None,
        Some(list) => {
            let mut set = BTreeSet::new();
            for t in list {
                if !is_tool(t) {
                    return Err(rejected(format!("unknown tool in policy: '{t}'")));
                }
                set.insert(t.clone());
            }
            Some(set)
        }
    };
    let paths = match paths {
        None => None,
        Some(list) => Some(
            list.iter()
                .map(|p| normalize_folder(p))
                .collect::<Result<Vec<_>>>()?,
        ),
    };
    Ok(Rule { tools, paths })
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum StoredScope {
    #[serde(rename = "unrestricted")]
    Unrestricted,
    #[serde(rename = "grants")]
    Grants(Vec<RuleSpec>),
}

impl StoredScope {
    pub fn compile(&self) -> Result<TokenScope> {
        match self {
            StoredScope::Unrestricted => Ok(TokenScope::full()),
            StoredScope::Grants(specs) => compile_rules(specs),
        }
    }

    pub fn summary(&self) -> String {
        match self {
            StoredScope::Unrestricted => "unrestricted".to_string(),
            StoredScope::Grants(g) => format!("{} grant(s)", g.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(tools: Option<&[&str]>, paths: Option<&[&str]>) -> TokenScope {
        TokenScope::single_rule(
            tools.map(|t| t.iter().map(|s| s.to_string()).collect()),
            paths.map(|p| p.iter().map(|s| s.to_string()).collect()),
        )
        .unwrap()
    }

    #[test]
    fn intersect_full_is_identity() {
        let child = rule(Some(&["ReadNote"]), Some(&["projects"]));
        let got = child.intersect(&TokenScope::full());
        assert!(got.allows("ReadNote") && !got.allows("WriteNote"));
        assert_eq!(
            got.folders_for("ReadNote"),
            Some(vec!["projects".to_string()])
        );
    }

    #[test]
    fn intersect_tools_is_set_intersection() {
        let a = rule(Some(&["ReadNote", "SearchNotes"]), None);
        let b = rule(Some(&["WriteNote"]), None);
        let got = a.intersect(&b);
        assert!(!got.allows("ReadNote") && !got.allows("WriteNote"));
    }

    #[test]
    fn intersect_paths_keeps_the_deeper_prefix() {
        let a = rule(None, Some(&["projects"]));
        let b = rule(None, Some(&["projects/drafts"]));
        let got = a.intersect(&b);
        assert_eq!(
            got.folders_for("ReadNote"),
            Some(vec!["projects/drafts".to_string()])
        );
    }

    #[test]
    fn intersect_disjoint_paths_grants_nothing() {
        let a = rule(None, Some(&["projects"]));
        let b = rule(None, Some(&["people"]));
        let got = a.intersect(&b);
        assert!(got.rules.is_empty());
    }

    #[test]
    fn stored_scope_serde_is_tagged() {
        let unrestricted = serde_json::to_value(&StoredScope::Unrestricted).unwrap();
        assert_eq!(unrestricted, serde_json::json!("unrestricted"));
        let grants = StoredScope::Grants(vec![RuleSpec {
            tools: Some(vec!["ReadNote".into()]),
            paths: Some(vec!["projects".into()]),
        }]);
        let json = serde_json::to_value(&grants).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"grants": [{"tools": ["ReadNote"], "paths": ["projects"]}]})
        );
        let back: StoredScope = serde_json::from_value(json).unwrap();
        assert_eq!(back, grants);
    }

    #[test]
    fn stored_scope_compiles_fail_closed() {
        let full = StoredScope::Unrestricted.compile().unwrap();
        assert!(full.allows("WriteNote"));
        let none = StoredScope::Grants(Vec::new()).compile().unwrap();
        assert!(!none.allows("ReadNote"));
        let empty_tools = StoredScope::Grants(vec![RuleSpec {
            tools: Some(Vec::new()),
            paths: None,
        }])
        .compile()
        .unwrap();
        assert!(!empty_tools.allows("ReadNote"));
        assert!(
            serde_json::from_value::<Vec<RuleSpec>>(serde_json::json!([{"path": ["a"]}])).is_err()
        );
        let phantom = StoredScope::Grants(vec![RuleSpec {
            tools: Some(vec!["NotATool".into()]),
            paths: None,
        }]);
        assert!(phantom.compile().is_err());
        let bad_path = StoredScope::Grants(vec![RuleSpec {
            tools: None,
            paths: Some(vec!["../escape".into()]),
        }]);
        assert!(bad_path.compile().is_err());
    }
}
