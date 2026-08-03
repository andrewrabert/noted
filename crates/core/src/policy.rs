use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{NotedError, Result, rejected};
use crate::path::Path;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    pub read: bool,
    pub write: bool,
}

fn nearest(entries: &BTreeMap<Path, Access>, at: &Path, root: Access) -> Access {
    at.ancestors()
        .find_map(|ancestor| entries.get(&ancestor).copied())
        .unwrap_or(root)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadableFile(Path);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WriteableFile(Path);

impl ReadableFile {
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn path(&self) -> Path {
        self.0.clone()
    }
}

impl WriteableFile {
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) fn path(&self) -> Path {
        self.0.clone()
    }
}

impl fmt::Display for ReadableFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for WriteableFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    scope: Option<Path>,
    root: Access,
    inside: BTreeMap<Path, Access>,
    extra: BTreeMap<Path, Access>,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy::new()
    }
}

impl Policy {
    pub fn new() -> Policy {
        Policy {
            scope: None,
            root: Access {
                read: true,
                write: true,
            },
            inside: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }

    pub fn with_fragments(fragments: &[PolicyFragment]) -> Result<Policy> {
        let mut policy = Policy::new();
        for fragment in fragments {
            let scope = match (&fragment.scope, &policy.scope) {
                (None, _) => policy.scope.clone(),
                (Some(scope), None) => Some(scope.clone()),
                (Some(scope), Some(held)) if scope.under(held) => Some(scope.clone()),
                (Some(scope), Some(held)) => {
                    return Err(PolicyError::ScopeOutsideHeld {
                        path: scope.clone(),
                        held: held.clone(),
                    }
                    .into());
                }
            };

            let held = match scope.as_ref() {
                Some(scope) => Access {
                    read: policy.readable(scope).is_ok(),
                    write: policy.writeable(scope).is_ok(),
                },
                None => policy.root,
            };
            let root = policy.narrowed(scope.as_ref(), fragment.access.unwrap_or(held))?;

            let mut inside: BTreeMap<Path, Access> = policy
                .inside
                .iter()
                .chain(policy.extra.iter())
                .filter(|(at, _)| match &scope {
                    Some(scope) => at.under(scope),
                    None => true,
                })
                .map(|(at, access)| (at.clone(), *access))
                .collect();
            if let Some(scope) = &scope {
                inside.insert(scope.clone(), root);
            }
            let mut extra: BTreeMap<Path, Access> = policy
                .extra
                .iter()
                .filter(|(at, _)| match &scope {
                    Some(scope) => !at.under(scope),
                    None => false,
                })
                .map(|(at, access)| (at.clone(), *access))
                .collect();

            for (at, access) in &fragment.paths {
                let at = match &scope {
                    Some(scope) => scope.join(at),
                    None => at.clone(),
                };
                inside.insert(at.clone(), policy.narrowed(Some(&at), *access)?);
            }
            for (at, access) in &fragment.extra {
                let inside_scope = match &scope {
                    Some(scope) => at.under(scope),
                    None => true,
                };
                if inside_scope {
                    return Err(PolicyError::ExtraInsideScope {
                        path: at.clone(),
                        scope: scope.clone(),
                    }
                    .into());
                }
                extra.insert(at.clone(), policy.narrowed(Some(at), *access)?);
            }

            let root = if scope.is_some() {
                Access::default()
            } else {
                root
            };
            policy = Policy {
                scope,
                root,
                inside,
                extra,
            };
        }
        Ok(policy)
    }

    pub fn scope(&self) -> Option<&Path> {
        self.scope.as_ref()
    }

    pub(crate) fn readable(&self, at: &Path) -> Result<ReadableFile> {
        let access = match &self.scope {
            Some(scope) if !at.under(scope) => nearest(&self.extra, at, Access::default()),
            _ => nearest(&self.inside, at, self.root),
        };
        match access.read {
            true => Ok(ReadableFile(at.clone())),
            false => Err(NotedError::Forbidden),
        }
    }

    pub(crate) fn writeable(&self, at: &Path) -> Result<WriteableFile> {
        let access = match &self.scope {
            Some(scope) if !at.under(scope) => nearest(&self.extra, at, Access::default()),
            _ => nearest(&self.inside, at, self.root),
        };
        match access.write {
            true => Ok(WriteableFile(at.clone())),
            false => Err(NotedError::Forbidden),
        }
    }

    fn narrowed(&self, at: Option<&Path>, access: Access) -> Result<Access> {
        let held = match at {
            Some(at) => Access {
                read: self.readable(at).is_ok(),
                write: self.writeable(at).is_ok(),
            },
            None => self.root,
        };
        if access.read && !held.read || access.write && !held.write {
            return Err(PolicyError::Widens { path: at.cloned() }.into());
        }
        Ok(access)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    ExtraInsideScope { path: Path, scope: Option<Path> },
    ScopeOutsideHeld { path: Path, held: Path },
    Widens { path: Option<Path> },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::ExtraInsideScope { path, scope } => match scope {
                Some(scope) => write!(
                    f,
                    "'{path}' is inside the scope '{scope}': write it under paths"
                ),
                None => write!(f, "'{path}' is inside the root scope: write it under paths"),
            },
            PolicyError::ScopeOutsideHeld { path, held } => write!(
                f,
                "scope '{path}' is outside the held scope '{held}': a fragment may only deepen the scope"
            ),
            PolicyError::Widens { path } => match path {
                Some(path) => write!(f, "'{path}' grants access the holder does not have"),
                None => write!(f, "the root grants access the holder does not have"),
            },
        }
    }
}

impl From<PolicyError> for NotedError {
    fn from(e: PolicyError) -> NotedError {
        rejected(e.to_string())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyFragment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Path>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub paths: BTreeMap<Path, Access>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<Path, Access>,
}

impl PolicyFragment {
    pub fn everything() -> PolicyFragment {
        PolicyFragment {
            scope: None,
            access: Some(Access {
                read: true,
                write: true,
            }),
            paths: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }
}

impl fmt::Display for PolicyFragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => f.write_str(&json),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl FromStr for PolicyFragment {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<PolicyFragment> {
        serde_yaml::from_str(s).map_err(|e| rejected(format!("invalid policy: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(s: &str) -> PolicyFragment {
        PolicyFragment::from_str(s).unwrap()
    }

    fn at(s: &str) -> Path {
        Path::new(s).unwrap()
    }

    #[test]
    fn fragment_round_trips_through_its_canonical_json() {
        let text = r#"{"scope":"dev","access":{"read":true,"write":false},"paths":{"vendor":{"read":false,"write":false}},"extra":{"finance":{"read":true,"write":true}}}"#;
        let parsed = fragment(text);
        assert_eq!(parsed.to_string(), text);
        assert_eq!(fragment(&parsed.to_string()), parsed);
        assert_eq!(parsed.scope, Some(at("dev")));
        assert_eq!(
            parsed.paths[&at("vendor")],
            Access {
                read: false,
                write: false,
            }
        );
    }

    #[test]
    fn a_fragment_may_only_narrow() {
        let policy = Policy::with_fragments(&[fragment(
            r#"{"paths":{"vendor":{"read":true,"write":false}}}"#,
        )])
        .unwrap();
        assert!(policy.readable(&at("vendor")).is_ok());
        assert!(policy.writeable(&at("vendor")).is_err());
        assert!(policy.readable(&at("vendor/x.md")).is_ok());
        assert!(policy.writeable(&at("vendor/x.md")).is_err());
        assert!(policy.readable(&at("other")).is_ok());
        assert!(policy.writeable(&at("other")).is_ok());

        let widened = Policy::with_fragments(&[
            fragment(r#"{"paths":{"vendor":{"read":true,"write":false}}}"#),
            fragment(r#"{"paths":{"vendor":{"read":true,"write":true}}}"#),
        ]);
        assert!(matches!(widened, Err(NotedError::InvalidInput(_))));
    }

    #[test]
    fn narrowing_the_scope_denies_everything_outside_it() {
        let policy = Policy::with_fragments(&[fragment(r#"{"scope":"dev"}"#)]).unwrap();
        assert_eq!(policy.scope(), Some(&at("dev")));
        assert!(policy.readable(&at("dev/a.md")).is_ok());
        assert!(policy.writeable(&at("dev/a.md")).is_ok());
        assert!(policy.readable(&at("other/a.md")).is_err());
        assert!(policy.writeable(&at("other/a.md")).is_err());
    }

    #[test]
    fn extra_reaches_outside_the_scope_and_never_inside_it() {
        let policy = Policy::with_fragments(&[fragment(
            r#"{"scope":"dev","extra":{"finance":{"read":true,"write":false},"finance/payroll":{"read":false,"write":false}}}"#,
        )])
        .unwrap();
        assert!(policy.readable(&at("finance/q1.md")).is_ok());
        assert!(policy.writeable(&at("finance/q1.md")).is_err());
        assert!(policy.readable(&at("finance/payroll/a.md")).is_err());
        assert!(policy.writeable(&at("finance/payroll/a.md")).is_err());

        let inside = Policy::with_fragments(&[fragment(
            r#"{"scope":"dev","extra":{"dev/x":{"read":true,"write":false}}}"#,
        )]);
        assert!(
            matches!(inside, Err(NotedError::InvalidInput(ref m)) if m.contains("inside the scope"))
        );
    }

    #[test]
    fn a_deeper_entry_wins_over_its_ancestors() {
        let policy =
            Policy::with_fragments(&[fragment(r#"{"paths":{"a":{"read":true,"write":false},"a/b":{"read":true,"write":true},"a/b/c":{"read":false,"write":false}}}"#)])
                .unwrap();
        assert!(policy.readable(&at("a/x.md")).is_ok());
        assert!(policy.writeable(&at("a/x.md")).is_err());
        assert!(policy.readable(&at("a/b/x.md")).is_ok());
        assert!(policy.writeable(&at("a/b/x.md")).is_ok());
        assert!(policy.readable(&at("a/b/c/x.md")).is_err());
        assert!(policy.writeable(&at("a/b/c/x.md")).is_err());
    }

    #[test]
    fn a_fragment_reaching_what_the_holder_cannot_is_refused() {
        assert!(matches!(
            Policy::with_fragments(&[
                fragment(r#"{"scope":"dev"}"#),
                fragment(r#"{"extra":{"finance":{"read":true,"write":false}}}"#),
            ]),
            Err(NotedError::InvalidInput(_))
        ));
        assert!(matches!(
            Policy::with_fragments(&[
                fragment(r#"{"scope":"dev"}"#),
                fragment(r#"{"scope":"other"}"#),
            ]),
            Err(NotedError::InvalidInput(_))
        ));
        assert!(
            Policy::with_fragments(&[
                fragment(r#"{"scope":"dev"}"#),
                fragment(r#"{"scope":"dev/deep"}"#),
            ])
            .is_ok()
        );
    }

    #[test]
    fn write_does_not_imply_read() {
        let policy =
            Policy::with_fragments(&[fragment(r#"{"access":{"read":false,"write":true}}"#)])
                .unwrap();
        assert!(policy.writeable(&at("a.md")).is_ok());
        assert!(policy.readable(&at("a.md")).is_err());
    }
}
