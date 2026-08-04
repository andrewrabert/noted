use std::fmt;

use fast_radix_trie::StringRadixMap;

use crate::error::{NotedError, Result, rejected};
use crate::fragment::{AccessFragment, RegionFragment};
use crate::path::{DirPath, Path};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Access {
    pub read: bool,
    pub write: bool,
}

impl AccessFragment {
    fn applied_to(
        &self,
        ceiling: Access,
        default: Access,
    ) -> std::result::Result<Access, AccessFragment> {
        let over = AccessFragment {
            read: (self.read == Some(true) && !ceiling.read).then_some(true),
            write: (self.write == Some(true) && !ceiling.write).then_some(true),
        };
        if over != AccessFragment::default() {
            return Err(over);
        }
        Ok(Access {
            read: self.read.unwrap_or(default.read),
            write: self.write.unwrap_or(default.write),
        })
    }
}

fn resolved(
    at: &DirPath,
    asked: AccessFragment,
    ceiling: Access,
    default: Access,
) -> Result<Access> {
    asked
        .applied_to(ceiling, default)
        .map_err(|asked| PolicyError::Exceeds {
            path: at.clone(),
            asked,
        })
        .map_err(NotedError::from)
}

#[derive(Clone, Debug)]
struct AccessEntries(StringRadixMap<Access>);

impl AccessEntries {
    fn new(base: &DirPath) -> AccessEntries {
        let mut entries = StringRadixMap::new();
        entries.insert(
            base.as_str(),
            Access {
                read: true,
                write: true,
            },
        );
        AccessEntries(entries)
    }

    // each name's ceiling is `self`, the policy before the fragment; its default is
    // `covering`, never `entries`, so named entries neither fill nor cap one another
    // and a fragment may deny at the base yet reopen a name beneath it
    fn with_entries(
        &self,
        base: (DirPath, AccessFragment),
        named: impl IntoIterator<Item = (DirPath, AccessFragment)>,
    ) -> Result<AccessEntries> {
        let (at, asked) = base;
        let prior = self.for_path(&at);
        let mut covering = self.clone();
        covering
            .0
            .insert(at.as_str(), resolved(&at, asked, prior, prior)?);

        let mut entries = covering.clone();
        for (at, asked) in named {
            let access = resolved(&at, asked, self.for_path(&at), covering.for_path(&at))?;
            entries.0.insert(at.as_str(), access);
        }
        Ok(entries)
    }

    fn for_path(&self, at: &DirPath) -> Access {
        match self.0.get_longest_common_prefix(at.as_str()) {
            Some((_, access)) => *access,
            None => Access::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RegionPolicy {
    scope: Option<Path>,
    base: DirPath,
    entries: AccessEntries,
}

impl RegionPolicy {
    pub fn new(base: DirPath) -> RegionPolicy {
        RegionPolicy {
            scope: None,
            entries: AccessEntries::new(&base),
            base,
        }
    }

    pub(crate) fn with_policy_fragment(&self, fragment: &RegionFragment) -> Result<RegionPolicy> {
        let (scope, base) = match (&self.scope, &fragment.scope) {
            (_, None) => (self.scope.clone(), self.base.clone()),
            (None, Some(deeper)) => (Some(deeper.clone()), self.base.join(deeper)),
            (Some(scope), Some(deeper)) => (Some(scope.join(deeper)), self.base.join(deeper)),
        };
        let entries = self.entries.with_entries(
            (base.clone(), fragment.access),
            fragment.named.iter().map(|(at, asked)| {
                let at = match at {
                    Some(at) => base.join(at),
                    None => base.clone(),
                };
                (at, *asked)
            }),
        )?;

        Ok(RegionPolicy {
            scope,
            base,
            entries,
        })
    }

    pub(crate) fn readable(&self, rel: &Path) -> Result<Readable> {
        let at = self.base.join(rel);
        match (self.entries.for_path(&at).read, at.to_path()) {
            (true, Some(path)) => Ok(Readable(path)),
            _ => Err(NotedError::Forbidden),
        }
    }

    pub(crate) fn writeable(&self, rel: &Path) -> Result<Writeable> {
        let at = self.base.join(rel);
        match (self.entries.for_path(&at).write, at.to_path()) {
            (true, Some(path)) => Ok(Writeable(path)),
            _ => Err(NotedError::Forbidden),
        }
    }

    pub fn access(&self) -> Access {
        self.entries.for_path(&self.base)
    }

    pub(crate) fn base(&self) -> &DirPath {
        &self.base
    }

    pub(crate) fn scope(&self) -> Option<&Path> {
        self.scope.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Readable(pub(crate) Path);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Writeable(pub(crate) Path);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    Exceeds {
        path: DirPath,
        asked: AccessFragment,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Exceeds { path, asked } => write!(
                f,
                "'{path}' asks for {asked}, which the holder does not have there"
            ),
        }
    }
}

impl From<PolicyError> for NotedError {
    fn from(e: PolicyError) -> NotedError {
        rejected(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> Path {
        Path::new(s).unwrap()
    }

    fn asked(read: Option<bool>, write: Option<bool>) -> AccessFragment {
        AccessFragment { read, write }
    }

    fn applied(policy: &RegionPolicy, fragment: RegionFragment) -> Result<RegionPolicy> {
        policy.with_policy_fragment(&fragment)
    }

    fn root() -> RegionPolicy {
        RegionPolicy::new(DirPath::root())
    }

    #[test]
    fn a_fresh_policy_allows_everything_over_its_base() {
        let policy = root();
        assert_eq!(
            policy.access(),
            Access {
                read: true,
                write: true
            }
        );
        assert_eq!(policy.readable(&at("a/b.md")).unwrap().0, at("a/b.md"));
    }

    #[test]
    fn a_named_entry_never_reaches_across_a_name_boundary() {
        let policy = applied(
            &root(),
            RegionFragment {
                named: vec![(Some(at("work")), asked(Some(false), Some(false)))],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(policy.readable(&at("work/a.md")).is_err());
        assert!(policy.readable(&at("workshop/a.md")).is_ok());
    }

    #[test]
    fn the_access_covers_the_named_entries() {
        let policy = applied(
            &root(),
            RegionFragment {
                access: asked(None, Some(false)),
                named: vec![(Some(at("vendor")), asked(Some(false), None))],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(policy.writeable(&at("vendor/x.md")).is_err());
        assert!(policy.readable(&at("vendor/x.md")).is_err());
        assert!(policy.readable(&at("other/x.md")).is_ok());
        assert!(policy.writeable(&at("other/x.md")).is_err());
    }

    #[test]
    fn a_sibling_denial_does_not_cover_a_deeper_named_entry() {
        let policy = applied(
            &root(),
            RegionFragment {
                named: vec![
                    (None, asked(Some(true), Some(false))),
                    (Some(at("task_0001.md")), asked(Some(true), Some(true))),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(policy.writeable(&at("task_0001.md")).is_ok());
        assert!(policy.writeable(&at("task_0002.md")).is_err());
        assert!(policy.readable(&at("task_0002.md")).is_ok());
    }

    #[test]
    fn a_deny_all_access_still_lets_a_named_entry_reopen() {
        let policy = applied(
            &root(),
            RegionFragment {
                access: asked(Some(false), Some(false)),
                named: vec![(Some(at("Log")), asked(Some(true), Some(true)))],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(policy.readable(&at("Log/a.md")).is_ok());
        assert!(policy.writeable(&at("Log/a.md")).is_ok());
        assert!(policy.readable(&at("other/a.md")).is_err());
        assert!(policy.writeable(&at("other/a.md")).is_err());
    }

    #[test]
    fn a_later_fragment_cannot_reopen_what_an_earlier_one_closed() {
        let closed = applied(
            &root(),
            RegionFragment {
                named: vec![(Some(at("secrets")), asked(Some(false), Some(false)))],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(matches!(
            applied(
                &closed,
                RegionFragment {
                    access: asked(Some(false), Some(false)),
                    named: vec![(Some(at("secrets")), asked(Some(true), None))],
                    ..Default::default()
                },
            ),
            Err(NotedError::InvalidInput(_))
        ));
    }

    #[test]
    fn asking_for_more_than_the_covering_key_is_refused() {
        let closed = applied(
            &root(),
            RegionFragment {
                access: asked(Some(true), Some(false)),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(matches!(
            applied(
                &closed,
                RegionFragment {
                    access: asked(None, Some(true)),
                    ..Default::default()
                },
            ),
            Err(NotedError::InvalidInput(_))
        ));
    }

    #[test]
    fn a_scope_deepens_the_base_and_nothing_above_it_is_addressable() {
        let scoped = applied(
            &root(),
            RegionFragment {
                scope: Some(at("projects")),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(scoped.scope(), Some(&at("projects")));
        assert_eq!(scoped.readable(&at("a.md")).unwrap().0, at("projects/a.md"));

        let deeper = applied(
            &scoped,
            RegionFragment {
                scope: Some(at("alpha")),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(deeper.scope(), Some(&at("projects/alpha")));
        assert_eq!(
            deeper.readable(&at("a.md")).unwrap().0,
            at("projects/alpha/a.md")
        );
    }

    #[test]
    fn write_does_not_imply_read() {
        let policy = applied(
            &root(),
            RegionFragment {
                access: asked(Some(false), Some(true)),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(policy.writeable(&at("a.md")).is_ok());
        assert!(policy.readable(&at("a.md")).is_err());
    }
}
