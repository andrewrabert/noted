use std::fmt;

use fast_radix_trie::StringRadixMap;

use crate::domain::{NotePath, Path, Region, Segment};
use crate::error::{NotedError, Result, rejected};
use crate::fragment::{AccessFragment, PolicyFragment};

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

// the one place a path becomes an index key: the region base and then the
// region-relative path, a separator after every segment, so a longest-prefix
// lookup stops at a segment boundary ('/docs/' never covers '/docsX/')
fn key(region: Region, at: &NotePath) -> String {
    let base = region.base();
    let mut out = String::from(Path::SEPARATOR);
    for part in base.segments().chain(at.segments()) {
        out.push_str(part.as_str());
        out.push_str(Path::SEPARATOR);
    }
    out
}

fn resolved(
    region: Region,
    at: &NotePath,
    asked: AccessFragment,
    ceiling: Access,
    default: Access,
) -> Result<Access> {
    asked
        .applied_to(ceiling, default)
        .map_err(|asked| PolicyError::Exceeds {
            region,
            at: at.clone(),
            asked,
        })
        .map_err(NotedError::from)
}

#[derive(Clone, Debug)]
struct AccessEntries(StringRadixMap<Access>);

impl AccessEntries {
    fn new(region: Region) -> AccessEntries {
        let mut entries = StringRadixMap::new();
        entries.insert(
            key(region, &NotePath::default()),
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
        region: Region,
        base: (&NotePath, AccessFragment),
        named: impl IntoIterator<Item = (NotePath, AccessFragment)>,
    ) -> Result<AccessEntries> {
        let (at, asked) = base;
        let prior = self.for_path(region, at);
        let mut covering = self.clone();
        covering
            .0
            .insert(key(region, at), resolved(region, at, asked, prior, prior)?);

        let mut entries = covering.clone();
        for (at, asked) in named {
            let access = resolved(
                region,
                &at,
                asked,
                self.for_path(region, &at),
                covering.for_path(region, &at),
            )?;
            entries.0.insert(key(region, &at), access);
        }
        Ok(entries)
    }

    fn for_path(&self, region: Region, at: &NotePath) -> Access {
        match self.0.get_longest_common_prefix(&key(region, at)) {
            Some((_, access)) => *access,
            None => Access::default(),
        }
    }
}

/// Where a note is inside its region: the scope joined to the name. Never the
/// region directory itself. Only the mint builds one; it leaves as segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegionNotePath(NotePath);

impl RegionNotePath {
    fn new(at: NotePath) -> Result<RegionNotePath> {
        let is_root = at.segments().next().is_none();
        match is_root {
            true => Err(NotedError::Forbidden),
            false => Ok(RegionNotePath(at)),
        }
    }

    pub(crate) fn segments(&self) -> impl Iterator<Item = &Segment> {
        self.0.segments()
    }
}

#[derive(Clone, Debug)]
pub struct RegionPolicy {
    region: Region,
    scope: NotePath,
    entries: AccessEntries,
}

impl RegionPolicy {
    pub(crate) fn new(region: Region) -> RegionPolicy {
        RegionPolicy {
            region,
            scope: NotePath::default(),
            entries: AccessEntries::new(region),
        }
    }

    pub(crate) fn with_policy_fragment(&self, fragment: &PolicyFragment) -> Result<RegionPolicy> {
        let scope = match &fragment.scope {
            None => self.scope.clone(),
            Some(deeper) => self.scope.join(deeper),
        };
        let entries = self.entries.with_entries(
            self.region,
            (&scope, fragment.access),
            fragment
                .paths
                .iter()
                .map(|(at, asked)| (scope.join(at), *asked)),
        )?;
        Ok(RegionPolicy {
            region: self.region,
            scope,
            entries,
        })
    }

    pub(crate) fn readable(&self, rel: &NotePath) -> Result<Readable> {
        let at = RegionNotePath::new(self.scope.join(rel))?;
        match self.entries.for_path(self.region, &at.0).read {
            true => Ok(Readable {
                region: self.region,
                at,
            }),
            false => Err(NotedError::Forbidden),
        }
    }

    pub(crate) fn writeable(&self, rel: &NotePath) -> Result<Writeable> {
        let at = RegionNotePath::new(self.scope.join(rel))?;
        match self.entries.for_path(self.region, &at.0).write {
            true => Ok(Writeable {
                region: self.region,
                at,
            }),
            false => Err(NotedError::Forbidden),
        }
    }

    pub fn access(&self) -> Access {
        self.entries.for_path(self.region, &self.scope)
    }

    pub(crate) fn scope(&self) -> &NotePath {
        &self.scope
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Readable {
    region: Region,
    at: RegionNotePath,
}

impl Readable {
    pub(crate) fn region(&self) -> Region {
        self.region
    }

    pub(crate) fn at(&self) -> &RegionNotePath {
        &self.at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Writeable {
    region: Region,
    at: RegionNotePath,
}

impl Writeable {
    pub(crate) fn region(&self) -> Region {
        self.region
    }

    pub(crate) fn at(&self) -> &RegionNotePath {
        &self.at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PolicyError {
    Exceeds {
        region: Region,
        at: NotePath,
        asked: AccessFragment,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Exceeds { region, at, asked } => write!(
                f,
                "'{}' asks for {asked}, which the holder does not have there",
                key(*region, at)
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
    use std::collections::BTreeMap;

    use super::*;

    fn at(s: &str) -> NotePath {
        NotePath::new(s).unwrap()
    }

    fn asked(read: Option<bool>, write: Option<bool>) -> AccessFragment {
        AccessFragment { read, write }
    }

    fn fragment(
        scope: Option<&str>,
        access: AccessFragment,
        paths: &[(&str, AccessFragment)],
    ) -> PolicyFragment {
        PolicyFragment {
            scope: scope.map(at),
            access,
            paths: paths
                .iter()
                .map(|(name, asked)| (at(name), *asked))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    fn applied(policy: &RegionPolicy, fragment: PolicyFragment) -> Result<RegionPolicy> {
        policy.with_policy_fragment(&fragment)
    }

    fn root() -> RegionPolicy {
        RegionPolicy::new(Region::Notes)
    }

    fn located(proof: &Readable) -> Vec<&str> {
        proof.at().segments().map(Segment::as_str).collect()
    }

    #[test]
    fn a_key_closes_every_segment_with_a_separator() {
        assert_eq!(key(Region::Notes, &at("/")), "/");
        assert_eq!(key(Region::Log, &at("/")), "/.logs/");
        assert_eq!(key(Region::Tasks, &at("/a/b.md")), "/.tasks/a/b.md/");
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
        assert_eq!(
            located(&policy.readable(&at("/a/b.md")).unwrap()),
            ["a", "b.md"]
        );
    }

    #[test]
    fn the_region_directory_itself_is_never_minted() {
        assert!(matches!(
            root().readable(&at("/")),
            Err(NotedError::Forbidden)
        ));
        assert!(matches!(
            root().writeable(&at("/")),
            Err(NotedError::Forbidden)
        ));
    }

    #[test]
    fn a_named_entry_never_reaches_across_a_name_boundary() {
        let policy = applied(
            &root(),
            fragment(
                None,
                AccessFragment::default(),
                &[("/work", asked(Some(false), Some(false)))],
            ),
        )
        .unwrap();
        assert!(policy.readable(&at("/work/a.md")).is_err());
        assert!(policy.readable(&at("/workshop/a.md")).is_ok());
    }

    #[test]
    fn the_access_covers_the_named_entries() {
        let policy = applied(
            &root(),
            fragment(
                None,
                asked(None, Some(false)),
                &[("/vendor", asked(Some(false), None))],
            ),
        )
        .unwrap();
        assert!(policy.writeable(&at("/vendor/x.md")).is_err());
        assert!(policy.readable(&at("/vendor/x.md")).is_err());
        assert!(policy.readable(&at("/other/x.md")).is_ok());
        assert!(policy.writeable(&at("/other/x.md")).is_err());
    }

    #[test]
    fn a_sibling_denial_does_not_cover_a_deeper_named_entry() {
        let policy = applied(
            &root(),
            fragment(
                None,
                AccessFragment::default(),
                &[
                    ("/", asked(Some(true), Some(false))),
                    ("/task_0001.md", asked(Some(true), Some(true))),
                ],
            ),
        )
        .unwrap();
        assert!(policy.writeable(&at("/task_0001.md")).is_ok());
        assert!(policy.writeable(&at("/task_0002.md")).is_err());
        assert!(policy.readable(&at("/task_0002.md")).is_ok());
    }

    #[test]
    fn a_deny_all_access_still_lets_a_named_entry_reopen() {
        let policy = applied(
            &root(),
            fragment(
                None,
                asked(Some(false), Some(false)),
                &[("/open", asked(Some(true), Some(true)))],
            ),
        )
        .unwrap();
        assert!(policy.readable(&at("/open/a.md")).is_ok());
        assert!(policy.writeable(&at("/open/a.md")).is_ok());
        assert!(policy.readable(&at("/other/a.md")).is_err());
        assert!(policy.writeable(&at("/other/a.md")).is_err());
    }

    #[test]
    fn a_later_fragment_cannot_reopen_what_an_earlier_one_closed() {
        let closed = applied(
            &root(),
            fragment(
                None,
                AccessFragment::default(),
                &[("/secrets", asked(Some(false), Some(false)))],
            ),
        )
        .unwrap();
        assert!(matches!(
            applied(
                &closed,
                fragment(
                    None,
                    asked(Some(false), Some(false)),
                    &[("/secrets", asked(Some(true), None))],
                ),
            ),
            Err(NotedError::InvalidInput(_))
        ));
    }

    #[test]
    fn asking_for_more_than_the_covering_key_is_refused() {
        let closed = applied(&root(), fragment(None, asked(Some(true), Some(false)), &[])).unwrap();
        assert!(matches!(
            applied(&closed, fragment(None, asked(None, Some(true)), &[])),
            Err(NotedError::InvalidInput(_))
        ));
    }

    #[test]
    fn a_scope_deepens_the_base_and_nothing_above_it_is_addressable() {
        let scoped = applied(
            &root(),
            fragment(Some("/projects"), AccessFragment::default(), &[]),
        )
        .unwrap();
        assert_eq!(scoped.scope(), &at("/projects"));
        assert_eq!(
            located(&scoped.readable(&at("/a.md")).unwrap()),
            ["projects", "a.md"]
        );

        let deeper = applied(
            &scoped,
            fragment(Some("/alpha"), AccessFragment::default(), &[]),
        )
        .unwrap();
        assert_eq!(deeper.scope(), &at("/projects/alpha"));
        assert_eq!(
            located(&deeper.readable(&at("/a.md")).unwrap()),
            ["projects", "alpha", "a.md"]
        );
    }

    #[test]
    fn a_key_is_read_from_the_scope_in_every_region() {
        for region in [Region::Notes, Region::Log, Region::Tasks] {
            let policy = applied(
                &RegionPolicy::new(region),
                fragment(
                    Some("/dev"),
                    AccessFragment::default(),
                    &[("/x", asked(Some(false), Some(false)))],
                ),
            )
            .unwrap();
            assert!(policy.readable(&at("/x/a.md")).is_err(), "{region:?}");
            assert!(policy.readable(&at("/y/a.md")).is_ok(), "{region:?}");
        }
    }

    #[test]
    fn write_does_not_imply_read() {
        let policy = applied(&root(), fragment(None, asked(Some(false), Some(true)), &[])).unwrap();
        assert!(policy.writeable(&at("/a.md")).is_ok());
        assert!(policy.readable(&at("/a.md")).is_err());
    }
}
