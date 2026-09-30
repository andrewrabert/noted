use std::fmt;
use std::path::PathBuf;

use fast_radix_trie::StringRadixMap;

use crate::disk::normalize;
use crate::domain::{NotePath, Path};
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

// the one place a path becomes an index key: the scope-relative path, a
// separator after every segment, so a longest-prefix lookup stops at a
// segment boundary ('/docs/' never covers '/docsX/').
fn key(at: &NotePath) -> String {
    let mut out = at.to_string();
    if !out.ends_with(Path::SEPARATOR) {
        out.push_str(Path::SEPARATOR);
    }
    out
}

fn resolved(
    at: &NotePath,
    asked: AccessFragment,
    ceiling: Access,
    default: Access,
) -> Result<Access> {
    asked
        .applied_to(ceiling, default)
        .map_err(|asked| PolicyError::Exceeds {
            at: at.clone(),
            asked,
        })
        .map_err(NotedError::from)
}

#[derive(Clone, Debug)]
struct AccessEntries(StringRadixMap<Access>);

impl AccessEntries {
    fn new() -> AccessEntries {
        let mut entries = StringRadixMap::new();
        entries.insert(
            key(&NotePath::default()),
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
        base: (&NotePath, AccessFragment),
        named: impl IntoIterator<Item = (NotePath, AccessFragment)>,
    ) -> Result<AccessEntries> {
        let (at, asked) = base;
        let prior = self.for_path(at);
        let mut covering = self.clone();
        covering
            .0
            .insert(key(at), resolved(at, asked, prior, prior)?);

        let mut entries = covering.clone();
        for (at, asked) in named {
            let access = resolved(&at, asked, self.for_path(&at), covering.for_path(&at))?;
            entries.0.insert(key(&at), access);
        }
        Ok(entries)
    }

    fn for_path(&self, at: &NotePath) -> Access {
        match self.0.get_longest_common_prefix(&key(at)) {
            Some((_, access)) => *access,
            None => Access::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Policy {
    scope: NotePath,
    entries: AccessEntries,
}

impl Policy {
    pub(crate) fn new() -> Policy {
        Policy {
            scope: NotePath::default(),
            entries: AccessEntries::new(),
        }
    }

    pub(crate) fn with_policy_fragment(&self, fragment: &PolicyFragment) -> Result<Policy> {
        let scope = match &fragment.scope {
            None => self.scope.clone(),
            Some(deeper) => self.scope.join(deeper)?,
        };
        let named = fragment
            .paths
            .iter()
            .map(|(at, asked)| Ok((scope.join(at)?, *asked)))
            .collect::<Result<Vec<_>>>()?;
        let entries = self
            .entries
            .with_entries((&scope, fragment.access), named)?;
        Ok(Policy { scope, entries })
    }

    // a read may start at the scope itself, so a listing can walk it
    pub(crate) fn readable(&self, rel: &NotePath) -> Result<Readable> {
        let at = self.scope.join(rel)?;
        match self.entries.for_path(&at).read {
            true => Ok(Readable(at)),
            false => Err(NotedError::Forbidden),
        }
    }

    // a write is never allowed on the scope directory itself
    pub(crate) fn writeable(&self, rel: &NotePath) -> Result<Writeable> {
        let at = self.scope.join(rel)?;
        match self.entries.for_path(&at).write {
            true => Ok(Writeable(at)),
            false => Err(NotedError::Forbidden),
        }
    }

    pub fn access(&self) -> Access {
        self.entries.for_path(&self.scope)
    }

    pub(crate) fn scope(&self) -> &NotePath {
        &self.scope
    }
}

/// A read the policy allowed: the scope joined to the name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Readable(NotePath);

/// A write the policy allowed, at a name other than the scope itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Writeable(NotePath);

/// Where an allowed read lands in the store, spelled from the store root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadablePath(Vec<String>);

/// The file an allowed read names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadableFile(ReadablePath);

/// The directory an allowed read names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadableDir(ReadablePath);

/// Where an allowed write lands in the store, spelled from the store root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WriteablePath(Vec<String>);

/// The file an allowed write names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WriteableFile(WriteablePath);

/// The directory an allowed write names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WriteableDir(WriteablePath);

impl Readable {
    pub(crate) fn file(&self) -> Result<ReadableFile> {
        Ok(ReadableFile(ReadablePath(self.0.to_store_file()?)))
    }

    pub(crate) fn dir(&self) -> Result<ReadableDir> {
        Ok(ReadableDir(ReadablePath(self.0.to_store_dir()?)))
    }
}

impl Writeable {
    pub(crate) fn file(&self) -> Result<WriteableFile> {
        Ok(WriteableFile(WriteablePath(self.0.to_store_file()?)))
    }

    pub(crate) fn dir(&self) -> Result<WriteableDir> {
        Ok(WriteableDir(WriteablePath(self.0.to_store_dir()?)))
    }
}

// base + parts, normalized; never above base
fn store_path(base: &PathBuf, parts: &[String]) -> Result<PathBuf> {
    let mut out = base.clone();
    out.extend(parts);
    let out = normalize(&out);
    match out.starts_with(base) {
        true => Ok(out),
        false => Err(rejected("invalid path")),
    }
}

impl ReadablePath {
    pub(crate) fn to_store_path(&self, base: &PathBuf) -> Result<PathBuf> {
        store_path(base, &self.0)
    }
}

impl WriteablePath {
    // never the store root itself
    pub(crate) fn to_store_path(&self, base: &PathBuf) -> Result<PathBuf> {
        let out = store_path(base, &self.0)?;
        match out != *base {
            true => Ok(out),
            false => Err(rejected("invalid path")),
        }
    }
}

impl AsRef<ReadablePath> for ReadableFile {
    fn as_ref(&self) -> &ReadablePath {
        &self.0
    }
}

impl AsRef<ReadablePath> for ReadableDir {
    fn as_ref(&self) -> &ReadablePath {
        &self.0
    }
}

impl AsRef<WriteablePath> for WriteableFile {
    fn as_ref(&self) -> &WriteablePath {
        &self.0
    }
}

impl AsRef<WriteablePath> for WriteableDir {
    fn as_ref(&self) -> &WriteablePath {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PolicyError {
    Exceeds { at: NotePath, asked: AccessFragment },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Exceeds { at, asked } => write!(
                f,
                "'{}' asks for {asked}, which the holder does not have there",
                key(at)
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

    fn applied(policy: &Policy, fragment: PolicyFragment) -> Result<Policy> {
        policy.with_policy_fragment(&fragment)
    }

    fn root() -> Policy {
        Policy::new()
    }

    fn located(proof: &Readable) -> String {
        format!("/{}", proof.file().unwrap().as_ref().0.join("/"))
    }

    #[test]
    fn a_key_closes_every_segment_with_a_separator() {
        assert_eq!(key(&at("/")), "/");
        assert_eq!(key(&at("/a/#2/b")), "/a/#2/b/");
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
        assert_eq!(located(&policy.readable(&at("/a/b")).unwrap()), "/a/b.md");
    }

    #[test]
    fn the_scope_directory_itself_is_never_written() {
        assert!(root().readable(&at("/")).is_ok());
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
        assert!(policy.readable(&at("/work/a")).is_err());
        assert!(policy.readable(&at("/workshop/a")).is_ok());
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
        assert!(policy.writeable(&at("/vendor/x")).is_err());
        assert!(policy.readable(&at("/vendor/x")).is_err());
        assert!(policy.readable(&at("/other/x")).is_ok());
        assert!(policy.writeable(&at("/other/x")).is_err());
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
                    ("/task_0001", asked(Some(true), Some(true))),
                ],
            ),
        )
        .unwrap();
        assert!(policy.writeable(&at("/task_0001")).is_ok());
        assert!(policy.writeable(&at("/task_0002")).is_err());
        assert!(policy.readable(&at("/task_0002")).is_ok());
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
        assert!(policy.readable(&at("/open/a")).is_ok());
        assert!(policy.writeable(&at("/open/a")).is_ok());
        assert!(policy.readable(&at("/other/a")).is_err());
        assert!(policy.writeable(&at("/other/a")).is_err());
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
            located(&scoped.readable(&at("/a")).unwrap()),
            "/projects/a.md"
        );

        let deeper = applied(
            &scoped,
            fragment(Some("/alpha"), AccessFragment::default(), &[]),
        )
        .unwrap();
        assert_eq!(deeper.scope(), &at("/projects/alpha"));
        assert_eq!(
            located(&deeper.readable(&at("/a")).unwrap()),
            "/projects/alpha/a.md"
        );
    }

    #[test]
    fn a_key_is_read_from_the_scope() {
        let policy = applied(
            &root(),
            fragment(
                Some("/dev"),
                AccessFragment::default(),
                &[("/x", asked(Some(false), Some(false)))],
            ),
        )
        .unwrap();
        assert!(policy.readable(&at("/x/a")).is_err());
        assert!(policy.readable(&at("/y/a")).is_ok());
    }

    #[test]
    fn write_does_not_imply_read() {
        let policy = applied(&root(), fragment(None, asked(Some(false), Some(true)), &[])).unwrap();
        assert!(policy.writeable(&at("/a")).is_ok());
        assert!(policy.readable(&at("/a")).is_err());
    }
}
