use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{NotedError, Result, rejected};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct RelPath(String);

impl RelPath {
    pub fn new(s: impl Into<String>) -> RelPath {
        RelPath(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for RelPath {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<RelPath> {
        Ok(RelPath::new(s))
    }
}

impl Ord for RelPath {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .to_lowercase()
            .cmp(&other.0.to_lowercase())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for RelPath {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::ops::Deref for RelPath {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<RelPath> for String {
    fn from(r: RelPath) -> String {
        r.0
    }
}

impl AsRef<str> for RelPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for RelPath {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for RelPath {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for RelPath {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

/// An opaque write validator, compared for equality, never inspected. It is the
/// fingerprint of a note's serialized bytes — the `If-Match` precondition for a
/// conditional write. sha256 is a private implementation detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Etag([u8; 32]);

impl Etag {
    /// Mint an etag from a note's serialized bytes. Crate-private on purpose:
    /// the only public door is `FromStr` (rehydrating a token off the wire), so
    /// a client can never forge one — an etag is always the fingerprint of a
    /// note this crate serialized.
    pub(crate) fn of(bytes: &[u8]) -> Etag {
        Etag(Sha256::digest(bytes).into())
    }
}

impl fmt::Display for Etag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Etag {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<Etag> {
        if s.len() != 64 {
            return Err(rejected("invalid write condition token"));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| rejected("invalid write condition token"))?;
        }
        Ok(Etag(out))
    }
}

/// The one contract every note kind shares: it can serialize itself to the exact
/// bytes it persists as. Everything else — mutability, schema, immutability — is
/// the concern of the specific kind. `to_bytes` is fallible because a kind with
/// structured frontmatter (Task, Log) can fail to serialize.
pub trait Note {
    fn to_bytes(&self) -> Result<Vec<u8>>;
}

/// A freeform, mutable, unstructured markdown note — the default kind. No schema,
/// no lifecycle. It is what remains once you take away a task's state machine and
/// a log's immutability.
#[derive(Clone)]
pub struct TextNote {
    path: RelPath,
    content: String,
}

impl TextNote {
    pub fn new(path: RelPath, content: impl Into<String>) -> TextNote {
        TextNote {
            path,
            content: content.into(),
        }
    }

    pub fn path(&self) -> &RelPath {
        &self.path
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn etag(&self) -> Etag {
        Etag::of(self.content.as_bytes())
    }

    pub fn set_content(&mut self, content: impl Into<String>) {
        self.content = content.into();
    }

    pub fn with_content(mut self, content: impl Into<String>) -> TextNote {
        self.set_content(content);
        self
    }

    pub fn with_path(mut self, path: RelPath) -> TextNote {
        self.path = path;
        self
    }
}

impl Note for TextNote {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.content.clone().into_bytes())
    }
}

/// Opaque bytes with no text meaning — an image or other attachment. It makes no
/// utf-8 or markdown assumptions; the bytes are the whole of it.
#[derive(Clone)]
pub struct BinaryNote {
    path: RelPath,
    bytes: Vec<u8>,
}

impl BinaryNote {
    pub fn new(path: RelPath, bytes: impl Into<Vec<u8>>) -> BinaryNote {
        BinaryNote {
            path,
            bytes: bytes.into(),
        }
    }

    pub fn path(&self) -> &RelPath {
        &self.path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn etag(&self) -> Etag {
        Etag::of(&self.bytes)
    }
}

impl Note for BinaryNote {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.bytes.clone())
    }
}
