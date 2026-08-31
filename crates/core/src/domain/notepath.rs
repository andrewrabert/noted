//! Which note. Measured from the holder's scope inside a region. Adds one rule
//! to the base path: no segment starts with `.`, so `.logs`, `.tasks`,
//! `.trash` and every dotfile are unspellable. `NotePath::new` is the crate's
//! only public parse door; serde enters through it.

use std::borrow::Cow;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::path::Path;
use super::segment::Segment;
use crate::error::{Result, rejected};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NotePath(Path);

impl NotePath {
    pub fn new(raw: &str) -> Result<NotePath> {
        let path = Path::new(raw)?;
        if path.segments().any(|part| part.as_str().starts_with('.')) {
            return Err(rejected(format!("{raw}: a segment starts with '.'")));
        }
        Ok(NotePath(path))
    }

    pub(crate) fn segments(&self) -> impl Iterator<Item = &Segment> {
        self.0.segments()
    }

    pub(crate) fn join(&self, deeper: &NotePath) -> NotePath {
        NotePath(self.0.join(&deeper.0))
    }
}

impl Default for NotePath {
    fn default() -> NotePath {
        NotePath::new(Path::SEPARATOR).expect("the root is a note path")
    }
}

impl fmt::Display for NotePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for NotePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_string())
    }
}

impl Serialize for NotePath {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for NotePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        NotePath::new(&raw).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for NotePath {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("NotePath")
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "default": Path::SEPARATOR,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> NotePath {
        NotePath::new(s).unwrap()
    }

    #[test]
    fn a_note_path_never_has_a_dotted_segment() {
        assert_eq!(at("/a/b.md").to_string(), "/a/b.md");
        assert_eq!(at("/"), NotePath::default());
        assert_eq!(at("a/b.md"), at("/a/b.md"));
        for bad in ["/.logs", ".logs", "/.tasks", "/a/.hidden", "", "/a/"] {
            assert!(NotePath::new(bad).is_err(), "accepted '{bad}'");
        }
    }

    #[test]
    fn join_deepens_and_the_root_is_the_identity() {
        assert_eq!(at("/a").join(&at("/b/c")), at("/a/b/c"));
        assert_eq!(NotePath::default().join(&at("/x")), at("/x"));
        assert_eq!(at("/x").join(&NotePath::default()), at("/x"));
    }

    #[test]
    fn serde_goes_through_the_one_door() {
        assert_eq!(serde_json::to_string(&at("/a/b")).unwrap(), "\"/a/b\"");
        assert_eq!(
            serde_json::from_str::<NotePath>("\"/\"").unwrap(),
            NotePath::default()
        );
        assert!(serde_json::from_str::<NotePath>("\"/.logs\"").is_err());
        assert!(serde_json::from_str::<NotePath>("\"\"").is_err());
        let schema = serde_json::to_value(schemars::schema_for!(NotePath)).unwrap();
        assert_eq!(schema["type"], "string");
        assert_eq!(schema["default"], "/");
        assert!(schema.get("pattern").is_none());
    }
}
