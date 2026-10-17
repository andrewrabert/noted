use std::fmt;
use std::str::FromStr;

use noyalib::{DuplicateKeyPolicy, ParserConfig};
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

use crate::error::{NotedError, Result, rejected};

/// A flat `---` block of `key: value` lines, in the order the keys were set.
#[derive(Clone, Debug, Default)]
pub struct FrontMatter {
    fields: Vec<(String, String)>,
}

impl FrontMatter {
    pub fn parse(block: &str) -> Result<FrontMatter> {
        let config = ParserConfig::new()
            .plain_scalar_strings(true)
            .duplicate_key_policy(DuplicateKeyPolicy::Error);
        let fields = noyalib::from_str_with_config::<Option<Parsed>>(block, &config)
            .map_err(|err| rejected(err.to_string()))?
            .map(|Parsed(fields)| fields)
            .unwrap_or_default();
        Ok(FrontMatter { fields })
    }

    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        let value = value.into();
        match self.fields.iter_mut().find(|(k, _)| k == key) {
            Some((_, slot)) => *slot = value,
            None => self.fields.push((key.to_string(), value)),
        }
    }

    pub fn set_opt(&mut self, key: &str, value: Option<impl Into<String>>) {
        if let Some(value) = value {
            self.set(key, value);
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn field<T: FromStr<Err = NotedError>>(&self, key: &str) -> Result<T> {
        let raw = self
            .get(key)
            .ok_or_else(|| rejected(format!("missing field '{key}'")))?;
        raw.parse()
    }

    pub fn opt_field<T: FromStr<Err = NotedError>>(&self, key: &str) -> Result<Option<T>> {
        self.get(key).map(str::parse).transpose()
    }

    pub fn dump(&self, body: &str) -> String {
        let yaml = noyalib::to_string(&Fields(&self.fields))
            .expect("a flat string mapping always serializes");
        let mut out = String::from("---\n");
        out.push_str(&yaml);
        if !yaml.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("---\n");
        out.push_str(body);
        if !body.ends_with('\n') {
            out.push('\n');
        }
        out
    }
}

pub fn split_front(text: &str) -> Option<(&str, &str)> {
    if !text.starts_with("---\n") {
        return None;
    }
    let end = text[4..].find("\n---\n").map(|i| i + 4)?;
    let block = &text[4..end];
    let body = &text[end + "\n---\n".len()..];
    Some((block, body))
}

struct Fields<'a>(&'a [(String, String)]);

impl Serialize for Fields<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

struct Parsed(Vec<(String, String)>);

impl<'de> Deserialize<'de> for Parsed {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_map(ParsedVisitor)
    }
}

struct ParsedVisitor;

impl<'de> Visitor<'de> for ParsedVisitor {
    type Value = Parsed;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a mapping of scalar fields")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Parsed, A::Error> {
        let mut fields = Vec::new();
        while let Some(entry) = map.next_entry::<String, String>()? {
            fields.push(entry);
        }
        Ok(Parsed(fields))
    }
}
