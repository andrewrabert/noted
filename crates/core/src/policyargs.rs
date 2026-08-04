use serde_json::{Map, Value, json};

use crate::error::{Result, rejected};
use crate::fragment::PolicyFragment;
use crate::path::Path;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyArgs {
    pub policy: Option<String>,
    pub scope: Option<String>,
    pub inside: Vec<String>,
}

impl PolicyArgs {
    pub fn fragments(&self) -> Result<Vec<PolicyFragment>> {
        Ok(vec![self.document()?.parse()?])
    }

    fn document(&self) -> Result<String> {
        let mut doc = match &self.policy {
            None => Map::new(),
            Some(raw) => read_policy(raw)?,
        };
        if let Some(scope) = &self.scope {
            doc.insert("scope".to_string(), json!(note_path(scope)?.as_str()));
        }
        write_entries(&mut doc, "paths", &self.inside)?;
        Ok(Value::Object(doc).to_string())
    }
}

fn note_path(raw: &str) -> Result<Path> {
    Path::new(raw.trim_start_matches('/'))
}

fn read_policy(raw: &str) -> Result<Map<String, Value>> {
    let text = match raw.strip_prefix('@') {
        None => raw.to_string(),
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| rejected(format!("cannot read policy file '{path}': {e}")))?,
    };
    match serde_json::from_str(&text) {
        Ok(Value::Object(doc)) => Ok(doc),
        Ok(_) => Err(rejected("policy must be an object")),
        Err(e) => Err(rejected(format!("invalid policy: {e}"))),
    }
}

fn write_entries(doc: &mut Map<String, Value>, key: &str, raws: &[String]) -> Result<()> {
    if raws.is_empty() {
        return Ok(());
    }
    let mut entries = match doc.remove(key) {
        Some(Value::Object(entries)) => entries,
        Some(_) => return Err(rejected(format!("'{key}' must be a mapping"))),
        None => Map::new(),
    };
    for raw in raws {
        match parse_entry(raw)? {
            (None, access) => {
                doc.insert("access".to_string(), access);
            }
            (Some(at), access) => {
                entries.insert(at, access);
            }
        }
    }
    if !entries.is_empty() {
        doc.insert(key.to_string(), Value::Object(entries));
    }
    Ok(())
}

fn parse_entry(raw: &str) -> Result<(Option<String>, Value)> {
    let (path, modes) = match raw.split_once('=') {
        Some((path, modes)) => (path, Some(modes)),
        None => (raw, None),
    };
    let at = match path.trim_start_matches('/').is_empty() {
        true => None,
        false => Some(note_path(path)?.to_string()),
    };
    let Some(modes) = modes else {
        return Ok((at, json!({"read": true, "write": true})));
    };
    let (mut read, mut write) = (false, false);
    for mode in modes.split(',').map(str::trim).filter(|m| !m.is_empty()) {
        match mode {
            "read" | "r" => read = true,
            "write" | "w" => write = true,
            other => return Err(rejected(format!("unknown access mode: '{other}'"))),
        }
    }
    Ok((at, json!({"read": read, "write": write})))
}
