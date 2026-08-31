use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::domain::NotePath;
use crate::error::{NotedError, Result, rejected};

/// What a fragment asks for: an absent flag keeps whatever is already there.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessFragment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<bool>,
}

impl AccessFragment {
    fn is_empty(&self) -> bool {
        self.read.is_none() && self.write.is_none()
    }
}

impl fmt::Display for AccessFragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => f.write_str(&json),
            Err(_) => Err(fmt::Error),
        }
    }
}

/// One holder's narrowing. `scope` deepens the holder's subtree; `paths` are
/// read from that scope and apply the same way in every region.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFragment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<NotePath>,
    #[serde(default, skip_serializing_if = "AccessFragment::is_empty")]
    pub access: AccessFragment,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub paths: BTreeMap<NotePath, AccessFragment>,
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
        serde_json::from_str(s).map_err(|e| rejected(format!("invalid policy: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fragment_round_trips_through_its_canonical_json() {
        let text = r#"{"scope":"/dev","access":{"read":true,"write":false},"paths":{"/vendor":{"read":false}}}"#;
        let parsed: PolicyFragment = text.parse().unwrap();
        assert_eq!(parsed.to_string(), text);
        assert_eq!(
            parsed.to_string().parse::<PolicyFragment>().unwrap(),
            parsed
        );
    }

    #[test]
    fn an_empty_fragment_carries_nothing() {
        let empty = PolicyFragment::default();
        assert_eq!(empty.to_string(), "{}");
        assert!(empty.access.is_empty());
    }

    #[test]
    fn an_unknown_field_is_refused() {
        assert!("{\"nope\": 1}".parse::<PolicyFragment>().is_err());
        assert!(r#"{"paths":{"/a":"rw"}}"#.parse::<PolicyFragment>().is_err());
    }

    #[test]
    fn a_key_is_a_note_path() {
        assert!(r#"{"paths":{"a":{"read":true}}}"#.parse::<PolicyFragment>().is_ok());
        assert!(r#"{"paths":{"a/":{"read":true}}}"#.parse::<PolicyFragment>().is_err());
        assert!(r#"{"scope":".logs"}"#.parse::<PolicyFragment>().is_err());
        assert!(r#"{"paths":{"/.tasks":{"read":true}}}"#.parse::<PolicyFragment>().is_err());
    }
}
