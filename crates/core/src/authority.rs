use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{NotedError, Result, rejected};
use crate::policy::{Policy, PolicyFragment};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Authority(PolicyFragment);

impl Authority {
    pub fn everything() -> Authority {
        Authority(PolicyFragment::everything())
    }

    pub(crate) fn policy(chain: &[Authority]) -> Result<Policy> {
        let fragments: Vec<PolicyFragment> = chain.iter().map(|held| held.0.clone()).collect();
        Policy::with_fragments(&fragments)
    }

    pub fn validate_chain(chain: &[Authority]) -> Result<()> {
        Self::policy(chain).map(|_| ())
    }

    pub fn scope_of(chain: &[Authority]) -> Result<Option<crate::path::Path>> {
        Self::policy(chain).map(|policy| policy.scope().cloned())
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Authority {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<Authority> {
        serde_json::from_str(s).map_err(|e| rejected(format!("invalid policy: {e}")))
    }
}
