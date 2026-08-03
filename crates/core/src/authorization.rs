use std::fmt;

use crate::authority::Authority;
use crate::error::Result;

#[derive(Clone)]
pub struct Bearer(String);

impl Bearer {
    pub fn new(s: impl Into<String>) -> Bearer {
        Bearer(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<str> for Bearer {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<Bearer> for String {
    fn from(bearer: Bearer) -> String {
        bearer.0
    }
}

impl From<&str> for Bearer {
    fn from(s: &str) -> Bearer {
        Bearer(s.to_string())
    }
}

impl From<String> for Bearer {
    fn from(s: String) -> Bearer {
        Bearer(s)
    }
}

impl fmt::Debug for Bearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bearer(…)")
    }
}

#[derive(Clone, Debug)]
pub struct Authorization {
    grants: Vec<Authority>,
    bearer: Option<Bearer>,
}

impl Authorization {
    pub fn new(grants: Vec<Authority>, bearer: Option<Bearer>) -> Result<Authorization> {
        Authority::validate_chain(&grants)?;
        Ok(Authorization { grants, bearer })
    }

    pub fn grants(&self) -> &[Authority] {
        &self.grants
    }

    pub fn bearer(&self) -> Option<&Bearer> {
        self.bearer.as_ref()
    }
}
