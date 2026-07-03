use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Local;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{rejected, unavailable, Result};
use crate::newtype::str_newtype;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct UnixEpochSeconds(u64);

impl UnixEpochSeconds {
    pub fn now() -> Result<UnixEpochSeconds> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| UnixEpochSeconds(d.as_secs()))
            .map_err(|e| unavailable(format!("system clock is before the unix epoch: {e}")))
    }

    pub const fn from_secs(secs: u64) -> UnixEpochSeconds {
        UnixEpochSeconds(secs)
    }

    pub const fn as_secs(self) -> u64 {
        self.0
    }

    pub fn format_utc(self) -> String {
        chrono::DateTime::<chrono::Utc>::from_timestamp(self.0 as i64, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|| self.0.to_string())
    }
}

impl std::fmt::Display for UnixEpochSeconds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for UnixEpochSeconds {
    type Err = crate::error::NotedError;
    fn from_str(s: &str) -> Result<UnixEpochSeconds> {
        s.trim()
            .parse::<u64>()
            .map(UnixEpochSeconds)
            .map_err(|_| rejected(format!("invalid timestamp: '{s}'")))
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct Ttl(u64);

impl Ttl {
    pub const fn from_secs(secs: u64) -> Ttl {
        Ttl(secs)
    }

    pub const fn as_secs(self) -> u64 {
        self.0
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct SecondsDuration(u64);

impl SecondsDuration {
    pub const fn from_secs(secs: u64) -> SecondsDuration {
        SecondsDuration(secs)
    }

    pub const fn as_secs(self) -> u64 {
        self.0
    }
}

impl std::ops::Add<Ttl> for UnixEpochSeconds {
    type Output = UnixEpochSeconds;
    fn add(self, ttl: Ttl) -> UnixEpochSeconds {
        UnixEpochSeconds(self.0.saturating_add(ttl.as_secs()))
    }
}

impl std::ops::Add<SecondsDuration> for UnixEpochSeconds {
    type Output = UnixEpochSeconds;
    fn add(self, d: SecondsDuration) -> UnixEpochSeconds {
        UnixEpochSeconds(self.0.saturating_add(d.0))
    }
}

impl std::ops::Sub<SecondsDuration> for UnixEpochSeconds {
    type Output = UnixEpochSeconds;
    fn sub(self, d: SecondsDuration) -> UnixEpochSeconds {
        UnixEpochSeconds(self.0.saturating_sub(d.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct Timestamp(String);

str_newtype!(Timestamp);

const TS_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.6f%:z";

impl Timestamp {
    pub fn now() -> Timestamp {
        Timestamp::from_local(Local::now())
    }

    pub fn from_local(dt: chrono::DateTime<Local>) -> Timestamp {
        Timestamp(dt.format(TS_FORMAT).to_string())
    }

    pub fn parse_rfc3339(&self) -> Option<chrono::DateTime<chrono::FixedOffset>> {
        chrono::DateTime::parse_from_rfc3339(&self.0).ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct Source(String);

str_newtype!(Source);

impl Source {
    pub fn from_opt(s: Option<String>) -> Option<Source> {
        s.filter(|s| !s.is_empty()).map(Source)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct LogBody(String);

str_newtype!(LogBody);
