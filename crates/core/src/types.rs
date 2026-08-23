use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{Local, SubsecRound};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{NotedError, Result, rejected, unavailable};
use crate::newtype::{secret_newtype, str_newtype};
use crate::timerange::{INSTANT, zoned};

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
pub struct SecondsDuration(u64);

impl SecondsDuration {
    pub const fn from_secs(secs: u64) -> SecondsDuration {
        SecondsDuration(secs)
    }

    pub const fn as_secs(self) -> u64 {
        self.0
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

// the canonical text is microseconds with an explicit offset:
// 2026-08-03T09:15:30.123456-07:00
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Timestamp(chrono::DateTime<chrono::FixedOffset>);

impl Timestamp {
    // the current local instant, truncated to microseconds
    pub fn now() -> Timestamp {
        Timestamp::at(Local::now().fixed_offset())
    }

    // truncates sub-microsecond digits so the value equals what is written
    pub fn at(at: chrono::DateTime<chrono::FixedOffset>) -> Timestamp {
        Timestamp(at.trunc_subsecs(6))
    }
}

impl std::str::FromStr for Timestamp {
    type Err = NotedError;

    fn from_str(s: &str) -> Result<Timestamp> {
        chrono::DateTime::parse_from_rfc3339(s)
            .map(Timestamp::at)
            .map_err(|_| rejected(format!("not a timestamp: '{s}'")))
    }
}

impl TryFrom<String> for Timestamp {
    type Error = NotedError;

    fn try_from(s: String) -> Result<Timestamp> {
        s.parse()
    }
}

impl From<Timestamp> for String {
    fn from(at: Timestamp) -> String {
        zoned(at.0, INSTANT)
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&zoned(self.0, INSTANT))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Bearer(String);

secret_newtype!(Bearer);

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

// Tool-schema field: a rustdoc comment here ships as the wire description.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct NoteBody(String);

str_newtype!(NoteBody);

// Tool-schema field: a rustdoc comment here ships as the wire description.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct TaskBody(String);

str_newtype!(TaskBody);

impl TaskBody {
    pub fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }
}

// the wire form is base64, standard alphabet with padding; the value is the bytes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct Base64Bytes(Vec<u8>);

impl Base64Bytes {
    pub fn decode(text: &str) -> Result<Base64Bytes> {
        BASE64
            .decode(text.trim())
            .map(Base64Bytes)
            .map_err(|e| rejected(format!("content is not base64: {e}")))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::str::FromStr for Base64Bytes {
    type Err = NotedError;
    fn from_str(s: &str) -> Result<Base64Bytes> {
        Base64Bytes::decode(s)
    }
}

impl TryFrom<String> for Base64Bytes {
    type Error = NotedError;
    fn try_from(s: String) -> Result<Base64Bytes> {
        Base64Bytes::decode(&s)
    }
}

impl From<Base64Bytes> for String {
    fn from(v: Base64Bytes) -> String {
        BASE64.encode(&v.0)
    }
}
