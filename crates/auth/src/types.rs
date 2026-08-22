use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use noted::error::{Result, rejected};
use noted::newtype::{secret_newtype, str_newtype, str_newtype_validated};
use noted::util::random_token;

fn valid_charset(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn validate_username(name: &str) -> Result<()> {
    if valid_charset(name) {
        Ok(())
    } else {
        Err(rejected(format!("invalid user name: '{name}'")))
    }
}

fn validate_label(name: &str) -> Result<()> {
    if valid_charset(name) {
        Ok(())
    } else {
        Err(rejected(format!("invalid key label name: '{name}'")))
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialPresentation(String);

impl CredentialPresentation {
    pub fn submitted(value: impl Into<String>) -> CredentialPresentation {
        CredentialPresentation(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LoginName(String);

impl LoginName {
    pub fn submitted(value: impl Into<String>) -> LoginName {
        LoginName(value.into())
    }

    pub fn candidate_username(&self) -> Result<Username> {
        Username::new(self.0.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LoginPeerIp(IpAddr);

impl LoginPeerIp {
    pub const fn accepted(value: IpAddr) -> LoginPeerIp {
        LoginPeerIp(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LoginSourceId(String);

impl LoginSourceId {
    pub fn new(value: impl Into<String>) -> LoginSourceId {
        LoginSourceId(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LoginSource {
    AcceptedTcpPeer(LoginPeerIp),
    NonTcpAdapter(LoginSourceId),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RedirectUri(url::Url);

impl RedirectUri {
    pub fn new(value: impl AsRef<str>) -> Result<RedirectUri> {
        url::Url::parse(value.as_ref())
            .map(RedirectUri)
            .map_err(|error| rejected(format!("invalid redirect URI: {error}")))
    }

    pub fn as_url(&self) -> &url::Url {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

fn validate_server_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(rejected(format!("invalid server id: '{id}'")))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Username(String);
str_newtype_validated!(Username, validate_username);

impl std::fmt::Debug for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Username({})", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServerId(String);
str_newtype_validated!(ServerId, validate_server_id);

const SERVER_ID_BYTES: usize = 12;

impl ServerId {
    pub fn fresh() -> ServerId {
        ServerId(random_token(SERVER_ID_BYTES))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientId(String);
str_newtype!(ClientId);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Label(String);
str_newtype_validated!(Label, validate_label);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);
str_newtype!(SessionId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RevocationEpoch(u64);

impl RevocationEpoch {
    pub fn initial() -> RevocationEpoch {
        RevocationEpoch(0)
    }

    pub fn next(self) -> Result<RevocationEpoch> {
        self.0
            .checked_add(1)
            .map(RevocationEpoch)
            .ok_or_else(|| rejected("revocation epoch exhausted"))
    }

    pub fn accepts(self, epoch: RevocationEpoch) -> bool {
        epoch >= self
    }
}

impl std::fmt::Display for RevocationEpoch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::str::FromStr for RevocationEpoch {
    type Err = std::num::ParseIntError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        value.parse().map(RevocationEpoch)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Fingerprint(String);
str_newtype!(Fingerprint);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PasswordHash(String);
str_newtype!(PasswordHash);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretHash(String);
str_newtype!(SecretHash);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);
secret_newtype!(Secret);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RefreshToken(String);
secret_newtype!(RefreshToken);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Password(String);
secret_newtype!(Password);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Owner {
    User(Username),
    Server(ServerId),
}

impl Owner {
    pub fn user(name: impl Into<String>) -> Result<Owner> {
        Ok(Owner::User(Username::new(name)?))
    }

    pub fn server(id: impl Into<String>) -> Result<Owner> {
        Ok(Owner::Server(ServerId::new(id)?))
    }
}

impl std::fmt::Display for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Owner::User(n) => write!(f, "user:{n}"),
            Owner::Server(id) => write!(f, "self:{id}"),
        }
    }
}

impl std::str::FromStr for Owner {
    type Err = noted::error::NotedError;
    fn from_str(s: &str) -> Result<Owner> {
        if let Some(name) = s.strip_prefix("user:") {
            return Owner::user(name);
        }
        if let Some(id) = s.strip_prefix("self:") {
            return Owner::server(id);
        }
        Err(rejected(format!("unqualified owner: '{s}'")))
    }
}

impl TryFrom<String> for Owner {
    type Error = noted::error::NotedError;
    fn try_from(s: String) -> Result<Owner> {
        s.parse()
    }
}

impl From<Owner> for String {
    fn from(o: Owner) -> String {
        o.to_string()
    }
}

impl Owner {
    fn eq_str(&self, o: &str) -> bool {
        match self {
            Owner::User(n) => o.strip_prefix("user:") == Some(n.as_str()),
            Owner::Server(id) => o.strip_prefix("self:") == Some(id.as_str()),
        }
    }
}

impl PartialEq<str> for Owner {
    fn eq(&self, o: &str) -> bool {
        self.eq_str(o)
    }
}

impl PartialEq<&str> for Owner {
    fn eq(&self, o: &&str) -> bool {
        self.eq_str(o)
    }
}

impl PartialEq<String> for Owner {
    fn eq(&self, o: &String) -> bool {
        self.eq_str(o)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthorizationTransactionId(String);

impl AuthorizationTransactionId {
    pub fn submitted(value: impl Into<String>) -> AuthorizationTransactionId {
        AuthorizationTransactionId(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! submitted_oauth_fact {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn submitted(value: impl Into<String>) -> $name {
                $name(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

submitted_oauth_fact!(AuthorizationCode);
submitted_oauth_fact!(CodeChallenge);
submitted_oauth_fact!(CodeVerifier);
submitted_oauth_fact!(ClientState);
submitted_oauth_fact!(RequestedScope);
submitted_oauth_fact!(SubmittedRedirectUri);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrantedScope(String);

impl GrantedScope {
    pub(crate) fn new(value: impl Into<String>) -> GrantedScope {
        GrantedScope(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationResponseType {
    Code,
    Unsupported,
}

impl AuthorizationResponseType {
    pub fn submitted(value: &str) -> AuthorizationResponseType {
        match value {
            "code" => AuthorizationResponseType::Code,
            _ => AuthorizationResponseType::Unsupported,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    S256,
    Unsupported,
}

impl CodeChallengeMethod {
    pub fn submitted(value: &str) -> CodeChallengeMethod {
        match value {
            "S256" => CodeChallengeMethod::S256,
            _ => CodeChallengeMethod::Unsupported,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OAuthTokenType {
    Bearer,
}

#[derive(Clone, PartialEq, Eq)]
pub struct OAuthAccessToken(String);

impl OAuthAccessToken {
    pub(crate) fn issued(value: impl Into<String>) -> OAuthAccessToken {
        OAuthAccessToken(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenLifetimeSeconds(i64);

impl TokenLifetimeSeconds {
    pub(crate) fn new(value: i64) -> TokenLifetimeSeconds {
        TokenLifetimeSeconds(value)
    }

    pub fn as_secs(self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_validates() {
        assert!("ann".parse::<Username>().is_ok());
        assert!("a-b_1".parse::<Username>().is_ok());
        assert!("1bad".parse::<Username>().is_err());
        assert!("has space".parse::<Username>().is_err());
        assert!("".parse::<Username>().is_err());
    }

    #[test]
    fn owner_round_trips_through_string() {
        let u: Owner = "user:ann".parse().unwrap();
        assert_eq!(u, Owner::user("ann").unwrap());
        assert_eq!(u.to_string(), "user:ann");
        let s: Owner = "self:abc-123".parse().unwrap();
        assert_eq!(s.to_string(), "self:abc-123");
        assert!("bare".parse::<Owner>().is_err());
        assert!("self:has space".parse::<Owner>().is_err());
        assert_eq!(serde_json::to_string(&u).unwrap(), "\"user:ann\"");
        assert_eq!(
            serde_json::from_str::<Owner>("\"self:abc-123\"").unwrap(),
            s
        );
    }

    #[test]
    fn a_fresh_server_id_is_its_own_owner() {
        let id = ServerId::fresh();
        let owner = Owner::Server(id.clone());
        assert_eq!(owner.to_string().parse::<Owner>().unwrap(), owner);
        assert_eq!(ServerId::new(id.as_str()).unwrap(), id);
    }

    #[test]
    fn secret_debug_is_redacted() {
        let t = Secret::new("noted_ref_supersecret");
        assert_eq!(format!("{t:?}"), "Secret(…)");
        assert!(!format!("{t:?}").contains("supersecret"));
        assert_eq!(t.expose(), "noted_ref_supersecret");
    }

    #[test]
    fn secret_serde_is_transparent() {
        let t = Secret::new("noted_ref_x");
        assert_eq!(serde_json::to_string(&t).unwrap(), "\"noted_ref_x\"");
    }
}
