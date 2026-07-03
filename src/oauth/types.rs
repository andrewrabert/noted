use serde::{Deserialize, Serialize};

use crate::error::{rejected, Result};
use crate::newtype::{secret_newtype, str_newtype, str_newtype_validated};

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
pub struct CredentialId(String);
str_newtype_validated!(CredentialId, validate_credential_id);

const CRED_ID_LEN: usize = 10;

fn validate_credential_id(s: &str) -> Result<()> {
    let ok = s.strip_prefix("cred_").is_some_and(|rest| {
        rest.len() == CRED_ID_LEN
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    });
    if ok {
        Ok(())
    } else {
        Err(rejected(format!("invalid credential id: '{s}'")))
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
pub struct AccessToken(String);
secret_newtype!(AccessToken);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RefreshToken(String);
secret_newtype!(RefreshToken);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Macaroon(String);
secret_newtype!(Macaroon);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Password(String);
secret_newtype!(Password);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Owner {
    User(Username),
    Key(CredentialId),
}

impl Owner {
    pub fn user(name: impl Into<String>) -> Result<Owner> {
        Ok(Owner::User(Username::new(name)?))
    }

    pub fn key(id: impl Into<String>) -> Result<Owner> {
        Ok(Owner::Key(CredentialId::new(id)?))
    }
}

impl std::fmt::Display for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Owner::User(n) => write!(f, "user:{n}"),
            Owner::Key(id) => write!(f, "key:{id}"),
        }
    }
}

impl std::str::FromStr for Owner {
    type Err = crate::error::NotedError;
    fn from_str(s: &str) -> Result<Owner> {
        if let Some(name) = s.strip_prefix("user:") {
            return Owner::user(name);
        }
        if let Some(id) = s.strip_prefix("key:") {
            return Owner::key(id);
        }
        Err(rejected(format!("unqualified owner: '{s}'")))
    }
}

impl TryFrom<String> for Owner {
    type Error = crate::error::NotedError;
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
            Owner::Key(id) => o.strip_prefix("key:") == Some(id.as_str()),
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
        let k: Owner = "key:cred_abcde23456".parse().unwrap();
        assert_eq!(k.to_string(), "key:cred_abcde23456");
        assert!("bare".parse::<Owner>().is_err());
        assert!("key:cred_abc".parse::<Owner>().is_err());
        assert_eq!(serde_json::to_string(&u).unwrap(), "\"user:ann\"");
        assert_eq!(
            serde_json::from_str::<Owner>("\"key:cred_abcde23456\"").unwrap(),
            k
        );
    }

    #[test]
    fn credential_id_validates() {
        assert!("cred_abcde23456".parse::<CredentialId>().is_ok());
        assert!("cred_abc".parse::<CredentialId>().is_err());
        assert!("cred_ABCDE23456".parse::<CredentialId>().is_err());
        assert!("cred_abcde01899".parse::<CredentialId>().is_err());
        assert!("nope_abcde23456".parse::<CredentialId>().is_err());
    }

    #[test]
    fn secret_debug_is_redacted() {
        let t = AccessToken::new("noted_acc_supersecret");
        assert_eq!(format!("{t:?}"), "AccessToken(…)");
        assert!(!format!("{t:?}").contains("supersecret"));
        assert_eq!(t.expose(), "noted_acc_supersecret");
    }

    #[test]
    fn secret_serde_is_transparent() {
        let t = AccessToken::new("noted_acc_x");
        assert_eq!(serde_json::to_string(&t).unwrap(), "\"noted_acc_x\"");
    }
}
