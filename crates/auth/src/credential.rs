use std::fmt::{self, Display};
use std::str::FromStr;
use std::sync::OnceLock;

use macaroon::{
    ByteString, Caveat as DependencyCaveat, Format, Macaroon as DependencyMacaroon, MacaroonKey,
    Verifier as DependencyVerifier,
};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::service::PREFIX_MAC;
use crate::types::{Fingerprint, Owner};
use noted::PolicyFragment;
use noted::error::{Result, rejected};
use noted::newtype::str_newtype;
use noted::util::random_token;

const KEY_BYTES: usize = 32;
const MACAROON_ID_BYTES: usize = 16;
const FINGERPRINT_CHARS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MacaroonId(String);
str_newtype!(MacaroonId);

impl MacaroonId {
    pub fn fresh() -> MacaroonId {
        MacaroonId(random_token(MACAROON_ID_BYTES))
    }
}

/// The material a server holds for one owner: the secret its roots are minted
/// under.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub secret: Vec<u8>,
}

impl KeyRecord {
    pub fn fresh() -> KeyRecord {
        let mut secret = vec![0u8; KEY_BYTES];
        rand::rng().fill_bytes(&mut secret);
        KeyRecord { secret }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Caveat {
    Policy(PolicyFragment),
    Token(MacaroonId),
}

const KEY_POLICY: &str = "policy";
const KEY_TOKEN: &str = "token_id";

impl Display for Caveat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Caveat::Policy(v) => write!(f, "{KEY_POLICY}={v}"),
            Caveat::Token(v) => write!(f, "{KEY_TOKEN}={v}"),
        }
    }
}

impl FromStr for Caveat {
    type Err = noted::error::NotedError;

    fn from_str(s: &str) -> Result<Caveat> {
        let (key, value) = s
            .split_once('=')
            .ok_or_else(|| rejected(format!("unqualified macaroon caveat: '{s}'")))?;
        let bad = || rejected(format!("invalid macaroon caveat: '{s}'"));
        match key {
            KEY_POLICY => Ok(Caveat::Policy(value.parse().map_err(|_| bad())?)),
            KEY_TOKEN => Ok(Caveat::Token(MacaroonId::new(value))),
            _ => Err(bad()),
        }
    }
}

impl From<Caveat> for String {
    fn from(caveat: Caveat) -> String {
        caveat.to_string()
    }
}

impl TryFrom<String> for Caveat {
    type Error = noted::error::NotedError;

    fn try_from(value: String) -> Result<Caveat> {
        value.parse()
    }
}

impl Caveat {
    fn encode(&self) -> ByteString {
        ByteString(self.to_string().into_bytes())
    }
}

fn init() {
    static I: OnceLock<()> = OnceLock::new();
    I.get_or_init(|| {
        let _ = macaroon::initialize();
    });
}

#[derive(Clone)]
pub struct Macaroon {
    encoded: String,
    decoded: DependencyMacaroon,
}

impl fmt::Debug for Macaroon {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Macaroon(…)")
    }
}

impl Serialize for Macaroon {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encoded)
    }
}

impl<'de> Deserialize<'de> for Macaroon {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        Self::from_encoded(encoded).map_err(D::Error::custom)
    }
}

impl Macaroon {
    pub fn from_encoded(encoded: String) -> Result<Macaroon> {
        init();
        let token = encoded
            .strip_prefix(PREFIX_MAC)
            .ok_or_else(|| rejected("invalid macaroon bearer prefix"))?;
        let decoded = DependencyMacaroon::deserialize(token)
            .map_err(|_| rejected("invalid macaroon bearer"))?;
        Ok(Macaroon { encoded, decoded })
    }

    fn from_decoded(decoded: DependencyMacaroon) -> Result<Macaroon> {
        let token = decoded
            .serialize(Format::V2)
            .map_err(|_| rejected("serialize macaroon"))?;
        Ok(Macaroon {
            encoded: format!("{PREFIX_MAC}{token}"),
            decoded,
        })
    }

    /// A root under `key`, identified by `owner`, carrying `caveats` in order.
    pub fn mint(owner: &Owner, key: &KeyRecord, caveats: &[Caveat]) -> Result<Macaroon> {
        init();
        let macaroon_key = MacaroonKey::generate(&key.secret);
        let identifier = ByteString(owner.to_string().into_bytes());
        let mut decoded = DependencyMacaroon::create(None, &macaroon_key, identifier)
            .map_err(|_| rejected("create root macaroon"))?;
        for caveat in caveats {
            decoded.add_first_party_caveat(caveat.encode());
        }
        Macaroon::from_decoded(decoded)
    }

    /// A bare root under a key nothing keeps.
    pub fn ephemeral() -> Result<Macaroon> {
        Macaroon::mint(&Owner::Server, &KeyRecord::fresh(), &[])
    }

    pub fn extended(&self, caveats: &[Caveat]) -> Result<Macaroon> {
        let mut decoded = self.decoded.clone();
        for caveat in caveats {
            decoded.add_first_party_caveat(caveat.encode());
        }
        Macaroon::from_decoded(decoded)
    }

    /// The candidate rebuilt from this macaroon. Refuses one whose identifier,
    /// caveat prefix or signature does not descend from this one.
    pub fn from_descendant(&self, candidate: &str) -> Result<Macaroon> {
        let candidate = Macaroon::from_encoded(candidate.to_string())?;
        let caveats = self.decoded.caveats();
        let candidate_caveats = candidate.decoded.caveats();
        let is_descendant = self.decoded.identifier() == candidate.decoded.identifier()
            && candidate_caveats.len() >= caveats.len()
            && candidate_caveats.starts_with(&caveats);
        if !is_descendant {
            return Err(rejected("macaroon is not a descendant"));
        }

        let mut descendant = self.decoded.clone();
        for caveat in &candidate_caveats[caveats.len()..] {
            let DependencyCaveat::FirstParty(first_party) = caveat else {
                return Err(rejected("macaroon is not a descendant"));
            };
            descendant.add_first_party_caveat(first_party.predicate());
        }
        if descendant.signature() != candidate.decoded.signature() {
            return Err(rejected("macaroon is not a descendant"));
        }
        Macaroon::from_decoded(descendant)
    }

    pub fn caveats(&self) -> Result<Vec<Caveat>> {
        self.decoded
            .caveats()
            .iter()
            .map(|caveat| {
                let DependencyCaveat::FirstParty(first_party) = caveat else {
                    return Err(rejected("unsupported third-party macaroon caveat"));
                };
                let predicate = String::from_utf8(first_party.predicate().0)
                    .map_err(|_| rejected("invalid macaroon caveat"))?;
                predicate.parse()
            })
            .collect()
    }

    /// The caveats this macaroon carries past `ancestor`, in order.
    pub fn beyond(&self, ancestor: &Macaroon) -> Result<Vec<Caveat>> {
        let held = ancestor.decoded.caveats().len();
        let mine = self.caveats()?;
        if mine.len() < held {
            return Err(rejected("macaroon is not a descendant"));
        }
        Ok(mine[held..].to_vec())
    }

    pub fn owner(&self) -> Result<Owner> {
        String::from_utf8(self.decoded.identifier().0)
            .map_err(|_| rejected("invalid macaroon owner"))?
            .parse()
    }

    pub fn verify_signature(&self, secret: &[u8]) -> Result<()> {
        let key = MacaroonKey::generate(secret);
        let mut verifier = DependencyVerifier::default();
        verifier.satisfy_general(|_| true);
        verifier
            .verify(&self.decoded, &key, Vec::new())
            .map_err(|_| rejected("invalid macaroon signature"))
    }

    pub fn fingerprint(&self) -> Fingerprint {
        let head_end = (PREFIX_MAC.len() + FINGERPRINT_CHARS).min(self.encoded.len());
        Fingerprint::new(format!("{}…", &self.encoded[..head_end]))
    }

    pub fn expose(&self) -> &str {
        &self.encoded
    }
}
