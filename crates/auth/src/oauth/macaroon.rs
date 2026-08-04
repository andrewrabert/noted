use std::fmt::{self, Display, Write};
use std::str::FromStr;
use std::sync::OnceLock;

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use macaroon::{ByteString, Caveat, Format, Macaroon as DependencyMacaroon, MacaroonKey, Verifier};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::{Value, json};

use super::KeyRecord;
use super::service::{AuthService, PREFIX_MAC};
use super::types::{RevocationEpoch, SessionId};
use crate::AuthState;
use noted::PolicyFragment;
use noted::error::{Result, rejected};
use noted::newtype::str_newtype;
use noted::types::{Ttl, UnixEpochSeconds};
use noted::util::random_token;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct MacaroonId(String);
str_newtype!(MacaroonId);

struct KeyValueStrings;

impl KeyValueStrings {
    const SEPARATOR: char = '=';

    fn encode(key: &str, value: &str) -> String {
        let mut encoded =
            String::with_capacity(key.len() + Self::SEPARATOR.len_utf8() + value.len());
        encoded.push_str(key);
        encoded.push(Self::SEPARATOR);
        encoded.push_str(value);
        encoded
    }

    fn decode(encoded: &str) -> Option<(&str, &str)> {
        encoded.split_once(Self::SEPARATOR)
    }
}

trait CaveatType: Display + FromStr + Sized + 'static {
    const KEY: &'static str;

    fn encode(&self) -> Result<ByteString> {
        let mut value = String::new();
        write!(&mut value, "{self}").map_err(|_| rejected("serialize macaroon caveat"))?;
        Ok(ByteString(
            KeyValueStrings::encode(Self::KEY, &value).into_bytes(),
        ))
    }
}

macro_rules! caveat_types {
    ($($name:ident($key:literal);)*) => {
        $(
            impl CaveatType for $name {
                const KEY: &'static str = $key;
            }
        )*

        static CAVEAT_DECODERS: phf::Map<&'static str, CaveatDecoder> = phf::phf_map! {
            $($key => decode_caveat::<$name> as CaveatDecoder,)*
        };
    };
}

type CaveatDecoder = fn(&str) -> Option<Box<dyn VerifyCaveat>>;

fn decode_caveat<T>(value: &str) -> Option<Box<dyn VerifyCaveat>>
where
    T: CaveatType + VerifyCaveat,
{
    value
        .parse::<T>()
        .ok()
        .map(|caveat| Box::new(caveat) as Box<dyn VerifyCaveat>)
}

caveat_types! {
    RevocationEpoch("epoch");
    UnixEpochSeconds("before");
    PolicyFragment("policy");
    MacaroonId("token_id");
    SessionId("session_id");
}

fn decode_predicate(predicate: &[u8]) -> Option<Box<dyn VerifyCaveat>> {
    let predicate = std::str::from_utf8(predicate).ok()?;
    let (key, value) = KeyValueStrings::decode(predicate)?;
    CAVEAT_DECODERS.get(key)?(value)
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
    resolved: Option<ResolvedAuthorization>,
}

#[derive(Clone)]
struct ResolvedAuthorization {
    owner: super::Owner,
    authority: Vec<PolicyFragment>,
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
    pub(crate) fn from_encoded(encoded: String) -> Result<Macaroon> {
        init();
        let token = encoded
            .strip_prefix(PREFIX_MAC)
            .ok_or_else(|| rejected("invalid macaroon bearer prefix"))?;
        let decoded = DependencyMacaroon::deserialize(token)
            .map_err(|_| rejected("invalid macaroon bearer"))?;
        Ok(Macaroon {
            encoded,
            decoded,
            resolved: None,
        })
    }

    fn from_decoded(decoded: DependencyMacaroon) -> Result<Macaroon> {
        let token = decoded
            .serialize(Format::V2)
            .map_err(|_| rejected("serialize macaroon"))?;
        Ok(Macaroon {
            encoded: format!("{PREFIX_MAC}{token}"),
            decoded,
            resolved: None,
        })
    }

    fn create_root(
        location: String,
        key_record: &KeyRecord,
        owner: &str,
        ttl: Ttl,
    ) -> Result<(Macaroon, UnixEpochSeconds)> {
        init();
        let key = MacaroonKey::generate(&key_record.secret);
        let identifier = ByteString(owner.as_bytes().to_vec());
        let mut decoded = DependencyMacaroon::create(Some(location), &key, identifier)
            .map_err(|_| rejected("create root macaroon"))?;
        let expires = UnixEpochSeconds::now()? + ttl;
        decoded.add_first_party_caveat(key_record.min_epoch.encode()?);
        decoded.add_first_party_caveat(expires.encode()?);
        Ok((Macaroon::from_decoded(decoded)?, expires))
    }

    pub(crate) fn identifier(&self) -> Result<String> {
        String::from_utf8(self.decoded.identifier().0)
            .map_err(|_| rejected("invalid macaroon owner"))
    }

    pub(crate) fn verify_signature(&self, secret: &[u8]) -> Result<()> {
        let key = MacaroonKey::generate(secret);
        let mut verifier = Verifier::default();
        verifier.satisfy_general(|_| true);
        verifier
            .verify(&self.decoded, &key, Vec::new())
            .map_err(|_| rejected("invalid macaroon signature"))
    }

    pub(crate) fn predicates(&self) -> Result<Vec<Box<dyn VerifyCaveat>>> {
        let mut predicates = Vec::new();
        for caveat in self.decoded.caveats() {
            let Caveat::FirstParty(first_party) = caveat else {
                return Err(rejected("unsupported third-party macaroon caveat"));
            };
            predicates.push(
                decode_predicate(&first_party.predicate().0)
                    .ok_or_else(|| rejected("invalid macaroon caveat"))?,
            );
        }
        Ok(predicates)
    }

    pub(crate) fn resolved(
        mut self,
        owner: super::Owner,
        authority: Vec<PolicyFragment>,
    ) -> Macaroon {
        self.resolved = Some(ResolvedAuthorization { owner, authority });
        self
    }

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
            let Caveat::FirstParty(first_party) = caveat else {
                return Err(rejected("macaroon is not a descendant"));
            };
            descendant.add_first_party_caveat(first_party.predicate());
        }
        if descendant.signature() != candidate.decoded.signature() {
            return Err(rejected("macaroon is not a descendant"));
        }
        Macaroon::from_decoded(descendant)
    }

    pub fn to_descendant(
        &self,
        authority: Option<&PolicyFragment>,
        ttl: Ttl,
        session: Option<&SessionId>,
    ) -> Result<Macaroon> {
        let mut descendant = self.decoded.clone();
        if let Some(authority) = authority {
            descendant.add_first_party_caveat(authority.encode()?);
        }
        descendant.add_first_party_caveat(MacaroonId::new(random_token(16)).encode()?);
        let expires = UnixEpochSeconds::now()? + ttl;
        descendant.add_first_party_caveat(expires.encode()?);
        if let Some(session) = session {
            descendant.add_first_party_caveat(session.encode()?);
        }
        Macaroon::from_decoded(descendant)
    }

    pub fn owner(&self) -> Result<super::Owner> {
        if let Some(resolved) = &self.resolved {
            return Ok(resolved.owner.clone());
        }
        let identifier = String::from_utf8(self.decoded.identifier().0)
            .map_err(|_| rejected("invalid macaroon owner"))?;
        identifier.parse()
    }

    pub fn authority(&self) -> Result<&[PolicyFragment]> {
        self.resolved
            .as_ref()
            .map(|resolved| resolved.authority.as_slice())
            .ok_or_else(|| rejected("macaroon authorization is unresolved"))
    }

    pub fn expose(&self) -> &str {
        &self.encoded
    }
}

pub(crate) struct CaveatVerification<'a> {
    pub(crate) auth: &'a AuthService,
    pub(crate) key_record: Option<&'a KeyRecord>,
    pub(crate) now: UnixEpochSeconds,
    pub(crate) fragments: Vec<PolicyFragment>,
}

pub(crate) trait VerifyCaveat {
    fn apply(self: Box<Self>, verification: &mut CaveatVerification<'_>) -> Option<()>;
}

impl VerifyCaveat for RevocationEpoch {
    fn apply(self: Box<Self>, verification: &mut CaveatVerification<'_>) -> Option<()> {
        match verification.key_record {
            Some(key_record) => key_record.min_epoch.accepts(*self).then_some(()),
            None => Some(()),
        }
    }
}

impl VerifyCaveat for UnixEpochSeconds {
    fn apply(self: Box<Self>, verification: &mut CaveatVerification<'_>) -> Option<()> {
        (verification.now < *self).then_some(())
    }
}

impl VerifyCaveat for PolicyFragment {
    fn apply(self: Box<Self>, verification: &mut CaveatVerification<'_>) -> Option<()> {
        verification.fragments.push(*self);
        Some(())
    }
}

impl VerifyCaveat for MacaroonId {
    fn apply(self: Box<Self>, verification: &mut CaveatVerification<'_>) -> Option<()> {
        (!verification.auth.is_revoked(self.as_str())).then_some(())
    }
}

impl VerifyCaveat for SessionId {
    fn apply(self: Box<Self>, verification: &mut CaveatVerification<'_>) -> Option<()> {
        (!verification.auth.is_revoked(self.as_str())).then_some(())
    }
}

pub(crate) fn mount_routes(router: Router<AuthState>) -> Router<AuthState> {
    router
        .route("/macaroon/root", post(root))
        .route("/macaroon/revoke", post(revoke))
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::to_string)
}

fn caller_owner(auth: &AuthService, headers: &HeaderMap) -> Option<String> {
    let token = bearer(headers)?;
    auth.resolve_bearer(&token)
        .ok()
        .flatten()
        .map(|(owner, _)| owner.to_string())
}

fn detail(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "detail": msg }))).into_response()
}

async fn root(State(state): State<AuthState>, headers: HeaderMap) -> Response {
    let auth = state.auth();
    let location = state
        .oauth()
        .map(|p| p.public_url().to_string())
        .unwrap_or_else(|| "noted".to_string());
    let Some(owner) = caller_owner(auth, &headers) else {
        return detail(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let key_rec = match auth.db().and_then(|db| db.mac_root(&owner)) {
        Ok(Some(r)) => r,
        Ok(None) => {
            let mut secret = vec![0u8; 32];
            rand::rng().fill_bytes(&mut secret);
            let rec = KeyRecord {
                secret,
                min_epoch: RevocationEpoch::initial(),
            };
            if auth
                .db()
                .and_then(|db| db.put_mac_root(&owner, &rec))
                .is_err()
            {
                return detail(StatusCode::INTERNAL_SERVER_ERROR, "server error");
            }
            rec
        }
        Err(_) => return detail(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    };
    match Macaroon::create_root(location, &key_rec, &owner, auth.default_ttl()) {
        Ok((macaroon, expires)) => Json(json!({
            "macaroon": macaroon.expose(),
            "expires_at": expires
        }))
        .into_response(),
        Err(_) => detail(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    }
}

async fn revoke(State(state): State<AuthState>, headers: HeaderMap, body: Bytes) -> Response {
    let auth = state.auth();
    let Some(owner) = caller_owner(auth, &headers) else {
        return detail(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let Ok(deadline) = UnixEpochSeconds::now().map(|n| n + auth.default_ttl()) else {
        return detail(StatusCode::INTERNAL_SERVER_ERROR, "server error");
    };
    if v.get("all").and_then(Value::as_bool) == Some(true) {
        let _ = auth.db().and_then(|db| db.bump_root_epoch(&owner));
    } else if let Some(id) = v.get("id").and_then(Value::as_str) {
        let _ = auth.db().and_then(|db| db.revoke_id(id, deadline));
    } else if let Some(s) = v.get("session").and_then(Value::as_str) {
        let _ = auth.db().and_then(|db| db.revoke_id(s, deadline));
    } else {
        return detail(StatusCode::BAD_REQUEST, "provide id, session, or all");
    }
    Json(json!({ "ok": true })).into_response()
}
