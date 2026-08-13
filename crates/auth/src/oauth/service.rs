use std::sync::Arc;

use rand::Rng;
use sha2::{Digest, Sha256};

use crate::password::hash_password;
use noted::PolicyFragment;
use noted::error::{Result, rejected};
use noted::types::{SecondsDuration, Ttl, UnixEpochSeconds};
use noted::util::random_token;

use super::db::{
    ApiKeyCred, CredentialCore, CredentialKind, CredentialRecord, CredentialStatus, Db, KeyRecord,
    LoginCred, UserRecord,
};
use super::macaroon::{CaveatVerification, Macaroon};
use super::types::{
    ClientId, CredentialId, Fingerprint, Label, Owner, Password, PasswordHash, Secret, SecretHash,
    Username,
};

pub const PREFIX_ACC: &str = "noted_acc_";
pub const PREFIX_REF: &str = "noted_ref_";
pub const PREFIX_KEY: &str = "noted_key_";
pub const PREFIX_MAC: &str = "noted_mac_";

pub const ACCESS_TTL: Ttl = Ttl::from_secs(3600);
pub const PENDING_WINDOW: SecondsDuration = SecondsDuration::from_secs(600);
pub const DEFAULT_CREDENTIAL_TTL: Ttl = Ttl::from_secs(30 * 24 * 3600);
pub const DEFAULT_CREDENTIAL_TTL_HUMAN: &str = "30d";
const FINGERPRINT_CHARS: usize = 8;
const CRED_ID_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const CRED_ID_LEN: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BearerKind {
    Access,
    Refresh,
    ApiKey,
    Macaroon,
}

impl BearerKind {
    pub fn from_secret(secret: &str) -> Option<BearerKind> {
        if secret.starts_with(PREFIX_ACC) {
            Some(BearerKind::Access)
        } else if secret.starts_with(PREFIX_REF) {
            Some(BearerKind::Refresh)
        } else if secret.starts_with(PREFIX_KEY) {
            Some(BearerKind::ApiKey)
        } else if secret.starts_with(PREFIX_MAC) {
            Some(BearerKind::Macaroon)
        } else {
            None
        }
    }
}

pub fn sha256_hex(secret: &str) -> SecretHash {
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    SecretHash::new(out)
}

pub fn new_credential_id() -> CredentialId {
    let mut bytes = [0u8; CRED_ID_LEN];
    rand::rng().fill_bytes(&mut bytes);
    let mut id = String::from("cred_");
    for b in bytes {
        id.push(CRED_ID_ALPHABET[(b % 32) as usize] as char);
    }
    CredentialId::new(id).expect("generated credential id matches its own format")
}

fn fingerprint(secret: &str, prefix: &str) -> Fingerprint {
    let head_end = (prefix.len() + FINGERPRINT_CHARS).min(secret.len());
    Fingerprint::new(format!("{}…", &secret[..head_end]))
}

fn mint_secret(prefix: &str) -> String {
    format!("{prefix}{}", random_token(32))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MintedKey {
    pub credential_id: CredentialId,
    pub token: Secret,
    pub fingerprint: Fingerprint,
    pub expires_at: UnixEpochSeconds,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UserSummary {
    pub name: Username,
    pub policy: PolicyFragment,
    pub created_at: UnixEpochSeconds,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CredentialSummary {
    pub credential_id: CredentialId,
    pub kind: CredentialKind,
    pub owner: Owner,
    pub status: CredentialStatus,
    pub fingerprint: Fingerprint,
    pub created_at: UnixEpochSeconds,
    pub expires_at: UnixEpochSeconds,
    pub label: Option<Label>,
    pub policy: Option<PolicyFragment>,
}

impl From<CredentialRecord> for CredentialSummary {
    fn from(r: CredentialRecord) -> Self {
        CredentialSummary {
            credential_id: r.credential_id().clone(),
            kind: r.kind(),
            owner: r.owner().clone(),
            status: r.status(),
            fingerprint: r.fingerprint().clone(),
            created_at: r.created_at(),
            expires_at: r.expires_at(),
            label: r.label().cloned(),
            policy: r.policy().cloned(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum RevokeBy {
    Label(Label),
    Id(CredentialId),
    SecretHash(SecretHash),
}

impl RevokeBy {
    pub fn from_secret(secret: &str) -> RevokeBy {
        RevokeBy::SecretHash(sha256_hex(secret))
    }
}

enum Mode {
    Db(Arc<Db>),
    Upstream(Macaroon),
}

pub struct AuthService {
    mode: Mode,
    default_ttl: Ttl,
}

impl AuthService {
    pub fn new(db: Arc<Db>, default_ttl: Ttl) -> AuthService {
        AuthService {
            mode: Mode::Db(db),
            default_ttl,
        }
    }

    pub fn upstream(token: &str, default_ttl: Ttl) -> Result<AuthService> {
        Ok(AuthService {
            mode: Mode::Upstream(Macaroon::from_encoded(token.to_string())?),
            default_ttl,
        })
    }

    pub fn db(&self) -> Result<&Arc<Db>> {
        match &self.mode {
            Mode::Db(db) => Ok(db),
            Mode::Upstream(_) => Err(rejected("this server holds no auth database")),
        }
    }

    pub fn default_ttl(&self) -> Ttl {
        self.default_ttl
    }

    pub fn from_bearer(&self, bearer: &str) -> Result<Macaroon> {
        match &self.mode {
            Mode::Db(db) => {
                let macaroon = Macaroon::from_encoded(bearer.to_string())?;
                let identifier = macaroon.identifier()?;
                let owner = identifier
                    .parse::<Owner>()
                    .map_err(|_| rejected("invalid macaroon owner"))?;
                let key_record = db
                    .mac_root(&identifier)?
                    .ok_or_else(|| rejected("unknown macaroon"))?;
                macaroon.verify_signature(&key_record.secret)?;
                let owner_authority = self
                    .owner_policy(&identifier)?
                    .ok_or_else(|| rejected("unknown macaroon owner"))?;
                let fragments =
                    self.verified_fragments(&macaroon, Some(&key_record), vec![owner_authority])?;
                Ok(macaroon.resolved(owner, fragments))
            }
            Mode::Upstream(root) => {
                if BearerKind::from_secret(bearer) != Some(BearerKind::Macaroon) {
                    return Err(rejected("not a macaroon bearer"));
                }
                let descendant = root.from_descendant(bearer)?;
                let owner = descendant
                    .identifier()?
                    .parse::<Owner>()
                    .map_err(|_| rejected("invalid macaroon owner"))?;
                let fragments = self.verified_fragments(&descendant, None, Vec::new())?;
                Ok(descendant.resolved(owner, fragments))
            }
        }
    }

    fn verified_fragments(
        &self,
        macaroon: &Macaroon,
        key_record: Option<&KeyRecord>,
        held: Vec<PolicyFragment>,
    ) -> Result<Vec<PolicyFragment>> {
        let mut verification = CaveatVerification {
            auth: self,
            key_record,
            now: UnixEpochSeconds::now()?,
            fragments: held,
        };
        for predicate in macaroon.predicates()? {
            predicate
                .apply(&mut verification)
                .ok_or_else(|| rejected("macaroon caveat rejected"))?;
        }
        Ok(verification.fragments)
    }

    pub(crate) fn is_revoked(&self, id: &str) -> bool {
        match &self.mode {
            Mode::Db(db) => db.is_revoked(id).unwrap_or(true),
            Mode::Upstream(_) => false,
        }
    }

    pub fn user_add(&self, name: &Username, password: &Password) -> Result<()> {
        if password.is_empty() {
            return Err(rejected("password must not be empty"));
        }
        if self.db()?.get_user(name.as_str())?.is_some() {
            return Err(rejected(format!("user '{name}' already exists")));
        }
        self.db()?.put_user(
            name.as_str(),
            &UserRecord {
                password_hash: PasswordHash::new(hash_password(password.expose())),
                policy: PolicyFragment::default(),
                created_at: UnixEpochSeconds::now()?,
            },
        )
    }

    pub fn user_passwd(&self, name: &Username, password: &Password) -> Result<()> {
        if password.is_empty() {
            return Err(rejected("password must not be empty"));
        }
        let mut rec = self.require_user(name)?;
        rec.password_hash = PasswordHash::new(hash_password(password.expose()));
        self.db()?.put_user(name.as_str(), &rec)
    }

    pub fn user_set_policy(&self, name: &Username, policy: PolicyFragment) -> Result<()> {
        let mut rec = self.require_user(name)?;
        rec.policy = policy;
        self.db()?.put_user(name.as_str(), &rec)
    }

    pub fn user_list(&self) -> Result<Vec<UserSummary>> {
        self.db()?
            .all_users()?
            .into_iter()
            .map(|(name, r)| {
                Ok(UserSummary {
                    name: Username::new(name)?,
                    policy: r.policy,
                    created_at: r.created_at,
                })
            })
            .collect()
    }

    pub fn user_get(&self, name: &Username) -> Result<Option<UserSummary>> {
        match self.db()?.get_user(name.as_str())? {
            Some(r) => Ok(Some(UserSummary {
                name: name.clone(),
                policy: r.policy,
                created_at: r.created_at,
            })),
            None => Ok(None),
        }
    }

    pub fn user_credentials(&self, name: &Username) -> Result<Vec<CredentialSummary>> {
        let owner = Owner::User(name.clone());
        Ok(self
            .db()?
            .scan_credentials()?
            .into_iter()
            .filter(|(_, r)| *r.owner() == owner)
            .map(|(_, r)| r.into())
            .collect())
    }

    pub fn user_revoke(&self, name: &Username, id: Option<&CredentialId>) -> Result<usize> {
        self.require_user(name)?;
        let owner = Owner::User(name.clone());
        let mut n = 0;
        for (hash, rec) in self.db()?.scan_credentials()? {
            if *rec.owner() != owner || rec.status() == CredentialStatus::Revoked {
                continue;
            }
            if let Some(id) = id
                && rec.credential_id() != id
            {
                continue;
            }
            self.db()?.revoke_credential_txn(&hash)?;
            n += 1;
        }
        if id.is_some() && n == 0 {
            return Err(rejected("no such credential"));
        }
        Ok(n)
    }

    pub fn user_remove(&self, name: &Username) -> Result<()> {
        self.require_user(name)?;
        self.db()?.remove_user_txn(name.as_str())
    }

    pub fn login_user(&self, name: &str) -> Result<Option<UserRecord>> {
        self.db()?.get_user(name)
    }

    fn require_user(&self, name: &Username) -> Result<UserRecord> {
        self.db()?
            .get_user(name.as_str())?
            .ok_or_else(|| rejected(format!("no such user: '{name}'")))
    }

    pub fn key_create(
        &self,
        label: &Label,
        policy: PolicyFragment,
        ttl: Option<Ttl>,
    ) -> Result<MintedKey> {
        let secret = mint_secret(PREFIX_KEY);
        let credential_id = new_credential_id();
        let created_at = UnixEpochSeconds::now()?;
        let expires_at = created_at + ttl.unwrap_or(self.default_ttl);
        let fp = fingerprint(&secret, PREFIX_KEY);
        let rec = CredentialRecord::ApiKey(ApiKeyCred {
            core: CredentialCore {
                credential_id: credential_id.clone(),
                owner: Owner::Key(credential_id.clone()),
                status: CredentialStatus::Pending,
                fingerprint: fp.clone(),
                created_at,
                expires_at,
            },
            label: label.clone(),
            policy,
        });
        self.db()?.put_credential(&sha256_hex(&secret), &rec)?;
        Ok(MintedKey {
            credential_id,
            fingerprint: fp,
            expires_at,
            token: Secret::new(secret),
        })
    }

    pub fn key_finalize(&self, credential_id: &CredentialId) -> Result<()> {
        for (hash, mut rec) in self.db()?.scan_credentials()? {
            if rec.credential_id() == credential_id && rec.kind() == CredentialKind::ApiKey {
                if rec.status() != CredentialStatus::Pending {
                    return Err(rejected("key is not pending"));
                }
                rec.set_status(CredentialStatus::Active);
                return self.db()?.put_credential(&hash, &rec);
            }
        }
        Err(rejected("no such credential"))
    }

    pub fn key_set_policy(
        &self,
        label: Option<&Label>,
        id: Option<&CredentialId>,
        policy: PolicyFragment,
    ) -> Result<usize> {
        let mut n = 0;
        for (hash, mut rec) in self.db()?.scan_credentials()? {
            if !Self::key_matches(&rec, label, id) || rec.status() == CredentialStatus::Revoked {
                continue;
            }
            rec.set_policy(policy.clone());
            self.db()?.put_credential(&hash, &rec)?;
            n += 1;
        }
        if n == 0 {
            return Err(rejected("no such key"));
        }
        Ok(n)
    }

    pub fn key_list(&self, label: Option<&Label>) -> Result<Vec<CredentialSummary>> {
        Ok(self
            .db()?
            .scan_credentials()?
            .into_iter()
            .filter(|(_, r)| {
                r.kind() == CredentialKind::ApiKey
                    && label.map(|l| r.label() == Some(l)).unwrap_or(true)
            })
            .map(|(_, r)| r.into())
            .collect())
    }

    pub fn key_revoke(&self, by: &RevokeBy) -> Result<usize> {
        if let RevokeBy::SecretHash(hash) = by {
            let Some(rec) = self.db()?.get_credential(hash)? else {
                return Err(rejected("no such credential"));
            };
            if rec.kind() != CredentialKind::ApiKey {
                return Err(rejected("not an API key"));
            }
            self.db()?.revoke_credential_txn(hash)?;
            return Ok(1);
        }
        let (label, id) = match by {
            RevokeBy::Label(l) => (Some(l), None),
            RevokeBy::Id(i) => (None, Some(i)),
            RevokeBy::SecretHash(_) => unreachable!(),
        };
        let mut n = 0;
        for (hash, rec) in self.db()?.scan_credentials()? {
            if Self::key_matches(&rec, label, id) && rec.status() != CredentialStatus::Revoked {
                self.db()?.revoke_credential_txn(&hash)?;
                n += 1;
            }
        }
        if n == 0 {
            return Err(rejected("no such key"));
        }
        Ok(n)
    }

    fn key_matches(
        rec: &CredentialRecord,
        label: Option<&Label>,
        id: Option<&CredentialId>,
    ) -> bool {
        if rec.kind() != CredentialKind::ApiKey {
            return false;
        }
        if let Some(id) = id {
            return rec.credential_id() == id;
        }
        match label {
            Some(l) => rec.label() == Some(l),
            None => false,
        }
    }

    pub fn resolve_bearer(&self, secret: &str) -> Result<Option<(Owner, PolicyFragment)>> {
        let kind = match BearerKind::from_secret(secret) {
            Some(BearerKind::Access) => CredentialKind::Access,
            Some(BearerKind::ApiKey) => CredentialKind::ApiKey,
            _ => return Ok(None),
        };
        let hash = sha256_hex(secret);
        let Some(rec) = self.db()?.get_credential(&hash)? else {
            return Ok(None);
        };
        if rec.kind() != kind || !rec.is_live(UnixEpochSeconds::now()?) {
            return Ok(None);
        }
        match self.fragment_of(&rec)? {
            Some(grant) => Ok(Some((rec.owner().clone(), grant))),
            None => {
                tracing::warn!(owner = %rec.owner(), id = %rec.credential_id(), "orphan credential; revoking");
                self.db()?.delete_credential(&hash)?;
                Ok(None)
            }
        }
    }

    pub fn owner_policy(&self, owner: &str) -> Result<Option<PolicyFragment>> {
        match owner.parse::<Owner>() {
            Ok(Owner::User(name)) => match self.db()?.get_user(name.as_str())? {
                Some(rec) => Ok(Some(rec.policy)),
                None => Ok(None),
            },
            Ok(Owner::Key(id)) => {
                for (_, rec) in self.db()?.scan_credentials()? {
                    if rec.credential_id() == &id && rec.kind() == CredentialKind::ApiKey {
                        if !rec.is_live(UnixEpochSeconds::now()?) {
                            return Ok(None);
                        }
                        return Ok(Some(rec.policy().cloned().unwrap_or_default()));
                    }
                }
                Ok(None)
            }
            Err(_) => Ok(None),
        }
    }

    fn fragment_of(&self, rec: &CredentialRecord) -> Result<Option<PolicyFragment>> {
        match rec.kind() {
            CredentialKind::ApiKey => Ok(Some(rec.policy().cloned().unwrap_or_default())),
            _ => match rec.owner() {
                Owner::User(name) => match self.db()?.get_user(name.as_str())? {
                    Some(user) => Ok(Some(user.policy)),
                    None => Ok(None),
                },
                _ => Ok(None),
            },
        }
    }

    pub fn issue_login_pair(
        &self,
        username: &str,
        client_id: &str,
    ) -> Result<(String, String, u64)> {
        let access = mint_secret(PREFIX_ACC);
        let refresh = mint_secret(PREFIX_REF);
        let created_at = UnixEpochSeconds::now()?;
        let access_until = created_at + ACCESS_TTL;
        let owner = Owner::user(username)?;
        let make = |ctor: fn(LoginCred) -> CredentialRecord, fp: Fingerprint, expires_at| {
            ctor(LoginCred {
                core: CredentialCore {
                    credential_id: new_credential_id(),
                    owner: owner.clone(),
                    status: CredentialStatus::Active,
                    fingerprint: fp,
                    created_at,
                    expires_at,
                },
                client_id: ClientId::new(client_id),
            })
        };
        self.db()?.put_credentials_txn(&[
            (
                sha256_hex(&access),
                make(
                    CredentialRecord::Access,
                    fingerprint(&access, PREFIX_ACC),
                    access_until,
                ),
            ),
            (
                sha256_hex(&refresh),
                make(
                    CredentialRecord::Refresh,
                    fingerprint(&refresh, PREFIX_REF),
                    created_at + self.default_ttl,
                ),
            ),
        ])?;
        Ok((access, refresh, access_until.as_secs()))
    }

    pub fn rotate_refresh(
        &self,
        old_refresh: &str,
        username: &str,
        client_id: &str,
    ) -> Result<(String, String, u64)> {
        let access = mint_secret(PREFIX_ACC);
        let refresh = mint_secret(PREFIX_REF);
        let created_at = UnixEpochSeconds::now()?;
        let access_until = created_at + ACCESS_TTL;
        let owner = Owner::user(username)?;
        let make = |ctor: fn(LoginCred) -> CredentialRecord, fp: Fingerprint, expires_at| {
            ctor(LoginCred {
                core: CredentialCore {
                    credential_id: new_credential_id(),
                    owner: owner.clone(),
                    status: CredentialStatus::Active,
                    fingerprint: fp,
                    created_at,
                    expires_at,
                },
                client_id: ClientId::new(client_id),
            })
        };
        self.db()?.rotate_credentials_txn(
            &sha256_hex(old_refresh),
            &[
                (
                    sha256_hex(&access),
                    make(
                        CredentialRecord::Access,
                        fingerprint(&access, PREFIX_ACC),
                        access_until,
                    ),
                ),
                (
                    sha256_hex(&refresh),
                    make(
                        CredentialRecord::Refresh,
                        fingerprint(&refresh, PREFIX_REF),
                        created_at + self.default_ttl,
                    ),
                ),
            ],
        )?;
        Ok((access, refresh, access_until.as_secs()))
    }

    pub fn refresh_owner(&self, refresh: &str) -> Result<Option<(String, Option<String>, u64)>> {
        self.login_token_owner(refresh, BearerKind::Refresh, CredentialKind::Refresh)
    }

    pub fn access_owner(&self, access: &str) -> Result<Option<(String, Option<String>, u64)>> {
        self.login_token_owner(access, BearerKind::Access, CredentialKind::Access)
    }

    fn login_token_owner(
        &self,
        secret: &str,
        bearer: BearerKind,
        kind: CredentialKind,
    ) -> Result<Option<(String, Option<String>, u64)>> {
        if BearerKind::from_secret(secret) != Some(bearer) {
            return Ok(None);
        }
        let Some(rec) = self.db()?.get_credential(&sha256_hex(secret))? else {
            return Ok(None);
        };
        if rec.kind() != kind || !rec.is_live(UnixEpochSeconds::now()?) {
            return Ok(None);
        }
        let Owner::User(name) = rec.owner() else {
            return Ok(None);
        };
        let name = name.to_string();
        if self.db()?.get_user(&name)?.is_none() {
            return Ok(None);
        }
        let client_id = rec.client_id().map(|c| c.as_str().to_string());
        Ok(Some((name, client_id, rec.expires_at().as_secs())))
    }

    pub fn sweep(&self) -> Result<()> {
        self.db()?
            .sweep_credentials(UnixEpochSeconds::now()? - PENDING_WINDOW)?;
        self.db()?.sweep_expired()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_dispatch_and_reject() {
        assert_eq!(
            BearerKind::from_secret("noted_acc_x"),
            Some(BearerKind::Access)
        );
        assert_eq!(
            BearerKind::from_secret("noted_ref_x"),
            Some(BearerKind::Refresh)
        );
        assert_eq!(
            BearerKind::from_secret("noted_key_x"),
            Some(BearerKind::ApiKey)
        );
        assert_eq!(
            BearerKind::from_secret("noted_mac_x"),
            Some(BearerKind::Macaroon)
        );
        assert_eq!(BearerKind::from_secret("ghp_something"), None);
        assert_eq!(BearerKind::from_secret(""), None);
    }

    #[test]
    fn credential_ids_are_prefixed_base32() {
        let id = new_credential_id();
        let id = id.as_str();
        assert!(id.starts_with("cred_"));
        assert_eq!(id.len(), 5 + CRED_ID_LEN);
        assert!(id[5..].bytes().all(|b| CRED_ID_ALPHABET.contains(&b)));
    }

    #[test]
    fn default_ttl_forms_agree() {
        assert_eq!(
            humantime::parse_duration(DEFAULT_CREDENTIAL_TTL_HUMAN)
                .unwrap()
                .as_secs(),
            DEFAULT_CREDENTIAL_TTL.as_secs()
        );
    }

    #[test]
    fn fingerprint_is_prefix_plus_head() {
        let secret = "noted_key_abcdefghijKLMNOP";
        assert_eq!(fingerprint(secret, PREFIX_KEY), "noted_key_abcdefgh…");
    }
}
