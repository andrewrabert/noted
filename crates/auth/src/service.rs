use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::credential::{Caveat, KeyRecord, Macaroon, MacaroonId};
use crate::db::{Db, RefreshRecord, UserRecord};
use crate::password::hash_password;
use crate::types::{
    ClientId, Fingerprint, Label, Owner, Password, PasswordHash, Secret, SecretHash, SessionId,
    Username,
};
use noted::PolicyFragment;
use noted::error::{Result, rejected};
use noted::types::{Ttl, UnixEpochSeconds};
use noted::util::random_token;

pub const PREFIX_REF: &str = "noted_ref_";
pub const PREFIX_MAC: &str = "noted_mac_";

pub const ACCESS_TTL: Ttl = Ttl::from_secs(3600);
pub const DEFAULT_CREDENTIAL_TTL: Ttl = Ttl::from_secs(30 * 24 * 3600);
pub const DEFAULT_CREDENTIAL_TTL_HUMAN: &str = "30d";

const FINGERPRINT_CHARS: usize = 8;
const SESSION_BYTES: usize = 16;
const SECRET_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BearerKind {
    Refresh,
    Macaroon,
}

impl BearerKind {
    pub fn from_secret(secret: &str) -> Option<BearerKind> {
        if secret.starts_with(PREFIX_REF) {
            Some(BearerKind::Refresh)
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

fn fingerprint(secret: &str, prefix: &str) -> Fingerprint {
    let head_end = (prefix.len() + FINGERPRINT_CHARS).min(secret.len());
    Fingerprint::new(format!("{}…", &secret[..head_end]))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UserSummary {
    pub name: Username,
    pub policy: PolicyFragment,
    pub created_at: UnixEpochSeconds,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MintSummary {
    pub token_id: MacaroonId,
    pub owner: Owner,
    pub label: Option<Label>,
    pub policy: PolicyFragment,
    pub fingerprint: Fingerprint,
    pub created_at: UnixEpochSeconds,
    pub expires_at: UnixEpochSeconds,
}

pub struct Login {
    pub access: Macaroon,
    pub refresh: Secret,
    pub session: SessionId,
    pub expires_at: UnixEpochSeconds,
}

pub struct AuthService {
    db: Arc<Db>,
    default_ttl: Ttl,
}

impl AuthService {
    pub fn new(db: Arc<Db>, default_ttl: Ttl) -> AuthService {
        AuthService { db, default_ttl }
    }

    pub fn db(&self) -> &Arc<Db> {
        &self.db
    }

    pub fn default_ttl(&self) -> Ttl {
        self.default_ttl
    }

    pub fn user_add(&self, name: &Username, password: &Password) -> Result<()> {
        if password.is_empty() {
            return Err(rejected("password must not be empty"));
        }
        if self.db.user(name)?.is_some() {
            return Err(rejected(format!("user '{name}' already exists")));
        }
        self.db.put_user(
            name,
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
        self.db.put_user(name, &rec)
    }

    pub fn user_set_policy(&self, name: &Username, policy: PolicyFragment) -> Result<()> {
        let mut rec = self.require_user(name)?;
        rec.policy = policy;
        self.db.put_user(name, &rec)
    }

    pub fn user_list(&self) -> Result<Vec<UserSummary>> {
        Ok(self
            .db
            .all_users()?
            .into_iter()
            .map(|(name, r)| UserSummary {
                name,
                policy: r.policy,
                created_at: r.created_at,
            })
            .collect())
    }

    pub fn user_get(&self, name: &Username) -> Result<Option<UserSummary>> {
        Ok(self.db.user(name)?.map(|r| UserSummary {
            name: name.clone(),
            policy: r.policy,
            created_at: r.created_at,
        }))
    }

    pub fn user_remove(&self, name: &Username) -> Result<()> {
        self.require_user(name)?;
        self.db.remove_user_txn(name)
    }

    /// Drops every refresh record of the user and bumps its epoch, so every
    /// credential minted under its key so far is dead.
    pub fn user_revoke(&self, name: &Username) -> Result<usize> {
        self.require_user(name)?;
        let owner = Owner::User(name.clone());
        let n = self.db.remove_refresh_of(&owner)?;
        self.user_root(name)?;
        self.db.bump_root_epoch(&owner)?;
        Ok(n)
    }

    pub fn login_user(&self, name: &str) -> Result<Option<UserRecord>> {
        match name.parse::<Username>() {
            Ok(name) => self.db.user(&name),
            Err(_) => Ok(None),
        }
    }

    fn require_user(&self, name: &Username) -> Result<UserRecord> {
        self.db
            .user(name)?
            .ok_or_else(|| rejected(format!("no such user: '{name}'")))
    }

    /// The user's root key, written on first call.
    pub fn user_root(&self, name: &Username) -> Result<KeyRecord> {
        let owner = Owner::User(name.clone());
        if let Some(rec) = self.db.root(&owner)? {
            return Ok(rec);
        }
        let rec = KeyRecord::fresh();
        self.db.put_root(&owner, &rec)?;
        Ok(rec)
    }

    /// A root under the user's key carrying `epoch=`, `session_id=` and
    /// `before=` at `ACCESS_TTL`, with an opaque `noted_ref_*` refresh beside it.
    pub fn issue_login(&self, name: &Username, client: &ClientId) -> Result<Login> {
        self.mint_login(
            name,
            client,
            SessionId::new(random_token(SESSION_BYTES)),
            None,
        )
    }

    /// The same, keeping the session the old refresh record names.
    pub fn rotate_login(&self, refresh: &str, name: &Username, client: &ClientId) -> Result<Login> {
        let old = sha256_hex(refresh);
        let session = self
            .db
            .refresh(&old)?
            .ok_or_else(|| rejected("unknown refresh token"))?
            .session;
        self.mint_login(name, client, session, Some(old))
    }

    fn mint_login(
        &self,
        name: &Username,
        client: &ClientId,
        session: SessionId,
        rotate: Option<SecretHash>,
    ) -> Result<Login> {
        self.require_user(name)?;
        let key = self.user_root(name)?;
        let owner = Owner::User(name.clone());
        let created_at = UnixEpochSeconds::now()?;
        let expires_at = created_at + ACCESS_TTL;
        let access = Macaroon::mint(
            &owner,
            &key,
            &[
                Caveat::Epoch(key.min_epoch),
                Caveat::Session(session.clone()),
                Caveat::Before(expires_at),
            ],
        )?;
        let refresh = format!("{PREFIX_REF}{}", random_token(SECRET_BYTES));
        let record = RefreshRecord {
            owner,
            client_id: client.clone(),
            session: session.clone(),
            fingerprint: fingerprint(&refresh, PREFIX_REF),
            created_at,
            expires_at: created_at + self.default_ttl,
        };
        let hash = sha256_hex(&refresh);
        match rotate {
            Some(old) => self.db.rotate_refresh_txn(&old, &hash, &record)?,
            None => self.db.put_refresh(&hash, &record)?,
        }
        Ok(Login {
            access,
            refresh: Secret::new(refresh),
            session,
            expires_at,
        })
    }

    pub fn refresh_owner(&self, refresh: &str) -> Result<Option<RefreshRecord>> {
        if BearerKind::from_secret(refresh) != Some(BearerKind::Refresh) {
            return Ok(None);
        }
        let Some(rec) = self.db.refresh(&sha256_hex(refresh))? else {
            return Ok(None);
        };
        if UnixEpochSeconds::now()? >= rec.expires_at {
            return Ok(None);
        }
        let Owner::User(name) = &rec.owner else {
            return Ok(None);
        };
        if self.db.user(name)?.is_none() {
            return Ok(None);
        }
        Ok(Some(rec))
    }

    pub fn sweep(&self) -> Result<()> {
        self.db.sweep(UnixEpochSeconds::now()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_dispatch_and_reject() {
        assert_eq!(
            BearerKind::from_secret("noted_ref_x"),
            Some(BearerKind::Refresh)
        );
        assert_eq!(
            BearerKind::from_secret("noted_mac_x"),
            Some(BearerKind::Macaroon)
        );
        assert_eq!(BearerKind::from_secret("noted_acc_x"), None);
        assert_eq!(BearerKind::from_secret("noted_key_x"), None);
        assert_eq!(BearerKind::from_secret("ghp_something"), None);
        assert_eq!(BearerKind::from_secret(""), None);
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
        let secret = "noted_ref_abcdefghijKLMNOP";
        assert_eq!(fingerprint(secret, PREFIX_REF), "noted_ref_abcdefgh…");
    }
}
