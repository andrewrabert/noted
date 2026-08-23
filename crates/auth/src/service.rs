use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::credential::{KeyRecord, Macaroon, MacaroonId};
use crate::db::{Db, RefreshRecord, UserRecord};
use crate::oauth::OAuthClient;
use crate::password::hash_password;
use crate::types::{
    ClientId, Fingerprint, Owner, Password, PasswordHash, RefreshToken, SecretHash, Username,
};
use noted::PolicyFragment;
use noted::error::{Result, rejected};
use noted::types::UnixEpochSeconds;
use noted::util::random_token;

pub const PREFIX_REF: &str = "noted_ref_";
pub const PREFIX_MAC: &str = "noted_mac_";

const FINGERPRINT_CHARS: usize = 8;
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
    pub policy: PolicyFragment,
    pub fingerprint: Fingerprint,
    pub created_at: UnixEpochSeconds,
}

pub struct Login {
    pub access: Macaroon,
    pub refresh: RefreshToken,
}

pub struct AuthService {
    db: Arc<Db>,
}

impl AuthService {
    pub fn new(db: Arc<Db>) -> AuthService {
        AuthService { db }
    }

    pub fn db(&self) -> &Arc<Db> {
        &self.db
    }

    pub(crate) fn register_oauth_client(&self, client: &OAuthClient) -> Result<()> {
        self.db.put_oauth_client(client)
    }

    pub(crate) fn oauth_clients(&self) -> Result<Vec<OAuthClient>> {
        self.db.oauth_clients()
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

    /// A bare root under the user's key, with an opaque `noted_ref_*` refresh
    /// beside it.
    pub fn issue_login(&self, name: &Username, client: &ClientId) -> Result<Login> {
        self.mint_login(name, client, None)
    }

    /// The same, atomically replacing the old refresh record.
    pub fn rotate_login(
        &self,
        refresh: &RefreshToken,
        name: &Username,
        client: &ClientId,
    ) -> Result<Login> {
        let old = sha256_hex(refresh.expose());
        self.db
            .refresh(&old)?
            .ok_or_else(|| rejected("unknown refresh token"))?;
        self.mint_login(name, client, Some(old))
    }

    fn mint_login(
        &self,
        name: &Username,
        client: &ClientId,
        rotate: Option<SecretHash>,
    ) -> Result<Login> {
        self.require_user(name)?;
        let key = self.user_root(name)?;
        let owner = Owner::User(name.clone());
        let created_at = UnixEpochSeconds::now()?;
        let access = Macaroon::mint(&owner, &key, &[])?;
        let refresh = format!("{PREFIX_REF}{}", random_token(SECRET_BYTES));
        let record = RefreshRecord {
            owner,
            client_id: client.clone(),
            fingerprint: fingerprint(&refresh, PREFIX_REF),
            created_at,
        };
        let hash = sha256_hex(&refresh);
        match rotate {
            Some(old) => self.db.rotate_refresh_txn(&old, &hash, &record)?,
            None => self.db.put_refresh(&hash, &record)?,
        }
        Ok(Login {
            access,
            refresh: RefreshToken::new(refresh),
        })
    }

    pub fn refresh_owner(&self, refresh: &RefreshToken) -> Result<Option<RefreshRecord>> {
        if BearerKind::from_secret(refresh.expose()) != Some(BearerKind::Refresh) {
            return Ok(None);
        }
        let Some(rec) = self.db.refresh(&sha256_hex(refresh.expose()))? else {
            return Ok(None);
        };
        let Owner::User(name) = &rec.owner else {
            return Ok(None);
        };
        if self.db.user(name)?.is_none() {
            return Ok(None);
        }
        Ok(Some(rec))
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
    fn fingerprint_is_prefix_plus_head() {
        let secret = "noted_ref_abcdefghijKLMNOP";
        assert_eq!(fingerprint(secret, PREFIX_REF), "noted_ref_abcdefgh…");
    }
}
