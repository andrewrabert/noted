use std::path::Path;

use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::error::{db_error, io_error, json_error, NotedError, Result};
use crate::oauth::types::{
    ClientId, CredentialId, Fingerprint, Label, Owner, PasswordHash, SecretHash,
};
use crate::types::UnixEpochSeconds;

const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
const CREDENTIALS: TableDefinition<&str, &[u8]> = TableDefinition::new("credentials");
const CLIENTS: TableDefinition<&str, &str> = TableDefinition::new("clients");
const MAC_ROOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("mac_roots");
const MAC_REVOKED: TableDefinition<&str, u64> = TableDefinition::new("mac_revoked");

fn db_err<E: Into<redb::Error>>(e: E) -> NotedError {
    db_error("oauth db", e)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub secret: Vec<u8>,
    pub min_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Access,
    Refresh,
    ApiKey,
}

impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialKind::Access => "access",
            CredentialKind::Refresh => "refresh",
            CredentialKind::ApiKey => "api_key",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Pending,
    Active,
    Revoked,
}

impl CredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialStatus::Pending => "pending",
            CredentialStatus::Active => "active",
            CredentialStatus::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub password_hash: PasswordHash,
    pub scope: crate::scope::StoredScope,
    pub created_at: UnixEpochSeconds,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CredentialCore {
    pub credential_id: CredentialId,
    pub owner: Owner,
    pub status: CredentialStatus,
    pub fingerprint: Fingerprint,
    pub created_at: UnixEpochSeconds,
    pub expires_at: UnixEpochSeconds,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginCred {
    #[serde(flatten)]
    pub core: CredentialCore,
    pub client_id: ClientId,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ApiKeyCred {
    #[serde(flatten)]
    pub core: CredentialCore,
    pub label: Label,
    pub scope: crate::scope::StoredScope,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialRecord {
    Access(LoginCred),
    Refresh(LoginCred),
    ApiKey(ApiKeyCred),
}

impl CredentialRecord {
    pub fn core(&self) -> &CredentialCore {
        match self {
            CredentialRecord::Access(c) | CredentialRecord::Refresh(c) => &c.core,
            CredentialRecord::ApiKey(c) => &c.core,
        }
    }

    fn core_mut(&mut self) -> &mut CredentialCore {
        match self {
            CredentialRecord::Access(c) | CredentialRecord::Refresh(c) => &mut c.core,
            CredentialRecord::ApiKey(c) => &mut c.core,
        }
    }

    pub fn kind(&self) -> CredentialKind {
        match self {
            CredentialRecord::Access(_) => CredentialKind::Access,
            CredentialRecord::Refresh(_) => CredentialKind::Refresh,
            CredentialRecord::ApiKey(_) => CredentialKind::ApiKey,
        }
    }

    pub fn credential_id(&self) -> &CredentialId {
        &self.core().credential_id
    }

    pub fn owner(&self) -> &Owner {
        &self.core().owner
    }

    pub fn status(&self) -> CredentialStatus {
        self.core().status
    }

    pub fn set_status(&mut self, status: CredentialStatus) {
        self.core_mut().status = status;
    }

    pub fn fingerprint(&self) -> &Fingerprint {
        &self.core().fingerprint
    }

    pub fn created_at(&self) -> UnixEpochSeconds {
        self.core().created_at
    }

    pub fn expires_at(&self) -> UnixEpochSeconds {
        self.core().expires_at
    }

    pub fn client_id(&self) -> Option<&ClientId> {
        match self {
            CredentialRecord::Access(c) | CredentialRecord::Refresh(c) => Some(&c.client_id),
            CredentialRecord::ApiKey(_) => None,
        }
    }

    pub fn label(&self) -> Option<&Label> {
        match self {
            CredentialRecord::ApiKey(c) => Some(&c.label),
            _ => None,
        }
    }

    pub fn scope(&self) -> Option<&crate::scope::StoredScope> {
        match self {
            CredentialRecord::ApiKey(c) => Some(&c.scope),
            _ => None,
        }
    }

    pub fn set_scope(&mut self, scope: crate::scope::StoredScope) {
        if let CredentialRecord::ApiKey(c) = self {
            c.scope = scope;
        }
    }

    pub fn is_live(&self, now: UnixEpochSeconds) -> bool {
        self.status() == CredentialStatus::Active && now < self.expires_at()
    }
}

pub struct Db {
    inner: Database,
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| io_error("oauth db: mkdir", e))?;
            }
        }
        let inner = Database::create(path).map_err(|e| db_error("oauth db: open", e))?;
        let w = inner.begin_write().map_err(db_err)?;
        {
            w.open_table(USERS).map_err(db_err)?;
            w.open_table(CREDENTIALS).map_err(db_err)?;
            w.open_table(CLIENTS).map_err(db_err)?;
            w.open_table(MAC_ROOTS).map_err(db_err)?;
            w.open_table(MAC_REVOKED).map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(Db { inner })
    }

    pub fn put_client(&self, client_id: &str, json: &str) -> Result<()> {
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(CLIENTS).map_err(db_err)?;
            t.insert(client_id, json).map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn all_clients(&self) -> Result<Vec<(String, String)>> {
        let r = self.inner.begin_read().map_err(db_err)?;
        let t = r.open_table(CLIENTS).map_err(db_err)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(db_err)? {
            let (k, v) = row.map_err(db_err)?;
            out.push((k.value().to_string(), v.value().to_string()));
        }
        Ok(out)
    }

    pub fn sweep_expired(&self) -> Result<()> {
        let now = UnixEpochSeconds::now()?.as_secs();
        let mut dead_ids: Vec<String> = Vec::new();
        {
            let r = self.inner.begin_read().map_err(db_err)?;
            let t = r.open_table(MAC_REVOKED).map_err(db_err)?;
            for row in t.iter().map_err(db_err)? {
                let (k, v) = row.map_err(db_err)?;
                if now >= v.value() {
                    dead_ids.push(k.value().to_string());
                }
            }
        }
        if dead_ids.is_empty() {
            return Ok(());
        }
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut rev = w.open_table(MAC_REVOKED).map_err(db_err)?;
            for id in &dead_ids {
                rev.remove(id.as_str()).map_err(db_err)?;
            }
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn revoke_id(&self, id: &str, expires_at: UnixEpochSeconds) -> Result<()> {
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(MAC_REVOKED).map_err(db_err)?;
            t.insert(id, expires_at.as_secs()).map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn is_revoked(&self, id: &str) -> Result<bool> {
        let r = self.inner.begin_read().map_err(db_err)?;
        let t = r.open_table(MAC_REVOKED).map_err(db_err)?;
        Ok(t.get(id).map_err(db_err)?.is_some())
    }

    pub fn put_user(&self, name: &str, rec: &UserRecord) -> Result<()> {
        let bytes = serde_json::to_vec(rec).map_err(|e| json_error("encode record", e))?;
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(USERS).map_err(db_err)?;
            t.insert(name, bytes.as_slice()).map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn get_user(&self, name: &str) -> Result<Option<UserRecord>> {
        let r = self.inner.begin_read().map_err(db_err)?;
        let t = r.open_table(USERS).map_err(db_err)?;
        match t.get(name).map_err(db_err)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value()).map_err(|e| json_error("decode record", e))?,
            )),
            None => Ok(None),
        }
    }

    pub fn all_users(&self) -> Result<Vec<(String, UserRecord)>> {
        let r = self.inner.begin_read().map_err(db_err)?;
        let t = r.open_table(USERS).map_err(db_err)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(db_err)? {
            let (k, v) = row.map_err(db_err)?;
            out.push((
                k.value().to_string(),
                serde_json::from_slice(v.value()).map_err(|e| json_error("decode record", e))?,
            ));
        }
        Ok(out)
    }

    pub fn remove_user_txn(&self, name: &str) -> Result<()> {
        let owner = Owner::user(name)?;
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut users = w.open_table(USERS).map_err(db_err)?;
            users.remove(name).map_err(db_err)?;
            drop(users);
            let mut creds = w.open_table(CREDENTIALS).map_err(db_err)?;
            let mut dead = Vec::new();
            for row in creds.iter().map_err(db_err)? {
                let (k, v) = row.map_err(db_err)?;
                let rec: CredentialRecord = serde_json::from_slice(v.value())
                    .map_err(|e| json_error("decode record", e))?;
                if *rec.owner() == owner {
                    dead.push(k.value().to_string());
                }
            }
            for k in &dead {
                creds.remove(k.as_str()).map_err(db_err)?;
            }
            drop(creds);
            let mut roots = w.open_table(MAC_ROOTS).map_err(db_err)?;
            let owner_key = owner.to_string();
            roots.remove(owner_key.as_str()).map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn put_credential(&self, secret_hash: &SecretHash, rec: &CredentialRecord) -> Result<()> {
        let bytes = serde_json::to_vec(rec).map_err(|e| json_error("encode record", e))?;
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(CREDENTIALS).map_err(db_err)?;
            t.insert(secret_hash.as_str(), bytes.as_slice())
                .map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn put_credentials_txn(&self, put: &[(SecretHash, CredentialRecord)]) -> Result<()> {
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(CREDENTIALS).map_err(db_err)?;
            for (hash, rec) in put {
                let bytes = serde_json::to_vec(rec).map_err(|e| json_error("encode record", e))?;
                t.insert(hash.as_str(), bytes.as_slice()).map_err(db_err)?;
            }
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn get_credential(&self, secret_hash: &SecretHash) -> Result<Option<CredentialRecord>> {
        let r = self.inner.begin_read().map_err(db_err)?;
        let t = r.open_table(CREDENTIALS).map_err(db_err)?;
        match t.get(secret_hash.as_str()).map_err(db_err)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value()).map_err(|e| json_error("decode record", e))?,
            )),
            None => Ok(None),
        }
    }

    pub fn scan_credentials(&self) -> Result<Vec<(SecretHash, CredentialRecord)>> {
        let r = self.inner.begin_read().map_err(db_err)?;
        let t = r.open_table(CREDENTIALS).map_err(db_err)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(db_err)? {
            let (k, v) = row.map_err(db_err)?;
            out.push((
                SecretHash::new(k.value()),
                serde_json::from_slice(v.value()).map_err(|e| json_error("decode record", e))?,
            ));
        }
        Ok(out)
    }

    pub fn delete_credential(&self, secret_hash: &SecretHash) -> Result<()> {
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(CREDENTIALS).map_err(db_err)?;
            t.remove(secret_hash.as_str()).map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn revoke_credential_txn(&self, secret_hash: &SecretHash) -> Result<()> {
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(CREDENTIALS).map_err(db_err)?;
            let rec = match t.get(secret_hash.as_str()).map_err(db_err)? {
                Some(v) => {
                    let mut rec: CredentialRecord = serde_json::from_slice(v.value())
                        .map_err(|e| json_error("decode record", e))?;
                    rec.set_status(CredentialStatus::Revoked);
                    Some(rec)
                }
                None => None,
            };
            if let Some(rec) = rec {
                let bytes = serde_json::to_vec(&rec).map_err(|e| json_error("encode record", e))?;
                t.insert(secret_hash.as_str(), bytes.as_slice())
                    .map_err(db_err)?;
                drop(t);
                if rec.kind() == CredentialKind::ApiKey {
                    let mut roots = w.open_table(MAC_ROOTS).map_err(db_err)?;
                    let owner = Owner::Key(rec.credential_id().clone()).to_string();
                    roots.remove(owner.as_str()).map_err(db_err)?;
                }
            }
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn rotate_credentials_txn(
        &self,
        remove_hash: &SecretHash,
        put: &[(SecretHash, CredentialRecord)],
    ) -> Result<()> {
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(CREDENTIALS).map_err(db_err)?;
            t.remove(remove_hash.as_str()).map_err(db_err)?;
            for (hash, rec) in put {
                let bytes = serde_json::to_vec(rec).map_err(|e| json_error("encode record", e))?;
                t.insert(hash.as_str(), bytes.as_slice()).map_err(db_err)?;
            }
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn sweep_credentials(&self, pending_cutoff: UnixEpochSeconds) -> Result<()> {
        let now = UnixEpochSeconds::now()?;
        let mut dead = Vec::new();
        {
            let r = self.inner.begin_read().map_err(db_err)?;
            let t = r.open_table(CREDENTIALS).map_err(db_err)?;
            for row in t.iter().map_err(db_err)? {
                let (k, v) = row.map_err(db_err)?;
                let rec: CredentialRecord = serde_json::from_slice(v.value())
                    .map_err(|e| json_error("decode record", e))?;
                let stale_pending =
                    rec.status() == CredentialStatus::Pending && rec.created_at() < pending_cutoff;
                if now >= rec.expires_at() || stale_pending {
                    dead.push(k.value().to_string());
                }
            }
        }
        if dead.is_empty() {
            return Ok(());
        }
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(CREDENTIALS).map_err(db_err)?;
            for k in &dead {
                t.remove(k.as_str()).map_err(db_err)?;
            }
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn mac_root(&self, owner: &str) -> Result<Option<KeyRecord>> {
        let r = self.inner.begin_read().map_err(db_err)?;
        let t = r.open_table(MAC_ROOTS).map_err(db_err)?;
        match t.get(owner).map_err(db_err)? {
            Some(v) => Ok(Some(
                serde_json::from_slice(v.value()).map_err(|e| json_error("decode record", e))?,
            )),
            None => Ok(None),
        }
    }

    pub fn put_mac_root(&self, owner: &str, rec: &KeyRecord) -> Result<()> {
        let bytes = serde_json::to_vec(rec).map_err(|e| json_error("encode record", e))?;
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(MAC_ROOTS).map_err(db_err)?;
            t.insert(owner, bytes.as_slice()).map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn delete_mac_root(&self, owner: &str) -> Result<()> {
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(MAC_ROOTS).map_err(db_err)?;
            t.remove(owner).map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn bump_root_epoch(&self, owner: &str) -> Result<()> {
        if let Some(mut rec) = self.mac_root(owner)? {
            rec.min_epoch += 1;
            self.put_mac_root(owner, &rec)?;
        }
        Ok(())
    }
}
