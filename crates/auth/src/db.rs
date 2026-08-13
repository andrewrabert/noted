use std::path::Path as StdPath;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::credential::{Caveat, KeyRecord, MacaroonId};
use crate::types::{
    ClientId, Fingerprint, Label, Owner, PasswordHash, RevocationEpoch, SecretHash, ServerId,
    SessionId, Username,
};
use noted::error::{NotedError, Result, db_error, io_error, json_error, rejected};
use noted::types::UnixEpochSeconds;

const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
const CLIENTS: TableDefinition<&str, &str> = TableDefinition::new("clients");
const REFRESH: TableDefinition<&str, &[u8]> = TableDefinition::new("refresh");
const MINTED: TableDefinition<&str, &[u8]> = TableDefinition::new("minted");
const ROOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("roots");
const REVOKED: TableDefinition<&str, u64> = TableDefinition::new("revoked");

/// The `roots` row holding the server's own identity. No owner spelling can
/// collide with it: every other key is `user:…` or `self:…`.
const SERVER_ROW: &str = "self";

fn db_err<E: Into<redb::Error>>(e: E) -> NotedError {
    db_error("auth db", e.into())
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| json_error("encode record", e))
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|e| json_error("decode record", e))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub password_hash: PasswordHash,
    pub policy: noted::PolicyFragment,
    pub created_at: UnixEpochSeconds,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshRecord {
    pub owner: Owner,
    pub client_id: ClientId,
    pub session: SessionId,
    pub fingerprint: Fingerprint,
    pub created_at: UnixEpochSeconds,
    pub expires_at: UnixEpochSeconds,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MintRecord {
    pub owner: Owner,
    pub label: Option<Label>,
    pub session: Option<SessionId>,
    pub policy: noted::PolicyFragment,
    pub fingerprint: Fingerprint,
    pub created_at: UnixEpochSeconds,
    pub expires_at: UnixEpochSeconds,
}

#[derive(Clone, Serialize, Deserialize)]
struct ServerRecord {
    id: ServerId,
    key: KeyRecord,
}

pub struct Db {
    inner: Database,
}

impl Db {
    pub fn open(path: &StdPath) -> Result<Db> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| io_error("auth db: mkdir", e))?;
        }
        let inner = Database::create(path).map_err(|e| db_error("auth db: open", e))?;
        let w = inner.begin_write().map_err(db_err)?;
        {
            w.open_table(USERS).map_err(db_err)?;
            w.open_table(CLIENTS).map_err(db_err)?;
            w.open_table(REFRESH).map_err(db_err)?;
            w.open_table(MINTED).map_err(db_err)?;
            w.open_table(ROOTS).map_err(db_err)?;
            w.open_table(REVOKED).map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(Db { inner })
    }

    fn get(&self, table: TableDefinition<&str, &[u8]>, key: &str) -> Result<Option<Vec<u8>>> {
        let r = self.inner.begin_read().map_err(db_err)?;
        let t = r.open_table(table).map_err(db_err)?;
        Ok(t.get(key).map_err(db_err)?.map(|v| v.value().to_vec()))
    }

    fn put(&self, table: TableDefinition<&str, &[u8]>, key: &str, bytes: &[u8]) -> Result<()> {
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(table).map_err(db_err)?;
            t.insert(key, bytes).map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    fn rows<T: for<'de> Deserialize<'de>>(
        &self,
        table: TableDefinition<&str, &[u8]>,
    ) -> Result<Vec<(String, T)>> {
        let r = self.inner.begin_read().map_err(db_err)?;
        let t = r.open_table(table).map_err(db_err)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(db_err)? {
            let (k, v) = row.map_err(db_err)?;
            out.push((k.value().to_string(), decode(v.value())?));
        }
        Ok(out)
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

    /// The server's own owner and key, written on first call.
    pub fn server_key(&self) -> Result<(Owner, KeyRecord)> {
        if let Some(bytes) = self.get(ROOTS, SERVER_ROW)? {
            let rec: ServerRecord = decode(&bytes)?;
            return Ok((Owner::Server(rec.id), rec.key));
        }
        let rec = ServerRecord {
            id: ServerId::fresh(),
            key: KeyRecord::fresh(),
        };
        self.put(ROOTS, SERVER_ROW, &encode(&rec)?)?;
        Ok((Owner::Server(rec.id), rec.key))
    }

    pub fn root(&self, owner: &Owner) -> Result<Option<KeyRecord>> {
        if let Owner::Server(id) = owner {
            let (own, key) = self.server_key()?;
            return Ok((own == Owner::Server(id.clone())).then_some(key));
        }
        match self.get(ROOTS, &owner.to_string())? {
            Some(bytes) => Ok(Some(decode(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn put_root(&self, owner: &Owner, rec: &KeyRecord) -> Result<()> {
        self.put(ROOTS, &owner.to_string(), &encode(rec)?)
    }

    /// The epoch the owner's root moved to.
    pub fn bump_root_epoch(&self, owner: &Owner) -> Result<RevocationEpoch> {
        let no_root = || rejected(format!("no root key to revoke under: '{owner}'"));
        if let Owner::Server(_) = owner {
            let bytes = self.get(ROOTS, SERVER_ROW)?.ok_or_else(no_root)?;
            let mut rec: ServerRecord = decode(&bytes)?;
            rec.key.min_epoch = rec.key.min_epoch.next()?;
            self.put(ROOTS, SERVER_ROW, &encode(&rec)?)?;
            return Ok(rec.key.min_epoch);
        }
        let mut rec = self.root(owner)?.ok_or_else(no_root)?;
        rec.min_epoch = rec.min_epoch.next()?;
        self.put_root(owner, &rec)?;
        Ok(rec.min_epoch)
    }

    pub fn put_refresh(&self, hash: &SecretHash, rec: &RefreshRecord) -> Result<()> {
        self.put(REFRESH, hash.as_str(), &encode(rec)?)
    }

    pub fn refresh(&self, hash: &SecretHash) -> Result<Option<RefreshRecord>> {
        match self.get(REFRESH, hash.as_str())? {
            Some(bytes) => Ok(Some(decode(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn rotate_refresh_txn(
        &self,
        remove: &SecretHash,
        hash: &SecretHash,
        rec: &RefreshRecord,
    ) -> Result<()> {
        let bytes = encode(rec)?;
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(REFRESH).map_err(db_err)?;
            t.remove(remove.as_str()).map_err(db_err)?;
            t.insert(hash.as_str(), bytes.as_slice()).map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn remove_refresh_of(&self, owner: &Owner) -> Result<()> {
        let dead: Vec<String> = self
            .rows::<RefreshRecord>(REFRESH)?
            .into_iter()
            .filter(|(_, rec)| rec.owner == *owner)
            .map(|(k, _)| k)
            .collect();
        if dead.is_empty() {
            return Ok(());
        }
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut t = w.open_table(REFRESH).map_err(db_err)?;
            for k in &dead {
                t.remove(k.as_str()).map_err(db_err)?;
            }
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn put_minted(&self, id: &MacaroonId, rec: &MintRecord) -> Result<()> {
        self.put(MINTED, id.as_str(), &encode(rec)?)
    }

    pub fn minted(&self, id: &MacaroonId) -> Result<Option<MintRecord>> {
        match self.get(MINTED, id.as_str())? {
            Some(bytes) => Ok(Some(decode(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn all_minted(&self) -> Result<Vec<(MacaroonId, MintRecord)>> {
        Ok(self
            .rows::<MintRecord>(MINTED)?
            .into_iter()
            .map(|(k, rec)| (MacaroonId::new(k), rec))
            .collect())
    }

    pub fn put_user(&self, name: &Username, rec: &UserRecord) -> Result<()> {
        self.put(USERS, name.as_str(), &encode(rec)?)
    }

    pub fn user(&self, name: &Username) -> Result<Option<UserRecord>> {
        match self.get(USERS, name.as_str())? {
            Some(bytes) => Ok(Some(decode(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn all_users(&self) -> Result<Vec<(Username, UserRecord)>> {
        self.rows::<UserRecord>(USERS)?
            .into_iter()
            .map(|(k, rec)| Ok((Username::new(k)?, rec)))
            .collect()
    }

    /// Drops the user, its root key, its refresh records and its ledger rows.
    pub fn remove_user_txn(&self, name: &Username) -> Result<()> {
        let owner = Owner::User(name.clone());
        let dead_refresh: Vec<String> = self
            .rows::<RefreshRecord>(REFRESH)?
            .into_iter()
            .filter(|(_, rec)| rec.owner == owner)
            .map(|(k, _)| k)
            .collect();
        let dead_minted: Vec<String> = self
            .rows::<MintRecord>(MINTED)?
            .into_iter()
            .filter(|(_, rec)| rec.owner == owner)
            .map(|(k, _)| k)
            .collect();
        let owner_key = owner.to_string();
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut users = w.open_table(USERS).map_err(db_err)?;
            users.remove(name.as_str()).map_err(db_err)?;
            drop(users);
            let mut refresh = w.open_table(REFRESH).map_err(db_err)?;
            for k in &dead_refresh {
                refresh.remove(k.as_str()).map_err(db_err)?;
            }
            drop(refresh);
            let mut minted = w.open_table(MINTED).map_err(db_err)?;
            for k in &dead_minted {
                minted.remove(k.as_str()).map_err(db_err)?;
            }
            drop(minted);
            let mut roots = w.open_table(ROOTS).map_err(db_err)?;
            roots.remove(owner_key.as_str()).map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    /// Tombstones every caveat until `until` and drops every named ledger row,
    /// in one write.
    pub fn withdraw(
        &self,
        dead: &[Caveat],
        rows: &[MacaroonId],
        until: UnixEpochSeconds,
    ) -> Result<()> {
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut revoked = w.open_table(REVOKED).map_err(db_err)?;
            for caveat in dead {
                revoked
                    .insert(caveat.to_string().as_str(), until.as_secs())
                    .map_err(db_err)?;
            }
            drop(revoked);
            let mut minted = w.open_table(MINTED).map_err(db_err)?;
            for id in rows {
                minted.remove(id.as_str()).map_err(db_err)?;
            }
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn is_revoked(&self, caveat: &Caveat) -> Result<bool> {
        let r = self.inner.begin_read().map_err(db_err)?;
        let t = r.open_table(REVOKED).map_err(db_err)?;
        Ok(t.get(caveat.to_string().as_str())
            .map_err(db_err)?
            .is_some())
    }

    /// Drops every expired refresh record, ledger row and revocation.
    pub fn sweep(&self, now: UnixEpochSeconds) -> Result<()> {
        let dead_refresh: Vec<String> = self
            .rows::<RefreshRecord>(REFRESH)?
            .into_iter()
            .filter(|(_, rec)| now >= rec.expires_at)
            .map(|(k, _)| k)
            .collect();
        let dead_minted: Vec<String> = self
            .rows::<MintRecord>(MINTED)?
            .into_iter()
            .filter(|(_, rec)| now >= rec.expires_at)
            .map(|(k, _)| k)
            .collect();
        let mut dead_revoked: Vec<String> = Vec::new();
        {
            let r = self.inner.begin_read().map_err(db_err)?;
            let t = r.open_table(REVOKED).map_err(db_err)?;
            for row in t.iter().map_err(db_err)? {
                let (k, v) = row.map_err(db_err)?;
                if now.as_secs() >= v.value() {
                    dead_revoked.push(k.value().to_string());
                }
            }
        }
        if dead_refresh.is_empty() && dead_minted.is_empty() && dead_revoked.is_empty() {
            return Ok(());
        }
        let w = self.inner.begin_write().map_err(db_err)?;
        {
            let mut refresh = w.open_table(REFRESH).map_err(db_err)?;
            for k in &dead_refresh {
                refresh.remove(k.as_str()).map_err(db_err)?;
            }
            drop(refresh);
            let mut minted = w.open_table(MINTED).map_err(db_err)?;
            for k in &dead_minted {
                minted.remove(k.as_str()).map_err(db_err)?;
            }
            drop(minted);
            let mut revoked = w.open_table(REVOKED).map_err(db_err)?;
            for k in &dead_revoked {
                revoked.remove(k.as_str()).map_err(db_err)?;
            }
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }
}
