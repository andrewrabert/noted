use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::credential::{Caveat, KeyRecord, Macaroon, MacaroonId};
use crate::db::MintRecord;
use crate::service::{AuthService, MintSummary};
use crate::types::{Fingerprint, Label, Owner, SessionId};
use noted::error::{Result, rejected};
use noted::types::{Ttl, UnixEpochSeconds};
use noted::{Bearer, PolicyFragment};

/// Sixty seconds is all a re-minted hop credential needs: it is spent on the
/// one request that produced it.
const RELAY_TTL: Ttl = Ttl::from_secs(60);

/// What a server knows about the caller once the bearer has been read.
#[derive(Clone, Debug)]
pub struct Verified {
    owner: Option<Owner>,
    fragments: Vec<PolicyFragment>,
    caveats: Vec<Caveat>,
    macaroon: Option<Macaroon>,
}

impl Verified {
    /// No bearer at all: whatever the server admits on its own policy.
    pub fn anonymous() -> Verified {
        Verified {
            owner: None,
            fragments: Vec::new(),
            caveats: Vec::new(),
            macaroon: None,
        }
    }

    pub fn owner(&self) -> Option<&Owner> {
        self.owner.as_ref()
    }

    /// The policy the credential carries, outermost first.
    pub fn fragments(&self) -> &[PolicyFragment] {
        &self.fragments
    }

    /// The caveats to replay onto a re-mint, in order.
    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    pub fn macaroon(&self) -> Option<&Macaroon> {
        self.macaroon.as_ref()
    }
}

#[derive(Clone, Debug)]
pub enum Denial {
    /// The bearer is not a parseable macaroon.
    Malformed(String),
    Unauthorized(String),
    Forbidden(String),
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denial::Malformed(m) | Denial::Unauthorized(m) | Denial::Forbidden(m) => f.write_str(m),
        }
    }
}

pub trait Verifier: Send + Sync + 'static {
    fn verify(&self, bearer: Option<&str>) -> std::result::Result<Verified, Denial>;
}

pub struct Mint {
    pub policy: PolicyFragment,
    pub ttl: Ttl,
    pub session: Option<SessionId>,
    pub label: Option<Label>,
}

pub struct Minted {
    pub macaroon: Macaroon,
    pub token_id: MacaroonId,
    pub fingerprint: Fingerprint,
    pub expires_at: UnixEpochSeconds,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Revoke {
    Label(Label),
    Token(MacaroonId),
    Session(SessionId),
    All,
}

impl Revoke {
    /// The last `token_id=` a bearer carries.
    pub fn from_bearer(bearer: &str) -> Result<Revoke> {
        Macaroon::from_encoded(bearer.to_string())?
            .caveats()?
            .into_iter()
            .rev()
            .find_map(|c| match c {
                Caveat::Token(id) => Some(Revoke::Token(id)),
                _ => None,
            })
            .ok_or_else(|| rejected("that credential carries no token id"))
    }
}

pub trait Minter: Send + Sync + 'static {
    /// The credential the server mints from for a caller presenting none.
    fn own(&self) -> &Verified;

    /// A descendant of the caller's own credential carrying, in order:
    /// `policy=`, `session_id=` when asked, a fresh `token_id=`, then `before=`.
    fn mint(&self, caller: &Verified, ask: &Mint) -> Result<Minted>;

    /// Withdraws only what this server minted for the caller's owner.
    fn revoke(&self, caller: &Verified, ask: &Revoke) -> Result<usize>;

    fn minted(&self, owner: &Owner) -> Result<Vec<MintSummary>>;
}

fn mint_caveats(ask: &Mint, expires_at: UnixEpochSeconds, token_id: &MacaroonId) -> Vec<Caveat> {
    let mut caveats = vec![Caveat::Policy(ask.policy.clone())];
    if let Some(session) = &ask.session {
        caveats.push(Caveat::Session(session.clone()));
    }
    caveats.push(Caveat::Token(token_id.clone()));
    caveats.push(Caveat::Before(expires_at));
    caveats
}

fn ledger_record(ask: &Mint, owner: &Owner, minted: &Minted, now: UnixEpochSeconds) -> MintRecord {
    MintRecord {
        owner: owner.clone(),
        label: ask.label.clone(),
        policy: ask.policy.clone(),
        fingerprint: minted.fingerprint.clone(),
        created_at: now,
        expires_at: minted.expires_at,
    }
}

fn summary(token_id: MacaroonId, rec: MintRecord) -> MintSummary {
    MintSummary {
        token_id,
        owner: rec.owner,
        label: rec.label,
        policy: rec.policy,
        fingerprint: rec.fingerprint,
        created_at: rec.created_at,
        expires_at: rec.expires_at,
    }
}

pub struct OriginAuthority {
    service: Arc<AuthService>,
    own: Verified,
}

impl OriginAuthority {
    pub fn new(service: Arc<AuthService>) -> OriginAuthority {
        let own = match own_credential(&service) {
            Ok(own) => own,
            Err(e) => {
                tracing::error!(error = %e, "the server could not read its own credential");
                Verified::anonymous()
            }
        };
        OriginAuthority { service, own }
    }

    fn root_of(&self, owner: &Owner) -> Result<KeyRecord> {
        match owner {
            Owner::User(name) => self.service.user_root(name),
            Owner::Server(_) => Ok(self.service.db().server_key()?.1),
        }
    }

    fn held_policy(&self, owner: &Owner) -> Result<Option<PolicyFragment>> {
        match owner {
            Owner::User(name) => Ok(self.service.db().user(name)?.map(|rec| rec.policy)),
            Owner::Server(_) => Ok(Some(PolicyFragment::default())),
        }
    }
}

fn own_credential(service: &AuthService) -> Result<Verified> {
    let (owner, key) = service.db().server_key()?;
    let macaroon = Macaroon::mint(&owner, &key, &[Caveat::Epoch(key.min_epoch)])?;
    Ok(Verified {
        owner: Some(owner),
        fragments: vec![PolicyFragment::default()],
        caveats: macaroon.caveats()?,
        macaroon: Some(macaroon),
    })
}

fn unauthorized<T>(message: impl Into<String>) -> std::result::Result<T, Denial> {
    Err(Denial::Unauthorized(message.into()))
}

impl Verifier for OriginAuthority {
    fn verify(&self, bearer: Option<&str>) -> std::result::Result<Verified, Denial> {
        let Some(bearer) = bearer else {
            return Ok(Verified::anonymous());
        };
        let macaroon = Macaroon::from_encoded(bearer.to_string())
            .map_err(|e| Denial::Malformed(e.to_string()))?;
        let owner = macaroon
            .owner()
            .map_err(|e| Denial::Malformed(e.to_string()))?;
        let Ok(Some(key)) = self.service.db().root(&owner) else {
            return unauthorized("unauthorized");
        };
        if macaroon.verify_signature(&key.secret).is_err() {
            return unauthorized("unauthorized");
        }
        let Ok(Some(held)) = self.held_policy(&owner) else {
            return unauthorized("unauthorized");
        };
        let Ok(caveats) = macaroon.caveats() else {
            return Err(Denial::Malformed("invalid macaroon caveat".to_string()));
        };
        let Ok(now) = UnixEpochSeconds::now() else {
            return unauthorized("unauthorized");
        };
        let mut fragments = vec![held];
        for caveat in &caveats {
            match caveat {
                Caveat::Epoch(epoch) if !key.min_epoch.accepts(*epoch) => {
                    return unauthorized("credential revoked");
                }
                Caveat::Before(deadline) if now >= *deadline => {
                    return unauthorized("credential expired");
                }
                Caveat::Policy(fragment) => fragments.push(fragment.clone()),
                Caveat::Token(id) if self.service.db().is_revoked(id.as_str()).unwrap_or(true) => {
                    return unauthorized("credential revoked");
                }
                Caveat::Session(id)
                    if self.service.db().is_revoked(id.as_str()).unwrap_or(true) =>
                {
                    return unauthorized("credential revoked");
                }
                _ => {}
            }
        }
        Ok(Verified {
            owner: Some(owner),
            fragments,
            caveats,
            macaroon: Some(macaroon),
        })
    }
}

impl Minter for OriginAuthority {
    fn own(&self) -> &Verified {
        &self.own
    }

    fn mint(&self, caller: &Verified, ask: &Mint) -> Result<Minted> {
        let owner = caller
            .owner()
            .or_else(|| self.own.owner())
            .ok_or_else(|| rejected("this server holds no credential to mint from"))?
            .clone();
        let now = UnixEpochSeconds::now()?;
        let expires_at = now + ask.ttl;
        let token_id = MacaroonId::fresh();
        let caveats = mint_caveats(ask, expires_at, &token_id);
        let macaroon = match caller.macaroon().or_else(|| self.own.macaroon()) {
            Some(held) => held.extended(&caveats)?,
            None => {
                let key = self.root_of(&owner)?;
                let mut rooted = vec![Caveat::Epoch(key.min_epoch)];
                rooted.extend(caveats);
                Macaroon::mint(&owner, &key, &rooted)?
            }
        };
        let minted = Minted {
            fingerprint: macaroon.fingerprint(),
            macaroon,
            token_id: token_id.clone(),
            expires_at,
        };
        self.service
            .db()
            .put_minted(&token_id, &ledger_record(ask, &owner, &minted, now))?;
        Ok(minted)
    }

    fn revoke(&self, caller: &Verified, ask: &Revoke) -> Result<usize> {
        let owner = caller
            .owner()
            .or_else(|| self.own.owner())
            .ok_or_else(|| rejected("this server holds no credential to revoke under"))?
            .clone();
        let db = self.service.db();
        if let Revoke::All = ask {
            db.bump_root_epoch(&owner)?;
            return Ok(1);
        }
        let until = UnixEpochSeconds::now()? + self.service.default_ttl();
        if let Revoke::Session(session) = ask {
            db.revoke_id(session.as_str(), until)?;
            return Ok(1);
        }
        let mut n = 0;
        for (id, rec) in db.all_minted()? {
            let hit = match ask {
                Revoke::Token(token) => id == *token,
                Revoke::Label(label) => rec.label.as_ref() == Some(label),
                Revoke::Session(_) | Revoke::All => false,
            };
            if hit && rec.owner == owner {
                db.revoke_id(id.as_str(), until)?;
                db.remove_minted(&id)?;
                n += 1;
            }
        }
        if n == 0 {
            return Err(rejected("no such credential"));
        }
        Ok(n)
    }

    fn minted(&self, owner: &Owner) -> Result<Vec<MintSummary>> {
        Ok(self
            .service
            .db()
            .all_minted()?
            .into_iter()
            .filter(|(_, rec)| rec.owner == *owner)
            .map(|(id, rec)| summary(id, rec))
            .collect())
    }
}

/// A server with no auth database: it reads what a credential says and holds
/// nobody to account for it.
pub struct OpenAuthority;

impl Verifier for OpenAuthority {
    fn verify(&self, bearer: Option<&str>) -> std::result::Result<Verified, Denial> {
        let Some(bearer) = bearer else {
            return Ok(Verified::anonymous());
        };
        let macaroon = Macaroon::from_encoded(bearer.to_string())
            .map_err(|e| Denial::Malformed(e.to_string()))?;
        let owner = macaroon
            .owner()
            .map_err(|e| Denial::Malformed(e.to_string()))?;
        let caveats = macaroon
            .caveats()
            .map_err(|e| Denial::Malformed(e.to_string()))?;
        let Ok(now) = UnixEpochSeconds::now() else {
            return unauthorized("unauthorized");
        };
        let mut fragments = Vec::new();
        for caveat in &caveats {
            match caveat {
                Caveat::Before(deadline) if now >= *deadline => {
                    return unauthorized("credential expired");
                }
                Caveat::Policy(fragment) => fragments.push(fragment.clone()),
                _ => {}
            }
        }
        Ok(Verified {
            owner: Some(owner),
            fragments,
            caveats,
            macaroon: Some(macaroon),
        })
    }
}

/// The credential a relay holds and every credential it hands its upstream.
pub struct RelayCredential {
    own: Verified,
    root: Macaroon,
    policy: PolicyFragment,
    ledger: Option<Arc<AuthService>>,
    at: String,
}

impl RelayCredential {
    /// `bearer`, else a bare root self-minted under `self:<random>`: the key
    /// comes from `ledger` when there is one and is fresh per process otherwise.
    pub fn open(
        bearer: Option<&Bearer>,
        policy: PolicyFragment,
        ledger: Option<Arc<AuthService>>,
        at: String,
    ) -> Result<RelayCredential> {
        let root = match bearer {
            Some(bearer) => Macaroon::from_encoded(bearer.expose().to_string())
                .map_err(|e| rejected(format!("{at}: {e}")))?,
            None => match &ledger {
                Some(service) => {
                    let (owner, key) = service.db().server_key()?;
                    Macaroon::mint(&owner, &key, &[Caveat::Epoch(key.min_epoch)])?
                }
                None => Macaroon::ephemeral()?,
            },
        };
        let own = Verified {
            owner: Some(root.owner()?),
            fragments: vec![policy.clone()],
            caveats: Vec::new(),
            macaroon: Some(root.clone()),
        };
        Ok(RelayCredential {
            own,
            root,
            policy,
            ledger,
            at,
        })
    }

    /// The relay's own credential extended by, in order: the relay's policy
    /// fragment, `caller`'s caveats in their original order, a fresh
    /// `token_id=`, then `before=` sixty seconds ahead.
    pub fn remint(&self, caller: &Verified) -> Result<Minted> {
        let expires_at = UnixEpochSeconds::now()? + RELAY_TTL;
        let token_id = MacaroonId::fresh();
        let mut caveats = vec![Caveat::Policy(self.policy.clone())];
        caveats.extend(caller.caveats().iter().cloned());
        caveats.push(Caveat::Token(token_id.clone()));
        caveats.push(Caveat::Before(expires_at));
        let macaroon = self.root.extended(&caveats)?;
        Ok(Minted {
            fingerprint: macaroon.fingerprint(),
            macaroon,
            token_id,
            expires_at,
        })
    }

    pub fn at(&self) -> &str {
        &self.at
    }

    fn is_revoked(&self, id: &str) -> bool {
        match &self.ledger {
            Some(service) => service.db().is_revoked(id).unwrap_or(true),
            None => false,
        }
    }
}

impl Verifier for RelayCredential {
    fn verify(&self, bearer: Option<&str>) -> std::result::Result<Verified, Denial> {
        let Some(bearer) = bearer else {
            return Ok(self.own.clone());
        };
        Macaroon::from_encoded(bearer.to_string()).map_err(|e| Denial::Malformed(e.to_string()))?;
        let macaroon = self.root.from_descendant(bearer).map_err(|_| {
            Denial::Forbidden("that credential is no descendant of this relay's".into())
        })?;
        let caveats = macaroon
            .beyond(&self.root)
            .map_err(|e| Denial::Malformed(e.to_string()))?;
        let Ok(now) = UnixEpochSeconds::now() else {
            return unauthorized("unauthorized");
        };
        let mut fragments = vec![self.policy.clone()];
        for caveat in &caveats {
            match caveat {
                Caveat::Before(deadline) if now >= *deadline => {
                    return unauthorized("credential expired");
                }
                Caveat::Policy(fragment) => fragments.push(fragment.clone()),
                Caveat::Token(id) if self.is_revoked(id.as_str()) => {
                    return unauthorized("credential revoked");
                }
                Caveat::Session(id) if self.is_revoked(id.as_str()) => {
                    return unauthorized("credential revoked");
                }
                _ => {}
            }
        }
        Ok(Verified {
            owner: macaroon.owner().ok(),
            fragments,
            caveats,
            macaroon: Some(macaroon),
        })
    }
}

impl Minter for RelayCredential {
    fn own(&self) -> &Verified {
        &self.own
    }

    fn mint(&self, caller: &Verified, ask: &Mint) -> Result<Minted> {
        let now = UnixEpochSeconds::now()?;
        let expires_at = now + ask.ttl;
        let token_id = MacaroonId::fresh();
        let mut caveats = vec![Caveat::Policy(self.policy.clone())];
        caveats.extend(caller.caveats().iter().cloned());
        caveats.extend(mint_caveats(ask, expires_at, &token_id));
        let macaroon = self.root.extended(&caveats)?;
        let minted = Minted {
            fingerprint: macaroon.fingerprint(),
            macaroon,
            token_id: token_id.clone(),
            expires_at,
        };
        if let Some(service) = &self.ledger {
            let owner = caller
                .owner()
                .or_else(|| self.own.owner())
                .ok_or_else(|| rejected("this relay holds no credential to mint from"))?
                .clone();
            service
                .db()
                .put_minted(&token_id, &ledger_record(ask, &owner, &minted, now))?;
        }
        Ok(minted)
    }

    fn revoke(&self, _caller: &Verified, ask: &Revoke) -> Result<usize> {
        let service = self
            .ledger
            .as_ref()
            .ok_or_else(|| rejected("this relay holds no ledger to revoke from"))?;
        let db = service.db();
        let until = UnixEpochSeconds::now()? + service.default_ttl();
        match ask {
            Revoke::Token(id) => {
                db.revoke_id(id.as_str(), until)?;
                db.remove_minted(id)?;
                Ok(1)
            }
            Revoke::Session(id) => {
                db.revoke_id(id.as_str(), until)?;
                Ok(1)
            }
            Revoke::Label(label) => {
                let mut n = 0;
                for (id, rec) in db.all_minted()? {
                    if rec.label.as_ref() == Some(label) {
                        db.revoke_id(id.as_str(), until)?;
                        db.remove_minted(&id)?;
                        n += 1;
                    }
                }
                if n == 0 {
                    return Err(rejected("no such credential"));
                }
                Ok(n)
            }
            Revoke::All => Err(rejected("a relay holds no epoch to bump")),
        }
    }

    fn minted(&self, owner: &Owner) -> Result<Vec<MintSummary>> {
        let Some(service) = &self.ledger else {
            return Ok(Vec::new());
        };
        Ok(service
            .db()
            .all_minted()?
            .into_iter()
            .filter(|(_, rec)| rec.owner == *owner)
            .map(|(id, rec)| summary(id, rec))
            .collect())
    }
}
