use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::credential::{Caveat, KeyRecord, Macaroon, MacaroonId};
use crate::db::MintRecord;
use crate::service::{AuthService, MintSummary};
use crate::types::{CredentialPresentation, Fingerprint, Owner};
use noted::PolicyFragment;
use noted::error::{Result, rejected};
use noted::types::{Ttl, UnixEpochSeconds};

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

    /// A caller known by owner alone: what an administrator acts as.
    pub fn as_owner(owner: Owner) -> Verified {
        Verified {
            owner: Some(owner),
            fragments: Vec::new(),
            caveats: Vec::new(),
            macaroon: None,
        }
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
    fn verify(
        &self,
        credential: Option<&CredentialPresentation>,
    ) -> std::result::Result<Verified, Denial>;
}

pub struct Mint {
    pub policy: PolicyFragment,
    pub ttl: Ttl,
}

#[derive(Clone, Debug)]
pub struct Minted {
    pub macaroon: Macaroon,
    pub token_id: MacaroonId,
    pub fingerprint: Fingerprint,
    pub expires_at: UnixEpochSeconds,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Revoke {
    Token(MacaroonId),
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

    /// The caveat this ask names outright; `All` names none.
    fn caveat(&self) -> Option<Caveat> {
        match self {
            Revoke::Token(id) => Some(Caveat::Token(id.clone())),
            Revoke::All => None,
        }
    }

    /// Whether a ledger row is one this ask names.
    fn names(&self, id: &MacaroonId, _rec: &MintRecord) -> bool {
        match self {
            Revoke::Token(token) => id == token,
            Revoke::All => true,
        }
    }
}

/// What a revocation withdrew.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Withdrawn {
    /// The caveats no credential may carry any more, in ledger order.
    pub revoked: Vec<Caveat>,
}

impl Withdrawn {
    pub(crate) fn sealed(revoked: Vec<Caveat>) -> Result<Withdrawn> {
        if revoked.is_empty() {
            return Err(rejected("this server minted nothing of that name"));
        }
        Ok(Withdrawn { revoked })
    }
}

/// Tombstones every `token_id=` the ask names among `owner`'s ledger rows, with
/// the ask's own caveat beside them, and drops those rows. A ledger that names
/// nothing withdraws nothing.
fn withdraw(service: &AuthService, owner: &Owner, ask: &Revoke) -> Result<Vec<Caveat>> {
    let db = service.db();
    let rows: Vec<MacaroonId> = db
        .all_minted()?
        .into_iter()
        .filter(|(id, rec)| rec.owner == *owner && ask.names(id, rec))
        .map(|(id, _)| id)
        .collect();
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let mut dead: Vec<Caveat> = rows.iter().cloned().map(Caveat::Token).collect();
    if let Some(caveat) = ask.caveat().filter(|c| !dead.contains(c)) {
        dead.push(caveat);
    }
    let until = UnixEpochSeconds::now()? + service.default_ttl();
    db.withdraw(&dead, &rows, until)?;
    Ok(dead)
}

pub trait Minter: Send + Sync + 'static {
    /// The credential the server mints from for a caller presenting none.
    fn own(&self) -> &Verified;

    /// A descendant of the caller's own credential carrying, in order:
    /// `policy=`, a fresh `token_id=`, then `before=`.
    fn mint(&self, caller: &Verified, ask: &Mint) -> Result<Minted>;

    /// Withdraws only what this server records having minted for the caller's
    /// owner; an ask that withdraws nothing is refused.
    fn revoke(&self, caller: &Verified, ask: &Revoke) -> Result<Withdrawn>;

    fn minted(&self, owner: &Owner) -> Result<Vec<MintSummary>>;
}

/// What an ask puts ahead of the `token_id=` and `before=` of the mint it asks for.
fn ask_caveats(ask: &Mint) -> Vec<Caveat> {
    let caveats = vec![Caveat::Policy(ask.policy.clone())];
    caveats
}

fn mint_caveats(ask: &Mint, expires_at: UnixEpochSeconds, token_id: &MacaroonId) -> Vec<Caveat> {
    let mut caveats = ask_caveats(ask);
    caveats.push(Caveat::Token(token_id.clone()));
    caveats.push(Caveat::Before(expires_at));
    caveats
}

fn ledger_record(ask: &Mint, owner: &Owner, minted: &Minted, now: UnixEpochSeconds) -> MintRecord {
    MintRecord {
        owner: owner.clone(),
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
            Owner::Server => Ok(self.service.db().server_key()?.1),
        }
    }

    fn held_policy(&self, owner: &Owner) -> Result<Option<PolicyFragment>> {
        match owner {
            Owner::User(name) => Ok(self.service.db().user(name)?.map(|rec| rec.policy)),
            Owner::Server => Ok(Some(PolicyFragment::default())),
        }
    }
}

fn own_credential(service: &AuthService) -> Result<Verified> {
    let (owner, key) = service.db().server_key()?;
    let macaroon = Macaroon::mint(&owner, &key, &[])?;
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
    fn verify(
        &self,
        credential: Option<&CredentialPresentation>,
    ) -> std::result::Result<Verified, Denial> {
        let Some(credential) = credential else {
            return Ok(Verified::anonymous());
        };
        let bearer = credential.expose();
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
                Caveat::Before(deadline) if now >= *deadline => {
                    return unauthorized("credential expired");
                }
                Caveat::Policy(fragment) => fragments.push(fragment.clone()),
                Caveat::Token(_) if self.service.db().is_revoked(caveat).unwrap_or(true) => {
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
                Macaroon::mint(&owner, &key, &caveats)?
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

    fn revoke(&self, caller: &Verified, ask: &Revoke) -> Result<Withdrawn> {
        let owner = caller
            .owner()
            .or_else(|| self.own.owner())
            .ok_or_else(|| rejected("this server holds no credential to revoke under"))?
            .clone();
        let dead = withdraw(&self.service, &owner, ask)?;
        if let Revoke::All = ask {
            self.root_of(&owner)?;
            self.service.db().remove_refresh_of(&owner)?;
            return Ok(Withdrawn { revoked: dead });
        }
        Withdrawn::sealed(dead)
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
    fn verify(
        &self,
        credential: Option<&CredentialPresentation>,
    ) -> std::result::Result<Verified, Denial> {
        let Some(credential) = credential else {
            return Ok(Verified::anonymous());
        };
        let bearer = credential.expose();
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
    confined: Macaroon,
    ledger: Option<Arc<AuthService>>,
}

impl RelayCredential {
    /// `bearer`, else a bare root self-minted under `self`: the key comes from
    /// `ledger` when there is one and is fresh per process otherwise.
    pub fn open(
        credential: Option<&CredentialPresentation>,
        policy: PolicyFragment,
        ledger: Option<Arc<AuthService>>,
    ) -> Result<RelayCredential> {
        let held = match credential {
            Some(credential) => Macaroon::from_encoded(credential.expose().to_string())?,
            None => match &ledger {
                Some(service) => {
                    let (owner, key) = service.db().server_key()?;
                    Macaroon::mint(&owner, &key, &[])?
                }
                None => Macaroon::ephemeral()?,
            },
        };
        let confined = held.extended(&[Caveat::Policy(policy.clone())])?;
        let own = Verified {
            owner: Some(confined.owner()?),
            fragments: vec![policy],
            caveats: Vec::new(),
            macaroon: Some(confined.clone()),
        };
        Ok(RelayCredential {
            own,
            confined,
            ledger,
        })
    }

    /// The confined credential extended by `caller`'s caveats, a fresh
    /// `token_id=`, then `before=` sixty seconds ahead.
    pub fn remint(&self, caller: &Verified) -> Result<Minted> {
        self.descend(caller, &[], RELAY_TTL)
    }

    /// The confined credential extended by `caller`'s caveats in their original
    /// order, then `tail`, then a fresh `token_id=` and `before=` at `ttl`.
    fn descend(&self, caller: &Verified, tail: &[Caveat], ttl: Ttl) -> Result<Minted> {
        let expires_at = UnixEpochSeconds::now()? + ttl;
        let token_id = MacaroonId::fresh();
        let mut caveats = caller.caveats().to_vec();
        caveats.extend(tail.iter().cloned());
        caveats.push(Caveat::Token(token_id.clone()));
        caveats.push(Caveat::Before(expires_at));
        let macaroon = self.confined.extended(&caveats)?;
        Ok(Minted {
            fingerprint: macaroon.fingerprint(),
            macaroon,
            token_id,
            expires_at,
        })
    }

    fn is_revoked(&self, caveat: &Caveat) -> bool {
        match &self.ledger {
            Some(service) => service.db().is_revoked(caveat).unwrap_or(true),
            None => false,
        }
    }
}

impl Verifier for RelayCredential {
    fn verify(
        &self,
        credential: Option<&CredentialPresentation>,
    ) -> std::result::Result<Verified, Denial> {
        let Some(credential) = credential else {
            return Ok(self.own.clone());
        };
        let bearer = credential.expose();
        Macaroon::from_encoded(bearer.to_string()).map_err(|e| Denial::Malformed(e.to_string()))?;
        let macaroon = self.confined.from_descendant(bearer).map_err(|_| {
            Denial::Forbidden("that credential is no descendant of this relay's".into())
        })?;
        let caveats = macaroon
            .beyond(&self.confined)
            .map_err(|e| Denial::Malformed(e.to_string()))?;
        let Ok(now) = UnixEpochSeconds::now() else {
            return unauthorized("unauthorized");
        };
        let mut fragments = self.own.fragments().to_vec();
        for caveat in &caveats {
            match caveat {
                Caveat::Before(deadline) if now >= *deadline => {
                    return unauthorized("credential expired");
                }
                Caveat::Policy(fragment) => fragments.push(fragment.clone()),
                Caveat::Token(_) if self.is_revoked(caveat) => {
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
        let minted = self.descend(caller, &ask_caveats(ask), ask.ttl)?;
        if let Some(service) = &self.ledger {
            let owner = caller
                .owner()
                .or_else(|| self.own.owner())
                .ok_or_else(|| rejected("this relay holds no credential to mint from"))?
                .clone();
            service
                .db()
                .put_minted(&minted.token_id, &ledger_record(ask, &owner, &minted, now))?;
        }
        Ok(minted)
    }

    fn revoke(&self, caller: &Verified, ask: &Revoke) -> Result<Withdrawn> {
        let service = self
            .ledger
            .as_ref()
            .ok_or_else(|| rejected("this relay records nothing it mints"))?;
        let owner = caller
            .owner()
            .or_else(|| self.own.owner())
            .ok_or_else(|| rejected("this relay holds no credential to revoke under"))?
            .clone();
        Withdrawn::sealed(withdraw(service, &owner, ask)?)
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
