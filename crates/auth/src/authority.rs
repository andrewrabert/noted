use std::fmt;
use std::sync::Arc;

use crate::credential::{Caveat, KeyRecord, Macaroon, MacaroonId};
use crate::db::MintRecord;
use crate::service::{AuthService, MintSummary};
use crate::types::{CredentialPresentation, Fingerprint, Owner};
use noted::PolicyFragment;
use noted::error::{Result, rejected};
use noted::types::UnixEpochSeconds;

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
}

#[derive(Clone, Debug)]
pub struct Minted {
    pub macaroon: Macaroon,
    pub token_id: MacaroonId,
    pub fingerprint: Fingerprint,
}

pub trait Minter: Send + Sync + 'static {
    /// The credential the server mints from for a caller presenting none.
    fn own(&self) -> &Verified;

    /// A descendant of the caller's own credential carrying, in order:
    /// `policy=`, then a fresh `token_id=`.
    fn mint(&self, caller: &Verified, ask: &Mint) -> Result<Minted>;

    fn minted(&self, owner: &Owner) -> Result<Vec<MintSummary>>;
}

/// What an ask puts ahead of the `token_id=` of the mint it asks for.
fn ask_caveats(ask: &Mint) -> Vec<Caveat> {
    vec![Caveat::Policy(ask.policy.clone())]
}

fn mint_caveats(ask: &Mint, token_id: &MacaroonId) -> Vec<Caveat> {
    let mut caveats = ask_caveats(ask);
    caveats.push(Caveat::Token(token_id.clone()));
    caveats
}

fn ledger_record(ask: &Mint, owner: &Owner, minted: &Minted, now: UnixEpochSeconds) -> MintRecord {
    MintRecord {
        owner: owner.clone(),
        policy: ask.policy.clone(),
        fingerprint: minted.fingerprint.clone(),
        created_at: now,
    }
}

fn summary(token_id: MacaroonId, rec: MintRecord) -> MintSummary {
    MintSummary {
        token_id,
        owner: rec.owner,
        policy: rec.policy,
        fingerprint: rec.fingerprint,
        created_at: rec.created_at,
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
        let mut fragments = vec![held];
        for caveat in &caveats {
            if let Caveat::Policy(fragment) = caveat {
                fragments.push(fragment.clone());
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
        let token_id = MacaroonId::fresh();
        let caveats = mint_caveats(ask, &token_id);
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
        };
        self.service
            .db()
            .put_minted(&token_id, &ledger_record(ask, &owner, &minted, now))?;
        Ok(minted)
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

pub struct OpenAuthority;

impl Verifier for OpenAuthority {
    fn verify(
        &self,
        credential: Option<&CredentialPresentation>,
    ) -> std::result::Result<Verified, Denial> {
        match credential {
            Some(_) => Err(Denial::Malformed(
                "this server has no authentication and takes no credential".to_string(),
            )),
            None => Ok(Verified::anonymous()),
        }
    }
}
