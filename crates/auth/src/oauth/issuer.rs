use std::str::FromStr;
use std::sync::Arc;

use oxide_auth::primitives::grant::Grant;
use oxide_auth::primitives::issuer::{IssuedToken, Issuer, RefreshedToken, TokenType};
use oxide_auth::primitives::scope::Scope;

use super::DEFAULT_SCOPE;
use crate::db::RefreshRecord;
use crate::service::{AuthService, Login};
use crate::types::{ClientId, Owner, Username};
use noted::error::Result;

pub struct DbIssuer {
    auth: Arc<AuthService>,
}

impl DbIssuer {
    pub fn new(auth: Arc<AuthService>) -> DbIssuer {
        DbIssuer { auth }
    }

    fn rebuild_grant(rec: &RefreshRecord) -> Grant {
        let owner = match &rec.owner {
            Owner::User(name) => name.as_str().to_string(),
            Owner::Server(id) => id.as_str().to_string(),
        };
        Grant {
            owner_id: owner,
            client_id: rec.client_id.as_str().to_string(),
            scope: Scope::from_str(DEFAULT_SCOPE).expect("static scope parses"),
            redirect_uri: url::Url::parse("http://localhost/").expect("static url parses"),
            until: unix_to_utc(rec.expires_at.as_secs()),
            extensions: Default::default(),
        }
    }

    fn issued(login: Login) -> IssuedToken {
        IssuedToken {
            token: login.access.expose().to_string(),
            refresh: Some(login.refresh.expose().to_string()),
            until: unix_to_utc(login.expires_at.as_secs()),
            token_type: TokenType::Bearer,
        }
    }

    fn grant_parts(grant: &Grant) -> Result<(Username, ClientId)> {
        Ok((
            grant.owner_id.parse::<Username>()?,
            ClientId::new(grant.client_id.clone()),
        ))
    }
}

fn unix_to_utc(secs: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0).unwrap_or_else(chrono::Utc::now)
}

impl Issuer for DbIssuer {
    fn issue(&mut self, grant: Grant) -> std::result::Result<IssuedToken, ()> {
        let (name, client) = Self::grant_parts(&grant).map_err(|_| ())?;
        let login = self.auth.issue_login(&name, &client).map_err(|_| ())?;
        Ok(Self::issued(login))
    }

    fn refresh(&mut self, refresh: &str, grant: Grant) -> std::result::Result<RefreshedToken, ()> {
        let (name, client) = Self::grant_parts(&grant).map_err(|_| ())?;
        let login = self
            .auth
            .rotate_login(refresh, &name, &client)
            .map_err(|_| ())?;
        let issued = Self::issued(login);
        Ok(RefreshedToken {
            token: issued.token,
            refresh: issued.refresh,
            until: issued.until,
            token_type: issued.token_type,
        })
    }

    /// A macaroon is recovered by the verifier, never by the issuer.
    fn recover_token(&self, _token: &str) -> std::result::Result<Option<Grant>, ()> {
        Ok(None)
    }

    fn recover_refresh(&self, token: &str) -> std::result::Result<Option<Grant>, ()> {
        match self.auth.refresh_owner(token) {
            Ok(Some(rec)) => Ok(Some(Self::rebuild_grant(&rec))),
            Ok(None) => Ok(None),
            Err(_) => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::service::{ACCESS_TTL, PREFIX_MAC, PREFIX_REF};
    use crate::types::{Password, Username};

    fn un(s: &str) -> Username {
        s.parse().unwrap()
    }
    fn pw(s: &str) -> Password {
        Password::new(s)
    }

    fn service() -> (tempfile::TempDir, Arc<AuthService>) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
        (
            dir,
            Arc::new(AuthService::new(
                db,
                noted::types::Ttl::from_secs(30 * 24 * 3600),
            )),
        )
    }

    fn grant_for(owner: &str, client: &str) -> Grant {
        Grant {
            owner_id: owner.to_string(),
            client_id: client.to_string(),
            scope: Scope::from_str(DEFAULT_SCOPE).unwrap(),
            redirect_uri: url::Url::parse("http://localhost/cb").unwrap(),
            until: chrono::Utc::now(),
            extensions: Default::default(),
        }
    }

    #[test]
    fn db_issuer_issues_recovers_and_rotates() {
        let (_dir, auth) = service();
        auth.user_add(&un("alice"), &pw("pw")).unwrap();
        let mut issuer = DbIssuer::new(auth.clone());

        let issued = issuer.issue(grant_for("alice", "client-1")).unwrap();
        assert!(issued.token.starts_with(PREFIX_MAC));
        let refresh0 = issued.refresh.clone().unwrap();
        assert!(refresh0.starts_with(PREFIX_REF));
        let ttl = issued.until.timestamp() - chrono::Utc::now().timestamp();
        assert!(
            (ttl - ACCESS_TTL.as_secs() as i64).abs() <= 2,
            "ttl was {ttl}"
        );

        // an access macaroon is the verifier's business, not the issuer's
        let issuer2 = DbIssuer::new(auth.clone());
        assert!(issuer2.recover_token(&issued.token).unwrap().is_none());
        let g = issuer2.recover_refresh(&refresh0).unwrap().unwrap();
        assert_eq!(g.owner_id, "alice");
        assert_eq!(g.client_id, "client-1");

        let mut issuer3 = DbIssuer::new(auth.clone());
        let rotated = issuer3
            .refresh(&refresh0, grant_for("alice", "client-1"))
            .unwrap();
        assert!(rotated.token.starts_with(PREFIX_MAC));
        // the access macaroon is a pure function of owner, epoch, session and
        // expiry, so only the refresh is guaranteed to differ
        assert_ne!(rotated.refresh, issued.refresh);
        assert!(issuer3.recover_refresh(&refresh0).unwrap().is_none());
        assert!(
            issuer3
                .recover_refresh(&rotated.refresh.clone().unwrap())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn recovery_dies_with_the_user() {
        let (_dir, auth) = service();
        auth.user_add(&un("bob"), &pw("pw")).unwrap();
        let mut issuer = DbIssuer::new(auth.clone());
        let issued = issuer.issue(grant_for("bob", "c")).unwrap();
        auth.user_remove(&un("bob")).unwrap();
        assert!(
            issuer
                .recover_refresh(&issued.refresh.unwrap())
                .unwrap()
                .is_none()
        );
    }
}
