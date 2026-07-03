use std::str::FromStr;
use std::sync::Arc;

use oxide_auth::primitives::grant::Grant;
use oxide_auth::primitives::issuer::{IssuedToken, Issuer, RefreshedToken, TokenType};
use oxide_auth::primitives::scope::Scope;

use super::{AuthService, DEFAULT_SCOPE};

pub struct DbIssuer {
    auth: Arc<AuthService>,
}

impl DbIssuer {
    pub fn new(auth: Arc<AuthService>) -> DbIssuer {
        DbIssuer { auth }
    }

    fn rebuild_grant(owner: String, client_id: Option<String>, until: u64) -> Grant {
        Grant {
            owner_id: owner,
            client_id: client_id.unwrap_or_default(),
            scope: Scope::from_str(DEFAULT_SCOPE).expect("static scope parses"),
            redirect_uri: url::Url::parse("http://localhost/").expect("static url parses"),
            until: unix_to_utc(until),
            extensions: Default::default(),
        }
    }
}

fn unix_to_utc(secs: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0).unwrap_or_else(chrono::Utc::now)
}

impl Issuer for DbIssuer {
    fn issue(&mut self, grant: Grant) -> std::result::Result<IssuedToken, ()> {
        let (access, refresh, until) = self
            .auth
            .issue_login_pair(&grant.owner_id, &grant.client_id)
            .map_err(|_| ())?;
        Ok(IssuedToken {
            token: access,
            refresh: Some(refresh),
            until: unix_to_utc(until),
            token_type: TokenType::Bearer,
        })
    }

    fn refresh(&mut self, refresh: &str, grant: Grant) -> std::result::Result<RefreshedToken, ()> {
        let (access, new_refresh, until) = self
            .auth
            .rotate_refresh(refresh, &grant.owner_id, &grant.client_id)
            .map_err(|_| ())?;
        Ok(RefreshedToken {
            token: access,
            refresh: Some(new_refresh),
            until: unix_to_utc(until),
            token_type: TokenType::Bearer,
        })
    }

    fn recover_token(&self, token: &str) -> std::result::Result<Option<Grant>, ()> {
        match self.auth.access_owner(token) {
            Ok(Some((owner, client_id, until))) => {
                Ok(Some(Self::rebuild_grant(owner, client_id, until)))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(()),
        }
    }

    fn recover_refresh(&self, token: &str) -> std::result::Result<Option<Grant>, ()> {
        match self.auth.refresh_owner(token) {
            Ok(Some((owner, client_id, until))) => {
                Ok(Some(Self::rebuild_grant(owner, client_id, until)))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::types::{Password, Username};
    fn un(s: &str) -> Username {
        s.parse().unwrap()
    }
    fn pw(s: &str) -> Password {
        Password::new(s)
    }
    use crate::oauth::service::{ACCESS_TTL, PREFIX_ACC, PREFIX_REF};
    use crate::oauth::Db;

    fn service() -> (tempfile::TempDir, Arc<AuthService>) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
        (
            dir,
            Arc::new(AuthService::new(
                db,
                crate::types::Ttl::from_secs(30 * 24 * 3600),
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
        assert!(issued.token.starts_with(PREFIX_ACC));
        let refresh0 = issued.refresh.clone().unwrap();
        assert!(refresh0.starts_with(PREFIX_REF));
        let ttl = issued.until.timestamp() - chrono::Utc::now().timestamp();
        assert!(
            (ttl - ACCESS_TTL.as_secs() as i64).abs() <= 2,
            "ttl was {ttl}"
        );

        let issuer2 = DbIssuer::new(auth.clone());
        let g = issuer2.recover_token(&issued.token).unwrap().unwrap();
        assert_eq!(g.owner_id, "alice");
        assert_eq!(g.client_id, "client-1");

        let mut issuer3 = DbIssuer::new(auth.clone());
        let rotated = issuer3
            .refresh(&refresh0, grant_for("alice", "client-1"))
            .unwrap();
        assert!(rotated.token.starts_with(PREFIX_ACC));
        assert_ne!(rotated.token, issued.token);
        assert!(issuer3.recover_refresh(&refresh0).unwrap().is_none());
        assert!(issuer3
            .recover_refresh(&rotated.refresh.clone().unwrap())
            .unwrap()
            .is_some());
    }

    #[test]
    fn recovery_dies_with_the_user() {
        let (_dir, auth) = service();
        auth.user_add(&un("bob"), &pw("pw")).unwrap();
        let mut issuer = DbIssuer::new(auth.clone());
        let issued = issuer.issue(grant_for("bob", "c")).unwrap();
        auth.user_remove(&un("bob")).unwrap();
        assert!(issuer.recover_token(&issued.token).unwrap().is_none());
        assert!(issuer
            .recover_refresh(&issued.refresh.unwrap())
            .unwrap()
            .is_none());
    }
}
