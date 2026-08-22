use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

use crate::password::{verify_dummy, verify_password};
use crate::service::AuthService;
use crate::types::{LoginName, LoginSource, Password, Username};
use noted::error::Result;

pub struct LoginAttempt {
    pub name: LoginName,
    pub password: Password,
    pub source: LoginSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    Authenticated(Username),
    InvalidCredentials,
    Throttled,
}

type LoginKey = (LoginName, LoginSource);
type LoginRateLimiter = RateLimiter<LoginKey, DefaultKeyedStateStore<LoginKey>, DefaultClock>;

pub struct LoginAuthenticator {
    service: Arc<AuthService>,
    limiter: LoginRateLimiter,
}

impl LoginAuthenticator {
    pub fn new(service: Arc<AuthService>) -> LoginAuthenticator {
        let quota = Quota::with_period(Duration::from_secs(60))
            .expect("non-zero period")
            .allow_burst(NonZeroU32::new(5).expect("non-zero burst"));
        LoginAuthenticator {
            service,
            limiter: RateLimiter::keyed(quota),
        }
    }

    pub fn authenticate(&self, attempt: LoginAttempt) -> Result<LoginOutcome> {
        let key = (attempt.name.clone(), attempt.source);
        if self.limiter.check_key(&key).is_err() {
            return Ok(LoginOutcome::Throttled);
        }

        let candidate = attempt.name.candidate_username();
        let record = match &candidate {
            Ok(name) => self.service.db().user(name)?,
            Err(_) => None,
        };
        let valid = match record {
            Some(user) => verify_password(attempt.password.expose(), user.password_hash.as_str()),
            None => {
                verify_dummy();
                false
            }
        };
        match (candidate, valid) {
            (Ok(name), true) => Ok(LoginOutcome::Authenticated(name)),
            _ => Ok(LoginOutcome::InvalidCredentials),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::types::LoginSourceId;
    use noted::types::Ttl;

    #[test]
    fn non_tcp_sources_partition_one_submitted_username_quota() {
        let directory = tempfile::tempdir().unwrap();
        let service = Arc::new(AuthService::new(
            Arc::new(Db::open(&directory.path().join("auth.redb")).unwrap()),
            Ttl::from_secs(3600),
        ));
        let authenticator = LoginAuthenticator::new(service);
        let name = LoginName::submitted("alice");
        let first = LoginSource::NonTcpAdapter(LoginSourceId::new("gateway-a"));
        let second = LoginSource::NonTcpAdapter(LoginSourceId::new("gateway-b"));

        for _ in 0..5 {
            assert!(
                authenticator
                    .limiter
                    .check_key(&(name.clone(), first.clone()))
                    .is_ok()
            );
        }
        assert!(
            authenticator
                .limiter
                .check_key(&(name.clone(), first))
                .is_err()
        );
        for _ in 0..5 {
            assert!(
                authenticator
                    .limiter
                    .check_key(&(name.clone(), second.clone()))
                    .is_ok()
            );
        }
        assert!(authenticator.limiter.check_key(&(name, second)).is_err());
    }
}
