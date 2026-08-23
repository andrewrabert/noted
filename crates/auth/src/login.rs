use std::sync::Arc;

use crate::password::{verify_dummy, verify_password};
use crate::service::AuthService;
use crate::types::{LoginName, Password, Username};
use noted::error::Result;

pub struct LoginAttempt {
    pub name: LoginName,
    pub password: Password,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    Authenticated(Username),
    InvalidCredentials,
}

pub struct LoginAuthenticator {
    service: Arc<AuthService>,
}

impl LoginAuthenticator {
    pub fn new(service: Arc<AuthService>) -> LoginAuthenticator {
        LoginAuthenticator { service }
    }

    pub fn authenticate(&self, attempt: LoginAttempt) -> Result<LoginOutcome> {
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
