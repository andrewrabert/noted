use std::sync::Arc;

use crate::authority::{Mint, Minter};
use crate::service::{AuthService, MintSummary, UserSummary};
use crate::types::{Owner, Password, Username};
use noted::PolicyFragment;
use noted::error::{Result, rejected};

#[derive(Clone, Debug)]
pub enum AdminCommand {
    AddUser {
        username: Username,
        password: Password,
    },
    ReplaceUserPassword {
        username: Username,
        password: Password,
    },
    ReplaceUserPolicy {
        username: Username,
        policy: PolicyFragment,
    },
    ListUsers,
    GetUser {
        username: Username,
    },
    RemoveUser {
        username: Username,
    },
    CreateKey {
        policy: PolicyFragment,
    },
    ListKeys,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UserDetails {
    pub user: UserSummary,
    pub credentials: Vec<MintSummary>,
}

#[derive(Clone, Debug)]
pub enum AdminOutcome {
    Completed,
    Users(Vec<UserSummary>),
    User(UserDetails),
    Minted(crate::authority::Minted),
    Credentials(Vec<MintSummary>),
}

pub struct Administration {
    service: Arc<AuthService>,
    minter: Arc<dyn Minter>,
}

impl Administration {
    pub fn new(service: Arc<AuthService>, minter: Arc<dyn Minter>) -> Administration {
        Administration { service, minter }
    }

    fn owner(&self) -> Result<Owner> {
        self.minter
            .own()
            .owner()
            .cloned()
            .ok_or_else(|| rejected("this server holds no credential of its own"))
    }

    pub fn execute(&self, command: AdminCommand) -> Result<AdminOutcome> {
        match command {
            AdminCommand::AddUser { username, password } => {
                self.service.user_add(&username, &password)?;
                Ok(AdminOutcome::Completed)
            }
            AdminCommand::ReplaceUserPassword { username, password } => {
                self.service.user_passwd(&username, &password)?;
                Ok(AdminOutcome::Completed)
            }
            AdminCommand::ReplaceUserPolicy { username, policy } => {
                self.service.user_set_policy(&username, policy)?;
                Ok(AdminOutcome::Completed)
            }
            AdminCommand::ListUsers => Ok(AdminOutcome::Users(self.service.user_list()?)),
            AdminCommand::GetUser { username } => {
                let user = self
                    .service
                    .user_get(&username)?
                    .ok_or_else(|| rejected(format!("no such user: '{username}'")))?;
                let credentials = self.minter.minted(&Owner::User(username))?;
                Ok(AdminOutcome::User(UserDetails { user, credentials }))
            }
            AdminCommand::RemoveUser { username } => {
                self.service.user_remove(&username)?;
                Ok(AdminOutcome::Completed)
            }
            AdminCommand::CreateKey { policy } => Ok(AdminOutcome::Minted(
                self.minter.mint(self.minter.own(), &Mint { policy })?,
            )),
            AdminCommand::ListKeys => Ok(AdminOutcome::Credentials(
                self.minter.minted(&self.owner()?)?,
            )),
        }
    }
}
