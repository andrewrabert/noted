use std::sync::Arc;

use crate::authority::{Mint, Minter, Revoke, Verified};
use crate::service::{AuthService, MintSummary, UserSummary};
use crate::types::{Label, Owner, Password, Username};
use noted::PolicyFragment;
use noted::error::{Result, rejected};
use noted::types::Ttl;

#[derive(Clone, Debug)]
pub enum AdminCredentialLifetime {
    Default,
    Explicit(Ttl),
}

#[derive(Clone, Debug)]
pub enum MintFilter {
    All,
    Label(Label),
}

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
    RevokeUser {
        username: Username,
    },
    RemoveUser {
        username: Username,
    },
    CreateKey {
        label: Label,
        policy: PolicyFragment,
        lifetime: AdminCredentialLifetime,
    },
    ListKeys {
        filter: MintFilter,
    },
    RevokeKey {
        revocation: Revoke,
    },
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
    Withdrawn(crate::authority::Withdrawn),
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
            AdminCommand::RevokeUser { username } => {
                self.service
                    .user_get(&username)?
                    .ok_or_else(|| rejected(format!("no such user: '{username}'")))?;
                Ok(AdminOutcome::Withdrawn(self.minter.revoke(
                    &Verified::as_owner(Owner::User(username)),
                    &Revoke::All,
                )?))
            }
            AdminCommand::RemoveUser { username } => {
                self.service.user_remove(&username)?;
                Ok(AdminOutcome::Completed)
            }
            AdminCommand::CreateKey {
                label,
                policy,
                lifetime,
            } => {
                let ttl = match lifetime {
                    AdminCredentialLifetime::Default => self.service.default_ttl(),
                    AdminCredentialLifetime::Explicit(ttl) => ttl,
                };
                Ok(AdminOutcome::Minted(self.minter.mint(
                    self.minter.own(),
                    &Mint {
                        policy,
                        ttl,
                        label: Some(label),
                    },
                )?))
            }
            AdminCommand::ListKeys { filter } => {
                let credentials = self
                    .minter
                    .minted(&self.owner()?)?
                    .into_iter()
                    .filter(|mint| match &filter {
                        MintFilter::All => true,
                        MintFilter::Label(label) => mint.label.as_ref() == Some(label),
                    })
                    .collect();
                Ok(AdminOutcome::Credentials(credentials))
            }
            AdminCommand::RevokeKey { revocation } => Ok(AdminOutcome::Withdrawn(
                self.minter.revoke(self.minter.own(), &revocation)?,
            )),
        }
    }
}
