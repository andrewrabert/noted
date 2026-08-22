use std::sync::Arc;

use noted::PolicyFragment;
use noted::types::Ttl;
use noted_auth::administration::{
    AdminCommand, AdminCredentialLifetime, AdminOutcome, Administration, MintFilter,
};
use noted_auth::authority::{OriginAuthority, Revoke};
use noted_auth::credential::MacaroonId;
use noted_auth::types::{Label, Password, Username};
use noted_auth::{AuthService, Db};

fn fixture() -> (tempfile::TempDir, Administration) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
    let service = Arc::new(AuthService::new(db, Ttl::from_secs(3600)));
    let minter = Arc::new(OriginAuthority::new(service.clone()));
    (dir, Administration::new(service, minter))
}

fn username() -> Username {
    Username::new("alice").unwrap()
}

#[test]
fn every_admin_command_returns_its_matching_closed_outcome() {
    let (_dir, admin) = fixture();
    assert!(matches!(
        admin
            .execute(AdminCommand::AddUser {
                username: username(),
                password: Password::new("pw"),
            })
            .unwrap(),
        AdminOutcome::Completed
    ));
    assert!(matches!(
        admin
            .execute(AdminCommand::ReplaceUserPassword {
                username: username(),
                password: Password::new("new"),
            })
            .unwrap(),
        AdminOutcome::Completed
    ));
    assert!(matches!(
        admin
            .execute(AdminCommand::ReplaceUserPolicy {
                username: username(),
                policy: PolicyFragment::default(),
            })
            .unwrap(),
        AdminOutcome::Completed
    ));
    assert!(matches!(
        admin.execute(AdminCommand::ListUsers).unwrap(),
        AdminOutcome::Users(_)
    ));
    assert!(matches!(
        admin
            .execute(AdminCommand::GetUser {
                username: username()
            })
            .unwrap(),
        AdminOutcome::User(_)
    ));
    let minted = admin
        .execute(AdminCommand::CreateKey {
            label: Label::new("agent").unwrap(),
            policy: PolicyFragment::default(),
            lifetime: AdminCredentialLifetime::Default,
        })
        .unwrap();
    let AdminOutcome::Minted(minted) = minted else {
        panic!("minted outcome expected")
    };
    assert!(matches!(
        admin
            .execute(AdminCommand::ListKeys {
                filter: MintFilter::All
            })
            .unwrap(),
        AdminOutcome::Credentials(_)
    ));
    assert!(matches!(
        admin
            .execute(AdminCommand::RevokeKey {
                revocation: Revoke::Token(minted.token_id),
            })
            .unwrap(),
        AdminOutcome::Withdrawn(_)
    ));
    assert!(matches!(
        admin
            .execute(AdminCommand::RevokeUser {
                username: username()
            })
            .unwrap(),
        AdminOutcome::Withdrawn(_)
    ));
    assert!(matches!(
        admin
            .execute(AdminCommand::RemoveUser {
                username: username()
            })
            .unwrap(),
        AdminOutcome::Completed
    ));
}

#[test]
fn user_details_include_live_credentials() {
    let (_dir, admin) = fixture();
    admin
        .execute(AdminCommand::AddUser {
            username: username(),
            password: Password::new("pw"),
        })
        .unwrap();
    let AdminOutcome::User(details) = admin
        .execute(AdminCommand::GetUser {
            username: username(),
        })
        .unwrap()
    else {
        panic!("user outcome expected")
    };
    assert_eq!(details.user.name, username());
    assert!(details.credentials.is_empty());
}

#[test]
fn default_and_explicit_key_lifetimes_preserve_existing_minting() {
    let (_dir, admin) = fixture();
    let default = admin
        .execute(AdminCommand::CreateKey {
            label: Label::new("default").unwrap(),
            policy: PolicyFragment::default(),
            lifetime: AdminCredentialLifetime::Default,
        })
        .unwrap();
    let explicit = admin
        .execute(AdminCommand::CreateKey {
            label: Label::new("short").unwrap(),
            policy: PolicyFragment::default(),
            lifetime: AdminCredentialLifetime::Explicit(Ttl::from_secs(10)),
        })
        .unwrap();
    let (AdminOutcome::Minted(default), AdminOutcome::Minted(explicit)) = (default, explicit)
    else {
        panic!("minted outcomes expected")
    };
    assert!(default.expires_at > explicit.expires_at);
}

#[test]
fn domain_rejections_preserve_existing_messages_and_classification() {
    let (_dir, admin) = fixture();
    let error = admin
        .execute(AdminCommand::RemoveUser {
            username: username(),
        })
        .unwrap_err();
    assert!(error.is_rejection());
    assert_eq!(error.message(), "no such user: 'alice'");

    let error = admin
        .execute(AdminCommand::RevokeKey {
            revocation: Revoke::Token(MacaroonId::new("missing")),
        })
        .unwrap_err();
    assert!(error.is_rejection());
    assert_eq!(error.message(), "this server minted nothing of that name");
}
