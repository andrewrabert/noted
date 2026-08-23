use std::sync::Arc;

use noted::PolicyFragment;
use noted_auth::administration::{AdminCommand, AdminOutcome, Administration};
use noted_auth::authority::OriginAuthority;
use noted_auth::types::{Password, Username};
use noted_auth::{AuthService, Db};

fn fixture() -> (tempfile::TempDir, Administration) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
    let service = Arc::new(AuthService::new(db));
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
    assert!(matches!(
        admin
            .execute(AdminCommand::CreateKey {
                policy: PolicyFragment::default(),
            })
            .unwrap(),
        AdminOutcome::Minted(_)
    ));
    assert!(matches!(
        admin.execute(AdminCommand::ListKeys).unwrap(),
        AdminOutcome::Credentials(_)
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
fn domain_rejections_preserve_existing_messages_and_classification() {
    let (_dir, admin) = fixture();
    let error = admin
        .execute(AdminCommand::RemoveUser {
            username: username(),
        })
        .unwrap_err();
    assert!(error.is_rejection());
    assert_eq!(error.message(), "no such user: 'alice'");
}
