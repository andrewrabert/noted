use std::sync::Arc;

use noted::PolicyFragment;
use noted_auth::Db;
use noted_auth::authority::{Denial, OpenAuthority, OriginAuthority, Verifier};
use noted_auth::credential::{Caveat, KeyRecord, Macaroon, MacaroonId};
use noted_auth::service::AuthService;
use noted_auth::types::{ClientId, CredentialPresentation, Owner};

fn fragment(text: &str) -> PolicyFragment {
    text.parse().unwrap()
}

fn owner() -> Owner {
    Owner::user("alice").unwrap()
}

#[test]
fn a_minted_credential_carries_its_caveats_in_mint_order() {
    let caveats = vec![
        Caveat::Policy(fragment(r#"{"scope":"/dev"}"#)),
        Caveat::Token(MacaroonId::fresh()),
    ];
    let macaroon = Macaroon::mint(&owner(), &KeyRecord::fresh(), &caveats).unwrap();
    assert_eq!(macaroon.caveats().unwrap(), caveats);
    assert_eq!(macaroon.owner().unwrap(), owner());
}

#[test]
fn an_open_authority_takes_no_credential_at_all() {
    let live = Macaroon::mint(
        &owner(),
        &KeyRecord::fresh(),
        &[
            Caveat::Policy(fragment(r#"{"scope":"/dev"}"#)),
            Caveat::Token(MacaroonId::new("minted-elsewhere")),
        ],
    )
    .unwrap();
    let denial = OpenAuthority
        .verify(Some(&CredentialPresentation::submitted(live.expose())))
        .unwrap_err();
    assert!(
        matches!(&denial, Denial::Malformed(message) if message.contains("takes no credential")),
        "{denial:?}"
    );

    let anonymous = OpenAuthority.verify(None).unwrap();
    assert!(anonymous.owner().is_none());
    assert!(anonymous.fragments().is_empty());
}

#[test]
fn an_origin_authority_refuses_a_forged_signature() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
    let service = Arc::new(AuthService::new(db));
    service
        .user_add(
            &"alice".parse().unwrap(),
            &noted_auth::types::Password::new("pw"),
        )
        .unwrap();
    let login = service
        .issue_login(&"alice".parse().unwrap(), &ClientId::new("client-1"))
        .unwrap();

    let authority = OriginAuthority::new(service.clone());
    assert!(
        authority
            .verify(Some(&CredentialPresentation::submitted(
                login.access.expose()
            )))
            .is_ok()
    );

    let forged = Macaroon::mint(&owner(), &KeyRecord::fresh(), &[]).unwrap();
    assert!(
        authority
            .verify(Some(&CredentialPresentation::submitted(forged.expose())))
            .is_err()
    );
}
