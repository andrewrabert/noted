use std::sync::Arc;

use noted::PolicyFragment;
use noted_auth::Db;
use noted_auth::authority::{
    Mint, Minter, OpenAuthority, OriginAuthority, RelayCredential, Verified, Verifier,
};
use noted_auth::credential::{Caveat, KeyRecord, Macaroon, MacaroonId};
use noted_auth::service::AuthService;
use noted_auth::types::{ClientId, CredentialPresentation, Owner};

fn fragment(text: &str) -> PolicyFragment {
    text.parse().unwrap()
}

fn owner() -> Owner {
    Owner::user("alice").unwrap()
}

fn relay(policy: &str) -> RelayCredential {
    RelayCredential::open(None, fragment(policy), None).unwrap()
}

fn caller_of(relay: &RelayCredential, caveats: &[Caveat]) -> Verified {
    let root = relay.own().macaroon().unwrap();
    let bearer = root.extended(caveats).unwrap();
    relay
        .verify(Some(&CredentialPresentation::submitted(bearer.expose())))
        .unwrap()
}

#[test]
fn a_minted_credential_carries_its_caveats_in_mint_order() {
    let caveats = vec![
        Caveat::Policy(fragment(r#"{"scope":"dev"}"#)),
        Caveat::Token(MacaroonId::fresh()),
    ];
    let macaroon = Macaroon::mint(&owner(), &KeyRecord::fresh(), &caveats).unwrap();
    assert_eq!(macaroon.caveats().unwrap(), caveats);
    assert_eq!(macaroon.owner().unwrap(), owner());
}

#[test]
fn a_descendant_rebuilds_from_its_ancestor_and_a_stranger_does_not() {
    let key = KeyRecord::fresh();
    let root = Macaroon::mint(&owner(), &key, &[]).unwrap();
    let child = root
        .extended(&[Caveat::Policy(fragment(r#"{"scope":"dev"}"#))])
        .unwrap();

    let rebuilt = root.from_descendant(child.expose()).unwrap();
    assert_eq!(rebuilt.expose(), child.expose());
    assert_eq!(
        root.from_descendant(root.expose()).unwrap().expose(),
        root.expose()
    );

    let same_owner_other_key = Macaroon::mint(&owner(), &KeyRecord::fresh(), &[]).unwrap();
    assert!(root.from_descendant(same_owner_other_key.expose()).is_err());
    assert!(
        root.from_descendant(Macaroon::ephemeral().unwrap().expose())
            .is_err()
    );
    assert!(child.from_descendant(root.expose()).is_err());
}

#[test]
fn beyond_yields_only_the_caveats_past_the_ancestor() {
    let root = Macaroon::mint(&owner(), &KeyRecord::fresh(), &[]).unwrap();
    let added = vec![
        Caveat::Policy(fragment(r#"{"scope":"dev"}"#)),
        Caveat::Token(MacaroonId::fresh()),
    ];
    let child = root.extended(&added).unwrap();

    assert_eq!(child.beyond(&root).unwrap(), added);
    assert!(child.beyond(&child).unwrap().is_empty());
    assert!(root.beyond(&child).is_err());
}

#[test]
fn a_re_mint_puts_the_relay_policy_ahead_of_the_callers_caveats() {
    let relay = relay(r#"{"scope":"relay"}"#);
    let held = vec![
        Caveat::Policy(fragment(r#"{"scope":"caller"}"#)),
        Caveat::Token(MacaroonId::new("caller-token")),
    ];
    let caller = caller_of(&relay, &held);
    assert_eq!(caller.caveats(), held.as_slice());

    let minted = relay.remint(&caller).unwrap();
    assert_eq!(
        minted.macaroon.caveats().unwrap(),
        vec![
            Caveat::Policy(fragment(r#"{"scope":"relay"}"#)),
            held[0].clone(),
            held[1].clone(),
            Caveat::Token(minted.token_id.clone()),
        ]
    );
}

#[test]
fn a_relay_minted_credential_presented_back_is_confined_once() {
    let relay = relay(r#"{"scope":"relay"}"#);
    let ask = Mint {
        policy: fragment(r#"{"scope":"agent"}"#),
    };
    let minted = Minter::mint(&relay, &Verified::anonymous(), &ask).unwrap();

    let back = relay
        .verify(Some(&CredentialPresentation::submitted(
            minted.macaroon.expose(),
        )))
        .unwrap();
    assert_eq!(
        back.fragments(),
        [
            fragment(r#"{"scope":"relay"}"#),
            fragment(r#"{"scope":"agent"}"#),
        ]
    );

    let forwarded = relay.remint(&back).unwrap();
    let carried = forwarded.macaroon.caveats().unwrap();
    assert_eq!(
        carried
            .iter()
            .filter(|caveat| **caveat == Caveat::Policy(fragment(r#"{"scope":"relay"}"#)))
            .count(),
        1
    );
    assert_eq!(carried[0], Caveat::Policy(fragment(r#"{"scope":"relay"}"#)));
}

#[test]
fn two_re_mints_of_one_caller_carry_distinct_token_ids() {
    let relay = relay(r#"{"scope":"relay"}"#);
    let caller = caller_of(&relay, &[Caveat::Policy(fragment(r#"{"scope":"caller"}"#))]);

    let first = relay.remint(&caller).unwrap();
    let second = relay.remint(&caller).unwrap();
    assert_ne!(first.token_id, second.token_id);
    assert_ne!(first.macaroon.expose(), second.macaroon.expose());
}

#[test]
fn an_open_authority_honors_policy_alone() {
    let live = Macaroon::mint(
        &owner(),
        &KeyRecord::fresh(),
        &[
            Caveat::Policy(fragment(r#"{"scope":"dev"}"#)),
            Caveat::Token(MacaroonId::new("minted-elsewhere")),
        ],
    )
    .unwrap();
    let verified = OpenAuthority
        .verify(Some(&CredentialPresentation::submitted(live.expose())))
        .unwrap();
    assert_eq!(verified.owner(), Some(&owner()));
    assert_eq!(verified.fragments(), [fragment(r#"{"scope":"dev"}"#)]);
    assert!(OpenAuthority.verify(None).unwrap().owner().is_none());
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

#[test]
fn a_relay_refuses_a_bearer_that_is_no_descendant() {
    let relay = relay(r#"{"scope":"relay"}"#);
    let stranger = Macaroon::ephemeral().unwrap();
    assert!(
        relay
            .verify(Some(&CredentialPresentation::submitted(stranger.expose())))
            .is_err()
    );
    assert!(
        relay
            .verify(Some(&CredentialPresentation::submitted("not-a-macaroon")))
            .is_err()
    );

    let bearer_less = relay.verify(None).unwrap();
    assert_eq!(bearer_less.fragments(), [fragment(r#"{"scope":"relay"}"#)]);
}
