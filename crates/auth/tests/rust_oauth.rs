use noted_auth::oauth::{OAuthClient, RegisterOAuthClient};
use noted_auth::types::RedirectUri;

#[test]
fn redirect_uris_require_parseable_urls() {
    let redirect = RedirectUri::new("https://client.example/callback?next=%2Fnotes").unwrap();
    assert_eq!(
        redirect.as_url().as_str(),
        "https://client.example/callback?next=%2Fnotes"
    );
    assert_eq!(
        redirect.as_str(),
        "https://client.example/callback?next=%2Fnotes"
    );
    assert!(RedirectUri::new("not a url").is_err());
}

#[test]
fn registration_requires_at_least_one_redirect() {
    assert!(RegisterOAuthClient::new(Vec::new()).is_err());
}

#[test]
fn registered_clients_receive_identity_issuance_and_valid_redirects() {
    let redirects = vec![
        RedirectUri::new("https://client.example/callback").unwrap(),
        RedirectUri::new("http://127.0.0.1:8080/return").unwrap(),
    ];
    let before = noted::types::UnixEpochSeconds::now().unwrap();
    let client =
        OAuthClient::registered(RegisterOAuthClient::new(redirects.clone()).unwrap()).unwrap();
    let after = noted::types::UnixEpochSeconds::now().unwrap();

    assert!(!client.client_id().as_str().is_empty());
    assert!(client.issued_at() >= before);
    assert!(client.issued_at() <= after);
    assert_eq!(client.redirect_uris(), redirects);
    assert!(
        client
            .redirect_uris()
            .iter()
            .all(|redirect| url::Url::parse(redirect.as_str()).is_ok())
    );
}
