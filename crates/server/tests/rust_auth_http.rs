mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use noted::PolicyFragment;
use noted_server::auth::AuthState;
use noted_server::http::{Served, build_app};
use noted_server::oauth::OAuthProvider;
use serde_json::json;

#[tokio::test]
async fn mint_and_revoke_keep_success_and_domain_error_responses_after_blocking_dispatch() {
    let dir = common::fixture_dir();
    let (app, token) = common::app_with_key(&dir).await;
    let (status, body) = common::post_json(&app, "/macaroon/mint", Some(&token), &json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        common::json_body(&body)["macaroon"]
            .as_str()
            .unwrap()
            .starts_with("noted_mac_")
    );
    let (status, _) =
        common::post_json(&common::open_app(&dir), "/macaroon/mint", None, &json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = common::request(
        &app,
        "POST",
        "/macaroon/mint",
        Some("bad"),
        "application/json",
        b"{".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = common::post_json(
        &app,
        "/macaroon/revoke",
        Some(&token),
        &json!({"id":"never-minted"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        !common::json_body(&body)["detail"]
            .as_str()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn revoke_preserves_selector_precedence_errors_denials_and_success_shape() {
    let dir = common::fixture_dir();
    let service = common::auth_service(&dir);
    let token = common::mint_key(&service, "agent", PolicyFragment::default());
    let app = common::origin_app(common::root(&dir), &service).await;
    let (status, body) = common::post_json(
        &app,
        "/macaroon/revoke",
        Some(&token),
        &json!({"all": true, "id": "ignored"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(common::json_body(&body)["epoch"].is_number());
    let (status, body) =
        common::post_json(&app, "/macaroon/revoke", Some(&token), &json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(common::json_body(&body)["detail"], "unauthorized");
}

#[tokio::test]
async fn bearer_denials_keep_status_detail_and_challenge_after_blocking_dispatch() {
    let dir = common::fixture_dir();
    let database = common::auth_service(&dir);
    let service = database.clone();
    let provider = Arc::new(
        OAuthProvider::new("http://localhost", database)
            .await
            .unwrap(),
    );
    let app = build_app(Served::origin(
        common::root(&dir),
        AuthState::origin(service, Some(provider)).await.unwrap(),
    ));
    let (status, body) =
        common::post_json(&app, "/macaroon/mint", Some("not-a-macaroon"), &json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        common::json_body(&body)["detail"]
            .as_str()
            .unwrap()
            .contains("macaroon")
    );
    let (status, headers, body) = common::request(
        &app,
        "POST",
        "/macaroon/mint",
        None,
        "application/json",
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(common::json_body(&body)["detail"], "unauthorized");
    assert_eq!(
        headers["www-authenticate"],
        "Bearer resource_metadata=\"http://localhost/.well-known/oauth-protected-resource/mcp\""
    );
}
