use axum::{
    Json,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde_json::json;

pub(super) fn begin_authorization(
    public_url: &str,
    outcome: noted_auth::oauth::BeginAuthorizationOutcome,
) -> Response {
    match outcome {
        noted_auth::oauth::BeginAuthorizationOutcome::LoginRequired(transaction) => (
            StatusCode::SEE_OTHER,
            [(
                header::LOCATION,
                format!("{public_url}/login?txn={}", transaction.as_str()),
            )],
        )
            .into_response(),
        noted_auth::oauth::BeginAuthorizationOutcome::Redirect(redirect) => (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, redirect.as_uri().as_str())],
        )
            .into_response(),
        noted_auth::oauth::BeginAuthorizationOutcome::InvalidRequest => {
            oauth_error(StatusCode::BAD_REQUEST, "invalid_request")
        }
        noted_auth::oauth::BeginAuthorizationOutcome::ServerError => {
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

pub(super) fn authorization_login(
    transaction: &str,
    outcome: noted_auth::oauth::AuthorizationLoginOutcome,
) -> Response {
    match outcome {
        noted_auth::oauth::AuthorizationLoginOutcome::Redirect(redirect) => (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, redirect.as_uri().as_str())],
        )
            .into_response(),
        noted_auth::oauth::AuthorizationLoginOutcome::Unknown => (
            StatusCode::BAD_REQUEST,
            Html(login_page("", Some("unknown login request"))),
        )
            .into_response(),
        noted_auth::oauth::AuthorizationLoginOutcome::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            Html(login_page(transaction, Some("invalid credentials"))),
        )
            .into_response(),
        noted_auth::oauth::AuthorizationLoginOutcome::InvalidRequest => {
            oauth_error(StatusCode::BAD_REQUEST, "invalid_request")
        }
        noted_auth::oauth::AuthorizationLoginOutcome::ServerError => {
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

pub(super) fn token(outcome: noted_auth::oauth::TokenOutcome) -> Response {
    match outcome {
        noted_auth::oauth::TokenOutcome::Issued(tokens) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::to_string(&json!({
                "access_token": tokens.access_token().expose(),
                "refresh_token": tokens.refresh_token().expose(),
                "token_type": match tokens.token_type() {
                    noted_auth::types::OAuthTokenType::Bearer => "bearer",
                },
                "scope": tokens.scope().as_str(),
            }))
            .unwrap_or_else(|_| r#"{"error":"server_error","error_description":""}"#.to_string()),
        )
            .into_response(),
        noted_auth::oauth::TokenOutcome::Rejected(rejection) => match rejection {
            noted_auth::oauth::TokenRejection::InvalidRequest => {
                oauth_error(StatusCode::BAD_REQUEST, "invalid_request")
            }
            noted_auth::oauth::TokenRejection::InvalidClient(
                noted_auth::oauth::ClientAuthenticationScheme::Basic,
            ) => (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic")],
                Json(json!({"error": "invalid_client", "error_description": ""})),
            )
                .into_response(),
            noted_auth::oauth::TokenRejection::UnsupportedGrantType => {
                oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type")
            }
            noted_auth::oauth::TokenRejection::InvalidGrant => {
                oauth_error(StatusCode::BAD_REQUEST, "invalid_grant")
            }
            noted_auth::oauth::TokenRejection::InvalidScope => {
                oauth_error(StatusCode::BAD_REQUEST, "invalid_scope")
            }
        },
        noted_auth::oauth::TokenOutcome::ServerError => {
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

fn oauth_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({"error": message, "error_description": ""})),
    )
        .into_response()
}

pub(super) fn login_page(transaction: &str, error: Option<&str>) -> String {
    let input_style = "width:100%;padding:.5rem;box-sizing:border-box";
    maud::html! {
        (maud::DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                title { "noted sign in" }
            }
            body style="font-family:sans-serif;max-width:22rem;margin:4rem auto" {
                h1 { "noted" }
                @if let Some(error) = error {
                    p style="color:#c00" { (error) }
                }
                form method="post" action="/login" {
                    input type="hidden" name="txn" value=(transaction);
                    p { input name="username" placeholder="username" autofocus style=(input_style); }
                    p { input name="password" type="password" placeholder="password" style=(input_style); }
                    p { button type="submit" style="padding:.5rem 1rem" { "Sign in" } }
                }
            }
        }
    }
    .into_string()
}
