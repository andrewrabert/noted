mod common;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use serde_json::{Value, json};

use noted::{Bearer, Endpoint, PolicyFragment, Transport};
use noted_auth::authority::{Mint, Minter, RelayCredential, Revoke, Verified};
use noted_auth::credential::{Caveat, Macaroon};
use noted_auth::types::Owner;
use noted_server::http::{Served, build_app};
use noted_server::relay::Relay;
use noted_server::serve::{Bind, Bound, HttpConfig, ServedConfig, serve_http};

use common::{json_body, post_json, post_mcp};

/// Every request the upstream saw, as the bearer it carried.
type Seen = Arc<Mutex<Vec<String>>>;

fn upstream(dir: &tempfile::TempDir) -> (Router, Seen) {
    recording(common::open_app(dir))
}

fn recording(app: Router) -> (Router, Seen) {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let layer = middleware::from_fn_with_state(seen.clone(), record);
    (app.layer(layer), seen)
}

async fn record(State(seen): State<Seen>, request: Request, next: Next) -> Response {
    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    seen.lock().unwrap().push(bearer);
    next.run(request).await
}

fn nowhere() -> Endpoint {
    "http://upstream.test".parse().unwrap()
}

fn credential(policy: &str, upstream_bearer: Option<&Bearer>) -> Arc<RelayCredential> {
    let presentation = upstream_bearer
        .map(|bearer| noted_auth::types::CredentialPresentation::submitted(bearer.expose()));
    Arc::new(RelayCredential::open(presentation.as_ref(), common::held(policy), None).unwrap())
}

async fn relay_app(
    cred: Arc<RelayCredential>,
    upstream_endpoint: Endpoint,
    bound: &Bound,
    transport: Transport,
) -> Router {
    let relay = Arc::new(Relay::open(cred, upstream_endpoint, bound, transport).unwrap());
    build_app(Served::relay(relay))
}

async fn in_front_of(cred: Arc<RelayCredential>, upstream: Router) -> Router {
    let bound = common::bound_listener().await;
    relay_app(cred, nowhere(), &bound, Transport::Router(upstream)).await
}

/// What a relay hands a caller that is to speak for it downstream: the relay's
/// own credential, unattenuated.
fn own_bearer(cred: &Arc<RelayCredential>) -> Bearer {
    Bearer::new(
        Minter::own(cred.as_ref())
            .macaroon()
            .expect("a relay holds a credential")
            .expose(),
    )
}

/// A caller's own caveat on the credential it holds, as a client mints it.
fn attenuated(bearer: &Bearer, policy: &str) -> String {
    Macaroon::from_encoded(bearer.expose().to_string())
        .unwrap()
        .extended(&[Caveat::Policy(common::held(policy))])
        .unwrap()
        .expose()
        .to_string()
}

async fn read(app: &Router, token: Option<&str>, path: &str) -> (StatusCode, Vec<u8>) {
    post_json(app, "/tool/ReadNote", token, &json!({ "path": path })).await
}

fn data(body: &[u8]) -> String {
    json_body(body)["ok"]["data"]
        .as_str()
        .expect("a tool answers with data")
        .to_string()
}

fn mcp_read(path: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "ReadNote", "arguments": {"path": path}}})
}

async fn seed(dir: &tempfile::TempDir, rel: &str, content: &str) {
    common::write(&common::root(dir), &common::note(rel, content))
        .await
        .unwrap();
}

#[tokio::test]
async fn relay_app_derives_routing_and_authentication_from_one_relay() {
    let bound = common::bound_listener().await;
    let app = relay_app(
        credential("{}", None),
        nowhere(),
        &bound,
        Transport::Router(Router::new()),
    )
    .await;

    let (status, _) = read(&app, None, "Inbox.md").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_three_hop_chain_composes_scopes_in_hop_order() {
    let dir = common::fixture_dir();
    seed(&dir, "a/b/x.md", "innermost").await;
    let (origin, _seen) = upstream(&dir);

    let outer = credential(r#"{"scope":"a"}"#, None);
    let outer_app = in_front_of(outer.clone(), origin).await;

    let inner = credential(r#"{"scope":"b"}"#, Some(&own_bearer(&outer)));
    let inner_app = in_front_of(inner, outer_app.clone()).await;

    let (status, body) = read(&inner_app, None, "x.md").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(data(&body), "innermost");

    // the outer hop's scope is applied first, so `b/` is still below it
    let (status, body) = read(&outer_app, None, "b/x.md").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(data(&body), "innermost");
    let (status, _) = read(&outer_app, None, "x.md").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_caller_bearer_that_is_no_descendant_is_forbidden() {
    let dir = common::fixture_dir();
    let (origin, seen) = upstream(&dir);
    let app = in_front_of(credential("{}", None), origin).await;

    let stranger = Macaroon::ephemeral().unwrap();
    let (status, body) = read(&app, Some(stranger.expose()), "Inbox.md").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        json_body(&body)["detail"]
            .as_str()
            .unwrap()
            .contains("no descendant")
    );
    assert!(seen.lock().unwrap().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a_bearer_less_caller_over_a_socket_relay_runs_at_the_relays_policy() {
    use noted_server::socket::bind_unix_socket;

    let dir = common::fixture_dir();
    seed(&dir, "a/x.md", "scoped").await;
    let sock = dir.path().join("noted.sock");
    let (listener, guard) = bind_unix_socket(&sock, None).unwrap();
    let origin = common::open_app(&dir);
    tokio::spawn(async move {
        let _guard = guard;
        let _ = axum::serve(listener, origin).await;
    });

    let endpoint: Endpoint = format!("unix://{}", sock.display()).parse().unwrap();
    let bound = common::bound_listener().await;
    let app = relay_app(
        credential(r#"{"scope":"a"}"#, None),
        endpoint,
        &bound,
        Transport::Real,
    )
    .await;

    let (status, body) = read(&app, None, "x.md").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(data(&body), "scoped");
}

#[tokio::test]
async fn a_relay_in_front_of_an_open_origin_self_mints_and_reaches_the_tree() {
    let dir = common::fixture_dir();
    let (origin, seen) = upstream(&dir);
    let app = in_front_of(credential(r#"{"scope":"projects"}"#, None), origin).await;

    let (status, body) = read(&app, None, "ideas.md").await;
    assert_eq!(status, StatusCode::OK);
    assert!(data(&body).contains("XYZZY"));

    let carried = seen.lock().unwrap().first().cloned().expect("one request");
    let macaroon =
        Macaroon::from_encoded(carried.strip_prefix("Bearer ").unwrap().to_string()).unwrap();
    assert!(
        matches!(macaroon.owner().unwrap(), Owner::Server(_)),
        "a relay with no bearer mints under its own server owner"
    );
    assert!(macaroon.caveats().unwrap().iter().any(
        |caveat| matches!(caveat, Caveat::Policy(fragment) if *fragment == common::held(r#"{"scope":"projects"}"#))
    ));
    assert!(
        macaroon
            .caveats()
            .unwrap()
            .iter()
            .any(|caveat| matches!(caveat, Caveat::Before(_)))
    );
}

#[tokio::test]
async fn a_relay_confinement_dominates_the_callers() {
    let dir = common::fixture_dir();
    seed(&dir, "a/b/x.md", "confined").await;
    let (origin, _seen) = upstream(&dir);
    let cred = credential(
        r#"{"scope":"a","access":{"read":true,"write":false}}"#,
        None,
    );
    let held = own_bearer(&cred);
    let app = in_front_of(cred, origin).await;

    let narrowed = attenuated(&held, r#"{"scope":"b"}"#);
    let (status, body) = read(&app, Some(&narrowed), "x.md").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(data(&body), "confined");

    let (status, _) = post_json(
        &app,
        "/tool/WriteNote",
        Some(&narrowed),
        &json!({"path": "y.md", "content": "no"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let widened = attenuated(&held, r#"{"access":{"write":true}}"#);
    let (status, _) = read(&app, Some(&widened), "b/x.md").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_upstream_status_and_detail_reach_the_caller_unchanged() {
    let dir = common::fixture_dir();
    let origin = common::open_app(&dir);
    let app = in_front_of(credential("{}", None), origin.clone()).await;

    let (direct_status, direct_body) = read(&origin, None, "nope.md").await;
    let (status, body) = read(&app, None, "nope.md").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(status, direct_status);
    assert_eq!(body, direct_body);
    assert!(json_body(&body)["detail"].is_string());
}

#[tokio::test]
async fn an_unreachable_upstream_names_only_the_dialable_endpoint_attempted() {
    let dead: Endpoint = "http://127.0.0.1:1".parse().unwrap();
    let bound = common::bound_listener().await;
    let app = relay_app(credential("{}", None), dead, &bound, Transport::Real).await;

    let (status, body) = read(&app, None, "Inbox.md").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let detail = json_body(&body)["detail"].as_str().unwrap().to_string();
    assert!(
        detail.starts_with("cannot reach http://127.0.0.1:1"),
        "{detail}"
    );
}

#[tokio::test]
async fn a_revoked_caller_token_id_produces_no_upstream_request() {
    let dir = common::fixture_dir();
    let (origin, seen) = upstream(&dir);
    let svc = common::auth_service(&dir);
    let cred = Arc::new(
        RelayCredential::open(None, PolicyFragment::default(), Some(svc.clone())).unwrap(),
    );
    let ask = Mint {
        policy: PolicyFragment::default(),
        ttl: svc.default_ttl(),
        session: None,
        label: None,
    };
    let minted = Minter::mint(cred.as_ref(), &Verified::anonymous(), &ask).unwrap();
    let token = minted.macaroon.expose().to_string();
    let app = in_front_of(cred.clone(), origin).await;

    let (status, _) = read(&app, Some(&token), "Inbox.md").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(seen.lock().unwrap().len(), 1);

    Minter::revoke(
        cred.as_ref(),
        &Verified::anonymous(),
        &Revoke::Token(minted.token_id.clone()),
    )
    .unwrap();

    let (status, body) = read(&app, Some(&token), "Inbox.md").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(&body)["detail"], "unauthorized");
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn relay_revocation_errors_name_the_listener_endpoint() {
    let upstream: Endpoint = "http://upstream.test/internal".parse().unwrap();
    let bound = common::bound_listener().await;
    let app = relay_app(
        credential("{}", None),
        upstream,
        &bound,
        Transport::Router(common::open_app(&common::fixture_dir())),
    )
    .await;

    let (status, body) = post_json(&app, "/macaroon/revoke", None, &json!({"id":"anything"})).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let detail = json_body(&body)["detail"].as_str().unwrap().to_string();
    assert!(detail.starts_with("http://127.0.0.1:"), "{detail}");
    assert!(
        detail.ends_with(": this relay records nothing it mints"),
        "{detail}"
    );
}

#[test]
fn malformed_relay_credentials_name_the_allocated_listener_endpoint_at_startup() {
    let endpoint: Endpoint = "http://relay.test/presented".parse().unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let error = runtime
        .block_on(serve_http(HttpConfig {
            served: ServedConfig::Relay {
                endpoint,
                bearer: Some(Bearer::new("not-a-macaroon")),
                policy: noted::PolicyArgs::default(),
                transport: Transport::Router(common::open_app(&common::fixture_dir())),
            },
            bind: Bind::Tcp {
                host: "127.0.0.1".to_string(),
                port: 0,
            },
            public_url: None,
            authentication: None,
            #[cfg(unix)]
            admin_socket: None,
        }))
        .unwrap_err();

    let message = error.to_string();
    let selected = message
        .strip_prefix("http://127.0.0.1:")
        .and_then(|remainder| remainder.split_once(": "))
        .map(|(port, _)| port.parse::<u16>().unwrap())
        .unwrap_or_else(|| panic!("missing bound relay endpoint: {message}"));
    assert_ne!(selected, 0, "{message}");
    assert!(!message.starts_with("http://127.0.0.1:0: "), "{message}");
    assert!(
        !message.starts_with("http://relay.test/presented: "),
        "{message}"
    );
}

#[tokio::test]
async fn a_relay_minted_credential_presented_back_composes_its_scope_once() {
    let dir = common::fixture_dir();
    seed(&dir, "a/x.md", "once").await;
    let (origin, seen) = upstream(&dir);
    let cred = credential(r#"{"scope":"a"}"#, None);
    let ask = Mint {
        policy: PolicyFragment::default(),
        ttl: noted::types::Ttl::from_secs(3600),
        session: None,
        label: None,
    };
    let minted = Minter::mint(cred.as_ref(), &Verified::anonymous(), &ask).unwrap();
    let token = minted.macaroon.expose().to_string();
    let app = in_front_of(cred, origin).await;

    let (status, body) = read(&app, Some(&token), "x.md").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(data(&body), "once");

    let carried = seen.lock().unwrap().first().cloned().expect("one request");
    let macaroon =
        Macaroon::from_encoded(carried.strip_prefix("Bearer ").unwrap().to_string()).unwrap();
    let caveats = macaroon.caveats().unwrap();
    let scope = Caveat::Policy(common::held(r#"{"scope":"a"}"#));
    assert_eq!(caveats.iter().filter(|c| **c == scope).count(), 1);
    assert_eq!(caveats[0], scope);
}

#[tokio::test]
async fn mcp_bodies_cross_a_relay_byte_for_byte() {
    let dir = common::fixture_dir();
    let origin = common::open_app(&dir);
    let app = in_front_of(credential("{}", None), origin.clone()).await;

    let (direct_status, _h, direct_body) = post_mcp(&origin, None, &mcp_read("Inbox.md")).await;
    let (status, _h, body) = post_mcp(&app, None, &mcp_read("Inbox.md")).await;
    assert_eq!(status, direct_status);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, direct_body);
    assert!(
        json_body(&body)["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("follow up with Dana")
    );
}
