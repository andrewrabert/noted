mod common;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use serde_json::{Value, json};

use noted::{Bearer, Endpoint, PolicyFragment, Transport};
use noted_server::http::{Served, build_app};
use noted_server::relay::Relay;
use noted_server::serve::Bound;

use common::{json_body, post_json, post_mcp};

/// Every request the upstream saw, as the bearer and the target it carried.
type Seen = Arc<Mutex<Vec<(String, String)>>>;

fn upstream(dir: &tempfile::TempDir) -> (Router, Seen) {
    recording(common::open_app(dir))
}

async fn keyed_upstream(dir: &tempfile::TempDir) -> (Router, Seen, Bearer) {
    let svc = common::auth_service(dir);
    let held = Bearer::new(common::mint_key(&svc, PolicyFragment::default()));
    let (app, seen) = recording(common::origin_app(common::root(dir), &svc).await);
    (app, seen, held)
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
    let target = request
        .uri()
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_default();
    seen.lock().unwrap().push((bearer, target));
    next.run(request).await
}

fn first(seen: &Seen) -> (String, String) {
    seen.lock().unwrap().first().cloned().expect("one request")
}

fn nowhere() -> Endpoint {
    "http://upstream.test".parse().unwrap()
}

async fn relay_app(
    bearer: Option<Bearer>,
    policy: &str,
    upstream_endpoint: Endpoint,
    bound: &Bound,
    transport: Transport,
) -> Router {
    let relay = Arc::new(
        Relay::open(
            bearer,
            common::held(policy),
            upstream_endpoint,
            bound,
            transport,
        )
        .unwrap(),
    );
    build_app(Served::relay(relay))
}

async fn in_front_of(bearer: Option<Bearer>, policy: &str, upstream: Router) -> Router {
    let bound = common::bound_listener().await;
    relay_app(
        bearer,
        policy,
        nowhere(),
        &bound,
        Transport::Router(upstream),
    )
    .await
}

fn narrowed(path: &str, policies: &[&str]) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(policies.iter().map(|policy| ("policy", *policy)))
        .finish();
    format!("{path}?{query}")
}

async fn read(app: &Router, token: Option<&str>, path: &str) -> (StatusCode, Vec<u8>) {
    post_json(app, "/tool/ReadNote", token, &json!({ "path": path })).await
}

async fn read_at(app: &Router, uri: &str, path: &str) -> (StatusCode, Vec<u8>) {
    post_json(app, uri, None, &json!({ "path": path })).await
}

fn data(body: &[u8]) -> String {
    json_body(body)["ok"]["data"]
        .as_str()
        .expect("a tool answers with data")
        .to_string()
}

fn detail(body: &[u8]) -> String {
    json_body(body)["detail"]
        .as_str()
        .expect("a refusal answers with a detail")
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
        None,
        "{}",
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

    let outer_app = in_front_of(None, r#"{"scope":"a"}"#, origin).await;
    let inner_app = in_front_of(None, r#"{"scope":"b"}"#, outer_app.clone()).await;

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
async fn a_relay_takes_no_credential_from_its_caller() {
    let dir = common::fixture_dir();
    let (origin, seen) = upstream(&dir);
    let app = in_front_of(None, "{}", origin).await;

    let (status, body) = read(&app, Some("noted_mac_whatever"), "Inbox.md").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        detail(&body).contains("takes no credential"),
        "{}",
        detail(&body)
    );
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_relay_carries_the_credential_it_was_configured_with_unchanged() {
    let dir = common::fixture_dir();
    let (origin, seen, held) = keyed_upstream(&dir).await;
    let app = in_front_of(Some(held.clone()), r#"{"scope":"projects"}"#, origin).await;

    let (status, body) = read(&app, None, "ideas.md").await;
    assert_eq!(status, StatusCode::OK);
    assert!(data(&body).contains("XYZZY"));

    let (carried, target) = first(&seen);
    assert_eq!(carried, format!("Bearer {}", held.expose()));
    assert_eq!(
        target,
        narrowed("/tool/ReadNote", &[r#"{"scope":"projects"}"#])
    );
}

#[tokio::test]
async fn a_relay_holding_no_credential_presents_none() {
    let dir = common::fixture_dir();
    let (origin, seen) = upstream(&dir);
    let app = in_front_of(None, "{}", origin).await;

    let (status, _) = read(&app, None, "Inbox.md").await;
    assert_eq!(status, StatusCode::OK);

    let (carried, target) = first(&seen);
    assert!(carried.is_empty(), "{carried}");
    assert_eq!(target, "/tool/ReadNote");
}

#[cfg(unix)]
#[tokio::test]
async fn a_caller_over_a_socket_relay_runs_at_the_relays_policy() {
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
    let app = relay_app(None, r#"{"scope":"a"}"#, endpoint, &bound, Transport::Real).await;

    let (status, body) = read(&app, None, "x.md").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(data(&body), "scoped");
}

#[tokio::test]
async fn a_relay_confinement_dominates_the_callers() {
    let dir = common::fixture_dir();
    seed(&dir, "a/b/x.md", "confined").await;
    let (origin, seen) = upstream(&dir);
    let app = in_front_of(
        None,
        r#"{"scope":"a","access":{"read":true,"write":false}}"#,
        origin,
    )
    .await;

    let (status, body) = read_at(
        &app,
        &narrowed("/tool/ReadNote", &[r#"{"scope":"b"}"#]),
        "x.md",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(data(&body), "confined");
    let (_, target) = first(&seen);
    assert_eq!(
        target,
        narrowed(
            "/tool/ReadNote",
            &[
                r#"{"scope":"a","access":{"read":true,"write":false}}"#,
                r#"{"scope":"b"}"#,
            ]
        )
    );

    let (status, _) = post_json(
        &app,
        &narrowed("/tool/WriteNote", &[r#"{"scope":"b"}"#]),
        None,
        &json!({"path": "y.md", "content": "no"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = read_at(
        &app,
        &narrowed("/tool/ReadNote", &[r#"{"access":{"write":true}}"#]),
        "b/x.md",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_upstream_status_and_detail_reach_the_caller_unchanged() {
    let dir = common::fixture_dir();
    let origin = common::open_app(&dir);
    let app = in_front_of(None, "{}", origin.clone()).await;

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
    let app = relay_app(None, "{}", dead, &bound, Transport::Real).await;

    let (status, body) = read(&app, None, "Inbox.md").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        detail(&body).starts_with("cannot reach http://127.0.0.1:1"),
        "{}",
        detail(&body)
    );
}

#[tokio::test]
async fn a_relay_mints_nothing_of_its_own() {
    let dir = common::fixture_dir();
    let (origin, _seen) = upstream(&dir);
    let app = in_front_of(None, "{}", origin).await;

    let (status, _) = post_json(&app, "/macaroon/mint", None, &json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mcp_bodies_cross_a_relay_byte_for_byte() {
    let dir = common::fixture_dir();
    let origin = common::open_app(&dir);
    let app = in_front_of(None, "{}", origin.clone()).await;

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
