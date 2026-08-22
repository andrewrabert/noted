mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::http::StatusCode;
use noted_auth::types::Password;
use noted_server::auth::AuthState;
use noted_server::http::{Served, build_app};
use noted_server::oauth::OAuthProvider;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PUBLIC: &str = "http://localhost";
const REDIRECT: &str = "http://client.example/callback";
const CODE_CHALLENGE: &str = "0123456789012345678901234567890123456789012";

async fn fixture() -> (tempfile::TempDir, SocketAddr, String) {
    let dir = common::fixture_dir();
    let database = common::auth_service(&dir);
    let service = database.clone();
    service
        .user_add(&common::un("alice"), &Password::new("correct"))
        .unwrap();
    let provider = Arc::new(OAuthProvider::new(PUBLIC, database).await.unwrap());
    let app = build_app(Served::origin(
        common::root(&dir),
        AuthState::origin(service, Some(provider)).await.unwrap(),
    ));
    let (_, body) = common::post_json(
        &app,
        "/register",
        None,
        &json!({"redirect_uris": [REDIRECT]}),
    )
    .await;
    let client = common::json_body(&body)["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    let path = format!(
        "/authorize?response_type=code&client_id={client}&redirect_uri={REDIRECT}&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256"
    );
    let (status, headers, _) = common::request(&app, "GET", &path, None, "", Vec::new()).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = headers.get("location").unwrap().to_str().unwrap();
    let txn = url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "txn")
        .unwrap()
        .1
        .into_owned();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (dir, address, txn)
}

async fn login(
    address: SocketAddr,
    local: Ipv4Addr,
    txn: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(IpAddr::V4(local), 0)).unwrap();
    let mut stream = socket.connect(address).await.unwrap();
    let body = format!("txn={txn}&username=alice&password=wrong");
    let mut request = format!(
        "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&body);
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let status = response
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    (status, response)
}

#[tokio::test]
async fn repeated_connections_from_one_peer_ip_share_one_username_quota() {
    let (_dir, address, txn) = fixture().await;
    for _ in 0..5 {
        assert_eq!(login(address, Ipv4Addr::LOCALHOST, &txn, &[]).await.0, 401);
    }
    assert_eq!(login(address, Ipv4Addr::LOCALHOST, &txn, &[]).await.0, 429);
}

#[tokio::test]
async fn forwarded_and_x_forwarded_for_cannot_change_the_quota() {
    let (_dir, address, txn) = fixture().await;
    for index in 0..6 {
        let headers = [
            ("Forwarded", format!("for=192.0.2.{index}")),
            ("X-Forwarded-For", format!("198.51.100.{index}")),
        ];
        let borrowed = [
            (headers[0].0, headers[0].1.as_str()),
            (headers[1].0, headers[1].1.as_str()),
        ];
        let status = login(address, Ipv4Addr::LOCALHOST, &txn, &borrowed).await.0;
        assert_eq!(status, if index < 5 { 401 } else { 429 });
    }
}

#[tokio::test]
async fn every_other_forwarding_header_cannot_change_the_quota() {
    let (_dir, address, txn) = fixture().await;
    for index in 0..6 {
        let value = format!("192.0.2.{index}");
        let status = login(address, Ipv4Addr::LOCALHOST, &txn, &[("X-Real-IP", &value)])
            .await
            .0;
        assert_eq!(status, if index < 5 { 401 } else { 429 });
    }
}

#[tokio::test]
async fn changing_peer_ports_cannot_change_the_quota() {
    let (_dir, address, txn) = fixture().await;
    for index in 0..6 {
        let status = login(address, Ipv4Addr::LOCALHOST, &txn, &[]).await.0;
        assert_eq!(status, if index < 5 { 401 } else { 429 });
    }
}

#[tokio::test]
async fn distinct_accepted_loopback_peer_ips_receive_distinct_quotas() {
    let (_dir, address, txn) = fixture().await;
    for _ in 0..5 {
        assert_eq!(
            login(address, Ipv4Addr::new(127, 0, 0, 1), &txn, &[])
                .await
                .0,
            401
        );
    }
    assert_eq!(
        login(address, Ipv4Addr::new(127, 0, 0, 2), &txn, &[])
            .await
            .0,
        401
    );
}

#[tokio::test]
async fn the_sixth_attributed_attempt_returns_the_existing_429_login_page() {
    let (_dir, address, txn) = fixture().await;
    for _ in 0..5 {
        let _ = login(address, Ipv4Addr::LOCALHOST, &txn, &[]).await;
    }
    let (status, response) = login(address, Ipv4Addr::LOCALHOST, &txn, &[]).await;
    assert_eq!(status, 429);
    assert!(response.contains("too many attempts, try later"));
    assert!(response.contains("noted sign in"));
}
