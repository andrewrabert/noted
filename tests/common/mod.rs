#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use noted::notes::Notes;
use noted::oauth::{AuthService, Db};
use noted::scope::{RuleSpec, StoredScope, TokenScope};
use noted::tasks::Tasks;
use serde_json::Value;
use tower::ServiceExt;

pub fn scope(tools: Option<&[&str]>, paths: Option<&[&str]>) -> TokenScope {
    let to_vec = |o: Option<&[&str]>| o.map(|s| s.iter().map(|x| x.to_string()).collect());
    TokenScope::single_rule(to_vec(tools), to_vec(paths)).unwrap()
}

pub fn grants(tools: Option<&[&str]>, paths: Option<&[&str]>) -> StoredScope {
    let to_vec = |o: Option<&[&str]>| o.map(|s: &[&str]| s.iter().map(|x| x.to_string()).collect());
    StoredScope::Grants(vec![RuleSpec {
        tools: to_vec(tools),
        paths: to_vec(paths),
    }])
}

pub fn auth_service(dir: &tempfile::TempDir) -> Arc<AuthService> {
    let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
    Arc::new(AuthService::new(
        db,
        noted::types::Ttl::from_secs(30 * 24 * 3600),
    ))
}

pub fn mint_key(svc: &AuthService, label: &str, scope: StoredScope) -> String {
    let minted = svc
        .key_create(
            &noted::oauth::types::Label::new(label).unwrap(),
            scope,
            None,
        )
        .unwrap();
    svc.key_finalize(&minted.credential_id).unwrap();
    minted.token.expose().to_string()
}

pub fn app_with_key(dir: &tempfile::TempDir) -> (Router, String) {
    let (notes, tasks) = cores(dir);
    let ctx = noted::mcp::context(notes, tasks);
    let svc = auth_service(dir);
    let token = mint_key(&svc, "test", StoredScope::Unrestricted);
    (noted::http::build_app(ctx, Some(svc), None), token)
}

pub fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

pub fn fixture_dir() -> tempfile::TempDir {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/notes");
    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join("notes");
    copy_tree(&src, &dst);
    tmp
}

pub fn notes_root(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("notes")
}

pub fn cores(dir: &tempfile::TempDir) -> (Notes, Tasks) {
    let root = notes_root(dir);
    let notes = Notes::new(&root, Some("test".into())).unwrap();
    let tasks = Tasks::new(notes.root());
    (notes, tasks)
}

pub async fn request(
    router: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    content_type: &str,
    body: Vec<u8>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", content_type);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let req = builder.body(axum::body::Body::from(body)).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, bytes)
}

pub async fn post_json(
    router: &Router,
    path: &str,
    token: Option<&str>,
    body: &Value,
) -> (StatusCode, Vec<u8>) {
    let (s, _h, b) = request(
        router,
        "POST",
        path,
        token,
        "application/json",
        serde_json::to_vec(body).unwrap(),
    )
    .await;
    (s, b)
}

/// rmcp requires the caller to accept both `application/json` and
/// `text/event-stream`, even though the stateless JSON reply is plain JSON.
pub async fn post_mcp(
    router: &Router,
    token: Option<&str>,
    body: &Value,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let req = builder
        .body(axum::body::Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, bytes)
}

pub async fn post_form(
    router: &Router,
    path: &str,
    fields: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish();
    request(
        router,
        "POST",
        path,
        None,
        "application/x-www-form-urlencoded",
        body.into_bytes(),
    )
    .await
}

pub fn json_body(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}
