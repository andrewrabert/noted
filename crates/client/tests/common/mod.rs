#![allow(dead_code)]

use std::path::{Path as StdPath, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use noted::note::{Condition, TextNote};
use noted::path::Path;
use noted::search::{Hit, SearchMode, SearchQuery};
use noted::store::NotedDir;
use noted::types::Source;
use noted::{Backend, BackendArgs, NotedRoot, PolicyArgs, PolicyFragment};
use noted_auth::oauth::{AuthService, Db};
use serde_json::Value;
use tower::ServiceExt;

pub fn rp(s: &str) -> Path {
    s.parse().unwrap()
}

pub fn note(rel: &str, content: &str) -> TextNote {
    TextNote::new(rp(rel), content)
}

pub fn read(root: &NotedRoot, rel: &str) -> noted::Result<String> {
    root.note_read(&rp(rel))
        .map(|n| n.body().as_str().to_string())
}

pub fn write(root: &NotedRoot, note: &TextNote) -> noted::Result<()> {
    root.note_write(note, Condition::Always)
}

pub fn held(text: &str) -> PolicyFragment {
    text.parse().unwrap()
}

pub fn query(pattern: &str, mode: SearchMode) -> SearchQuery {
    SearchQuery {
        pattern: pattern.parse().unwrap(),
        mode,
        ..Default::default()
    }
}

pub async fn grep(root: &NotedRoot, pattern: &str) -> noted::Result<Vec<Hit>> {
    root.note_search(&query(pattern, SearchMode::Line)).await
}

pub async fn found(root: &NotedRoot, pattern: &str) -> noted::Result<Vec<String>> {
    Ok(root
        .note_search(&query(pattern, SearchMode::Path))
        .await?
        .into_iter()
        .map(|hit| hit.path.to_string())
        .collect())
}

pub fn auth_service(dir: &tempfile::TempDir) -> Arc<AuthService> {
    let db = Arc::new(Db::open(&dir.path().join("auth.redb")).unwrap());
    Arc::new(AuthService::new(
        db,
        noted::types::Ttl::from_secs(30 * 24 * 3600),
    ))
}

pub fn mint_key(svc: &AuthService, label: &str, policy: PolicyFragment) -> String {
    let minted = svc
        .key_create(
            &noted_auth::oauth::types::Label::new(label).unwrap(),
            policy,
            None,
        )
        .unwrap();
    svc.key_finalize(&minted.credential_id).unwrap();
    minted.token.expose().to_string()
}

pub fn app_with_key(dir: &tempfile::TempDir) -> (Router, String) {
    let svc = auth_service(dir);
    let token = mint_key(&svc, "test", PolicyFragment::default());
    (
        noted_server::http::build_app(backend(dir), Some(svc), None),
        token,
    )
}

pub fn copy_tree(src: &StdPath, dst: &StdPath) {
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

pub fn root(dir: &tempfile::TempDir) -> NotedRoot {
    policed_root(dir, PolicyFragment::default())
}

pub fn confined(dir: &tempfile::TempDir, policy: &str) -> NotedRoot {
    policed_root(dir, held(policy))
}

pub fn policed_root(dir: &tempfile::TempDir, policy: PolicyFragment) -> NotedRoot {
    NotedRoot::open(NotedDir::new(notes_root(dir)), Some(Source::new("test")))
        .unwrap()
        .with_authority(&[policy])
        .unwrap()
}

pub fn backend(dir: &tempfile::TempDir) -> Arc<Backend> {
    policed_backend(dir, PolicyFragment::default())
}

pub fn policed_backend(dir: &tempfile::TempDir, policy: PolicyFragment) -> Arc<Backend> {
    Arc::new(
        Backend::new(BackendArgs {
            dir: Some(notes_root(dir).display().to_string()),
            source: Some("test".to_string()),
            policy: PolicyArgs {
                policy: Some(policy.to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap(),
    )
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
