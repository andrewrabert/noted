use noted::error::NotedError;
use noted::tools::ToolOutput;
use noted::{Bearer, ToolCall};
use noted_client::{Backend, BackendArgs, Transport};
use serde_json::json;

fn dialing(router: axum::Router, token: Option<&str>) -> Backend {
    Backend::new(BackendArgs::Remote {
        endpoint: "http://test".parse().unwrap(),
        bearer: token.map(Bearer::new),
        transport: Transport::Router(router),
    })
    .unwrap()
}

async fn invoke(
    backend: &Backend,
    name: &str,
    args: serde_json::Value,
) -> noted::Result<ToolOutput> {
    let call = ToolCall::raw(name, args)?;
    backend.invoke(&call).await
}

fn canned(status: u16, body: &'static str) -> axum::Router {
    use axum::http::StatusCode;
    use axum::routing::post;
    axum::Router::new().route(
        "/tool/{name}",
        post(move || async move { (StatusCode::from_u16(status).unwrap(), body) }),
    )
}

async fn invoke_canned(status: u16, body: &'static str) -> Result<ToolOutput, NotedError> {
    let backend = dialing(canned(status, body), None);
    invoke(&backend, "ReadNote", json!({"path": "a.md"})).await
}

#[tokio::test]
async fn http_missing_ok_key_is_unavailable() {
    let err = invoke_canned(200, "{\"nope\": 1}").await.unwrap_err();
    let NotedError::Unavailable(msg) = &err else {
        panic!("expected Unavailable, got {err:?}");
    };
    assert!(msg.contains("malformed"));
}

#[tokio::test]
async fn http_non_json_body_is_json_error() {
    let err = invoke_canned(200, "not json").await.unwrap_err();
    let NotedError::Json { context, source } = &err else {
        panic!("expected Json, got {err:?}");
    };
    assert!(context.contains("malformed"));
    assert!(std::error::Error::source(&err).is_some());
    let _ = source;
}

#[tokio::test]
async fn http_4xx_without_detail_falls_back() {
    let err = invoke_canned(400, "{\"other\": 1}").await.unwrap_err();
    let NotedError::InvalidInput(msg) = &err else {
        panic!("expected InvalidInput, got {err:?}");
    };
    assert!(msg.contains("HTTP 400"));
}

#[tokio::test]
async fn http_5xx_without_detail_falls_back() {
    let err = invoke_canned(500, "{}").await.unwrap_err();
    let NotedError::Unavailable(msg) = &err else {
        panic!("expected Unavailable, got {err:?}");
    };
    assert!(msg.contains("HTTP 500"));
}

#[tokio::test]
async fn http_detail_is_surfaced() {
    let err = invoke_canned(400, "{\"detail\": \"boom detail\"}")
        .await
        .unwrap_err();
    assert!(err.message().contains("boom detail"));
}

#[tokio::test]
async fn local_backend_invokes_core_tools_and_enforces_policy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.md"), "hello\n").unwrap();
    let local = |policy| {
        Backend::new(BackendArgs::Local {
            dir: noted::NotedDir::new(dir.path().to_path_buf()),
            source: None,
            policy,
        })
        .unwrap()
    };
    let backend = local(noted::PolicyArgs::default());
    let root =
        noted::NotedRoot::open(noted::NotedDir::new(dir.path().to_path_buf()), None).unwrap();
    let call = ToolCall::raw("ReadNote", json!({"path": "a.md"})).unwrap();
    assert_eq!(
        serde_json::to_value(backend.invoke(&call).await.unwrap()).unwrap(),
        serde_json::to_value(root.invoke(&call).await.unwrap()).unwrap(),
    );
    let confined = local(noted::PolicyArgs {
        policy: Some(r#"{"access":{"read":false,"write":false}}"#.to_string()),
        ..Default::default()
    });
    assert!(matches!(
        confined.invoke(&call).await,
        Err(NotedError::Forbidden)
    ));
    assert!(backend.submit_txn("txn", "user", "password").await.is_err());
}
