use noted::HttpUrl;
use std::pin::Pin;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait Threadsafe: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> Threadsafe for T {}
#[cfg(target_arch = "wasm32")]
pub(crate) trait Threadsafe {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> Threadsafe for T {}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) type Router = axum::Router;
#[cfg(target_arch = "wasm32")]
pub(crate) type Router = std::convert::Infallible;

#[cfg(not(target_arch = "wasm32"))]
fn authority(target: &HttpUrl) -> String {
    let url = target.as_url();
    match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        (None, _) => "localhost".to_string(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn route(
    router: &Router,
    target: &HttpUrl,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> std::result::Result<(u16, Option<String>, Vec<u8>), String> {
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    // a real client names the authority it dialed; a routed request carries no
    // socket to infer one from, so the target url supplies it
    let mut builder = Request::builder()
        .method("POST")
        .uri(target.path_and_query())
        .header("host", authority(target));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(axum::body::Body::from(body))
        .map_err(|e| e.to_string())?;
    let resp = router
        .clone()
        .oneshot(request)
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((status, content_type, bytes.to_vec()))
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn route(
    router: &Router,
    _target: &HttpUrl,
    _headers: &[(&str, &str)],
    _body: Vec<u8>,
) -> std::result::Result<(u16, Option<String>, Vec<u8>), String> {
    match *router {}
}
