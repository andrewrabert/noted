use std::sync::{Arc, LazyLock};

use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::{Value, json};

use crate::auth::AuthState;
use crate::mcp::McpContext;
use crate::relay::Relay;
use noted::error::NotedError;
use noted::{APP_NAME, NotedRoot, PolicyFragment, ToolCall};
use noted_auth::{Denial, Verified};
use url::form_urlencoded;

const MODULE: &str = include_str!(concat!(env!("OUT_DIR"), "/noted_ui.module.js"));

/// The page for an open server: tool calls need no bearer.
static OPEN_DOCUMENT: LazyLock<String> = LazyLock::new(|| page("open"));

/// The page for a server that mints tokens: tool calls need a bearer.
static BEARER_DOCUMENT: LazyLock<String> = LazyLock::new(|| page("bearer"));

/// The one document, wasm inside it, `data-auth` on `<html>` naming the mode.
fn page(auth: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en" data-auth="{auth}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{APP_NAME}</title>
<style>html,body{{margin:0;height:100%;overflow:hidden;background:#1a1b26}}</style>
</head>
<body>
<script type="module">
// Native editing surface only: the canvas remains the application's renderer.
// The browser owns clipboard gestures, text services, selection, and undo.
(() => {{
  const fields = new Map();
  let nextId = 0;
  let loginForm = null;
  let autofillTimer = null;
  function form() {{
    if (loginForm) return loginForm;
    loginForm = document.createElement("form");
    loginForm.id = "noted-login";
    loginForm.method = "post";
    loginForm.action = "/login";
    loginForm.autocomplete = "on";
    loginForm.style.display = "contents";
    const transaction = document.createElement("input");
    transaction.type = "hidden";
    transaction.name = "txn";
    transaction.value = new URLSearchParams(location.search).get("txn") || "";
    loginForm.append(transaction);
    loginForm.addEventListener("submit", event => {{
      event.preventDefault();
      const submit = [...fields.values()].find(field => field.purpose === "submit");
      if (submit && !submit.el.disabled) emit(submit, "submit");
    }});
    document.body.append(loginForm);
    // Extensions do not all dispatch input/change when filling a field.
    autofillTimer = setInterval(() => {{
      for (const field of fields.values()) detectAutofill(field);
    }}, 200);
    return loginForm;
  }}
  function detectAutofill(field) {{
    if ((field.purpose === "username" || field.purpose === "current-password") &&
        field.el.value !== field.observed && !field.composing) emit(field, "input");
  }}
  const style = document.createElement("style");
  style.textContent = `
    .noted-input {{
      opacity: 0; position: fixed; box-sizing: border-box; margin: 0; border: 0;
      border-radius: 0; outline: none; resize: none; appearance: none;
      background: transparent; color: transparent; caret-color: transparent;
      -webkit-text-fill-color: transparent; text-shadow: none; box-shadow: none;
      font-family: 'Noted Fira Sans', sans-serif; font-weight: 400;
      font-kerning: normal; font-variant-ligatures: normal; letter-spacing: normal;
      overflow: hidden; scrollbar-width: none; z-index: 1;
    }}
    .noted-input::selection {{ color: transparent; background: transparent; }}
    .noted-input::-webkit-scrollbar {{ display: none; }}
    .noted-input:autofill {{ transition: background-color 999999s; }}
    .noted-input:-webkit-autofill {{ transition: background-color 999999s; }}
  `;
  document.head.append(style);

  function emit(field, kind) {{
    const el = field.el;
    field.observed = el.value;
    field.seq += 1;
    field.send(JSON.stringify({{
      seq: field.seq, kind, value: el.value,
      start: el.selectionStart ?? 0, end: el.selectionEnd ?? 0,
      backward: el.selectionDirection === "backward",
      focused: document.activeElement === el,
      scroll: kind === "scroll" ? field.scrollDelta : 0,
    }}));
  }}

  function selected(field) {{
    return `${{field.el.selectionStart}}:${{field.el.selectionEnd}}:${{field.el.selectionDirection}}`;
  }}

  function selection(field) {{
    const current = selected(field);
    if (current !== field.selection) {{
      field.selection = current;
      emit(field, "selection");
    }}
  }}

  const api = {{
    async font(bytes) {{
      const face = new FontFace("Noted Fira Sans", bytes);
      document.fonts.add(await face.load());
    }},
    create(send, multiline, secure, label, purpose) {{
      const id = ++nextId;
      const el = document.createElement(purpose === "submit" ? "button" : multiline ? "textarea" : "input");
      if (!multiline) el.type = purpose === "submit" ? "submit" : secure ? "password" : "text";
      el.className = "noted-input";
      el.setAttribute("aria-label", label);
      el.autocomplete = purpose === "username" || purpose === "current-password" ? purpose : "off";
      if (purpose) {{
        el.id = `noted-login-${{purpose}}`;
        el.name = purpose === "current-password" ? "password" : purpose;
        if (purpose !== "submit") {{
          el.required = true;
          el.autocapitalize = "none";
        }}
      }}
      el.spellcheck = false;
      el.style.display = "none";
      const field = {{ el, send, purpose, observed: "", seq: 0, composing: false, selection: "", scroll: 0, scrollDelta: 0 }};
      fields.set(id, field);
      el.addEventListener("focus", () => emit(field, "focus"));
      el.addEventListener("blur", () => emit(field, "focus"));
      el.addEventListener("input", () => {{
        field.selection = selected(field);
        emit(field, "input");
      }});
      el.addEventListener("change", () => detectAutofill(field));
      el.addEventListener("select", () => selection(field));
      el.addEventListener("compositionstart", () => {{ field.composing = true; }});
      el.addEventListener("compositionend", () => {{
        field.composing = false;
        emit(field, "input");
      }});
      el.addEventListener("keydown", event => {{
        // Preserve all native clipboard/undo/navigation defaults. Iced receives
        // the resulting input/selection events, not a second keyboard edit.
        event.stopPropagation();
        if (!multiline && event.key === "Enter" && !event.isComposing) {{
          event.preventDefault();
          if (purpose === "current-password" || purpose === "submit") form().requestSubmit();
          else emit(field, "submit");
        }}
      }});
      if (secure) {{
        for (const name of ["copy", "cut"]) {{
          el.addEventListener(name, event => event.preventDefault());
        }}
      }}
      el.addEventListener("scroll", () => {{
        const lineHeight = Number.parseFloat(el.style.lineHeight) || 20;
        const line = Math.round(el.scrollTop / lineHeight);
        if (line !== field.scroll) {{
          field.scrollDelta = field.scroll - line;
          field.scroll = line;
          emit(field, "scroll");
        }}
      }});
      // Keep wheel scrolling within the native multiline editor. Single-line
      // inputs pass it through to the Iced canvas so their parent can scroll.
      el.addEventListener("wheel", event => {{
        if (multiline && el.scrollHeight > el.clientHeight) {{
          event.preventDefault();
          el.scrollTop += event.deltaY * (event.deltaMode === 1 ? Number.parseFloat(el.style.lineHeight) : 1);
        }} else {{
          document.querySelector("canvas")?.dispatchEvent(new WheelEvent("wheel", event));
        }}
      }}, {{ passive: false }});
      (purpose ? form() : document.body).append(el);
      return id;
    }},
    sync(id, json) {{
      const field = fields.get(id);
      if (!field) return;
      const s = JSON.parse(json), el = field.el;
      field.state = s;
      detectAutofill(field);
      const visible = s.clip[2] > 0 && s.clip[3] > 0;
      el.style.display = visible ? "block" : "none";
      el.disabled = field.purpose === "submit" && !s.enabled;
      el.readOnly = !s.enabled;
      el.tabIndex = s.enabled ? 0 : -1;
      el.style.pointerEvents = s.enabled ? "auto" : "none";
      el.style.left = `${{s.x}}px`;
      el.style.top = `${{s.y}}px`;
      el.style.width = `${{s.width}}px`;
      el.style.height = `${{s.height}}px`;
      el.style.padding = s.padding.map(p => `${{p}}px`).join(" ");
      el.style.fontSize = `${{s.size}}px`;
      el.style.lineHeight = `${{s.lineHeight}}px`;
      el.style.clipPath = `inset(${{Math.max(0, s.clip[1] - s.y)}}px ${{Math.max(0, s.x + s.width - s.clip[0] - s.clip[2])}}px ${{Math.max(0, s.y + s.height - s.clip[1] - s.clip[3])}}px ${{Math.max(0, s.clip[0] - s.x)}}px)`;
      // An older Iced frame must never overwrite newer typing or composition.
      if (s.ack !== null && s.ack >= field.seq && !field.composing) {{
        if (el.value !== s.value) {{
          const start = el.selectionStart, end = el.selectionEnd, direction = el.selectionDirection;
          el.value = s.value;
          if (typeof el.setSelectionRange === "function") {{
            el.setSelectionRange(Math.min(start, el.value.length), Math.min(end, el.value.length), direction);
          }}
          field.observed = el.value;
          field.selection = selected(field);
        }}
        if (visible && s.focused && document.activeElement !== el) el.focus({{ preventScroll: true }});
      }}
    }},
    credentials() {{
      if (!loginForm) return "null";
      return JSON.stringify([
        loginForm.elements.namedItem("username")?.value || "",
        loginForm.elements.namedItem("password")?.value || "",
      ]);
    }},
    remove(id) {{
      const field = fields.get(id);
      if (!field) return;
      // Remove listeners before dropping the Rust callback (blur can fire on removal).
      field.send = () => {{}};
      field.el.remove();
      fields.delete(id);
      if (loginForm && ![...fields.values()].some(field => field.purpose)) {{
        loginForm.remove(); loginForm = null;
        clearInterval(autofillTimer); autofillTimer = null;
      }}
    }},
  }};
  document.addEventListener("selectionchange", () => {{
    for (const field of fields.values()) {{
      if (document.activeElement === field.el) selection(field);
    }}
  }});
  globalThis.notedInput = api;
}})();
{MODULE}
</script>
</body>
</html>"#
    )
}

/// The page stamped with whether tool calls need a bearer.
pub(crate) fn document(requires_bearer: bool) -> Html<&'static str> {
    Html(if requires_bearer {
        BEARER_DOCUMENT.as_str()
    } else {
        OPEN_DOCUMENT.as_str()
    })
}

fn error_response(error: NotedError) -> Response {
    let status = match &error {
        NotedError::NotFound => StatusCode::NOT_FOUND,
        NotedError::Forbidden => StatusCode::FORBIDDEN,
        NotedError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        NotedError::Conflict => StatusCode::CONFLICT,
        NotedError::Unauthorized | NotedError::InvalidCredentials => StatusCode::UNAUTHORIZED,
        NotedError::UnknownTxn => StatusCode::BAD_REQUEST,
        NotedError::Unavailable(_)
        | NotedError::Io { .. }
        | NotedError::Json { .. }
        | NotedError::Db { .. }
        | NotedError::Http { .. } => StatusCode::SERVICE_UNAVAILABLE,
    };
    detail(status, error.message().into_owned())
}

fn detail(status: StatusCode, message: String) -> Response {
    (status, Json(json!({ "detail": message }))).into_response()
}

/// What the app answers from and the authentication derived for that same
/// source.
#[derive(Clone)]
pub struct Served {
    kind: ServedKind,
    auth: AuthState,
}

#[derive(Clone)]
enum ServedKind {
    Origin(NotedRoot),
    Relay(Arc<Relay>),
}

impl Served {
    pub fn origin(root: NotedRoot, auth: AuthState) -> Served {
        Served {
            kind: ServedKind::Origin(root),
            auth,
        }
    }

    pub fn relay(relay: Arc<Relay>) -> Served {
        let auth = AuthState::relay(relay.clone());
        Served {
            kind: ServedKind::Relay(relay),
            auth,
        }
    }

    pub(crate) fn auth(&self) -> &AuthState {
        &self.auth
    }
}

#[derive(Clone)]
struct AppState {
    auth: AuthState,
}

impl AppState {
    fn requires_bearer(&self) -> bool {
        self.auth.minter().is_some()
    }
}

pub fn build_app(served: Served) -> Router {
    let state = AppState {
        auth: served.auth.clone(),
    };
    let requires_bearer = state.requires_bearer();

    let inner = match &served.kind {
        ServedKind::Origin(root) => Router::new()
            .route("/tool/{name}", post(origin_tool))
            .with_state(root.clone())
            .nest_service("/mcp", mcp_service(root.clone())),
        ServedKind::Relay(relay) => Router::new()
            .route("/tool/{name}", post(relay_forward))
            .route("/mcp", post(relay_forward))
            .with_state(relay.clone()),
    };

    inner
        .merge(crate::auth::routes(served.auth))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            |State(state): State<AppState>, request, next| auth_middleware(state, request, next),
        ))
        .route("/", get(move || async move { document(requires_bearer) }))
}

fn mcp_service(root: NotedRoot) -> StreamableHttpService<McpContext, LocalSessionManager> {
    let context = crate::mcp::context(root);
    let mut config = StreamableHttpServerConfig::default();
    config.legacy_session_mode = false;
    config.json_response = true;
    config.allowed_hosts.clear();
    StreamableHttpService::new(
        move || Ok(context.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    )
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn accept(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::ACCEPT)?.to_str().ok()
}

/// The policy the request asks to be held to, outermost first. No `policy=`
/// is an empty ask, which narrows nothing.
fn query_policy(request: &axum::extract::Request) -> noted::error::Result<Vec<PolicyFragment>> {
    form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
        .filter(|(key, _)| key == "policy")
        .map(|(_, value)| value.parse())
        .collect()
}

/// The path the caller asked for, before any nested service stripped its
/// prefix: `/mcp/token` is no more public than `/mcp` itself.
fn requested_path(request: &axum::extract::Request) -> String {
    request
        .extensions()
        .get::<OriginalUri>()
        .map(|uri| uri.path().to_string())
        .unwrap_or_else(|| request.uri().path().to_string())
}

fn is_public(path: &str) -> bool {
    path.starts_with("/.well-known/")
        || matches!(path, "/register" | "/authorize" | "/login" | "/token")
}

async fn auth_middleware(
    state: AppState,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = requested_path(&request);
    if is_public(&path) {
        request.extensions_mut().insert(Verified::anonymous());
        return next.run(request).await;
    }
    let presented =
        bearer(request.headers()).map(noted_auth::types::CredentialPresentation::submitted);
    if presented.is_none() && state.requires_bearer() {
        return denial_response(&Denial::Unauthorized("unauthorized".into()), &state);
    }
    let verifier = state.auth.verifier().clone();
    match crate::auth::run_blocking(move || verifier.verify(presented.as_ref())).await {
        Ok(Ok(caller)) => match query_policy(&request) {
            Ok(query) => {
                request.extensions_mut().insert(query);
                request.extensions_mut().insert(caller);
                next.run(request).await
            }
            Err(error) => error_response(error),
        },
        Ok(Err(denial)) => denial_response(&denial, &state),
        Err(error) => detail(
            StatusCode::SERVICE_UNAVAILABLE,
            state.auth.relay_self_error(error).to_string(),
        ),
    }
}

fn denial_response(denial: &Denial, state: &AppState) -> Response {
    match denial {
        Denial::Malformed(message) => detail(StatusCode::BAD_REQUEST, message.clone()),
        Denial::Forbidden(message) => detail(StatusCode::FORBIDDEN, message.clone()),
        Denial::Unauthorized(_) => {
            let mut response = detail(StatusCode::UNAUTHORIZED, "unauthorized".to_string());
            if let Some(oauth) = state.auth.oauth()
                && let Ok(value) = HeaderValue::from_str(&oauth.resource_metadata_challenge())
            {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, value);
            }
            response
        }
    }
}

async fn origin_tool(
    State(root): State<NotedRoot>,
    Path(name): Path<String>,
    Extension(caller): Extension<Verified>,
    Extension(query): Extension<Vec<PolicyFragment>>,
    body: Bytes,
) -> Response {
    let args = if body.is_empty() {
        Value::Object(Default::default())
    } else {
        match serde_json::from_slice(&body) {
            Ok(args) => args,
            Err(e) => return detail(StatusCode::BAD_REQUEST, e.to_string()),
        }
    };
    match run(&root, &name, args, &caller, &query).await {
        Ok(output) => Json(json!({ "ok": output })).into_response(),
        Err(e) => error_response(e),
    }
}

async fn run(
    root: &NotedRoot,
    name: &str,
    args: Value,
    caller: &Verified,
    query: &[PolicyFragment],
) -> noted::Result<noted::tools::ToolOutput> {
    let call = ToolCall::raw(name, args)?;
    root.with_authority(caller.fragments())?
        .with_authority(query)?
        .invoke(&call)
        .await
}

async fn relay_forward(
    State(relay): State<Arc<Relay>>,
    OriginalUri(uri): OriginalUri,
    Extension(asked): Extension<Vec<PolicyFragment>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    relay
        .forward(uri.path(), accept(&headers), &asked, body)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use noted_client::Transport;

    #[tokio::test]
    async fn relay_middleware_blocking_failure_names_the_relays_listener_endpoint() {
        let bound = crate::serve::Bind::Tcp {
            host: "127.0.0.1".to_string(),
            port: 0,
        }
        .bind()
        .await
        .unwrap();
        let relay = Arc::new(
            Relay::open(
                None,
                PolicyFragment::default(),
                "http://upstream.test/internal".parse().unwrap(),
                &bound,
                Transport::Router(Router::new()),
            )
            .unwrap(),
        );
        let auth = AuthState::relay(relay);
        let error = crate::auth::run_blocking(|| panic!("verification failed"))
            .await
            .unwrap_err();

        let detail = auth.relay_self_error(error).to_string();
        assert!(detail.starts_with(&format!("{}: ", bound.endpoint())));
        assert!(detail.contains("blocking authentication task failed"));
    }

    #[tokio::test]
    async fn origin_middleware_blocking_failure_claims_no_listener_endpoint() {
        let auth = AuthState::open();
        let error = crate::auth::run_blocking(|| panic!("verification failed"))
            .await
            .unwrap_err();

        let detail = auth.relay_self_error(error).to_string();
        assert!(!detail.contains("http://"));
        assert!(detail.starts_with("blocking authentication task failed"));
    }
}
