use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::error::{rejected, unavailable, Result};
use crate::scope::StoredScope;

use super::db::Db;
use super::service::{AuthService, RevokeBy, ScopeEdit, DEFAULT_CREDENTIAL_TTL};
use super::types::{CredentialId, Label, Password, Username};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AdminRequest {
    UserAdd {
        name: String,
        password: String,
    },
    UserPasswd {
        name: String,
        password: String,
    },
    UserGrant {
        name: String,
        edit: ScopeEdit,
    },
    UserUngrant {
        name: String,
        n: usize,
    },
    UserList,
    UserGet {
        name: String,
    },
    UserRevoke {
        name: String,
        id: Option<String>,
    },
    UserRemove {
        name: String,
    },
    KeyCreate {
        label: String,
        scope: StoredScope,
        ttl: Option<crate::types::Ttl>,
    },
    KeyFinalize {
        credential_id: String,
    },
    KeyGrant {
        label: Option<String>,
        id: Option<String>,
        edit: ScopeEdit,
    },
    KeyUngrant {
        label: Option<String>,
        id: Option<String>,
        n: usize,
    },
    KeyList {
        label: Option<String>,
    },
    KeyRevoke {
        by: RevokeBy,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminErrorKind {
    Rejected,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AdminResponse {
    #[serde(rename = "ok")]
    Ok(Value),
    #[serde(rename = "error")]
    Err {
        kind: AdminErrorKind,
        message: String,
    },
}

impl AdminResponse {
    fn from_result(r: Result<Value>) -> AdminResponse {
        match r {
            Ok(v) => AdminResponse::Ok(v),
            Err(e) => AdminResponse::Err {
                kind: if e.is_rejection() {
                    AdminErrorKind::Rejected
                } else {
                    AdminErrorKind::Unavailable
                },
                message: e.message().to_string(),
            },
        }
    }

    pub fn into_result(self) -> Result<Value> {
        match self {
            AdminResponse::Ok(v) => Ok(v),
            AdminResponse::Err { kind, message } => Err(match kind {
                AdminErrorKind::Rejected => rejected(message),
                AdminErrorKind::Unavailable => unavailable(message),
            }),
        }
    }
}

fn to_value<T: Serialize>(v: T) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| unavailable(format!("serialize admin response: {e}")))
}

pub fn apply(svc: &AuthService, req: AdminRequest) -> AdminResponse {
    let result: Result<Value> = (|| {
        Ok(match req {
            AdminRequest::UserAdd { name, password } => {
                svc.user_add(&Username::new(name)?, &Password::new(password))?;
                json!({})
            }
            AdminRequest::UserPasswd { name, password } => {
                svc.user_passwd(&Username::new(name)?, &Password::new(password))?;
                json!({})
            }
            AdminRequest::UserGrant { name, edit } => {
                svc.user_grant(&Username::new(name)?, edit)?;
                json!({})
            }
            AdminRequest::UserUngrant { name, n } => {
                svc.user_ungrant(&Username::new(name)?, n)?;
                json!({})
            }
            AdminRequest::UserList => to_value(svc.user_list()?)?,
            AdminRequest::UserGet { name } => {
                let name = Username::new(name)?;
                match svc.user_get(&name)? {
                    Some(user) => {
                        let creds = svc.user_credentials(&name)?;
                        json!({"user": to_value(user)?, "credentials": to_value(creds)?})
                    }
                    None => return Err(rejected(format!("no such user: '{name}'"))),
                }
            }
            AdminRequest::UserRevoke { name, id } => {
                let id = id.map(CredentialId::new).transpose()?;
                let n = svc.user_revoke(&Username::new(name)?, id.as_ref())?;
                json!({ "revoked": n })
            }
            AdminRequest::UserRemove { name } => {
                svc.user_remove(&Username::new(name)?)?;
                json!({})
            }
            AdminRequest::KeyCreate { label, scope, ttl } => {
                to_value(svc.key_create(&Label::new(label)?, scope, ttl)?)?
            }
            AdminRequest::KeyFinalize { credential_id } => {
                svc.key_finalize(&CredentialId::new(credential_id)?)?;
                json!({})
            }
            AdminRequest::KeyGrant { label, id, edit } => {
                let label = label.map(Label::new).transpose()?;
                let id = id.map(CredentialId::new).transpose()?;
                let n = svc.key_grant(label.as_ref(), id.as_ref(), edit)?;
                json!({ "granted": n })
            }
            AdminRequest::KeyUngrant { label, id, n } => {
                let label = label.map(Label::new).transpose()?;
                let id = id.map(CredentialId::new).transpose()?;
                svc.key_ungrant(label.as_ref(), id.as_ref(), n)?;
                json!({})
            }
            AdminRequest::KeyList { label } => {
                let label = label.map(Label::new).transpose()?;
                to_value(svc.key_list(label.as_ref())?)?
            }
            AdminRequest::KeyRevoke { by } => json!({ "revoked": svc.key_revoke(&by)? }),
        })
    })();
    AdminResponse::from_result(result)
}

pub fn bind_socket(path: &Path) -> Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|e| rejected(format!("admin socket: cannot replace {e}")))?;
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| rejected(format!("admin socket: {e}")))?;
        }
    }
    let listener =
        UnixListener::bind(path).map_err(|e| rejected(format!("admin socket: bind: {e}")))?;
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(0o600)
    };
    std::fs::set_permissions(path, mode)
        .map_err(|e| unavailable(format!("admin socket: chmod: {e}")))?;
    Ok(listener)
}

pub async fn serve_socket(listener: UnixListener, svc: Arc<AuthService>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let svc = svc.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_conn(stream, svc).await {
                tracing::debug!("admin socket connection ended: {e}");
            }
        });
    }
}

async fn serve_conn(stream: UnixStream, svc: Arc<AuthService>) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<AdminRequest>(&line) {
            Ok(req) => {
                let svc = svc.clone();
                tokio::task::spawn_blocking(move || apply(&svc, req))
                    .await
                    .unwrap_or_else(|e| AdminResponse::Err {
                        kind: AdminErrorKind::Unavailable,
                        message: format!("admin task failed: {e}"),
                    })
            }
            Err(e) => {
                let resp = AdminResponse::Err {
                    kind: AdminErrorKind::Rejected,
                    message: format!("malformed admin request: {e}"),
                };
                write_line(&mut write, &resp).await?;
                break;
            }
        };
        write_line(&mut write, &response).await?;
    }
    Ok(())
}

async fn write_line(
    write: &mut tokio::net::unix::OwnedWriteHalf,
    resp: &AdminResponse,
) -> std::io::Result<()> {
    let mut buf = serde_json::to_vec(resp).unwrap_or_else(|_| {
        br#"{"error":{"kind":"unavailable","message":"serialization failed"}}"#.to_vec()
    });
    buf.push(b'\n');
    write.write_all(&buf).await
}

pub struct AdminClient {
    stream: BufReader<UnixStream>,
}

impl AdminClient {
    pub async fn connect(path: &Path) -> Result<AdminClient> {
        let stream = UnixStream::connect(path)
            .await
            .map_err(|e| unavailable(format!("admin socket: connect: {e}")))?;
        Ok(AdminClient {
            stream: BufReader::new(stream),
        })
    }

    pub async fn call(&mut self, req: &AdminRequest) -> Result<Value> {
        let mut buf = serde_json::to_vec(req)
            .map_err(|e| unavailable(format!("serialize admin request: {e}")))?;
        buf.push(b'\n');
        self.stream
            .get_mut()
            .write_all(&buf)
            .await
            .map_err(|e| unavailable(format!("admin socket: write: {e}")))?;
        let mut line = String::new();
        let n = self
            .stream
            .read_line(&mut line)
            .await
            .map_err(|e| unavailable(format!("admin socket: read: {e}")))?;
        if n == 0 {
            return Err(unavailable("admin socket: server closed the connection"));
        }
        serde_json::from_str::<AdminResponse>(&line)
            .map_err(|e| unavailable(format!("admin socket: bad response: {e}")))?
            .into_result()
    }
}

pub enum AdminConn {
    Direct(AuthService),
    Socket(AdminClient),
}

impl AdminConn {
    pub async fn open(admin_socket: Option<&Path>, auth_db: Option<&Path>) -> Result<AdminConn> {
        if let Some(path) = admin_socket {
            match AdminClient::connect(path).await {
                Ok(client) => return Ok(AdminConn::Socket(client)),
                Err(e) => {
                    if auth_db.is_none() {
                        return Err(e);
                    }
                }
            }
        }
        let Some(db_path) = auth_db else {
            return Err(rejected(
                "--admin-socket or --auth-db (NOTED_ADMIN_SOCKET / NOTED_AUTH_DB) is required",
            ));
        };
        let db = Db::open(db_path).map_err(|e| {
            rejected(format!(
                "{e} (if the server is running, use --admin-socket)"
            ))
        })?;
        Ok(AdminConn::Direct(AuthService::new(
            Arc::new(db),
            DEFAULT_CREDENTIAL_TTL,
        )))
    }

    pub async fn call(&mut self, req: AdminRequest) -> Result<Value> {
        match self {
            AdminConn::Direct(svc) => apply(svc, req).into_result(),
            AdminConn::Socket(client) => client.call(&req).await,
        }
    }
}
