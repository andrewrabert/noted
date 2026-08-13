use std::path::Path as StdPath;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

use noted::PolicyFragment;
use noted::error::{Result, rejected, unavailable};

use crate::authority::{Mint, Minter, OriginAuthority, Revoke, Verified};
use crate::db::Db;
use crate::service::{AuthService, DEFAULT_CREDENTIAL_TTL};
use crate::types::{Label, Owner, Password, Username};

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
    UserSetPolicy {
        name: String,
        policy: PolicyFragment,
    },
    UserList,
    UserGet {
        name: String,
    },
    UserRevoke {
        name: String,
    },
    UserRemove {
        name: String,
    },
    KeyCreate {
        label: String,
        policy: PolicyFragment,
        ttl: Option<noted::types::Ttl>,
    },
    KeyList {
        label: Option<String>,
    },
    KeyRevoke {
        by: Revoke,
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

/// The database and the credential authority one administrative connection
/// speaks to. Every key it hands out descends from the server's own credential.
pub struct Admin {
    service: Arc<AuthService>,
    minter: Arc<dyn Minter>,
}

impl Admin {
    pub fn new(service: Arc<AuthService>, minter: Arc<dyn Minter>) -> Admin {
        Admin { service, minter }
    }

    fn owner(&self) -> Result<Owner> {
        self.minter
            .own()
            .owner()
            .cloned()
            .ok_or_else(|| rejected("this server holds no credential of its own"))
    }
}

pub fn apply(admin: &Admin, req: AdminRequest) -> AdminResponse {
    let svc = &admin.service;
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
            AdminRequest::UserSetPolicy { name, policy } => {
                svc.user_set_policy(&Username::new(name)?, policy)?;
                json!({})
            }
            AdminRequest::UserList => to_value(svc.user_list()?)?,
            AdminRequest::UserGet { name } => {
                let name = Username::new(name)?;
                match svc.user_get(&name)? {
                    Some(user) => {
                        let minted = admin.minter.minted(&Owner::User(name))?;
                        json!({"user": to_value(user)?, "credentials": to_value(minted)?})
                    }
                    None => return Err(rejected(format!("no such user: '{name}'"))),
                }
            }
            AdminRequest::UserRevoke { name } => {
                let name = Username::new(name)?;
                svc.user_get(&name)?
                    .ok_or_else(|| rejected(format!("no such user: '{name}'")))?;
                to_value(
                    admin
                        .minter
                        .revoke(&Verified::as_owner(Owner::User(name)), &Revoke::All)?,
                )?
            }
            AdminRequest::UserRemove { name } => {
                svc.user_remove(&Username::new(name)?)?;
                json!({})
            }
            AdminRequest::KeyCreate { label, policy, ttl } => {
                let ask = Mint {
                    policy,
                    ttl: ttl.unwrap_or_else(|| svc.default_ttl()),
                    session: None,
                    label: Some(Label::new(label)?),
                };
                let minted = admin.minter.mint(admin.minter.own(), &ask)?;
                json!({
                    "macaroon": minted.macaroon.expose(),
                    "token_id": minted.token_id,
                    "fingerprint": minted.fingerprint,
                    "expires_at": minted.expires_at,
                })
            }
            AdminRequest::KeyList { label } => {
                let label = label.map(Label::new).transpose()?;
                let listed: Vec<_> = admin
                    .minter
                    .minted(&admin.owner()?)?
                    .into_iter()
                    .filter(|m| label.as_ref().is_none_or(|l| m.label.as_ref() == Some(l)))
                    .collect();
                to_value(listed)?
            }
            AdminRequest::KeyRevoke { by } => {
                to_value(admin.minter.revoke(admin.minter.own(), &by)?)?
            }
        })
    })();
    AdminResponse::from_result(result)
}

#[cfg(unix)]
pub async fn serve_socket(listener: UnixListener, admin: Admin) {
    let admin = Arc::new(admin);
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let admin = admin.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_conn(stream, admin).await {
                tracing::debug!("admin socket connection ended: {e}");
            }
        });
    }
}

#[cfg(unix)]
async fn serve_conn(stream: UnixStream, admin: Arc<Admin>) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<AdminRequest>(&line) {
            Ok(req) => {
                let admin = admin.clone();
                tokio::task::spawn_blocking(move || apply(&admin, req))
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

#[cfg(unix)]
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

#[cfg(unix)]
pub struct AdminClient {
    stream: BufReader<UnixStream>,
}

#[cfg(unix)]
impl AdminClient {
    pub async fn connect(path: &StdPath) -> Result<AdminClient> {
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
    Direct(Arc<Admin>),
    #[cfg(unix)]
    Socket(AdminClient),
}

impl AdminConn {
    /// The socket where one answers, else the database opened directly, whose
    /// mints descend from the stored server key alone. Callers must supply at
    /// least one of the two; naming the flags that carry them is the CLI's job.
    pub async fn open(
        admin_socket: Option<&StdPath>,
        auth_db: Option<&StdPath>,
    ) -> Result<AdminConn> {
        #[cfg(unix)]
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
        #[cfg(not(unix))]
        let _ = admin_socket;
        let Some(db_path) = auth_db else {
            return Err(rejected("an admin socket or an auth database is required"));
        };
        let db_path = db_path.to_path_buf();
        let db = tokio::task::spawn_blocking(move || Db::open(&db_path))
            .await
            .map_err(|e| unavailable(format!("admin: open task failed: {e}")))?
            .map_err(|e| {
                rejected(format!(
                    "{e} (if the server is running, connect to its admin socket)"
                ))
            })?;
        let service = Arc::new(AuthService::new(Arc::new(db), DEFAULT_CREDENTIAL_TTL));
        let minter = Arc::new(OriginAuthority::new(service.clone()));
        Ok(AdminConn::Direct(Arc::new(Admin::new(service, minter))))
    }

    pub async fn call(&mut self, req: AdminRequest) -> Result<Value> {
        match self {
            AdminConn::Direct(admin) => {
                let admin = admin.clone();
                tokio::task::spawn_blocking(move || apply(&admin, req))
                    .await
                    .map_err(|e| unavailable(format!("admin task failed: {e}")))?
                    .into_result()
            }
            #[cfg(unix)]
            AdminConn::Socket(client) => client.call(&req).await,
        }
    }
}
