use std::path::Path;
use std::sync::Arc;

use noted::error::{Result, rejected, unavailable};
use noted_auth::Db;
use noted_auth::administration::{AdminCommand, AdminOutcome, Administration, UserDetails};
use noted_auth::authority::{Minted, OriginAuthority};
use noted_auth::service::AuthService;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum AdminRequest {
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
        policy: noted::PolicyFragment,
    },
    UserList,
    UserGet {
        name: String,
    },
    UserRemove {
        name: String,
    },
    KeyCreate {
        policy: noted::PolicyFragment,
    },
    KeyList,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum AdminErrorKind {
    Rejected,
    Unavailable,
}

#[derive(Deserialize)]
enum AdminResponse {
    #[serde(rename = "ok")]
    Ok(Value),
    #[serde(rename = "error")]
    Err {
        kind: AdminErrorKind,
        message: String,
    },
}

#[derive(Deserialize)]
struct EncodedMinted {
    macaroon: noted_auth::credential::Macaroon,
    token_id: noted_auth::credential::MacaroonId,
    fingerprint: noted_auth::types::Fingerprint,
}

impl AdminRequest {
    fn from_command(command: &AdminCommand) -> AdminRequest {
        match command {
            AdminCommand::AddUser { username, password } => AdminRequest::UserAdd {
                name: username.as_str().to_string(),
                password: password.expose().to_string(),
            },
            AdminCommand::ReplaceUserPassword { username, password } => AdminRequest::UserPasswd {
                name: username.as_str().to_string(),
                password: password.expose().to_string(),
            },
            AdminCommand::ReplaceUserPolicy { username, policy } => AdminRequest::UserSetPolicy {
                name: username.as_str().to_string(),
                policy: policy.clone(),
            },
            AdminCommand::ListUsers => AdminRequest::UserList,
            AdminCommand::GetUser { username } => AdminRequest::UserGet {
                name: username.as_str().to_string(),
            },
            AdminCommand::RemoveUser { username } => AdminRequest::UserRemove {
                name: username.as_str().to_string(),
            },
            AdminCommand::CreateKey { policy } => AdminRequest::KeyCreate {
                policy: policy.clone(),
            },
            AdminCommand::ListKeys => AdminRequest::KeyList,
        }
    }
}

impl AdminResponse {
    fn into_outcome(self, command: &AdminCommand) -> Result<AdminOutcome> {
        let value = match self {
            AdminResponse::Ok(value) => value,
            AdminResponse::Err { kind, message } => {
                return Err(match kind {
                    AdminErrorKind::Rejected => rejected(message),
                    AdminErrorKind::Unavailable => unavailable(message),
                });
            }
        };
        fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
            serde_json::from_value(value)
                .map_err(|error| unavailable(format!("bad admin response: {error}")))
        }
        Ok(match command {
            AdminCommand::AddUser { .. }
            | AdminCommand::ReplaceUserPassword { .. }
            | AdminCommand::ReplaceUserPolicy { .. }
            | AdminCommand::RemoveUser { .. } => AdminOutcome::Completed,
            AdminCommand::ListUsers => AdminOutcome::Users(decode(value)?),
            AdminCommand::GetUser { .. } => AdminOutcome::User(decode::<UserDetails>(value)?),
            AdminCommand::CreateKey { .. } => {
                let minted: EncodedMinted = decode(value)?;
                AdminOutcome::Minted(Minted {
                    macaroon: minted.macaroon,
                    token_id: minted.token_id,
                    fingerprint: minted.fingerprint,
                })
            }
            AdminCommand::ListKeys => AdminOutcome::Credentials(decode(value)?),
        })
    }
}

pub struct AdminConnection {
    inner: AdminConnectionInner,
}

enum AdminConnectionInner {
    Direct(Arc<Administration>),
    #[cfg(unix)]
    Socket(AdminSocketClient),
}

#[cfg(unix)]
struct AdminSocketClient {
    stream: BufReader<UnixStream>,
}

#[cfg(unix)]
impl AdminSocketClient {
    async fn connect(path: &Path) -> Result<AdminSocketClient> {
        let stream = UnixStream::connect(path)
            .await
            .map_err(|error| unavailable(format!("admin socket: connect: {error}")))?;
        Ok(AdminSocketClient {
            stream: BufReader::new(stream),
        })
    }

    async fn call(&mut self, command: &AdminCommand) -> Result<AdminOutcome> {
        let request = AdminRequest::from_command(command);
        let mut bytes = serde_json::to_vec(&request)
            .map_err(|error| unavailable(format!("serialize admin request: {error}")))?;
        bytes.push(b'\n');
        self.stream
            .get_mut()
            .write_all(&bytes)
            .await
            .map_err(|error| unavailable(format!("admin socket: write: {error}")))?;
        let mut line = String::new();
        let read = self
            .stream
            .read_line(&mut line)
            .await
            .map_err(|error| unavailable(format!("admin socket: read: {error}")))?;
        if read == 0 {
            return Err(unavailable("admin socket: server closed the connection"));
        }
        serde_json::from_str::<AdminResponse>(&line)
            .map_err(|error| unavailable(format!("admin socket: bad response: {error}")))?
            .into_outcome(command)
    }
}

impl AdminConnection {
    pub async fn open(
        admin_socket: Option<&Path>,
        auth_db: Option<&Path>,
    ) -> Result<AdminConnection> {
        #[cfg(unix)]
        if let Some(path) = admin_socket {
            match AdminSocketClient::connect(path).await {
                Ok(client) => {
                    return Ok(AdminConnection {
                        inner: AdminConnectionInner::Socket(client),
                    });
                }
                Err(error) if auth_db.is_none() => return Err(error),
                Err(_) => {}
            }
        }
        #[cfg(not(unix))]
        let _ = admin_socket;

        let Some(path) = auth_db else {
            return Err(rejected("an admin socket or an auth database is required"));
        };
        let path = path.to_path_buf();
        let administration = tokio::task::spawn_blocking(move || -> Result<Arc<Administration>> {
            let db = Db::open(&path)?;
            let service = Arc::new(AuthService::new(Arc::new(db)));
            let minter = Arc::new(OriginAuthority::new(service.clone()));
            Ok(Arc::new(Administration::new(service, minter)))
        })
        .await
        .map_err(|error| unavailable(format!("admin: open task failed: {error}")))?
        .map_err(|error| {
            rejected(format!(
                "{error} (if the server is running, connect to its admin socket)"
            ))
        })?;
        Ok(AdminConnection {
            inner: AdminConnectionInner::Direct(administration),
        })
    }

    pub async fn call(&mut self, command: AdminCommand) -> Result<AdminOutcome> {
        match &mut self.inner {
            AdminConnectionInner::Direct(administration) => {
                let administration = administration.clone();
                tokio::task::spawn_blocking(move || administration.execute(command))
                    .await
                    .map_err(|error| unavailable(format!("admin task failed: {error}")))?
            }
            #[cfg(unix)]
            AdminConnectionInner::Socket(client) => client.call(&command).await,
        }
    }
}
