use std::sync::Arc;

use noted::error::{Result, json_error};
use noted_auth::administration::{
    AdminCommand, AdminCredentialLifetime, AdminOutcome, Administration,
};
use noted_auth::types::{Password, Username};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(test)]
mod tests;

#[derive(Deserialize)]
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
    UserRevoke {
        name: String,
    },
    UserRemove {
        name: String,
    },
    KeyCreate {
        policy: noted::PolicyFragment,
        ttl: Option<noted::types::Ttl>,
    },
    KeyList,
    KeyRevoke {
        by: noted_auth::authority::Revoke,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum AdminErrorKind {
    Rejected,
    Unavailable,
}

#[derive(Serialize)]
enum AdminResponse {
    #[serde(rename = "ok")]
    Ok(Value),
    #[serde(rename = "error")]
    Err {
        kind: AdminErrorKind,
        message: String,
    },
}

impl AdminRequest {
    fn into_command(self) -> Result<AdminCommand> {
        Ok(match self {
            AdminRequest::UserAdd { name, password } => AdminCommand::AddUser {
                username: Username::new(name)?,
                password: Password::new(password),
            },
            AdminRequest::UserPasswd { name, password } => AdminCommand::ReplaceUserPassword {
                username: Username::new(name)?,
                password: Password::new(password),
            },
            AdminRequest::UserSetPolicy { name, policy } => AdminCommand::ReplaceUserPolicy {
                username: Username::new(name)?,
                policy,
            },
            AdminRequest::UserList => AdminCommand::ListUsers,
            AdminRequest::UserGet { name } => AdminCommand::GetUser {
                username: Username::new(name)?,
            },
            AdminRequest::UserRevoke { name } => AdminCommand::RevokeUser {
                username: Username::new(name)?,
            },
            AdminRequest::UserRemove { name } => AdminCommand::RemoveUser {
                username: Username::new(name)?,
            },
            AdminRequest::KeyCreate { policy, ttl } => AdminCommand::CreateKey {
                policy,
                lifetime: ttl
                    .map(AdminCredentialLifetime::Explicit)
                    .unwrap_or(AdminCredentialLifetime::Default),
            },
            AdminRequest::KeyList => AdminCommand::ListKeys,
            AdminRequest::KeyRevoke { by } => AdminCommand::RevokeKey { revocation: by },
        })
    }
}

fn to_value<T: Serialize>(value: T) -> Result<Value> {
    serde_json::to_value(value).map_err(|error| json_error("serialize admin response", error))
}

impl AdminResponse {
    fn from_domain(result: Result<AdminOutcome>) -> AdminResponse {
        match result.and_then(|outcome| {
            Ok(match outcome {
                AdminOutcome::Completed => json!({}),
                AdminOutcome::Users(users) => to_value(users)?,
                AdminOutcome::User(details) => to_value(details)?,
                AdminOutcome::Minted(minted) => json!({
                    "macaroon": minted.macaroon.expose(),
                    "token_id": minted.token_id,
                    "fingerprint": minted.fingerprint,
                    "expires_at": minted.expires_at,
                }),
                AdminOutcome::Credentials(credentials) => to_value(credentials)?,
                AdminOutcome::Withdrawn(withdrawn) => to_value(withdrawn)?,
            })
        }) {
            Ok(value) => AdminResponse::Ok(value),
            Err(error) => AdminResponse::Err {
                kind: if error.is_rejection() {
                    AdminErrorKind::Rejected
                } else {
                    AdminErrorKind::Unavailable
                },
                message: error.message().to_string(),
            },
        }
    }
}

#[cfg(unix)]
pub(crate) async fn serve_socket(listener: UnixListener, administration: Administration) {
    let administration = Arc::new(administration);
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let administration = administration.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_conn(stream, administration).await {
                tracing::debug!("admin socket connection ended: {error}");
            }
        });
    }
}

#[cfg(unix)]
async fn serve_conn(
    stream: UnixStream,
    administration: Arc<Administration>,
) -> std::io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<AdminRequest>(&line) {
            Ok(request) => match request.into_command() {
                Ok(command) => {
                    let administration = administration.clone();
                    tokio::task::spawn_blocking(move || administration.execute(command))
                        .await
                        .map(AdminResponse::from_domain)
                        .unwrap_or_else(|error| AdminResponse::Err {
                            kind: AdminErrorKind::Unavailable,
                            message: format!("admin task failed: {error}"),
                        })
                }
                Err(error) => AdminResponse::from_domain(Err(error)),
            },
            Err(error) => {
                let response = AdminResponse::Err {
                    kind: AdminErrorKind::Rejected,
                    message: format!("malformed admin request: {error}"),
                };
                write_line(&mut write, &response).await?;
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
    response: &AdminResponse,
) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(response).unwrap_or_else(|_| {
        br#"{"error":{"kind":"unavailable","message":"serialization failed"}}"#.to_vec()
    });
    bytes.push(b'\n');
    write.write_all(&bytes).await
}
