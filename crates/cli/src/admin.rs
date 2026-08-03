use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde_json::Value;

use noted::error::{Result, rejected, unavailable};
use noted_auth::oauth::admin::{AdminConn, AdminRequest};
use noted_auth::oauth::service::{CredentialSummary, RevokeBy, UserSummary};
use noted_auth::oauth::types::Label;
use noted::types::Ttl;

use crate::config::{block_on, parse_ttl};
use crate::{EntryFlags, GlobalArgs};

#[derive(serde::Deserialize)]
struct UserGetResponse {
    user: UserSummary,
    credentials: Vec<CredentialSummary>,
}

#[derive(Args)]
struct AdminTransport {
    #[cfg(unix)]
    #[arg(long = "admin-socket", env = "NOTED_ADMIN_SOCKET", global = true)]
    admin_socket: Option<PathBuf>,
    #[arg(long = "auth-db", env = "NOTED_AUTH_DB", global = true)]
    auth_db: Option<PathBuf>,
}

impl AdminTransport {
    /// The sole adapter to core's admin connection: it owns the messages that
    /// name CLI flags and their environment variables.
    async fn open(&self) -> Result<AdminConn> {
        #[cfg(unix)]
        let socket = self.admin_socket.clone();
        #[cfg(not(unix))]
        let socket: Option<PathBuf> = None;
        if socket.is_none() && self.auth_db.is_none() {
            #[cfg(unix)]
            return Err(rejected(
                "--admin-socket or --auth-db (NOTED_ADMIN_SOCKET / NOTED_AUTH_DB) is required",
            ));
            #[cfg(not(unix))]
            return Err(rejected("--auth-db (NOTED_AUTH_DB) is required"));
        }
        AdminConn::open(socket.as_deref(), self.auth_db.as_deref()).await
    }
}

#[derive(Args)]
pub(crate) struct UserCmd {
    #[command(flatten)]
    transport: AdminTransport,
    #[command(subcommand)]
    sub: UserSub,
}

#[derive(Subcommand)]
enum UserSub {
    Add(UserNameArg),
    Passwd(UserNameArg),
    Policy(UserPolicyCmd),
    #[command(alias = "ls")]
    List(UserListCmd),
    Revoke(UserRevokeCmd),
    #[command(alias = "rm")]
    Remove(UserNameArg),
}

#[derive(Args)]
struct UserNameArg {
    name: String,
}

#[derive(Args)]
struct UserPolicyCmd {
    name: String,
    #[command(flatten)]
    entries: EntryFlags,
}

#[derive(Args)]
struct UserListCmd {
    name: Option<String>,
}

#[derive(Args)]
struct UserRevokeCmd {
    name: String,
    #[arg(long)]
    id: Option<String>,
}

#[derive(Args)]
pub(crate) struct KeyCmd {
    #[command(flatten)]
    transport: AdminTransport,
    #[command(subcommand)]
    sub: KeySub,
}

#[derive(Subcommand)]
enum KeySub {
    Create(KeyCreateCmd),
    Policy(KeyPolicyCmd),
    #[command(alias = "ls")]
    List(KeyListCmd),
    Revoke(KeyRevokeCmd),
}

#[derive(Args)]
struct KeyCreateCmd {
    label: String,
    #[command(flatten)]
    entries: EntryFlags,
    #[arg(long, value_parser = parse_ttl)]
    ttl: Option<Ttl>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct KeyPolicyCmd {
    label: Option<String>,
    #[arg(long, conflicts_with = "label")]
    id: Option<String>,
    #[command(flatten)]
    entries: EntryFlags,
}

#[derive(Args)]
struct KeyListCmd {
    label: Option<String>,
}

#[derive(Args)]
struct KeyRevokeCmd {
    #[arg(long)]
    label: Option<String>,
    #[arg(long, conflicts_with = "label")]
    id: Option<String>,
}

fn admin_one(t: &AdminTransport, req: AdminRequest) -> Result<Value> {
    block_on(async move {
        let mut conn = t.open().await?;
        conn.call(req).await
    })
}

fn format_ts(secs: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| secs.to_string())
}

fn from_response<T: serde::de::DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|e| unavailable(format!("bad admin response: {e}")))
}

fn print_credentials(creds: &[CredentialSummary]) {
    for c in creds {
        let expires = c.expires_at.format_utc();
        let label = c
            .label
            .as_ref()
            .map(|l| format!("  label={l}"))
            .unwrap_or_default();
        println!(
            "  {}  {:<8}{:<8}{}  expires {expires}{label}",
            c.credential_id,
            c.kind.as_str(),
            c.status.as_str(),
            c.fingerprint
        );
    }
}

fn prompt_password() -> Result<String> {
    use std::io::Write;
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "password: ");
    let _ = stderr.flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| rejected(format!("read password: {e}")))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

pub(crate) fn run_user(cmd: UserCmd, globals: &GlobalArgs) -> Result<()> {
    let t = &cmd.transport;
    match cmd.sub {
        UserSub::Add(a) => {
            let password = prompt_password()?;
            admin_one(
                t,
                AdminRequest::UserAdd {
                    name: a.name.clone(),
                    password,
                },
            )?;
            println!("added user {}", a.name);
        }
        UserSub::Passwd(a) => {
            let password = prompt_password()?;
            admin_one(
                t,
                AdminRequest::UserPasswd {
                    name: a.name.clone(),
                    password,
                },
            )?;
            println!("password changed for {}", a.name);
        }
        UserSub::Policy(c) => {
            admin_one(
                t,
                AdminRequest::UserSetPolicy {
                    name: c.name.clone(),
                    policy: globals.policy_args(&c.entries).held()?,
                },
            )?;
            println!("policy set for {}", c.name);
        }
        UserSub::List(l) => match l.name {
            None => {
                let users: Vec<UserSummary> = from_response(admin_one(t, AdminRequest::UserList)?)?;
                if users.is_empty() {
                    println!("no users");
                }
                for u in users {
                    println!("{}  {}", u.name, u.policy);
                }
            }
            Some(name) => {
                let resp: UserGetResponse =
                    from_response(admin_one(t, AdminRequest::UserGet { name: name.clone() })?)?;
                println!("user: {name}");
                println!("policy: {}", resp.user.policy);
                if !resp.credentials.is_empty() {
                    println!("credentials:");
                    print_credentials(&resp.credentials);
                }
            }
        },
        UserSub::Revoke(r) => {
            let v = admin_one(
                t,
                AdminRequest::UserRevoke {
                    name: r.name.clone(),
                    id: r.id,
                },
            )?;
            println!("revoked {}", v["revoked"].as_u64().unwrap_or(0));
        }
        UserSub::Remove(a) => {
            admin_one(
                t,
                AdminRequest::UserRemove {
                    name: a.name.clone(),
                },
            )?;
            println!("removed user {}", a.name);
        }
    }
    Ok(())
}

pub(crate) fn run_key(cmd: KeyCmd, globals: &GlobalArgs) -> Result<()> {
    let t = &cmd.transport;
    match cmd.sub {
        KeySub::Create(c) => {
            let policy = globals.policy_args(&c.entries).held()?;
            let label = c.label.clone();
            let ttl = c.ttl;
            let as_json = c.json;
            block_on(async move {
                let mut conn = t.open().await?;
                let minted = conn
                    .call(AdminRequest::KeyCreate { label, policy, ttl })
                    .await?;
                let credential_id = minted["credential_id"]
                    .as_str()
                    .ok_or_else(|| rejected("bad mint response"))?
                    .to_string();
                if as_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&minted).unwrap_or_default()
                    );
                } else {
                    println!("{}", minted["token"].as_str().unwrap_or(""));
                    eprintln!(
                        "credential-id {credential_id}  fingerprint {}  expires {}",
                        minted["fingerprint"].as_str().unwrap_or("?"),
                        minted["expires_at"]
                            .as_u64()
                            .map(format_ts)
                            .unwrap_or_default()
                    );
                    eprintln!("the secret is shown exactly once — it is not stored");
                }
                conn.call(AdminRequest::KeyFinalize { credential_id })
                    .await?;
                Ok(())
            })
        }
        KeySub::Policy(c) => {
            if c.label.is_none() && c.id.is_none() {
                return Err(rejected("setting a key policy needs a LABEL or --id"));
            }
            let v = admin_one(
                t,
                AdminRequest::KeySetPolicy {
                    label: c.label,
                    id: c.id,
                    policy: globals.policy_args(&c.entries).held()?,
                },
            )?;
            println!(
                "policy set for {} key(s)",
                v["updated"].as_u64().unwrap_or(0)
            );
            Ok(())
        }
        KeySub::List(l) => {
            let keys: Vec<CredentialSummary> =
                from_response(admin_one(t, AdminRequest::KeyList { label: l.label })?)?;
            if keys.is_empty() {
                println!("no keys");
            }
            for k in keys {
                let label = k.label.as_ref().map(Label::as_str).unwrap_or("-");
                let expires = k.expires_at.format_utc();
                let policy = k.policy.clone().unwrap_or_default();
                println!(
                    "{label}  {}  {:<8}{}  expires {expires}  {policy}",
                    k.credential_id,
                    k.status.as_str(),
                    k.fingerprint
                );
            }
            Ok(())
        }
        KeySub::Revoke(r) => {
            let by = match (r.label, r.id) {
                (Some(label), None) => RevokeBy::Label(Label::new(label)?),
                (None, Some(id)) => RevokeBy::Id(id.parse()?),
                (None, None) => {
                    use std::io::IsTerminal;
                    if std::io::stdin().is_terminal() {
                        return Err(rejected(
                            "key revoke needs --label, --id, or the secret piped on stdin",
                        ));
                    }
                    let mut line = String::new();
                    std::io::stdin()
                        .read_line(&mut line)
                        .map_err(|e| rejected(format!("read secret: {e}")))?;
                    let secret = line.trim();
                    if secret.is_empty() {
                        return Err(rejected("no secret on stdin"));
                    }
                    RevokeBy::from_secret(secret)
                }
                (Some(_), Some(_)) => unreachable!("clap conflicts_with"),
            };
            let v = admin_one(t, AdminRequest::KeyRevoke { by })?;
            println!("revoked {}", v["revoked"].as_u64().unwrap_or(0));
            Ok(())
        }
    }
}
