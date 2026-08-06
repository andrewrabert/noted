use clap::{Args, Subcommand};
use serde_json::Value;

use noted::error::{Result, rejected, unavailable};
use noted::types::Ttl;
use noted_auth::oauth::admin::{AdminConn, AdminRequest};
use noted_auth::oauth::service::{CredentialSummary, RevokeBy, UserSummary};
use noted_auth::oauth::types::Label;

use crate::args::{AuthPaths, EntryFlags, parse_ttl};
use crate::config::Config;

#[derive(serde::Deserialize)]
struct UserGetResponse {
    user: UserSummary,
    credentials: Vec<CredentialSummary>,
}

impl AuthPaths {
    /// Connects to a running server's admin socket where available, else opens
    /// the auth database. It owns the messages that name CLI flags and their
    /// environment variables.
    pub(crate) async fn admin_conn(&self) -> Result<AdminConn> {
        #[cfg(unix)]
        let socket = self.admin_socket.clone();
        #[cfg(not(unix))]
        let socket: Option<std::path::PathBuf> = None;
        if socket.is_none() && self.auth_db.is_none() {
            #[cfg(unix)]
            return Err(rejected("--admin-socket or --auth-db is required"));
            #[cfg(not(unix))]
            return Err(rejected("--auth-db is required"));
        }
        AdminConn::open(socket.as_deref(), self.auth_db.as_deref()).await
    }
}

#[derive(Args)]
pub(crate) struct UserCmd {
    #[command(flatten)]
    paths: AuthPaths,
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
    paths: AuthPaths,
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

async fn admin_one(paths: &AuthPaths, req: AdminRequest) -> Result<Value> {
    let mut conn = paths.admin_conn().await?;
    conn.call(req).await
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

pub(crate) async fn run_user(cmd: UserCmd, config: &Config) -> Result<()> {
    let t = &cmd.paths;
    match cmd.sub {
        UserSub::Add(a) => {
            let password = crate::prompt::password().await?;
            admin_one(
                t,
                AdminRequest::UserAdd {
                    name: a.name.clone(),
                    password,
                },
            )
            .await?;
            println!("added user {}", a.name);
        }
        UserSub::Passwd(a) => {
            let password = crate::prompt::password().await?;
            admin_one(
                t,
                AdminRequest::UserPasswd {
                    name: a.name.clone(),
                    password,
                },
            )
            .await?;
            println!("password changed for {}", a.name);
        }
        UserSub::Policy(c) => {
            admin_one(
                t,
                AdminRequest::UserSetPolicy {
                    name: c.name.clone(),
                    policy: config.policy_fragment(&c.entries)?,
                },
            )
            .await?;
            println!("policy set for {}", c.name);
        }
        UserSub::List(l) => match l.name {
            None => {
                let users: Vec<UserSummary> =
                    from_response(admin_one(t, AdminRequest::UserList).await?)?;
                if users.is_empty() {
                    println!("no users");
                }
                for u in users {
                    println!("{}  {}", u.name, u.policy);
                }
            }
            Some(name) => {
                let resp: UserGetResponse = from_response(
                    admin_one(t, AdminRequest::UserGet { name: name.clone() }).await?,
                )?;
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
            )
            .await?;
            println!("revoked {}", v["revoked"].as_u64().unwrap_or(0));
        }
        UserSub::Remove(a) => {
            admin_one(
                t,
                AdminRequest::UserRemove {
                    name: a.name.clone(),
                },
            )
            .await?;
            println!("removed user {}", a.name);
        }
    }
    Ok(())
}

pub(crate) async fn run_key(cmd: KeyCmd, config: &Config) -> Result<()> {
    let t = &cmd.paths;
    match cmd.sub {
        KeySub::Create(c) => {
            let policy = config.policy_fragment(&c.entries)?;
            let label = c.label.clone();
            let ttl = c.ttl;
            let as_json = c.json;
            let mut conn = t.admin_conn().await?;
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
                    policy: config.policy_fragment(&c.entries)?,
                },
            )
            .await?;
            println!(
                "policy set for {} key(s)",
                v["updated"].as_u64().unwrap_or(0)
            );
            Ok(())
        }
        KeySub::List(l) => {
            let keys: Vec<CredentialSummary> =
                from_response(admin_one(t, AdminRequest::KeyList { label: l.label }).await?)?;
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
                    let secret = crate::prompt::piped_line().await?.ok_or_else(|| {
                        rejected("key revoke needs --label, --id, or the secret piped on stdin")
                    })?;
                    if secret.is_empty() {
                        return Err(rejected("no secret on stdin"));
                    }
                    RevokeBy::from_secret(&secret)
                }
                (Some(_), Some(_)) => unreachable!("clap conflicts_with"),
            };
            let v = admin_one(t, AdminRequest::KeyRevoke { by }).await?;
            println!("revoked {}", v["revoked"].as_u64().unwrap_or(0));
            Ok(())
        }
    }
}
