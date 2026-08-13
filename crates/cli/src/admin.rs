use clap::{Args, Subcommand};
use serde_json::Value;

use noted::error::{Result, rejected, unavailable};
use noted::types::Ttl;
use noted_auth::admin::{AdminConn, AdminRequest};
use noted_auth::authority::Revoke;
use noted_auth::service::{MintSummary, UserSummary};
use noted_auth::types::Label;
use noted_client::authclient::Granted;

use crate::args::{AuthPaths, EntryFlags, parse_ttl};
use crate::config::Config;
use crate::settings::{Flags, Layer, Variable};

#[derive(serde::Deserialize)]
struct UserGetResponse {
    user: UserSummary,
    credentials: Vec<MintSummary>,
}

/// Connects to a running server's admin socket where available, else opens the
/// auth database. It owns the messages that name CLI flags.
async fn admin_conn(config: &Config) -> Result<AdminConn> {
    #[cfg(unix)]
    let socket = config.setting(Variable::AdminSocket);
    #[cfg(not(unix))]
    let socket: Option<&str> = None;
    let auth_db = config.setting(Variable::AuthDb);
    if socket.is_none() && auth_db.is_none() {
        #[cfg(unix)]
        return Err(rejected("--admin-socket or --auth-db is required"));
        #[cfg(not(unix))]
        return Err(rejected("--auth-db is required"));
    }
    AdminConn::open(
        socket.map(std::path::Path::new),
        auth_db.map(std::path::Path::new),
    )
    .await
}

#[derive(Args)]
pub(crate) struct UserCmd {
    #[command(flatten)]
    paths: AuthPaths,
    #[command(subcommand)]
    sub: UserSub,
}

impl Flags for UserCmd {
    fn write(&self, layer: &mut Layer) {
        self.paths.write(layer);
    }
}

#[derive(Subcommand)]
enum UserSub {
    Add(UserNameArg),
    Passwd(UserNameArg),
    Policy(UserPolicyCmd),
    #[command(alias = "ls")]
    List(UserListCmd),
    Revoke(UserNameArg),
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
pub(crate) struct KeyCmd {
    #[command(flatten)]
    paths: AuthPaths,
    #[command(subcommand)]
    sub: KeySub,
}

impl Flags for KeyCmd {
    fn write(&self, layer: &mut Layer) {
        self.paths.write(layer);
    }
}

#[derive(Subcommand)]
enum KeySub {
    Create(KeyCreateCmd),
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

async fn admin_one(config: &Config, req: AdminRequest) -> Result<Value> {
    let mut conn = admin_conn(config).await?;
    conn.call(req).await
}

fn from_response<T: serde::de::DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|e| unavailable(format!("bad admin response: {e}")))
}

fn print_minted_keys(keys: &[MintSummary]) {
    for k in keys {
        let label = k.label.as_ref().map(Label::as_str).unwrap_or("-");
        println!(
            "{label}  {}  {}  expires {}  {}",
            k.token_id.as_str(),
            k.fingerprint.as_str(),
            k.expires_at.format_utc(),
            k.policy
        );
    }
}

pub(crate) async fn run_user(cmd: UserCmd, config: &Config) -> Result<()> {
    match cmd.sub {
        UserSub::Add(a) => {
            let password = crate::prompt::password().await?;
            admin_one(
                config,
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
                config,
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
                config,
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
                    from_response(admin_one(config, AdminRequest::UserList).await?)?;
                if users.is_empty() {
                    println!("no users");
                }
                for u in users {
                    println!("{}  {}", u.name, u.policy);
                }
            }
            Some(name) => {
                let resp: UserGetResponse = from_response(
                    admin_one(config, AdminRequest::UserGet { name: name.clone() }).await?,
                )?;
                println!("user: {name}");
                println!("policy: {}", resp.user.policy);
                if !resp.credentials.is_empty() {
                    println!("credentials:");
                    print_minted_keys(&resp.credentials);
                }
            }
        },
        UserSub::Revoke(r) => {
            let v = admin_one(
                config,
                AdminRequest::UserRevoke {
                    name: r.name.clone(),
                },
            )
            .await?;
            println!("revoked {}", v["revoked"].as_u64().unwrap_or(0));
        }
        UserSub::Remove(a) => {
            admin_one(
                config,
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
    match cmd.sub {
        KeySub::Create(c) => {
            let minted = admin_one(
                config,
                AdminRequest::KeyCreate {
                    label: c.label.clone(),
                    policy: config.policy_fragment(&c.entries)?,
                    ttl: c.ttl,
                },
            )
            .await?;
            let granted: Granted = from_response(minted)?;
            crate::auth::print_minted(&granted, c.json);
            if !c.json {
                eprintln!("the secret is shown exactly once — it is not stored");
            }
            Ok(())
        }
        KeySub::List(l) => {
            let keys: Vec<MintSummary> =
                from_response(admin_one(config, AdminRequest::KeyList { label: l.label }).await?)?;
            if keys.is_empty() {
                println!("no keys");
            }
            print_minted_keys(&keys);
            Ok(())
        }
        KeySub::Revoke(r) => {
            let by = match (r.label, r.id) {
                (Some(label), None) => Revoke::Label(Label::new(label)?),
                (None, Some(id)) => Revoke::Token(id.parse()?),
                (None, None) => {
                    let bearer = crate::prompt::piped_line().await?.ok_or_else(|| {
                        rejected("key revoke needs --label, --id, or the macaroon piped on stdin")
                    })?;
                    if bearer.is_empty() {
                        return Err(rejected("no macaroon on stdin"));
                    }
                    Revoke::from_bearer(&bearer)?
                }
                (Some(_), Some(_)) => unreachable!("clap conflicts_with"),
            };
            let v = admin_one(config, AdminRequest::KeyRevoke { by }).await?;
            println!("revoked {}", v["revoked"].as_u64().unwrap_or(0));
            Ok(())
        }
    }
}
