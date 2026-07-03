use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde_json::Value;

use crate::config::{block_on, parse_ttl};
use crate::error::{rejected, unavailable, Result};
use crate::oauth::admin::{AdminConn, AdminRequest};
use crate::oauth::service::{CredentialSummary, RevokeBy, ScopeEdit, UserSummary};
use crate::oauth::types::Label;
use crate::scope::StoredScope;

use super::RuleFlags;

#[derive(serde::Deserialize)]
struct UserGetResponse {
    user: UserSummary,
    credentials: Vec<CredentialSummary>,
}

#[derive(Args)]
struct AdminTransport {
    #[arg(long = "admin-socket", env = "NOTED_ADMIN_SOCKET", global = true)]
    admin_socket: Option<PathBuf>,
    #[arg(long = "auth-db", env = "NOTED_AUTH_DB", global = true)]
    auth_db: Option<PathBuf>,
}

#[derive(Args)]
pub(super) struct UserCmd {
    #[command(flatten)]
    transport: AdminTransport,
    #[command(subcommand)]
    sub: UserSub,
}

#[derive(Subcommand)]
enum UserSub {
    Add(UserNameArg),
    Passwd(UserNameArg),
    Grant(UserGrantCmd),
    Ungrant(UserUngrantCmd),
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
struct UserGrantCmd {
    name: String,
    #[command(flatten)]
    flags: RuleFlags,
    #[arg(long, conflicts_with_all = ["tools", "path", "rules"])]
    all: bool,
}

#[derive(Args)]
struct UserUngrantCmd {
    name: String,
    n: usize,
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
pub(super) struct KeyCmd {
    #[command(flatten)]
    transport: AdminTransport,
    #[command(subcommand)]
    sub: KeySub,
}

#[derive(Subcommand)]
enum KeySub {
    Create(KeyCreateCmd),
    Grant(KeyGrantCmd),
    Ungrant(KeyUngrantCmd),
    #[command(alias = "ls")]
    List(KeyListCmd),
    Revoke(KeyRevokeCmd),
}

#[derive(Args)]
struct KeyCreateCmd {
    label: String,
    #[command(flatten)]
    flags: RuleFlags,
    #[arg(long, value_parser = parse_ttl)]
    ttl: Option<crate::types::Ttl>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct KeyGrantCmd {
    label: Option<String>,
    #[arg(long, conflicts_with = "label")]
    id: Option<String>,
    #[command(flatten)]
    flags: RuleFlags,
    #[arg(long, conflicts_with_all = ["tools", "path", "rules"])]
    all: bool,
}

#[derive(Args)]
struct KeyUngrantCmd {
    label: Option<String>,
    #[arg(long, conflicts_with = "label")]
    id: Option<String>,
    n: usize,
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
    let socket = t.admin_socket.clone();
    let db = t.auth_db.clone();
    block_on(async move {
        let mut conn = AdminConn::open(socket.as_deref(), db.as_deref()).await?;
        conn.call(req).await
    })
}

fn scope_edit_of(flags: &RuleFlags, all: bool) -> Result<ScopeEdit> {
    if all {
        return Ok(ScopeEdit::All);
    }
    match flags.to_specs()? {
        Some(specs) => Ok(ScopeEdit::Append(specs)),
        None => Err(rejected("a grant needs --tools, --path, --rules, or --all")),
    }
}

fn format_stored_scope(scope: &StoredScope) -> String {
    match scope {
        StoredScope::Unrestricted => "unrestricted".to_string(),
        StoredScope::Grants(specs) if specs.is_empty() => "no access (no grants)".to_string(),
        StoredScope::Grants(specs) => specs
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let tools = s
                    .tools
                    .as_ref()
                    .map(|t| t.join(","))
                    .unwrap_or_else(|| "*".into());
                let paths = s
                    .paths
                    .as_ref()
                    .map(|p| p.join(" "))
                    .unwrap_or_else(|| "/".into());
                format!("{}. {tools} @ {paths}", i + 1)
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
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

pub(super) fn run_user(cmd: UserCmd) -> Result<()> {
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
        UserSub::Grant(g) => {
            let edit = scope_edit_of(&g.flags, g.all)?;
            admin_one(
                t,
                AdminRequest::UserGrant {
                    name: g.name.clone(),
                    edit,
                },
            )?;
            println!("granted");
        }
        UserSub::Ungrant(u) => {
            admin_one(
                t,
                AdminRequest::UserUngrant {
                    name: u.name.clone(),
                    n: u.n,
                },
            )?;
            println!("removed grant {}", u.n);
        }
        UserSub::List(l) => match l.name {
            None => {
                let users: Vec<UserSummary> = from_response(admin_one(t, AdminRequest::UserList)?)?;
                if users.is_empty() {
                    println!("no users");
                }
                for u in users {
                    println!("{}  {}", u.name, u.scope.summary());
                }
            }
            Some(name) => {
                let resp: UserGetResponse =
                    from_response(admin_one(t, AdminRequest::UserGet { name: name.clone() })?)?;
                println!("user: {name}");
                println!("scope:\n{}", format_stored_scope(&resp.user.scope));
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

pub(super) fn run_key(cmd: KeyCmd) -> Result<()> {
    let t = &cmd.transport;
    match cmd.sub {
        KeySub::Create(c) => {
            let scope = match c.flags.to_specs()? {
                None => StoredScope::Unrestricted,
                Some(specs) => StoredScope::Grants(specs),
            };
            let socket = t.admin_socket.clone();
            let db = t.auth_db.clone();
            let label = c.label.clone();
            let ttl = c.ttl;
            let as_json = c.json;
            block_on(async move {
                let mut conn = AdminConn::open(socket.as_deref(), db.as_deref()).await?;
                let minted = conn
                    .call(AdminRequest::KeyCreate { label, scope, ttl })
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
        KeySub::Grant(g) => {
            if g.label.is_none() && g.id.is_none() {
                return Err(rejected("key grant needs a LABEL or --id"));
            }
            let edit = scope_edit_of(&g.flags, g.all)?;
            let v = admin_one(
                t,
                AdminRequest::KeyGrant {
                    label: g.label,
                    id: g.id,
                    edit,
                },
            )?;
            println!("granted to {} key(s)", v["granted"].as_u64().unwrap_or(0));
            Ok(())
        }
        KeySub::Ungrant(u) => {
            if u.label.is_none() && u.id.is_none() {
                return Err(rejected("key ungrant needs a LABEL or --id"));
            }
            admin_one(
                t,
                AdminRequest::KeyUngrant {
                    label: u.label,
                    id: u.id,
                    n: u.n,
                },
            )?;
            println!("removed grant {}", u.n);
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
                let scope_summary = k
                    .scope
                    .as_ref()
                    .map(StoredScope::summary)
                    .unwrap_or_else(|| "unrestricted".to_string());
                println!(
                    "{label}  {}  {:<8}{}  expires {expires}  {scope_summary}",
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
