use std::process::ExitCode;

use clap::{Args, Subcommand};

use noted::HttpUrl;
use noted::error::{Result, rejected};
use noted::types::Ttl;
use noted_auth::oauth::types::SessionId;
use noted_client::authclient::{self, RevokeSelector, Session};
use noted_client::credentials::CredentialStore;

use crate::config::{block_on, credential_store_config, parse_ttl};
use crate::{EntryFlags, GlobalArgs};

#[derive(Args)]
pub(crate) struct AuthCmd {
    #[command(subcommand)]
    sub: AuthSub,
}

#[derive(Subcommand)]
enum AuthSub {
    Login(AuthUrl),
    Logout(AuthUrl),
    Status,
    Mint(MintCmd),
    Revoke(RevokeCmd),
}

#[derive(Args)]
struct AuthUrl {
    #[arg(long)]
    url: Option<String>,
}

#[derive(Args)]
struct MintCmd {
    #[arg(long)]
    url: Option<String>,
    #[command(flatten)]
    entries: EntryFlags,
    #[arg(long, value_parser = parse_ttl, default_value = "1h")]
    ttl: Ttl,
    #[arg(long)]
    session: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct RevokeCmd {
    #[arg(long)]
    url: Option<String>,
    id: Option<String>,
    #[arg(long)]
    session: Option<String>,
    #[arg(long)]
    all: bool,
}

fn resolve_url(explicit: Option<&str>, globals: &GlobalArgs) -> Result<HttpUrl> {
    let raw = explicit
        .filter(|s| !s.is_empty())
        .or_else(|| globals.url.as_deref().filter(|s| !s.is_empty()))
        .ok_or_else(|| rejected("a server URL is required (--url or NOTED_URL)"))?;
    raw.parse()
}

pub(crate) fn run_auth(cmd: AuthCmd, globals: &GlobalArgs) -> Result<ExitCode> {
    let store = CredentialStore::open(credential_store_config()?);
    match cmd.sub {
        AuthSub::Login(a) => {
            let url = resolve_url(a.url.as_deref(), globals)?;
            let cred = block_on(authclient::login(&url))?;
            store.set(&url, &cred)?;
            match &cred.user {
                Some(u) => println!("Logged in to {url} as {u}"),
                None => println!("Logged in to {url}"),
            }
            Ok(ExitCode::SUCCESS)
        }
        AuthSub::Logout(a) => {
            let url = resolve_url(a.url.as_deref(), globals)?;
            store.remove(&url)?;
            println!("Logged out of {url}");
            Ok(ExitCode::SUCCESS)
        }
        AuthSub::Status => {
            let hosts = store.list()?;
            if hosts.is_empty() {
                println!("not logged in to any server");
            }
            for h in hosts {
                let user = h.user.as_deref().unwrap_or("-");
                println!("{}  user={user}  ({})", h.url, h.storage);
            }
            Ok(ExitCode::SUCCESS)
        }
        AuthSub::Mint(m) => run_mint(&store, m, globals),
        AuthSub::Revoke(r) => run_revoke(&store, r, globals),
    }
}

fn run_mint(store: &CredentialStore, m: MintCmd, globals: &GlobalArgs) -> Result<ExitCode> {
    let url = resolve_url(m.url.as_deref(), globals)?;
    let cred = store
        .get(&url)?
        .ok_or_else(|| rejected(format!("not logged in to {url}; run `noted auth login`")))?;
    let root = cred
        .root_macaroon
        .as_ref()
        .ok_or_else(|| rejected("no root macaroon stored; run `noted auth login` again"))?;

    let held = globals.policy_args(&m.entries).held()?;

    let session = m.session.as_deref().map(SessionId::new);
    let _child = root.to_descendant(Some(&held), m.ttl, session.as_ref())?;
    Ok(ExitCode::SUCCESS)
}

fn run_revoke(store: &CredentialStore, r: RevokeCmd, globals: &GlobalArgs) -> Result<ExitCode> {
    let url = resolve_url(r.url.as_deref(), globals)?;
    let cred = store
        .get(&url)?
        .ok_or_else(|| rejected(format!("not logged in to {url}; run `noted auth login`")))?;
    let selector = if r.all {
        RevokeSelector::All
    } else if let Some(s) = r.session {
        RevokeSelector::Session(s)
    } else if let Some(id) = r.id {
        RevokeSelector::Id(id)
    } else {
        return Err(rejected("provide an id, --session, or --all"));
    };
    let session = Session::open(
        &url,
        Some(cred.access_token.expose()),
        CredentialStore::open(credential_store_config()?),
    );
    block_on(session.revoke(selector))?;
    println!("revoked");
    Ok(ExitCode::SUCCESS)
}
