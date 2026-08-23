use std::process::ExitCode;

use clap::{Args, Subcommand};
use serde_json::json;

use noted::error::Result;
use noted_client::authclient::{self, Ask, Granted, Session};

use crate::args::EntryFlags;
use crate::config::Config;
use crate::settings::{Flags, Layer, Variable};

#[derive(Args)]
pub(crate) struct AuthCmd {
    #[command(subcommand)]
    sub: AuthSub,
}

impl Flags for AuthCmd {
    fn write(&self, layer: &mut Layer) {
        let url = match &self.sub {
            AuthSub::Login(a) | AuthSub::Logout(a) => a.url.as_deref(),
            AuthSub::Status => None,
            AuthSub::Mint(m) => m.url.as_deref(),
        };
        layer.set(Variable::Url, url);
    }
}

#[derive(Subcommand)]
enum AuthSub {
    Login(AuthUrl),
    Logout(AuthUrl),
    Status,
    Mint(MintCmd),
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
    #[arg(long)]
    json: bool,
}

pub(crate) async fn run_auth(cmd: AuthCmd, config: &Config) -> Result<ExitCode> {
    let store = config.credential_store()?;
    let url = config.login_url();
    match cmd.sub {
        AuthSub::Login(_) => {
            let url = url?;
            let cred = authclient::login(&url).await?;
            store.set(&url, &cred)?;
            match &cred.user {
                Some(u) => println!("Logged in to {url} as {u}"),
                None => println!("Logged in to {url}"),
            }
            Ok(ExitCode::SUCCESS)
        }
        AuthSub::Logout(_) => {
            let url = url?;
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
        AuthSub::Mint(m) => run_mint(m, config).await,
    }
}

/// Prints what the server minted: the credential on stdout, what names it on
/// stderr. A refusal is an error, so the process exits 1.
pub(crate) fn print_minted(granted: &Granted, as_json: bool) {
    if as_json {
        let record = json!({
            "macaroon": granted.macaroon.expose(),
            "token_id": granted.token_id,
            "fingerprint": granted.fingerprint,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&record).unwrap_or_default()
        );
        return;
    }
    println!("{}", granted.macaroon.expose());
    eprintln!(
        "token-id {}  fingerprint {}",
        granted.token_id.as_str(),
        granted.fingerprint.as_str()
    );
}

async fn run_mint(m: MintCmd, config: &Config) -> Result<ExitCode> {
    let url = config.login_url()?;
    let session = Session::open(
        &url,
        config.setting(Variable::Token),
        config.credential_store()?,
    );
    let granted = session
        .mint(&Ask {
            policy: config.policy_fragment(&m.entries)?,
        })
        .await?;
    print_minted(&granted, m.json);
    Ok(ExitCode::SUCCESS)
}
