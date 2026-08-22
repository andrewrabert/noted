use clap::{Args, Subcommand};
use noted::error::{Result, rejected};
use noted::types::Ttl;
use noted_auth::administration::{AdminCommand, AdminCredentialLifetime, AdminOutcome, MintFilter};
use noted_auth::authority::Revoke;
use noted_auth::service::MintSummary;
use noted_auth::types::{Label, Password, Username};
use noted_client::admin::AdminConnection;
use noted_client::authclient::Granted;

use crate::args::{AuthPaths, EntryFlags, parse_ttl};
use crate::config::Config;
use crate::settings::{Flags, Layer, Variable};

/// Connects to a running server's admin socket where available, else opens the
/// auth database. It owns the messages that name CLI flags.
async fn admin_conn(config: &Config) -> Result<AdminConnection> {
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
    AdminConnection::open(
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

enum PreparedAdminCommand {
    AddUser {
        username: String,
        password: Password,
    },
    ReplaceUserPassword {
        username: String,
        password: Password,
    },
    ReplaceUserPolicy {
        username: String,
        policy: noted::PolicyFragment,
    },
    ListUsers,
    GetUser {
        username: String,
    },
    RevokeUser {
        username: String,
    },
    RemoveUser {
        username: String,
    },
    CreateKey {
        label: String,
        policy: noted::PolicyFragment,
        lifetime: AdminCredentialLifetime,
    },
    ListKeys {
        label: Option<String>,
    },
    RevokeKey {
        revocation: Revoke,
    },
}

impl UserPolicyCmd {
    fn prepare(&self, config: &Config) -> Result<PreparedAdminCommand> {
        Ok(PreparedAdminCommand::ReplaceUserPolicy {
            username: self.name.clone(),
            policy: config.policy_fragment(&self.entries)?,
        })
    }
}

impl KeyCreateCmd {
    fn prepare(&self, config: &Config) -> Result<PreparedAdminCommand> {
        Ok(PreparedAdminCommand::CreateKey {
            label: self.label.clone(),
            policy: config.policy_fragment(&self.entries)?,
            lifetime: self
                .ttl
                .map(AdminCredentialLifetime::Explicit)
                .unwrap_or(AdminCredentialLifetime::Default),
        })
    }
}

impl PreparedAdminCommand {
    fn into_command(self) -> Result<AdminCommand> {
        Ok(match self {
            PreparedAdminCommand::AddUser { username, password } => AdminCommand::AddUser {
                username: Username::new(username)?,
                password,
            },
            PreparedAdminCommand::ReplaceUserPassword { username, password } => {
                AdminCommand::ReplaceUserPassword {
                    username: Username::new(username)?,
                    password,
                }
            }
            PreparedAdminCommand::ReplaceUserPolicy { username, policy } => {
                AdminCommand::ReplaceUserPolicy {
                    username: Username::new(username)?,
                    policy,
                }
            }
            PreparedAdminCommand::ListUsers => AdminCommand::ListUsers,
            PreparedAdminCommand::GetUser { username } => AdminCommand::GetUser {
                username: Username::new(username)?,
            },
            PreparedAdminCommand::RevokeUser { username } => AdminCommand::RevokeUser {
                username: Username::new(username)?,
            },
            PreparedAdminCommand::RemoveUser { username } => AdminCommand::RemoveUser {
                username: Username::new(username)?,
            },
            PreparedAdminCommand::CreateKey {
                label,
                policy,
                lifetime,
            } => AdminCommand::CreateKey {
                label: Label::new(label)?,
                policy,
                lifetime,
            },
            PreparedAdminCommand::ListKeys { label } => AdminCommand::ListKeys {
                filter: label
                    .map(Label::new)
                    .transpose()?
                    .map(MintFilter::Label)
                    .unwrap_or(MintFilter::All),
            },
            PreparedAdminCommand::RevokeKey { revocation } => {
                AdminCommand::RevokeKey { revocation }
            }
        })
    }
}

async fn admin_one(config: &Config, prepared: PreparedAdminCommand) -> Result<AdminOutcome> {
    let mut connection = admin_conn(config).await?;
    connection.call(prepared.into_command()?).await
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
            let prepared = PreparedAdminCommand::AddUser {
                username: a.name.clone(),
                password: Password::new(password),
            };
            admin_one(config, prepared).await?;
            println!("added user {}", a.name);
        }
        UserSub::Passwd(a) => {
            let password = crate::prompt::password().await?;
            let prepared = PreparedAdminCommand::ReplaceUserPassword {
                username: a.name.clone(),
                password: Password::new(password),
            };
            admin_one(config, prepared).await?;
            println!("password changed for {}", a.name);
        }
        UserSub::Policy(c) => {
            let prepared = c.prepare(config)?;
            let AdminOutcome::Completed = admin_one(config, prepared).await? else {
                unreachable!("replace-user-policy command has a closed completed outcome")
            };
            println!("policy set for {}", c.name);
        }
        UserSub::List(l) => match l.name {
            None => {
                let AdminOutcome::Users(users) =
                    admin_one(config, PreparedAdminCommand::ListUsers).await?
                else {
                    unreachable!("list-users command has a closed users outcome")
                };
                if users.is_empty() {
                    println!("no users");
                }
                for u in users {
                    println!("{}  {}", u.name, u.policy);
                }
            }
            Some(name) => {
                let prepared = PreparedAdminCommand::GetUser {
                    username: name.clone(),
                };
                let AdminOutcome::User(details) = admin_one(config, prepared).await? else {
                    unreachable!("get-user command has a closed user outcome")
                };
                println!("user: {name}");
                println!("policy: {}", details.user.policy);
                if !details.credentials.is_empty() {
                    println!("credentials:");
                    print_minted_keys(&details.credentials);
                }
            }
        },
        UserSub::Revoke(r) => {
            let prepared = PreparedAdminCommand::RevokeUser { username: r.name };
            let AdminOutcome::Withdrawn(withdrawn) = admin_one(config, prepared).await? else {
                unreachable!("revoke-user command has a closed withdrawn outcome")
            };
            crate::auth::print_withdrawn(&withdrawn);
        }
        UserSub::Remove(a) => {
            let prepared = PreparedAdminCommand::RemoveUser {
                username: a.name.clone(),
            };
            admin_one(config, prepared).await?;
            println!("removed user {}", a.name);
        }
    }
    Ok(())
}

pub(crate) async fn run_key(cmd: KeyCmd, config: &Config) -> Result<()> {
    match cmd.sub {
        KeySub::Create(c) => {
            let prepared = c.prepare(config)?;
            let AdminOutcome::Minted(minted) = admin_one(config, prepared).await? else {
                unreachable!("create-key command has a closed minted outcome")
            };
            let granted = Granted {
                macaroon: minted.macaroon,
                token_id: minted.token_id,
                fingerprint: minted.fingerprint,
                expires_at: minted.expires_at,
            };
            crate::auth::print_minted(&granted, c.json);
            if !c.json {
                eprintln!("the secret is shown exactly once — it is not stored");
            }
            Ok(())
        }
        KeySub::List(l) => {
            let prepared = PreparedAdminCommand::ListKeys { label: l.label };
            let AdminOutcome::Credentials(keys) = admin_one(config, prepared).await? else {
                unreachable!("list-keys command has a closed credentials outcome")
            };
            if keys.is_empty() {
                println!("no keys");
            }
            print_minted_keys(&keys);
            Ok(())
        }
        KeySub::Revoke(r) => {
            let revocation = match (r.label, r.id) {
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
            let prepared = PreparedAdminCommand::RevokeKey { revocation };
            let AdminOutcome::Withdrawn(withdrawn) = admin_one(config, prepared).await? else {
                unreachable!("revoke-key command has a closed withdrawn outcome")
            };
            crate::auth::print_withdrawn(&withdrawn);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noted::PolicyFragment;

    const INVALID_USERNAME: &str = "invalid username";
    const INVALID_LABEL: &str = "invalid label";

    fn config(bindings: &[(Variable, &str)]) -> Config {
        let mut layer = Layer::flags();
        for (variable, value) in bindings {
            layer.set(*variable, Some(value));
        }
        Config::new(
            crate::settings::Settings::resolve(vec![layer]).unwrap(),
            None,
        )
    }

    fn username_commands() -> Vec<PreparedAdminCommand> {
        vec![
            PreparedAdminCommand::AddUser {
                username: INVALID_USERNAME.to_string(),
                password: Password::new("password"),
            },
            PreparedAdminCommand::ReplaceUserPassword {
                username: INVALID_USERNAME.to_string(),
                password: Password::new("password"),
            },
            PreparedAdminCommand::ReplaceUserPolicy {
                username: INVALID_USERNAME.to_string(),
                policy: PolicyFragment::default(),
            },
            PreparedAdminCommand::GetUser {
                username: INVALID_USERNAME.to_string(),
            },
            PreparedAdminCommand::RevokeUser {
                username: INVALID_USERNAME.to_string(),
            },
            PreparedAdminCommand::RemoveUser {
                username: INVALID_USERNAME.to_string(),
            },
        ]
    }

    fn connection_first_label_commands() -> Vec<PreparedAdminCommand> {
        vec![
            PreparedAdminCommand::CreateKey {
                label: INVALID_LABEL.to_string(),
                policy: PolicyFragment::default(),
                lifetime: AdminCredentialLifetime::Default,
            },
            PreparedAdminCommand::ListKeys {
                label: Some(INVALID_LABEL.to_string()),
            },
        ]
    }

    fn invalid_revoke_label_command() -> KeyCmd {
        KeyCmd {
            paths: AuthPaths {
                auth_db: None,
                #[cfg(unix)]
                admin_socket: None,
            },
            sub: KeySub::Revoke(KeyRevokeCmd {
                label: Some(INVALID_LABEL.to_string()),
                id: None,
            }),
        }
    }

    fn all_commands() -> Vec<PreparedAdminCommand> {
        username_commands()
            .into_iter()
            .chain(connection_first_label_commands())
            .collect()
    }

    fn output(error: &noted::error::NotedError) -> String {
        crate::error_output(error)
    }

    #[test]
    fn malformed_policy_precedes_missing_admin_configuration() {
        let config = config(&[(Variable::Policy, "{")]);
        let user = UserPolicyCmd {
            name: INVALID_USERNAME.to_string(),
            entries: EntryFlags::default(),
        };
        let key = KeyCreateCmd {
            label: INVALID_LABEL.to_string(),
            entries: EntryFlags::default(),
            ttl: None,
            json: false,
        };

        for error in [
            user.prepare(&config).err().unwrap(),
            key.prepare(&config).err().unwrap(),
        ] {
            assert!(output(&error).starts_with("error: invalid policy: "));
        }
    }

    #[test]
    fn malformed_policy_does_not_create_auth_database_or_parent() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("absent");
        let database = parent.join("auth.redb");
        let config = config(&[
            (Variable::Policy, "{"),
            (Variable::AuthDb, database.to_str().unwrap()),
        ]);
        let user = UserPolicyCmd {
            name: "user".to_string(),
            entries: EntryFlags::default(),
        };
        let key = KeyCreateCmd {
            label: "key".to_string(),
            entries: EntryFlags::default(),
            ttl: None,
            json: false,
        };

        assert!(user.prepare(&config).is_err());
        assert!(key.prepare(&config).is_err());
        assert!(!parent.exists());
        assert!(!database.exists());
    }

    #[tokio::test]
    async fn missing_admin_configuration_precedes_invalid_usernames() {
        let config = config(&[]);
        for prepared in username_commands() {
            let error = admin_one(&config, prepared).await.unwrap_err();
            #[cfg(unix)]
            assert_eq!(
                output(&error),
                "error: --admin-socket or --auth-db is required"
            );
            #[cfg(not(unix))]
            assert_eq!(output(&error), "error: --auth-db is required");
        }
    }

    #[tokio::test]
    async fn invalid_revoke_label_precedes_missing_admin_configuration() {
        let error = run_key(invalid_revoke_label_command(), &config(&[]))
            .await
            .unwrap_err();

        assert_eq!(
            output(&error),
            format!("error: invalid key label name: '{INVALID_LABEL}'")
        );
    }

    #[tokio::test]
    async fn invalid_revoke_label_does_not_create_auth_database_or_parent() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("absent");
        let database = parent.join("auth.redb");
        let config = config(&[(Variable::AuthDb, database.to_str().unwrap())]);

        let error = run_key(invalid_revoke_label_command(), &config)
            .await
            .unwrap_err();

        assert_eq!(
            output(&error),
            format!("error: invalid key label name: '{INVALID_LABEL}'")
        );
        assert!(!parent.exists());
        assert!(!database.exists());
    }

    #[tokio::test]
    async fn missing_admin_configuration_precedes_invalid_create_and_list_labels() {
        let config = config(&[]);
        for prepared in connection_first_label_commands() {
            let error = admin_one(&config, prepared).await.unwrap_err();
            #[cfg(unix)]
            assert_eq!(
                output(&error),
                "error: --admin-socket or --auth-db is required"
            );
            #[cfg(not(unix))]
            assert_eq!(output(&error), "error: --auth-db is required");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_admin_socket_precedes_invalid_auth_database_path() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("admin.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            assert_eq!(
                lines.next_line().await.unwrap().unwrap(),
                r#"{"op":"user_list"}"#
            );
            write.write_all(b"{\"ok\":[]}\n").await.unwrap();
        });
        let config = config(&[
            (Variable::AdminSocket, socket.to_str().unwrap()),
            (Variable::AuthDb, "/"),
        ]);

        assert!(matches!(
            admin_one(&config, PreparedAdminCommand::ListUsers)
                .await
                .unwrap(),
            AdminOutcome::Users(users) if users.is_empty()
        ));
        peer.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unreachable_admin_socket_precedes_invalid_usernames_and_labels() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("missing.sock");
        let config = config(&[(Variable::AdminSocket, socket.to_str().unwrap())]);
        for prepared in all_commands() {
            let error = admin_one(&config, prepared).await.unwrap_err();
            let output = output(&error);
            assert!(output.starts_with("error: admin socket: connect: "));
            assert!(!output.contains(INVALID_USERNAME));
            assert!(!output.contains(INVALID_LABEL));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_database_fallback_precedes_invalid_usernames_and_labels() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("not-a-directory");
        std::fs::write(&parent, "occupied").unwrap();
        let socket = dir.path().join("missing.sock");
        let database = parent.join("auth.redb");
        let config = config(&[
            (Variable::AdminSocket, socket.to_str().unwrap()),
            (Variable::AuthDb, database.to_str().unwrap()),
        ]);
        for prepared in all_commands() {
            let error = admin_one(&config, prepared).await.unwrap_err();
            let output = output(&error);
            assert!(output.ends_with(" (if the server is running, connect to its admin socket)"));
            assert!(!output.contains(INVALID_USERNAME));
            assert!(!output.contains(INVALID_LABEL));
        }
    }

    #[tokio::test]
    async fn connected_admin_commands_report_invalid_usernames_and_labels() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("auth.redb");
        let config = config(&[(Variable::AuthDb, database.to_str().unwrap())]);
        for prepared in username_commands() {
            let error = admin_one(&config, prepared).await.unwrap_err();
            assert_eq!(
                output(&error),
                format!("error: invalid user name: '{INVALID_USERNAME}'")
            );
        }
        for prepared in connection_first_label_commands() {
            let error = admin_one(&config, prepared).await.unwrap_err();
            assert_eq!(
                output(&error),
                format!("error: invalid key label name: '{INVALID_LABEL}'")
            );
        }
    }
}
