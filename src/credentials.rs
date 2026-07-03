use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::expand_home;
use crate::error::{io_error, json_error, rejected, unavailable, yaml_error, Result};
use crate::httpurl::HttpUrl;
use crate::oauth::types::{AccessToken, ClientId, Macaroon, RefreshToken};
use crate::types::UnixEpochSeconds;
use crate::util::atomic_write;

#[derive(Clone, Debug)]
pub struct Credential {
    pub user: Option<String>,
    pub client_id: ClientId,
    pub access_token: AccessToken,
    pub refresh_token: Option<RefreshToken>,
    pub expires_at: Option<UnixEpochSeconds>,
    pub root_macaroon: Option<Macaroon>,
}

#[derive(Clone, Debug)]
pub struct HostSummary {
    pub url: HttpUrl,
    pub user: Option<String>,
    pub storage: &'static str,
}

#[derive(Clone, Serialize, Deserialize)]
struct Pointer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    client_id: ClientId,
}

#[derive(Serialize, Deserialize)]
struct Secret {
    access_token: AccessToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<RefreshToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<UnixEpochSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_macaroon: Option<Macaroon>,
}

trait SecretBackend: Send + Sync {
    fn kind(&self) -> &'static str;
    fn get(&self, url: &str) -> Result<Option<String>>;
    fn set(&self, url: &str, blob: &str) -> Result<()>;
    fn remove(&self, url: &str) -> Result<()>;
}

struct Keyring;

impl SecretBackend for Keyring {
    fn kind(&self) -> &'static str {
        "keyring"
    }
    fn get(&self, url: &str) -> Result<Option<String>> {
        match keyring::Entry::new("noted", url).and_then(|e| e.get_password()) {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(unavailable(format!("keyring: {e}"))),
        }
    }
    fn set(&self, url: &str, blob: &str) -> Result<()> {
        keyring::Entry::new("noted", url)
            .and_then(|e| e.set_password(blob))
            .map_err(|e| unavailable(format!("keyring: {e}")))
    }
    fn remove(&self, url: &str) -> Result<()> {
        match keyring::Entry::new("noted", url).and_then(|e| e.delete_credential()) {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(unavailable(format!("keyring: {e}"))),
        }
    }
}

struct PlaintextFile {
    path: PathBuf,
}

impl PlaintextFile {
    fn load(&self) -> Result<BTreeMap<String, String>> {
        load_yaml(&self.path)
    }
    fn save(&self, map: &BTreeMap<String, String>) -> Result<()> {
        save_yaml(&self.path, map)
    }
}

impl SecretBackend for PlaintextFile {
    fn kind(&self) -> &'static str {
        "file"
    }
    fn get(&self, url: &str) -> Result<Option<String>> {
        Ok(self.load()?.get(url).cloned())
    }
    fn set(&self, url: &str, blob: &str) -> Result<()> {
        let mut map = self.load()?;
        map.insert(url.to_string(), blob.to_string());
        self.save(&map)
    }
    fn remove(&self, url: &str) -> Result<()> {
        let mut map = self.load()?;
        if map.remove(url).is_some() {
            self.save(&map)?;
        }
        Ok(())
    }
}

pub struct CredentialStore {
    hosts_path: PathBuf,
    backend: Box<dyn SecretBackend>,
}

impl CredentialStore {
    pub fn open() -> Result<CredentialStore> {
        let hosts_path = hosts_file_path()?;
        let forced_plaintext = std::env::var_os("NOTED_HOSTS_FILE").is_some();
        let backend: Box<dyn SecretBackend> = if !forced_plaintext && keyring_available() {
            Box::new(Keyring)
        } else {
            Box::new(PlaintextFile {
                path: secrets_path(&hosts_path),
            })
        };
        Ok(CredentialStore {
            hosts_path,
            backend,
        })
    }

    #[cfg(feature = "test-util")]
    pub fn open_plaintext_at(hosts_path: PathBuf) -> CredentialStore {
        let path = secrets_path(&hosts_path);
        CredentialStore {
            hosts_path,
            backend: Box::new(PlaintextFile { path }),
        }
    }

    pub fn get(&self, url: &HttpUrl) -> Result<Option<Credential>> {
        let url = url.as_str();
        let hosts = self.load_hosts()?;
        let Some(ptr) = hosts.get(url) else {
            return Ok(None);
        };
        let Some(blob) = self.backend.get(url)? else {
            return Ok(None);
        };
        let secret: Secret =
            serde_json::from_str(&blob).map_err(|e| json_error("credential", e))?;
        Ok(Some(Credential {
            user: ptr.user.clone(),
            client_id: ptr.client_id.clone(),
            access_token: secret.access_token,
            refresh_token: secret.refresh_token,
            expires_at: secret.expires_at,
            root_macaroon: secret.root_macaroon,
        }))
    }

    pub fn set(&self, url: &HttpUrl, cred: &Credential) -> Result<()> {
        let url = url.as_str();
        let mut hosts = self.load_hosts()?;
        hosts.insert(
            url.to_string(),
            Pointer {
                user: cred.user.clone(),
                client_id: cred.client_id.clone(),
            },
        );
        self.save_hosts(&hosts)?;
        let secret = Secret {
            access_token: cred.access_token.clone(),
            refresh_token: cred.refresh_token.clone(),
            expires_at: cred.expires_at,
            root_macaroon: cred.root_macaroon.clone(),
        };
        let blob = serde_json::to_string(&secret).map_err(|e| json_error("credential", e))?;
        self.backend.set(url, &blob)
    }

    pub fn remove(&self, url: &HttpUrl) -> Result<()> {
        let url = url.as_str();
        let mut hosts = self.load_hosts()?;
        hosts.remove(url);
        self.save_hosts(&hosts)?;
        self.backend.remove(url)
    }

    pub fn list(&self) -> Result<Vec<HostSummary>> {
        let hosts = self.load_hosts()?;
        hosts
            .into_iter()
            .map(|(url, ptr)| {
                Ok(HostSummary {
                    url: url.parse()?,
                    user: ptr.user,
                    storage: self.backend.kind(),
                })
            })
            .collect()
    }

    fn load_hosts(&self) -> Result<BTreeMap<String, Pointer>> {
        load_yaml(&self.hosts_path)
    }

    fn save_hosts(&self, hosts: &BTreeMap<String, Pointer>) -> Result<()> {
        save_yaml(&self.hosts_path, hosts)
    }
}

fn hosts_file_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("NOTED_HOSTS_FILE") {
        if !p.is_empty() {
            return Ok(expand_home(&p));
        }
    }
    let dir = dirs::config_dir().ok_or_else(|| rejected("cannot determine config dir"))?;
    Ok(dir.join("noted").join("hosts.yaml"))
}

fn secrets_path(hosts_path: &std::path::Path) -> PathBuf {
    hosts_path.with_file_name("secrets.yaml")
}

fn keyring_available() -> bool {
    match keyring::Entry::new("noted", "__probe__") {
        Ok(e) => !matches!(
            e.get_password(),
            Err(keyring::Error::PlatformFailure(_)) | Err(keyring::Error::NoStorageAccess(_))
        ),
        Err(_) => false,
    }
}

fn load_yaml<T: for<'de> Deserialize<'de> + Default>(path: &std::path::Path) -> Result<T> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_yaml::from_str(&text).map_err(|e| yaml_error("credential store", e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(io_error("credential store", e)),
    }
}

fn save_yaml<T: Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| io_error("credential store", e))?;
        }
    }
    let yaml = serde_yaml::to_string(value).map_err(|e| yaml_error("credential store", e))?;
    atomic_write(path, &yaml)
}
