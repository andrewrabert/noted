#[cfg(unix)]
use std::path::{Path, PathBuf};

use crate::error::{NotedError, Result, rejected};
use crate::httpurl::HttpUrl;

/// A socket-dialed backend resolves no host: the path, not the authority,
/// names the server.
#[cfg(unix)]
const SOCKET_URL: &str = "http://localhost/";

/// What a client dials: a TCP server named by URL, or a Unix socket named by
/// path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    kind: EndpointKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EndpointKind {
    Tcp(HttpUrl),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl Endpoint {
    pub fn tcp(&self) -> Option<&HttpUrl> {
        match &self.kind {
            EndpointKind::Tcp(url) => Some(url),
            #[cfg(unix)]
            EndpointKind::Unix(_) => None,
        }
    }

    #[cfg(unix)]
    pub fn unix_path(&self) -> Option<&Path> {
        match &self.kind {
            EndpointKind::Tcp(_) => None,
            EndpointKind::Unix(path) => Some(path),
        }
    }

    pub fn base_url(&self) -> Result<HttpUrl> {
        match &self.kind {
            EndpointKind::Tcp(url) => Ok(url.clone()),
            #[cfg(unix)]
            EndpointKind::Unix(_) => SOCKET_URL.parse(),
        }
    }

    /// The http(s) url a stored credential is keyed by. A unix endpoint is
    /// rejected: it holds no stored login.
    pub fn login_url(&self) -> Result<HttpUrl> {
        match &self.kind {
            EndpointKind::Tcp(url) => Ok(url.clone()),
            #[cfg(unix)]
            EndpointKind::Unix(_) => Err(rejected(
                "a unix endpoint holds no stored login: use an http(s) url",
            )),
        }
    }
}

/// The filesystem path a unix:// endpoint dials. The path is taken exactly
/// as written, byte for byte, and must be absolute: a dialed URL has no
/// working directory to resolve against.
#[cfg(unix)]
fn socket_path(raw: &Path) -> Result<PathBuf> {
    if !raw.is_absolute() {
        return Err(rejected(format!(
            "a unix socket is named by an absolute path: {}",
            raw.display()
        )));
    }
    Ok(raw.to_path_buf())
}

impl std::str::FromStr for Endpoint {
    type Err = NotedError;

    fn from_str(value: &str) -> Result<Endpoint> {
        match value.strip_prefix("unix:") {
            Some(tail) => {
                let Some(path) = tail.strip_prefix("//") else {
                    return Err(rejected(format!(
                        "a unix endpoint is spelled unix://<path>: {value}"
                    )));
                };
                #[cfg(unix)]
                {
                    Ok(Endpoint {
                        kind: EndpointKind::Unix(socket_path(&PathBuf::from(path))?),
                    })
                }
                #[cfg(not(unix))]
                {
                    let _ = path;
                    Err(rejected(format!(
                        "this platform holds no unix sockets: {value}"
                    )))
                }
            }
            None => {
                let url: HttpUrl = value.parse()?;
                if url.as_url().port() == Some(0) {
                    return Err(rejected(format!(
                        "a dialable TCP endpoint must have a nonzero port: {value}"
                    )));
                }
                Ok(Endpoint {
                    kind: EndpointKind::Tcp(url),
                })
            }
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            EndpointKind::Tcp(url) => write!(f, "{url}"),
            #[cfg(unix)]
            EndpointKind::Unix(path) => write!(f, "unix://{}", path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::path::PathBuf;

    use super::Endpoint;

    #[test]
    fn parses_http_and_https_as_tcp() {
        let tcp: Endpoint = "http://host:8000".parse().unwrap();
        assert!(tcp.tcp().is_some());
        assert_eq!(tcp.base_url().unwrap().as_str(), "http://host:8000/");
        let tls: Endpoint = "https://host/base".parse().unwrap();
        assert_eq!(tls.base_url().unwrap().as_str(), "https://host/base");
    }

    #[test]
    fn dialable_tcp_endpoints_reject_explicit_port_zero() {
        assert!("http://127.0.0.1:0".parse::<Endpoint>().is_err());
        assert!("https://example.com:0/base".parse::<Endpoint>().is_err());
    }

    #[test]
    fn dialable_tcp_endpoints_keep_implicit_and_explicit_nonzero_ports() {
        let implicit: Endpoint = "http://example.com/base".parse().unwrap();
        assert_eq!(implicit.to_string(), "http://example.com/base");
        let explicit: Endpoint = "http://127.0.0.1:8000".parse().unwrap();
        assert_eq!(explicit.to_string(), "http://127.0.0.1:8000/");
    }

    #[cfg(unix)]
    #[test]
    fn parses_an_absolute_unix_path() {
        let ep: Endpoint = "unix:///run/noted.sock".parse().unwrap();
        assert_eq!(
            ep.unix_path(),
            Some(PathBuf::from("/run/noted.sock").as_path())
        );
        assert!(ep.tcp().is_none());
        assert_eq!(ep.base_url().unwrap().as_str(), "http://localhost/");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_relative_unix_path() {
        assert!("unix://noted.sock".parse::<Endpoint>().is_err());
        assert!("unix://~/noted.sock".parse::<Endpoint>().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn keeps_a_non_utf8_socket_path_byte_for_byte() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let raw = PathBuf::from(OsStr::from_bytes(b"/run/nc\xffted.sock"));
        assert_eq!(super::socket_path(&raw).unwrap(), raw);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_relative_path_given_as_a_path() {
        assert!(super::socket_path(&PathBuf::from("noted.sock")).is_err());
    }

    #[test]
    fn a_tcp_endpoint_names_the_url_a_login_is_stored_under() {
        let ep: Endpoint = "https://host/base".parse().unwrap();
        assert_eq!(ep.login_url().unwrap().as_str(), "https://host/base");
    }

    #[cfg(unix)]
    #[test]
    fn a_unix_endpoint_holds_no_stored_login() {
        let ep: Endpoint = "unix:///run/noted.sock".parse().unwrap();
        let err = ep.login_url().unwrap_err();
        assert!(err.message().contains("no stored login"), "{err:?}");
    }

    #[test]
    fn rejects_a_bare_unix_scheme_and_an_unknown_one() {
        assert!("unix:/run/noted.sock".parse::<Endpoint>().is_err());
        assert!("ftp://host/x".parse::<Endpoint>().is_err());
        assert!("".parse::<Endpoint>().is_err());
    }

    #[test]
    fn displays_the_spelling_it_parsed() {
        assert_eq!(
            "http://host:8000".parse::<Endpoint>().unwrap().to_string(),
            "http://host:8000/"
        );
        #[cfg(unix)]
        assert_eq!(
            "unix:///run/noted.sock"
                .parse::<Endpoint>()
                .unwrap()
                .to_string(),
            "unix:///run/noted.sock"
        );
    }
}
