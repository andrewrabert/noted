#[cfg(unix)]
use std::path::PathBuf;

use crate::error::{NotedError, Result, rejected};
use crate::httpurl::HttpUrl;

/// A socket-dialed backend resolves no host: the path, not the authority,
/// names the server.
#[cfg(unix)]
const SOCKET_URL: &str = "http://localhost/";

/// What a client dials: a TCP server named by URL, or a Unix socket named by
/// path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Tcp(HttpUrl),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl Endpoint {
    pub fn tcp(&self) -> Option<&HttpUrl> {
        match self {
            Endpoint::Tcp(url) => Some(url),
            #[cfg(unix)]
            Endpoint::Unix(_) => None,
        }
    }

    pub fn base_url(&self) -> Result<HttpUrl> {
        match self {
            Endpoint::Tcp(url) => Ok(url.clone()),
            #[cfg(unix)]
            Endpoint::Unix(_) => SOCKET_URL.parse(),
        }
    }

    /// The http(s) url a stored credential is keyed by. A unix endpoint is
    /// rejected: it holds no stored login.
    pub fn login_url(&self) -> Result<HttpUrl> {
        match self {
            Endpoint::Tcp(url) => Ok(url.clone()),
            #[cfg(unix)]
            Endpoint::Unix(_) => Err(rejected(
                "a unix endpoint holds no stored login: use an http(s) url",
            )),
        }
    }
}

/// The filesystem path a socket is bound at and dialed on. The path is taken
/// exactly as written, byte for byte, and must be absolute.
#[cfg(unix)]
pub fn socket_path(raw: &std::path::Path) -> Result<PathBuf> {
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

    fn from_str(s: &str) -> Result<Endpoint> {
        match s.strip_prefix("unix:") {
            Some(tail) => {
                let Some(path) = tail.strip_prefix("//") else {
                    return Err(rejected(format!(
                        "a unix endpoint is spelled unix://<path>: {s}"
                    )));
                };
                #[cfg(unix)]
                {
                    Ok(Endpoint::Unix(socket_path(std::path::Path::new(path))?))
                }
                #[cfg(not(unix))]
                {
                    let _ = path;
                    Err(rejected(format!(
                        "this platform holds no unix sockets: {s}"
                    )))
                }
            }
            None => Ok(Endpoint::Tcp(s.parse()?)),
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Tcp(url) => write!(f, "{url}"),
            #[cfg(unix)]
            Endpoint::Unix(path) => write!(f, "unix://{}", path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Endpoint;

    #[test]
    fn parses_http_and_https_as_tcp() {
        let tcp: Endpoint = "http://host:8000".parse().unwrap();
        assert!(tcp.tcp().is_some());
        assert_eq!(tcp.base_url().unwrap().as_str(), "http://host:8000/");
        let tls: Endpoint = "https://host/base".parse().unwrap();
        assert_eq!(tls.base_url().unwrap().as_str(), "https://host/base");
    }

    #[cfg(unix)]
    #[test]
    fn parses_an_absolute_unix_path() {
        let ep: Endpoint = "unix:///run/noted.sock".parse().unwrap();
        assert_eq!(ep, Endpoint::Unix("/run/noted.sock".into()));
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

        let raw = std::path::Path::new(OsStr::from_bytes(b"/run/nc\xffted.sock"));
        assert_eq!(super::socket_path(raw).unwrap(), raw);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_relative_path_given_as_a_path() {
        assert!(super::socket_path(std::path::Path::new("noted.sock")).is_err());
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
