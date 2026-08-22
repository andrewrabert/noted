use axum::http::HeaderMap;
use noted_auth::types::{LoginPeerIp, LoginSource, LoginSourceId};

const X_FORWARDED_FOR: &str = "x-forwarded-for";

#[derive(Clone, Copy, Debug)]
pub(crate) struct AcceptedTcpPeer(std::net::SocketAddr);

impl AcceptedTcpPeer {
    pub(crate) const fn new(peer: std::net::SocketAddr) -> AcceptedTcpPeer {
        AcceptedTcpPeer(peer)
    }

    pub(crate) const fn ip(self) -> std::net::IpAddr {
        self.0.ip()
    }
}

pub(crate) fn source(peer: Option<std::net::SocketAddr>, headers: &HeaderMap) -> LoginSource {
    match peer {
        Some(peer) => {
            LoginSource::AcceptedTcpPeer(LoginPeerIp::accepted(AcceptedTcpPeer::new(peer).ip()))
        }
        None => {
            let source = headers
                .get(X_FORWARDED_FOR)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.split(',').next().unwrap_or_default().trim())
                .unwrap_or("?");
            LoginSource::NonTcpAdapter(LoginSourceId::new(source))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn tcp_source_uses_peer_ip_without_port_and_ignores_forwarding_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.7"));
        headers.insert("forwarded", HeaderValue::from_static("for=203.0.113.8"));
        let peer = "192.0.2.4:4321".parse().unwrap();

        assert_eq!(
            source(Some(peer), &headers),
            LoginSource::AcceptedTcpPeer(LoginPeerIp::accepted("192.0.2.4".parse().unwrap()))
        );
    }

    #[test]
    fn non_tcp_source_uses_first_trimmed_forwarded_value_without_ip_parsing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("  gateway.example  , 198.51.100.7"),
        );

        assert_eq!(
            source(None, &headers),
            LoginSource::NonTcpAdapter(LoginSourceId::new("gateway.example"))
        );
    }

    #[test]
    fn non_tcp_source_uses_question_mark_for_absent_and_non_text_headers() {
        assert_eq!(
            source(None, &HeaderMap::new()),
            LoginSource::NonTcpAdapter(LoginSourceId::new("?"))
        );

        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_bytes(b"\xff").unwrap());
        assert_eq!(
            source(None, &headers),
            LoginSource::NonTcpAdapter(LoginSourceId::new("?"))
        );
    }
}
