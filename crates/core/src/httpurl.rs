use url::Url;

use crate::error::{NotedError, Result, rejected};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpUrl(Url);

impl HttpUrl {
    pub fn as_url(&self) -> &Url {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn join(&self, path: &str) -> HttpUrl {
        let mut url = self.0.clone();
        {
            let mut segments = url.path_segments_mut().expect("http(s) url is a base");
            segments.pop_if_empty();
            for seg in path.split('/').filter(|s| !s.is_empty()) {
                segments.push(seg);
            }
        }
        HttpUrl(url)
    }

    // the url's path, with '?' and the query appended when the url carries one
    // always begins with '/'
    pub fn path_and_query(&self) -> String {
        match self.0.query() {
            Some(query) => format!("{}?{}", self.0.path(), query),
            None => self.0.path().to_string(),
        }
    }
}

impl std::str::FromStr for HttpUrl {
    type Err = NotedError;

    fn from_str(s: &str) -> Result<HttpUrl> {
        let url = Url::parse(s).map_err(|e| rejected(format!("invalid URL {s:?}: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(rejected(format!("URL must be http or https: {s}")));
        }
        if url.cannot_be_a_base() {
            return Err(rejected(format!("not a usable base URL: {s}")));
        }
        Ok(HttpUrl(url))
    }
}

impl std::fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::HttpUrl;

    #[test]
    fn rejects_non_urls_and_non_http_schemes() {
        assert!("fart".parse::<HttpUrl>().is_err());
        assert!("mailto:bob@example.com".parse::<HttpUrl>().is_err());
        assert!("ftp://host/x".parse::<HttpUrl>().is_err());
        assert!("".parse::<HttpUrl>().is_err());
    }

    #[test]
    fn parses_http_and_https() {
        assert!("http://127.0.0.1:8000".parse::<HttpUrl>().is_ok());
        assert!("https://example.com/base".parse::<HttpUrl>().is_ok());
    }

    #[test]
    fn join_appends_onto_base_path() {
        let base: HttpUrl = "http://host:8000".parse().unwrap();
        assert_eq!(
            base.join("tool/ReadNote").as_str(),
            "http://host:8000/tool/ReadNote"
        );

        let prefixed: HttpUrl = "http://host:8000/api".parse().unwrap();
        assert_eq!(
            prefixed.join("macaroon/revoke").as_str(),
            "http://host:8000/api/macaroon/revoke"
        );
    }

    #[test]
    fn path_and_query_carries_the_base_path_and_query() {
        let prefixed: HttpUrl = "http://host:8000/api".parse().unwrap();
        assert_eq!(
            prefixed.join("tool/ReadNote").path_and_query(),
            "/api/tool/ReadNote"
        );

        let queried: HttpUrl = "http://host:8000/tool/ReadNote?x=1".parse().unwrap();
        assert_eq!(queried.path_and_query(), "/tool/ReadNote?x=1");
    }

    #[test]
    fn join_is_stable_regardless_of_trailing_slash() {
        let bare: HttpUrl = "http://host:8000".parse().unwrap();
        let slashed: HttpUrl = "http://host:8000/".parse().unwrap();
        assert_eq!(bare.join("x").as_str(), slashed.join("x").as_str());
    }
}
