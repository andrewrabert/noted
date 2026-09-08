//! The only file in the crate that names `web_sys`.

use std::rc::Rc;

use super::{Entry, Host};

const TOKEN_KEY: &str = "noted.token";
const VERIFIER_KEY: &str = "noted.verifier";
const STATE_KEY: &str = "noted.state";

pub struct WebHost;

impl WebHost {
    pub fn install() -> Rc<dyn Host> {
        Rc::new(Self)
    }
}

/// The `data-auth` attribute the server stamped on `<html>`. This is a fact
/// about the served page, not about the browser, so it is not on `Host`.
pub fn served_auth() -> Option<String> {
    web_sys::window()?
        .document()?
        .document_element()?
        .get_attribute("data-auth")
}

fn location() -> Option<web_sys::Location> {
    web_sys::window().map(|window| window.location())
}

fn local() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn session() -> Option<web_sys::Storage> {
    web_sys::window()?.session_storage().ok()?
}

fn query(search: &str, key: &str) -> Option<String> {
    url::form_urlencoded::parse(search.trim_start_matches('?').as_bytes())
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

impl Host for WebHost {
    fn endpoint(&self) -> Option<String> {
        location()?.origin().ok()
    }

    fn entry(&self) -> Entry {
        let Some(location) = location() else {
            return Entry::App;
        };
        let path = location.pathname().unwrap_or_default();
        let search = location.search().unwrap_or_default();
        match path.as_str() {
            "/" => match (query(&search, "code"), query(&search, "state")) {
                (Some(code), Some(state)) => Entry::Code { code, state },
                _ => Entry::App,
            },
            "/login" => match query(&search, "txn") {
                Some(txn) => Entry::Txn(txn),
                None => Entry::App,
            },
            _ => Entry::App,
        }
    }

    fn stored_token(&self) -> Option<noted::Bearer> {
        local()?
            .get_item(TOKEN_KEY)
            .ok()?
            .filter(|token| !token.is_empty())
            .map(noted::Bearer::new)
    }

    fn set_token(&self, token: Option<&noted::Bearer>) {
        let Some(store) = local() else {
            return;
        };
        match token {
            Some(token) => {
                let _ = store.set_item(TOKEN_KEY, token.expose());
            }
            None => {
                let _ = store.remove_item(TOKEN_KEY);
            }
        }
    }

    fn stash(&self, verifier: &str, state: &str) {
        let Some(store) = session() else {
            return;
        };
        let _ = store.set_item(VERIFIER_KEY, verifier);
        let _ = store.set_item(STATE_KEY, state);
    }

    fn take_stash(&self) -> Option<(String, String)> {
        let store = session()?;
        let verifier = store.get_item(VERIFIER_KEY).ok()??;
        let state = store.get_item(STATE_KEY).ok()??;
        let _ = store.remove_item(VERIFIER_KEY);
        let _ = store.remove_item(STATE_KEY);
        Some((verifier, state))
    }

    fn navigate(&self, url: &str) {
        if let Some(location) = location() {
            let _ = location.assign(url);
        }
    }

    fn replace_url(&self, path: &str) {
        if let Some(history) = web_sys::window().and_then(|window| window.history().ok()) {
            let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(path));
        }
    }
}
