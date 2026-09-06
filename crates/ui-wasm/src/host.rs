//! Everything outside the app — the page's URL, its storage, its clipboard —
//! is behind one trait.

#[cfg(target_arch = "wasm32")]
pub mod web;

/// What the page's own URL asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Code { code: String, state: String },
    Txn(String),
    App,
}

pub trait Host {
    /// The origin every call is aimed at.
    fn endpoint(&self) -> Option<String>;

    /// `/?code=&state=` is `Code`, `/login?txn=` is `Txn`, everything else
    /// `App`.
    fn entry(&self) -> Entry;

    /// The token under the key `noted.token`.
    fn stored_token(&self) -> Option<noted::Bearer>;

    /// `Some` writes the token, `None` removes it.
    fn set_token(&self, token: Option<&noted::Bearer>);

    /// The verifier and state one navigation away from being needed.
    fn stash(&self, verifier: &str, state: &str);

    /// Takes the stash; a second call answers None.
    fn take_stash(&self) -> Option<(String, String)>;

    fn navigate(&self, url: &str);

    /// Rewrites the address bar without a navigation.
    fn replace_url(&self, path: &str);

    /// The text the last paste carried, taken.
    fn clipboard_read(&self) -> Option<String>;

    fn clipboard_write(&self, text: String);
}
