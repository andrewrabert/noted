use serde::Serialize;

use crate::error::{rejected, Result};

pub fn dump_front<T: Serialize>(front: &T, body: &str) -> Result<String> {
    let yaml = serde_yaml::to_string(front).map_err(|e| rejected(format!("yaml: {e}")))?;
    let body = if body.ends_with('\n') {
        body.to_string()
    } else {
        format!("{body}\n")
    };
    Ok(format!("---\n{yaml}---\n{body}"))
}

pub fn split_front(text: &str) -> Option<(&str, &str)> {
    if !text.starts_with("---\n") {
        return None;
    }
    let end = text[4..].find("\n---\n").map(|i| i + 4)?;
    let block = &text[4..end];
    let body = &text[end + "\n---\n".len()..];
    Some((block, body))
}
