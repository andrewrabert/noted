use base64::Engine;
use rand::Rng;

pub use crate::disk::{atomic_create, atomic_write, normalize, temp_dir_in};

pub fn random_token(n_bytes: usize) -> String {
    let mut bytes = vec![0u8; n_bytes];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

// orders by unicode-lowercased chars, falling back to raw order as the
// tiebreak; allocates nothing per comparison
pub fn case_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.chars()
        .flat_map(char::to_lowercase)
        .cmp(b.chars().flat_map(char::to_lowercase))
        .then_with(|| a.cmp(b))
}

pub fn slice_lines(text: &str, offset: Option<i64>, limit: Option<i64>) -> String {
    if offset.is_none() && limit.is_none() {
        return text.to_string();
    }
    let lines: Vec<&str> = text.lines().collect();
    let start = offset
        .filter(|o| *o > 0)
        .map(|o| (o - 1) as usize)
        .unwrap_or(0);
    let start = start.min(lines.len());
    let end = match limit {
        Some(l) if l > 0 => (start + l as usize).min(lines.len()),
        _ => lines.len(),
    };
    lines[start..end].join("\n")
}
