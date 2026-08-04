use std::iter::Peekable;
use std::str::{FromStr, Lines};

use crate::error::{NotedError, Result, rejected};

/// A flat `---` block of `key: value` lines, in the order the keys were set.
#[derive(Clone, Debug, Default)]
pub struct FrontMatter {
    fields: Vec<(String, String)>,
}

impl FrontMatter {
    pub fn parse(block: &str) -> Result<FrontMatter> {
        let mut fields = Vec::new();
        let mut lines = block.lines().peekable();
        while let Some(line) = lines.next() {
            let text = line.trim_start();
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            let Some((key, rest)) = text.split_once(':') else {
                return Err(rejected(format!("not a front matter field: '{line}'")));
            };
            let key = key.trim_end();
            if key.is_empty() {
                return Err(rejected(format!("not a front matter field: '{line}'")));
            }
            let head = match rest.strip_prefix(' ') {
                Some(head) => head.trim_start(),
                None if rest.is_empty() => "",
                None => return Err(rejected(format!("not a front matter field: '{line}'"))),
            };
            fields.push((key.to_string(), read_scalar(head, &mut lines)?));
        }
        Ok(FrontMatter { fields })
    }

    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        self.fields.push((key.to_string(), value.into()));
    }

    pub fn set_opt(&mut self, key: &str, value: Option<impl Into<String>>) {
        if let Some(value) = value {
            self.set(key, value);
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn field<T: FromStr<Err = NotedError>>(&self, key: &str) -> Result<T> {
        let raw = self
            .get(key)
            .ok_or_else(|| rejected(format!("missing field '{key}'")))?;
        raw.parse()
    }

    pub fn opt_field<T: FromStr<Err = NotedError>>(&self, key: &str) -> Result<Option<T>> {
        self.get(key).map(str::parse).transpose()
    }

    pub fn dump(&self, body: &str) -> String {
        let mut out = String::from("---\n");
        for (key, value) in &self.fields {
            out.push_str(&emit_line(key, value));
            out.push('\n');
        }
        out.push_str("---\n");
        out.push_str(body);
        if !body.ends_with('\n') {
            out.push('\n');
        }
        out
    }
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

fn emit_line(key: &str, value: &str) -> String {
    format!("{key}: {}", emit_scalar(value))
}

fn emit_scalar(value: &str) -> String {
    if is_plain(value) {
        return value.to_string();
    }
    if !value.chars().any(is_unprintable) {
        return format!("'{}'", value.replace('\'', "''"));
    }
    serde_json::Value::String(value.to_string()).to_string()
}

fn is_unprintable(c: char) -> bool {
    (c as u32) < 0x20 || c as u32 == 0x7f
}

fn is_plain(value: &str) -> bool {
    const OPENERS: [char; 16] = [
        ',', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`',
    ];
    if value.is_empty() || value.starts_with(' ') || value.ends_with(' ') {
        return false;
    }
    if value.chars().any(is_unprintable) {
        return false;
    }
    if value.contains(": ") || value.ends_with(':') || value.contains(" #") {
        return false;
    }
    if value.starts_with(OPENERS) {
        return false;
    }
    for indicator in ['-', '?', ':'] {
        if let Some(rest) = value.strip_prefix(indicator)
            && (rest.is_empty() || rest.starts_with(' '))
        {
            return false;
        }
    }
    if value == "---" || value == "..." {
        return false;
    }
    !is_core_scalar(value)
}

// a YAML 1.2 core-schema null, bool, integer or float
fn is_core_scalar(value: &str) -> bool {
    matches!(
        value,
        "null" | "Null" | "NULL" | "~" | "true" | "True" | "TRUE" | "false" | "False" | "FALSE"
    ) || is_inf_or_nan(value)
        || is_int(value)
        || is_float(value)
}

fn is_inf_or_nan(value: &str) -> bool {
    let body = value.strip_prefix(['-', '+']).unwrap_or(value);
    matches!(body, ".inf" | ".Inf" | ".INF") || matches!(value, ".nan" | ".NaN" | ".NAN")
}

fn is_int(value: &str) -> bool {
    if let Some(hex) = value.strip_prefix("0x") {
        return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    if let Some(oct) = value.strip_prefix("0o") {
        return !oct.is_empty()
            && oct
                .bytes()
                .all(|b| b.is_ascii_digit() && b != b'8' && b != b'9');
    }
    let digits = value.strip_prefix(['-', '+']).unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

fn is_float(value: &str) -> bool {
    fn digits(s: &str) -> bool {
        s.bytes().all(|b| b.is_ascii_digit())
    }
    let body = value.strip_prefix(['-', '+']).unwrap_or(value);
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(at) => (&body[..at], Some(&body[at + 1..])),
        None => (body, None),
    };
    if let Some(exponent) = exponent {
        let power = exponent.strip_prefix(['-', '+']).unwrap_or(exponent);
        if power.is_empty() || !digits(power) {
            return false;
        }
    }
    match mantissa.split_once('.') {
        Some(("", frac)) => !frac.is_empty() && digits(frac),
        Some((int, frac)) => !int.is_empty() && digits(int) && digits(frac),
        None => !mantissa.is_empty() && digits(mantissa),
    }
}

fn read_scalar(head: &str, lines: &mut Peekable<Lines<'_>>) -> Result<String> {
    if let Some(rest) = head.strip_prefix('\'') {
        return read_single_quoted(rest);
    }
    if let Some(rest) = head.strip_prefix('"') {
        return read_double_quoted(rest);
    }
    if let Some(rest) = head.strip_prefix('|') {
        return read_literal_block(rest, lines);
    }
    Ok(read_plain(head))
}

fn read_plain(head: &str) -> String {
    let cut = head.find(" #").unwrap_or(head.len());
    head[..cut].trim_end().to_string()
}

fn read_single_quoted(rest: &str) -> Result<String> {
    let mut out = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\'' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('\'') => {
                chars.next();
                out.push('\'');
            }
            _ => return Ok(out),
        }
    }
    Err(rejected("unterminated quoted value"))
}

fn read_double_quoted(rest: &str) -> Result<String> {
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Ok(out),
            '\\' => read_escape(&mut chars, &mut out)?,
            _ => out.push(c),
        }
    }
    Err(rejected("unterminated quoted value"))
}

fn read_escape(chars: &mut std::str::Chars<'_>, out: &mut String) -> Result<()> {
    let Some(c) = chars.next() else {
        return Err(rejected("unterminated escape"));
    };
    let escaped = match c {
        '0' => '\0',
        'a' => '\u{7}',
        'b' => '\u{8}',
        't' => '\t',
        'n' => '\n',
        'v' => '\u{b}',
        'f' => '\u{c}',
        'r' => '\r',
        'e' => '\u{1b}',
        ' ' => ' ',
        '"' => '"',
        '/' => '/',
        '\\' => '\\',
        'N' => '\u{85}',
        '_' => '\u{a0}',
        'L' => '\u{2028}',
        'P' => '\u{2029}',
        'x' => return read_hex(chars, out, 2),
        'u' => return read_hex(chars, out, 4),
        'U' => return read_hex(chars, out, 8),
        other => return Err(rejected(format!("unknown escape '\\{other}'"))),
    };
    out.push(escaped);
    Ok(())
}

fn read_hex(chars: &mut std::str::Chars<'_>, out: &mut String, width: usize) -> Result<()> {
    let mut text = String::new();
    for _ in 0..width {
        match chars.next() {
            Some(c) => text.push(c),
            None => return Err(rejected("truncated escape")),
        }
    }
    let point = u32::from_str_radix(&text, 16).map_err(|_| rejected("invalid escape"))?;
    let escaped = char::from_u32(point).ok_or_else(|| rejected("invalid escape"))?;
    out.push(escaped);
    Ok(())
}

enum Chomp {
    Clip,
    Strip,
    Keep,
}

fn read_literal_block(head: &str, lines: &mut Peekable<Lines<'_>>) -> Result<String> {
    let chomp = match head.trim_end() {
        "" => Chomp::Clip,
        "-" => Chomp::Strip,
        "+" => Chomp::Keep,
        other => return Err(rejected(format!("unsupported block header '|{other}'"))),
    };
    let mut indent: Option<usize> = None;
    let mut out = String::new();
    while let Some(line) = lines.peek() {
        let blank = line.trim().is_empty();
        let depth = line.len() - line.trim_start().len();
        if !blank {
            match indent {
                None => indent = Some(depth),
                Some(first) if depth < first => break,
                Some(_) => {}
            }
        }
        if let (Some(first), false) = (indent, blank) {
            out.push_str(&line[first..]);
        }
        out.push('\n');
        lines.next();
    }
    Ok(match chomp {
        Chomp::Keep => out,
        Chomp::Strip => out.trim_end_matches('\n').to_string(),
        Chomp::Clip => {
            let mut clipped = out.trim_end_matches('\n').to_string();
            if !clipped.is_empty() {
                clipped.push('\n');
            }
            clipped
        }
    })
}
