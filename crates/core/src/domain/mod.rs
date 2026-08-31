//! Domain: the segment grammar, the base path, and the types composed on it.
//!
//!   Segment   - one part; opaque; built only here, read via `as_str`
//!   Path      - the base: a Segment list with the one spelling (`/`, `/a/b`)
//!   NotePath  - Path + no dotted segment; measured from Scope; the public door
//!   Region    - Notes, Log, Tasks; owns each base directory as a Path

pub(crate) mod notepath;
pub(crate) mod path;
pub(crate) mod region;
pub(crate) mod segment;

pub use notepath::NotePath;
pub(crate) use path::Path;
pub(crate) use region::Region;
pub(crate) use segment::Segment;

/// Source guards: each rule names a token that may appear only where stated.
/// The failure line reads `<file>: <n> x <token> <rule>`.
/// The needles are spelled with `concat!` so this file does not carry the
/// tokens it forbids.
#[cfg(test)]
mod guards {
    use std::fs;

    struct Rule {
        name: &'static str,
        needle: &'static str,
        /// A file passes when its path contains one of these.
        allowed: &'static [&'static str],
        /// The match must not continue an identifier to the left.
        whole_token: bool,
    }

    const RULES: &[Rule] = &[
        Rule {
            name: "appears only under crates/core/src/fs/",
            needle: concat!("std::", "path"),
            allowed: &["/src/fs/"],
            whole_token: false,
        },
        Rule {
            name: "appears only under crates/core/src/fs/",
            needle: concat!("Path", "Buf"),
            allowed: &["/src/fs/"],
            whole_token: false,
        },
        Rule {
            name: "is called only under crates/core/src/domain/",
            needle: concat!("Path::", "new("),
            allowed: &["/src/domain/"],
            whole_token: true,
        },
        Rule {
            name: "appears only in the two server-minting files, root/log.rs and root/task.rs",
            needle: concat!("\".", "md\""),
            allowed: &["/src/root/log.rs", "/src/root/task.rs"],
            whole_token: false,
        },
    ];

    fn sources(dir: &str, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).expect("readable source dir") {
            let entry = entry.expect("readable dir entry");
            let path = entry.path().to_string_lossy().into_owned();
            if entry.file_type().expect("file type").is_dir() {
                sources(&path, out);
            } else if path.ends_with(".rs") {
                out.push(path);
            }
        }
    }

    fn hits(text: &str, rule: &Rule) -> usize {
        text.match_indices(rule.needle)
            .filter(|(at, _)| {
                !rule.whole_token
                    || !text[..*at]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_alphanumeric() || c == '_')
            })
            .count()
    }

    #[test]
    fn forbidden_tokens_stay_in_their_one_home() {
        let mut files = Vec::new();
        sources(concat!(env!("CARGO_MANIFEST_DIR"), "/src"), &mut files);
        let mut failures = Vec::new();
        for rule in RULES {
            for file in &files {
                if rule.allowed.iter().any(|ok| file.contains(ok)) {
                    continue;
                }
                let text = fs::read_to_string(file).expect("readable source");
                let n = hits(&text, rule);
                if n > 0 {
                    failures.push(format!("{file}: {n} x `{}` {}", rule.needle, rule.name));
                }
            }
        }
        assert!(failures.is_empty(), "\n{}\n", failures.join("\n"));
    }
}
