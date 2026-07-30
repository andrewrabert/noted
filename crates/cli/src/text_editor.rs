//! Vendored from <https://github.com/twilligon/edit/blob/master/src/lib.rs>.
//! The upstream source is dedicated to the public domain under CC0-1.0.
//!
//! `edit` lets you open and edit something in a text editor, regardless of platform.
//! (Think `git commit`.)
//!
//! It works on Windows, Mac, and Linux, and knows about lots of different text editors to fall
//! back upon in case standard environment variables such as `VISUAL` and `EDITOR` aren't set.
//!
//! Pruned to the single entry point noted uses, [`edit_file`].

use std::{
    env,
    ffi::OsStr,
    io::{Error, ErrorKind, Result},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use which::which;

static ENV_VARS: &[&str] = &["VISUAL", "EDITOR"];

// TODO: should we hardcode full paths as well in case $PATH is borked?
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
#[rustfmt::skip]
static HARDCODED_NAMES: &[&str] = &[
    // CLI editors
    "sensible-editor", "nano", "pico", "vim", "nvim", "vi", "emacs",
    // GUI editors
    "code", "atom", "subl", "gedit", "gvim",
    // Generic "file openers"
    "xdg-open", "gnome-open", "kde-open",
];

#[cfg(target_os = "macos")]
#[rustfmt::skip]
static HARDCODED_NAMES: &[&str] = &[
    // CLI editors
    "nano", "pico", "vim", "nvim", "vi", "emacs",
    // open has a special flag to open in the default text editor
    // (this really should come before the CLI editors, but in order
    // not to break compatibility, we still prefer CLI over GUI)
    "open -Wt",
    // GUI editors
    "code -w", "atom -w", "subl -w", "gvim", "mate",
    // Generic "file openers"
    "open -a TextEdit",
    "open -a TextMate",
    // TODO: "open -f" reads input from standard input and opens with
    // TextEdit. if this flag were used we could skip the tempfile
    "open",
];

#[cfg(target_os = "windows")]
#[rustfmt::skip]
static HARDCODED_NAMES: &[&str] = &[
    // GUI editors
    "code.cmd -n -w", "atom.exe -w", "subl.exe -w",
    // notepad++ does not block for input
    // Installed by default
    "notepad.exe",
    // Generic "file openers"
    "cmd.exe /C start",
];

fn get_full_editor_path<T: AsRef<OsStr>>(binary_name: T) -> which::Result<PathBuf> {
    which(binary_name)
}

fn string_to_cmd(s: String) -> (PathBuf, Vec<String>) {
    match shell_words::split(&s) {
        Ok(mut v) if !v.is_empty() => (v.remove(0).into(), v),
        _ => {
            let mut args = s.split_ascii_whitespace();
            (
                args.next().unwrap().into(),
                args.map(String::from).collect(),
            )
        }
    }
}

fn get_full_editor_cmd(s: String) -> Result<(PathBuf, Vec<String>)> {
    let (path, args) = string_to_cmd(s);
    match get_full_editor_path(&path) {
        Ok(result) => Ok((result, args)),
        Err(_) if path.exists() => Ok((path, args)),
        Err(_) => Err(Error::from(ErrorKind::NotFound)),
    }
}

fn get_editor_args() -> Result<(PathBuf, Vec<String>)> {
    ENV_VARS
        .iter()
        .filter_map(env::var_os)
        .filter(|v| !v.is_empty())
        .filter_map(|v| v.into_string().ok())
        .filter_map(|s| get_full_editor_cmd(s).ok())
        .next()
        .or_else(|| {
            HARDCODED_NAMES
                .iter()
                .map(|s| s.to_string())
                .filter_map(|s| get_full_editor_cmd(s).ok())
                .next()
        })
        .ok_or_else(|| Error::from(ErrorKind::NotFound))
}

/// Open an existing file (or create a new one, depending on the editor's behavior) in the
/// [default editor] and wait for the editor to exit.
///
/// # Arguments
///
/// A [`Path`] to a file, new or existing, to open in the default editor.
///
/// # Returns
///
/// A Result is returned in case of errors finding or spawning the editor, but the contents of the
/// file are not read and returned as in [`edit`] and [`edit_bytes`].
///
/// [default editor]: fn.get_editor.html
/// [`Path`]: https://doc.rust-lang.org/std/path/struct.Path.html
/// [`edit`]: fn.edit.html
/// [`edit_bytes`]: fn.edit_bytes.html
pub fn edit_file<P: AsRef<Path>>(file: P) -> Result<()> {
    let (editor, args) = get_editor_args()?;
    let status = Command::new(&editor)
        .args(&args)
        .arg(file.as_ref())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()?
        .status;

    if status.success() {
        Ok(())
    } else {
        let full_command = if args.is_empty() {
            format!(
                "{} {}",
                editor.to_string_lossy(),
                file.as_ref().to_string_lossy()
            )
        } else {
            format!(
                "{} {} {}",
                editor.to_string_lossy(),
                args.join(" "),
                file.as_ref().to_string_lossy()
            )
        };

        Err(Error::other(format!(
            "editor '{}' exited with error: {}",
            full_command, status
        )))
    }
}
