//! Editor resolution and launch. The hardcoded fallback list is vendored from
//! <https://github.com/twilligon/edit/blob/master/src/lib.rs>, dedicated to the
//! public domain under CC0-1.0.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use noted::error::{Result, io_error, rejected, unavailable};

use crate::config::EditorPreference;

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

/// A resolved editor: the program and the arguments that precede the file.
pub(crate) struct TextEditor {
    program: PathBuf,
    args: Vec<String>,
}

impl TextEditor {
    /// The first command of `preference` that resolves against `PATH`, else
    /// the first of the platform's known editors. Path lookup runs off the
    /// blocking pool. Rejects with "no editor found" when nothing resolves.
    pub(crate) async fn resolve(preference: &EditorPreference) -> Result<TextEditor> {
        let candidates: Vec<String> = preference
            .commands()
            .iter()
            .cloned()
            .chain(HARDCODED_NAMES.iter().map(|s| s.to_string()))
            .collect();
        tokio::task::spawn_blocking(move || {
            candidates
                .into_iter()
                .find_map(|s| TextEditor::lookup(s).ok())
                .ok_or_else(|| rejected("no editor found"))
        })
        .await
        .map_err(|e| unavailable(format!("editor lookup failed: {e}")))?
    }

    fn lookup(command: String) -> std::result::Result<TextEditor, ()> {
        let (program, args) = split_command(command);
        match which::which(&program) {
            Ok(resolved) => Ok(TextEditor {
                program: resolved,
                args,
            }),
            Err(_) if program.exists() => Ok(TextEditor { program, args }),
            Err(_) => Err(()),
        }
    }

    /// Runs the editor on `file`, inheriting the terminal, and waits for it to
    /// exit. A non-zero exit is rejected, naming the command.
    pub(crate) async fn edit(&self, file: &Path) -> Result<()> {
        let status = tokio::process::Command::new(&self.program)
            .args(&self.args)
            .arg(file)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .map_err(|e| io_error("cannot launch editor", e))?;
        if status.success() {
            return Ok(());
        }
        let mut command = vec![self.program.to_string_lossy().into_owned()];
        command.extend(self.args.iter().cloned());
        command.push(file.to_string_lossy().into_owned());
        Err(rejected(format!(
            "editor '{}' exited with error: {status}",
            command.join(" ")
        )))
    }
}

fn split_command(s: String) -> (PathBuf, Vec<String>) {
    match shell_words::split(&s) {
        Ok(mut v) if !v.is_empty() => (v.remove(0).into(), v),
        _ => {
            let mut args = s.split_ascii_whitespace();
            (
                args.next().unwrap_or_default().into(),
                args.map(String::from).collect(),
            )
        }
    }
}
