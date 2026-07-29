use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use tempfile::TempDir;

use crate::backend::Backend;
use crate::config::block_on;
use crate::error::{NotedError, Result, io_error, rejected};
use crate::note::{RelPath, TextNote};
use crate::picker::Pick;
use crate::tools::{ReadArgs, ToolOutput, WriteArgs, WriteWhen};

use super::GlobalArgs;
use super::dispatch::{build_backend, call_of};

#[derive(Args)]
pub(super) struct OpenArgs {
    /// Note to open, by relative path; omit to pick one interactively
    path: Option<RelPath>,
    /// Overwrite unconditionally, ignoring concurrent changes
    #[arg(short, long)]
    force: bool,
}

struct EditBuffer {
    dir: Option<TempDir>,
    file: PathBuf,
    armed: bool,
}

impl EditBuffer {
    fn create(basename: &str, initial: &str) -> Result<EditBuffer> {
        let dir = tempfile::tempdir().map_err(|e| io_error("cannot create temp dir", e))?;
        let file = dir.path().join(basename);
        std::fs::write(&file, initial).map_err(|e| io_error("cannot write temp file", e))?;
        Ok(EditBuffer {
            dir: Some(dir),
            file,
            armed: false,
        })
    }

    fn arm(&mut self) {
        self.armed = true;
    }

    fn commit(mut self) {
        self.dir.take();
    }
}

impl Drop for EditBuffer {
    fn drop(&mut self) {
        if self.armed
            && let Some(dir) = self.dir.take()
        {
            eprintln!("your edits are preserved at {}", dir.keep().display());
        }
    }
}

pub(super) fn run_open(globals: &GlobalArgs, args: OpenArgs) -> Result<ExitCode> {
    let backend = build_backend(globals)?;
    let path = match args.path {
        Some(path) => path,
        None => match pick_path(&backend)? {
            Pick::Chosen(choice) => choice.parse()?,
            Pick::Aborted => return Ok(ExitCode::SUCCESS),
        },
    };
    edit_note(&backend, path, args.force)
}

fn pick_path(backend: &Backend) -> Result<Pick> {
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        return Err(rejected("open with no path requires a terminal"));
    }
    let paths = block_on(list_paths(backend))?;
    if paths.is_empty() {
        return Err(rejected("no notes"));
    }
    crate::picker::pick(paths)
}

async fn list_paths(backend: &Backend) -> Result<Vec<String>> {
    let call = call_of(
        "SearchNotes",
        serde_json::json!({"mode": "path", "pattern": "."}),
    );
    match backend.invoke(&call).await? {
        ToolOutput::Text(s) => Ok(parse_paths(&s)),
        other => Err(rejected(format!(
            "unexpected search output: {}",
            other.render()
        ))),
    }
}

fn parse_paths(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| line.ends_with(".md"))
        .map(str::to_string)
        .collect()
}

fn edit_note(backend: &Backend, path: RelPath, force: bool) -> Result<ExitCode> {
    let original = match block_on(read_note(backend, &path)) {
        Ok(note) => Some(note),
        Err(NotedError::NotFound(_)) => None,
        Err(e) => return Err(e),
    };
    let initial = original.as_ref().map(TextNote::content).unwrap_or_default();

    let basename = path.rsplit('/').next().unwrap_or(path.as_str());
    let mut buffer = EditBuffer::create(basename, initial)?;

    run_editor(&buffer.file)?;

    let edited = std::fs::read_to_string(&buffer.file)
        .map_err(|e| io_error("cannot read edited buffer", e))?;
    if edited == initial {
        println!("unchanged");
        buffer.commit();
        return Ok(ExitCode::SUCCESS);
    }

    let edited = match &original {
        Some(original) => original.clone().with_content(edited),
        None => TextNote::new(path.clone(), edited),
    };

    buffer.arm();
    let when = if force {
        None
    } else {
        Some(match &original {
            None => WriteWhen::Missing,
            Some(original) => WriteWhen::ExistsMatching(original.etag()),
        })
    };

    match block_on(write_note(backend, &edited, when)) {
        Ok(out) => {
            println!("{}", out.render());
            buffer.commit();
            Ok(ExitCode::SUCCESS)
        }
        Err(NotedError::Conflict(_)) => {
            eprintln!("note changed since it was opened: '{path}'");
            if std::io::stdin().is_terminal() && prompt_overwrite() {
                let out = block_on(write_note(backend, &edited, None))?;
                println!("{}", out.render());
                buffer.commit();
                Ok(ExitCode::SUCCESS)
            } else {
                // Armed guard's Drop preserves the buffer and reports the path.
                Ok(ExitCode::FAILURE)
            }
        }
        // Armed guard's Drop preserves the buffer and reports the path.
        Err(e) => Err(e),
    }
}

async fn read_note(backend: &Backend, path: &RelPath) -> Result<TextNote> {
    let call = call_of("ReadNote", ReadArgs::new(path.clone()));
    match backend.invoke(&call).await? {
        ToolOutput::Text(s) => Ok(TextNote::new(path.clone(), s)),
        other => Err(rejected(format!(
            "unexpected read output: {}",
            other.render()
        ))),
    }
}

async fn write_note(
    backend: &Backend,
    note: &TextNote,
    when: Option<WriteWhen>,
) -> Result<ToolOutput> {
    let mut args = WriteArgs::new(note.path().clone(), note.content().to_string());
    if let Some(when) = when {
        args = args.when(when);
    }
    backend.invoke(&call_of("WriteNote", args)).await
}

fn run_editor(file: &std::path::Path) -> Result<()> {
    crate::text_editor::edit_file(file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            rejected("no editor found")
        } else {
            io_error("cannot launch editor", e)
        }
    })
}

fn prompt_overwrite() -> bool {
    eprint!("overwrite anyway? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "Yes")
}

#[cfg(test)]
mod tests {
    use super::parse_paths;

    #[test]
    fn parse_paths_keeps_notes_and_drops_blanks_and_sidecars() {
        let text = "Inbox.md\n\n  projects/ideas.md  \nLog/2026/07/x.md.meta\n";
        assert_eq!(
            parse_paths(text),
            vec!["Inbox.md".to_string(), "projects/ideas.md".to_string()]
        );
    }

    #[test]
    fn parse_paths_of_empty_output_is_empty() {
        assert!(parse_paths("").is_empty());
        assert!(parse_paths("\n \n").is_empty());
    }
}
