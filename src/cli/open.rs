use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use tempfile::TempDir;

use crate::backend::Backend;
use crate::config::block_on;
use crate::error::{io_error, rejected, NotedError, Result};
use crate::notes::RelPath;
use crate::tools::{ContentHash, ReadArgs, ToolOutput, WriteArgs, WriteWhen};

use super::dispatch::{build_backend, call_of};
use super::GlobalArgs;

#[derive(Args)]
pub(super) struct OpenArgs {
    /// Note to open, by relative path
    path: RelPath,
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
        if self.armed {
            if let Some(dir) = self.dir.take() {
                eprintln!("your edits are preserved at {}", dir.keep().display());
            }
        }
    }
}

pub(super) fn run_open(globals: &GlobalArgs, args: OpenArgs) -> Result<ExitCode> {
    let backend = build_backend(globals)?;
    let path = args.path;

    let initial = match block_on(read_note(&backend, &path)) {
        Ok(text) => Some(text),
        Err(NotedError::NotFound(_)) => None,
        Err(e) => return Err(e),
    };

    let basename = path.rsplit('/').next().unwrap_or(path.as_str());
    let mut buffer = EditBuffer::create(basename, initial.as_deref().unwrap_or_default())?;

    run_editor(&buffer.file)?;

    let edited = std::fs::read_to_string(&buffer.file)
        .map_err(|e| io_error("cannot read edited buffer", e))?;
    if edited == initial.as_deref().unwrap_or_default() {
        println!("unchanged");
        buffer.commit();
        return Ok(ExitCode::SUCCESS);
    }

    buffer.arm();
    let when = if args.force {
        None
    } else {
        Some(match &initial {
            None => WriteWhen::Missing,
            Some(initial) => WriteWhen::ExistsMatching(ContentHash::of(initial)),
        })
    };

    match block_on(write_note(&backend, &path, &edited, when)) {
        Ok(out) => {
            println!("{}", out.render());
            buffer.commit();
            Ok(ExitCode::SUCCESS)
        }
        Err(NotedError::Conflict(_)) => {
            eprintln!("note changed since it was opened: '{path}'");
            if std::io::stdin().is_terminal() && prompt_overwrite() {
                let out = block_on(write_note(&backend, &path, &edited, None))?;
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

async fn read_note(backend: &Backend, path: &RelPath) -> Result<String> {
    let call = call_of("ReadNote", ReadArgs::new(path.clone()));
    match backend.invoke(&call).await? {
        ToolOutput::Text(s) => Ok(s),
        other => Err(rejected(format!(
            "unexpected read output: {}",
            other.render()
        ))),
    }
}

async fn write_note(
    backend: &Backend,
    path: &RelPath,
    content: &str,
    when: Option<WriteWhen>,
) -> Result<ToolOutput> {
    let mut args = WriteArgs::new(path.clone(), content.to_string());
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
