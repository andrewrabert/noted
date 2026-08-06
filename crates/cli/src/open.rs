use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use tempfile::TempDir;

use noted::error::{NotedError, Result, io_error, rejected, unavailable};
use noted::note::{Condition, TextNote};
use noted::path::Path;
use noted::tools::{ReadArgs, SearchNotesArgs, ToolOutput, WriteArgs};
use noted::{AuthorizedBackend, ToolCall};

use crate::config::Config;
use crate::picker::Pick;
use crate::text_editor::TextEditor;

#[derive(Args)]
pub(crate) struct OpenArgs {
    /// Note to open, by relative path; omit to pick one interactively
    path: Option<Path>,
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
    /// Creates the temp dir and seeds the file off the blocking pool.
    async fn create(basename: &str, initial: &str) -> Result<EditBuffer> {
        let basename = basename.to_string();
        let initial = initial.to_string();
        blocking(move || {
            let dir = tempfile::tempdir().map_err(|e| io_error("cannot create temp dir", e))?;
            let file = dir.path().join(basename);
            std::fs::write(&file, initial).map_err(|e| io_error("cannot write temp file", e))?;
            Ok(EditBuffer {
                dir: Some(dir),
                file,
                armed: false,
            })
        })
        .await
    }

    /// Reads the edited text off the blocking pool.
    async fn read(&self) -> Result<String> {
        let file = self.file.clone();
        blocking(move || {
            std::fs::read_to_string(&file).map_err(|e| io_error("cannot read edited buffer", e))
        })
        .await
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

async fn blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| unavailable(format!("edit buffer failed: {e}")))?
}

pub(crate) async fn run_open(config: &Config, args: OpenArgs) -> Result<ExitCode> {
    let backend = config.connect().await?;
    let backend = backend.with_authority(None)?;
    let editor = TextEditor::resolve(&config.editor()).await?;
    let path = match args.path {
        Some(path) => path,
        None => match pick_path(&backend).await? {
            Pick::Chosen(choice) => choice.parse()?,
            Pick::Aborted => return Ok(ExitCode::SUCCESS),
        },
    };
    edit_note(&backend, &editor, path, args.force).await
}

async fn pick_path(backend: &AuthorizedBackend<'_>) -> Result<Pick> {
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        return Err(rejected("open with no path requires a terminal"));
    }
    let paths = list_paths(backend).await?;
    if paths.is_empty() {
        return Err(rejected("no notes"));
    }
    crate::picker::pick(paths).await
}

async fn list_paths(backend: &AuthorizedBackend<'_>) -> Result<Vec<String>> {
    let call = ToolCall::new(SearchNotesArgs::recent())?;
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

async fn edit_note(
    backend: &AuthorizedBackend<'_>,
    editor: &TextEditor,
    path: Path,
    force: bool,
) -> Result<ExitCode> {
    let original = match read_note(backend, &path).await {
        Ok(note) => Some(note),
        Err(NotedError::NotFound) => None,
        Err(e) => return Err(e),
    };
    let initial = original
        .as_ref()
        .map(|note| note.body().as_str())
        .unwrap_or_default();

    let shown = path.to_string();
    let basename = shown.rsplit('/').next().unwrap_or(&shown);
    let mut buffer = EditBuffer::create(basename, initial).await?;

    editor.edit(&buffer.file).await?;

    let edited = buffer.read().await?;
    if edited == initial {
        println!("unchanged");
        buffer.commit();
        return Ok(ExitCode::SUCCESS);
    }

    let edited = match &original {
        Some(original) => original.clone().with_body(edited),
        None => TextNote::new(path.clone(), edited),
    };

    buffer.arm();
    let when = if force {
        None
    } else {
        Some(match &original {
            None => Condition::Missing,
            Some(original) => Condition::Matching(original.etag()),
        })
    };

    match write_note(backend, &edited, when).await {
        Ok(out) => {
            println!("{}", out.render());
            buffer.commit();
            Ok(ExitCode::SUCCESS)
        }
        Err(NotedError::Conflict) => {
            eprintln!("note changed since it was opened: '{path}'");
            if std::io::stdin().is_terminal()
                && crate::prompt::confirm("overwrite anyway? [y/N]").await
            {
                let out = write_note(backend, &edited, None).await?;
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

async fn read_note(backend: &AuthorizedBackend<'_>, path: &Path) -> Result<TextNote> {
    let call = ToolCall::new(ReadArgs::new(path.clone()))?;
    match backend.invoke(&call).await? {
        ToolOutput::Text(s) => Ok(TextNote::new(path.clone(), s)),
        other => Err(rejected(format!(
            "unexpected read output: {}",
            other.render()
        ))),
    }
}

async fn write_note(
    backend: &AuthorizedBackend<'_>,
    note: &TextNote,
    when: Option<Condition>,
) -> Result<ToolOutput> {
    let mut args = WriteArgs::new(note.path().clone(), note.body().clone());
    if let Some(when) = when {
        args = args.when(when);
    }
    backend.invoke(&ToolCall::new(args)?).await
}

#[cfg(test)]
mod tests {
    use super::parse_paths;

    #[test]
    fn parse_paths_keeps_notes_and_drops_blanks_and_non_notes() {
        let text = "Inbox.md\n\n  projects/ideas.md  \nprojects/diagram.png\n";
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
