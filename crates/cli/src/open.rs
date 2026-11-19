use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use tempfile::TempDir;
use tokio::sync::mpsc;

use noted::error::{NotedError, Result, io_error, rejected, unavailable};
use noted::tools::{ReadArgs, SearchNotesArgs, Tools, WriteArgs};
use noted::{NoteEvent, NotePath, TextPath};
use noted_client::{Backend, NoteChanges};

use crate::config::Config;
use crate::picker::Pick;
use crate::text_editor::TextEditor;

#[derive(Args)]
pub(crate) struct OpenArgs {
    /// Note to open, by relative path; omit to pick one interactively
    path: Option<TextPath>,
}

struct Mirror {
    dir: TempDir,
    file: PathBuf,
}

impl Mirror {
    async fn create(path: &TextPath, initial: &str) -> Result<Mirror> {
        let shown = path.to_string();
        let initial = initial.to_string();
        blocking(move || {
            let dir = tempfile::tempdir().map_err(|e| io_error("cannot create temp dir", e))?;
            let mut file = dir
                .path()
                .canonicalize()
                .map_err(|e| io_error("cannot create temp dir", e))?;
            file.extend(shown.split('/').filter(|part| !part.is_empty()));
            if let Some(parent) = file.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| io_error("cannot create temp dir", e))?;
            }
            std::fs::write(&file, initial).map_err(|e| io_error("cannot write temp file", e))?;
            Ok(Mirror { dir, file })
        })
        .await
    }

    async fn read(&self) -> Result<Option<String>> {
        let file = self.file.clone();
        blocking(move || match std::fs::read_to_string(&file) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error("cannot read edited buffer", e)),
        })
        .await
    }

    async fn replace(&self, text: &str) -> Result<()> {
        let file = self.file.clone();
        let text = text.to_string();
        blocking(move || {
            let Some(name) = file.file_name().and_then(|name| name.to_str()) else {
                return Err(rejected("the edit buffer has no utf-8 file name"));
            };
            let sibling = file.with_file_name(format!(".{name}.noted"));
            std::fs::write(&sibling, text).map_err(|e| io_error("cannot write temp file", e))?;
            std::fs::rename(&sibling, &file).map_err(|e| io_error("cannot write temp file", e))
        })
        .await
    }

    async fn remove(&self) -> Result<()> {
        let file = self.file.clone();
        blocking(move || match std::fs::remove_file(&file) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_error("cannot remove temp file", e)),
        })
        .await
    }

    fn keep(self) -> PathBuf {
        self.dir.keep()
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

type Saved = std::result::Result<(), String>;

fn watch_saves(
    file: &Path,
) -> Result<(notify::RecommendedWatcher, mpsc::UnboundedReceiver<Saved>)> {
    use notify::Watcher as _;
    use notify::event::{AccessKind, AccessMode, EventKind};

    let Some(dir) = file.parent() else {
        return Err(rejected("the edit buffer has no directory"));
    };
    let (saved, saves) = mpsc::unbounded_channel();
    let target = file.to_path_buf();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        let report = match event {
            Err(e) => Err(e.to_string()),
            Ok(event) if event.need_rescan() => Ok(()),
            Ok(event) => {
                let wrote = match event.kind {
                    EventKind::Access(AccessKind::Close(AccessMode::Write)) => true,
                    EventKind::Access(_) => false,
                    _ => true,
                };
                if !(wrote && event.paths.contains(&target)) {
                    return;
                }
                Ok(())
            }
        };
        let _ = saved.send(report);
    })
    .map_err(|e| unavailable(format!("cannot watch the edit buffer: {e}")))?;
    watcher
        .watch(dir, notify::RecursiveMode::NonRecursive)
        .map_err(|e| unavailable(format!("cannot watch the edit buffer: {e}")))?;
    Ok((watcher, saves))
}

pub(crate) async fn run_open(config: &Config, args: OpenArgs) -> Result<ExitCode> {
    let backend = config.connect().await?;
    let editor = TextEditor::resolve(&config.editor()).await?;
    let path = match args.path {
        Some(path) => path,
        None => match pick_path(&backend).await? {
            Pick::Chosen(choice) => TextPath::try_from(NotePath::new(&choice)?)?,
            Pick::Aborted => return Ok(ExitCode::SUCCESS),
        },
    };
    edit_note(&backend, &editor, path).await
}

async fn pick_path(backend: &Backend) -> Result<Pick> {
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        return Err(rejected("open with no path requires a terminal"));
    }
    let paths = list_paths(backend).await?;
    if paths.is_empty() {
        return Err(rejected("no notes"));
    }
    crate::picker::pick(paths).await
}

async fn list_paths(backend: &Backend) -> Result<Vec<String>> {
    let hits = backend.search_notes(SearchNotesArgs::recent()).await?;
    Ok(hits
        .into_iter()
        .filter(|hit| hit.path.as_ref() != &NotePath::default())
        .map(|hit| hit.path.to_string())
        .collect())
}

async fn edit_note(backend: &Backend, editor: &TextEditor, path: TextPath) -> Result<ExitCode> {
    let mut changes = Some(backend.watch_note(path.clone()).await?);
    let initial: String = read_body(backend, &path).await?.unwrap_or_default();
    let mirror = Mirror::create(&path, &initial).await?;
    let (_watcher, mut saves) = watch_saves(&mirror.file)?;
    let mut session = Session {
        backend,
        path,
        mirror,
        synced: Some(initial),
        pushed: false,
        notices: Vec::new(),
    };

    let file = session.mirror.file.clone();
    let editing = editor.edit(&file);
    tokio::pin!(editing);
    let edited = loop {
        tokio::select! {
            edited = &mut editing => break edited,
            Some(saved) = saves.recv() => {
                let mut burst = vec![saved];
                while let Ok(saved) = saves.try_recv() {
                    burst.push(saved);
                }
                for failed in burst.into_iter().filter_map(std::result::Result::err) {
                    session.notice(format!("watching the edit buffer failed: {failed}"));
                }
                let pushed = session.push().await;
                session.report(pushed);
            }
            change = next_change(&mut changes) => match change {
                Ok(Some(event)) => {
                    let applied = session.apply(event).await;
                    session.report(applied);
                }
                Ok(None) => {
                    session.notice(format!("changes to '{}' stopped arriving", session.path));
                    changes = None;
                }
                Err(e) => session.notice(format!("cannot follow '{}': {e}", session.path)),
            },
        }
    };
    let last = session.push().await;
    session.finish(edited, last)
}

async fn next_change(changes: &mut Option<NoteChanges>) -> Result<Option<NoteEvent>> {
    match changes {
        Some(changes) => changes.next().await,
        None => std::future::pending().await,
    }
}

struct Session<'a> {
    backend: &'a Backend,
    path: TextPath,
    mirror: Mirror,
    synced: Option<String>,
    pushed: bool,
    notices: Vec<String>,
}

impl Session<'_> {
    fn notice(&mut self, message: String) {
        if self.notices.last() != Some(&message) {
            self.notices.push(message);
        }
    }

    fn report(&mut self, outcome: Result<()>) {
        if let Err(e) = outcome {
            self.notice(format!("'{}': {e}", self.path));
        }
    }

    async fn push(&mut self) -> Result<()> {
        let Some(text) = self.mirror.read().await? else {
            return Ok(());
        };
        if self.synced.as_ref() == Some(&text) {
            return Ok(());
        }
        write_body(self.backend, &self.path, text.clone()).await?;
        self.synced = Some(text);
        self.pushed = true;
        Ok(())
    }

    async fn apply(&mut self, event: NoteEvent) -> Result<()> {
        if self.mirror.read().await? != self.synced {
            return self.push().await;
        }
        let remote = match event.removed {
            true => None,
            false => read_body(self.backend, &self.path).await?,
        };
        if remote == self.synced {
            return Ok(());
        }
        match &remote {
            Some(text) => self.mirror.replace(text).await?,
            None => self.mirror.remove().await?,
        }
        self.synced = remote;
        Ok(())
    }

    fn finish(self, edited: Result<()>, last: Result<()>) -> Result<ExitCode> {
        for notice in &self.notices {
            eprintln!("{notice}");
        }
        if let Err(e) = last {
            eprintln!(
                "your edits are preserved at {}",
                self.mirror.keep().display()
            );
            if let Err(editor) = edited {
                eprintln!("{editor}");
            }
            return Err(e);
        }
        edited?;
        match self.pushed {
            true => println!("wrote {}", self.path),
            false => println!("unchanged"),
        }
        Ok(ExitCode::SUCCESS)
    }
}

async fn read_body(backend: &Backend, path: &TextPath) -> Result<Option<String>> {
    match backend.read_note(ReadArgs::new(path.clone())).await {
        Ok(note) => Ok(Some(note.body().as_str().to_string())),
        Err(NotedError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

async fn write_body(backend: &Backend, path: &TextPath, text: String) -> Result<()> {
    backend.write_note(WriteArgs::new(path.clone(), text)).await
}
