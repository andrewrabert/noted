pub mod api;
pub mod clipboard;
mod screen;

use iced::widget::{
    button, column, container, markdown, row, scrollable, space, text, text_editor, text_input,
};
use iced::{Element, Fill, Task, Theme};

use noted::ToolCall;
use noted::tools::ToolOutput;

const LOG_LIMIT: i64 = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Notes,
    Tasks,
    Log,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Editor {
    Note,
    TaskNotes,
    Log,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Created,
    Started,
    Blocked,
    Completed,
    Rejected,
    Invalid,
}

impl TaskState {
    pub const ALL: [TaskState; 6] = [
        TaskState::Created,
        TaskState::Started,
        TaskState::Blocked,
        TaskState::Completed,
        TaskState::Rejected,
        TaskState::Invalid,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            TaskState::Created => "created",
            TaskState::Started => "started",
            TaskState::Blocked => "blocked",
            TaskState::Completed => "completed",
            TaskState::Rejected => "rejected",
            TaskState::Invalid => "invalid",
        }
    }

    pub fn parse(s: &str) -> Option<TaskState> {
        TaskState::ALL.into_iter().find(|st| st.as_str() == s)
    }
}

impl std::fmt::Display for TaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct TaskRow {
    pub path: String,
    pub state: Option<TaskState>,
    pub task: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct LogRow {
    pub path: String,
    pub created: String,
    pub body: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(Tab),
    StatusDismissed,

    FilterChanged(String),
    NotesListed(Result<ToolOutput, String>),
    NoteSelected(String),
    NoteLoaded(String, Result<ToolOutput, String>),
    EditToggled,
    NoteAction(text_editor::Action),
    NoteSaved(Result<ToolOutput, String>),
    NoteEdited(Result<ToolOutput, String>),
    NoteReloaded(String, Result<ToolOutput, String>),
    SaveNote,
    LinkClicked(markdown::Uri),
    FindChanged(String),
    ReplaceChanged(String),
    ReplaceAllToggled,
    ApplyReplace,
    DestChanged(String),
    ApplyRename,
    DeleteArmed,
    ApplyDelete,
    NoteGone(Result<ToolOutput, String>),

    TasksLoaded(Result<ToolOutput, String>),
    RefreshTasks,
    PrefixChanged(String),
    IncludeCompletedToggled,
    TaskMatchChanged(String),
    TasksMatched(Result<ToolOutput, String>),
    TaskSelected(String),
    TaskStateSelected(String, TaskState),
    NewTaskChanged(String),
    NewGroupChanged(String),
    TaskNotesAction(text_editor::Action),
    CreateTask,
    DestGroupChanged(String),
    MoveTask,
    TaskChanged(Result<ToolOutput, String>),

    LogAction(text_editor::Action),
    SubmitLog,
    LogSubmitted(Result<ToolOutput, String>),
    RefreshLog,
    LogFilterChanged(String),
    SinceChanged(String),
    UntilChanged(String),
    LogLoaded(Result<ToolOutput, String>),
    LogMatched(Result<ToolOutput, String>),

    Copy(Editor),
    Paste(Editor),
    Pasted(Editor, Option<String>),
}

pub struct State {
    tab: Tab,
    status: Option<String>,
    theme: Theme,

    notes: Vec<String>,
    picker: picker::PickerState,
    filter: String,
    open: Option<String>,
    preview: markdown::Content,
    editing: bool,
    note: text_editor::Content,
    find: String,
    replace: String,
    replace_all: bool,
    dest: String,
    delete_armed: bool,

    tasks: Vec<TaskRow>,
    prefix: String,
    include_completed: bool,
    task_match: String,
    matched_tasks: Option<Vec<String>>,
    selected_task: Option<String>,
    new_task: String,
    new_group: String,
    task_notes: text_editor::Content,
    dest_group: String,

    log: text_editor::Content,
    log_filter: String,
    since: String,
    until: String,
    entries: Vec<LogRow>,
    hits: String,
}

impl State {
    fn new() -> (State, Task<Message>) {
        let state = State {
            tab: Tab::Notes,
            status: None,
            theme: Theme::TokyoNight,
            notes: Vec::new(),
            picker: picker::PickerState::new(Vec::new()),
            filter: String::new(),
            open: None,
            preview: markdown::Content::new(),
            editing: false,
            note: text_editor::Content::new(),
            find: String::new(),
            replace: String::new(),
            replace_all: false,
            dest: String::new(),
            delete_armed: false,
            tasks: Vec::new(),
            prefix: String::new(),
            include_completed: false,
            task_match: String::new(),
            matched_tasks: None,
            selected_task: None,
            new_task: String::new(),
            new_group: String::new(),
            task_notes: text_editor::Content::new(),
            dest_group: String::new(),
            log: text_editor::Content::new(),
            log_filter: String::new(),
            since: String::new(),
            until: String::new(),
            entries: Vec::new(),
            hits: String::new(),
        };
        (
            state,
            Task::batch([call(list_notes(), Message::NotesListed)]),
        )
    }

    fn tab(&self) -> Tab {
        self.tab
    }

    fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    fn fail(&mut self, what: &str, error: String) {
        self.status = Some(format!("{what}: {error}"));
    }

    fn refilter(&mut self) {
        self.picker.on_key(picker::Key::ClearQuery);
        for c in self.filter.chars() {
            self.picker.on_key(picker::Key::Char(c));
        }
    }

    pub(crate) fn task_rows(&self) -> Vec<TaskRow> {
        match &self.matched_tasks {
            None => self.tasks.clone(),
            Some(matched) => self
                .tasks
                .iter()
                .filter(|row| matched.iter().any(|path| path == &row.path))
                .cloned()
                .collect(),
        }
    }
}

fn list_notes() -> noted::Result<ToolCall> {
    api::search_notes(
        ".",
        noted::search::SearchMode::Path,
        noted::search::SearchOrder::Modified,
    )
}

fn call(
    request: noted::Result<ToolCall>,
    to_message: impl Fn(Result<ToolOutput, String>) -> Message + Send + 'static,
) -> Task<Message> {
    Task::perform(api::invoke(request), to_message)
}

fn update(state: &mut State, message: Message) -> Task<Message> {
    match message {
        Message::TabSelected(tab) => {
            state.tab = tab;
            match tab {
                Tab::Tasks if state.tasks.is_empty() => update(state, Message::RefreshTasks),
                Tab::Log if state.entries.is_empty() && state.hits.is_empty() => {
                    update(state, Message::RefreshLog)
                }
                _ => Task::none(),
            }
        }
        Message::StatusDismissed => {
            state.status = None;
            Task::none()
        }

        Message::FilterChanged(filter) => {
            state.filter = filter;
            state.refilter();
            Task::none()
        }
        Message::NotesListed(Ok(output)) => {
            state.notes = api::paths(&output);
            state.picker = picker::PickerState::new(state.notes.clone());
            state.refilter();
            Task::none()
        }
        Message::NotesListed(Err(e)) => {
            state.fail("cannot list notes", e);
            Task::none()
        }
        Message::NoteSelected(path) => {
            let request = api::read_note(&path);
            state.delete_armed = false;
            state.dest = path.clone();
            Task::perform(api::invoke(request), move |result| {
                Message::NoteLoaded(path.clone(), result)
            })
        }
        Message::NoteLoaded(path, Ok(output)) => {
            let content = api::text(output);
            state.preview = markdown::Content::parse(&content);
            state.note = text_editor::Content::with_text(&content);
            state.open = Some(path);
            state.editing = false;
            Task::none()
        }
        Message::NoteLoaded(path, Err(e)) => {
            state.fail(&format!("cannot read {path}"), e);
            Task::none()
        }
        Message::EditToggled => {
            state.editing = !state.editing;
            Task::none()
        }
        Message::NoteAction(action) => {
            let is_edit = action.is_edit();
            state.note.perform(action);
            if is_edit {
                state.preview = markdown::Content::parse(&state.note.text());
            }
            Task::none()
        }
        Message::SaveNote => match &state.open {
            Some(path) => call(
                api::write_note(path, &state.note.text()),
                Message::NoteSaved,
            ),
            None => Task::none(),
        },
        Message::NoteSaved(result) => {
            state.status = Some(match result {
                Ok(output) => output.render(),
                Err(e) => format!("cannot write: {e}"),
            });
            Task::none()
        }
        // The editor still holds the pre-edit text, which the next save would
        // write back over the edit.
        Message::NoteEdited(Ok(output)) => {
            state.status = Some(output.render());
            match &state.open {
                Some(path) => {
                    let path = path.clone();
                    let request = api::read_note(&path);
                    Task::perform(api::invoke(request), move |result| {
                        Message::NoteReloaded(path.clone(), result)
                    })
                }
                None => Task::none(),
            }
        }
        Message::NoteEdited(Err(e)) => {
            state.fail("cannot edit", e);
            Task::none()
        }
        Message::NoteReloaded(_, Ok(output)) => {
            let content = api::text(output);
            state.preview = markdown::Content::parse(&content);
            state.note = text_editor::Content::with_text(&content);
            Task::none()
        }
        Message::NoteReloaded(path, Err(e)) => {
            state.fail(&format!("cannot reread {path}"), e);
            Task::none()
        }
        Message::LinkClicked(uri) => {
            let target = uri.as_str().trim_start_matches("./").to_string();
            if state.notes.iter().any(|path| path == &target) {
                update(state, Message::NoteSelected(target))
            } else {
                state.status = Some(format!("not a note in this tree: {uri}"));
                Task::none()
            }
        }
        Message::FindChanged(find) => {
            state.find = find;
            Task::none()
        }
        Message::ReplaceChanged(replace) => {
            state.replace = replace;
            Task::none()
        }
        Message::ReplaceAllToggled => {
            state.replace_all = !state.replace_all;
            Task::none()
        }
        Message::ApplyReplace => match (&state.open, state.find.is_empty()) {
            (Some(path), false) => call(
                api::edit_note(path, &state.find, &state.replace, state.replace_all),
                Message::NoteEdited,
            ),
            _ => Task::none(),
        },
        Message::DestChanged(dest) => {
            state.dest = dest;
            Task::none()
        }
        Message::ApplyRename => match &state.open {
            Some(path) if !state.dest.is_empty() && state.dest != *path => {
                call(api::move_note(path, &state.dest, false), Message::NoteGone)
            }
            _ => Task::none(),
        },
        Message::DeleteArmed => {
            state.delete_armed = true;
            Task::none()
        }
        Message::ApplyDelete => match &state.open {
            Some(path) => call(api::delete_note(path), Message::NoteGone),
            None => Task::none(),
        },
        Message::NoteGone(Ok(output)) => {
            state.status = Some(output.render());
            state.open = None;
            state.editing = false;
            state.delete_armed = false;
            state.preview = markdown::Content::new();
            state.note = text_editor::Content::new();
            call(list_notes(), Message::NotesListed)
        }
        Message::NoteGone(Err(e)) => {
            state.delete_armed = false;
            state.fail("cannot change the tree", e);
            Task::none()
        }

        Message::RefreshTasks => {
            let listing = call(
                api::get_tasks(&state.prefix, true, state.include_completed),
                Message::TasksLoaded,
            );
            if state.task_match.is_empty() {
                state.matched_tasks = None;
                listing
            } else {
                Task::batch([
                    listing,
                    call(
                        api::search_tasks(
                            &state.task_match,
                            &state.prefix,
                            state.include_completed,
                        ),
                        Message::TasksMatched,
                    ),
                ])
            }
        }
        Message::TasksLoaded(Ok(output)) => {
            state.tasks = task_rows(&api::record(output));
            Task::none()
        }
        Message::TasksLoaded(Err(e)) => {
            state.fail("cannot read tasks", e);
            Task::none()
        }
        Message::PrefixChanged(prefix) => {
            state.prefix = prefix;
            update(state, Message::RefreshTasks)
        }
        Message::IncludeCompletedToggled => {
            state.include_completed = !state.include_completed;
            update(state, Message::RefreshTasks)
        }
        Message::TaskMatchChanged(pattern) => {
            state.task_match = pattern;
            if state.task_match.is_empty() {
                state.matched_tasks = None;
                Task::none()
            } else {
                call(
                    api::search_tasks(&state.task_match, &state.prefix, state.include_completed),
                    Message::TasksMatched,
                )
            }
        }
        Message::TasksMatched(Ok(output)) => {
            state.matched_tasks = Some(
                api::paths(&output)
                    .into_iter()
                    .map(|path| path.trim_end_matches(".md").to_string())
                    .collect(),
            );
            Task::none()
        }
        Message::TasksMatched(Err(e)) => {
            state.matched_tasks = Some(Vec::new());
            state.fail("cannot match tasks", e);
            Task::none()
        }
        Message::TaskSelected(path) => {
            state.selected_task = Some(path);
            Task::none()
        }
        Message::TaskStateSelected(path, task_state) => call(
            api::update_task(&path, Some(task_state.as_str()), None, None),
            Message::TaskChanged,
        ),
        Message::NewTaskChanged(task) => {
            state.new_task = task;
            Task::none()
        }
        Message::NewGroupChanged(group) => {
            state.new_group = group;
            Task::none()
        }
        Message::TaskNotesAction(action) => {
            state.task_notes.perform(action);
            Task::none()
        }
        Message::CreateTask => {
            if state.new_task.trim().is_empty() {
                return Task::none();
            }
            let request = api::create_task(
                state.new_task.trim(),
                &state.new_group,
                &state.task_notes.text(),
            );
            state.new_task.clear();
            state.task_notes = text_editor::Content::new();
            call(request, Message::TaskChanged)
        }
        Message::DestGroupChanged(group) => {
            state.dest_group = group;
            Task::none()
        }
        Message::MoveTask => match &state.selected_task {
            Some(path) => call(
                api::move_task(path, &state.dest_group),
                Message::TaskChanged,
            ),
            None => Task::none(),
        },
        Message::TaskChanged(Ok(_)) => update(state, Message::RefreshTasks),
        Message::TaskChanged(Err(e)) => {
            state.fail("cannot change the task", e);
            Task::none()
        }

        Message::LogAction(action) => {
            state.log.perform(action);
            Task::none()
        }
        Message::SubmitLog => {
            let body = state.log.text();
            if body.trim().is_empty() {
                return Task::none();
            }
            state.log = text_editor::Content::new();
            call(api::log_note(&body), Message::LogSubmitted)
        }
        Message::LogSubmitted(Ok(output)) => {
            state.status = Some(output.render());
            update(state, Message::RefreshLog)
        }
        Message::LogSubmitted(Err(e)) => {
            state.fail("cannot log", e);
            Task::none()
        }
        Message::RefreshLog => {
            if state.log_filter.is_empty() {
                state.hits.clear();
                call(
                    api::get_log(&state.since, &state.until, LOG_LIMIT),
                    Message::LogLoaded,
                )
            } else {
                state.entries.clear();
                call(
                    api::search_log(&state.log_filter, &state.since, &state.until, LOG_LIMIT),
                    Message::LogMatched,
                )
            }
        }
        Message::LogFilterChanged(filter) => {
            state.log_filter = filter;
            update(state, Message::RefreshLog)
        }
        Message::SinceChanged(since) => {
            state.since = since;
            update(state, Message::RefreshLog)
        }
        Message::UntilChanged(until) => {
            state.until = until;
            update(state, Message::RefreshLog)
        }
        Message::LogLoaded(Ok(output)) => {
            state.entries = log_rows(&api::record(output));
            Task::none()
        }
        Message::LogLoaded(Err(e)) => {
            state.fail("cannot read the log", e);
            Task::none()
        }
        Message::LogMatched(Ok(output)) => {
            state.hits = api::text(output);
            Task::none()
        }
        Message::LogMatched(Err(e)) => {
            state.fail("cannot search the log", e);
            Task::none()
        }

        Message::Copy(editor) => {
            let selection = match editor {
                Editor::Note => state.note.selection(),
                Editor::TaskNotes => state.task_notes.selection(),
                Editor::Log => state.log.selection(),
            };
            if let Some(selection) = selection {
                clipboard::write(selection);
            }
            Task::none()
        }
        Message::Paste(editor) => {
            Task::perform(clipboard::read(), move |text| Message::Pasted(editor, text))
        }
        Message::Pasted(editor, Some(text)) => {
            let action =
                text_editor::Action::Edit(text_editor::Edit::Paste(std::sync::Arc::new(text)));
            match editor {
                Editor::Note => update(state, Message::NoteAction(action)),
                Editor::TaskNotes => update(state, Message::TaskNotesAction(action)),
                Editor::Log => update(state, Message::LogAction(action)),
            }
        }
        Message::Pasted(_, None) => Task::none(),
    }
}

fn task_rows(record: &serde_json::Value) -> Vec<TaskRow> {
    record
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| TaskRow {
                    path: string_at(item, "path"),
                    state: TaskState::parse(&string_at(item, "state")),
                    task: string_at(item, "task"),
                    updated_at: string_at(item, "updated_at"),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn log_rows(record: &serde_json::Value) -> Vec<LogRow> {
    record
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| LogRow {
                    path: string_at(item, "path"),
                    created: string_at(item, "created"),
                    body: string_at(item, "body"),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn string_at(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn view(state: &State) -> Element<'_, Message> {
    let tabs = row![
        tab_button("Notes", Tab::Notes, state.tab()),
        tab_button("Tasks", Tab::Tasks, state.tab()),
        tab_button("Log", Tab::Log, state.tab()),
        space::horizontal(),
    ]
    .spacing(5);

    let body = match state.tab() {
        Tab::Notes => screen::notes::view(state),
        Tab::Tasks => screen::tasks::view(state),
        Tab::Log => screen::log::view(state),
    };

    let mut screen = column![tabs, body].spacing(10).padding(10).height(Fill);
    if let Some(status) = state.status() {
        screen = screen.push(
            container(
                row![
                    scrollable(text(status.to_string())).width(Fill),
                    button("x").on_press(Message::StatusDismissed),
                ]
                .spacing(10),
            )
            .padding(5),
        );
    }
    screen.into()
}

fn tab_button(label: &str, tab: Tab, current: Tab) -> Element<'_, Message> {
    let button = button(text(label.to_string()));
    if tab == current {
        button.into()
    } else {
        button.on_press(Message::TabSelected(tab)).into()
    }
}

fn editor<'a>(
    content: &'a text_editor::Content,
    which: Editor,
    on_action: fn(text_editor::Action) -> Message,
) -> text_editor::TextEditor<'a, iced::advanced::text::highlighter::PlainText, Message> {
    text_editor(content)
        .on_action(on_action)
        .key_binding(move |press| {
            let binding = text_editor::Binding::from_key_press(press.clone())?;
            match binding {
                text_editor::Binding::Copy => {
                    Some(text_editor::Binding::Custom(Message::Copy(which)))
                }
                text_editor::Binding::Cut => Some(text_editor::Binding::Sequence(vec![
                    text_editor::Binding::Custom(Message::Copy(which)),
                    text_editor::Binding::Backspace,
                ])),
                text_editor::Binding::Paste => {
                    Some(text_editor::Binding::Custom(Message::Paste(which)))
                }
                other => Some(other),
            }
        })
}

fn labeled_input<'a>(
    label: &'a str,
    value: &'a str,
    on_input: fn(String) -> Message,
) -> Element<'a, Message> {
    row![
        text(label).width(90),
        text_input(label, value).on_input(on_input),
    ]
    .spacing(5)
    .into()
}

pub fn run() -> iced::Result {
    clipboard::install();
    iced::application(State::new, update, view)
        .title(noted::APP_NAME)
        .theme(|state: &State| state.theme.clone())
        .run()
}
