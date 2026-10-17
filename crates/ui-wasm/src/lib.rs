pub mod api;
mod browser;
pub mod host;
mod screen;

use browser::{editor, input as text_input};
use iced::widget::{
    button, column, container, markdown, row, scrollable, space, text, text_editor,
};
use iced::{Element, Fill, Task, Theme, Widget};

use noted::search::Hit;
use noted::tasks::{TaskDue, TaskNote, TaskState};
use noted::{LogNote, LogPath, NotePath, TaskPath, TextNote, TextPath, Trashed};
use noted_client::Backend;

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

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(Tab),
    StatusDismissed,
    KeyboardToggled,

    SignInPressed,
    LoginUsernameChanged(String),
    LoginPasswordChanged(String),
    LoginUsernameSubmitted,
    LoginSubmitted,
    LoggedIn(Result<noted::Bearer, api::ApiError>),
    TxnSubmitted(Result<String, api::ApiError>),
    LogoutRequested,
    LogoutConfirmed,

    FilterChanged(String),
    NotesListed(Result<Vec<Hit<TextPath>>, api::ApiError>),
    NoteSelected(String),
    NoteLoaded(String, Result<TextNote, api::ApiError>),
    EditToggled,
    NoteAction(text_editor::Action),
    NoteSaved(Result<(), api::ApiError>),
    NoteEdited(Result<TextNote, api::ApiError>),
    NoteReloaded(String, Result<TextNote, api::ApiError>),
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
    NoteMoved(Result<(), api::ApiError>),
    NoteDeleted(Result<Trashed, api::ApiError>),

    TasksLoaded(Result<Vec<TaskNote>, api::ApiError>),
    RefreshTasks,
    PrefixChanged(String),
    IncludeCompletedToggled,
    TaskMatchChanged(String),
    TasksMatched(Result<Vec<Hit<TaskPath>>, api::ApiError>),
    TaskSelected(String),
    TaskStateSelected(String, TaskState),
    NewTaskChanged(String),
    NewGroupChanged(String),
    NewDueChanged(String),
    TaskNotesAction(text_editor::Action),
    CreateTask,
    DestGroupChanged(String),
    MoveTask,
    DueChanged(String),
    SetDue,
    ClearDue,
    TaskChanged(Result<TaskNote, api::ApiError>),

    LogAction(text_editor::Action),
    SubmitLog,
    LogSubmitted(Result<LogNote, api::ApiError>),
    RefreshLog,
    LogFilterChanged(String),
    SinceChanged(String),
    UntilChanged(String),
    LogLoaded(Result<Vec<LogNote>, api::ApiError>),
    LogMatched(Result<Vec<Hit<LogPath>>, api::ApiError>),

    BrowserEdited(Editor, browser::Edit),
}

/// What the server stamped on the page it served: whether tool calls need a
/// bearer. Read once at boot; nothing asks the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Tool calls need no bearer. There is nothing to sign in to.
    Open,
    /// Tool calls need a bearer minted by the server.
    Bearer,
}

impl AuthMode {
    /// The `data-auth` attribute value. Anything but `open` is `Bearer`, the
    /// strict side.
    pub fn parse(value: Option<&str>) -> AuthMode {
        match value {
            Some("open") => AuthMode::Open,
            _ => AuthMode::Bearer,
        }
    }
}

/// Who the app is acting as.
pub enum Auth {
    /// The server is open; every call goes out with no bearer.
    Open,
    Authed(noted::Bearer),
    LoggedOut,
    Txn {
        txn: String,
        form: LoginForm,
    },
}

#[derive(Debug, Clone, Default)]
pub struct LoginForm {
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
}

impl LoginForm {
    /// Both fields carry text and no submission is in flight.
    pub fn can_submit(&self) -> bool {
        !self.busy && !self.username.is_empty() && !self.password.is_empty()
    }

    /// Keeps the username, clears the password, names the failure.
    pub fn reject(&mut self, error: &api::ApiError) {
        self.busy = false;
        self.password.clear();
        self.error = Some(error.message());
    }
}

pub struct State {
    host: std::rc::Rc<dyn host::Host>,
    auth: Auth,
    logout_armed: bool,

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

    tasks: Vec<TaskNote>,
    prefix: String,
    include_completed: bool,
    task_match: String,
    matched_tasks: Option<Vec<TaskPath>>,
    selected_task: Option<String>,
    new_task: String,
    new_group: String,
    new_due: String,
    task_notes: text_editor::Content,
    dest_group: String,
    due: String,

    log: text_editor::Content,
    log_filter: String,
    since: String,
    until: String,
    entries: Vec<LogNote>,
    hits: String,
}

impl State {
    fn new(host: std::rc::Rc<dyn host::Host>, mode: AuthMode) -> (State, Task<Message>) {
        if mode == AuthMode::Open {
            let app = State::fresh(host, Auth::Open);
            let task = initial_loads(&app);
            return (app, task);
        }
        match host.entry() {
            host::Entry::Code { code, state } => match (host.take_stash(), host.endpoint()) {
                (Some((verifier, stashed)), Some(endpoint)) if stashed == state => {
                    let app = State::fresh(host, Auth::LoggedOut);
                    let redirect = redirect_uri(&endpoint);
                    (
                        app,
                        Task::perform(
                            async move {
                                api::remote(endpoint, None)?
                                    .exchange_code(
                                        noted_client::oauth::WEB_CLIENT_ID,
                                        &code,
                                        &verifier,
                                        &redirect,
                                    )
                                    .await
                                    .map(|tokens| tokens.access)
                            },
                            |result| Message::LoggedIn(result.map_err(api::ApiError::of)),
                        ),
                    )
                }
                _ => {
                    let mut app = State::fresh(host, Auth::LoggedOut);
                    app.status = Some("login failed: state".to_string());
                    (app, Task::none())
                }
            },
            host::Entry::Txn(txn) => (
                State::fresh(
                    host,
                    Auth::Txn {
                        txn,
                        form: LoginForm::default(),
                    },
                ),
                Task::none(),
            ),
            host::Entry::App => match host.stored_token() {
                Some(token) => {
                    let app = State::fresh(host, Auth::Authed(token));
                    let task = initial_loads(&app);
                    (app, task)
                }
                None => (State::fresh(host, Auth::LoggedOut), Task::none()),
            },
        }
    }

    /// Every field but `host` and `auth` at its default.
    fn fresh(host: std::rc::Rc<dyn host::Host>, auth: Auth) -> State {
        State {
            host,
            auth,
            logout_armed: false,
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
            prefix: String::from("/"),
            include_completed: false,
            task_match: String::new(),
            matched_tasks: None,
            selected_task: None,
            new_task: String::new(),
            new_group: String::from("/"),
            new_due: String::new(),
            task_notes: text_editor::Content::new(),
            dest_group: String::from("/"),
            due: String::new(),
            log: text_editor::Content::new(),
            log_filter: String::new(),
            since: String::new(),
            until: String::new(),
            entries: Vec::new(),
            hits: String::new(),
        }
    }

    fn bearer(&self) -> Option<noted::Bearer> {
        match &self.auth {
            Auth::Authed(token) => Some(token.clone()),
            _ => None,
        }
    }

    /// Forgets the stored token and shows the overlay. The open note, task
    /// notes, and log draft survive.
    fn sign_out(&mut self) {
        self.host.set_token(None);
        self.auth = Auth::LoggedOut;
        self.logout_armed = false;
    }

    fn tab(&self) -> Tab {
        self.tab
    }

    fn status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    fn fail(&mut self, what: &str, error: api::ApiError) {
        self.status = Some(format!("{what}: {}", error.message()));
    }

    fn refilter(&mut self) {
        self.picker.on_key(picker::Key::ClearQuery);
        for c in self.filter.chars() {
            self.picker.on_key(picker::Key::Char(c));
        }
    }

    /// The backend every call goes to; a page with no origin has none.
    fn remote(&self) -> noted::Result<Backend> {
        match self.host.endpoint() {
            Some(endpoint) => api::remote(endpoint, self.bearer()),
            None => Err(noted::error::unavailable("the page has no origin")),
        }
    }

    pub(crate) fn task_rows(&self) -> Vec<TaskNote> {
        match &self.matched_tasks {
            None => self.tasks.clone(),
            Some(matched) => self
                .tasks
                .iter()
                .filter(|task| matched.contains(task.path()))
                .cloned()
                .collect(),
        }
    }
}

fn list_notes(state: &State) -> Task<Message> {
    Task::perform(
        api::search_notes(
            state.remote(),
            ".".to_string(),
            noted::search::SearchMode::Path,
            noted::search::SearchOrder::Modified,
        ),
        Message::NotesListed,
    )
}

/// The built-in client's redirect URI for this origin.
fn redirect_uri(endpoint: &str) -> String {
    match endpoint.parse::<noted::HttpUrl>() {
        Ok(base) => noted_client::oauth::web_redirect_uri(&base),
        Err(_) => format!("{}/", endpoint.trim_end_matches('/')),
    }
}

/// Any tool reply the server refused for want of a credential.
fn rejected_credential(message: &Message) -> bool {
    use api::ApiError::Unauthorized;
    matches!(
        message,
        Message::NotesListed(Err(Unauthorized))
            | Message::NoteLoaded(_, Err(Unauthorized))
            | Message::NoteSaved(Err(Unauthorized))
            | Message::NoteEdited(Err(Unauthorized))
            | Message::NoteReloaded(_, Err(Unauthorized))
            | Message::NoteMoved(Err(Unauthorized))
            | Message::NoteDeleted(Err(Unauthorized))
            | Message::TasksLoaded(Err(Unauthorized))
            | Message::TasksMatched(Err(Unauthorized))
            | Message::TaskChanged(Err(Unauthorized))
            | Message::LogSubmitted(Err(Unauthorized))
            | Message::LogLoaded(Err(Unauthorized))
            | Message::LogMatched(Err(Unauthorized))
    )
}

fn initial_loads(state: &State) -> Task<Message> {
    Task::batch([list_notes(state)])
}

fn update(state: &mut State, message: Message) -> Task<Message> {
    // Under `Auth::Open` a refusal is a server fault, so it falls through to
    // the handler that reports it.
    if rejected_credential(&message) && !matches!(state.auth, Auth::Open) {
        if matches!(state.auth, Auth::Authed(_)) {
            state.sign_out();
            state.status = Some("session expired; sign in again".to_string());
        }
        return Task::none();
    }
    match message {
        Message::SignInPressed => {
            let Some(Ok(base)) = state
                .host
                .endpoint()
                .map(|endpoint| endpoint.parse::<noted::HttpUrl>())
            else {
                return Task::none();
            };
            let verifier = noted::util::random_token(48);
            let secret = noted::util::random_token(24);
            state.host.stash(&verifier, &secret);
            state.host.navigate(
                noted_client::oauth::authorize_url(
                    &base,
                    noted_client::oauth::WEB_CLIENT_ID,
                    &noted_client::oauth::web_redirect_uri(&base),
                    &noted_client::oauth::code_challenge(&verifier),
                    &secret,
                )
                .as_str(),
            );
            Task::none()
        }
        Message::LoginUsernameChanged(username) => {
            if let Auth::Txn { form, .. } = &mut state.auth {
                form.username = username;
            }
            Task::none()
        }
        Message::LoginPasswordChanged(password) => {
            if let Auth::Txn { form, .. } = &mut state.auth {
                form.password = password;
            }
            Task::none()
        }
        Message::LoginUsernameSubmitted => iced::widget::operation::focus(screen::login::PASSWORD),
        Message::LoginSubmitted => {
            #[cfg(target_arch = "wasm32")]
            if let (Auth::Txn { form, .. }, Some((username, password))) =
                (&mut state.auth, browser::login_credentials())
            {
                form.username = username;
                form.password = password;
            }
            let Some(endpoint) = state.host.endpoint() else {
                return Task::none();
            };
            match &mut state.auth {
                Auth::Txn { txn, form } if form.can_submit() => {
                    form.busy = true;
                    form.error = None;
                    let (txn, username, password) =
                        (txn.clone(), form.username.clone(), form.password.clone());
                    Task::perform(
                        async move {
                            api::remote(endpoint, None)?
                                .submit_txn(&txn, &username, &password)
                                .await
                        },
                        |result| Message::TxnSubmitted(result.map_err(api::ApiError::of)),
                    )
                }
                _ => Task::none(),
            }
        }
        Message::TxnSubmitted(Ok(redirect)) => {
            state.host.navigate(&redirect);
            Task::none()
        }
        Message::TxnSubmitted(Err(error)) => {
            if let Auth::Txn { form, .. } = &mut state.auth {
                form.reject(&error);
            }
            Task::none()
        }
        Message::LoggedIn(Ok(token)) => {
            state.host.set_token(Some(&token));
            state.host.replace_url("/");
            state.auth = Auth::Authed(token);
            initial_loads(state)
        }
        Message::LoggedIn(Err(error)) => {
            state.host.replace_url("/");
            state.status = Some(error.message());
            Task::none()
        }
        Message::LogoutRequested if state.editing && !state.logout_armed => {
            state.logout_armed = true;
            Task::none()
        }
        Message::LogoutRequested | Message::LogoutConfirmed => {
            state.host.set_token(None);
            *state = State::fresh(state.host.clone(), Auth::LoggedOut);
            Task::none()
        }
        Message::KeyboardToggled => Task::none(),
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
        Message::NotesListed(Ok(hits)) => {
            state.notes = hits.iter().map(|hit| hit.path.to_string()).collect();
            state.picker = picker::PickerState::new(state.notes.clone());
            state.refilter();
            Task::none()
        }
        Message::NotesListed(Err(e)) => {
            state.fail("cannot list notes", e);
            Task::none()
        }
        Message::NoteSelected(path) => {
            let request = api::read_note(state.remote(), path.clone());
            state.delete_armed = false;
            state.dest = path.clone();
            Task::perform(request, move |result| Message::NoteLoaded(path, result))
        }
        Message::NoteLoaded(path, Ok(note)) => {
            let content = note.body().as_str();
            state.preview = markdown::Content::parse(content);
            state.note = text_editor::Content::with_text(content);
            state.open = Some(path);
            state.editing = false;
            state.logout_armed = false;
            Task::none()
        }
        Message::NoteLoaded(path, Err(e)) => {
            state.fail(&format!("cannot read {path}"), e);
            Task::none()
        }
        Message::EditToggled => {
            state.editing = !state.editing;
            state.logout_armed = false;
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
            Some(path) => Task::perform(
                api::write_note(state.remote(), path.clone(), state.note.text()),
                Message::NoteSaved,
            ),
            None => Task::none(),
        },
        Message::NoteSaved(result) => {
            let path = state.open.clone().unwrap_or_default();
            state.status = Some(match result {
                Ok(()) => format!("wrote {path}"),
                Err(e) => format!("cannot write: {}", e.message()),
            });
            Task::none()
        }
        // The editor still holds the pre-edit text, which the next save would
        // write back over the edit.
        Message::NoteEdited(Ok(note)) => {
            let path: &NotePath = note.path().as_ref();
            state.status = Some(format!("edited {path}"));
            match &state.open {
                Some(path) => {
                    let path = path.clone();
                    let request = api::read_note(state.remote(), path.clone());
                    Task::perform(request, move |result| Message::NoteReloaded(path, result))
                }
                None => Task::none(),
            }
        }
        Message::NoteEdited(Err(e)) => {
            state.fail("cannot edit", e);
            Task::none()
        }
        Message::NoteReloaded(_, Ok(note)) => {
            let content = note.body().as_str();
            state.preview = markdown::Content::parse(content);
            state.note = text_editor::Content::with_text(content);
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
            (Some(path), false) => Task::perform(
                api::edit_note(
                    state.remote(),
                    path.clone(),
                    state.find.clone(),
                    state.replace.clone(),
                    state.replace_all,
                ),
                Message::NoteEdited,
            ),
            _ => Task::none(),
        },
        Message::DestChanged(dest) => {
            state.dest = dest;
            Task::none()
        }
        Message::ApplyRename => match &state.open {
            Some(path) if !state.dest.is_empty() && state.dest != *path => Task::perform(
                api::move_note(state.remote(), path.clone(), state.dest.clone(), false),
                Message::NoteMoved,
            ),
            _ => Task::none(),
        },
        Message::DeleteArmed => {
            state.delete_armed = true;
            Task::none()
        }
        Message::ApplyDelete => match &state.open {
            Some(path) => Task::perform(
                api::delete_note(state.remote(), path.clone()),
                Message::NoteDeleted,
            ),
            None => Task::none(),
        },
        Message::NoteMoved(Ok(())) => {
            let from = state.open.take().unwrap_or_default();
            state.status = Some(format!("moved {from} -> {}", state.dest));
            state.editing = false;
            state.logout_armed = false;
            state.delete_armed = false;
            state.preview = markdown::Content::new();
            state.note = text_editor::Content::new();
            list_notes(state)
        }
        Message::NoteDeleted(Ok(trashed)) => {
            state.status = Some(format!("deleted {trashed}"));
            state.open = None;
            state.editing = false;
            state.logout_armed = false;
            state.delete_armed = false;
            state.preview = markdown::Content::new();
            state.note = text_editor::Content::new();
            list_notes(state)
        }
        Message::NoteMoved(Err(e)) | Message::NoteDeleted(Err(e)) => {
            state.delete_armed = false;
            state.fail("cannot change the tree", e);
            Task::none()
        }

        Message::RefreshTasks => {
            let listing = Task::perform(
                api::get_tasks(
                    state.remote(),
                    state.prefix.clone(),
                    state.include_completed,
                ),
                Message::TasksLoaded,
            );
            if state.task_match.is_empty() {
                state.matched_tasks = None;
                listing
            } else {
                Task::batch([
                    listing,
                    Task::perform(
                        api::search_tasks(
                            state.remote(),
                            state.task_match.clone(),
                            state.prefix.clone(),
                            state.include_completed,
                        ),
                        Message::TasksMatched,
                    ),
                ])
            }
        }
        Message::TasksLoaded(Ok(tasks)) => {
            state.tasks = tasks;
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
                Task::perform(
                    api::search_tasks(
                        state.remote(),
                        state.task_match.clone(),
                        state.prefix.clone(),
                        state.include_completed,
                    ),
                    Message::TasksMatched,
                )
            }
        }
        Message::TasksMatched(Ok(hits)) => {
            state.matched_tasks = Some(hits.into_iter().map(|hit| hit.path).collect());
            Task::none()
        }
        Message::TasksMatched(Err(e)) => {
            state.matched_tasks = Some(Vec::new());
            state.fail("cannot match tasks", e);
            Task::none()
        }
        Message::TaskSelected(path) => {
            state.due = state
                .tasks
                .iter()
                .find(|task| task.path().to_string() == path)
                .and_then(|task| Option::<String>::from(task.front().due))
                .unwrap_or_default();
            state.selected_task = Some(path);
            Task::none()
        }
        Message::TaskStateSelected(path, task_state) => Task::perform(
            api::update_task(state.remote(), path, Some(task_state), None),
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
        Message::NewDueChanged(due) => {
            state.new_due = due;
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
                state.remote(),
                state.new_task.trim().to_string(),
                state.new_group.clone(),
                state.task_notes.text(),
                state.new_due.clone(),
            );
            state.new_task.clear();
            state.new_due.clear();
            state.task_notes = text_editor::Content::new();
            Task::perform(request, Message::TaskChanged)
        }
        Message::DestGroupChanged(group) => {
            state.dest_group = group;
            Task::none()
        }
        Message::MoveTask => match &state.selected_task {
            Some(path) => Task::perform(
                api::move_task(state.remote(), path.clone(), state.dest_group.clone()),
                Message::TaskChanged,
            ),
            None => Task::none(),
        },
        Message::DueChanged(due) => {
            state.due = due;
            Task::none()
        }
        Message::SetDue => match &state.selected_task {
            Some(path) => match state.due.parse::<TaskDue>() {
                Ok(due) => Task::perform(
                    api::update_task(state.remote(), path.clone(), None, Some(due)),
                    Message::TaskChanged,
                ),
                Err(e) => {
                    state.fail("cannot change the task", api::ApiError::of(e));
                    Task::none()
                }
            },
            None => Task::none(),
        },
        Message::ClearDue => match &state.selected_task {
            Some(path) => Task::perform(
                api::update_task(state.remote(), path.clone(), None, Some(TaskDue::none())),
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
            Task::perform(api::log_note(state.remote(), body), Message::LogSubmitted)
        }
        Message::LogSubmitted(Ok(entry)) => {
            let path: &NotePath = entry.path().as_ref();
            state.status = Some(format!("logged {path}"));
            update(state, Message::RefreshLog)
        }
        Message::LogSubmitted(Err(e)) => {
            state.fail("cannot log", e);
            Task::none()
        }
        Message::RefreshLog => {
            if state.log_filter.is_empty() {
                state.hits.clear();
                Task::perform(
                    api::get_log(
                        state.remote(),
                        state.since.clone(),
                        state.until.clone(),
                        LOG_LIMIT,
                    ),
                    Message::LogLoaded,
                )
            } else {
                state.entries.clear();
                Task::perform(
                    api::search_log(
                        state.remote(),
                        state.log_filter.clone(),
                        state.since.clone(),
                        state.until.clone(),
                        LOG_LIMIT,
                    ),
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
        Message::LogLoaded(Ok(entries)) => {
            state.entries = entries;
            Task::none()
        }
        Message::LogLoaded(Err(e)) => {
            state.fail("cannot read the log", e);
            Task::none()
        }
        Message::LogMatched(Ok(hits)) => {
            state.hits = render_search(&hits);
            Task::none()
        }
        Message::LogMatched(Err(e)) => {
            state.fail("cannot search the log", e);
            Task::none()
        }

        Message::BrowserEdited(editor, edit) => {
            let content = match editor {
                Editor::Note => &mut state.note,
                Editor::TaskNotes => &mut state.task_notes,
                Editor::Log => &mut state.log,
            };
            edit.apply(content);
            if editor == Editor::Note {
                state.preview = markdown::Content::parse(&state.note.text());
            }
            Task::none()
        }
    }
}

/// The log's matches as `path:num:text` lines, `--` between entries.
fn render_search(hits: &[Hit<LogPath>]) -> String {
    hits.iter()
        .map(|hit| {
            hit.lines()
                .map(|(num, text)| format!("{}:{num}:{text}", hit.path))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect::<Vec<_>>()
        .join("\n--\n")
}

fn view(state: &State) -> Element<'_, Message> {
    let tabs = row![
        tab_button("Notes", Tab::Notes, state.tab()),
        tab_button("Tasks", Tab::Tasks, state.tab()),
        tab_button("Log", Tab::Log, state.tab()),
        space::horizontal(),
        logout_button(state),
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
            .padding(5)
            .boxed(),
        );
    }
    match &state.auth {
        Auth::Open | Auth::Authed(_) => screen.boxed(),
        auth => iced::widget::center(screen::login::view(auth)).boxed(),
    }
}

fn logout_button(state: &State) -> Element<'_, Message> {
    match (&state.auth, state.logout_armed) {
        (Auth::Authed(_), false) => button(text("log out"))
            .on_press(Message::LogoutRequested)
            .boxed(),
        (Auth::Authed(_), true) => button(text("discard edits and log out"))
            .on_press(Message::LogoutConfirmed)
            .boxed(),
        _ => space::horizontal().boxed(),
    }
}

fn tab_button(label: &str, tab: Tab, current: Tab) -> Element<'_, Message> {
    let button = button(text(label.to_string()));
    if tab == current {
        button.boxed()
    } else {
        button.on_press(Message::TabSelected(tab)).boxed()
    }
}

fn labeled_input<'a>(
    label: &'a str,
    value: &'a str,
    on_input: fn(String) -> Message,
) -> Element<'a, Message> {
    row![
        text(label).width(90),
        text_input(label, value).on_input(on_input).boxed(),
    ]
    .spacing(5)
    .boxed()
}

#[cfg(target_arch = "wasm32")]
pub fn run() -> iced::Result {
    browser::install();
    let host = host::web::WebHost::install();
    let mode = AuthMode::parse(host::web::served_auth().as_deref());
    iced::application(move || State::new(host.clone(), mode), update, view)
        .title(noted::APP_NAME)
        .theme(|state: &State| state.theme.clone())
        .run()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::host::Host;

    impl State {
        fn form(&self) -> Option<&LoginForm> {
            match &self.auth {
                Auth::Txn { form, .. } => Some(form),
                _ => None,
            }
        }
    }
    use std::cell::RefCell;
    use std::rc::Rc;

    struct FakeHost {
        entry: host::Entry,
        endpoint: Option<String>,
        token: RefCell<Option<noted::Bearer>>,
        stash: RefCell<Option<(String, String)>>,
        navigated: RefCell<Option<String>>,
        replaced: RefCell<Option<String>>,
    }

    impl FakeHost {
        fn new(entry: host::Entry) -> Rc<FakeHost> {
            Rc::new(FakeHost {
                entry,
                endpoint: Some("http://notes.test".to_string()),
                token: RefCell::new(None),
                stash: RefCell::new(None),
                navigated: RefCell::new(None),
                replaced: RefCell::new(None),
            })
        }
    }

    impl host::Host for FakeHost {
        fn endpoint(&self) -> Option<String> {
            self.endpoint.clone()
        }

        fn entry(&self) -> host::Entry {
            self.entry.clone()
        }

        fn stored_token(&self) -> Option<noted::Bearer> {
            self.token.borrow().clone()
        }

        fn set_token(&self, token: Option<&noted::Bearer>) {
            *self.token.borrow_mut() = token.cloned();
        }

        fn stash(&self, verifier: &str, state: &str) {
            *self.stash.borrow_mut() = Some((verifier.to_string(), state.to_string()));
        }

        fn take_stash(&self) -> Option<(String, String)> {
            self.stash.borrow_mut().take()
        }

        fn navigate(&self, url: &str) {
            *self.navigated.borrow_mut() = Some(url.to_string());
        }

        fn replace_url(&self, path: &str) {
            *self.replaced.borrow_mut() = Some(path.to_string());
        }
    }

    fn app(host: Rc<FakeHost>) -> State {
        State::new(host, AuthMode::Bearer).0
    }

    #[test]
    fn an_open_page_starts_loaded_with_no_sign_in_and_ignores_a_stored_token() {
        let host = FakeHost::new(host::Entry::App);
        host.set_token(Some(&noted::Bearer::new("stale")));
        let (state, _task) = State::new(host.clone(), AuthMode::Open);
        assert!(matches!(state.auth, Auth::Open));
        assert_eq!(state.bearer(), None);
        assert!(host.stored_token().is_some(), "the token is left in place");
    }

    #[test]
    fn an_open_page_treats_a_code_entry_as_the_app() {
        let host = FakeHost::new(host::Entry::Code {
            code: "c".to_string(),
            state: "s".to_string(),
        });
        host.stash("v", "s");
        let (state, _task) = State::new(host.clone(), AuthMode::Open);
        assert!(matches!(state.auth, Auth::Open));
        assert_eq!(state.status, None);
        assert!(host.take_stash().is_some(), "the stash is untouched");
    }

    #[test]
    fn an_unauthorized_reply_on_an_open_page_is_reported_and_changes_no_state() {
        let host = FakeHost::new(host::Entry::App);
        let (mut state, _task) = State::new(host, AuthMode::Open);
        let _ = update(
            &mut state,
            Message::NotesListed(Err(api::ApiError::Unauthorized)),
        );
        assert!(matches!(state.auth, Auth::Open));
        assert!(state.status.is_some());
    }

    #[test]
    fn the_page_attribute_parses_strictly() {
        assert_eq!(AuthMode::parse(Some("open")), AuthMode::Open);
        assert_eq!(AuthMode::parse(Some("bearer")), AuthMode::Bearer);
        assert_eq!(AuthMode::parse(Some("anything")), AuthMode::Bearer);
        assert_eq!(AuthMode::parse(None), AuthMode::Bearer);
    }

    fn authed() -> (Rc<FakeHost>, State) {
        let host = FakeHost::new(host::Entry::App);
        host.set_token(Some(&noted::Bearer::new("t")));
        let state = app(host.clone());
        (host, state)
    }

    #[test]
    fn pressing_sign_in_stashes_a_verifier_and_navigates_to_authorize() {
        let host = FakeHost::new(host::Entry::App);
        let mut state = app(host.clone());
        let _ = update(&mut state, Message::SignInPressed);
        let (verifier, secret) = host.stash.borrow().clone().expect("a stash");
        let navigated = host.navigated.borrow().clone().expect("a navigation");
        assert!(navigated.starts_with("http://notes.test/authorize?"));
        assert!(navigated.contains(&format!("client_id={}", noted_client::oauth::WEB_CLIENT_ID)));
        assert!(navigated.contains(&noted_client::oauth::code_challenge(&verifier)));
        assert!(navigated.contains(&format!("state={secret}")));
    }

    #[test]
    fn a_code_entry_exchanges_the_stashed_verifier() {
        let host = FakeHost::new(host::Entry::Code {
            code: "c".to_string(),
            state: "s".to_string(),
        });
        host.stash("v", "s");
        let state = app(host.clone());
        assert!(matches!(state.auth, Auth::LoggedOut));
        assert_eq!(state.status, None);
        assert_eq!(host.take_stash(), None);
    }

    #[test]
    fn a_code_entry_with_a_mismatched_state_shows_the_overlay() {
        let host = FakeHost::new(host::Entry::Code {
            code: "c".to_string(),
            state: "other".to_string(),
        });
        host.stash("v", "s");
        let state = app(host);
        assert!(matches!(state.auth, Auth::LoggedOut));
        assert_eq!(state.status.as_deref(), Some("login failed: state"));
    }

    #[test]
    fn a_finished_token_is_stored_and_the_code_leaves_the_address_bar() {
        let host = FakeHost::new(host::Entry::App);
        let mut state = app(host.clone());
        let _ = update(
            &mut state,
            Message::LoggedIn(Ok(noted::Bearer::new("minted"))),
        );
        assert!(matches!(state.auth, Auth::Authed(_)));
        assert_eq!(
            host.stored_token().map(|token| token.expose().to_string()),
            Some("minted".to_string())
        );
        assert_eq!(host.replaced.borrow().as_deref(), Some("/"));
    }

    #[test]
    fn a_txn_entry_shows_the_login_form_and_loads_nothing() {
        let host = FakeHost::new(host::Entry::Txn("txn-1".to_string()));
        let (state, _task) = State::new(host, AuthMode::Bearer);
        assert!(matches!(&state.auth, Auth::Txn { txn, .. } if txn == "txn-1"));
        assert!(state.notes.is_empty());
    }

    #[test]
    fn a_submitted_transaction_navigates_to_the_redirect() {
        let host = FakeHost::new(host::Entry::Txn("txn-1".to_string()));
        let mut state = app(host.clone());
        let _ = update(
            &mut state,
            Message::TxnSubmitted(Ok("http://notes.test/?code=c&state=s".to_string())),
        );
        assert_eq!(
            host.navigated.borrow().as_deref(),
            Some("http://notes.test/?code=c&state=s")
        );
    }

    #[test]
    fn a_rejected_credential_keeps_the_username_and_clears_the_password() {
        let host = FakeHost::new(host::Entry::Txn("txn-1".to_string()));
        let mut state = app(host);
        let _ = update(&mut state, Message::LoginUsernameChanged("ann".to_string()));
        let _ = update(&mut state, Message::LoginPasswordChanged("pw".to_string()));
        let _ = update(
            &mut state,
            Message::TxnSubmitted(Err(api::ApiError::InvalidCredentials)),
        );
        let form = state.form().expect("a form");
        assert_eq!(form.username, "ann");
        assert!(form.password.is_empty());
        assert_eq!(
            form.error.as_deref(),
            Some(api::ApiError::InvalidCredentials.message().as_str())
        );
    }

    #[test]
    fn an_unauthorized_reply_clears_the_token_and_keeps_the_open_note() {
        let (host, mut state) = authed();
        state.open = Some("Inbox.md".to_string());
        state.note = text_editor::Content::with_text("body");
        let _ = update(
            &mut state,
            Message::NotesListed(Err(api::ApiError::Unauthorized)),
        );
        assert!(matches!(state.auth, Auth::LoggedOut));
        assert_eq!(host.stored_token(), None);
        assert_eq!(state.open.as_deref(), Some("Inbox.md"));
        assert_eq!(state.note.text().trim_end(), "body");
    }

    #[test]
    fn an_unauthorized_reply_while_logged_out_changes_nothing() {
        let host = FakeHost::new(host::Entry::App);
        let mut state = app(host);
        state.status = Some("kept".to_string());
        let _ = update(
            &mut state,
            Message::NotesListed(Err(api::ApiError::Unauthorized)),
        );
        assert!(matches!(state.auth, Auth::LoggedOut));
        assert_eq!(state.status.as_deref(), Some("kept"));
    }

    #[test]
    fn a_form_submits_only_with_both_fields_filled_and_nothing_in_flight() {
        let mut form = LoginForm::default();
        assert!(!form.can_submit());
        form.username = "ann".to_string();
        assert!(!form.can_submit());
        form.password = "pw".to_string();
        assert!(form.can_submit());
        form.busy = true;
        assert!(!form.can_submit());
    }

    #[test]
    fn logging_out_drops_the_token_and_empties_every_tab() {
        let (host, mut state) = authed();
        state.open = Some("Inbox.md".to_string());
        state.tasks = vec![
            serde_json::from_value(serde_json::json!({
                "path": "/dev/#1",
                "front": {
                    "task": "do it",
                    "state": TaskState::Created,
                    "due": null,
                    "created_at": "2026-07-01T09:00:00-07:00",
                    "updated_at": "2026-07-01T09:00:00-07:00",
                },
                "body": "",
            }))
            .unwrap(),
        ];
        state.entries = vec![
            serde_json::from_value(serde_json::json!({
                "path": "/@2026-07-01T09:00:00.000000-07:00",
                "front": {
                    "created": "2026-07-01T09:00:00-07:00",
                    "cwd": "",
                    "host": "",
                    "source": null,
                },
                "body": "hi",
            }))
            .unwrap(),
        ];
        let _ = update(&mut state, Message::LogoutRequested);
        assert!(matches!(state.auth, Auth::LoggedOut));
        assert_eq!(host.stored_token(), None);
        assert!(state.open.is_none());
        assert!(state.tasks.is_empty());
        assert!(state.entries.is_empty());
    }

    #[test]
    fn an_unauthorized_reply_names_the_expired_session() {
        let (_host, mut state) = authed();
        let _ = update(
            &mut state,
            Message::NotesListed(Err(api::ApiError::Unauthorized)),
        );
        assert!(matches!(state.auth, Auth::LoggedOut));
        assert_eq!(
            state.status.as_deref(),
            Some("session expired; sign in again")
        );
    }

    #[test]
    fn a_failed_exchange_shows_the_overlay_and_clears_the_address_bar() {
        let host = FakeHost::new(host::Entry::App);
        let mut state = app(host.clone());
        let _ = update(
            &mut state,
            Message::LoggedIn(Err(api::ApiError::Failed("boom".to_string()))),
        );
        assert!(matches!(state.auth, Auth::LoggedOut));
        assert_eq!(state.status.as_deref(), Some("boom"));
        assert_eq!(host.replaced.borrow().as_deref(), Some("/"));
    }

    #[test]
    fn leaving_edit_mode_disarms_the_logout_button() {
        let (_host, mut state) = authed();
        state.editing = true;
        let _ = update(&mut state, Message::LogoutRequested);
        assert!(state.logout_armed, "the first press arms");
        assert!(matches!(state.auth, Auth::Authed(_)));
        let _ = update(&mut state, Message::EditToggled);
        assert!(!state.editing);
        assert!(!state.logout_armed, "leaving edit mode disarms");
    }
}
