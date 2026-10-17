use crate::browser::input as text_input;
use iced::widget::{button, column, pick_list, row, scrollable, table, text};
use iced::{Element, Fill, Widget};

use noted::tasks::{TaskNote, TaskState};

use crate::{Editor, Message, State, editor, labeled_input};

pub fn view(state: &State) -> Element<'_, Message> {
    column![
        controls(state),
        grid(state),
        create(state),
        move_task(state),
        set_due(state),
    ]
    .spacing(10)
    .height(Fill)
    .boxed()
}

fn controls(state: &State) -> Element<'_, Message> {
    row![
        text_input("group prefix, e.g. dev/noted", &state.prefix)
            .on_input(Message::PrefixChanged)
            .boxed(),
        text_input("match tasks", &state.task_match)
            .on_input(Message::TaskMatchChanged)
            .boxed(),
        button(if state.include_completed {
            "[x] closed"
        } else {
            "[ ] closed"
        })
        .on_press(Message::IncludeCompletedToggled),
        button("refresh").on_press(Message::RefreshTasks),
    ]
    .spacing(5)
    .boxed()
}

fn grid(state: &State) -> Element<'_, Message> {
    scrollable(table(
        [
            table::column(text("state"), |row: TaskNote| {
                let path = row.path().to_string();
                pick_list(
                    Some(row.front().state),
                    TaskState::ALL,
                    TaskState::to_string,
                )
                .placeholder("state")
                .on_select(move |picked| Message::TaskStateSelected(path.clone(), picked))
            })
            .width(140),
            table::column(text("task"), |row: TaskNote| {
                let selected = row.front().task.to_string();
                button(text(selected))
                    .on_press(Message::TaskSelected(row.path().to_string()))
                    .width(Fill)
            })
            .width(Fill),
            table::column(text("due"), |row: TaskNote| {
                text(Option::<String>::from(row.front().due).unwrap_or_default())
            })
            .width(110),
            table::column(text("path"), |row: TaskNote| text(row.path().to_string())).width(240),
            table::column(text("updated"), |row: TaskNote| {
                text(row.front().updated_at.to_string())
            })
            .width(220),
        ],
        state.task_rows(),
    ))
    .height(Fill)
    .boxed()
}

fn create(state: &State) -> Element<'_, Message> {
    column![
        labeled_input("task", &state.new_task, Message::NewTaskChanged),
        labeled_input("group", &state.new_group, Message::NewGroupChanged),
        labeled_input("due", &state.new_due, Message::NewDueChanged),
        row![
            editor(
                &state.task_notes,
                Editor::TaskNotes,
                Message::TaskNotesAction
            )
            .placeholder("notes seeding the task body")
            .height(90)
            .boxed(),
            button("create").on_press(Message::CreateTask),
        ]
        .spacing(5),
    ]
    .spacing(5)
    .boxed()
}

fn move_task(state: &State) -> Element<'_, Message> {
    let selected = state.selected_task.as_deref().unwrap_or("no task selected");
    row![
        text(selected.to_string()).width(240),
        text_input("destination group", &state.dest_group)
            .on_input(Message::DestGroupChanged)
            .boxed(),
        button("move").on_press(Message::MoveTask),
    ]
    .spacing(5)
    .boxed()
}

fn set_due(state: &State) -> Element<'_, Message> {
    let selected = state.selected_task.as_deref().unwrap_or("no task selected");
    row![
        text(selected.to_string()).width(240),
        text_input("due YYYY-MM-DD", &state.due)
            .on_input(Message::DueChanged)
            .boxed(),
        button("set due").on_press(Message::SetDue),
        button("clear due").on_press(Message::ClearDue),
    ]
    .spacing(5)
    .boxed()
}
