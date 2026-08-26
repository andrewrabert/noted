use iced::widget::{button, column, pick_list, row, scrollable, table, text, text_input};
use iced::{Element, Fill};

use crate::{Editor, Message, State, TaskRow, TaskState, editor, labeled_input};

pub fn view(state: &State) -> Element<'_, Message> {
    column![controls(state), grid(state), create(state), regroup(state),]
        .spacing(10)
        .height(Fill)
        .into()
}

fn controls(state: &State) -> Element<'_, Message> {
    row![
        text_input("group prefix, e.g. dev/noted", &state.prefix).on_input(Message::PrefixChanged),
        text_input("match tasks", &state.task_match).on_input(Message::TaskMatchChanged),
        button(if state.include_completed {
            "[x] closed"
        } else {
            "[ ] closed"
        })
        .on_press(Message::IncludeCompletedToggled),
        button("refresh").on_press(Message::RefreshTasks),
    ]
    .spacing(5)
    .into()
}

fn grid(state: &State) -> Element<'_, Message> {
    scrollable(table(
        [
            table::column(text("state"), |row: TaskRow| {
                pick_list(row.state, &TaskState::ALL[..], TaskState::to_string)
                    .placeholder("state")
                    .on_select(move |picked| Message::TaskStateSelected(row.path.clone(), picked))
            })
            .width(140),
            table::column(text("task"), |row: TaskRow| {
                let selected = row.task.clone();
                button(text(selected))
                    .on_press(Message::TaskSelected(row.path.clone()))
                    .width(Fill)
            })
            .width(Fill),
            table::column(text("path"), |row: TaskRow| text(row.path)).width(240),
            table::column(text("updated"), |row: TaskRow| text(row.updated_at)).width(220),
        ],
        state.task_rows(),
    ))
    .height(Fill)
    .into()
}

fn create(state: &State) -> Element<'_, Message> {
    column![
        labeled_input("task", &state.new_task, Message::NewTaskChanged),
        labeled_input("group", &state.new_group, Message::NewGroupChanged),
        row![
            editor(
                &state.task_notes,
                Editor::TaskNotes,
                Message::TaskNotesAction
            )
            .placeholder("notes seeding the task body")
            .height(90),
            button("create").on_press(Message::CreateTask),
        ]
        .spacing(5),
    ]
    .spacing(5)
    .into()
}

fn regroup(state: &State) -> Element<'_, Message> {
    let selected = state.selected_task.as_deref().unwrap_or("no task selected");
    row![
        text(selected.to_string()).width(240),
        text_input("destination group", &state.dest_group).on_input(Message::DestGroupChanged),
        button("move").on_press(Message::MoveTask),
    ]
    .spacing(5)
    .into()
}
