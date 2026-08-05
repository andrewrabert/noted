use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Element, Fill};

use crate::{Editor, LogRow, Message, State, editor};

pub fn view(state: &State) -> Element<'_, Message> {
    column![
        text("An entry is immutable once written: no edit, no move, no delete."),
        editor(&state.log, Editor::Log, Message::LogAction)
            .placeholder("what happened")
            .height(120)
            .padding(10),
        row![button("log it").on_press(Message::SubmitLog)],
        controls(state),
        entries(state),
    ]
    .spacing(10)
    .height(Fill)
    .into()
}

fn controls(state: &State) -> Element<'_, Message> {
    row![
        text_input("match entries", &state.log_filter).on_input(Message::LogFilterChanged),
        text_input("since, e.g. 2026-08-01", &state.since).on_input(Message::SinceChanged),
        text_input("until", &state.until).on_input(Message::UntilChanged),
        button("refresh").on_press(Message::RefreshLog),
    ]
    .spacing(5)
    .into()
}

fn entries(state: &State) -> Element<'_, Message> {
    let body: Element<'_, Message> = if state.log_filter.is_empty() {
        let mut items = column![].spacing(10);
        for entry in &state.entries {
            items = items.push(entry_view(entry));
        }
        items.into()
    } else {
        text(state.hits.clone()).into()
    };
    scrollable(body).height(Fill).into()
}

fn entry_view(entry: &LogRow) -> Element<'_, Message> {
    container(
        column![
            row![
                text(entry.created.clone()).width(260),
                text(entry.path.clone()).width(Fill),
            ]
            .spacing(5),
            text(entry.body.clone()),
        ]
        .spacing(5),
    )
    .padding(5)
    .into()
}
