use crate::browser::input as text_input;
use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Element, Fill, Widget};

use noted::LogNote;

use crate::{Editor, Message, State, editor};

pub fn view(state: &State) -> Element<'_, Message> {
    column![
        text("An entry is immutable once written: no edit, no move, no delete."),
        editor(&state.log, Editor::Log, Message::LogAction)
            .placeholder("what happened")
            .height(120)
            .padding(10)
            .boxed(),
        row![button("log it").on_press(Message::SubmitLog)],
        controls(state),
        entries(state),
    ]
    .spacing(10)
    .height(Fill)
    .boxed()
}

fn controls(state: &State) -> Element<'_, Message> {
    row![
        text_input("match entries", &state.log_filter)
            .on_input(Message::LogFilterChanged)
            .boxed(),
        text_input("since, e.g. 2026-08-01", &state.since)
            .on_input(Message::SinceChanged)
            .boxed(),
        text_input("until", &state.until)
            .on_input(Message::UntilChanged)
            .boxed(),
        button("refresh").on_press(Message::RefreshLog),
    ]
    .spacing(5)
    .boxed()
}

fn entries(state: &State) -> Element<'_, Message> {
    let body: Element<'_, Message> = if state.log_filter.is_empty() {
        let mut items = column![].spacing(10);
        for entry in &state.entries {
            items = items.push(entry_view(entry));
        }
        items.boxed()
    } else {
        text(state.hits.clone()).boxed()
    };
    scrollable(body).height(Fill).boxed()
}

fn entry_view(entry: &LogNote) -> Element<'_, Message> {
    container(
        column![
            row![
                text(entry.front().created.to_string()).width(260),
                text(entry.path().to_string()).width(Fill),
            ]
            .spacing(5),
            text(entry.body().to_string()),
        ]
        .spacing(5),
    )
    .padding(5)
    .boxed()
}
