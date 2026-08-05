use iced::widget::{button, column, container, markdown, row, scrollable, text, text_input};
use iced::{Element, Fill, FillPortion};

use crate::{Editor, Message, State, editor};

pub fn view(state: &State) -> Element<'_, Message> {
    row![
        container(list(state)).width(FillPortion(1)),
        container(note(state)).width(FillPortion(3)),
    ]
    .spacing(10)
    .height(Fill)
    .into()
}

fn list(state: &State) -> Element<'_, Message> {
    let mut items = column![].spacing(2);
    for (_, path) in state.picker.window(usize::MAX) {
        let selected = state.open.as_deref() == Some(path);
        let label = text(path.to_string());
        items = items.push(if selected {
            button(label).width(Fill).into()
        } else {
            Element::from(
                button(label)
                    .width(Fill)
                    .on_press(Message::NoteSelected(path.to_string())),
            )
        });
    }

    column![
        text_input("filter notes", &state.filter).on_input(Message::FilterChanged),
        scrollable(items).height(Fill),
    ]
    .spacing(5)
    .into()
}

fn note(state: &State) -> Element<'_, Message> {
    let Some(path) = state.open.as_deref() else {
        return container(text("pick a note")).padding(10).into();
    };

    let header = row![
        text(path.to_string()).width(Fill),
        button(if state.editing { "preview" } else { "edit" }).on_press(Message::EditToggled),
        button("save").on_press(Message::SaveNote),
    ]
    .spacing(5);

    let body: Element<'_, Message> = if state.editing {
        editor(&state.note, Editor::Note, Message::NoteAction)
            .placeholder("write Markdown here")
            .height(Fill)
            .padding(10)
            .highlight("markdown", iced::highlighter::Theme::Base16Ocean)
            .into()
    } else {
        scrollable(markdown::view(state.preview.items(), &state.theme).map(Message::LinkClicked))
            .spacing(10)
            .height(Fill)
            .into()
    };

    column![header, body, replace(state), rename(state)]
        .spacing(10)
        .into()
}

fn replace(state: &State) -> Element<'_, Message> {
    row![
        text_input("find", &state.find).on_input(Message::FindChanged),
        text_input("replace with", &state.replace).on_input(Message::ReplaceChanged),
        button(if state.replace_all {
            "[x] all"
        } else {
            "[ ] all"
        })
        .on_press(Message::ReplaceAllToggled),
        button("replace").on_press(Message::ApplyReplace),
    ]
    .spacing(5)
    .into()
}

fn rename(state: &State) -> Element<'_, Message> {
    row![
        text_input("destination path", &state.dest).on_input(Message::DestChanged),
        button("rename").on_press(Message::ApplyRename),
        if state.delete_armed {
            button("really delete").on_press(Message::ApplyDelete)
        } else {
            button("delete").on_press(Message::DeleteArmed)
        },
    ]
    .spacing(5)
    .into()
}
