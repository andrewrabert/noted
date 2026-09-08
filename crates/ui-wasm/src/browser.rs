//! Browser editing semantics around Iced widgets. Only Iced draws the controls.
mod field;
#[cfg(target_arch = "wasm32")]
mod target;

pub use field::{editor, input};
use iced::advanced::text::Position;
use iced::widget::text_editor;

/// A browser selection uses UTF-16 offsets, while Iced uses UTF-8 line offsets.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Edit {
    pub value: String,
    pub start: usize,
    pub end: usize,
    pub backward: bool,
}

impl Edit {
    pub fn cursor(&self) -> text_editor::Cursor {
        let start = position(&self.value, self.start);
        let end = position(&self.value, self.end);
        text_editor::Cursor {
            position: if self.backward { start } else { end },
            selection: (start != end).then_some(if self.backward { end } else { start }),
        }
    }

    pub fn apply(&self, content: &mut text_editor::Content) {
        // Keep the existing Iced buffer. Native browser history produces edits
        // through the same path as typing, cut, paste, and composition commits.
        if content.text() != self.value {
            content.perform(text_editor::Action::SelectAll);
            content.perform(text_editor::Action::Edit(text_editor::Edit::Paste(
                std::sync::Arc::new(self.value.clone()),
            )));
        }
        content.move_to(self.cursor());
    }
}

pub fn position(text: &str, utf16: usize) -> Position {
    let mut remaining = utf16;
    let mut position = Position { line: 0, index: 0 };
    for ch in text.chars() {
        if remaining < ch.len_utf16() {
            break;
        }
        remaining -= ch.len_utf16();
        if ch == '\n' {
            position.line += 1;
            position.index = 0;
        } else {
            position.index += ch.len_utf8();
        }
    }
    position
}

#[cfg(target_arch = "wasm32")]
pub fn install() {
    target::install();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_offsets_preserve_unicode_and_selection_direction() {
        let edit = Edit {
            value: "a😀\ne\u{301}文".into(),
            start: 1,
            end: 7,
            backward: true,
        };
        assert_eq!(edit.cursor().position, Position { line: 0, index: 1 });
        assert_eq!(
            edit.cursor().selection,
            Some(Position { line: 1, index: 6 })
        );
        assert_eq!(position(&edit.value, 2), Position { line: 0, index: 1 });
    }

    #[test]
    fn native_replacement_and_undo_update_the_existing_buffer() {
        let mut content = text_editor::Content::with_text("before");
        for value in ["after😀", "before", ""] {
            let edit = Edit {
                value: value.into(),
                start: 0,
                end: value.encode_utf16().count(),
                backward: false,
            };
            edit.apply(&mut content);
            assert_eq!(content.text(), value);
            assert_eq!(content.cursor(), edit.cursor());
        }
    }
}
