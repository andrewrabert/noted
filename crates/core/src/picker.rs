use std::io::Write;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::style::{Attribute, Print, SetAttribute};
use crossterm::terminal::{Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, event, execute, queue, terminal};
use picker::{Action, Key, PickerState};

use crate::error::{Result, io_error};

pub(crate) enum Pick {
    Chosen(String),
    Aborted,
}

pub(crate) fn pick(items: Vec<String>) -> Result<Pick> {
    let mut state = PickerState::new(items);
    let mut screen = RawScreen::enter()?;
    loop {
        let rows = screen.list_rows();
        state.scroll_into_view(rows);
        screen.render(&state, rows)?;
        let Event::Key(event) = event::read().map_err(|e| io_error("cannot read key", e))? else {
            continue;
        };
        if event.kind != KeyEventKind::Press {
            continue;
        }
        let Some(key) = key_of(event) else {
            continue;
        };
        match state.on_key(key) {
            Action::Accept(item) => return Ok(Pick::Chosen(item)),
            Action::Cancel => return Ok(Pick::Aborted),
            Action::Redraw => {}
        }
    }
}

fn key_of(event: KeyEvent) -> Option<Key> {
    let ctrl = event.modifiers.contains(KeyModifiers::CONTROL);
    match event.code {
        KeyCode::Enter => Some(Key::Enter),
        KeyCode::Esc => Some(Key::Cancel),
        KeyCode::Backspace => Some(Key::Backspace),
        KeyCode::Up => Some(Key::Up),
        KeyCode::Down => Some(Key::Down),
        KeyCode::Char('c' | 'd') if ctrl => Some(Key::Cancel),
        KeyCode::Char('p') if ctrl => Some(Key::Up),
        KeyCode::Char('n') if ctrl => Some(Key::Down),
        KeyCode::Char('u') if ctrl => Some(Key::ClearQuery),
        KeyCode::Char(c) if !ctrl => Some(Key::Char(c)),
        _ => None,
    }
}

/// Owns the terminal mode. `Drop` restores it on every exit path, including
/// `?` and panics, so an aborted picker never leaves a raw alternate screen.
struct RawScreen {
    out: std::io::Stderr,
}

impl RawScreen {
    fn enter() -> Result<RawScreen> {
        terminal::enable_raw_mode().map_err(|e| io_error("cannot enter raw mode", e))?;
        let mut out = std::io::stderr();
        execute!(out, EnterAlternateScreen, cursor::Hide)
            .map_err(|e| io_error("cannot enter alternate screen", e))?;
        Ok(RawScreen { out })
    }

    fn list_rows(&self) -> usize {
        let (_, height) = terminal::size().unwrap_or((80, 24));
        usize::from(height).saturating_sub(1)
    }

    fn render(&mut self, state: &PickerState, rows: usize) -> Result<()> {
        let (width, _) = terminal::size().unwrap_or((80, 24));
        let width = usize::from(width);
        queue!(
            self.out,
            Clear(ClearType::All),
            cursor::MoveTo(0, 0),
            Print(truncate(&format!("> {}", state.query()), width))
        )
        .map_err(|e| io_error("cannot draw picker", e))?;
        for (row, item) in state.window(rows) {
            let line = truncate(item, width);
            let y = u16::try_from(row - state.offset() + 1).unwrap_or(u16::MAX);
            queue!(self.out, cursor::MoveTo(0, y))
                .map_err(|e| io_error("cannot draw picker", e))?;
            if row == state.cursor() {
                queue!(
                    self.out,
                    SetAttribute(Attribute::Reverse),
                    Print(line),
                    SetAttribute(Attribute::Reset)
                )
            } else {
                queue!(self.out, Print(line))
            }
            .map_err(|e| io_error("cannot draw picker", e))?;
        }
        self.out
            .flush()
            .map_err(|e| io_error("cannot draw picker", e))
    }
}

impl Drop for RawScreen {
    fn drop(&mut self) {
        let _ = execute!(self.out, cursor::Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

fn truncate(s: &str, width: usize) -> String {
    s.chars().take(width).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    #[test]
    fn key_of_decodes_navigation_and_editing() {
        assert_eq!(key_of(key(KeyCode::Enter)), Some(Key::Enter));
        assert_eq!(key_of(key(KeyCode::Backspace)), Some(Key::Backspace));
        assert_eq!(key_of(key(KeyCode::Up)), Some(Key::Up));
        assert_eq!(key_of(key(KeyCode::Down)), Some(Key::Down));
        assert_eq!(key_of(key(KeyCode::Char('a'))), Some(Key::Char('a')));
    }

    #[test]
    fn key_of_decodes_every_cancel_binding() {
        assert_eq!(key_of(key(KeyCode::Esc)), Some(Key::Cancel));
        assert_eq!(key_of(ctrl('c')), Some(Key::Cancel));
        assert_eq!(key_of(ctrl('d')), Some(Key::Cancel));
    }

    #[test]
    fn key_of_decodes_the_control_bindings() {
        assert_eq!(key_of(ctrl('p')), Some(Key::Up));
        assert_eq!(key_of(ctrl('n')), Some(Key::Down));
        assert_eq!(key_of(ctrl('u')), Some(Key::ClearQuery));
    }

    #[test]
    fn key_of_ignores_keys_the_picker_has_no_binding_for() {
        assert_eq!(key_of(key(KeyCode::Tab)), None);
        assert_eq!(key_of(key(KeyCode::F(1))), None);
        assert_eq!(key_of(ctrl('z')), None);
    }
}
