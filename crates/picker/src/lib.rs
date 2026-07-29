//! Match and state for a fuzzy picker. This crate deliberately depends on no
//! terminal library: the driver lives in `noted::picker`.

use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};

/// A keypress the picker understands, decoded by the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Backspace,
    Up,
    Down,
    Enter,
    ClearQuery,
    Cancel,
}

/// What the driver should do next. `Accept` carries the chosen item, so an
/// accept with nothing selected cannot be constructed.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Accept(String),
    Cancel,
    Redraw,
}

fn matcher() -> Matcher {
    Matcher::new(Config::DEFAULT.match_paths())
}

/// Indices into `items` that match `query`, best score first; ties keep the
/// original order. An empty query keeps every item in its original order.
fn filter(matcher: &mut Matcher, items: &[String], query: &str) -> Vec<usize> {
    if query.is_empty() {
        return (0..items.len()).collect();
    }
    let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
    let mut buf = Vec::new();
    let mut scored: Vec<(u32, usize)> = items
        .iter()
        .enumerate()
        .filter_map(|(i, item)| {
            let score = pattern.score(Utf32Str::new(item, &mut buf), matcher)?;
            Some((score, i))
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, i)| i).collect()
}

pub struct PickerState {
    items: Vec<String>,
    query: String,
    filtered: Vec<usize>,
    cursor: usize,
    offset: usize,
    matcher: Matcher,
}

impl PickerState {
    pub fn new(items: Vec<String>) -> PickerState {
        let filtered = (0..items.len()).collect();
        PickerState {
            items,
            query: String::new(),
            filtered,
            cursor: 0,
            offset: 0,
            matcher: matcher(),
        }
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    fn set_query(&mut self, query: String) {
        self.query = query;
        self.filtered = filter(&mut self.matcher, &self.items, &self.query);
        self.cursor = self.cursor.min(self.filtered.len().saturating_sub(1));
        self.offset = 0;
    }

    fn push_char(&mut self, c: char) {
        let mut query = std::mem::take(&mut self.query);
        query.push(c);
        self.set_query(query);
    }

    fn backspace(&mut self) {
        let mut query = std::mem::take(&mut self.query);
        query.pop();
        self.set_query(query);
    }

    fn move_up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    fn move_down(&mut self) {
        if self.cursor + 1 < self.filtered.len() {
            self.cursor += 1;
        }
    }

    pub fn selection(&self) -> Option<&str> {
        let index = *self.filtered.get(self.cursor)?;
        Some(self.items[index].as_str())
    }

    pub fn scroll_into_view(&mut self, rows: usize) {
        if rows == 0 {
            self.offset = 0;
            return;
        }
        if self.cursor < self.offset {
            self.offset = self.cursor;
        } else if self.cursor >= self.offset + rows {
            self.offset = self.cursor + 1 - rows;
        }
    }

    pub fn window(&self, rows: usize) -> impl Iterator<Item = (usize, &str)> {
        self.filtered
            .iter()
            .enumerate()
            .skip(self.offset)
            .take(rows)
            .map(|(row, index)| (row, self.items[*index].as_str()))
    }

    pub fn on_key(&mut self, key: Key) -> Action {
        match key {
            Key::Enter => {
                return match self.selection() {
                    Some(item) => Action::Accept(item.to_string()),
                    None => Action::Redraw,
                };
            }
            Key::Cancel => return Action::Cancel,
            Key::Up => self.move_up(),
            Key::Down => self.move_down(),
            Key::ClearQuery => self.set_query(String::new()),
            Key::Backspace => self.backspace(),
            Key::Char(c) => self.push_char(c),
        }
        Action::Redraw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn matched(items: &[String], query: &str) -> Vec<String> {
        filter(&mut matcher(), items, query)
            .into_iter()
            .map(|i| items[i].clone())
            .collect()
    }

    #[test]
    fn filter_empty_query_keeps_every_item_in_order() {
        let items = items(&["b.md", "a.md", "c.md"]);
        assert_eq!(matched(&items, ""), items);
    }

    #[test]
    fn filter_matches_subsequences_and_drops_the_rest() {
        let items = items(&["proj/ideas.md", "Inbox.md", "proj/notes.md"]);
        assert_eq!(
            matched(&items, "pid"),
            vec!["proj/ideas.md".to_string()],
            "only the path whose chars appear in order matches"
        );
    }

    #[test]
    fn filter_ranks_the_tighter_match_first() {
        let items = items(&["archive/old-inbox-2024.md", "Inbox.md"]);
        assert_eq!(
            matched(&items, "inbox"),
            vec![
                "Inbox.md".to_string(),
                "archive/old-inbox-2024.md".to_string()
            ],
            "a match on a path boundary outranks one mid-word"
        );
    }

    #[test]
    fn filter_is_smart_case() {
        let items = items(&["Inbox.md", "inbox-old.md"]);
        assert_eq!(matched(&items, "inbox").len(), 2);
        assert_eq!(matched(&items, "Inbox"), vec!["Inbox.md".to_string()]);
    }

    #[test]
    fn cursor_clamps_at_both_ends() {
        let mut state = PickerState::new(items(&["a.md", "b.md"]));
        state.move_up();
        assert_eq!(state.selection(), Some("a.md"));
        state.move_down();
        state.move_down();
        state.move_down();
        assert_eq!(state.selection(), Some("b.md"));
    }

    #[test]
    fn editing_the_query_refilters_and_clamps_the_cursor() {
        let mut state = PickerState::new(items(&["alpha.md", "beta.md", "gamma.md"]));
        state.move_down();
        state.move_down();
        assert_eq!(state.selection(), Some("gamma.md"));
        state.push_char('a');
        state.push_char('l');
        assert_eq!(state.selection(), Some("alpha.md"));
        state.backspace();
        state.backspace();
        assert_eq!(state.query, "");
        assert_eq!(state.selection(), Some("alpha.md"));
    }

    #[test]
    fn selection_is_none_when_nothing_matches() {
        let mut state = PickerState::new(items(&["alpha.md"]));
        state.push_char('z');
        assert_eq!(state.selection(), None);
    }

    #[test]
    fn on_key_maps_accept_cancel_and_edits() {
        let mut state = PickerState::new(items(&["alpha.md", "beta.md"]));
        assert_eq!(state.on_key(Key::Char('b')), Action::Redraw);
        assert_eq!(state.query, "b");
        assert_eq!(
            state.on_key(Key::Enter),
            Action::Accept("beta.md".to_string())
        );
        assert_eq!(state.on_key(Key::Cancel), Action::Cancel);
    }

    #[test]
    fn enter_with_no_matches_redraws_instead_of_accepting() {
        let mut state = PickerState::new(items(&["alpha.md"]));
        state.push_char('z');
        assert_eq!(state.on_key(Key::Enter), Action::Redraw);
        assert_eq!(state.query, "z");
    }

    #[test]
    fn up_and_down_move_without_editing_the_query() {
        let mut state = PickerState::new(items(&["alpha.md", "beta.md"]));
        state.on_key(Key::Down);
        assert_eq!(state.selection(), Some("beta.md"));
        state.on_key(Key::Up);
        assert_eq!(state.selection(), Some("alpha.md"));
        assert_eq!(state.query, "");
    }

    #[test]
    fn clear_query_restores_the_full_list() {
        let mut state = PickerState::new(items(&["alpha.md", "beta.md"]));
        state.push_char('b');
        assert_eq!(state.selection(), Some("beta.md"));
        state.on_key(Key::ClearQuery);
        assert_eq!(state.query, "");
        assert_eq!(state.selection(), Some("alpha.md"));
    }

    #[test]
    fn viewport_scrolls_to_keep_the_cursor_visible() {
        let mut state = PickerState::new(items(&["a", "b", "c", "d", "e"]));
        state.scroll_into_view(2);
        assert_eq!(state.offset, 0);
        for _ in 0..3 {
            state.move_down();
        }
        state.scroll_into_view(2);
        assert_eq!(state.offset, 2);
        assert_eq!(
            state.window(2).map(|(_, s)| s).collect::<Vec<_>>(),
            vec!["c", "d"]
        );
        state.move_up();
        state.move_up();
        state.scroll_into_view(2);
        assert_eq!(state.offset, 1);
    }
}
