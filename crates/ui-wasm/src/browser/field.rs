use super::Edit;
use crate::Message;
use iced::advanced::{Layout, Shell, Widget, layout, mouse, renderer, widget};
use iced::widget::{text_editor, text_input};
use iced::{Element, Event, Length, Padding, Rectangle, Renderer, Size, Theme};

pub struct Input<'a> {
    inner: text_input::TextInput<'a, Message>,
    value: &'a str,
    label: &'a str,
    on_input: Option<fn(String) -> Message>,
    on_submit: Option<Message>,
    secure: bool,
    purpose: &'static str,
    id: Option<widget::Id>,
}

pub fn input<'a>(label: &'a str, value: &'a str) -> Input<'a> {
    Input {
        inner: text_input(label, value),
        value,
        label,
        on_input: None,
        on_submit: None,
        secure: false,
        purpose: "",
        id: None,
    }
}

impl<'a> Input<'a> {
    pub fn autocomplete(mut self, value: &'static str) -> Self {
        self.purpose = value;
        self
    }

    pub fn id(mut self, id: widget::Id) -> Self {
        self.id = Some(id.clone());
        self.inner = self.inner.id(id);
        self
    }
    pub fn on_input(self, f: fn(String) -> Message) -> Self {
        self.on_input_maybe(Some(f))
    }
    pub fn on_input_maybe(mut self, f: Option<fn(String) -> Message>) -> Self {
        self.on_input = f;
        self.inner = self.inner.on_input_maybe(f);
        self
    }
    pub fn on_submit(mut self, message: Message) -> Self {
        self.inner = self.inner.on_submit(message.clone());
        self.on_submit = Some(message);
        self
    }
    pub fn secure(mut self, secure: bool) -> Self {
        self.inner = self.inner.secure(secure);
        self.secure = secure;
        self
    }
}

impl<'a> From<Input<'a>> for Element<'a, Message> {
    fn from(input: Input<'a>) -> Self {
        let enabled = input.on_input.is_some();
        // Iced's secure Input currently moves only its unmasked buffer when
        // operated on. Render the mask through a normal Iced input so DOM
        // selections also move the visible caret; secrets stay in app/DOM state.
        #[cfg(target_arch = "wasm32")]
        let inner: Element<'a, Message> = if input.secure {
            let mut masked =
                text_input(input.label, super::mask(input.value)).on_input_maybe(input.on_input);
            if let Some(id) = input.id {
                masked = masked.id(id);
            }
            masked.into()
        } else {
            input.inner.into()
        };
        #[cfg(not(target_arch = "wasm32"))]
        let inner = input.inner.into();
        Self::new(Field {
            inner,
            value: input.value.to_owned(),
            label: input.label.to_owned(),
            key: input.label.to_owned(),
            on_edit: input
                .on_input
                .map(|f| Box::new(move |edit: Edit| f(edit.value)) as _),
            on_submit: input.on_submit,
            multiline: false,
            secure: input.secure,
            purpose: input.purpose,
            padding: Padding::new(5.0),
            enabled,
        })
    }
}

pub struct Editor<'a> {
    content: &'a text_editor::Content,
    which: crate::Editor,
    on_action: fn(text_editor::Action) -> Message,
    placeholder: &'a str,
    height: Length,
    padding: Padding,
    highlight: bool,
    key: Option<String>,
}

pub fn submit<'a>(inner: impl Into<Element<'a, Message>>, enabled: bool) -> Element<'a, Message> {
    Element::new(Field {
        inner: inner.into(),
        value: String::new(),
        label: "Sign in".into(),
        key: "login-submit".into(),
        on_edit: None,
        on_submit: Some(Message::LoginSubmitted),
        multiline: false,
        secure: false,
        purpose: "submit",
        padding: Padding::ZERO,
        enabled,
    })
}

pub fn editor(
    content: &text_editor::Content,
    which: crate::Editor,
    on_action: fn(text_editor::Action) -> Message,
) -> Editor<'_> {
    Editor {
        content,
        which,
        on_action,
        placeholder: "",
        height: Length::Shrink,
        padding: Padding::new(5.0),
        highlight: false,
        key: None,
    }
}

impl<'a> Editor<'a> {
    pub fn key(mut self, value: &str) -> Self {
        self.key = Some(value.to_owned());
        self
    }

    pub fn placeholder(mut self, value: &'a str) -> Self {
        self.placeholder = value;
        self
    }
    pub fn height(mut self, value: impl Into<Length>) -> Self {
        self.height = value.into();
        self
    }
    pub fn padding(mut self, value: impl Into<Padding>) -> Self {
        self.padding = value.into();
        self
    }
    pub fn highlight(mut self, _language: &str) -> Self {
        self.highlight = true;
        self
    }
}

impl<'a> From<Editor<'a>> for Element<'a, Message> {
    fn from(editor: Editor<'a>) -> Self {
        let inner = text_editor(editor.content)
            .on_action(editor.on_action)
            .placeholder(editor.placeholder)
            .height(editor.height)
            .padding(editor.padding);
        let inner: Element<'a, Message> = if editor.highlight {
            inner.highlight("markdown").into()
        } else {
            inner.into()
        };
        Self::new(Field {
            inner,
            value: editor.content.text(),
            label: editor.placeholder.to_owned(),
            key: editor.key.unwrap_or_else(|| format!("{:?}", editor.which)),
            on_edit: Some(Box::new(move |edit| {
                Message::BrowserEdited(editor.which, edit)
            })),
            on_submit: None,
            multiline: true,
            secure: false,
            purpose: "",
            padding: editor.padding,
            enabled: true,
        })
    }
}

struct Field<'a> {
    inner: Element<'a, Message>,
    value: String,
    label: String,
    key: String,
    on_edit: Option<Box<dyn Fn(Edit) -> Message + 'a>>,
    on_submit: Option<Message>,
    multiline: bool,
    secure: bool,
    padding: Padding,
    enabled: bool,
    purpose: &'static str,
}

#[derive(Default)]
struct State {
    identity: (String, bool, bool),
    #[cfg(target_arch = "wasm32")]
    target: Option<super::target::Target>,
    #[cfg(target_arch = "wasm32")]
    selection: Option<Edit>,
    #[cfg(target_arch = "wasm32")]
    pending: Option<iced::advanced::shell::Tracking>,
    #[cfg(target_arch = "wasm32")]
    seq: u64,
    #[cfg(target_arch = "wasm32")]
    focused: bool,
}

impl Widget<Message, Theme, Renderer> for Field<'_> {
    fn tag(&self) -> widget::tree::Tag {
        widget::tree::Tag::of::<State>()
    }
    fn state(&self) -> widget::tree::State {
        widget::tree::State::new(State {
            identity: (self.key.clone(), self.multiline, self.secure),
            ..State::default()
        })
    }
    fn diff(&mut self, tree: &mut widget::Tree) {
        if tree.state.downcast_ref::<State>().identity
            != (self.key.clone(), self.multiline, self.secure)
        {
            tree.state = self.state();
            tree.children.clear();
        }
        tree.diff_children(std::slice::from_mut(&mut self.inner));
    }
    fn size(&self) -> Size<Length> {
        self.inner.as_widget().size()
    }
    fn layout(
        &mut self,
        tree: &mut widget::Tree,
        renderer: &Renderer,
        limits: &layout::Limits,
    ) -> layout::Node {
        if tree.children.is_empty() {
            tree.children.push(widget::Tree::new(&self.inner));
        }
        self.inner
            .as_widget_mut()
            .layout(&mut tree.children[0], renderer, limits)
    }
    fn operate(
        &mut self,
        tree: &mut widget::Tree,
        layout: Layout<'_>,
        renderer: &Renderer,
        operation: &mut dyn widget::Operation,
    ) {
        self.inner
            .as_widget_mut()
            .operate(&mut tree.children[0], layout, renderer, operation);
        #[cfg(target_arch = "wasm32")]
        {
            let mut focus = Focus {
                set: None,
                focused: false,
                cursor: None,
            };
            self.inner
                .as_widget_mut()
                .operate(&mut tree.children[0], layout, renderer, &mut focus);
            tree.state.downcast_mut::<State>().focused = focus.focused;
        }
    }
    fn update(
        &mut self,
        tree: &mut widget::Tree,
        event: &Event,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        renderer: &Renderer,
        shell: &mut Shell<'_, Message>,
        viewport: &Rectangle,
    ) {
        #[cfg(target_arch = "wasm32")]
        {
            let state = tree.state.downcast_mut::<State>();
            let target = state.target.get_or_insert_with(|| {
                super::target::Target::new(self.multiline, self.secure, &self.label, self.purpose)
            });
            target.listen(shell.waker());
            if state
                .pending
                .as_ref()
                .is_none_or(iced::advanced::shell::Tracking::is_processed)
            {
                state.pending = None;
                if let Some(event) = target.pop() {
                    state.seq = event.seq;
                    state.focused = event.focused;
                    state.selection = Some(event.edit.clone());
                    if event.kind == "input" && self.enabled {
                        if let Some(on_edit) = &self.on_edit {
                            state.pending = Some(shell.publish_and_track(on_edit(event.edit)));
                        }
                    } else if event.kind == "submit" && self.enabled {
                        if let Some(message) = &self.on_submit {
                            shell.publish(message.clone());
                        }
                    } else if event.kind == "scroll" && self.multiline {
                        self.inner.as_widget_mut().update(
                            &mut tree.children[0],
                            &Event::Mouse(iced::mouse::Event::WheelScrolled {
                                delta: iced::mouse::ScrollDelta::Lines {
                                    x: 0.0,
                                    y: event.scroll as f32,
                                },
                            }),
                            layout,
                            mouse::Cursor::Available(layout.bounds().center()),
                            renderer,
                            shell,
                            viewport,
                        );
                    }
                    shell.request_redraw();
                }
                let selection = state
                    .selection
                    .as_ref()
                    .filter(|edit| edit.value == self.value)
                    .map(|edit| {
                        if self.secure {
                            super::masked_cursor(edit)
                        } else {
                            edit.cursor()
                        }
                    });
                let mut focus = Focus {
                    set: Some(state.focused && self.enabled),
                    focused: false,
                    cursor: selection,
                };
                self.inner.as_widget_mut().operate(
                    &mut tree.children[0],
                    layout,
                    renderer,
                    &mut focus,
                );
            } else {
                shell.request_redraw();
            }
            // DOM targets own native editing, selection, clipboard, and undo.
            // Canvas keyboard events must never insert the same text a second time.
            if matches!(
                event,
                Event::Keyboard(_)
                    | Event::InputMethod(_)
                    | Event::Clipboard(_)
                    | Event::Mouse(_)
                    | Event::Touch(_)
            ) {
                return;
            }
        }
        self.inner.as_widget_mut().update(
            &mut tree.children[0],
            event,
            layout,
            cursor,
            renderer,
            shell,
            viewport,
        );
    }
    fn draw(
        &self,
        tree: &widget::Tree,
        renderer: &mut Renderer,
        theme: &Theme,
        style: &renderer::Style,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
    ) {
        self.inner.as_widget().draw(
            &tree.children[0],
            renderer,
            theme,
            style,
            layout,
            cursor,
            viewport,
        );
        #[cfg(target_arch = "wasm32")]
        if let Some(target) = &tree.state.downcast_ref::<State>().target {
            use iced::advanced::text::Renderer as _;
            let state = tree.state.downcast_ref::<State>();
            let bounds = layout.bounds();
            let clip = bounds.intersection(viewport).unwrap_or_default();
            let ready = state
                .pending
                .as_ref()
                .is_none_or(iced::advanced::shell::Tracking::is_processed);
            target.sync(&serde_json::json!({
                "value": self.value, "ack": if ready { Some(state.seq) } else { None },
                "focused": state.focused, "enabled": self.enabled,
                "x": bounds.x, "y": bounds.y, "width": bounds.width, "height": bounds.height,
                "clip": [clip.x, clip.y, clip.width, clip.height],
                "padding": [self.padding.top, self.padding.right, self.padding.bottom, self.padding.left],
                "size": renderer.text_size().0,
                "lineHeight": renderer.line_height().to_absolute(renderer.text_size()).0,
            }));
        }
    }
    fn mouse_interaction(
        &self,
        tree: &widget::Tree,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
        renderer: &Renderer,
    ) -> mouse::Interaction {
        self.inner.as_widget().mouse_interaction(
            &tree.children[0],
            layout,
            cursor,
            viewport,
            renderer,
        )
    }
}

#[cfg(target_arch = "wasm32")]
struct Focus {
    set: Option<bool>,
    focused: bool,
    cursor: Option<text_editor::Cursor>,
}

#[cfg(target_arch = "wasm32")]
impl widget::Operation for Focus {
    fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn widget::Operation)) {
        operate(self);
    }
    fn focusable(
        &mut self,
        _id: Option<&widget::Id>,
        _bounds: Rectangle,
        state: &mut dyn widget::operation::Focusable,
    ) {
        if let Some(focused) = self.set {
            if focused && !state.is_focused() {
                state.focus();
            }
            if !focused && state.is_focused() {
                state.unfocus();
            }
        }
        self.focused = state.is_focused();
    }
    fn text_input(
        &mut self,
        _id: Option<&widget::Id>,
        _bounds: Rectangle,
        state: &mut dyn widget::operation::TextInput,
    ) {
        if let Some(cursor) = self.cursor {
            if let Some(anchor) = cursor.selection {
                state.select_range(anchor, cursor.position);
            } else {
                state.move_cursor_to(cursor.position);
            }
        }
    }
}
