use iced::advanced::shell::Waker;
use std::{cell::RefCell, collections::VecDeque, rc::Rc};
use wasm_bindgen::{closure::Closure, prelude::*};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = notedInput, js_name = create)]
    fn create(callback: &js_sys::Function, multiline: bool, secure: bool, label: &str) -> u32;
    #[wasm_bindgen(js_namespace = notedInput, js_name = sync)]
    fn sync_js(id: u32, state: &str);
    #[wasm_bindgen(js_namespace = notedInput)]
    fn remove(id: u32);
    #[wasm_bindgen(js_namespace = notedInput)]
    fn font(bytes: &[u8]);
}

#[derive(serde::Deserialize)]
pub struct Event {
    pub seq: u64,
    pub kind: String,
    #[serde(flatten)]
    pub edit: super::Edit,
    pub focused: bool,
    pub scroll: i32,
}

pub struct Target {
    id: u32,
    events: Rc<RefCell<VecDeque<Event>>>,
    waker: Rc<RefCell<Option<Waker>>>,
    _callback: Closure<dyn Fn(String)>,
}

impl Target {
    pub fn new(multiline: bool, secure: bool, label: &str) -> Self {
        let events = Rc::new(RefCell::new(VecDeque::new()));
        let waker: Rc<RefCell<Option<Waker>>> = Rc::default();
        let sink = events.clone();
        let wake = waker.clone();
        let callback = Closure::new(move |json: String| {
            if let Ok(event) = serde_json::from_str(&json) {
                sink.borrow_mut().push_back(event);
                if let Some(waker) = wake.borrow().as_ref() {
                    waker.wake();
                }
            }
        });
        let id = create(callback.as_ref().unchecked_ref(), multiline, secure, label);
        Self {
            id,
            events,
            waker,
            _callback: callback,
        }
    }

    pub fn listen(&self, waker: &Waker) {
        *self.waker.borrow_mut() = Some(waker.clone());
    }
    pub fn pop(&self) -> Option<Event> {
        self.events.borrow_mut().pop_front()
    }
    pub fn sync(&self, state: &serde_json::Value) {
        sync_js(self.id, &state.to_string());
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        remove(self.id);
    }
}

pub fn install() {
    font(iced::advanced::graphics::text::FIRA_SANS_REGULAR);
}
