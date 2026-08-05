pub use platform::{install, read, write};

#[cfg(target_arch = "wasm32")]
mod platform {
    use std::cell::RefCell;

    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;

    thread_local! {
        static PASTED: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    pub fn install() {
        let Some(document) = web_sys::window().and_then(|window| window.document()) else {
            return;
        };
        let listener =
            Closure::<dyn Fn(web_sys::ClipboardEvent)>::new(|event: web_sys::ClipboardEvent| {
                let Some(text) = event
                    .clipboard_data()
                    .and_then(|data| data.get_data("text").ok())
                else {
                    return;
                };
                PASTED.with_borrow_mut(|slot| *slot = Some(text));
            });
        let _ =
            document.add_event_listener_with_callback("paste", listener.as_ref().unchecked_ref());
        listener.forget();
    }

    pub fn write(text: String) {
        let Some(navigator) = web_sys::window().map(|window| window.navigator()) else {
            return;
        };
        let _ = navigator.clipboard().write_text(&text);
    }

    pub async fn read() -> Option<String> {
        // The browser dispatches `paste` after the key press that triggered it,
        // so `PASTED` is still empty at this point.
        yield_to_event_loop().await;
        PASTED.with_borrow_mut(|slot| slot.take())
    }

    async fn yield_to_event_loop() {
        let promise = js_sys::Promise::new(&mut |resolve, _reject| {
            if let Some(window) = web_sys::window() {
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 0);
            }
        });
        let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod platform {
    pub fn install() {}

    pub fn write(_text: String) {}

    pub async fn read() -> Option<String> {
        None
    }
}
