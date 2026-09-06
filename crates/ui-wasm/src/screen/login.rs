use iced::widget::{button, column, container, text, text_input};
use iced::{Element, Fill};

use crate::{Auth, Message};

pub(crate) const USERNAME: iced::widget::Id = iced::widget::Id::new("login-username");
pub(crate) const PASSWORD: iced::widget::Id = iced::widget::Id::new("login-password");

/// `LoggedOut` is a titled card with one "Sign in" button. `Txn` is that card
/// with a username, a `.secure(true)` password, and a submit button, every
/// control disabled while the form is busy, its error beneath. `Open` and
/// `Authed` never reach here.
pub(crate) fn view(auth: &Auth) -> Element<'_, Message> {
    let card = match auth {
        Auth::Txn { form, .. } => {
            let busy = form.busy;
            let username = text_input("username", &form.username)
                .id(USERNAME)
                .on_input_maybe((!busy).then_some(Message::LoginUsernameChanged))
                .on_submit(Message::LoginUsernameSubmitted);
            let password = text_input("password", &form.password)
                .id(PASSWORD)
                .secure(true)
                .on_input_maybe((!busy).then_some(Message::LoginPasswordChanged))
                .on_submit(Message::LoginSubmitted);
            let submit = button(text("Sign in"))
                .on_press_maybe(form.can_submit().then_some(Message::LoginSubmitted));
            let mut card = column![text(noted::APP_NAME).size(24), username, password, submit];
            if let Some(error) = &form.error {
                card = card.push(text(error.clone()));
            }
            card
        }
        _ => column![
            text(noted::APP_NAME).size(24),
            button(text("Sign in")).on_press(Message::SignInPressed),
        ],
    };
    container(card.spacing(10).width(320))
        .padding(20)
        .width(Fill)
        .into()
}
