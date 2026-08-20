//! Where a keystroke goes.
//!
//! Every key the terminal reports arrives here first, and this actor's only
//! state is which region currently owns the keyboard. Keeping that in one
//! place is what stops two regions from both deciding a key was theirs: a
//! modal that is up gets every key, and the composer gets none of them, with
//! no region needing to know the other exists.
//!
//! Two keys never reach a region at all. Esc asks the running turn to stop,
//! and Ctrl+C does the same but leaves when nothing was running. Which of
//! those two things happens is not decided here — this actor does not know
//! whether a turn is open — so both become one [`Interrupt`] carrying the
//! difference, and the session, which does know, resolves it.

use super::message::{Focus, FocusChanged, Interrupt, KeyPressed, Pasted, Wire};
use acton_reactive::prelude::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// The type every handler returns.
type FutureBox = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync + 'static>>;

/// Where one key is bound for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// To the input buffer.
    Composer,
    /// To the modal that has taken the keyboard.
    Approval,
    /// To the session, as a request to stop.
    Interrupt {
        /// Whether to leave when nothing was running.
        quit_when_idle: bool,
    },
}

/// Decides where a key belongs.
///
/// Pure, and deliberately total: there is no key this does not answer for.
/// A modal takes everything, including Esc and Ctrl+C, because refusing a
/// permission is what those mean while one is up — the alternative would be a
/// key that dismisses the prompt without ever answering the agent.
#[must_use]
pub const fn route(focus: Focus, key: KeyEvent) -> Route {
    if matches!(focus, Focus::Approval) {
        return Route::Approval;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        return Route::Interrupt {
            quit_when_idle: true,
        };
    }

    if matches!(key.code, KeyCode::Esc) {
        return Route::Interrupt {
            quit_when_idle: false,
        };
    }

    Route::Composer
}

/// The keyboard's current owner.
#[acton_actor]
pub struct Router {
    /// Who has the keyboard.
    focus: Focus,
    /// The input buffer.
    composer: Option<ActorHandle>,
    /// The permission modal.
    approval: Option<ActorHandle>,
    /// The connection, which owns what an interrupt means.
    session: Option<ActorHandle>,
}

impl Router {
    /// Builds and starts the router.
    pub async fn start(runtime: &mut ActorRuntime) -> ActorHandle {
        let mut builder = runtime.new_actor::<Self>();
        configure(&mut builder);
        builder.start().await
    }

    /// Who currently holds the keyboard.
    #[must_use]
    pub const fn focus(&self) -> Focus {
        self.focus
    }
}

/// Wires every handler.
fn configure(builder: &mut ManagedActor<Idle, Router>) {
    builder.mutate_on::<Wire>(|actor, context| {
        let message = context.message();
        actor.model.composer = Some(message.composer.clone());
        actor.model.approval = Some(message.approval.clone());
        actor.model.session = Some(message.session.clone());
        Reply::ready()
    });

    builder.mutate_on::<FocusChanged>(|actor, context| {
        actor.model.focus = context.message().holder;
        Reply::ready()
    });

    builder.act_on::<KeyPressed>(|actor, context| {
        let key = context.message().key;
        forward(actor, route(actor.model.focus, key), key)
    });

    builder.act_on::<Pasted>(|actor, context| {
        // A paste is content wherever focus happens to be, so it goes to the
        // buffer that holds content and to nothing else. A modal answers keys,
        // not text.
        let message = context.message().clone();
        let composer = actor.model.composer.clone();

        Reply::pending(async move {
            if let Some(composer) = composer {
                composer.send(message).await;
            }
        })
    });
}

/// Delivers one key to whoever the route names.
fn forward(actor: &ManagedActor<Started, Router>, destination: Route, key: KeyEvent) -> FutureBox {
    let composer = actor.model.composer.clone();
    let approval = actor.model.approval.clone();
    let session = actor.model.session.clone();

    Reply::pending(async move {
        match destination {
            Route::Composer => {
                if let Some(composer) = composer {
                    composer.send(KeyPressed { key }).await;
                }
            }
            Route::Approval => {
                if let Some(approval) = approval {
                    approval.send(KeyPressed { key }).await;
                }
            }
            Route::Interrupt { quit_when_idle } => {
                if let Some(session) = session {
                    session.send(Interrupt { quit_when_idle }).await;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn control(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    #[test]
    fn ordinary_keys_reach_the_composer() {
        assert_eq!(
            route(Focus::Composer, key(KeyCode::Char('a'))),
            Route::Composer
        );
        assert_eq!(route(Focus::Composer, key(KeyCode::Enter)), Route::Composer);
    }

    #[test]
    fn escape_asks_to_stop_without_leaving() {
        assert_eq!(
            route(Focus::Composer, key(KeyCode::Esc)),
            Route::Interrupt {
                quit_when_idle: false
            }
        );
    }

    #[test]
    fn control_c_asks_to_stop_and_leaves_when_idle() {
        assert_eq!(
            route(Focus::Composer, control(KeyCode::Char('c'))),
            Route::Interrupt {
                quit_when_idle: true
            }
        );
    }

    #[test]
    fn a_modal_takes_every_key_including_the_interrupts() {
        for pressed in [
            key(KeyCode::Char('y')),
            key(KeyCode::Esc),
            control(KeyCode::Char('c')),
            key(KeyCode::Enter),
        ] {
            assert_eq!(route(Focus::Approval, pressed), Route::Approval);
        }
    }

    #[test]
    fn other_control_keys_are_still_the_composers() {
        assert_eq!(
            route(Focus::Composer, control(KeyCode::Char('u'))),
            Route::Composer
        );
    }
}
