//! The interactive chat interface.
//!
//! Garrison's daemon is an ACP agent, so the chat is an ACP *client*: it holds
//! one socket open, streams what the agent says onto the screen, and answers
//! the permission requests the agent blocks on. Nothing here reaches into the
//! agent's internals, which is why the same interface would drive any ACP
//! agent and why driving Garrison from Zed instead is not a different program.
//!
//! # How it is put together
//!
//! Seven actors, each owning exactly one thing:
//!
//! | Actor | Owns |
//! |---|---|
//! | [`compositor::Compositor`] | the terminal, and every byte written to it |
//! | [`transcript::Transcript`] | the reply being streamed, and what is finished |
//! | [`status::Status`] | what the agent is doing, and for how long |
//! | [`composer::Composer`] | the input buffer and the caret |
//! | [`approval::Approval`] | permissions the agent is blocked on |
//! | [`input::Router`] | which of those has the keyboard |
//! | [`session::Session`] | the connection, the open turn, and the queue |
//!
//! Only the compositor writes to the screen. The others render their own rows
//! and send them, which is what lets a frame be composed atomically instead of
//! six actors interleaving escape sequences into it.
//!
//! # The handshake happens first
//!
//! `initialize` and `session/new` complete before any actor exists, on the
//! plain [`crate::duplex::DuplexClient`], while the terminal is still in its
//! normal mode. A failure there is an ordinary error message on an ordinary
//! terminal, and the session actor starts already connected rather than
//! carrying a "still starting" state every handler would have to check.

pub mod approval;
pub mod composer;
pub mod compositor;
pub mod geometry;
pub mod input;
pub mod message;
pub mod session;
pub mod slash;
pub mod status;
pub mod transcript;
pub mod viewport;
pub mod wrap;

use crate::duplex::{AgentEvent, DuplexClient};
use crate::error::GarrisonError;
use crate::protocol::acp;
use acton_reactive::prelude::*;
use crossterm::event::{Event, EventStream};
use message::{FromAgent, KeyPressed, Pasted, ScreenResized, Shutdown, Wire};
use ratatui::layout::Size;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::watch;
use tokio_stream::StreamExt;

/// The name the agent sees this client identify itself as.
const CLIENT_NAME: &str = "garrison-chat";

/// Runs the chat until the user leaves or the agent disconnects.
///
/// # Errors
///
/// A socket that will not connect, a handshake the agent refuses, and any
/// failure taking over or giving back the terminal.
pub async fn run(socket: &Path, cwd: PathBuf, approve_all: bool) -> Result<(), GarrisonError> {
    let mut client = DuplexClient::connect(socket).await?;

    let request = acp::InitializeRequest::new(acp::PROTOCOL_VERSION).client_info(
        acp::Implementation::new(CLIENT_NAME, env!("CARGO_PKG_VERSION")),
    );
    let _: acp::InitializeResponse = client.request(acp::method::INITIALIZE, &request).await?;

    let opened: acp::NewSessionResponse = client
        .request(
            acp::method::SESSION_NEW,
            &acp::NewSessionRequest::new(cwd.clone()),
        )
        .await?;

    let (writer, events) = client.split();
    let (exit, watching) = watch::channel(false);
    let mut runtime = ActonApp::launch_async().await;

    // The compositor takes the terminal over, so it is built first and any
    // failure here happens before anything else has state to unwind.
    let compositor = compositor::Compositor::start(&mut runtime)
        .await
        .map_err(|error| GarrisonError::runtime(format!("could not take the terminal: {error}")))?;

    let transcript = transcript::Transcript::start(&mut runtime).await;
    let status = status::Status::start(&mut runtime).await;
    let composer = composer::Composer::start(&mut runtime).await;
    let approval = approval::Approval::start(&mut runtime, approve_all).await;
    let router = input::Router::start(&mut runtime).await;
    let session =
        session::Session::start(&mut runtime, writer, opened.session_id, cwd, exit.clone()).await;

    let wire = Wire {
        compositor: compositor.clone(),
        transcript,
        status,
        composer,
        approval,
        router: router.clone(),
        session: session.clone(),
    };
    for handle in [
        &wire.compositor,
        &wire.transcript,
        &wire.status,
        &wire.composer,
        &wire.approval,
        &wire.router,
        &wire.session,
    ] {
        handle.send(wire.clone()).await;
    }

    let keys = tokio::spawn(read_keys(
        router,
        compositor.clone(),
        exit.subscribe(),
        exit.clone(),
    ));
    let wire_events = tokio::spawn(read_agent(session, events, exit));

    let mut watching = watching;
    while !*watching.borrow() {
        if watching.changed().await.is_err() {
            break;
        }
    }

    keys.abort();
    wire_events.abort();

    compositor.send(Shutdown).await;
    runtime
        .shutdown_all()
        .await
        .map_err(|error| GarrisonError::runtime(format!("shutdown failed: {error}")))
}

/// Pumps terminal events into the interface until it is asked to stop.
///
/// This is one of the two places the program touches the outside world on its
/// own schedule, so it is a task rather than an actor: there is no state here
/// to own, only a stream to drain.
async fn read_keys(
    router: ActorHandle,
    compositor: ActorHandle,
    mut leaving: watch::Receiver<bool>,
    exit: watch::Sender<bool>,
) {
    let mut stream = EventStream::new();

    loop {
        tokio::select! {
            _ = leaving.changed() => return,
            event = stream.next() => match event {
                Some(Ok(Event::Key(key))) if key.is_press() => {
                    router.send(KeyPressed { key }).await;
                }
                Some(Ok(Event::Paste(text))) => router.send(Pasted { text }).await,
                Some(Ok(Event::Resize(width, height))) => {
                    compositor
                        .send(ScreenResized {
                            size: Size::new(width, height),
                        })
                        .await;
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    tracing::warn!(%error, "the terminal stopped reporting events");
                    let _ = exit.send(true);
                    return;
                }
                // The terminal's input ended, which is a hangup, not idleness.
                None => {
                    let _ = exit.send(true);
                    return;
                }
            },
        }
    }
}

/// Pumps what the agent says into the session actor.
///
/// Every event is wrapped rather than copied: one of them carries a request
/// the agent is blocked on, and duplicating that would mean two places
/// believing they owed an answer.
async fn read_agent(
    session: ActorHandle,
    mut events: UnboundedReceiver<AgentEvent>,
    exit: watch::Sender<bool>,
) {
    while let Some(event) = events.recv().await {
        session
            .send(FromAgent {
                event: Arc::new(event),
            })
            .await;
    }

    let _ = exit.send(true);
}
