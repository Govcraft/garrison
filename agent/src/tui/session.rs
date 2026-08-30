//! The connection, and everything that depends on what it is doing.
//!
//! This actor owns the write half of the socket, the session identifier, and
//! the single fact everything else keeps asking about: whether a turn is
//! currently open. That is why interrupts and submissions both end up here
//! rather than being decided at the keyboard. A key cannot know whether Esc
//! should stop something; this can.
//!
//! It also owns the queue. A message typed while the agent is still working is
//! not refused and is not silently dropped into the running turn — it is held,
//! shown as held, and sent the moment the turn ends. The transcript still gets
//! it straight away, because committing what the user typed is the
//! transcript's job and does not wait on the wire.

use super::message::{
    AgentChunk, AgentFinished, ClearHistory, FromAgent, Interrupt, Note, PermissionAnswered,
    PermissionAsked, Quit, Submitted, ToolEnded, ToolStarted, TurnEnded, TurnStarted, Wire,
};
use super::slash::{self, Command};
use super::transcript::{error_line, notice_line, tool_line, user_line};
use crate::duplex::{AgentEvent, WireWriter};
use crate::error::GarrisonError;
use crate::protocol::acp;
use crate::protocol::jsonrpc::{ErrorObject, RequestId};
use acton_reactive::prelude::*;
use ratatui::text::Line;
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use tokio::sync::watch;

/// The type every handler returns.
type FutureBox = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync + 'static>>;

/// What an outstanding request that is not a turn was asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Awaiting {
    /// A replacement session.
    NewSession,
    /// The agent's governance settings.
    Status,
    /// The verdict on an abandoned turn.
    Abandon,
}

/// The live connection to the agent.
#[acton_actor]
pub struct Session {
    /// The write half. Synchronous, so handlers never await the socket.
    writer: Option<WireWriter>,
    /// The session every prompt is sent under.
    id: Option<acp::SessionId>,
    /// The open turn, if there is one.
    turn: Option<RequestId>,
    /// Requests that are not turns, and what each was for.
    outstanding: BTreeMap<RequestId, Awaiting>,
    /// Messages typed while a turn was open, oldest first.
    queued: VecDeque<String>,
    /// Titles of running tool calls, so a finish can name what finished.
    titles: BTreeMap<String, String>,
    /// Where a new session would be rooted.
    cwd: PathBuf,
    /// Raised once, when the interface should come down.
    exit: Option<watch::Sender<bool>>,
    /// The only writer to the terminal.
    compositor: Option<ActorHandle>,
    /// The transcript.
    transcript: Option<ActorHandle>,
    /// The status line.
    status: Option<ActorHandle>,
    /// The permission modal.
    approval: Option<ActorHandle>,
}

impl Session {
    /// Builds and starts the session around an already-open connection.
    ///
    /// The handshake happens before this: by the time the actor exists the
    /// agent has answered `initialize` and handed back a session, so there is
    /// no half-started state for anything else to have to wait on.
    pub async fn start(
        runtime: &mut ActorRuntime,
        writer: WireWriter,
        id: acp::SessionId,
        cwd: PathBuf,
        exit: watch::Sender<bool>,
    ) -> ActorHandle {
        let mut builder = runtime.new_actor::<Self>();
        builder.model.writer = Some(writer);
        builder.model.id = Some(id);
        builder.model.cwd = cwd;
        builder.model.exit = Some(exit);
        configure(&mut builder);
        builder.start().await
    }

    /// Whether a turn is open.
    #[must_use]
    pub const fn is_busy(&self) -> bool {
        self.turn.is_some()
    }

    /// How many messages are waiting for the current turn to end.
    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.queued.len()
    }

    /// Sends one prompt and records the turn it opened.
    fn begin(&mut self, text: &str) -> Result<(), GarrisonError> {
        let method = acp::method::SESSION_PROMPT;
        let id = self
            .id
            .clone()
            .ok_or_else(|| GarrisonError::transport(method, "no session is open"))?;
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| GarrisonError::transport(method, "the connection has closed"))?;

        self.turn = Some(writer.prompt(id, text)?);
        Ok(())
    }

    /// Picks up the turn a restart interrupted.
    ///
    /// Tracked as the open turn rather than as an outstanding request, because
    /// that is what it is: the answer arrives the way a prompt's does, and
    /// everything the interface does about a running turn — the busy check,
    /// the streaming, the interrupt — should apply to it unchanged.
    ///
    /// # Errors
    ///
    /// No session open, or a closed connection.
    fn resume(&mut self) -> Result<(), GarrisonError> {
        let method = acp::ext::SESSION_RESUME;
        let session_id = self
            .id
            .clone()
            .ok_or_else(|| GarrisonError::transport(method, "no session is open"))?;
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| GarrisonError::transport(method, "the connection has closed"))?;

        let request = acp::InterruptedTurnRequest { session_id };
        self.turn = Some(writer.request(method, &request)?);
        Ok(())
    }

    /// Gives up on that turn. Not a turn itself, so it is merely outstanding.
    ///
    /// # Errors
    ///
    /// As [`Self::resume`].
    fn abandon(&mut self) -> Result<(), GarrisonError> {
        let method = acp::ext::SESSION_ABANDON;
        let session_id = self
            .id
            .clone()
            .ok_or_else(|| GarrisonError::transport(method, "no session is open"))?;

        let request = acp::InterruptedTurnRequest { session_id };
        self.ask(method, &request, Awaiting::Abandon)
    }

    /// Sends a request that is not a turn, and remembers what it was for.
    fn ask<P: serde::Serialize>(
        &mut self,
        method: &str,
        params: &P,
        purpose: Awaiting,
    ) -> Result<(), GarrisonError> {
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| GarrisonError::transport(method, "the connection has closed"))?;
        let id = writer.request(method, params)?;
        self.outstanding.insert(id, purpose);
        Ok(())
    }

    /// Raises the exit flag. Sending twice is harmless; nobody listening is too.
    fn leave(&self) {
        if let Some(exit) = &self.exit {
            let _ = exit.send(true);
        }
    }
}

/// How the interface introduces itself.
#[must_use]
pub fn banner(session: &acp::SessionId) -> Vec<Line<'static>> {
    vec![
        notice_line(format!("garrison-agent {}", env!("CARGO_PKG_VERSION"))),
        notice_line(format!("session {}", session.0)),
        notice_line("/help for commands, Ctrl+C to leave".to_string()),
        Line::default(),
    ]
}

/// The `/help` listing.
#[must_use]
pub fn help() -> Vec<Line<'static>> {
    let mut lines = vec![notice_line("commands".to_string())];
    lines.extend(slash::ALL.iter().map(|command| {
        notice_line(format!(
            "  /{:<7} {}",
            command.name(),
            command.description()
        ))
    }));
    lines
}

/// How the agent's governance settings read.
#[must_use]
pub fn describe_status(status: &acp::GarrisonStatus) -> Vec<Line<'static>> {
    let approvals = if status.policy.auto_approve.is_empty() {
        "every tool call is asked about".to_string()
    } else {
        format!("auto-approved: {}", status.policy.auto_approve.join(", "))
    };

    vec![
        notice_line(format!(
            "{} {} speaking ACP v{}",
            status.agent, status.version, status.protocol_version
        )),
        notice_line(format!(
            "{} session(s) open, approvals time out after {}s",
            status.sessions, status.policy.approval_timeout_secs
        )),
        notice_line(approvals),
        notice_line(describe_entitlement(status.entitlement.as_ref())),
        notice_line(if status.audit.enabled {
            status.audit.chain_head.as_ref().map_or_else(
                || "audit: recording".to_string(),
                |head| format!("audit: recording, chain head {head}"),
            )
        } else {
            "audit: not recording".to_string()
        }),
        notice_line(describe_sandbox(&status.sandbox)),
        notice_line(describe_store(status.session_store.as_ref())),
    ]
}

/// One line on whether this conversation will still be here tomorrow.
///
/// Pure. The unhealthy case leads, because a store that will not answer is
/// refusing every turn on the daemon and that is what the operator is looking
/// at the status to find out.
fn describe_store(store: Option<&acp::SessionStoreStatus>) -> String {
    let Some(store) = store else {
        return "sessions: not stored, this conversation ends with the daemon".to_string();
    };

    if !store.healthy {
        return format!(
            "sessions: the store is not answering, turns are refused ({})",
            store.last_error.as_deref().unwrap_or("no reason given")
        );
    }

    let kept = format!(
        "sessions: {} stored, kept {} days",
        store.sessions, store.retain_days
    );
    if store.interrupted == 0 {
        kept
    } else {
        format!(
            "{kept}, {} interrupted (/resume or /abandon)",
            store.interrupted
        )
    }
}

/// One line on whether a seat entitles this install to run at all.
///
/// Pure. A standalone agent says so rather than being silent about it: an
/// operator reading `/status` in a governed deployment and seeing nothing
/// about seats would reasonably conclude the check was passing.
fn describe_entitlement(status: Option<&acp::EntitlementStatus>) -> String {
    let Some(status) = status else {
        return "seat: standalone, this agent answers to no control plane".to_string();
    };

    match status.reason.as_deref() {
        Some(reason) => format!("seat: {} - {reason}", status.state),
        None => {
            let mut line = format!("seat: {}", status.state);
            if let Some(tier) = status.tier.as_deref() {
                line.push_str(&format!(" ({tier})"));
            }
            if let Some(checked) = status.checked_at.as_deref() {
                line.push_str(&format!(", confirmed {checked}"));
            }
            line
        }
    }
}

/// One line on what stands between a tool call and the host.
fn describe_sandbox(sandbox: &acp::SandboxStatus) -> String {
    if !sandbox.enabled {
        return "sandbox: off, writing tools run in the agent's process".to_string();
    }

    sandbox.hardening.as_ref().map_or_else(
        || "sandbox: on".to_string(),
        |hardening| format!("sandbox: on, hardening {hardening}"),
    )
}

/// What a turn's ending is worth saying, if anything.
#[must_use]
pub fn ending(outcome: &Result<serde_json::Value, ErrorObject>) -> Vec<Line<'static>> {
    let result = match outcome {
        Ok(value) => value,
        Err(error) => {
            return vec![error_line(format!(
                "{} (code {})",
                error.message,
                i32::from(error.code)
            ))]
        }
    };

    let Ok(response) = serde_json::from_value::<acp::PromptResponse>(result.clone()) else {
        return Vec::new();
    };

    match response.stop_reason {
        acp::StopReason::EndTurn => Vec::new(),
        acp::StopReason::Cancelled => vec![notice_line("interrupted".to_string())],
        acp::StopReason::Refusal => {
            vec![notice_line("the agent declined to continue".to_string())]
        }
        acp::StopReason::MaxTokens => vec![notice_line("stopped: out of context".to_string())],
        acp::StopReason::MaxTurnRequests => {
            vec![notice_line(
                "stopped: too many steps in one turn".to_string(),
            )]
        }
        _ => Vec::new(),
    }
}

/// The text a content block shows, when it shows any.
#[must_use]
pub fn text_of(block: &acp::ContentBlock) -> Option<String> {
    match block {
        acp::ContentBlock::Text(text) => Some(text.text.clone()),
        _ => None,
    }
}

/// Wires every handler.
fn configure(builder: &mut ManagedActor<Idle, Session>) {
    builder.mutate_on::<Wire>(|actor, context| {
        let message = context.message();
        actor.model.compositor = Some(message.compositor.clone());
        actor.model.transcript = Some(message.transcript.clone());
        actor.model.status = Some(message.status.clone());
        actor.model.approval = Some(message.approval.clone());

        let greeting = actor.model.id.as_ref().map(banner).unwrap_or_default();
        let transcript = message.transcript.clone();
        Reply::pending(async move {
            transcript.send(Note { lines: greeting }).await;
        })
    });

    builder.mutate_on::<Submitted>(|actor, context| {
        let text = context.message().text.clone();
        submit(actor, text)
    });

    builder.mutate_on::<Interrupt>(|actor, context| {
        interrupt(actor, context.message().quit_when_idle)
    });

    builder.mutate_on::<Quit>(|actor, _| {
        actor.model.leave();
        Reply::ready()
    });

    builder.mutate_on::<PermissionAnswered>(|actor, context| {
        let message = context.message();
        let outcome = acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(
            acp::PermissionOptionId::new(message.option),
        ));
        let failure = actor
            .model
            .writer
            .as_ref()
            .ok_or_else(|| {
                GarrisonError::transport(
                    acp::method::SESSION_REQUEST_PERMISSION,
                    "the connection has closed",
                )
            })
            .and_then(|writer| writer.answer_permission(message.id.clone(), outcome))
            .err();

        report(actor, failure.map(|error| error_line(error.to_string())))
    });

    builder.mutate_on::<FromAgent>(|actor, context| {
        let event = std::sync::Arc::clone(&context.message().event);
        absorb(actor, &event)
    });
}

/// Echoes what the user typed, then either sends it or holds it.
fn submit(actor: &mut ManagedActor<Started, Session>, text: String) -> FutureBox {
    if let Some((command, _)) = slash::parse(&text) {
        return run_command(actor, command, text);
    }

    let mut lines = vec![user_line(text.clone())];
    let mut started = false;

    if actor.model.is_busy() {
        actor.model.queued.push_back(text);
        lines.push(notice_line("held until the current turn ends".to_string()));
    } else if let Err(error) = actor.model.begin(&text) {
        lines.push(error_line(error.to_string()));
    } else {
        started = true;
    }

    announce(actor, lines, started)
}

/// Carries out one slash command.
fn run_command(
    actor: &mut ManagedActor<Started, Session>,
    command: Command,
    typed: String,
) -> FutureBox {
    let mut lines = vec![user_line(typed)];

    match command {
        Command::Help => lines.extend(help()),
        Command::Quit => {
            actor.model.leave();
            return announce(actor, lines, false);
        }
        Command::Clear => {
            let compositor = actor.model.compositor.clone();
            return Reply::pending(async move {
                if let Some(compositor) = compositor {
                    compositor.send(ClearHistory).await;
                }
            });
        }
        Command::New => {
            if actor.model.is_busy() {
                lines.push(notice_line(
                    "finish or interrupt the current turn first".to_string(),
                ));
            } else {
                let request = acp::NewSessionRequest::new(actor.model.cwd.clone());
                if let Err(error) =
                    actor
                        .model
                        .ask(acp::method::SESSION_NEW, &request, Awaiting::NewSession)
                {
                    lines.push(error_line(error.to_string()));
                }
            }
        }
        Command::Resume => {
            if actor.model.is_busy() {
                lines.push(notice_line(
                    "finish or interrupt the current turn first".to_string(),
                ));
            } else if let Err(error) = actor.model.resume() {
                lines.push(error_line(error.to_string()));
            } else {
                return announce(actor, lines, true);
            }
        }
        Command::Abandon => {
            if let Err(error) = actor.model.abandon() {
                lines.push(error_line(error.to_string()));
            }
        }
        Command::Status => {
            if let Err(error) = actor.model.ask(
                acp::ext::STATUS,
                &serde_json::Value::Object(serde_json::Map::new()),
                Awaiting::Status,
            ) {
                lines.push(error_line(error.to_string()));
            }
        }
    }

    announce(actor, lines, false)
}

/// Stops the running turn, or leaves when there was nothing to stop.
fn interrupt(actor: &mut ManagedActor<Started, Session>, quit_when_idle: bool) -> FutureBox {
    if !actor.model.is_busy() {
        if quit_when_idle {
            actor.model.leave();
        }
        return Reply::ready();
    }

    // The turn is not closed here. It closes when its answer arrives, which is
    // what tells us the agent really stopped rather than that it was asked to.
    actor.model.queued.clear();
    let failure = actor
        .model
        .id
        .clone()
        .zip(actor.model.writer.as_ref())
        .ok_or_else(|| {
            GarrisonError::transport(acp::method::SESSION_CANCEL, "the connection has closed")
        })
        .and_then(|(id, writer)| writer.cancel(id))
        .err();

    let line = failure.map_or_else(
        || notice_line("stopping…".to_string()),
        |error| error_line(error.to_string()),
    );
    report(actor, Some(line))
}

/// Reads one thing the agent said.
fn absorb(actor: &mut ManagedActor<Started, Session>, event: &AgentEvent) -> FutureBox {
    match event {
        AgentEvent::Update(notification) => update(actor, &notification.update),
        AgentEvent::Permission { id, request } => {
            let asked = PermissionAsked {
                id: id.clone(),
                request: request.clone(),
            };
            let approval = actor.model.approval.clone();
            Reply::pending(async move {
                if let Some(approval) = approval {
                    approval.send(asked).await;
                }
            })
        }
        AgentEvent::Unsupported { id, method } => {
            let failure = actor
                .model
                .writer
                .as_ref()
                .and_then(|writer| writer.refuse(id.clone(), method).err());
            report(actor, failure.map(|error| error_line(error.to_string())))
        }
        AgentEvent::Response { id, outcome } => answer(actor, id, outcome),
        AgentEvent::Closed { reason } => {
            actor.model.leave();
            report(actor, Some(error_line(format!("disconnected: {reason}"))))
        }
    }
}

/// Reads one `session/update`.
fn update(actor: &mut ManagedActor<Started, Session>, update: &acp::SessionUpdate) -> FutureBox {
    match update {
        acp::SessionUpdate::AgentMessageChunk(chunk) => {
            let Some(text) = text_of(&chunk.content) else {
                return Reply::ready();
            };
            let transcript = actor.model.transcript.clone();
            Reply::pending(async move {
                if let Some(transcript) = transcript {
                    transcript.send(AgentChunk { text }).await;
                }
            })
        }
        acp::SessionUpdate::ToolCall(call) => {
            let id = call.tool_call_id.0.to_string();
            actor.model.titles.insert(id.clone(), call.title.clone());
            let status = actor.model.status.clone();
            let title = call.title.clone();
            Reply::pending(async move {
                if let Some(status) = status {
                    status.send(ToolStarted { id, title }).await;
                }
            })
        }
        acp::SessionUpdate::ToolCallUpdate(change) => tool_changed(actor, change),
        _ => Reply::ready(),
    }
}

/// Reads one tool-call update, which is only interesting once it settles.
fn tool_changed(
    actor: &mut ManagedActor<Started, Session>,
    change: &acp::ToolCallUpdate,
) -> FutureBox {
    let id = change.tool_call_id.0.to_string();
    if let Some(title) = &change.fields.title {
        actor.model.titles.insert(id.clone(), title.clone());
    }

    let succeeded = match change.fields.status {
        Some(acp::ToolCallStatus::Completed) => true,
        Some(acp::ToolCallStatus::Failed) => false,
        _ => return Reply::ready(),
    };

    let title = actor.model.titles.remove(&id).unwrap_or_else(|| id.clone());
    let status = actor.model.status.clone();
    let transcript = actor.model.transcript.clone();
    let line = tool_line(title, succeeded);

    Reply::pending(async move {
        if let Some(status) = status {
            status.send(ToolEnded { id }).await;
        }
        if let Some(transcript) = transcript {
            transcript.send(Note { lines: vec![line] }).await;
        }
    })
}

/// Matches one answer to whatever asked for it.
fn answer(
    actor: &mut ManagedActor<Started, Session>,
    id: &RequestId,
    outcome: &Result<serde_json::Value, ErrorObject>,
) -> FutureBox {
    if actor.model.turn.as_ref() == Some(id) {
        return finish(actor, outcome);
    }

    match actor.model.outstanding.remove(id) {
        Some(Awaiting::NewSession) => replaced(actor, outcome),
        Some(Awaiting::Status) => announce(actor, governance(outcome), false),
        Some(Awaiting::Abandon) => announce(actor, abandoned(outcome), false),
        None => Reply::ready(),
    }
}

/// Reads the answer to `_garrison/status`.
fn governance(outcome: &Result<serde_json::Value, ErrorObject>) -> Vec<Line<'static>> {
    match outcome {
        Ok(value) => serde_json::from_value::<acp::GarrisonStatus>(value.clone()).map_or_else(
            |error| vec![error_line(format!("unreadable status: {error}"))],
            |status| describe_status(&status),
        ),
        Err(error) => vec![error_line(error.message.to_string())],
    }
}

/// Reads the answer to `_garrison/session/abandon`.
///
/// The error case is the interesting one and is not a failure: `-32021` means
/// there was nothing to abandon, which is what an operator typing `/abandon`
/// on a healthy session should be told plainly.
fn abandoned(outcome: &Result<serde_json::Value, ErrorObject>) -> Vec<Line<'static>> {
    match outcome {
        Ok(value) => serde_json::from_value::<acp::AbandonResponse>(value.clone()).map_or_else(
            |error| vec![error_line(format!("unreadable answer: {error}"))],
            |response| vec![notice_line(format!("abandoned turn {}", response.turn_id))],
        ),
        Err(error) => vec![notice_line(error.message.to_string())],
    }
}

/// Adopts the session `/new` asked for.
fn replaced(
    actor: &mut ManagedActor<Started, Session>,
    outcome: &Result<serde_json::Value, ErrorObject>,
) -> FutureBox {
    let lines = match outcome {
        Ok(value) => match serde_json::from_value::<acp::NewSessionResponse>(value.clone()) {
            Ok(response) => {
                let id = response.session_id;
                let line = notice_line(format!("new session {}", id.0));
                actor.model.id = Some(id);
                actor.model.titles.clear();
                actor.model.queued.clear();
                vec![line]
            }
            Err(error) => vec![error_line(format!("unreadable session: {error}"))],
        },
        Err(error) => vec![error_line(error.message.to_string())],
    };

    announce(actor, lines, false)
}

/// Closes the open turn and starts whatever was waiting behind it.
fn finish(
    actor: &mut ManagedActor<Started, Session>,
    outcome: &Result<serde_json::Value, ErrorObject>,
) -> FutureBox {
    actor.model.turn = None;
    actor.model.titles.clear();
    let mut lines = ending(outcome);

    let next = actor.model.queued.pop_front();
    let started = match next {
        Some(text) => match actor.model.begin(&text) {
            Ok(()) => true,
            Err(error) => {
                lines.push(error_line(error.to_string()));
                false
            }
        },
        None => false,
    };

    let transcript = actor.model.transcript.clone();
    let status = actor.model.status.clone();

    Reply::pending(async move {
        if let Some(transcript) = transcript {
            // The tail is flushed before anything is said about how the turn
            // ended, so the last words of the reply cannot land underneath the
            // note explaining that it stopped.
            transcript.send(AgentFinished).await;
            if !lines.is_empty() {
                transcript.send(Note { lines }).await;
            }
        }
        if let Some(status) = status {
            status.send(TurnEnded).await;
            if started {
                status.send(TurnStarted).await;
            }
        }
    })
}

/// Commits some transcript rows and, when a turn just opened, says so.
fn announce(
    actor: &ManagedActor<Started, Session>,
    lines: Vec<Line<'static>>,
    started: bool,
) -> FutureBox {
    let transcript = actor.model.transcript.clone();
    let status = actor.model.status.clone();

    Reply::pending(async move {
        if let Some(transcript) = transcript {
            transcript.send(Note { lines }).await;
        }
        if started {
            if let Some(status) = status {
                status.send(TurnStarted).await;
            }
        }
    })
}

/// Commits one row, when there is one to commit.
fn report(actor: &ManagedActor<Started, Session>, line: Option<Line<'static>>) -> FutureBox {
    let Some(line) = line else {
        return Reply::ready();
    };

    announce(actor, vec![line], false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    fn ended(reason: acp::StopReason) -> Vec<Line<'static>> {
        let response = serde_json::to_value(acp::PromptResponse::new(reason))
            .expect("a prompt response serializes");
        ending(&Ok(response))
    }

    #[test]
    fn an_ordinary_ending_says_nothing() {
        assert!(ended(acp::StopReason::EndTurn).is_empty());
    }

    #[test]
    fn every_other_ending_is_explained() {
        for reason in [
            acp::StopReason::Cancelled,
            acp::StopReason::Refusal,
            acp::StopReason::MaxTokens,
            acp::StopReason::MaxTurnRequests,
        ] {
            assert!(
                !ended(reason).is_empty(),
                "a turn that stopped for {reason:?} must say why"
            );
        }
    }

    #[test]
    fn a_refused_turn_reports_the_agents_error() {
        let mut error = ErrorObject::internal_error();
        error.message = "the model fell over".into();
        let lines = ending(&Err(error));

        assert_eq!(lines.len(), 1);
        assert!(text(&lines[0]).contains("the model fell over"));
    }

    #[test]
    fn an_unreadable_answer_is_not_mistaken_for_a_clean_ending() {
        // Anything that is not a PromptResponse says nothing rather than
        // claiming the turn ended normally, because a claim would be a guess.
        let lines = ending(&Ok(serde_json::Value::String("nonsense".to_string())));

        assert!(lines.is_empty());
    }

    #[test]
    fn only_text_blocks_have_text() {
        let block = acp::ContentBlock::from("hello");

        assert_eq!(text_of(&block), Some("hello".to_string()));
    }

    #[test]
    fn the_help_listing_covers_every_command() {
        let listed = help();

        for command in slash::ALL {
            assert!(
                listed
                    .iter()
                    .any(|line| text(line).contains(command.name())),
                "/{} is missing from the help",
                command.name()
            );
        }
    }

    #[test]
    fn the_banner_names_the_session_it_opened() {
        let id = acp::SessionId::new("thread_abc");
        let lines = banner(&id);

        assert!(lines.iter().any(|line| text(line).contains("thread_abc")));
    }

    #[test]
    fn status_without_auto_approval_says_so_rather_than_showing_an_empty_list() {
        let status = acp::GarrisonStatus {
            agent: "garrison-agent".to_string(),
            version: "0.1.0".to_string(),
            protocol_version: 1,
            sessions: 1,
            policy: acp::PolicyStatus {
                approval_timeout_secs: 30,
                auto_approve: Vec::new(),
                governance: None,
            },
            audit: acp::AuditStatus::undescribed(true),
            context: None,
            sandbox: acp::SandboxStatus {
                enabled: true,
                hardening: Some("enforce".to_string()),
                timeout_secs: Some(120),
                memory_limit_bytes: None,
            },
            threads: None,
            plane: None,
            session_store: None,
            entitlement: None,
        };

        let rendered: String = describe_status(&status)
            .iter()
            .map(text)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("every tool call is asked about"));
        assert!(rendered.contains("audit: recording"));
        assert!(rendered.contains("sandbox: on, hardening enforce"));
    }

    #[test]
    fn an_unsandboxed_agent_says_where_its_tools_actually_run() {
        // Silence would read as "fine". Someone reviewing a deployment needs
        // the absence of isolation stated, not merely unmentioned.
        let rendered = describe_sandbox(&acp::SandboxStatus::disabled());

        assert!(rendered.contains("off"), "got: {rendered}");
        assert!(
            rendered.contains("in the agent's process"),
            "got: {rendered}"
        );
    }
}
