//! Sessions: one conversation, one owning actor, one turn at a time.
//!
//! ACP calls them sessions; Garrison's actor is a [`Thread`]. It owns
//! everything about one exchange — the history, the working directory, whether
//! a turn is running, and how to stop it. Nothing else touches that state, so
//! there is no lock anywhere in this file and none needed.
//!
//! # Why a turn is a task, not a handler
//!
//! A turn is the longest thing the agent does: minutes of model calls and tool
//! runs. It cannot live in an actor handler at all.
//!
//! `mutate_on` is awaited inline on the message loop, so a turn there would
//! block every other message for its whole duration. `act_on` looks like the
//! escape hatch and is not: acton-reactive pushes read-only handler futures
//! into a `FuturesUnordered` that the loop drains **to completion** at its next
//! flush point, so a long `act_on` future blocks the loop just as thoroughly,
//! only later and less predictably.
//!
//! So [`StartTurn`] is a short `mutate_on` that admits the turn, spawns it as a
//! task it keeps the handle to, and returns. The task reports back with
//! [`TurnOutcome`]. `session/cancel` is therefore heard *during* a turn, which
//! is the whole point.
//!
//! # Why sessions are not restarted
//!
//! [`ThreadSupervisor`] supervises *lifetime*: it creates sessions, hands out
//! their addresses, lists them, and stops them. It deliberately does not use
//! acton-reactive's restart supervision, because a restarted actor comes back
//! with a `Default` model — and for a session that means an empty history. The
//! failure a restart repairs is a lost connection or a crashed child process; a
//! session owns neither. Silently resurrecting a conversation with no memory of
//! itself is worse than reporting that it is gone.

use crate::approval::{with_turn_scope, TurnScope};
use crate::protocol::acp::{self, StopReason};
use crate::protocol::codec::EventSink;
use crate::router::{ClaimTurn, ReleaseTurn};
use crate::types::{ClientId, ThreadId, TurnId};
use acton_ai::facade::ActonAI;
use acton_ai::messages::{Message, MessageRole};
use acton_reactive::prelude::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Token counts for one turn, as the provider reported them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TurnUsage {
    /// Tokens sent.
    pub prompt_tokens: u64,
    /// Tokens received.
    pub completion_tokens: u64,
}

/// What a turn produced.
#[derive(Clone, Debug)]
pub enum TurnResult {
    /// The model finished. Carries the ACP stop reason the client will see.
    Completed {
        /// Why it stopped.
        stop_reason: StopReason,
        /// Everything it said.
        text: String,
        /// What it cost.
        usage: TurnUsage,
    },
    /// The client cancelled it.
    Cancelled,
    /// It failed, and the `session/prompt` must be answered with an error.
    Failed {
        /// What went wrong, in words a client can display.
        reason: String,
    },
}

/// Starts a turn on this session.
#[acton_message]
pub struct StartTurn {
    /// What the user said, flattened out of the ACP prompt blocks.
    pub content: String,
}

/// Whether a turn was admitted.
#[acton_message]
pub enum TurnAdmission {
    /// It was.
    Started {
        /// The new turn.
        turn_id: TurnId,
    },
    /// It was not: this session is already running a turn.
    Busy {
        /// The turn already in flight.
        turn_id: TurnId,
    },
}

impl Request for StartTurn {
    type Response = TurnAdmission;
}

/// Sent by the turn's own task when the turn is over, however it ended.
#[acton_message]
pub struct TurnOutcome {
    /// The turn that ended.
    pub turn_id: TurnId,
    /// The user message it ran, kept so history is only committed on success.
    pub content: String,
    /// How it ended.
    pub result: TurnResult,
}

/// Told to the connection so it can answer the parked `session/prompt`.
#[acton_message]
pub struct TurnFinished {
    /// The session whose turn ended.
    pub thread_id: ThreadId,
    /// The turn that ended.
    pub turn_id: TurnId,
    /// How it ended.
    pub result: TurnResult,
}

/// Stops the running turn, if there is one. ACP's `session/cancel`.
#[acton_message]
pub struct InterruptTurn;

/// Whether there was anything to cancel.
#[acton_message]
pub struct Interrupted {
    /// The turn that was asked to stop, or `None` if the session was idle.
    pub turn_id: Option<TurnId>,
}

impl Request for InterruptTurn {
    type Response = Interrupted;
}

/// Re-points a session's events and approvals at a different connection, and
/// replays its history to the new owner.
///
/// This is ACP's `session/load`: the conversation survives the client that
/// started it, and the next turn's chunks and permission requests must go to
/// whoever is attached now.
#[acton_message]
pub struct Reattach {
    /// The client taking ownership.
    pub owner: ClientId,
    /// Its event sink.
    pub sink: EventSink,
    /// Its connection actor.
    pub conn: ActorHandle,
}

impl Request for Reattach {
    type Response = ThreadSummary;
}

/// Asks a session to describe itself.
#[acton_message]
pub struct DescribeThread;

impl Request for DescribeThread {
    type Response = ThreadSummary;
}

/// What `session/list` needs to know about one session.
#[acton_message]
pub struct ThreadSummary {
    /// The session's identity.
    pub thread_id: ThreadId,
    /// How many messages its history holds.
    pub message_count: usize,
    /// Whether a turn is in flight.
    pub busy: bool,
    /// The directory it is rooted at.
    pub project_root: PathBuf,
}

impl Default for ThreadSummary {
    fn default() -> Self {
        Self {
            thread_id: ThreadId::new(),
            message_count: 0,
            busy: false,
            project_root: PathBuf::new(),
        }
    }
}

/// The turn currently in flight.
///
/// Holds the task's join handle so the turn has an owner: an actor that stops
/// mid-turn aborts it rather than leaving it running against a socket nobody
/// is reading.
#[derive(Debug)]
struct RunningTurn {
    turn_id: TurnId,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

/// Everything a session needs that is fixed for its whole life.
#[derive(Clone, Debug)]
pub struct ThreadSetup {
    /// This session's identity.
    pub thread_id: ThreadId,
    /// The client that created it, and answers its approvals.
    pub owner: ClientId,
    /// Where its events go.
    pub sink: EventSink,
    /// That client's connection actor.
    pub conn: ActorHandle,
    /// The acton-ai runtime that runs its turns.
    pub runtime: ActonAI,
    /// The turn router, for attributing broadcast tool events.
    pub router: ActorHandle,
    /// The directory the session's work is rooted at — ACP's `cwd`.
    ///
    /// Shared rather than cloned per turn: it is read-only for the life of
    /// the session, and both the approval preflight and the patch tool read
    /// it on every call.
    pub project_root: Arc<PathBuf>,
    /// A system prompt to prepend to every turn.
    pub system_prompt: Option<String>,
    /// How long an approval may wait for the client.
    pub approval_timeout: Duration,
    /// Tool-name patterns that skip the approval round-trip.
    pub auto_approve: Arc<Vec<String>>,
    /// The language servers this session's LSP tools reach.
    pub lsp: Arc<crate::lsp::LspRegistry>,
}

/// One conversation.
#[acton_actor]
pub struct Thread {
    setup: Option<ThreadSetup>,
    history: Vec<Message>,
    running: Option<RunningTurn>,
}

impl Thread {
    /// Restores a session's history.
    #[must_use]
    pub fn with_history(mut self, history: Vec<Message>) -> Self {
        self.history = history;
        self
    }

    /// The messages to send for a turn: everything so far plus what was said.
    ///
    /// Pure, so the history-assembly rule is testable without a model.
    fn turn_messages(&self, content: &str) -> Vec<Message> {
        let mut messages = self.history.clone();
        messages.push(Message::user(content));
        messages
    }

    /// Commits a completed exchange to the history.
    ///
    /// Only a turn that produced text is recorded. A cancelled or failed turn
    /// leaves no trace, so a client that retries sends the same conversation it
    /// thought it had rather than one containing a question the model never
    /// answered.
    fn commit(&mut self, content: &str, text: &str) {
        self.history.push(Message::user(content));
        self.history.push(Message::assistant(text));
    }

    /// A description of this session for `session/list`.
    fn summary(&self) -> ThreadSummary {
        let (thread_id, project_root) = match &self.setup {
            Some(setup) => (setup.thread_id.clone(), setup.project_root.as_ref().clone()),
            None => (ThreadId::new(), PathBuf::new()),
        };

        ThreadSummary {
            thread_id,
            message_count: self.history.len(),
            busy: self.running.is_some(),
            project_root,
        }
    }
}

/// Replays a history to a newly attached client as `session/update` events.
///
/// Emitted from inside the `Reattach` handler, before its reply is sent, so the
/// FIFO sink guarantees every chunk reaches the socket ahead of the
/// `session/load` response — which is the ordering ACP asks for.
///
/// Tool and system messages are skipped: a session's tool traffic is
/// reconstructed by the client from the tool-call updates it already saw, and
/// replaying a system prompt as a user-visible chunk would put words in the
/// operator's mouth.
fn replay(thread_id: &ThreadId, history: &[Message], sink: &EventSink) {
    for message in history {
        let update = match message.role {
            MessageRole::User => acp::user_chunk(thread_id, &message.content),
            MessageRole::Assistant => acp::agent_chunk(thread_id, &message.content),
            MessageRole::System | MessageRole::Tool => continue,
        };
        sink.notify(acp::method::SESSION_UPDATE, &update);
    }
}

/// Wires a session's handlers.
fn configure_handlers(builder: &mut ManagedActor<Idle, Thread>) {
    builder.mutate_on::<StartTurn>(|actor, envelope| {
        let reply = envelope.reply_envelope();

        if let Some(running) = &actor.model.running {
            let admission = TurnAdmission::Busy {
                turn_id: running.turn_id.clone(),
            };
            return Reply::pending(async move {
                reply.send(admission).await;
            });
        }

        let Some(setup) = actor.model.setup.clone() else {
            tracing::error!("a session was asked to run a turn before it was configured");
            return Reply::ready();
        };

        let content = envelope.message().content.clone();
        let messages = actor.model.turn_messages(&content);
        let turn_id = TurnId::new();
        let cancel = CancellationToken::new();

        // Spawned rather than awaited: see the module docs on why neither kind
        // of handler can hold a turn.
        let task = tokio::spawn(run_turn(
            setup,
            turn_id.clone(),
            content,
            cancel.clone(),
            messages,
            actor.new_envelope(),
        ));

        actor.model.running = Some(RunningTurn {
            turn_id: turn_id.clone(),
            cancel,
            task,
        });

        Reply::pending(async move {
            reply.send(TurnAdmission::Started { turn_id }).await;
        })
    });

    builder.mutate_on::<TurnOutcome>(|actor, envelope| {
        let message = envelope.message().clone();

        // A stale outcome — from a turn that was already cleared — must not
        // clear whatever is running now.
        let is_current = actor
            .model
            .running
            .as_ref()
            .is_some_and(|running| running.turn_id == message.turn_id);
        if !is_current {
            return Reply::ready();
        }

        actor.model.running = None;

        if let TurnResult::Completed { text, .. } = &message.result {
            actor.model.commit(&message.content, text);
        }

        let Some(setup) = actor.model.setup.clone() else {
            return Reply::ready();
        };

        Reply::pending(async move {
            // The connection answers the parked `session/prompt` from this.
            setup
                .conn
                .send(TurnFinished {
                    thread_id: setup.thread_id.clone(),
                    turn_id: message.turn_id.clone(),
                    result: message.result,
                })
                .await;

            // Best-effort: the router forgets the turn on acton-ai's own
            // `TurnFinished` too, and a cancelled turn may never publish one,
            // which is exactly why this release exists.
            let _ = setup
                .router
                .ask(ReleaseTurn {
                    turn_id: message.turn_id,
                })
                .await;
        })
    });

    builder.mutate_on::<InterruptTurn>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let turn_id = actor.model.running.as_ref().map(|running| {
            running.cancel.cancel();
            running.turn_id.clone()
        });

        Reply::pending(async move {
            reply.send(Interrupted { turn_id }).await;
        })
    });

    builder.mutate_on::<Reattach>(|actor, envelope| {
        let message = envelope.message().clone();
        let reply = envelope.reply_envelope();

        if let Some(setup) = &mut actor.model.setup {
            setup.owner = message.owner;
            setup.sink = message.sink;
            setup.conn = message.conn;
            replay(&setup.thread_id, &actor.model.history, &setup.sink);
        }

        let summary = actor.model.summary();
        Reply::pending(async move {
            reply.send(summary).await;
        })
    });

    // `mutate_on` although it mutates nothing: a read-only handler would not
    // run until the loop's next flush, and `session/list` asks every session
    // in turn.
    builder.mutate_on::<DescribeThread>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let summary = actor.model.summary();
        Reply::pending(async move {
            reply.send(summary).await;
        })
    });

    builder.before_stop(|actor| {
        // A session that stops mid-turn takes the turn with it.
        if let Some(running) = &actor.model.running {
            running.cancel.cancel();
            running.task.abort();
        }
        async {}
    });
}

/// Runs one turn end to end and reports how it ended.
///
/// Free function so it borrows nothing from the actor: everything it needs was
/// cloned out before the task was spawned. The task-local approval scope is set
/// here rather than at the call site because task-locals do not cross a spawn.
async fn run_turn(
    setup: ThreadSetup,
    turn_id: TurnId,
    content: String,
    cancel: CancellationToken,
    messages: Vec<Message>,
    self_envelope: Option<OutboundEnvelope>,
) {
    let result = drive_turn(&setup, &turn_id, cancel, messages).await;

    if let Some(envelope) = self_envelope {
        envelope
            .send(TurnOutcome {
                turn_id,
                content,
                result,
            })
            .await;
    }
}

/// The turn itself, separated so `run_turn` is only about reporting.
async fn drive_turn(
    setup: &ThreadSetup,
    turn_id: &TurnId,
    cancel: CancellationToken,
    messages: Vec<Message>,
) -> TurnResult {
    // Claiming is what lets the router attribute this turn's broadcast tool
    // events. Awaiting the acknowledgement before starting is the exclusion;
    // see `crate::router`.
    if let Err(error) = setup
        .router
        .ask(ClaimTurn {
            thread_id: setup.thread_id.clone(),
            turn_id: turn_id.clone(),
            sink: setup.sink.clone(),
        })
        .await
    {
        return TurnResult::Failed {
            reason: format!("could not start a turn: {error}"),
        };
    }

    let scope = TurnScope {
        thread_id: setup.thread_id.clone(),
        turn_id: turn_id.clone(),
        client_id: setup.owner.clone(),
        project_root: Arc::clone(&setup.project_root),
        conn: setup.conn.clone(),
        timeout: setup.approval_timeout,
        auto_approve: Arc::clone(&setup.auto_approve),
    };

    let sink = setup.sink.clone();
    let thread_id = setup.thread_id.clone();
    let mut builder = setup.runtime.continue_with(messages).on_token(move |text| {
        sink.notify(
            acp::method::SESSION_UPDATE,
            &acp::agent_chunk(&thread_id, text),
        );
    });
    if let Some(system) = &setup.system_prompt {
        builder = builder.system(system.clone());
    }
    // Every filesystem-capable builtin is built for this session's root and
    // no other directory: not the daemon's working directory, not `/tmp`. It
    // is the same boundary `apply_patch` and the language servers below are
    // held to, which is the whole point of scoping it here rather than once
    // at launch.
    builder = builder.use_builtins_in(setup.project_root.as_ref());
    // Registered per prompt because acton-ai has no runtime-wide registration
    // for a downstream tool. Garrison builds every turn's prompt itself, so
    // "per prompt" and "always" are the same thing here.
    builder = crate::patch::install(builder, setup.project_root.as_ref().clone());
    builder = crate::lsp::install(
        builder,
        Arc::clone(&setup.lsp),
        Arc::clone(&setup.project_root),
    );

    // The scope must wrap the await, not merely be set before it: the approval
    // hook runs inside `collect()`, on this task.
    let outcome = with_turn_scope(scope, async move {
        tokio::select! {
            // Biased so a cancellation that arrives while the model is
            // mid-response wins deterministically, rather than depending on
            // which branch `select!` samples first.
            biased;
            () = cancel.cancelled() => None,
            result = builder.collect() => Some(result),
        }
    })
    .await;

    match outcome {
        None => TurnResult::Cancelled,
        Some(Ok(response)) => TurnResult::Completed {
            stop_reason: stop_reason_for(response.stop_reason),
            text: response.text,
            usage: TurnUsage {
                prompt_tokens: response.usage.input_tokens,
                completion_tokens: response.usage.output_tokens,
            },
        },
        Some(Err(error)) => TurnResult::Failed {
            reason: error.to_string(),
        },
    }
}

/// Translates acton-ai's stop reason into ACP's.
///
/// Pure. `ToolUse` and `StopSequence` both mean the model stopped of its own
/// accord with the turn complete, which is ACP's `end_turn`; a turn that ended
/// in `ToolUse` and still had rounds left never reaches here, because the
/// prompt loop keeps going.
#[must_use]
fn stop_reason_for(reason: acton_ai::messages::StopReason) -> StopReason {
    match reason {
        acton_ai::messages::StopReason::MaxTokens => StopReason::MaxTokens,
        acton_ai::messages::StopReason::Error => StopReason::Refusal,
        acton_ai::messages::StopReason::EndTurn
        | acton_ai::messages::StopReason::ToolUse
        | acton_ai::messages::StopReason::StopSequence => StopReason::EndTurn,
    }
}

// =============================================================================
// Supervisor
// =============================================================================

/// Creates a session and returns its address.
#[acton_message]
pub struct CreateThread {
    /// The configuration for the new session. Its `thread_id` is authoritative.
    pub setup: ThreadSetup,
    /// History to restore.
    pub history: Vec<Message>,
}

/// The address of a newly created session.
#[acton_message]
pub struct ThreadCreated {
    /// The session's identity.
    pub thread_id: ThreadId,
    /// Its actor.
    pub handle: ActorHandle,
}

impl Request for CreateThread {
    type Response = ThreadCreated;
}

/// Self-sent once a session actor is running, to add it to the table.
#[acton_message]
struct RegisterThread {
    thread_id: ThreadId,
    handle: ActorHandle,
}

/// Looks a session up by identity.
#[acton_message]
pub struct FindThread {
    /// The session wanted.
    pub thread_id: ThreadId,
}

/// The answer to [`FindThread`].
#[acton_message]
pub struct ThreadLookup {
    /// The session's actor, or `None` if no such session exists.
    pub handle: Option<ActorHandle>,
}

impl Request for FindThread {
    type Response = ThreadLookup;
}

/// Asks for every live session's address.
#[acton_message]
pub struct ListThreads;

/// Every live session, oldest first.
///
/// Ordered by identifier, which for a time-sortable `mti` identity is creation
/// order — so `session/list` reads chronologically without storing a timestamp.
#[acton_message]
pub struct ThreadList {
    /// The sessions, with their addresses.
    pub threads: Vec<(ThreadId, ActorHandle)>,
}

impl Request for ListThreads {
    type Response = ThreadList;
}

/// Owns every session's lifetime.
///
/// See the module docs for why this is not acton-reactive supervision.
#[acton_actor]
pub struct ThreadSupervisor {
    runtime: ActorRuntime,
    threads: HashMap<ThreadId, ActorHandle>,
}

impl ThreadSupervisor {
    /// Spawns the supervisor.
    pub async fn spawn(runtime: &mut ActorRuntime) -> ActorHandle {
        let mut builder = runtime.new_actor_with_name::<Self>("thread_supervisor".to_string());

        // Its own clone, so it can spawn sessions from inside a handler without
        // reaching back into whoever started it.
        builder.model.runtime = runtime.clone();
        configure_supervisor(&mut builder);

        builder.start().await
    }

    /// Every session, oldest first.
    fn sorted(&self) -> Vec<(ThreadId, ActorHandle)> {
        let mut threads: Vec<_> = self
            .threads
            .iter()
            .map(|(id, handle)| (id.clone(), handle.clone()))
            .collect();
        threads.sort_by(|left, right| left.0.cmp(&right.0));
        threads
    }
}

/// Wires the supervisor's handlers.
fn configure_supervisor(builder: &mut ManagedActor<Idle, ThreadSupervisor>) {
    builder.mutate_on::<CreateThread>(|actor, envelope| {
        let message = envelope.message().clone();
        let reply = envelope.reply_envelope();
        let mut runtime = actor.model.runtime.clone();
        let thread_id = message.setup.thread_id.clone();
        let self_envelope = actor.new_envelope();

        Reply::pending(async move {
            let handle = spawn_thread(&mut runtime, message).await;

            // The table lives behind the message loop this future has already
            // left, so registration travels as a message. It is enqueued
            // *before* the creator is told the session exists, and a mailbox is
            // FIFO — so nobody who could know the identity can ask about it
            // ahead of the registration.
            if let Some(envelope) = self_envelope {
                envelope
                    .send(RegisterThread {
                        thread_id: thread_id.clone(),
                        handle: handle.clone(),
                    })
                    .await;
            }

            reply.send(ThreadCreated { thread_id, handle }).await;
        })
    });

    builder.mutate_on::<RegisterThread>(|actor, envelope| {
        let message = envelope.message();
        actor
            .model
            .threads
            .insert(message.thread_id.clone(), message.handle.clone());
        Reply::ready()
    });

    builder.mutate_on::<FindThread>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let handle = actor
            .model
            .threads
            .get(&envelope.message().thread_id)
            .cloned();
        Reply::pending(async move {
            reply.send(ThreadLookup { handle }).await;
        })
    });

    builder.mutate_on::<ListThreads>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let threads = actor.model.sorted();
        Reply::pending(async move {
            reply.send(ThreadList { threads }).await;
        })
    });
}

/// Spawns one session actor with its history restored.
async fn spawn_thread(runtime: &mut ActorRuntime, message: CreateThread) -> ActorHandle {
    let name = format!("session_{}", message.setup.thread_id);
    let mut builder = runtime.new_actor_with_name::<Thread>(name);

    builder.model.setup = Some(message.setup);
    builder.model.history = message.history;
    configure_handlers(&mut builder);

    builder.start().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn a_turn_sends_the_history_plus_the_new_message() {
        let thread = Thread {
            history: vec![Message::user("first"), Message::assistant("answer")],
            ..Thread::default()
        };

        let messages = thread.turn_messages("second");

        assert_eq!(messages.len(), 3);
        assert_eq!(messages[2], Message::user("second"));
    }

    #[test]
    fn committing_appends_the_exchange() {
        let mut thread = Thread::default();

        thread.commit("question", "answer");

        assert_eq!(
            thread.history,
            vec![Message::user("question"), Message::assistant("answer")]
        );
    }

    #[test]
    fn an_unconfigured_session_still_describes_itself() {
        let summary = Thread::default().summary();

        assert_eq!(summary.message_count, 0);
        assert!(!summary.busy);
    }

    #[test]
    fn a_summary_counts_history_messages() {
        let thread =
            Thread::default().with_history(vec![Message::user("q"), Message::assistant("a")]);

        assert_eq!(thread.summary().message_count, 2);
    }

    #[test]
    fn history_is_restorable() {
        let history = vec![Message::user("earlier")];

        let thread = Thread::default().with_history(history.clone());

        assert_eq!(thread.history, history);
    }

    #[test]
    fn a_replay_emits_one_chunk_per_visible_message() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sink = EventSink::new(tx);
        let thread_id = ThreadId::new();
        let history = vec![
            Message::system("you are a coding agent"),
            Message::user("hello"),
            Message::assistant("hi"),
        ];

        replay(&thread_id, &history, &sink);
        drop(sink);

        let lines: Vec<String> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(lines.len(), 2, "{lines:?}");

        let first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(first["method"], acp::method::SESSION_UPDATE);
        assert_eq!(
            first["params"]["update"]["sessionUpdate"],
            "user_message_chunk"
        );
        assert_eq!(first["params"]["update"]["content"]["text"], "hello");

        let second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(
            second["params"]["update"]["sessionUpdate"],
            "agent_message_chunk"
        );
    }

    #[test]
    fn acton_stop_reasons_map_onto_acp_ones() {
        use acton_ai::messages::StopReason as Acton;

        assert_eq!(stop_reason_for(Acton::EndTurn), StopReason::EndTurn);
        assert_eq!(stop_reason_for(Acton::ToolUse), StopReason::EndTurn);
        assert_eq!(stop_reason_for(Acton::StopSequence), StopReason::EndTurn);
        assert_eq!(stop_reason_for(Acton::MaxTokens), StopReason::MaxTokens);
        assert_eq!(stop_reason_for(Acton::Error), StopReason::Refusal);
    }
}
