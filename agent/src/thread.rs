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

use crate::admission::{self, Admission, AdmitTurn, TurnRefusal, Work};
use crate::approval::{with_turn_scope, TurnScope};
use crate::entitlement::EntitlementLost;
use crate::protocol::acp::{self, StopReason};
use crate::protocol::codec::EventSink;
use crate::protocol::conn::{Describe, StatusPart};
use crate::router::{ClaimTurn, ReleaseTurn};
use crate::session::ids::{acton_turn_id, checkpoint_id_for};
use crate::session::meta::SessionMeta;
use crate::session::store::SessionStore;
use crate::types::{ClientId, ThreadId, TurnId};
use acton_ai::facade::ActonAI;
use acton_ai::memory::{CompactionRecord, COMPACTION_NOTICE};
use acton_ai::messages::{Message, MessageRole};
use acton_ai::prompt::PromptBuilder;
use acton_reactive::prelude::*;
use chrono::Utc;
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
        /// The plan as it stood when the turn ended, if the model published
        /// one. The client saw each version stream past; this is the state.
        plan: Option<acton_ai::tools::plan::Plan>,
        /// What the prompt loop summarized away during the turn, oldest
        /// first. Empty unless auto-compaction is on and fired.
        compactions: Vec<CompactionRecord>,
    },
    /// The client cancelled it.
    Cancelled,
    /// A gate refused to admit it, and the `session/prompt` must be answered
    /// with that gate's error code.
    Refused(TurnRefusal),
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

/// Picks a turn a restart interrupted back up where it stopped.
///
/// `_garrison/session/resume`. The turn runs under the identifier it already
/// had, against the checkpoint it already wrote, so the rounds it spent and
/// the tools it ran are not spent or run again.
#[acton_message]
pub struct ResumeTurn;

/// What asking to resume produced.
#[acton_message]
pub enum ResumeAdmission {
    /// The interrupted turn is running again.
    Resumed {
        /// The turn, with the identifier it always had.
        turn_id: TurnId,
    },
    /// There was no interrupted turn to pick up.
    Nothing,
    /// A turn is already running on this session.
    Busy {
        /// The turn in flight.
        turn_id: TurnId,
    },
}

impl Request for ResumeTurn {
    type Response = ResumeAdmission;
}

/// Gives up on a turn a restart interrupted, unblocking the session.
///
/// `_garrison/session/abandon`. The saved progress is marked abandoned rather
/// than deleted, so the record of a turn that was started and never finished
/// survives for whoever reads the trail.
#[acton_message]
pub struct AbandonTurn;

/// What asking to abandon produced.
#[acton_message]
pub struct Abandoned {
    /// The turn given up on, or `None` if nothing was interrupted.
    pub turn_id: Option<TurnId>,
}

impl Request for AbandonTurn {
    type Response = Abandoned;
}

/// Sent by this actor to itself once a finished turn is safely stored.
///
/// The step between a turn ending and its client being told: the history has
/// to reach the store before the client can send the next prompt, or a
/// restart in that window would lose the exchange the client was just told
/// had succeeded.
#[acton_message]
struct NoteStored {
    /// The session's state as the store now holds it, `None` when the write
    /// did not land.
    meta: Option<SessionMeta>,
    /// How many of the history's messages the store now holds.
    appended: usize,
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
    /// The gates every turn must pass, in the order they are asked.
    ///
    /// Each answers [`AdmitTurn`]; see [`crate::admission`]. A subsystem that
    /// wants a say in whether a turn starts adds its actor here and never
    /// touches the turn itself.
    pub gates: Vec<ActorHandle>,
    /// Where this session is written so it survives a restart.
    ///
    /// `None` on an install that arms no `[checkpoint]` database: the session
    /// then lives in this actor alone and dies with the process, which is
    /// what a standalone developer install does and always did.
    pub store: Option<SessionStore>,
    /// The policy agent every tool call in this session is put to.
    ///
    /// `None` leaves the local auto-approve list as the whole policy, which
    /// is what a stack brought up without a policy agent gets.
    pub policy: Option<ActorHandle>,
}

/// What the store holds for this session, as this actor last left it.
///
/// Present exactly when [`ThreadSetup::store`] is, and kept beside the
/// history rather than inside it because none of it is something the model
/// ever sees.
#[derive(Clone, Debug)]
struct Stored {
    /// The session's stored state, including which conversation its history
    /// lives in.
    meta: SessionMeta,
    /// How many of [`Thread::history`]'s messages the store already holds.
    ///
    /// Everything past this index is what the next append writes. A
    /// compaction resets it, because a compacted history is not an append
    /// onto the stored one.
    appended: usize,
}

/// One conversation.
#[acton_actor]
pub struct Thread {
    setup: Option<ThreadSetup>,
    history: Vec<Message>,
    running: Option<RunningTurn>,
    stored: Option<Stored>,
    /// Why the turn in flight was cancelled, when it was cancelled by losing
    /// entitlement rather than by the client. Consumed by [`TurnOutcome`], so
    /// what reaches the client is the refusal and not a bare `cancelled`.
    revoked: Option<TurnRefusal>,
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

    /// Commits a completed exchange to the history, compactions and all.
    ///
    /// Only a turn that produced text is recorded. A cancelled or failed turn
    /// leaves no trace, so a client that retries sends the same conversation it
    /// thought it had rather than one containing a question the model never
    /// answered.
    ///
    /// With `compactions` empty this is the append it has always been. With
    /// records present the turn's own prompt is appended first and then
    /// [`adopt`] replays them onto the result, so what is stored is the
    /// conversation the model actually had rather than the one it was
    /// spared.
    fn commit(&mut self, content: &str, text: &str, compactions: &[CompactionRecord]) {
        self.history.push(Message::user(content));
        self.history = adopt(std::mem::take(&mut self.history), compactions);
        self.history.push(Message::assistant(text));
    }

    /// Restores what the store holds for this session.
    #[must_use]
    fn with_stored(mut self, meta: Option<SessionMeta>, appended: usize) -> Self {
        self.stored = meta.map(|meta| Stored { meta, appended });
        self
    }

    /// The messages the store has not been told about yet.
    fn unappended(&self) -> Vec<Message> {
        let appended = self.stored.as_ref().map_or(0, |stored| stored.appended);
        self.history.get(appended..).unwrap_or_default().to_vec()
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
///
/// A compaction summary is a user-role message the framework wrote, not
/// something the operator said, so it replays as an agent *thought*: the
/// closest spec-native slot for context the agent carries and did not utter.
/// Dropping it instead would hide that the history was rewritten.
fn replay(thread_id: &ThreadId, history: &[Message], sink: &EventSink) {
    for message in history {
        let update = match message.role {
            MessageRole::User if is_compaction_summary(message) => {
                acp::thought_chunk(thread_id, &message.content)
            }
            MessageRole::User => acp::user_chunk(thread_id, &message.content),
            MessageRole::Assistant => acp::agent_chunk(thread_id, &message.content),
            MessageRole::System | MessageRole::Tool => continue,
        };
        sink.notify(acp::method::SESSION_UPDATE, &update);
    }
}

/// Whether a message is the framework's compaction summary.
///
/// Recognized by acton-ai's own opening line, which is a public constant for
/// exactly this: a transcript reader, a stored session, and this replay all
/// need to tell the summary apart from a participant's words, and matching the
/// constant is the only way to do that which cannot drift from what the model
/// was shown.
#[must_use]
fn is_compaction_summary(message: &Message) -> bool {
    message.role == MessageRole::User && message.content.starts_with(COMPACTION_NOTICE)
}

/// Replays a turn's compactions onto the session's own copy of the history.
///
/// Pure, and the whole reason compaction is worth anything across turns: the
/// prompt loop compacts *its* list and hands back records, not the rewritten
/// list, so without this the next turn resends the elided span and pays for
/// the same summary again.
///
/// Each record's [`CompactionRecord::adopt`] does the work, applied in order,
/// each against the history the previous one produced. Upstream states the
/// rule this depends on — a compaction is a strict prefix elision, counted
/// from the first non-system message — as `elided_prefix_len`, so the
/// alignment is acton-ai's promise rather than Garrison's inference. When the
/// elided prefix reaches past everything the session owns (the loop's list
/// also held this turn's rounds, which the session never keeps), `adopt` drops
/// what there is and the history becomes the summary alone.
#[must_use]
fn adopt(history: Vec<Message>, compactions: &[CompactionRecord]) -> Vec<Message> {
    compactions
        .iter()
        .fold(history, |history, record| record.adopt(&history))
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

        // The gates decide whether this turn runs; `revoked` only ever
        // explains a cancellation, so a new turn starts without one.
        actor.model.revoked = None;

        let content = envelope.message().content.clone();
        let messages = actor.model.turn_messages(&content);
        let turn_id = TurnId::new();
        let cancel = CancellationToken::new();

        // Marked open here and written to the store by the turn's own task,
        // after admission: a refused turn must not leave a session looking
        // like it has work half-done in it.
        let opening = open_turn(&mut actor.model, &turn_id, &content);

        // Spawned rather than awaited: see the module docs on why neither kind
        // of handler can hold a turn.
        let task = tokio::spawn(run_turn(
            TurnJob {
                setup,
                turn_id: turn_id.clone(),
                content,
                cancel: cancel.clone(),
                messages,
                opening,
            },
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

    // Resuming is starting a turn that already has a name. Everything else
    // about it — the gate fold, the claim, the checkpoint sink — is the same
    // path a fresh turn takes, because the turn *is* the same turn: acton-ai
    // finds the record already written under this turn's checkpoint id and
    // picks up from the round it stopped at rather than re-dispatching the
    // ones it already paid for.
    builder.mutate_on::<ResumeTurn>(|actor, envelope| {
        let reply = envelope.reply_envelope();

        if let Some(running) = &actor.model.running {
            let admission = ResumeAdmission::Busy {
                turn_id: running.turn_id.clone(),
            };
            return Reply::pending(async move {
                reply.send(admission).await;
            });
        }

        let Some((setup, opening, turn_id, content)) = resumable(&actor.model) else {
            return Reply::pending(async move {
                reply.send(ResumeAdmission::Nothing).await;
            });
        };

        let messages = actor.model.turn_messages(&content);
        let cancel = CancellationToken::new();

        let task = tokio::spawn(run_turn(
            TurnJob {
                setup,
                turn_id: turn_id.clone(),
                content,
                cancel: cancel.clone(),
                messages,
                opening: Some(opening),
            },
            actor.new_envelope(),
        ));

        actor.model.running = Some(RunningTurn {
            turn_id: turn_id.clone(),
            cancel,
            task,
        });

        Reply::pending(async move {
            reply.send(ResumeAdmission::Resumed { turn_id }).await;
        })
    });

    builder.mutate_on::<AbandonTurn>(|actor, envelope| {
        let reply = envelope.reply_envelope();

        let Some(stored) = &mut actor.model.stored else {
            return Reply::pending(async move {
                reply.send(Abandoned { turn_id: None }).await;
            });
        };
        let Some(open) = stored.meta.open_turn.take() else {
            return Reply::pending(async move {
                reply.send(Abandoned { turn_id: None }).await;
            });
        };

        let meta = stored.meta.clone();
        let Some(setup) = actor.model.setup.clone() else {
            return Reply::pending(async move {
                reply.send(Abandoned { turn_id: None }).await;
            });
        };

        Reply::pending(async move {
            abandon(&setup, &meta, &open.turn_id).await;
            reply
                .send(Abandoned {
                    turn_id: Some(open.turn_id),
                })
                .await;
        })
    });

    builder.mutate_on::<NoteStored>(|actor, envelope| {
        let message = envelope.message();
        if let (Some(stored), Some(meta)) = (&mut actor.model.stored, message.meta.as_ref()) {
            stored.meta = meta.clone();
            stored.appended = message.appended;
        }
        Reply::ready()
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

        let compacted = matches!(
            &message.result,
            TurnResult::Completed { compactions, .. } if !compactions.is_empty()
        );
        // A turn cancelled because this install lost its seat is not a
        // cancellation from the client's point of view: nobody asked for it
        // to stop, and answering `stopReason: cancelled` would hide a
        // governance decision behind a word that means the operator changed
        // their mind. The refusal replaces it, with the same code and the
        // same words the next turn would be refused with.
        let mut message = message;
        if matches!(message.result, TurnResult::Cancelled) {
            if let Some(refusal) = actor.model.revoked.take() {
                message.result = TurnResult::Refused(refusal);
            }
        }

        if let TurnResult::Completed {
            text,
            compactions,
            usage,
            ..
        } = &message.result
        {
            actor.model.commit(&message.content, text, compactions);
            if let Some(stored) = &mut actor.model.stored {
                stored
                    .meta
                    .close_turn(usage.prompt_tokens, usage.completion_tokens);
            }
        } else if let Some(stored) = &mut actor.model.stored {
            // Cancelled, failed or refused: the turn is over either way, so
            // the record must stop naming it as in flight. What becomes of
            // its checkpoint is decided in `persist_turn`.
            //
            // Only if it is the turn the record names, though. A turn refused
            // *because* the session already holds an interrupted one must not
            // clear that one on its way out: the refusal would then unblock
            // the session it was protecting, and the second prompt would run.
            if names(&stored.meta, &message.turn_id) {
                stored.meta.open_turn = None;
            }
        }

        let Some(setup) = actor.model.setup.clone() else {
            return Reply::ready();
        };

        let job = PersistJob {
            stored: actor.model.stored.clone(),
            history: actor.model.history.clone(),
            unappended: actor.model.unappended(),
            compacted,
            turn_id: message.turn_id.clone(),
        };
        let self_envelope = actor.new_envelope();

        Reply::pending(async move {
            // Written before the client is told the turn finished, so a
            // client that immediately prompts again cannot race the history
            // it just produced into the store behind the next turn's.
            let noted = persist_turn(&setup, job, &message.result).await;
            if let Some(envelope) = self_envelope {
                envelope.send(noted).await;
            }

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

    // Losing entitlement ends the turn in flight. The seat monitor
    // broadcasts; every session hears it. A turn that was already going to be
    // refused on its next `AdmitTurn` must not be allowed to finish this one,
    // because the model is still being spent on an install the plane has
    // stopped entitling.
    builder.mutate_on::<EntitlementLost>(|actor, envelope| {
        let refusal = envelope.message().refusal.clone();
        let Some(running) = &actor.model.running else {
            return Reply::ready();
        };

        tracing::warn!(
            turn_id = %running.turn_id,
            %refusal,
            "ending a turn in flight: this install no longer holds an entitlement",
        );
        running.cancel.cancel();
        actor.model.revoked = Some(refusal);
        Reply::ready()
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
async fn run_turn(job: TurnJob, self_envelope: Option<OutboundEnvelope>) {
    let TurnJob {
        setup,
        turn_id,
        content,
        cancel,
        messages,
        opening,
    } = job;

    let result = drive_turn(&setup, &turn_id, cancel, messages, opening.as_ref()).await;

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

/// Everything one turn needs, gathered on the loop and carried off it.
///
/// A struct rather than six arguments because the resume path builds the same
/// job from a stored record, and two call sites passing positional arguments
/// in the same order is a bug waiting for someone to add a seventh.
struct TurnJob {
    /// The session's settled configuration.
    setup: ThreadSetup,
    /// The turn's identity, minted here or read back from the store.
    turn_id: TurnId,
    /// What the operator asked for.
    content: String,
    /// Cancelled by `session/cancel`.
    cancel: CancellationToken,
    /// The history this turn sends, prompt included.
    messages: Vec<Message>,
    /// The session's record with this turn marked open, when the session is
    /// stored. `None` on an install with no session store.
    opening: Option<SessionMeta>,
}

/// Discovers this turn's `AGENTS.md` project instructions, gated by whatever
/// governs this install. Returns the fragment to append to the system prompt
/// together with the fingerprints the turn's audit entry seals, or `None` when
/// discovery is disabled, found nothing, or failed.
///
/// # Fail-closed, and one deliberate exception
///
/// A policy actor that cannot be asked has not said "enabled", on the same
/// reasoning [`admission::admit`] already applies to every other gate: this
/// falls back to [`AgentsMdDiscovery::Disabled`] when `setup.policy` is
/// `Some` but the ask errors. The exception is `setup.policy` being `None`
/// outright — no governance subsystem participates in this stack at all, the
/// same stack shape that leaves every tool call to the local auto-approve
/// list — where discovery runs unrestricted rather than locking down alone
/// while nothing else here is gated.
///
/// A discovery error (an unreadable file, an unresolvable path) is logged and
/// swallowed rather than failing the turn: a turn that could not read
/// `AGENTS.md` should still run, the same way a turn missing its optional
/// system prompt still runs.
async fn discovered_agents_md(setup: &ThreadSetup) -> Option<crate::instructions::Discovered> {
    let policy = match &setup.policy {
        Some(handle) => match handle
            .ask(crate::policy::agent::CurrentAgentsMdPolicy)
            .await
        {
            Ok(policy) => policy,
            Err(error) => {
                tracing::warn!(
                    thread_id = %setup.thread_id,
                    %error,
                    "the AGENTS.md discovery policy could not be read; treating discovery as disabled",
                );
                crate::policy::agent::AgentsMdPolicy {
                    discovery: garrison_policy::AgentsMdDiscovery::Disabled,
                    allowed_paths: Vec::new(),
                }
            }
        },
        None => crate::policy::agent::AgentsMdPolicy {
            discovery: garrison_policy::AgentsMdDiscovery::Enabled,
            allowed_paths: Vec::new(),
        },
    };

    match crate::instructions::discover(
        setup.project_root.as_ref(),
        setup.project_root.as_ref(),
        policy.discovery,
        &policy.allowed_paths,
    ) {
        Ok(discovered) if discovered.is_empty() => None,
        Ok(discovered) => {
            for source in &discovered.layers {
                // Operational visibility, not the record: these same
                // fingerprints are sealed into the turn's audit entry, which
                // is what an auditor reads. This is here so an operator
                // tailing logs can see what steered a turn without opening
                // the trail.
                tracing::info!(
                    thread_id = %setup.thread_id,
                    scope = ?source.scope,
                    path = %source.path.display(),
                    content_hash = %source.content_hash,
                    "AGENTS.md instructions loaded for this turn",
                );
            }
            Some(discovered)
        }
        Err(error) => {
            tracing::warn!(
                thread_id = %setup.thread_id,
                %error,
                "AGENTS.md discovery failed; the turn runs without project instructions",
            );
            None
        }
    }
}

/// Seals a refusal the gates made, so a turn nobody ran still leaves a line.
///
/// Thin over [`crate::audit::seal_refusal`], which the completion path shares.
/// What belongs here rather than there is the prompt this turn would have sent:
/// the last thing the user said, measured in bytes and never copied.
async fn seal_refusal(
    setup: &ThreadSetup,
    turn_id: &TurnId,
    refusal: &TurnRefusal,
    messages: &[Message],
    opening: Option<&SessionMeta>,
) {
    let prompt_size_bytes = messages
        .iter()
        .rev()
        .find(|message| message.role == MessageRole::User)
        .map_or(0, |message| message.content.len() as u64);

    crate::audit::seal_refusal(
        &setup.runtime,
        &setup.thread_id,
        turn_id,
        refusal,
        opening.map(|meta| meta.conversation.clone()),
        prompt_size_bytes,
    )
    .await;
}

/// The turn itself, separated so `run_turn` is only about reporting.
async fn drive_turn(
    setup: &ThreadSetup,
    turn_id: &TurnId,
    cancel: CancellationToken,
    messages: Vec<Message>,
    opening: Option<&SessionMeta>,
) -> TurnResult {
    // Admission comes before the claim: a refused turn never touches the
    // router, so there is nothing to release. The gates are asked in order and
    // the first refusal ends it; a gate that cannot be asked refuses.
    let request = AdmitTurn {
        thread_id: setup.thread_id.clone(),
        turn_id: turn_id.clone(),
        work: Work::Turn,
    };
    if let Admission::Refuse(refusal) = admission::admit(&setup.gates, &request).await {
        seal_refusal(setup, turn_id, &refusal, &messages, opening).await;
        return TurnResult::Refused(refusal);
    }

    // Recorded after admission and before the claim: a refused turn leaves
    // no trace of work in flight, and a turn that reaches the provider has
    // already been written down as running. A store that will not take the
    // write refuses the turn rather than running work no restart could find.
    if let (Some(store), Some(meta)) = (setup.store.as_ref(), opening) {
        if let Err(error) = store.write_meta(&setup.thread_id, meta).await {
            tracing::error!(
                thread_id = %setup.thread_id,
                %error,
                "a turn could not be recorded as started",
            );
            return TurnResult::Refused(TurnRefusal::StoreUnavailable);
        }
    }

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
        policy: setup.policy.clone(),
    };

    let sink = setup.sink.clone();
    let thread_id = setup.thread_id.clone();
    let mut builder = setup.runtime.continue_with(messages).on_token(move |text| {
        sink.notify(
            acp::method::SESSION_UPDATE,
            &acp::agent_chunk(&thread_id, text),
        );
    });
    // `.system()` overwrites rather than appends, so the operator's own
    // prompt and the discovered `AGENTS.md` fragment are joined into one
    // call rather than two: a second call here would silently discard
    // whichever call ran first.
    let agents_md = discovered_agents_md(setup).await;
    let (fragment, context_sources) = match agents_md {
        Some(discovered) => (Some(discovered.context_fragment), discovered.layers),
        None => (None, Vec::new()),
    };
    let system = match (&setup.system_prompt, fragment) {
        (Some(configured), Some(fragment)) => Some(format!("{configured}\n\n{fragment}")),
        (Some(configured), None) => Some(configured.clone()),
        (None, Some(fragment)) => Some(fragment),
        (None, None) => None,
    };
    if let Some(system) = system {
        builder = builder.system(system);
    }
    // Seals which project instructions steered this turn into its own audit
    // entry: scope, path, and content hash, never the content. Set
    // unconditionally — an empty list is the honest record for a turn no
    // `AGENTS.md` reached, and acton-ai skips the field entirely when empty,
    // so a turn without instructions hashes over exactly the bytes it did
    // before this existed.
    builder = builder.context_sources(context_sources);
    // Named so the checkpoint carries the identity the client was told, and
    // pointed at the conversation the metadata names rather than the one the
    // store minted; compaction moves that pointer, and the record follows it.
    match checkpointed(builder, setup, turn_id, opening) {
        Ok(built) => builder = built,
        Err(reason) => return TurnResult::Failed { reason },
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
            plan: response.plan,
            compactions: response.compactions,
        },
        Some(Err(error)) => TurnResult::Failed {
            reason: error.to_string(),
        },
    }
}

/// The prompt builder, told where this turn is written down.
///
/// Three facts reach acton-ai here, and each is a fact Garrison already knows
/// under its own name:
///
/// - the **turn id** the client was told, so a checkpoint read back after a
///   restart can be matched to the turn ACP announced;
/// - the **conversation** [`SessionMeta`] points at, which is not always the
///   one the store minted: compaction rewrites a history into a fresh
///   conversation and moves the pointer;
/// - the **checkpoint** to write each round into, named by
///   [`checkpoint_id_for`] so the turn and its record share one identity.
///
/// `Err` carries the reason as prose, because the only thing that can fail
/// here is an identifier this daemon cannot translate, and that is a failure
/// of the turn rather than of the store.
fn checkpointed(
    mut builder: PromptBuilder,
    setup: &ThreadSetup,
    turn_id: &TurnId,
    opening: Option<&SessionMeta>,
) -> Result<PromptBuilder, String> {
    builder = builder.turn_id(acton_turn_id(turn_id).map_err(|error| error.to_string())?);

    if let Some(meta) = opening {
        builder = builder.conversation_id(meta.conversation.clone());
    }

    if let Some(store) = &setup.store {
        let checkpoint = checkpoint_id_for(turn_id).map_err(|error| error.to_string())?;
        builder = builder.checkpoint(store.handle().clone(), checkpoint);
    }

    Ok(builder)
}

/// Whether the record's open turn is this turn.
///
/// Pure. The distinction matters exactly once, and it is the one that keeps
/// fail-closed closed: see the `TurnOutcome` handler.
fn names(meta: &SessionMeta, turn_id: &TurnId) -> bool {
    meta.interrupted()
        .is_some_and(|open| &open.turn_id == turn_id)
}

/// Marks a turn open on the session's record and hands back a copy to write.
///
/// The copy is what the turn's own task writes to the store after admission,
/// so the record this actor holds and the record on disk say the same thing
/// about the same moment. `None` when the session is not stored.
fn open_turn(model: &mut Thread, turn_id: &TurnId, content: &str) -> Option<SessionMeta> {
    let stored = model.stored.as_mut()?;

    // A session that already names an open turn is a session the gate is
    // about to refuse. Recording this turn over the top of it would erase
    // exactly the turn the refusal is about, and the operator would lose the
    // choice between resuming and abandoning it without ever being offered
    // one. So nothing is written, and the refusal arrives with the record
    // intact.
    if stored.meta.interrupted().is_some() {
        return None;
    }

    stored.meta.open(
        turn_id.clone(),
        Utc::now().to_rfc3339(),
        content.to_string(),
    );
    Some(stored.meta.clone())
}

/// What a resume needs, when there is something to resume.
///
/// The stored record is the whole of the evidence: a session that names an
/// open turn is a session whose daemon did not survive to clear it. Note that
/// the prompt comes from the record rather than from the client, so a resume
/// replays the operator's original words even to a client that never saw them
/// land.
fn resumable(model: &Thread) -> Option<(ThreadSetup, SessionMeta, TurnId, String)> {
    let setup = model.setup.clone()?;
    let stored = model.stored.as_ref()?;
    let open = stored.meta.interrupted()?;

    Some((
        setup,
        stored.meta.clone(),
        open.turn_id.clone(),
        open.content.clone(),
    ))
}

/// Gives up on an interrupted turn, in the store and in its checkpoint.
///
/// Both halves are best effort and neither is retried: the operator has said
/// the work is not wanted, and the session must become promptable again even
/// if the checkpoint record cannot be reached. The metadata write is what the
/// gate reads, so it is the one that matters.
async fn abandon(setup: &ThreadSetup, meta: &SessionMeta, turn_id: &TurnId) {
    let Some(store) = &setup.store else {
        return;
    };

    if let Err(error) = store.write_meta(&setup.thread_id, meta).await {
        tracing::error!(
            thread_id = %setup.thread_id,
            %error,
            "an abandoned turn could not be cleared from the session record",
        );
    }

    let Ok(checkpoint) = checkpoint_id_for(turn_id) else {
        return;
    };
    match store.checkpoint(&checkpoint).await {
        Ok(Some(record)) => {
            if let Err(error) = store.abandon_checkpoint(record).await {
                tracing::warn!(%error, "an abandoned turn's checkpoint was left in place");
            }
        }
        Ok(None) => {}
        Err(error) => tracing::warn!(%error, "an abandoned turn's checkpoint could not be read"),
    }
}

/// What the store is told about a turn that has ended.
///
/// Built on the loop so it is a snapshot of one consistent moment, then
/// carried into the pending future that does the writing.
struct PersistJob {
    /// The session's record, already folded to account for the turn.
    stored: Option<Stored>,
    /// The session's whole history as this actor now holds it.
    history: Vec<Message>,
    /// The tail of that history the store has not been told about.
    unappended: Vec<Message>,
    /// Whether the turn compacted, which decides append against rewrite.
    compacted: bool,
    /// The turn that ended, for its checkpoint.
    turn_id: TurnId,
}

/// Writes a finished turn down, and says what the record now holds.
///
/// The two shapes of write are not interchangeable. Ordinarily the new
/// messages are appended, because a conversation is append-only and appending
/// is cheap. A turn that compacted has *rewritten* its history, a prefix of
/// messages having become one summary, and an append-only conversation cannot
/// express that, so the whole adopted history is written into a fresh
/// conversation and the record is re-pointed at it. Losing that distinction
/// would mean a restart replaying a history the model had already compacted
/// away, and paying for it again.
///
/// Nothing here raises: the turn has already happened and the client is about
/// to be told so. A failed write leaves the appended count where it was, so
/// the next turn writes the messages this one could not.
async fn persist_turn(setup: &ThreadSetup, job: PersistJob, result: &TurnResult) -> NoteStored {
    let (Some(store), Some(stored)) = (setup.store.as_ref(), job.stored) else {
        return NoteStored {
            meta: None,
            appended: 0,
        };
    };

    let mut meta = stored.meta;
    let mut appended = stored.appended;

    let written = if job.compacted {
        store
            .rewrite(&setup.thread_id, &meta, &job.history)
            .await
            .map(|conversation| {
                meta.conversation = conversation;
                job.history.len()
            })
    } else {
        match store.append(&meta.conversation, &job.unappended).await {
            Ok(()) => store
                .write_meta(&setup.thread_id, &meta)
                .await
                .map(|()| job.history.len()),
            Err(error) => Err(error),
        }
    };

    match written {
        Ok(count) => appended = count,
        Err(error) => tracing::error!(
            thread_id = %setup.thread_id,
            %error,
            "a finished turn could not be written to the session store",
        ),
    }

    settle_checkpoint(store, &job.turn_id, result).await;

    if let Err(error) = store.touch(&setup.thread_id).await {
        tracing::debug!(%error, "a session's last-active time was not updated");
    }

    NoteStored {
        meta: Some(meta),
        appended,
    }
}

/// Disposes of the turn's checkpoint according to how the turn ended.
///
/// A completed turn's checkpoint has served its purpose: its work is in the
/// history now, and keeping it would offer a resume of a turn that is already
/// done. A cancelled turn's is abandoned, which is the operator's decision
/// recorded. A failed or refused turn's is left exactly where it is, because
/// that is the one a resume would want.
async fn settle_checkpoint(store: &SessionStore, turn_id: &TurnId, result: &TurnResult) {
    let Ok(checkpoint) = checkpoint_id_for(turn_id) else {
        return;
    };

    match result {
        TurnResult::Completed { .. } => {
            if let Err(error) = store.delete_checkpoint(&checkpoint).await {
                tracing::debug!(%error, "a finished turn's checkpoint was left in place");
            }
        }
        TurnResult::Cancelled => match store.checkpoint(&checkpoint).await {
            Ok(Some(record)) => {
                if let Err(error) = store.abandon_checkpoint(record).await {
                    tracing::debug!(%error, "a cancelled turn's checkpoint was left in place");
                }
            }
            Ok(None) => {}
            Err(error) => tracing::debug!(%error, "a cancelled turn's checkpoint was not read"),
        },
        TurnResult::Failed { .. } | TurnResult::Refused(_) => {}
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
    /// The session's stored record, when it was read back from the store.
    ///
    /// `None` for a session that is not stored at all. A session being loaded
    /// after a restart carries the record that says what it was doing.
    pub meta: Option<SessionMeta>,
    /// How many of `history` the store already holds.
    ///
    /// The length of the restored history on a load, zero on a create. It is
    /// what keeps a hydrated session from writing its whole past back into the
    /// store the first time it finishes a turn.
    pub appended: usize,
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

    // The supervisor's contribution to `_garrison/status`: how many sessions
    // the daemon holds in all, which no single connection can see.
    builder.mutate_on::<Describe>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let part = StatusPart::Threads(acp::ThreadsStatus {
            live: actor.model.threads.len(),
        });
        Reply::pending(async move {
            reply.send(part).await;
        })
    });
}

/// Spawns one session actor with its history restored.
async fn spawn_thread(runtime: &mut ActorRuntime, message: CreateThread) -> ActorHandle {
    let name = format!("session_{}", message.setup.thread_id);
    let mut builder = runtime.new_actor_with_name::<Thread>(name);

    builder.model.setup = Some(message.setup);
    builder.model.history = message.history;
    builder.model = std::mem::take(&mut builder.model).with_stored(message.meta, message.appended);
    configure_handlers(&mut builder);

    // Before `start`, because a subscription registered afterwards is
    // silently ignored — which would leave a session that runs happily and
    // never hears that its seat was taken away.
    builder.handle().subscribe::<EntitlementLost>().await;

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

    /// A record that says the summary replaced `elided` leading messages.
    ///
    /// The outcome's counts are the loop's, over its own longer list; the
    /// prefix length is the one that lands on the session's copy, which is why
    /// the two are deliberately different numbers here.
    fn record(summary: &str, elided: usize) -> CompactionRecord {
        CompactionRecord {
            summary: summary.to_string(),
            outcome: acton_ai::memory::CompactionOutcome {
                messages_before: elided + 4,
                messages_after: 5,
                tokens_before: 900,
                tokens_after: 300,
                messages_elided: elided,
            },
            elided_prefix_len: elided,
        }
    }

    /// A history of `count` alternating user and assistant messages.
    fn conversation(count: usize) -> Vec<Message> {
        (0..count)
            .map(|index| {
                if index % 2 == 0 {
                    Message::user(format!("q{index}"))
                } else {
                    Message::assistant(format!("a{index}"))
                }
            })
            .collect()
    }

    #[test]
    fn committing_appends_the_exchange() {
        let mut thread = Thread::default();

        thread.commit("question", "answer", &[]);

        assert_eq!(
            thread.history,
            vec![Message::user("question"), Message::assistant("answer")]
        );
    }

    #[test]
    fn adopting_no_compactions_leaves_the_history_alone() {
        let history = conversation(4);

        assert_eq!(adopt(history.clone(), &[]), history);
    }

    #[test]
    fn adopting_replaces_the_elided_prefix_with_the_summary() {
        let history = conversation(6);

        let adopted = adopt(history.clone(), &[record("what came before", 4)]);

        assert_eq!(adopted.len(), 3, "four messages became one summary");
        assert!(adopted[0].content.starts_with(COMPACTION_NOTICE));
        assert!(adopted[0].content.contains("what came before"));
        assert_eq!(adopted[1..], history[4..]);
    }

    #[test]
    fn an_elided_prefix_past_the_sessions_own_messages_leaves_the_summary_alone() {
        // The loop's list also held this turn's rounds, which the session
        // never keeps, so a record can name more messages than there are.
        let history = conversation(3);

        let adopted = adopt(history, &[record("everything so far", 9)]);

        assert_eq!(adopted.len(), 1);
        assert!(adopted[0].content.starts_with(COMPACTION_NOTICE));
    }

    #[test]
    fn two_compactions_of_one_turn_apply_in_sequence() {
        let history = conversation(8);

        let adopted = adopt(
            history,
            &[record("first pass", 4), record("second pass", 2)],
        );

        // The first pass left 1 summary + 4 messages; the second elided the
        // summary and the message after it, leaving 1 summary + 3.
        assert_eq!(adopted.len(), 4);
        assert!(adopted[0].content.contains("second pass"));
        assert!(
            !adopted.iter().any(|m| m.content.contains("first pass")),
            "the second summary stands for the first"
        );
    }

    #[test]
    fn committing_with_a_compaction_keeps_the_summary_then_the_answer() {
        let mut thread = Thread::default().with_history(conversation(4));

        thread.commit("question", "answer", &[record("the earlier work", 3)]);

        assert_eq!(thread.history.len(), 4);
        assert!(thread.history[0].content.starts_with(COMPACTION_NOTICE));
        assert_eq!(thread.history[2], Message::user("question"));
        assert_eq!(thread.history[3], Message::assistant("answer"));
    }

    #[test]
    fn committing_a_compaction_that_swallowed_the_prompt_still_records_the_answer() {
        let mut thread = Thread::default().with_history(conversation(2));

        thread.commit("question", "answer", &[record("all of it", 3)]);

        assert_eq!(thread.history.len(), 2);
        assert!(thread.history[0].content.starts_with(COMPACTION_NOTICE));
        assert_eq!(thread.history[1], Message::assistant("answer"));
    }

    #[test]
    fn a_compaction_summary_is_told_apart_from_what_the_operator_said() {
        assert!(is_compaction_summary(&acton_ai::memory::summary_message(
            "earlier"
        )));
        assert!(!is_compaction_summary(&Message::user("earlier")));
        assert!(!is_compaction_summary(&Message::assistant(
            COMPACTION_NOTICE
        )));
    }

    #[test]
    fn a_replay_shows_a_compaction_summary_as_an_agent_thought() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sink = EventSink::new(tx);
        let history = vec![
            acton_ai::memory::summary_message("what came before"),
            Message::user("and then?"),
        ];

        replay(&ThreadId::new(), &history, &sink);
        drop(sink);

        let lines: Vec<String> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(lines.len(), 2, "{lines:?}");

        let first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(
            first["params"]["update"]["sessionUpdate"], "agent_thought_chunk",
            "the framework's summary is not something the operator said"
        );

        let second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(
            second["params"]["update"]["sessionUpdate"],
            "user_message_chunk"
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
