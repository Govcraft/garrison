//! One actor per connected ACP client.
//!
//! A `ClientConn` owns everything about one socket: the negotiated protocol
//! version, which sessions that client opened, the `session/prompt` requests
//! held open while their turns run, and the permission requests suspended
//! waiting for an answer. All of it is one actor's model, so none of it is
//! behind a lock.
//!
//! # Two kinds of waiting, both free
//!
//! ACP asks an agent to hold two things open at once, and both are handled the
//! same way: by keeping a reply envelope and returning.
//!
//! **`session/prompt` is answered when the turn ends**, which may be minutes
//! later. The connection parks the JSON-RPC request id against the session and
//! answers it from [`TurnFinished`]. Nothing awaits the turn.
//!
//! **`session/request_permission` is a request the *agent* sends.** When the
//! policy gate defers, [`RequestApproval`] arrives here as an ordinary `ask`
//! that this handler does not answer: it stores the reply envelope, writes the
//! request to the client, arms a timer, and returns. The asking task — the
//! turn's own task, deep inside `collect()` — stays parked. Nothing else in
//! the process waits: not this actor's mailbox, not the other sessions, not the
//! runtime.
//!
//! Three things resolve a suspended permission, all through the same envelope:
//!
//! - the client answers, and the verdict is sent;
//! - the timer fires, and a denial reading "approval timed out" is sent;
//! - **this actor stops**, dropping the envelope, which resolves the parked
//!   `ask` as `NoReply` in microseconds. That is why a client vanishing mid-turn
//!   cannot wedge a session: the hook is released by the disconnection itself,
//!   not by a timeout that outlives it.
//!
//! # Why dispatch is spawned
//!
//! Every method but the handshake ends in an `ask` to another actor. Awaiting
//! that on the message loop would mean a connection could not receive a
//! permission answer while it was waiting for a session to admit a turn. So the
//! frame handler reads what it needs off the model, spawns the dispatch, and
//! returns; every state change the dispatch needs travels back as a self-sent
//! message.
//!
//! Spawned rather than returned from `act_on`, because acton-reactive drains
//! read-only handler futures to completion at its flush points — a handler
//! future that waits is a message loop that waits.
//!
//! # The "always allow" cache is per connection
//!
//! ACP's `allow_always` is remembered against the session, on this actor, and
//! dies with the connection. A client that reconnects is asked again. That is
//! deliberate: a remembered approval is a governance decision with no record,
//! and the shortest safe life for one is the session the operator was looking
//! at when they made it.

use crate::admission::refusal_code;
use crate::approval::{ApprovalOutcome, RequestApproval, CANCELLED_REASON, REJECTED_REASON};
use crate::protocol::acp::{self, Permission};
use crate::protocol::codec::EventSink;
use crate::protocol::jsonrpc::{encode, error_code, params, ErrorObject, Inbound, RequestId};
use crate::session;
use crate::thread::{
    AbandonTurn, CreateThread, DescribeThread, FindThread, InterruptTurn, ListThreads, Reattach,
    ResumeAdmission, ResumeTurn, StartTurn, ThreadList, ThreadLookup, ThreadSetup, TurnAdmission,
    TurnFinished, TurnResult,
};
use crate::types::{ClientId, ThreadId};
use acton_ai::checkpoint::CheckpointStatus;
use acton_ai::facade::ActonAI;
use acton_reactive::prelude::*;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The server-wide settings a new session inherits.
#[derive(Clone, Debug)]
pub struct ThreadDefaults {
    /// The root a session is confined to unless the client names another.
    pub project_root: PathBuf,
    /// Every directory a client may root a session at, canonicalized.
    ///
    /// Includes `project_root`. A `session/new` naming anything outside these
    /// is refused rather than honoured.
    pub approved_roots: Arc<Vec<PathBuf>>,
    /// The system prompt a session uses unless the server was configured
    /// otherwise.
    pub system_prompt: Option<String>,
    /// How long a client has to answer a permission request before it is
    /// denied.
    pub approval_timeout: Duration,
    /// Tool-name patterns that skip the permission round-trip.
    pub auto_approve: Arc<Vec<String>>,
    /// The language servers every session's tools reach.
    pub lsp: Arc<crate::lsp::LspRegistry>,
    /// The gates every session's turns must pass, in order.
    ///
    /// See [`crate::admission`]. Empty means every turn is admitted.
    pub gates: Vec<ActorHandle>,
    /// Where sessions are written so they survive a restart.
    ///
    /// `None` on an install that arms no session store, which is the
    /// standalone developer install: its sessions live in their actors and die
    /// with the process, exactly as they did before persistence existed.
    pub store: Option<session::SessionStore>,
    /// Who every session this daemon opens belongs to.
    ///
    /// Settled once at launch and stamped onto each stored session, so a row
    /// shipped to the fleet view later carries its tenant chain rather than
    /// landing unattributed and invisible.
    pub attribution: session::Attribution,
}

impl Default for ThreadDefaults {
    fn default() -> Self {
        Self {
            project_root: PathBuf::from("."),
            approved_roots: Arc::new(Vec::new()),
            system_prompt: None,
            approval_timeout: Duration::from_secs(300),
            auto_approve: Arc::new(Vec::new()),
            lsp: Arc::new(crate::lsp::LspRegistry::default()),
            gates: Vec::new(),
            store: None,
            attribution: session::Attribution::default(),
        }
    }
}

/// Everything a connection needs that is fixed for its whole life.
#[derive(Clone, Debug)]
pub struct ConnSetup {
    /// The identity assigned to this connection.
    pub client_id: ClientId,
    /// Where its events go.
    pub sink: EventSink,
    /// The session supervisor.
    pub supervisor: ActorHandle,
    /// The acton-ai runtime sessions run their turns on.
    pub runtime: ActonAI,
    /// The turn router.
    pub router: ActorHandle,
    /// What new sessions inherit.
    pub defaults: ThreadDefaults,
    /// What this agent advertises at `initialize`.
    pub capabilities: acp::AgentCapabilities,
    /// Whether the runtime is recording tool calls, for `_garrison/status`.
    pub audited: bool,
    /// What isolation the runtime's writing tools run under, for the same.
    pub sandbox: acp::SandboxStatus,
    /// Every actor that contributes a part to `_garrison/status`, asked in
    /// order. See [`Describe`].
    pub describers: Vec<ActorHandle>,
    /// The daemon's credential holder, on a governed install.
    ///
    /// A subsystem that needs the control plane asks this handle for an
    /// authenticated client and never builds one; see [`crate::plane`].
    pub plane: Option<ActorHandle>,
}

/// Asks a subsystem to describe itself for `_garrison/status`.
///
/// One request, answered by every actor that has something to report: the
/// session supervisor, and later the plane session, the policy agent, the
/// seat monitor, the audit shipper. Each answers with the [`StatusPart`] it
/// owns and [`assemble`] places it; a subsystem that joins the status adds one
/// variant here, one field on [`acp::GarrisonStatus`], and one handler on its
/// own actor, and never edits [`status`].
#[acton_message]
pub struct Describe;

/// One subsystem's contribution to the status.
///
/// Non-exhaustive: every subsystem that joins the status adds a variant.
#[acton_message]
#[non_exhaustive]
pub enum StatusPart {
    /// From the session supervisor.
    Threads(acp::ThreadsStatus),
    /// From the plane session, when this daemon is governed.
    Plane(acp::PlaneStatus),
    /// From the turn router, which sees every compaction.
    Context(acp::ContextStatus),
    /// From the seat monitor: whether a seat entitles this install to run at
    /// all, and how long the last answer may outlive the plane.
    Entitlement(acp::EntitlementStatus),
    /// From the audit anchor keeper: the writer's health, what the trail
    /// promises, and where the head is anchored.
    ///
    /// Boxed because it is by far the widest part, and every `StatusPart` in
    /// flight — one per describer, on every status request — would otherwise
    /// be sized for it.
    Audit(Box<acp::AuditStatus>),
    /// From the session keeper: whether sessions survive a restart, and how
    /// many of them are waiting on a decision about an interrupted turn.
    SessionStore(acp::SessionStoreStatus),
}

impl Request for Describe {
    type Response = StatusPart;
}

/// A frame the reader task pulled off the socket.
#[acton_message]
pub struct Incoming {
    /// The classified frame.
    pub frame: Inbound,
}

/// Records a completed handshake and the version it settled on.
#[acton_message]
struct MarkInitialized {
    version: acp::ProtocolVersion,
}

/// Records that this client owns a session.
#[acton_message]
struct OwnSession {
    thread_id: ThreadId,
}

/// Holds a `session/prompt` open until its turn ends.
#[acton_message]
struct ParkPrompt {
    thread_id: ThreadId,
    id: RequestId,
}

/// Releases a parked `session/prompt` without answering it from a turn.
///
/// Used when the turn was never admitted, so the dispatch answers directly.
#[acton_message]
struct UnparkPrompt {
    thread_id: ThreadId,
}

/// Fires when a client has taken too long to answer a permission request.
#[acton_message]
struct ApprovalExpired {
    id: RequestId,
}

/// A permission request written to the client and not yet answered.
#[derive(Debug)]
struct Suspended {
    reply: OutboundEnvelope,
    thread_id: ThreadId,
    tool_name: String,
}

/// One connected client.
#[acton_actor]
pub struct ClientConn {
    setup: Option<ConnSetup>,
    version: Option<acp::ProtocolVersion>,
    sessions: BTreeSet<ThreadId>,
    /// `session/prompt` requests held open, one per session at most.
    prompts: HashMap<ThreadId, RequestId>,
    /// Permission requests written to the client and awaiting an answer.
    pending: HashMap<RequestId, Suspended>,
    timers: HashMap<RequestId, ScheduledSend>,
    /// Tools the client said "always allow" for, per session.
    always: HashMap<ThreadId, BTreeSet<String>>,
    /// The counter behind agent-initiated request ids.
    next_request: i64,
}

impl ClientConn {
    /// Spawns a connection actor.
    ///
    /// Deliberately a plain top-level actor and not a supervised child. Restart
    /// semantics are meaningless for a connection — the file descriptor is gone
    /// — and acton-reactive's supervision registry keeps a slot per child for
    /// the life of the process, which for a server accepting connections
    /// indefinitely is an unbounded leak.
    pub async fn spawn(runtime: &mut ActorRuntime, setup: ConnSetup) -> ActorHandle {
        let name = format!("conn_{}", setup.client_id);
        let mut builder = runtime.new_actor_with_name::<Self>(name);

        builder.model.setup = Some(setup);
        configure_handlers(&mut builder);

        builder.start().await
    }

    /// Mints the next identifier for a request this agent sends.
    ///
    /// Numeric and monotonic within a connection, which is all JSON-RPC asks:
    /// the client only has to echo it back.
    fn mint_request_id(&mut self) -> RequestId {
        self.next_request = self.next_request.wrapping_add(1);
        RequestId::Number(self.next_request)
    }

    /// Whether this session has already been told to stop asking about a tool.
    fn is_always_allowed(&self, thread_id: &ThreadId, tool_name: &str) -> bool {
        self.always
            .get(thread_id)
            .is_some_and(|tools| tools.contains(tool_name))
    }
}

/// Wires the connection's handlers.
fn configure_handlers(builder: &mut ManagedActor<Idle, ClientConn>) {
    builder.mutate_on::<Incoming>(|actor, envelope| {
        let Some(setup) = actor.model.setup.clone() else {
            return Reply::ready();
        };

        match envelope.message().frame.clone() {
            // An answer to something this agent asked. Resolved on the loop,
            // because it is a state change and nothing about it can block.
            Inbound::Response { id, outcome } => {
                return resolve_answer(actor, &id, outcome);
            }
            Inbound::Request { id, method, params } => {
                // `session/prompt` is parked here, on the message loop, before
                // the turn is even asked for. Parking inside the dispatch would
                // race the turn: a turn that finished before its id was stored
                // would find nothing to answer, and the client would wait
                // forever on a prompt that had already completed.
                // A resume is parked exactly as a prompt is, because it is
                // answered exactly as a prompt is: by the turn it starts.
                let parked = if method == acp::method::SESSION_PROMPT
                    || method == acp::ext::SESSION_RESUME
                {
                    match park_prompt(actor, &id, params.as_ref()) {
                        Parked::Busy => {
                            setup.sink.fail(Some(id), busy_error());
                            return Reply::ready();
                        }
                        Parked::Held(thread_id) => Some(thread_id),
                        Parked::Unparseable => None,
                    }
                } else {
                    None
                };

                let context = context_for(actor, setup);
                tokio::spawn(async move {
                    match handle(&context, &method, params).await {
                        Ok(Answer::Result(result)) => {
                            context.setup.sink.respond(id, &result);
                        }
                        // The method took ownership of the id: `session/prompt`
                        // answers it when its turn ends.
                        Ok(Answer::Deferred) => {}
                        Err(error) => {
                            // A prompt that never started a turn has nothing
                            // left to answer it, so its parking must be undone
                            // or the session can never be prompted again.
                            if let Some(thread_id) = parked {
                                context.notify_self(UnparkPrompt { thread_id }).await;
                            }
                            context.setup.sink.fail(Some(id), error);
                        }
                    }
                });
            }
            Inbound::Notification { method, params } => {
                let context = context_for(actor, setup);
                tokio::spawn(async move {
                    notify(&context, &method, params).await;
                });
            }
        }

        Reply::ready()
    });

    builder.mutate_on::<MarkInitialized>(|actor, envelope| {
        actor.model.version = Some(envelope.message().version);
        Reply::ready()
    });

    builder.mutate_on::<OwnSession>(|actor, envelope| {
        actor
            .model
            .sessions
            .insert(envelope.message().thread_id.clone());
        Reply::ready()
    });

    builder.mutate_on::<ParkPrompt>(|actor, envelope| {
        let message = envelope.message();
        actor
            .model
            .prompts
            .insert(message.thread_id.clone(), message.id.clone());
        Reply::ready()
    });

    builder.mutate_on::<UnparkPrompt>(|actor, envelope| {
        actor.model.prompts.remove(&envelope.message().thread_id);
        Reply::ready()
    });

    builder.mutate_on::<TurnFinished>(|actor, envelope| {
        let message = envelope.message().clone();
        let Some(id) = actor.model.prompts.remove(&message.thread_id) else {
            // No parked prompt: the client disconnected, or the turn was
            // started by a client that has since handed the session over.
            return Reply::ready();
        };
        let Some(setup) = actor.model.setup.clone() else {
            return Reply::ready();
        };

        answer_prompt(&setup.sink, id, &message);
        Reply::ready()
    });

    // The suspension itself. Note what this handler does *not* do: answer.
    builder.mutate_on::<RequestApproval>(|actor, envelope| {
        let request = envelope.message().clone();
        let reply = envelope.reply_envelope();

        if actor
            .model
            .is_always_allowed(&request.thread_id, &request.tool_name)
        {
            return Reply::pending(async move {
                reply.send(ApprovalOutcome::Allowed).await;
            });
        }

        let Some(setup) = actor.model.setup.clone() else {
            return Reply::ready();
        };

        let id = actor.model.mint_request_id();
        actor.model.pending.insert(
            id.clone(),
            Suspended {
                reply,
                thread_id: request.thread_id.clone(),
                tool_name: request.tool_name.clone(),
            },
        );

        let timer = actor
            .handle()
            .send_after(ApprovalExpired { id: id.clone() }, request.timeout);
        actor.model.timers.insert(id.clone(), timer);

        setup.sink.request(
            id,
            acp::method::SESSION_REQUEST_PERMISSION,
            &permission_request(&request),
        );

        Reply::ready()
    });

    builder.mutate_on::<ApprovalExpired>(|actor, envelope| {
        let id = envelope.message().id.clone();
        let Some(suspended) = take_pending(actor, &id) else {
            return Reply::ready();
        };

        tracing::info!(tool = %suspended.tool_name, "approval timed out; denying");
        Reply::pending(async move {
            suspended
                .reply
                .send(ApprovalOutcome::Denied {
                    reason: crate::approval::TIMEOUT_REASON.to_string(),
                })
                .await;
        })
    });
}

/// What a message handler returns.
///
/// Spelled out because acton-reactive's `Reply` helpers are a namespace rather
/// than a type, so a function that produces a handler's return value has to
/// name the boxed future itself.
type Handled = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync + 'static>>;

/// What parking a `session/prompt` did.
enum Parked {
    /// The id is held against this session and a turn may be started.
    Held(ThreadId),
    /// This connection already has a prompt open on that session.
    Busy,
    /// The parameters did not name a session Garrison minted; the dispatch will
    /// produce the proper error.
    Unparseable,
}

/// Holds a `session/prompt`'s request id against its session.
///
/// Reads the session out of the raw parameters rather than deserializing the
/// whole request, because this runs on the message loop and the only field it
/// needs is the one that decides where the answer goes.
fn park_prompt(
    actor: &mut ManagedActor<Started, ClientConn>,
    id: &RequestId,
    raw: Option<&Value>,
) -> Parked {
    let Some(thread_id) = raw
        .and_then(|value| value.get("sessionId"))
        .and_then(Value::as_str)
        .and_then(|text| ThreadId::parse(text).ok())
    else {
        return Parked::Unparseable;
    };

    if actor.model.prompts.contains_key(&thread_id) {
        return Parked::Busy;
    }

    actor.model.prompts.insert(thread_id.clone(), id.clone());
    Parked::Held(thread_id)
}

/// The error for a session that is already running a turn.
fn busy_error() -> ErrorObject {
    ErrorObject::new(
        error_code::SESSION_BUSY,
        "this session is already running a turn",
    )
}

/// Applies a client's answer to the permission request it names.
fn resolve_answer(
    actor: &mut ManagedActor<Started, ClientConn>,
    id: &RequestId,
    outcome: Result<Value, ErrorObject>,
) -> Handled {
    let Some(suspended) = take_pending(actor, id) else {
        tracing::debug!(%id, "ignoring an answer to a request we are not waiting on");
        return Box::pin(async {});
    };

    let permission = read_permission(outcome);

    if permission == Some(Permission::AllowAlways) {
        actor
            .model
            .always
            .entry(suspended.thread_id.clone())
            .or_default()
            .insert(suspended.tool_name.clone());
    }

    let answer = match permission {
        Some(Permission::AllowOnce | Permission::AllowAlways) => ApprovalOutcome::Allowed,
        Some(Permission::Reject) => ApprovalOutcome::Denied {
            reason: REJECTED_REASON.to_string(),
        },
        None => ApprovalOutcome::Denied {
            reason: CANCELLED_REASON.to_string(),
        },
    };

    Box::pin(async move {
        suspended.reply.send(answer).await;
    })
}

/// Reads a permission out of whatever the client sent back.
///
/// Pure. Anything unreadable — a JSON-RPC error, a body that is not a
/// `RequestPermissionResponse`, an option Garrison never offered — is `None`,
/// and `None` is not consent.
fn read_permission(outcome: Result<Value, ErrorObject>) -> Option<Permission> {
    let value = match outcome {
        Ok(value) => value,
        Err(error) => {
            tracing::debug!(?error, "client refused a permission request with an error");
            return None;
        }
    };

    match serde_json::from_value::<acp::RequestPermissionResponse>(value) {
        Ok(response) => acp::permission_for(&response.outcome),
        Err(error) => {
            tracing::warn!(%error, "client sent an unreadable permission answer");
            None
        }
    }
}

/// Builds the ACP permission request for one deferred tool call.
///
/// The tool-call id is minted here rather than carried from the invocation:
/// acton-ai's `ToolInvocation` does not include one, although the prompt loop
/// built it from a `ToolCall` that did. Listed as an upstream gap; until it
/// closes, a permission request and the later tool-call events use different
/// identifiers and a client shows two entries for one call.
fn permission_request(request: &RequestApproval) -> acp::RequestPermissionRequest {
    let tool_call_id = format!("approval-{}", request.approval_id);
    let fields = acp::ToolCallUpdateFields::new()
        .title(request.tool_name.clone())
        .kind(acp::tool_kind_for(&request.tool_name))
        .status(acp::ToolCallStatus::Pending)
        .raw_input(request.arguments.clone());

    acp::RequestPermissionRequest::new(
        acp::session_id(&request.thread_id),
        acp::ToolCallUpdate::new(tool_call_id, fields),
        acp::permission_options(),
    )
}

/// Answers a parked `session/prompt` with however its turn ended.
fn answer_prompt(sink: &EventSink, id: RequestId, finished: &TurnFinished) {
    match &finished.result {
        TurnResult::Completed {
            stop_reason,
            usage,
            plan,
            compactions,
            ..
        } => {
            let mut response = acp::PromptResponse::new(*stop_reason);
            // Token counts ride in `_meta`: they are not part of stable ACP,
            // and inventing a core field for them would make Garrison's frames
            // unreadable to a conformant client. The final plan rides there
            // too, and is the authoritative one: the streamed plan updates
            // come from the router, so the last of them can arrive after this
            // response.
            let meta = turn_meta(
                &finished.turn_id.to_string(),
                usage,
                plan.as_ref(),
                compactions,
            );
            response.meta = Some(meta);
            sink.respond(id, &response);
        }
        TurnResult::Cancelled => {
            sink.respond(id, &acp::PromptResponse::new(acp::StopReason::Cancelled));
        }
        // The code names which gate said no; the data says why in words.
        TurnResult::Refused(refusal) => {
            sink.fail(
                Some(id),
                ErrorObject::new(refusal_code(refusal), "the turn was not admitted")
                    .data(Value::String(refusal.to_string())),
            );
        }
        TurnResult::Failed { reason } => {
            sink.fail(
                Some(id),
                ErrorObject::new(error_code::TURN_FAILED, "the turn failed")
                    .data(Value::String(reason.clone())),
            );
        }
    }
}

/// Wraps what a turn ended up costing, planning, and forgetting in the one
/// `_meta` key Garrison claims.
///
/// Pure, so the shape a client reads at the end of a turn is testable without
/// a socket.
fn turn_meta(
    turn_id: &str,
    usage: &crate::thread::TurnUsage,
    plan: Option<&acton_ai::tools::plan::Plan>,
    compactions: &[acton_ai::memory::CompactionRecord],
) -> acp::Meta {
    acp::garrison_meta(&acp::TurnMeta {
        turn_id: turn_id.to_string(),
        prompt_tokens: usage.prompt_tokens,
        completion_tokens: usage.completion_tokens,
        plan: plan.map(acp::plan_summary),
        compactions: compactions.iter().map(acp::compaction_summary).collect(),
    })
}

/// Removes a suspended permission request and cancels its timer.
fn take_pending(
    actor: &mut ManagedActor<Started, ClientConn>,
    id: &RequestId,
) -> Option<Suspended> {
    if let Some(timer) = actor.model.timers.remove(id) {
        timer.cancel();
    }
    actor.model.pending.remove(id)
}

/// Snapshots what a dispatch needs out of the actor.
fn context_for(actor: &ManagedActor<Started, ClientConn>, setup: ConnSetup) -> Dispatch {
    Dispatch {
        setup,
        version: actor.model.version,
        sessions: actor.model.sessions.clone(),
        conn: actor.handle().clone(),
        self_envelope: actor.new_envelope(),
    }
}

/// Everything the dispatcher needs, cloned out of the actor.
struct Dispatch {
    setup: ConnSetup,
    version: Option<acp::ProtocolVersion>,
    sessions: BTreeSet<ThreadId>,
    conn: ActorHandle,
    self_envelope: Option<OutboundEnvelope>,
}

impl Dispatch {
    /// Sends a message to this connection's own actor.
    async fn notify_self(&self, message: impl ActonMessage + 'static) {
        if let Some(envelope) = &self.self_envelope {
            envelope.send(message).await;
        }
    }

    /// Looks a session up, refusing sessions this client does not hold.
    ///
    /// Ownership is checked before the supervisor is consulted, so one client
    /// cannot discover another's sessions by probing identifiers.
    async fn find(&self, thread_id: &ThreadId) -> Result<ActorHandle, ErrorObject> {
        if !self.sessions.contains(thread_id) {
            return Err(acp::unknown_session(&acp::session_id(thread_id)));
        }
        match self
            .setup
            .supervisor
            .ask(FindThread {
                thread_id: thread_id.clone(),
            })
            .await
        {
            Ok(ThreadLookup {
                handle: Some(handle),
            }) => Ok(handle),
            Ok(ThreadLookup { handle: None }) => {
                Err(acp::unknown_session(&acp::session_id(thread_id)))
            }
            Err(error) => Err(internal(&format!("session lookup failed: {error}"))),
        }
    }
}

/// What a method produced.
enum Answer {
    /// Answer the request with this.
    Result(Value),
    /// The method kept the request id and will answer later.
    Deferred,
}

/// Reports a fault on the agent's side.
fn internal(reason: &str) -> ErrorObject {
    ErrorObject::internal_error().data(Value::String(reason.to_string()))
}

/// Routes one request to its method.
async fn handle(
    context: &Dispatch,
    method: &str,
    raw: Option<Value>,
) -> Result<Answer, ErrorObject> {
    if method == acp::method::INITIALIZE {
        return initialize(context, raw).await.map(Answer::Result);
    }

    if context.version.is_none() {
        return Err(ErrorObject::new(
            error_code::NOT_INITIALIZED,
            "initialize must be the first request on a connection",
        ));
    }

    match method {
        acp::method::SESSION_NEW => session_new(context, raw).await.map(Answer::Result),
        acp::method::SESSION_LOAD => session_load(context, raw).await.map(Answer::Result),
        acp::method::SESSION_LIST => session_list(context, raw).await.map(Answer::Result),
        acp::ext::STATUS => status(context).await.map(Answer::Result),
        acp::ext::SESSION_ABANDON => session_abandon(context, raw).await.map(Answer::Result),
        acp::method::SESSION_PROMPT => session_prompt(context, raw).await,
        acp::ext::SESSION_RESUME => session_resume(context, raw).await,
        other => Err(ErrorObject::method_not_found().data(Value::String(other.to_string()))),
    }
}

/// Routes one notification. Notifications are never answered, even in error.
async fn notify(context: &Dispatch, method: &str, raw: Option<Value>) {
    if method != acp::method::SESSION_CANCEL {
        tracing::debug!(method, "ignoring an unknown notification");
        return;
    }

    if let Err(error) = session_cancel(context, raw).await {
        tracing::debug!(?error, "could not act on a cancellation");
    }
}

/// `initialize`: agree a version and state capabilities.
async fn initialize(context: &Dispatch, raw: Option<Value>) -> Result<Value, ErrorObject> {
    let request: acp::InitializeRequest = params(raw)?;

    if request.protocol_version < acp::MIN_PROTOCOL_VERSION {
        return Err(ErrorObject::new(
            error_code::UNSUPPORTED_VERSION,
            format!(
                "client speaks ACP {} but this agent needs at least {}",
                request.protocol_version.as_u16(),
                acp::MIN_PROTOCOL_VERSION.as_u16()
            ),
        ));
    }

    // A client ahead of the agent is served at the agent's version rather than
    // refused, which is what ACP's negotiation asks for: the response states
    // the version that will actually be spoken.
    let agreed = request.protocol_version.min(acp::PROTOCOL_VERSION);

    tracing::info!(
        client_id = %context.setup.client_id,
        client = request.client_info.as_ref().map_or("unnamed", |info| info.name.as_str()),
        version = agreed.as_u16(),
        "client initialized",
    );

    context
        .notify_self(MarkInitialized { version: agreed })
        .await;

    let response = acp::InitializeResponse::new(agreed)
        .agent_capabilities(context.setup.capabilities.clone())
        .agent_info(acp::Implementation::new(
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
        ));

    encode(&response)
}

/// `session/new`: open a session this client holds.
async fn session_new(context: &Dispatch, raw: Option<Value>) -> Result<Value, ErrorObject> {
    let request: acp::NewSessionRequest = params(raw)?;
    let project_root = project_root(context, &request.cwd)?;
    let thread_id = ThreadId::new();

    // Written down before the client is told the id, so the session the client
    // holds and the session a restart can find are the same session.
    let meta = record_session(context, &thread_id, &project_root).await?;
    let setup = thread_setup(context, thread_id, project_root);

    let created = context
        .setup
        .supervisor
        .ask(CreateThread {
            setup,
            history: Vec::new(),
            meta,
            appended: 0,
        })
        .await
        .map_err(|error| internal(&format!("could not create a session: {error}")))?;

    context
        .notify_self(OwnSession {
            thread_id: created.thread_id.clone(),
        })
        .await;

    encode(&acp::NewSessionResponse::new(acp::session_id(
        &created.thread_id,
    )))
}

/// Resolves the directory a session is rooted at, or refuses to open it.
///
/// The client names a directory; the administrator decides which directories
/// may be named. A `cwd` that resolves outside every approved root is not
/// quietly replaced with the default — that would give the client a session it
/// did not ask for, pointed somewhere it did not expect — it is refused, and
/// the refusal says which boundary it fell outside.
///
/// # Errors
///
/// [`ErrorCode::InvalidParams`](acp::ErrorCode) naming what was wrong with the
/// requested root.
fn project_root(context: &Dispatch, cwd: &Path) -> Result<PathBuf, ErrorObject> {
    let defaults = &context.setup.defaults;

    crate::boundary::resolve(cwd, &defaults.project_root, &defaults.approved_roots).map_err(
        |rejection| {
            tracing::warn!(
                cwd = %cwd.display(),
                rejection = %rejection,
                "refused a session root",
            );
            // Name the remedy, not just the refusal. The boundary is an
            // administrator's decision, so somebody reading this needs to
            // know which knob moves it rather than guessing that the answer
            // is to restart the agent somewhere else.
            ErrorObject::invalid_params().data(Value::String(format!(
                "cannot open a session there: {rejection}. Approve the tree by \
                 listing it under [threads] workspace_roots in the agent's \
                 config, or start the agent in it"
            )))
        },
    )
}

/// `session/load`: re-point an existing session's events at this connection
/// and replay its history.
async fn session_load(context: &Dispatch, raw: Option<Value>) -> Result<Value, ErrorObject> {
    let request: acp::LoadSessionRequest = params(raw)?;
    let thread_id = acp::thread_id(&request.session_id)?;

    // Load is the one place a client may name a session it does not yet hold,
    // so the supervisor is consulted directly rather than through `find`.
    let ThreadLookup { handle } = context
        .setup
        .supervisor
        .ask(FindThread {
            thread_id: thread_id.clone(),
        })
        .await
        .map_err(|error| internal(&format!("session lookup failed: {error}")))?;

    let Some(handle) = handle else {
        // Not live is not the same as unknown. A daemon that has restarted
        // holds no sessions at all, and the store is what remembers them.
        return hydrate(context, &request.session_id, &thread_id).await;
    };

    // The replay is emitted from inside this `ask`, so the FIFO sink puts every
    // chunk on the socket before the response ACP says they must precede.
    handle
        .ask(Reattach {
            owner: context.setup.client_id.clone(),
            sink: context.setup.sink.clone(),
            conn: context.conn.clone(),
        })
        .await
        .map_err(|error| internal(&format!("could not load the session: {error}")))?;

    context.notify_self(OwnSession { thread_id }).await;

    encode(&acp::LoadSessionResponse::new())
}

/// `session/prompt`: run one turn, answering when it ends.
async fn session_prompt(context: &Dispatch, raw: Option<Value>) -> Result<Answer, ErrorObject> {
    let request: acp::PromptRequest = params(raw)?;
    let thread_id = acp::thread_id(&request.session_id)?;
    let session = context.find(&thread_id).await?;

    // The dispatcher does not have the request id — the frame handler kept it —
    // so the id was parked before this ran. Nothing to do here but start.
    let admission = session
        .ask(StartTurn {
            content: acp::prompt_text(&request.prompt),
        })
        .await
        .map_err(|error| internal(&format!("could not start a turn: {error}")))?;

    match admission {
        TurnAdmission::Started { .. } => Ok(Answer::Deferred),
        // Reachable when a turn is running that this connection has no parked
        // prompt for, which is what a `session/load` mid-turn leaves behind.
        // The frame handler's own busy check cannot see that.
        TurnAdmission::Busy { turn_id } => {
            Err(busy_error().data(serde_json::json!({ "turnId": turn_id.to_string() })))
        }
    }
}

/// `session/cancel`: ask a running turn to stop.
///
/// A notification, so there is nothing to answer. The parked `session/prompt`
/// is what tells the client the cancellation took effect, with
/// [`acp::StopReason::Cancelled`].
async fn session_cancel(context: &Dispatch, raw: Option<Value>) -> Result<(), ErrorObject> {
    let request: acp::CancelNotification = params(raw)?;
    let thread_id = acp::thread_id(&request.session_id)?;
    let session = context.find(&thread_id).await?;

    session
        .ask(InterruptTurn)
        .await
        .map_err(|error| internal(&format!("could not cancel: {error}")))?;

    Ok(())
}

/// `session/list`: describe every session this client holds.
async fn session_list(context: &Dispatch, raw: Option<Value>) -> Result<Value, ErrorObject> {
    // The cursor is discarded: a connection's session set is small enough to
    // answer whole. The cwd is not, because it decides which stored sessions
    // are worth offering back.
    let request: acp::ListSessionsRequest = params(raw)?;

    let ThreadList { threads } = context
        .setup
        .supervisor
        .ask(ListThreads)
        .await
        .map_err(|error| internal(&format!("could not list sessions: {error}")))?;

    let mut sessions = Vec::new();
    let mut live = Vec::new();
    for (thread_id, handle) in threads {
        if !context.sessions.contains(&thread_id) {
            continue;
        }
        live.push(thread_id.clone());
        match handle.ask(DescribeThread).await {
            Ok(summary) => sessions.push(acp::SessionInfo::new(
                acp::session_id(&thread_id),
                summary.project_root,
            )),
            // A session that stopped between the list and the description is
            // simply no longer listable, not a failure of the whole call.
            Err(error) => tracing::debug!(%thread_id, %error, "skipping an unreachable session"),
        }
    }

    // Appended rather than merged in place: what is live comes first, in the
    // order it was created, and what can be reopened follows it.
    let stored = stored_sessions(context, request.cwd.as_deref(), &live).await;
    sessions.extend(stored);

    encode(&acp::ListSessionsResponse::new(sessions))
}

// =============================================================================
// Sessions that outlive the process
// =============================================================================

/// Everything a session actor needs, built once for both ways in.
///
/// `session/new` and a `session/load` that hydrates from the store want the
/// identical configuration; the only thing that differs between them is which
/// identity and which root it is built around. Factored out so the two paths
/// cannot drift, which is how one of them would quietly end up with the wrong
/// gates or no store.
fn thread_setup(context: &Dispatch, thread_id: ThreadId, project_root: PathBuf) -> ThreadSetup {
    let defaults = &context.setup.defaults;

    ThreadSetup {
        thread_id,
        owner: context.setup.client_id.clone(),
        sink: context.setup.sink.clone(),
        conn: context.conn.clone(),
        runtime: context.setup.runtime.clone(),
        router: context.setup.router.clone(),
        project_root: Arc::new(project_root),
        system_prompt: defaults.system_prompt.clone(),
        approval_timeout: defaults.approval_timeout,
        auto_approve: Arc::clone(&defaults.auto_approve),
        lsp: Arc::clone(&defaults.lsp),
        gates: defaults.gates.clone(),
        store: defaults.store.clone(),
    }
}

/// The refusal a client sees when the session store will not answer.
///
/// The same code the turn gate refuses with, because it is the same fact: a
/// daemon that cannot write a session down does not open one, rather than
/// opening one whose history the next restart will not find.
fn store_unavailable(error: &crate::error::GarrisonError) -> ErrorObject {
    ErrorObject::new(
        error_code::STORE_UNAVAILABLE,
        format!("the session store is unavailable: {error}"),
    )
}

/// Writes a new session down before the client is told it exists.
///
/// Ordered that way on purpose. A session the client holds an id for but the
/// store has never heard of is a session that vanishes at the next restart
/// with nothing to say about why, so the write is what the id is issued
/// against. Returns `None` on an install with no store armed, which is the
/// standalone developer install and behaves exactly as it did before.
async fn record_session(
    context: &Dispatch,
    thread_id: &ThreadId,
    project_root: &Path,
) -> Result<Option<session::SessionMeta>, ErrorObject> {
    let defaults = &context.setup.defaults;
    let Some(store) = &defaults.store else {
        return Ok(None);
    };

    let conversation = store
        .create(thread_id, defaults.system_prompt.clone())
        .await
        .map_err(|error| store_unavailable(&error))?;

    let meta = session::SessionMeta::opening(
        conversation,
        project_root.to_path_buf(),
        session::CLIENT_SOCKET,
    )
    .attributed(&defaults.attribution);

    store
        .write_meta(thread_id, &meta)
        .await
        .map_err(|error| store_unavailable(&error))?;

    Ok(Some(meta))
}

/// Brings a stored session back as a live actor, or says it is unknown.
///
/// The boundary is re-checked here rather than trusted from the record. The
/// approved roots are an administrator's decision and may have narrowed since
/// the session was written; a session rooted outside them now is refused, and
/// a stored record is not a way around that.
async fn hydrate(
    context: &Dispatch,
    session_id: &acp::SessionId,
    thread_id: &ThreadId,
) -> Result<Value, ErrorObject> {
    let Some(store) = &context.setup.defaults.store else {
        return Err(acp::unknown_session(session_id));
    };

    let stored = store
        .resolve(thread_id)
        .await
        .map_err(|error| store_unavailable(&error))?;
    let Some(stored) = stored else {
        return Err(acp::unknown_session(session_id));
    };

    let project_root = approved_root(context, &stored.meta.project_root)?;
    let history = store
        .history(&stored.meta.conversation)
        .await
        .map_err(|error| store_unavailable(&error))?;
    let appended = history.len();

    let setup = thread_setup(context, thread_id.clone(), project_root);
    let created = context
        .setup
        .supervisor
        .ask(CreateThread {
            setup,
            history,
            meta: Some(stored.meta.clone()),
            appended,
        })
        .await
        .map_err(|error| internal(&format!("could not restore the session: {error}")))?;

    // Reattaching a session this connection just created looks redundant and
    // is not: the replay is emitted from inside the `ask`, so the history
    // reaches the socket before the response ACP says it must precede.
    created
        .handle
        .ask(Reattach {
            owner: context.setup.client_id.clone(),
            sink: context.setup.sink.clone(),
            conn: context.conn.clone(),
        })
        .await
        .map_err(|error| internal(&format!("could not load the session: {error}")))?;

    context
        .notify_self(OwnSession {
            thread_id: thread_id.clone(),
        })
        .await;

    tracing::info!(
        %thread_id,
        messages = appended,
        interrupted = stored.meta.interrupted().is_some(),
        "restored a session written before this process started",
    );

    let response = acp::LoadSessionResponse::new();
    match interrupted_meta(store, &stored.meta).await {
        Some(interrupted) => encode(&response.meta(Some(acp::garrison_meta(&acp::LoadMeta {
            interrupted_turn: interrupted,
        })))),
        None => encode(&response),
    }
}

/// Re-checks a stored session's root against the roots approved *now*.
///
/// Separate from [`project_root`] because the refusal is a different one. A
/// `session/new` naming a bad directory is a client mistake and reads as
/// invalid parameters; a stored session whose root has since been de-approved
/// is an administrator's decision catching up with history, and `-32020`
/// SESSION_ROOT_UNAPPROVED is the code that says so. The record is left
/// alone either way: the session is not deleted, it is simply not opened
/// here, and re-approving the tree brings it back.
fn approved_root(context: &Dispatch, stored: &Path) -> Result<PathBuf, ErrorObject> {
    let defaults = &context.setup.defaults;

    crate::boundary::resolve(stored, &defaults.project_root, &defaults.approved_roots).map_err(
        |rejection| {
            tracing::warn!(
                root = %stored.display(),
                rejection = %rejection,
                "refused to reopen a stored session",
            );
            ErrorObject::new(
                error_code::SESSION_ROOT_UNAPPROVED,
                format!(
                    "this session was opened at '{}', which is no longer inside an approved                      tree: {rejection}. Approve it again under [threads] workspace_roots to                      reopen the session",
                    stored.display()
                ),
            )
        },
    )
}

/// What a client is told about a turn a restart cut short.
///
/// The record's open turn is the fact; the checkpoint adds how far it got and
/// whether there is anything left to pick up. A checkpoint that cannot be read
/// makes the turn unresumable rather than unreportable: the operator still
/// needs to know the session is blocked, and abandoning it is still open to
/// them.
async fn interrupted_meta(
    store: &session::SessionStore,
    meta: &session::SessionMeta,
) -> Option<acp::InterruptedTurnMeta> {
    let open = meta.interrupted()?;
    let record = match session::checkpoint_id_for(&open.turn_id) {
        Ok(id) => store.checkpoint(&id).await.ok().flatten(),
        Err(_) => None,
    };

    Some(acp::InterruptedTurnMeta {
        turn_id: open.turn_id.to_string(),
        started_at: open.started_at.clone(),
        prompt: open.content.clone(),
        rounds_completed: record.as_ref().map(|record| record.rounds_completed),
        resumable: record.as_ref().is_some_and(|record| {
            matches!(
                record.status,
                CheckpointStatus::InProgress | CheckpointStatus::Failed
            )
        }),
    })
}

/// Stored sessions this client is not already holding live, for `session/list`.
///
/// Filtered by the requested `cwd` when the client named one, because a client
/// asking what it can reopen is asking about the project in front of it rather
/// than about every project this daemon has ever served.
async fn stored_sessions(
    context: &Dispatch,
    cwd: Option<&Path>,
    live: &[ThreadId],
) -> Vec<acp::SessionInfo> {
    let Some(store) = &context.setup.defaults.store else {
        return Vec::new();
    };

    let sessions = match store.list().await {
        Ok(sessions) => sessions,
        // A store that will not answer costs the client the resumable
        // sessions, not the live ones it can already see.
        Err(error) => {
            tracing::warn!(%error, "could not list stored sessions");
            return Vec::new();
        }
    };

    sessions
        .into_iter()
        .filter(|stored| cwd.is_none_or(|cwd| stored.meta.project_root == cwd))
        .filter_map(|stored| {
            // A name that is not one of Garrison's identities belongs to some
            // other writer of this database and is not this daemon's to offer.
            let thread_id = ThreadId::parse(&stored.name).ok()?;
            (!live.contains(&thread_id)).then(|| {
                acp::SessionInfo::new(
                    acp::session_id(&thread_id),
                    stored.meta.project_root.clone(),
                )
                .updated_at(Some(stored.last_active.clone()))
            })
        })
        .collect()
}

/// `_garrison/session/resume`: pick an interrupted turn back up.
///
/// Answers like `session/prompt` does — deferred, resolved when the turn ends
/// — because that is what it is: the same turn, under the same identity,
/// carrying on from the round its checkpoint stopped at. A session with
/// nothing to resume is `-32021`, never a silently restarted turn.
async fn session_resume(context: &Dispatch, raw: Option<Value>) -> Result<Answer, ErrorObject> {
    let request: acp::InterruptedTurnRequest = params(raw)?;
    let thread_id = acp::thread_id(&request.session_id)?;
    let session = context.find(&thread_id).await?;

    let admission = session
        .ask(ResumeTurn)
        .await
        .map_err(|error| internal(&format!("could not resume: {error}")))?;

    match admission {
        ResumeAdmission::Resumed { .. } => Ok(Answer::Deferred),
        ResumeAdmission::Nothing => Err(ErrorObject::new(
            error_code::NO_INTERRUPTED_TURN,
            "this session has no interrupted turn to resume",
        )),
        ResumeAdmission::Busy { turn_id } => {
            Err(busy_error().data(serde_json::json!({ "turnId": turn_id.to_string() })))
        }
    }
}

/// `_garrison/session/abandon`: give up on an interrupted turn.
///
/// The escape hatch that keeps fail-closed from meaning stuck: a session whose
/// interrupted turn cannot or should not be resumed is promptable again the
/// moment an operator says so, and the record says the turn was abandoned
/// rather than forgotten.
async fn session_abandon(context: &Dispatch, raw: Option<Value>) -> Result<Value, ErrorObject> {
    let request: acp::InterruptedTurnRequest = params(raw)?;
    let thread_id = acp::thread_id(&request.session_id)?;
    let session = context.find(&thread_id).await?;

    let abandoned = session
        .ask(AbandonTurn)
        .await
        .map_err(|error| internal(&format!("could not abandon: {error}")))?;

    let Some(turn_id) = abandoned.turn_id else {
        return Err(ErrorObject::new(
            error_code::NO_INTERRUPTED_TURN,
            "this session has no interrupted turn to abandon",
        ));
    };

    tracing::info!(%thread_id, %turn_id, "an operator abandoned an interrupted turn");

    encode(&acp::AbandonResponse {
        turn_id: turn_id.to_string(),
    })
}

/// `_garrison/status`: what this agent is, and what it is enforcing.
///
/// Three sources, assembled in one place: what the connection knows on its
/// own, what the audit trail says about its chain, and one [`StatusPart`]
/// from every describer in [`ConnSetup::describers`].
async fn status(context: &Dispatch) -> Result<Value, ErrorObject> {
    let base = own_status(context);
    let chain_head = chain_head(&context.setup.runtime, context.setup.audited).await;
    let parts = describe_all(&context.setup.describers).await;

    encode(&assemble(base, chain_head, parts))
}

/// The part of the status this connection can state without asking anyone.
fn own_status(context: &Dispatch) -> acp::GarrisonStatus {
    let defaults = &context.setup.defaults;

    acp::GarrisonStatus {
        agent: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: context.version.unwrap_or(acp::PROTOCOL_VERSION).as_u16(),
        sessions: context.sessions.len(),
        policy: acp::PolicyStatus {
            approval_timeout_secs: defaults.approval_timeout.as_secs(),
            auto_approve: defaults.auto_approve.as_ref().clone(),
        },
        audit: acp::AuditStatus::undescribed(context.setup.audited),
        sandbox: context.setup.sandbox.clone(),
        threads: None,
        plane: None,
        context: None,
        session_store: None,
        entitlement: None,
    }
}

/// The hash at the end of the audit chain, when there is a chain to ask.
///
/// Not asked at all when auditing is off: acton-ai answers that case with a
/// configuration error, and there is no point paying for one per status call.
async fn chain_head(runtime: &ActonAI, audited: bool) -> Option<String> {
    if !audited {
        return None;
    }
    match runtime.audit_head().await {
        Ok(head) => Some(head.hash),
        Err(error) => {
            tracing::debug!(%error, "the audit trail did not disclose its head");
            None
        }
    }
}

/// Asks every describer for its part, keeping the ones that answered.
///
/// A subsystem that does not answer is missing from the status rather than
/// failing it: an operator asking "why is this daemon refusing turns" needs
/// the rest of the picture most precisely when one piece is wedged.
async fn describe_all(describers: &[ActorHandle]) -> Vec<StatusPart> {
    let mut parts = Vec::with_capacity(describers.len());
    for describer in describers {
        match describer.ask(Describe).await {
            Ok(part) => parts.push(part),
            Err(error) => {
                tracing::debug!(describer = %describer.id(), ?error, "a subsystem did not describe itself");
            }
        }
    }
    parts
}

/// Places each subsystem's part into the status.
///
/// Pure. Every variant of [`StatusPart`] has exactly one home here, which is
/// what makes adding a subsystem a three-line change.
fn assemble(
    mut status: acp::GarrisonStatus,
    chain_head: Option<String>,
    parts: Vec<StatusPart>,
) -> acp::GarrisonStatus {
    status.audit.chain_head = chain_head;
    for part in parts {
        match part {
            StatusPart::Threads(threads) => status.threads = Some(threads),
            StatusPart::Plane(plane) => status.plane = Some(plane),
            StatusPart::Context(context) => status.context = Some(context),
            StatusPart::Entitlement(entitlement) => status.entitlement = Some(entitlement),
            // The keeper asked the writer itself, so its answer replaces the
            // head this connection read on its own — including the head,
            // which the keeper reports from the same barrier that produced
            // the health beside it.
            StatusPart::Audit(audit) => status.audit = *audit,
            StatusPart::SessionStore(store) => status.session_store = Some(store),
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thread::TurnUsage;
    use crate::types::{ApprovalId, TurnId};
    use serde_json::json;
    use tokio::sync::mpsc;

    fn sink() -> (EventSink, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (EventSink::new(tx), rx)
    }

    fn approval(tool_name: &str) -> RequestApproval {
        RequestApproval {
            approval_id: ApprovalId::new(),
            thread_id: ThreadId::new(),
            turn_id: TurnId::new(),
            tool_name: tool_name.to_string(),
            arguments: json!({"command": "ls"}),
            timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn the_defaults_give_a_client_five_minutes_to_answer() {
        assert_eq!(
            ThreadDefaults::default().approval_timeout,
            Duration::from_secs(300)
        );
    }

    #[test]
    fn request_ids_are_unique_within_a_connection() {
        let mut conn = ClientConn::default();

        let first = conn.mint_request_id();
        let second = conn.mint_request_id();

        assert_ne!(first, second);
    }

    #[test]
    fn a_permission_request_offers_the_three_options_and_the_arguments() {
        let request = approval("bash");

        let built = permission_request(&request);

        assert_eq!(built.options.len(), 3);
        assert_eq!(built.tool_call.fields.title, Some("bash".to_string()));
        assert_eq!(built.tool_call.fields.kind, Some(acp::ToolKind::Execute));
        assert_eq!(
            built.tool_call.fields.raw_input,
            Some(json!({"command": "ls"}))
        );
    }

    #[test]
    fn always_allow_is_remembered_per_session_not_globally() {
        let mut conn = ClientConn::default();
        let first = ThreadId::new();
        let second = ThreadId::new();
        conn.always
            .entry(first.clone())
            .or_default()
            .insert("bash".to_string());

        assert!(conn.is_always_allowed(&first, "bash"));
        assert!(!conn.is_always_allowed(&first, "write_file"));
        assert!(!conn.is_always_allowed(&second, "bash"));
    }

    #[test]
    fn an_allow_once_answer_is_read_as_allow_once() {
        let value = json!({"outcome": {"outcome": "selected", "optionId": acp::OPTION_ALLOW_ONCE}});

        assert_eq!(read_permission(Ok(value)), Some(Permission::AllowOnce));
    }

    #[test]
    fn an_error_answer_is_not_consent() {
        assert_eq!(read_permission(Err(ErrorObject::internal_error())), None);
    }

    #[test]
    fn an_unreadable_answer_is_not_consent() {
        assert_eq!(read_permission(Ok(json!({"nonsense": true}))), None);
    }

    #[test]
    fn a_cancelled_answer_is_not_consent() {
        let value = json!({"outcome": {"outcome": "cancelled"}});

        assert_eq!(read_permission(Ok(value)), None);
    }

    #[test]
    fn a_completed_turn_answers_the_prompt_with_its_stop_reason_and_usage() {
        let (sink, mut rx) = sink();
        let finished = TurnFinished {
            thread_id: ThreadId::new(),
            turn_id: TurnId::new(),
            result: TurnResult::Completed {
                stop_reason: acp::StopReason::EndTurn,
                text: "done".to_string(),
                usage: TurnUsage {
                    prompt_tokens: 11,
                    completion_tokens: 7,
                },
                plan: None,
                compactions: Vec::new(),
            },
        };

        answer_prompt(&sink, RequestId::Number(4), &finished);

        let line = rx.try_recv().expect("a response");
        let parsed: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["id"], 4);
        assert_eq!(parsed["result"]["stopReason"], "end_turn");
        assert_eq!(parsed["result"]["_meta"]["garrison"]["promptTokens"], 11);
        assert_eq!(parsed["result"]["_meta"]["garrison"]["completionTokens"], 7);
        assert!(
            parsed["result"]["_meta"]["garrison"]["plan"].is_null(),
            "a turn with no plan says nothing about one"
        );
        assert!(
            parsed["result"]["_meta"]["garrison"]["compactions"].is_null(),
            "a turn that compacted nothing says nothing about compaction"
        );
    }

    #[test]
    fn a_completed_turn_reports_its_final_plan_and_compactions_in_meta() {
        use acton_ai::memory::{CompactionOutcome, CompactionRecord};
        use acton_ai::tools::plan::{Plan, PlanStep, PlanStepStatus};

        let plan = Plan::new(
            vec![
                PlanStep::parse("read the parser", PlanStepStatus::Completed).unwrap(),
                PlanStep::parse("fix the parser", PlanStepStatus::InProgress).unwrap(),
            ],
            None,
        )
        .expect("a two-step plan is valid");
        let record = CompactionRecord {
            summary: "the earlier exchanges".to_string(),
            outcome: CompactionOutcome {
                messages_before: 12,
                messages_after: 5,
                tokens_before: 900,
                tokens_after: 300,
                messages_elided: 8,
            },
            elided_prefix_len: 8,
        };

        let meta = turn_meta(
            "turn_abc",
            &TurnUsage::default(),
            Some(&plan),
            std::slice::from_ref(&record),
        );
        let garrison = &meta[acp::ext::META_KEY];

        assert_eq!(garrison["plan"]["completed"], 1);
        assert_eq!(garrison["plan"]["total"], 2);
        assert_eq!(garrison["plan"]["steps"][1]["status"], "in_progress");
        assert_eq!(garrison["compactions"][0]["messagesElided"], 8);
        assert_eq!(garrison["compactions"][0]["elidedPrefixLen"], 8);
    }

    #[test]
    fn a_cancelled_turn_answers_the_prompt_with_cancelled() {
        let (sink, mut rx) = sink();
        let finished = TurnFinished {
            thread_id: ThreadId::new(),
            turn_id: TurnId::new(),
            result: TurnResult::Cancelled,
        };

        answer_prompt(&sink, RequestId::Number(1), &finished);

        let parsed: Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
        assert_eq!(parsed["result"]["stopReason"], "cancelled");
    }

    #[test]
    fn a_failed_turn_answers_the_prompt_with_an_error() {
        let (sink, mut rx) = sink();
        let finished = TurnFinished {
            thread_id: ThreadId::new(),
            turn_id: TurnId::new(),
            result: TurnResult::Failed {
                reason: "the provider hung up".to_string(),
            },
        };

        answer_prompt(&sink, RequestId::Number(2), &finished);

        let parsed: Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
        assert_eq!(parsed["error"]["code"], error_code::TURN_FAILED);
        assert_eq!(parsed["error"]["data"], "the provider hung up");
    }

    #[test]
    fn a_refused_turn_answers_the_prompt_with_the_gates_code() {
        let (sink, mut rx) = sink();
        let finished = TurnFinished {
            thread_id: ThreadId::new(),
            turn_id: TurnId::new(),
            result: TurnResult::Refused(crate::admission::TurnRefusal::Seat {
                reason: "seat revoked".to_string(),
            }),
        };

        answer_prompt(&sink, RequestId::Number(3), &finished);

        let parsed: Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
        assert_eq!(parsed["error"]["code"], error_code::SEAT_REFUSED);
        assert_eq!(
            parsed["error"]["data"],
            "no seat entitles this turn: seat revoked"
        );
    }

    fn bare_status() -> acp::GarrisonStatus {
        acp::GarrisonStatus {
            agent: "garrison-agent".to_string(),
            version: "0.0.0".to_string(),
            protocol_version: 1,
            sessions: 1,
            policy: acp::PolicyStatus {
                approval_timeout_secs: 1,
                auto_approve: Vec::new(),
            },
            audit: acp::AuditStatus::undescribed(true),
            sandbox: acp::SandboxStatus::disabled(),
            threads: None,
            plane: None,
            session_store: None,
            context: None,
            entitlement: None,
        }
    }

    #[test]
    fn assembling_places_the_compaction_policy() {
        let assembled = assemble(
            bare_status(),
            None,
            vec![StatusPart::Context(acp::ContextStatus {
                compaction: Some(acp::CompactionStatus {
                    threshold: 0.8,
                    keep_recent_turns: 3,
                }),
                compactions: 2,
            })],
        );

        let context = assembled.context.expect("the context part must land");
        assert_eq!(context.compactions, 2);
        assert_eq!(
            context.compaction.map(|policy| policy.keep_recent_turns),
            Some(3)
        );
    }

    #[test]
    fn assembling_places_each_part_and_the_chain_head() {
        let assembled = assemble(
            bare_status(),
            Some("abc123".to_string()),
            vec![StatusPart::Threads(acp::ThreadsStatus { live: 4 })],
        );

        assert_eq!(assembled.audit.chain_head.as_deref(), Some("abc123"));
        assert_eq!(assembled.threads, Some(acp::ThreadsStatus { live: 4 }));
    }

    #[test]
    fn a_missing_part_leaves_its_field_absent_rather_than_failing() {
        let assembled = assemble(bare_status(), None, Vec::new());

        assert_eq!(assembled.threads, None);
        assert_eq!(assembled.audit.chain_head, None);
        let encoded = serde_json::to_value(&assembled).unwrap();
        assert!(encoded.get("threads").is_none());
    }

    #[tokio::test]
    async fn the_supervisor_describes_how_many_sessions_it_holds() {
        let mut runtime = ActonApp::launch_async().await;
        let supervisor = crate::thread::ThreadSupervisor::spawn(&mut runtime).await;

        let parts = describe_all(&[supervisor]).await;

        assert!(
            matches!(
                parts.as_slice(),
                [StatusPart::Threads(acp::ThreadsStatus { live: 0 })]
            ),
            "{parts:?}"
        );
        runtime.shutdown_all().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn a_describer_that_has_stopped_is_left_out() {
        let mut runtime = ActonApp::launch_async().await;
        let supervisor = crate::thread::ThreadSupervisor::spawn(&mut runtime).await;
        supervisor.stop().await.expect("the supervisor stops");

        let parts = describe_all(&[supervisor]).await;

        assert!(parts.is_empty());
        runtime.shutdown_all().await.expect("clean shutdown");
    }
}
