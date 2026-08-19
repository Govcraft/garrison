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

use crate::approval::{ApprovalOutcome, RequestApproval, CANCELLED_REASON, REJECTED_REASON};
use crate::protocol::acp::{self, Permission};
use crate::protocol::codec::EventSink;
use crate::protocol::jsonrpc::{encode, error_code, params, ErrorObject, Inbound, RequestId};
use crate::thread::{
    CreateThread, DescribeThread, FindThread, InterruptTurn, ListThreads, Reattach, StartTurn,
    ThreadList, ThreadLookup, ThreadSetup, TurnAdmission, TurnFinished, TurnResult,
};
use crate::types::{ClientId, ThreadId};
use acton_ai::facade::ActonAI;
use acton_reactive::prelude::*;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// The server-wide settings a new session inherits.
#[derive(Clone, Debug)]
pub struct ThreadDefaults {
    /// The root a session is confined to unless the client names another.
    pub project_root: PathBuf,
    /// The system prompt a session uses unless the server was configured
    /// otherwise.
    pub system_prompt: Option<String>,
    /// How long a client has to answer a permission request before it is
    /// denied.
    pub approval_timeout: Duration,
    /// Tool-name patterns that skip the permission round-trip.
    pub auto_approve: Arc<Vec<String>>,
}

impl Default for ThreadDefaults {
    fn default() -> Self {
        Self {
            project_root: PathBuf::from("."),
            system_prompt: None,
            approval_timeout: Duration::from_secs(300),
            auto_approve: Arc::new(Vec::new()),
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
                let parked = if method == acp::method::SESSION_PROMPT {
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
            stop_reason, usage, ..
        } => {
            let mut response = acp::PromptResponse::new(*stop_reason);
            // Token counts ride in `_meta`: they are not part of stable ACP,
            // and inventing a core field for them would make Garrison's frames
            // unreadable to a conformant client.
            let meta = turn_meta(&finished.turn_id.to_string(), usage);
            response.meta = Some(meta);
            sink.respond(id, &response);
        }
        TurnResult::Cancelled => {
            sink.respond(id, &acp::PromptResponse::new(acp::StopReason::Cancelled));
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

/// Wraps turn usage in the one `_meta` key Garrison claims.
fn turn_meta(turn_id: &str, usage: &crate::thread::TurnUsage) -> serde_json::Map<String, Value> {
    let payload = acp::TurnMeta {
        turn_id: turn_id.to_string(),
        prompt_tokens: usage.prompt_tokens,
        completion_tokens: usage.completion_tokens,
    };

    let mut meta = serde_json::Map::new();
    match serde_json::to_value(payload) {
        Ok(value) => {
            meta.insert(acp::ext::META_KEY.to_string(), value);
        }
        Err(error) => tracing::error!(%error, "dropping unserializable turn metadata"),
    }
    meta
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
        acp::method::SESSION_PROMPT => session_prompt(context, raw).await,
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
    let thread_id = ThreadId::new();

    let setup = ThreadSetup {
        thread_id,
        owner: context.setup.client_id.clone(),
        sink: context.setup.sink.clone(),
        conn: context.conn.clone(),
        runtime: context.setup.runtime.clone(),
        router: context.setup.router.clone(),
        project_root: project_root(context, request.cwd),
        system_prompt: context.setup.defaults.system_prompt.clone(),
        approval_timeout: context.setup.defaults.approval_timeout,
        auto_approve: Arc::clone(&context.setup.defaults.auto_approve),
    };

    let created = context
        .setup
        .supervisor
        .ask(CreateThread {
            setup,
            history: Vec::new(),
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

/// Resolves the directory a session is rooted at.
///
/// ACP requires an absolute `cwd`; a relative one is taken as a client bug
/// worth tolerating rather than a request worth refusing, and falls back to the
/// server's configured root so the session cannot silently escape it.
fn project_root(context: &Dispatch, cwd: PathBuf) -> PathBuf {
    if cwd.is_absolute() {
        return cwd;
    }
    tracing::warn!(
        cwd = %cwd.display(),
        "client sent a relative cwd; using the configured project root",
    );
    context.setup.defaults.project_root.clone()
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
        return Err(acp::unknown_session(&request.session_id));
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
    // Parsed and discarded: the request's only fields are a cwd filter and a
    // cursor, and a connection's session set is small enough to answer whole.
    let _request: acp::ListSessionsRequest = params(raw)?;

    let ThreadList { threads } = context
        .setup
        .supervisor
        .ask(ListThreads)
        .await
        .map_err(|error| internal(&format!("could not list sessions: {error}")))?;

    let mut sessions = Vec::new();
    for (thread_id, handle) in threads {
        if !context.sessions.contains(&thread_id) {
            continue;
        }
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

    encode(&acp::ListSessionsResponse::new(sessions))
}

/// `_garrison/status`: what this agent is, and what it is enforcing.
async fn status(context: &Dispatch) -> Result<Value, ErrorObject> {
    let defaults = &context.setup.defaults;

    encode(&acp::GarrisonStatus {
        agent: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: context.version.unwrap_or(acp::PROTOCOL_VERSION).as_u16(),
        sessions: context.sessions.len(),
        policy: acp::PolicyStatus {
            approval_timeout_secs: defaults.approval_timeout.as_secs(),
            auto_approve: defaults.auto_approve.as_ref().clone(),
        },
        audit: acp::AuditStatus {
            enabled: context.setup.audited,
            chain_head: None,
        },
    })
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
            },
        };

        answer_prompt(&sink, RequestId::Number(4), &finished);

        let line = rx.try_recv().expect("a response");
        let parsed: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["id"], 4);
        assert_eq!(parsed["result"]["stopReason"], "end_turn");
        assert_eq!(parsed["result"]["_meta"]["garrison"]["promptTokens"], 11);
        assert_eq!(parsed["result"]["_meta"]["garrison"]["completionTokens"], 7);
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
}
