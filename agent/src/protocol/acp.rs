//! The Agent Client Protocol, as Garrison speaks it.
//!
//! Garrison is an **ACP agent**. It does not define a wire vocabulary of its
//! own: the methods, the events, and the permission round-trip are the ones
//! every ACP host — Zed, the JetBrains plugin, the Neovim client — already
//! knows how to drive.
//!
//! # Where the types come from
//!
//! From [`agent_client_protocol_schema`], Zed's published crate, at protocol
//! version [`PROTOCOL_VERSION`]. That crate is *only* the schema — request,
//! response, and notification types plus their serde plumbing — which is
//! exactly the half Garrison wants. The companion `agent-client-protocol`
//! crate adds a connection runtime built on `async-io`/`async-process`/
//! `blocking`, and a `Connection` object that owns dispatch. Garrison's
//! dispatch is owned by actors (see [`super::conn`]), so adopting that runtime
//! would mean two schedulers and two notions of who owns a socket. The schema
//! crate keeps the wire spec-exact and leaves the concurrency model alone.
//!
//! # Garrison's own surface
//!
//! ACP reserves `_`-prefixed methods and a `_meta` object on every message for
//! extensions. Everything Garrison adds — control-plane status, policy
//! introspection, audit-chain provenance — goes there, under [`ext`]. No core
//! ACP message ever grows a nonstandard field.
//!
//! # Identity
//!
//! ACP's [`SessionId`] is an opaque string; Garrison's [`ThreadId`] is an
//! `mti` TypeID. The wire carries the string form of the TypeID, so a session
//! identifier is still parseable, sortable by creation time, and prefixed —
//! and a client that treats it as opaque is never wrong.

use crate::types::{ThreadId, TurnId};
use serde::{Deserialize, Serialize};

pub use agent_client_protocol_schema::v1::{
    AgentCapabilities, CancelNotification, ContentBlock, ContentChunk, Error as ProtocolError,
    ErrorCode, Implementation, InitializeRequest, InitializeResponse, ListSessionsRequest,
    ListSessionsResponse, LoadSessionRequest, LoadSessionResponse, Meta, NewSessionRequest,
    NewSessionResponse, PermissionOption, PermissionOptionId, PermissionOptionKind, Plan,
    PlanEntry, PlanEntryPriority, PlanEntryStatus, PromptCapabilities, PromptRequest,
    PromptResponse, RequestId, RequestPermissionOutcome, RequestPermissionRequest,
    RequestPermissionResponse, SelectedPermissionOutcome, SessionCapabilities, SessionId,
    SessionInfo, SessionListCapabilities, SessionNotification, SessionUpdate, StopReason, ToolCall,
    ToolCallContent, ToolCallId, ToolCallStatus, ToolCallUpdate, ToolCallUpdateFields, ToolKind,
};
pub use agent_client_protocol_schema::ProtocolVersion;

/// The ACP version Garrison implements.
///
/// Version 1 is the current stable protocol. The schema crate also carries an
/// unstable v2 draft behind a feature flag; Garrison deliberately does not
/// enable it, because a draft that can change under a shipped agent is not
/// something a governed deployment can be asked to depend on.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V1;

/// The oldest ACP version Garrison will negotiate down to.
///
/// Version 0 was a pre-release and the specification itself says to treat it
/// as unsupported, so the floor and the ceiling are the same number today.
pub const MIN_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V1;

/// The ACP method names, taken from the schema rather than spelled out.
///
/// Re-exported as plain constants so a `match` arm reads as a name and a typo
/// is a compile error, and sourced from `AGENT_METHOD_NAMES` /
/// `CLIENT_METHOD_NAMES` so a rename upstream cannot silently desynchronize
/// Garrison from the protocol it claims to speak.
pub mod method {
    use agent_client_protocol_schema::v1::{AGENT_METHOD_NAMES, CLIENT_METHOD_NAMES};

    /// Handshake and capability negotiation.
    pub const INITIALIZE: &str = AGENT_METHOD_NAMES.initialize;
    /// Opens a session rooted at a working directory.
    pub const SESSION_NEW: &str = AGENT_METHOD_NAMES.session_new;
    /// Re-attaches to an existing session and replays its history.
    pub const SESSION_LOAD: &str = AGENT_METHOD_NAMES.session_load;
    /// Runs one turn. Answers when the turn ends.
    pub const SESSION_PROMPT: &str = AGENT_METHOD_NAMES.session_prompt;
    /// Asks the running turn to stop. A notification: there is no answer.
    pub const SESSION_CANCEL: &str = AGENT_METHOD_NAMES.session_cancel;
    /// Lists the sessions this client may see.
    pub const SESSION_LIST: &str = AGENT_METHOD_NAMES.session_list;

    /// Streamed session events: message chunks, tool calls, plans.
    pub const SESSION_UPDATE: &str = CLIENT_METHOD_NAMES.session_update;
    /// The agent asking the client for permission to run a tool.
    pub const SESSION_REQUEST_PERMISSION: &str = CLIENT_METHOD_NAMES.session_request_permission;
}

/// Garrison's extension surface, in ACP's reserved `_`-prefixed namespace.
///
/// See <https://agentclientprotocol.com/protocol/extensibility>. A client that
/// knows nothing about Garrison never sees any of this; a client that does
/// gets it without any core message being bent out of shape.
pub mod ext {
    /// The prefix every Garrison-specific method carries.
    pub const NAMESPACE: &str = "_garrison/";

    /// Reports what this agent is, and what it is enforcing.
    pub const STATUS: &str = "_garrison/status";

    /// Announces that a turn's history was summarized to fit the window.
    ///
    /// A notification, never a request: nothing is being asked of the client.
    /// It exists because compaction changes what the model is told, and an
    /// operator watching a session should see that happen rather than infer
    /// it from an answer that forgot something.
    pub const SESSION_COMPACTED: &str = "_garrison/session/compacted";

    /// The key Garrison uses inside any ACP `_meta` object.
    ///
    /// One key, one nested object: a `_meta` is shared with every other
    /// extension in the ecosystem, so Garrison claims exactly one name in it.
    pub const META_KEY: &str = "garrison";
}

// =============================================================================
// Garrison extension payloads
// =============================================================================

/// The answer to `_garrison/status`.
///
/// `PartialEq` without `Eq`: [`CompactionStatus::threshold`] is a fraction of
/// the context window, and a fraction is not something to compare for total
/// equality.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct GarrisonStatus {
    /// The agent binary's name.
    pub agent: String,
    /// Its version.
    pub version: String,
    /// The ACP version this connection settled on.
    pub protocol_version: u16,
    /// How many sessions this client currently holds.
    pub sessions: usize,
    /// What the approval gate is configured to do.
    pub policy: PolicyStatus,
    /// Whether tool calls are being recorded, and where the chain stands.
    pub audit: AuditStatus,
    /// What isolation the agent's writing tools run under.
    pub sandbox: SandboxStatus,
    /// What the session supervisor holds across every connection.
    ///
    /// Absent when the supervisor could not be asked; the rest of the status
    /// is still worth having.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threads: Option<ThreadsStatus>,
    /// How this daemon's one authenticated path to the control plane is
    /// faring.
    ///
    /// Absent on a standalone agent, which has no plane to report on, and on
    /// a governed one whose plane session could not be asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plane: Option<PlaneStatus>,
    /// What the daemon does when a conversation outgrows the model's window.
    ///
    /// Absent when the router could not be asked, exactly as [`Self::threads`]
    /// is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ContextStatus>,
}

/// What the daemon's credential holder reports about reaching the plane.
///
/// This is the field an operator reads first when turns are being refused,
/// because every governed subsystem spends the same bearer: if the exchange
/// is failing, the policy pull, the seat check, and the audit shipper are all
/// failing for one reason, and it is here.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PlaneStatus {
    /// Whether the last thing that happened was the plane answering.
    ///
    /// False before the first exchange as well as after a failed one: this
    /// says "a bearer is not known to be obtainable", not "the network is
    /// down".
    pub reachable: bool,
    /// When a bearer was last obtained, RFC 3339, if ever.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_exchange_at: Option<String>,
    /// When the bearer in hand stops being accepted, RFC 3339.
    ///
    /// Absent when there is no bearer, which is the same thing the daemon
    /// knows and worth saying rather than showing a stale time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// What went wrong last time, if the last attempt failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// What the daemon does with a history that no longer fits the window.
///
/// Reported by the turn router, which is the one actor that sees every
/// compaction: the policy it was launched under, and how many compactions it
/// has routed since it started.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ContextStatus {
    /// The auto-compaction policy in force, or `None` when the oldest
    /// exchanges are truncated rather than summarized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compaction: Option<CompactionStatus>,
    /// Compactions this daemon has performed since it started.
    ///
    /// Zero with a policy present means the sessions so far have stayed
    /// inside the window, which is a different statement from compaction
    /// being off.
    pub compactions: usize,
}

/// The auto-compaction policy, as acton-ai resolved it at launch.
///
/// Resolved from `[context]` in `acton-ai.toml`: Garrison never calls
/// `.compaction()` on the builder, so the file is the single source of truth
/// and this is a readback of it rather than a second copy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CompactionStatus {
    /// The share of the window's available budget at which the oldest
    /// exchanges are summarized.
    pub threshold: f64,
    /// How many trailing exchanges survive verbatim.
    pub keep_recent_turns: usize,
}

/// What the session supervisor reports about the sessions it owns.
///
/// Distinct from [`GarrisonStatus::sessions`], which counts only the sessions
/// the asking connection holds: this is the daemon-wide figure.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ThreadsStatus {
    /// How many sessions are alive in the whole daemon.
    pub live: usize,
}

/// The approval gate's configuration, as the client may see it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PolicyStatus {
    /// How long a permission request waits before it is denied.
    pub approval_timeout_secs: u64,
    /// Tool-name patterns that never reach the client.
    pub auto_approve: Vec<String>,
}

/// What isolation stands between a tool call and the host.
///
/// A reviewer asking "does this thing run `bash` in my daemon's process" gets
/// an answer from the running agent rather than from the config file someone
/// hopes it loaded.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SandboxStatus {
    /// Whether writing tools are dispatched to a sandboxed child at all.
    ///
    /// False means `bash`, `write_file`, and `edit_file` run in the agent's
    /// own process, with the agent's own privileges.
    pub enabled: bool,
    /// The OS-hardening policy in force: `off`, `besteffort`, or `enforce`.
    ///
    /// Absent when nothing is sandboxed, because there is no policy to name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardening: Option<String>,
    /// How long a sandboxed call may run before the parent kills it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// The child's address-space ceiling, in bytes, when one is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_limit_bytes: Option<u64>,
}

impl SandboxStatus {
    /// The answer when no sandbox is configured.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            hardening: None,
            timeout_secs: None,
            memory_limit_bytes: None,
        }
    }
}

/// What the audit trail can say about itself.
///
/// The four states of [`state`](Self::state) are what an operator triages on,
/// and they are deliberately four rather than a boolean: `disabled` (nothing
/// is being recorded), `configured` (a trail is armed and nothing has been
/// written to it yet), `healthy` (every append reached the disk), and
/// `degraded` (at least one did not, so the record is incomplete). A daemon
/// that cannot ask its own writer reports `degraded` and never `healthy`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AuditStatus {
    /// Whether the runtime is recording tool invocations at all.
    pub enabled: bool,
    /// Where the audit stands, in one word.
    #[serde(default)]
    pub state: crate::audit::AuditState,
    /// What an append promises before it is acknowledged: `best_effort` or
    /// `strict`. Absent when no trail is armed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durability: Option<String>,
    /// The hash at the end of the chain, when the runtime will disclose it.
    ///
    /// Read from `ActonAI::audit_head()` at the moment of the request. Absent
    /// when no trail is configured, or when the audit actor did not answer:
    /// a status that cannot vouch for the chain says nothing rather than
    /// guessing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_head: Option<String>,
    /// The sequence number that head carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    /// The trail's identity, once acton-ai has sealed one into the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trail_id: Option<String>,
    /// Entries this process has written and, when strict, synced.
    #[serde(default)]
    pub appended: u64,
    /// Appends this process could not write.
    #[serde(default)]
    pub failures: u64,
    /// The sequence number of the first entry that failed to reach the disk,
    /// which is where an auditor starts reading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_failed_sequence: Option<u64>,
    /// What the operating system said about the most recent failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// When the writer first failed, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_since: Option<String>,
    /// The externally anchored head, which is what makes a tail truncation
    /// detectable. Absent when nothing anchors this trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<AnchorStatus>,
}

impl AuditStatus {
    /// What a connection can say before any subsystem has described itself.
    ///
    /// `enabled` is known from the runtime; everything else waits for the
    /// audit keeper's part, and a daemon without a keeper reports the state
    /// it can actually justify rather than a healthy-looking default.
    #[must_use]
    pub fn undescribed(enabled: bool) -> Self {
        Self {
            enabled,
            state: if enabled {
                crate::audit::AuditState::Configured
            } else {
                crate::audit::AuditState::Disabled
            },
            durability: None,
            chain_head: None,
            sequence: None,
            trail_id: None,
            appended: 0,
            failures: 0,
            first_failed_sequence: None,
            last_error: None,
            degraded_since: None,
            anchor: None,
        }
    }
}

/// Where the chain head is remembered outside the trail.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AnchorStatus {
    /// The anchor file.
    pub path: String,
    /// The sequence number it vouches for, absent until one is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    /// The hash it vouches for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// When it was last written, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored_at: Option<String>,
    /// Why the last attempt to write it failed, when one did. An anchor that
    /// stops advancing while the trail grows is a finding in its own right.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// What Garrison attaches to a `session/prompt` response's `_meta`.
///
/// Token counts are not part of stable ACP — the schema hides `PromptResponse`
/// usage behind an unstable feature — so they travel in the extension slot
/// where a client can read them without either side pretending they are
/// standard.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct TurnMeta {
    /// Garrison's identifier for the turn that just ended.
    pub turn_id: String,
    /// Tokens sent.
    pub prompt_tokens: u64,
    /// Tokens received.
    pub completion_tokens: u64,
    /// The plan as it stood when the turn ended, when the model published one.
    ///
    /// The authoritative end state. Plan updates stream as
    /// [`SessionUpdate::Plan`] notifications from the router while the turn
    /// runs, and those travel on the same sink as this response but from a
    /// different actor, so the last of them may land *after* it. A client that
    /// wants the final plan reads it here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanSummary>,
    /// What compaction did to this turn's history, oldest first.
    ///
    /// Empty, and absent from the wire, unless the history outgrew the window
    /// and `[context] auto_compact` was on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compactions: Vec<CompactionSummary>,
}

/// A plan as Garrison states it in `_meta`.
///
/// The counts are carried rather than left to be derived: a client that only
/// wants "three of seven done" should not have to walk the steps to find out.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PlanSummary {
    /// The steps, in the order the model listed them.
    pub steps: Vec<PlanStepSummary>,
    /// The model's note about the plan as a whole, if it wrote one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// How many steps are finished.
    pub completed: usize,
    /// How many steps there are.
    pub total: usize,
}

/// One step of a plan, in `_meta`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PlanStepSummary {
    /// What the step is.
    pub title: String,
    /// Where it stands, spelled as ACP spells it.
    pub status: PlanEntryStatus,
}

/// Garrison's correlation for one streamed plan update.
///
/// Rides in the notification's `_meta.garrison`. The turn identifier is the
/// point of it: a client holding several open prompts can tell which answer
/// this plan belongs to, and match it against the `turnId` the eventual
/// `session/prompt` response carries.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct PlanMeta {
    /// Garrison's identifier for the turn that published this plan.
    pub turn_id: String,
    /// The `update_plan` call that published it.
    pub tool_call_id: String,
    /// The model's note about the plan, if it wrote one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// How many steps are finished.
    pub completed: usize,
    /// How many steps there are.
    pub total: usize,
}

/// What one compaction did, in `_meta`.
///
/// Counts only. The summary text itself is a message in the session's history,
/// where a `session/load` replays it and session persistence stores it, and
/// duplicating kilobytes of it in every prompt response would create a second
/// source of truth for the same words.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CompactionSummary {
    /// Estimated tokens before the pass.
    pub tokens_before: u64,
    /// Estimated tokens after it.
    pub tokens_after: u64,
    /// Messages the summary replaced, as the prompt loop counted them.
    pub messages_elided: u64,
    /// Messages in the loop's history before the pass.
    pub messages_before: u64,
    /// Messages in it after.
    pub messages_after: u64,
    /// How many leading messages of the *session's own* history the summary
    /// stands for.
    ///
    /// acton-ai's statement that a compaction is a strict prefix elision
    /// (`CompactionRecord::elided_prefix_len`), and therefore the number that
    /// makes the daemon's copy of the history adoptable rather than guessable.
    /// It can exceed the messages the session owns, because the loop's list
    /// also held this turn's rounds.
    pub elided_prefix_len: u64,
}

/// The `_garrison/session/compacted` notification's parameters.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CompactionNotice {
    /// The session whose history was summarized.
    pub session_id: SessionId,
    /// Garrison's identifier for the turn it happened in.
    pub turn_id: String,
    /// Estimated tokens before the pass.
    pub tokens_before: u64,
    /// Estimated tokens after it.
    pub tokens_after: u64,
    /// Messages the summary replaced.
    pub messages_elided: u64,
}

// =============================================================================
// Permission options
// =============================================================================

/// The option id for "run it this once".
pub const OPTION_ALLOW_ONCE: &str = "allow_once";
/// The option id for "run it, and stop asking me for this tool".
pub const OPTION_ALLOW_ALWAYS: &str = "allow_always";
/// The option id for "do not run it".
pub const OPTION_REJECT: &str = "reject_once";

/// What a client's permission answer means to the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Permission {
    /// Allow this call and no others.
    AllowOnce,
    /// Allow this call, and every later call to the same tool in this session.
    AllowAlways,
    /// Refuse.
    Reject,
}

/// The options Garrison offers for every permission request.
///
/// Deliberately three, not four. ACP also defines `reject_always`, and a
/// remembered *refusal* is a policy decision wearing a dialog's clothes: it
/// silently narrows what the agent may do for the rest of the session with no
/// record anyone reviews. Refusals in Garrison are per-call and land in the
/// audit chain individually.
#[must_use]
pub fn permission_options() -> Vec<PermissionOption> {
    vec![
        PermissionOption::new(
            OPTION_ALLOW_ONCE,
            "Allow once",
            PermissionOptionKind::AllowOnce,
        ),
        PermissionOption::new(
            OPTION_ALLOW_ALWAYS,
            "Always allow",
            PermissionOptionKind::AllowAlways,
        ),
        PermissionOption::new(OPTION_REJECT, "Reject", PermissionOptionKind::RejectOnce),
    ]
}

/// Reads a client's answer.
///
/// `None` means the client cancelled — it is no longer waiting on an answer,
/// which the caller must treat as a refusal rather than as consent. Pure, so
/// the mapping is testable without a socket.
#[must_use]
pub fn permission_for(outcome: &RequestPermissionOutcome) -> Option<Permission> {
    let RequestPermissionOutcome::Selected(selected) = outcome else {
        return None;
    };

    match selected.option_id.0.as_ref() {
        OPTION_ALLOW_ONCE => Some(Permission::AllowOnce),
        OPTION_ALLOW_ALWAYS => Some(Permission::AllowAlways),
        OPTION_REJECT => Some(Permission::Reject),
        // A client that answers with an option we never offered has answered
        // nothing. Refusing is the only safe reading.
        other => {
            tracing::warn!(option = %other, "unknown permission option; treating as a refusal");
            None
        }
    }
}

// =============================================================================
// Conversions
// =============================================================================

/// Renders a thread identity as an ACP session identifier.
#[must_use]
pub fn session_id(thread_id: &ThreadId) -> SessionId {
    SessionId::new(thread_id.to_string())
}

/// Reads a thread identity back out of an ACP session identifier.
///
/// # Errors
///
/// [`ErrorCode::ResourceNotFound`] when the string is not one Garrison minted.
/// A malformed identifier and an identifier for a session that has ended are
/// the same answer on purpose: neither tells a client anything about sessions
/// it does not own.
pub fn thread_id(session_id: &SessionId) -> Result<ThreadId, ProtocolError> {
    ThreadId::parse(session_id.0.as_ref()).map_err(|_| unknown_session(session_id))
}

/// The error for a session this client may not have.
#[must_use]
pub fn unknown_session(session_id: &SessionId) -> ProtocolError {
    ProtocolError::resource_not_found(Some(format!("acp://session/{session_id}")))
}

/// Flattens a prompt into the text the model is given.
///
/// Garrison advertises no image, audio, or embedded-context capability, so a
/// conformant client sends text and resource links and nothing else. A link
/// arrives as its URI, which is what a coding agent with filesystem tools can
/// act on. Anything else is dropped rather than stringified into noise the
/// model would have to ignore.
#[must_use]
pub fn prompt_text(blocks: &[ContentBlock]) -> String {
    let mut parts: Vec<String> = Vec::new();

    for block in blocks {
        match block {
            ContentBlock::Text(text) => parts.push(text.text.clone()),
            ContentBlock::ResourceLink(link) => parts.push(format!("@{}", link.uri)),
            other => tracing::debug!(?other, "dropping an unsupported prompt block"),
        }
    }

    parts.join("\n")
}

/// The `session/update` carrying a piece of the agent's answer.
#[must_use]
pub fn agent_chunk(thread_id: &ThreadId, text: &str) -> SessionNotification {
    SessionNotification::new(
        session_id(thread_id),
        SessionUpdate::AgentMessageChunk(ContentChunk::new(text.into())),
    )
}

/// The `session/update` carrying a piece of what the user said.
///
/// Only used when replaying a loaded session: live user text came from the
/// client, which does not need to be told about it.
#[must_use]
pub fn user_chunk(thread_id: &ThreadId, text: &str) -> SessionNotification {
    SessionNotification::new(
        session_id(thread_id),
        SessionUpdate::UserMessageChunk(ContentChunk::new(text.into())),
    )
}

/// The `session/update` carrying context the agent holds but never said.
///
/// Used when replaying a loaded session to render the framework's compaction
/// summary: it is a user-role message in the history because that is the shape
/// the model needs, but it is not something the operator said, and replaying
/// it as a user chunk would put words in their mouth.
#[must_use]
pub fn thought_chunk(thread_id: &ThreadId, text: &str) -> SessionNotification {
    SessionNotification::new(
        session_id(thread_id),
        SessionUpdate::AgentThoughtChunk(ContentChunk::new(text.into())),
    )
}

/// The `session/update` announcing that a tool call has started.
///
/// ACP models a tool call as an object the client creates once and then
/// updates, so this is the create half: it carries the identifier every later
/// update refers to, the arguments the model proposed, and a kind so the
/// client can pick an icon before anything has happened.
#[must_use]
pub fn tool_call_started(
    thread_id: &ThreadId,
    tool_call_id: &str,
    tool_name: &str,
    raw_input: Option<serde_json::Value>,
) -> SessionNotification {
    let call = ToolCall::new(tool_call_id.to_string(), tool_name)
        .kind(tool_kind_for(tool_name))
        .status(ToolCallStatus::InProgress)
        .raw_input(raw_input);

    SessionNotification::new(session_id(thread_id), SessionUpdate::ToolCall(call))
}

/// The `session/update` closing out a tool call.
///
/// A refused call is [`ToolCallStatus::Failed`] with the refusal as its
/// content: from the client's point of view the tool did not run and the
/// reason is what matters, and conflating "the policy said no" with "the tool
/// errored" would be a governance product lying about its own decisions in the
/// one place an operator is looking.
#[must_use]
pub fn tool_call_finished(
    thread_id: &ThreadId,
    tool_call_id: &str,
    success: bool,
    summary: &str,
) -> SessionNotification {
    let status = if success {
        ToolCallStatus::Completed
    } else {
        ToolCallStatus::Failed
    };

    let mut fields = ToolCallUpdateFields::new().status(status);
    if !summary.is_empty() {
        fields = fields.content(vec![ToolCallContent::from(ContentBlock::from(summary))]);
    }

    SessionNotification::new(
        session_id(thread_id),
        SessionUpdate::ToolCallUpdate(ToolCallUpdate::new(tool_call_id.to_string(), fields)),
    )
}

/// Wraps an extension payload in the one `_meta` key Garrison claims.
///
/// A `_meta` object is shared with every other extension in the ecosystem, so
/// Garrison takes exactly one name in it and nests everything under that. A
/// payload that will not serialize is logged and dropped rather than failing
/// the frame it rides on: metadata is never the reason a client loses a turn's
/// answer.
#[must_use]
pub fn garrison_meta<T: Serialize>(payload: &T) -> Meta {
    let mut meta = Meta::new();
    match serde_json::to_value(payload) {
        Ok(value) => {
            meta.insert(ext::META_KEY.to_string(), value);
        }
        Err(error) => tracing::error!(%error, "dropping unserializable garrison metadata"),
    }
    meta
}

/// The `session/update` carrying the model's current plan.
///
/// Spec-native: every ACP host already renders `sessionUpdate: "plan"`, so a
/// plan a governed agent published is visible in Zed, the JetBrains plugin and
/// Neovim without any of them knowing what Garrison is. Garrison's own
/// correlation — which turn this plan belongs to, and which `update_plan` call
/// published it — rides in the notification's `_meta.garrison`, which is the
/// slot ACP reserves for exactly that.
///
/// acton-ai's plans carry no priority, so every entry is
/// [`PlanEntryPriority::Medium`]: a constant, stated here rather than guessed
/// per step from wording the model never meant as a priority.
#[must_use]
pub fn plan_update(
    thread_id: &ThreadId,
    turn_id: &TurnId,
    tool_call_id: &str,
    plan: &acton_ai::tools::plan::Plan,
) -> SessionNotification {
    let entries: Vec<PlanEntry> = plan
        .steps()
        .iter()
        .map(|step| {
            PlanEntry::new(
                step.title().as_str(),
                PlanEntryPriority::Medium,
                plan_entry_status(step.status()),
            )
        })
        .collect();

    let meta = garrison_meta(&PlanMeta {
        turn_id: turn_id.to_string(),
        tool_call_id: tool_call_id.to_string(),
        note: plan.note().map(|note| note.as_str().to_string()),
        completed: plan.completed_count(),
        total: plan.step_count(),
    });

    SessionNotification::new(
        session_id(thread_id),
        SessionUpdate::Plan(Plan::new(entries)),
    )
    .meta(Some(meta))
}

/// The `_garrison/session/compacted` notification for one compaction pass.
#[must_use]
pub fn compaction_notice(
    thread_id: &ThreadId,
    turn_id: &TurnId,
    tokens_before: u64,
    tokens_after: u64,
    messages_elided: u64,
) -> CompactionNotice {
    CompactionNotice {
        session_id: session_id(thread_id),
        turn_id: turn_id.to_string(),
        tokens_before,
        tokens_after,
        messages_elided,
    }
}

/// Restates a plan for a `session/prompt` response's `_meta`.
///
/// Pure, so the shape a client reads at the end of a turn is testable without
/// a model.
#[must_use]
pub fn plan_summary(plan: &acton_ai::tools::plan::Plan) -> PlanSummary {
    PlanSummary {
        steps: plan
            .steps()
            .iter()
            .map(|step| PlanStepSummary {
                title: step.title().as_str().to_string(),
                status: plan_entry_status(step.status()),
            })
            .collect(),
        note: plan.note().map(|note| note.as_str().to_string()),
        completed: plan.completed_count(),
        total: plan.step_count(),
    }
}

/// Restates one compaction for a `session/prompt` response's `_meta`.
#[must_use]
pub fn compaction_summary(record: &acton_ai::memory::CompactionRecord) -> CompactionSummary {
    CompactionSummary {
        tokens_before: record.outcome.tokens_before as u64,
        tokens_after: record.outcome.tokens_after as u64,
        messages_elided: record.outcome.messages_elided as u64,
        messages_before: record.outcome.messages_before as u64,
        messages_after: record.outcome.messages_after as u64,
        elided_prefix_len: record.elided_prefix_len as u64,
    }
}

/// Translates acton-ai's plan-step status into ACP's.
///
/// Pure, and total in both directions: the two vocabularies are the same three
/// states, which is why a plan needs no lossy mapping to reach a client.
#[must_use]
pub fn plan_entry_status(status: acton_ai::tools::plan::PlanStepStatus) -> PlanEntryStatus {
    use acton_ai::tools::plan::PlanStepStatus as Step;

    match status {
        Step::Pending => PlanEntryStatus::Pending,
        Step::InProgress => PlanEntryStatus::InProgress,
        Step::Completed => PlanEntryStatus::Completed,
    }
}

/// Classifies a tool by name, so a client can render the right icon.
///
/// Pure, exhaustive over Garrison's own builtins, and deliberately generous
/// about MCP: an `mcp__server__tool` name says nothing about what the tool
/// does, so it gets [`ToolKind::Other`] rather than a guess.
#[must_use]
pub fn tool_kind_for(tool_name: &str) -> ToolKind {
    match tool_name {
        "read_file" | "list_files" => ToolKind::Read,
        "glob" | "grep" => ToolKind::Search,
        "write_file" | "edit_file" | "apply_patch" => ToolKind::Edit,
        "bash" => ToolKind::Execute,
        "web_fetch" => ToolKind::Fetch,
        _ => ToolKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_client_protocol_schema::v1::SelectedPermissionOutcome;

    #[test]
    fn the_negotiated_floor_is_never_above_the_ceiling() {
        assert!(MIN_PROTOCOL_VERSION <= PROTOCOL_VERSION);
    }

    #[test]
    fn the_method_names_are_the_specs_names() {
        // Spelled out rather than compared to the constants they came from:
        // this is the test that would fail if the schema crate renamed a
        // method and Garrison followed it silently.
        assert_eq!(method::INITIALIZE, "initialize");
        assert_eq!(method::SESSION_NEW, "session/new");
        assert_eq!(method::SESSION_LOAD, "session/load");
        assert_eq!(method::SESSION_PROMPT, "session/prompt");
        assert_eq!(method::SESSION_CANCEL, "session/cancel");
        assert_eq!(method::SESSION_LIST, "session/list");
        assert_eq!(method::SESSION_UPDATE, "session/update");
        assert_eq!(
            method::SESSION_REQUEST_PERMISSION,
            "session/request_permission"
        );
    }

    #[test]
    fn every_garrison_method_is_in_the_reserved_namespace() {
        for method in [ext::STATUS, ext::SESSION_COMPACTED] {
            assert!(method.starts_with(ext::NAMESPACE), "{method}");
        }
        assert!(ext::NAMESPACE.starts_with('_'));
    }

    /// A two-step plan whose first step is where the model says it is.
    fn a_plan(first: acton_ai::tools::plan::PlanStepStatus) -> acton_ai::tools::plan::Plan {
        use acton_ai::tools::plan::{Plan as ModelPlan, PlanNote, PlanStep, PlanStepStatus};

        ModelPlan::new(
            vec![
                PlanStep::parse("read the parser", first).unwrap(),
                PlanStep::parse("fix the parser", PlanStepStatus::Pending).unwrap(),
            ],
            Some(PlanNote::parse("two passes").unwrap()),
        )
        .expect("a two-step plan is valid")
    }

    #[test]
    fn a_plan_update_is_a_spec_native_plan_with_garrisons_correlation_beside_it() {
        use acton_ai::tools::plan::PlanStepStatus;

        let notification = plan_update(
            &ThreadId::new(),
            &TurnId::new(),
            "call-1",
            &a_plan(PlanStepStatus::InProgress),
        );
        let frame = serde_json::to_value(&notification).expect("the notification must serialize");

        assert_eq!(frame["update"]["sessionUpdate"], "plan");
        assert_eq!(frame["update"]["entries"][0]["content"], "read the parser");
        assert_eq!(frame["update"]["entries"][0]["status"], "in_progress");
        assert_eq!(frame["update"]["entries"][1]["status"], "pending");
        assert_eq!(frame["update"]["entries"][0]["priority"], "medium");

        let garrison = &frame["_meta"][ext::META_KEY];
        assert_eq!(garrison["toolCallId"], "call-1");
        assert_eq!(garrison["note"], "two passes");
        assert_eq!(garrison["completed"], 0);
        assert_eq!(garrison["total"], 2);
    }

    #[test]
    fn a_plan_updates_meta_names_the_turn_the_prompt_response_will_name() {
        use acton_ai::tools::plan::PlanStepStatus;

        let turn_id = TurnId::new();
        let notification = plan_update(
            &ThreadId::new(),
            &turn_id,
            "call-1",
            &a_plan(PlanStepStatus::Completed),
        );

        let frame = serde_json::to_value(&notification).unwrap();
        assert_eq!(frame["_meta"][ext::META_KEY]["turnId"], turn_id.to_string());
    }

    #[test]
    fn a_finished_plan_counts_itself_for_the_response_meta() {
        use acton_ai::tools::plan::PlanStepStatus;

        let summary = plan_summary(&a_plan(PlanStepStatus::Completed));

        assert_eq!(summary.completed, 1);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.steps[0].status, PlanEntryStatus::Completed);
        assert_eq!(summary.note.as_deref(), Some("two passes"));
    }

    #[test]
    fn the_three_plan_statuses_mean_the_same_thing_on_both_sides() {
        use acton_ai::tools::plan::PlanStepStatus;

        assert_eq!(
            plan_entry_status(PlanStepStatus::Pending),
            PlanEntryStatus::Pending
        );
        assert_eq!(
            plan_entry_status(PlanStepStatus::InProgress),
            PlanEntryStatus::InProgress
        );
        assert_eq!(
            plan_entry_status(PlanStepStatus::Completed),
            PlanEntryStatus::Completed
        );
    }

    #[test]
    fn a_compaction_notice_names_the_session_the_turn_and_what_it_cost() {
        let thread_id = ThreadId::new();
        let turn_id = TurnId::new();

        let notice = compaction_notice(&thread_id, &turn_id, 900, 300, 8);
        let frame = serde_json::to_value(&notice).expect("the notice must serialize");

        assert_eq!(frame["sessionId"], thread_id.to_string());
        assert_eq!(frame["turnId"], turn_id.to_string());
        assert_eq!(frame["tokensBefore"], 900);
        assert_eq!(frame["tokensAfter"], 300);
        assert_eq!(frame["messagesElided"], 8);
    }

    #[test]
    fn a_compaction_summary_carries_the_counts_and_not_the_text() {
        use acton_ai::memory::{CompactionOutcome, CompactionRecord};

        let record = CompactionRecord {
            summary: "words the model wrote".to_string(),
            outcome: CompactionOutcome {
                messages_before: 12,
                messages_after: 5,
                tokens_before: 900,
                tokens_after: 300,
                messages_elided: 8,
            },
            elided_prefix_len: 6,
        };

        let frame = serde_json::to_value(compaction_summary(&record)).unwrap();

        assert_eq!(frame["messagesElided"], 8);
        assert_eq!(frame["elidedPrefixLen"], 6);
        assert!(
            !frame.to_string().contains("words the model wrote"),
            "the summary text belongs in the history, not in every response"
        );
    }

    #[test]
    fn garrison_metadata_takes_exactly_one_key() {
        let meta = garrison_meta(&TurnMeta::default());

        assert_eq!(meta.len(), 1);
        assert!(meta.contains_key(ext::META_KEY));
    }

    #[test]
    fn a_session_identifier_round_trips_to_a_thread() {
        let expected = ThreadId::new();

        let parsed = thread_id(&session_id(&expected)).expect("round trip");

        assert_eq!(parsed, expected);
    }

    #[test]
    fn a_session_identifier_we_did_not_mint_is_not_found() {
        let error = thread_id(&SessionId::new("not-a-typeid")).unwrap_err();

        assert_eq!(error.code, ErrorCode::ResourceNotFound);
    }

    #[test]
    fn a_prompt_flattens_text_and_links() {
        let blocks = vec![
            ContentBlock::from("fix the parser"),
            ContentBlock::ResourceLink(agent_client_protocol_schema::v1::ResourceLink::new(
                "parser.rs",
                "file:///src/parser.rs",
            )),
        ];

        assert_eq!(
            prompt_text(&blocks),
            "fix the parser\n@file:///src/parser.rs"
        );
    }

    #[test]
    fn an_empty_prompt_is_empty_text() {
        assert_eq!(prompt_text(&[]), "");
    }

    #[test]
    fn the_three_options_are_the_three_ids_the_reader_understands() {
        let ids: Vec<String> = permission_options()
            .iter()
            .map(|option| option.option_id.0.to_string())
            .collect();

        assert_eq!(ids, [OPTION_ALLOW_ONCE, OPTION_ALLOW_ALWAYS, OPTION_REJECT]);
        for id in ids {
            let outcome = RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(id));
            assert!(permission_for(&outcome).is_some());
        }
    }

    #[test]
    fn always_is_distinguishable_from_once() {
        let once =
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(OPTION_ALLOW_ONCE));
        let always =
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(OPTION_ALLOW_ALWAYS));

        assert_eq!(permission_for(&once), Some(Permission::AllowOnce));
        assert_eq!(permission_for(&always), Some(Permission::AllowAlways));
    }

    #[test]
    fn a_cancelled_request_is_not_consent() {
        assert_eq!(permission_for(&RequestPermissionOutcome::Cancelled), None);
    }

    #[test]
    fn an_option_we_never_offered_is_not_consent() {
        let outcome =
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new("allow_forever"));

        assert_eq!(permission_for(&outcome), None);
    }

    #[test]
    fn a_started_tool_call_carries_its_identifier_kind_and_input() {
        let notification = tool_call_started(
            &ThreadId::new(),
            "call-1",
            "bash",
            Some(serde_json::json!({"command": "ls"})),
        );

        let SessionUpdate::ToolCall(call) = notification.update else {
            panic!("expected a tool call");
        };
        assert_eq!(call.tool_call_id.0.as_ref(), "call-1");
        assert_eq!(call.kind, ToolKind::Execute);
        assert_eq!(call.status, ToolCallStatus::InProgress);
        assert_eq!(call.raw_input, Some(serde_json::json!({"command": "ls"})));
    }

    #[test]
    fn a_refused_tool_call_finishes_as_failed_with_the_reason() {
        let notification =
            tool_call_finished(&ThreadId::new(), "call-1", false, "denied by policy");

        let SessionUpdate::ToolCallUpdate(update) = notification.update else {
            panic!("expected a tool call update");
        };
        assert_eq!(update.fields.status, Some(ToolCallStatus::Failed));
        assert_eq!(update.fields.content.map(|content| content.len()), Some(1));
    }

    #[test]
    fn a_finished_tool_call_with_no_summary_carries_no_content() {
        let notification = tool_call_finished(&ThreadId::new(), "call-1", true, "");

        let SessionUpdate::ToolCallUpdate(update) = notification.update else {
            panic!("expected a tool call update");
        };
        assert_eq!(update.fields.status, Some(ToolCallStatus::Completed));
        assert!(update.fields.content.is_none());
    }

    #[test]
    fn tools_are_classified_by_what_they_do() {
        assert_eq!(tool_kind_for("read_file"), ToolKind::Read);
        assert_eq!(tool_kind_for("grep"), ToolKind::Search);
        assert_eq!(tool_kind_for("apply_patch"), ToolKind::Edit);
        assert_eq!(tool_kind_for("bash"), ToolKind::Execute);
        assert_eq!(tool_kind_for("mcp__docs__search"), ToolKind::Other);
    }
}
