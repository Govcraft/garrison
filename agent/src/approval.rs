//! The approval round-trip: policy gate → owning client → verdict.
//!
//! acton-ai's policy gate can defer a decision to a callback. Garrison's
//! callback is an **ACP round-trip**: the client that owns the session is sent
//! a `session/request_permission`, renders whatever dialog it likes, and
//! answers. The tool call waits; the runtime does not.
//!
//! # How the callback knows which client to ask
//!
//! The hook is installed once, on the runtime, and every session's tool calls
//! flow through that one function. It is handed a
//! [`ToolInvocation`](acton_ai::policy::ToolInvocation) carrying a `turn_id`
//! and a `correlation_id`, neither of which a caller of `collect()` is ever
//! told — so there is nothing in the invocation to route on.
//!
//! What *is* reliable is the task. acton-ai documents the hook as awaited "on
//! the prompt loop's own task, between the model asking for a tool and the
//! tool running", and Garrison drives every turn inside
//! [`with_turn_scope`]. A [`tokio::task_local`] therefore names the owning
//! session exactly, with no registry to keep in sync, no window in which two
//! turns could be confused, and no cost.
//!
//! If the scope is somehow absent the hook **denies**. A governance gate that
//! cannot identify who is being asked must not guess, and a denial is the
//! failure the model can see and report.
//!
//! # Who owns the deadline
//!
//! The connection actor does. It arms the timer when it parks the request and
//! answers its own reply envelope with a denial when the timer fires, so the
//! reason travels the same path a human refusal would and lands in the audit
//! chain identically. The `ask` here carries a longer deadline purely as a
//! backstop for a connection actor that has stopped answering at all.

use crate::types::{ApprovalId, ClientId, ThreadId, TurnId};
use acton_ai::policy::{name_matches, ApprovalDecision, ToolInvocation};
use acton_reactive::prelude::*;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

/// Told to the model when the gate cannot establish who owns the call.
pub const NO_OWNER_REASON: &str =
    "approval could not be routed: this tool call is not running inside a Garrison session";

/// Told to the model when nobody answered in time.
pub const TIMEOUT_REASON: &str = "approval timed out";

/// Told to the model when the client refused without saying why.
pub const REJECTED_REASON: &str = "the operator refused this tool call";

/// Told to the model when the client withdrew the question.
pub const CANCELLED_REASON: &str = "the operator cancelled this permission request";

/// Told to the model when the asking client vanished mid-call.
pub const DISCONNECTED_REASON: &str =
    "approval could not be answered: the client that owns this session disconnected";

/// How much longer than the connection's own deadline the hook waits.
///
/// The connection is the authority on the timeout; this slack only ensures
/// that a *responsive* connection always wins the race, so the model is told
/// "approval timed out" rather than something about an actor deadline.
pub const BACKSTOP_SLACK: Duration = Duration::from_secs(5);

/// Names the session a turn belongs to, for the duration of that turn.
#[derive(Clone, Debug)]
pub struct TurnScope {
    /// The session running the turn.
    pub thread_id: ThreadId,
    /// The turn, in Garrison's identity.
    pub turn_id: TurnId,
    /// The client that owns the session, and therefore answers its approvals.
    pub client_id: ClientId,
    /// That client's connection actor.
    pub conn: ActorHandle,
    /// How long the client has to answer before the call is denied.
    pub timeout: Duration,
    /// Tool-name patterns that skip the round-trip entirely.
    ///
    /// Shared rather than cloned per turn because it is read-only for the
    /// life of the process and a turn may consult it many times.
    pub auto_approve: Arc<Vec<String>>,
}

impl TurnScope {
    /// Whether this tool may run without asking anybody.
    ///
    /// Pure, and the only place the configured auto-approve list is
    /// interpreted. The *session*-scoped "always allow" cache is a different
    /// thing entirely and lives on the connection, because it is the client's
    /// answer rather than the operator's configuration.
    #[must_use]
    pub fn is_auto_approved(&self, tool_name: &str) -> bool {
        self.auto_approve
            .iter()
            .any(|pattern| name_matches(pattern, tool_name))
    }
}

tokio::task_local! {
    static TURN_SCOPE: TurnScope;
}

/// Runs `future` with `scope` visible to the approval hook.
///
/// Wrap the whole turn, not just the `collect()` call: anything the turn
/// awaits inherits the scope, and anything outside it correctly does not.
pub async fn with_turn_scope<F>(scope: TurnScope, future: F) -> F::Output
where
    F: Future,
{
    TURN_SCOPE.scope(scope, future).await
}

/// Returns the scope of the turn on this task, if there is one.
#[must_use]
pub fn current_turn_scope() -> Option<TurnScope> {
    TURN_SCOPE.try_with(Clone::clone).ok()
}

/// Asks a connection actor to obtain a human verdict for one tool call.
///
/// The connection replies through a stored envelope once the client answers,
/// so this request can stay outstanding for as long as a person takes.
#[acton_message]
pub struct RequestApproval {
    /// Correlates the question, its timer, and its answer.
    pub approval_id: ApprovalId,
    /// The session whose turn raised the call.
    pub thread_id: ThreadId,
    /// The turn the call belongs to.
    pub turn_id: TurnId,
    /// The tool the model asked for.
    pub tool_name: String,
    /// The arguments the model proposed.
    pub arguments: serde_json::Value,
    /// How long the client has to answer.
    pub timeout: Duration,
}

/// What the connection came back with.
///
/// Deliberately narrower than ACP's four permission kinds: "always allow" is
/// resolved into an [`ApprovalOutcome::Allowed`] plus a cache write *on the
/// connection*, so the gate never has to know that remembering is a thing.
#[acton_message]
pub enum ApprovalOutcome {
    /// Run the tool.
    Allowed,
    /// Do not, and tell the model this.
    Denied {
        /// Why, in words the model can act on.
        reason: String,
    },
}

impl Request for RequestApproval {
    type Response = ApprovalOutcome;
}

/// The approval hook Garrison installs on the acton-ai runtime.
pub async fn approval_hook(invocation: ToolInvocation) -> ApprovalDecision {
    let Some(scope) = current_turn_scope() else {
        tracing::error!(
            tool = %invocation.tool_name,
            "tool call reached the approval hook with no turn scope; denying",
        );
        return ApprovalDecision::deny(NO_OWNER_REASON);
    };

    if scope.is_auto_approved(&invocation.tool_name) {
        tracing::debug!(
            tool = %invocation.tool_name,
            thread_id = %scope.thread_id,
            "auto-approved by name",
        );
        return ApprovalDecision::Approve;
    }

    let approval_id = ApprovalId::new();
    tracing::debug!(
        %approval_id,
        thread_id = %scope.thread_id,
        client_id = %scope.client_id,
        tool = %invocation.tool_name,
        "asking client for permission",
    );

    let request = RequestApproval {
        approval_id,
        thread_id: scope.thread_id,
        turn_id: scope.turn_id,
        tool_name: invocation.tool_name,
        arguments: invocation.arguments,
        timeout: scope.timeout,
    };

    match scope
        .conn
        .ask_with_timeout(request, scope.timeout + BACKSTOP_SLACK)
        .await
    {
        Ok(outcome) => decision_for(outcome),
        // The connection stopped, was restarted, or dropped the envelope: in
        // every case nobody is coming to answer, and the call must not run.
        Err(AskError::NoReply | AskError::Undeliverable | AskError::Cancelled) => {
            ApprovalDecision::deny(DISCONNECTED_REASON)
        }
        Err(error) => {
            tracing::warn!(%error, "approval backstop fired");
            ApprovalDecision::deny(TIMEOUT_REASON)
        }
    }
}

/// Translates a connection's outcome into the gate's decision.
///
/// Pure, so the mapping is testable without a socket or an actor. Note that
/// Garrison never rewrites a model's arguments here: ACP's permission request
/// asks a yes-or-no question, and answering a different question than the one
/// the operator was shown would make the audit entry a lie.
#[must_use]
pub fn decision_for(outcome: ApprovalOutcome) -> ApprovalDecision {
    match outcome {
        ApprovalOutcome::Allowed => ApprovalDecision::Approve,
        ApprovalOutcome::Denied { reason } => ApprovalDecision::deny(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A minimal actor to stand in for a connection when only its address
    /// matters. These tests never send it anything.
    #[acton_actor]
    struct Nobody;

    #[test]
    fn allowed_maps_to_approve() {
        assert_eq!(
            decision_for(ApprovalOutcome::Allowed),
            ApprovalDecision::Approve
        );
    }

    #[test]
    fn denied_carries_the_reason_verbatim() {
        assert_eq!(
            decision_for(ApprovalOutcome::Denied {
                reason: "not on a Friday".to_string()
            }),
            ApprovalDecision::deny("not on a Friday")
        );
    }

    #[test]
    fn an_auto_approve_pattern_matches_by_name() {
        let scope = TurnScope {
            thread_id: ThreadId::new(),
            turn_id: TurnId::new(),
            client_id: ClientId::new(),
            conn: ActorHandle::default(),
            timeout: Duration::from_secs(1),
            auto_approve: Arc::new(vec!["read_file".to_string(), "mcp__*".to_string()]),
        };

        assert!(scope.is_auto_approved("read_file"));
        assert!(scope.is_auto_approved("mcp__docs__search"));
        assert!(!scope.is_auto_approved("bash"));
        assert!(!scope.is_auto_approved("write_file"));
    }

    #[tokio::test]
    async fn there_is_no_scope_outside_a_turn() {
        assert!(current_turn_scope().is_none());
    }

    #[tokio::test]
    async fn a_call_with_no_scope_is_denied() {
        let decision = approval_hook(ToolInvocation {
            tool_name: "bash".to_string(),
            arguments: json!({}),
            correlation_id: acton_ai::types::CorrelationId::new(),
            turn_id: acton_ai::types::TurnId::new(),
        })
        .await;

        assert_eq!(decision, ApprovalDecision::deny(NO_OWNER_REASON));
    }

    #[tokio::test]
    async fn the_scope_reaches_across_an_await() {
        let mut runtime = acton_reactive::prelude::ActonApp::launch_async().await;
        let conn = runtime.new_actor::<Nobody>().start().await;

        let expected = ThreadId::new();
        let scope = TurnScope {
            thread_id: expected.clone(),
            turn_id: TurnId::new(),
            client_id: ClientId::new(),
            conn,
            timeout: Duration::from_secs(1),
            auto_approve: Arc::new(Vec::new()),
        };

        let seen = with_turn_scope(scope, async {
            tokio::task::yield_now().await;
            current_turn_scope().map(|scope| scope.thread_id)
        })
        .await;

        assert_eq!(seen, Some(expected));
    }
}
