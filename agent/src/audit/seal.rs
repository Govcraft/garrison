//! Sealing the work the gates turned away.
//!
//! The gates are asked before the prompt loop, so the runtime never sees
//! refused work and cannot record it the way it records what it runs. Without
//! this, an install whose seat lapsed and was refused all afternoon would leave
//! a trail indistinguishable from an install nobody touched, and telling those
//! two apart is most of what an audit trail is for.
//!
//! Both paths that ask the gates seal through here: a turn refused in
//! `thread.rs`, and a completion refused in `protocol::conn`. They record the
//! same shape, because an auditor asking "what did this install try to do and
//! get turned away from" should not have to know which surface asked.
//!
//! # What is written, and what is not
//!
//! The stable [`TurnRefusal::decision`] word, the rendered refusal, and the
//! prompt's size in bytes. The prompt is counted and never copied: a refused
//! turn is still a developer's private text, and a record that leaves the
//! workstation is the wrong place for it.
//!
//! # Nothing here changes the verdict
//!
//! A refusal that cannot be sealed is still a refusal. The work was already
//! being turned away, and failing louder would not admit it. What an operator
//! gets instead is the error in the log and the audit health `_garrison/status`
//! already reports. An install with no trail configured is skipped rather than
//! logged at, since it has nothing to seal into.

use crate::admission::TurnRefusal;
use crate::session::ids::acton_turn_id;
use crate::types::{ThreadId, TurnId};
use acton_ai::facade::ActonAI;
use acton_ai::types::ConversationId;

/// Seals one refusal into the trail.
///
/// `conversation` is the stored conversation the work belonged to, when there
/// is one; a completion has none, and acton-ai records the entry without it.
pub async fn seal_refusal(
    runtime: &ActonAI,
    thread_id: &ThreadId,
    turn_id: &TurnId,
    refusal: &TurnRefusal,
    conversation: Option<ConversationId>,
    prompt_size_bytes: u64,
) {
    // An install with no trail configured has nothing to seal into, and saying
    // so on every refusal would be noise rather than evidence.
    if runtime.audit_durability().is_none() {
        return;
    }

    let turn = match acton_turn_id(turn_id) {
        Ok(turn) => turn,
        Err(error) => {
            tracing::error!(
                %thread_id,
                %turn_id,
                %error,
                "refused work could not be sealed: its id does not translate",
            );
            return;
        }
    };

    match runtime
        .record_refused_turn(
            turn,
            conversation,
            refusal.decision(),
            &refusal.to_string(),
            prompt_size_bytes,
        )
        .await
    {
        Ok(receipt) if receipt.is_durable() => {}
        Ok(receipt) => tracing::error!(
            %thread_id,
            %turn_id,
            decision = refusal.decision(),
            ?receipt,
            "refused work was sealed but never reached the disk",
        ),
        Err(error) => tracing::error!(
            %thread_id,
            %turn_id,
            decision = refusal.decision(),
            %error,
            "refused work could not be recorded",
        ),
    }
}
