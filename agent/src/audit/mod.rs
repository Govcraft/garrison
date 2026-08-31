//! Making the audit trail's failures visible, and refusing to run past them.
//!
//! acton-ai owns the trail: it seals the entries, holds the writer's lock,
//! fsyncs when the trail is strict, and reports its own health. None of that
//! is reimplemented here. What this module adds is the three things an
//! *agency deployment* needs that an embedded runtime cannot decide for
//! itself:
//!
//! 1. **An externally anchored head** ([`anchor`]), so deleting the tail of a
//!    trail is detectable. A hash chain cannot notice its own truncation; a
//!    record of where it used to end can.
//! 2. **A four-state answer** ([`state`]) for `_garrison/status`, so an
//!    operator can tell "not recording" from "armed but idle" from "recording"
//!    from "the record is incomplete" without reading a log.
//! 3. **A turn gate** ([`keeper`]), so a strict deployment stops running turns
//!    once the writer has failed, rather than running them unrecorded.
//! 4. **A record of what the gates turned away** ([`seal`]), because the
//!    runtime only records the work it runs, and an install refused all
//!    afternoon must not read like an install nobody touched.
//!
//! [`verify`] is the offline form of the first: `garrison-agent audit verify`
//! answers both the chain question and the anchor question, with a distinct
//! exit code for each.
//!
//! # Where the plane fits, and where it does not
//!
//! Nowhere on this path. Durability is enforced locally, the anchor is
//! written unconditionally, and no turn is ever blocked on a control plane
//! being reachable. Pushing the anchored head to the plane's `AuditChain`
//! belongs to issue #8, which adds a second sink for the value [`anchor`]
//! already computes; [`Anchor`] carries exactly the fields that row wants so
//! that stays an addition rather than a redesign.

pub mod anchor;
pub mod keeper;
pub mod seal;
pub mod state;
pub mod verify;

pub use anchor::{Anchor, AnchorVerdict, HeadComparison, StartupDecision};
pub use keeper::{AnchorKeeper, AnchorNow, AnchorOutcome, KeeperSettings};
pub use seal::seal_refusal;
pub use state::{state_for, AuditState};
pub use verify::{Outcome as VerifyOutcome, VerifyReport};

use crate::config::GarrisonConfig;
use crate::error::GarrisonError;
use acton_ai::facade::ActonAI;
use acton_reactive::prelude::*;

/// Brings the audit subsystem up, or refuses to start.
///
/// Everything the daemon decides about auditing happens here, in this order,
/// because each step depends on the one before:
///
/// 1. **Is a trail required, and is there one?** The rule lives in
///    [`GarrisonConfig::audit_required`]; a required trail that is not armed
///    is a refusal to start (exit 2), because an install that answers to an
///    agency and records nothing is the exact failure an audit prevents.
/// 2. **Does the trail still end where this daemon last saw it end?** The
///    anchor answers that, and a truncated or rewritten trail refuses to
///    start unless the deployment asked for a warning instead.
/// 3. **Then** the keeper spawns and takes a fresh anchor, so the first turn
///    of the process runs over an anchor that is current.
///
/// Returns `None` when nothing is armed and nothing requires it, which is the
/// standalone developer install: no keeper, no gate, no anchor.
///
/// # Errors
///
/// [`GarrisonErrorKind::Configuration`](crate::error::GarrisonErrorKind::Configuration)
/// when a required trail is not armed, or when the trail and the anchor
/// disagree and `[audit] on_anchor_mismatch` is `refuse`. Both are refusals
/// to start: restarting does not change either answer.
pub async fn spawn(
    runtime: &mut ActorRuntime,
    ai: &ActonAI,
    config: &GarrisonConfig,
    install: Option<String>,
) -> Result<Option<ActorHandle>, GarrisonError> {
    let Some(audit) = ai.audit_config() else {
        if config.audit_required() {
            return Err(GarrisonError::configuration(
                "audit",
                "an audit trail is required — a [plane] section is configured, or [audit] \
                 required = true — and acton-ai.toml arms none. Add an `[audit]` section to \
                 acton-ai.toml naming an absolute per-user trail path, or set [audit] \
                 required = false in garrison.toml to run this install unrecorded. This is a \
                 refusal to start (exit 2), not a crash: restarting will not change the answer",
            ));
        }
        tracing::warn!(
            "no audit trail is armed: tool calls are not being recorded. Add an [audit] \
             section to acton-ai.toml to record them"
        );
        return Ok(None);
    };

    // Canonical from here on, so the anchor names the same file whichever
    // directory the daemon was started from.
    let trail_path = audit
        .path()
        .canonicalize()
        .unwrap_or_else(|_| audit.path().to_path_buf());
    let durability = config.audit.durability_for(ai.audit_durability());
    let anchor_path = config.audit.anchor_path();

    let head = ai.audit_head().await.map_err(|error| {
        GarrisonError::configuration(
            "audit",
            format!("the audit trail's head could not be read: {error}"),
        )
    })?;
    let anchored = anchor::read(&anchor_path)?;
    let verdict = anchor::verdict(anchored.as_ref(), &trail_path, &head);

    match anchor::startup_decision(&verdict, config.audit.on_anchor_mismatch) {
        StartupDecision::Proceed => {}
        StartupDecision::Warn(message) => tracing::warn!(
            trail = %trail_path.display(),
            anchor = %anchor_path.display(),
            "{message}"
        ),
        StartupDecision::Refuse(message) => {
            return Err(GarrisonError::configuration("audit.anchor", message))
        }
    }

    let keeper = AnchorKeeper::spawn(
        runtime,
        KeeperSettings {
            runtime: ai.clone(),
            trail_path,
            anchor_path,
            install,
            durability,
        },
    )
    .await;

    // Before the first turn, so a daemon that dies immediately still leaves
    // an anchor at the head it started from.
    match keeper.ask(AnchorNow).await {
        Ok(AnchorOutcome::Anchored(anchor)) => tracing::info!(
            sequence = anchor.sequence,
            durability = %durability,
            "the audit chain head is anchored",
        ),
        Ok(AnchorOutcome::Failed(error)) => {
            tracing::error!(%error, "the audit chain head could not be anchored at startup");
        }
        Err(error) => tracing::error!(?error, "the audit anchor keeper did not answer"),
    }

    Ok(Some(keeper))
}
