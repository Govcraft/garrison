//! Sessions that outlive the process.
//!
//! A daemon restarts: it is upgraded, it is bounced by a supervisor, the
//! machine reboots. Without this module every conversation an operator was
//! having is gone at that moment, and so is the record of what the agent did
//! in it. That is unacceptable twice over — the operator loses their work, and
//! the audit trail acquires a gap exactly where a reader most wants
//! continuity.
//!
//! # What is stored, and where
//!
//! acton-ai's [`MemoryStore`](acton_ai::memory::MemoryStore) owns a libSQL
//! database, armed by `[checkpoint]` in `acton-ai.toml`. It holds four things
//! Garrison needs and none it has to reimplement:
//!
//! - the **session**, keyed by the ACP session id itself
//!   ([`ids::session_name`]);
//! - the **conversation**, which is the history the next turn will send;
//! - the **metadata** ([`meta::SessionMeta`]), which is everything else
//!   Garrison must know before it will hand a session back: the root it is
//!   confined to, who it belongs to, and whether a turn was running when the
//!   daemon stopped;
//! - the **turn checkpoint**, written after every provider round, which is
//!   what makes an interrupted turn resumable instead of merely lost.
//!
//! # Fail closed, in one sentence each
//!
//! - The store cannot be reached: no turn starts
//!   ([`TurnRefusal::StoreUnavailable`](crate::admission::TurnRefusal::StoreUnavailable)).
//! - A turn was interrupted: no *other* turn starts on that session until an
//!   operator resumes or abandons it
//!   ([`TurnRefusal::TurnInterrupted`](crate::admission::TurnRefusal::TurnInterrupted)).
//!   Never a silent restart of the work, which would re-execute tools and be
//!   paid for twice.
//!
//! Both rules live in [`keeper::gate_decision`], a pure function, and reach
//! the turn path through the one admission seam every other gate uses.
//!
//! # Where the plane fits
//!
//! Nowhere. Persistence is local, and no turn is ever blocked on a control
//! plane being reachable. [`meta::SessionMeta`] carries the install, tenant
//! and operator a `AgentSession` row wants so that shipping sessions to the
//! fleet view stays an addition rather than a redesign.

pub mod identity;
pub mod ids;
pub mod keeper;
pub mod meta;
pub mod retention;
pub mod store;

pub use identity::{load_or_create_agent_id, CLIENT_CLI, CLIENT_SOCKET};
pub use ids::{acton_turn_id, checkpoint_id_for, session_name, turn_id_for};
pub use keeper::{KeeperSettings, SessionKeeper};
pub use meta::{Attribution, OpenTurn, SessionMeta, SessionStatus};
pub use retention::{plan_retention, RetentionPlan, RetentionPolicy};
pub use store::{SessionStore, StoredSession};

use crate::config::GarrisonConfig;
use crate::error::GarrisonError;
use acton_ai::checkpoint::ResumePolicy;
use acton_ai::facade::ActonAI;
use acton_reactive::prelude::*;

/// Brings session persistence up, or refuses to start.
///
/// Three decisions, in the order they depend on each other:
///
/// 1. **Is a store armed, and does this install require one?** The rule is
///    [`GarrisonConfig::sessions_required`]: an install that answers to a
///    control plane has an agency expecting its sessions to survive, a
///    standalone developer install does not. A required store that is not
///    armed is a refusal to start (exit 2).
/// 2. **Is the resume policy one Garrison can honour?**
///    [`ResumePolicy::ResumeAuto`] is refused, because a turn resumed in the
///    background would settle pending tool calls with no client connected to
///    approve them — which is the one thing a governed agent may never do.
/// 3. **Then** the store facade and the keeper are built, and the keeper runs
///    its first retention sweep.
///
/// Returns `None` when nothing is armed and nothing requires it: the
/// standalone install, whose sessions live in memory exactly as they did
/// before this module existed.
///
/// # Errors
///
/// [`GarrisonErrorKind::Configuration`](crate::error::GarrisonErrorKind::Configuration)
/// when a required store is not armed or the resume policy cannot be
/// honoured, and
/// [`GarrisonErrorKind::Store`](crate::error::GarrisonErrorKind::Store) when
/// this install's agent identity cannot be read or written. All three are
/// refusals to start: restarting does not change any of the answers.
pub async fn spawn(
    runtime: &mut ActorRuntime,
    ai: &ActonAI,
    config: &GarrisonConfig,
) -> Result<Option<(ActorHandle, SessionStore)>, GarrisonError> {
    let Some(handle) = ai.checkpoint_store() else {
        if config.sessions_required() {
            return Err(GarrisonError::configuration(
                "sessions",
                "sessions must survive a restart — a [plane] section is configured, or \
                 [sessions] required = true — and acton-ai.toml arms no session store. Add a \
                 `[checkpoint]` section to acton-ai.toml naming an absolute per-user database \
                 path, or set [sessions] required = false in garrison.toml to run this install \
                 with sessions that die with the process. This is a refusal to start (exit 2), \
                 not a crash: restarting will not change the answer",
            ));
        }
        tracing::warn!(
            "no session store is armed: conversations are lost when this daemon stops. Add a \
             [checkpoint] section to acton-ai.toml to keep them"
        );
        return Ok(None);
    };

    if ai.checkpoint_policy() == Some(ResumePolicy::ResumeAuto) {
        return Err(GarrisonError::configuration(
            "checkpoint.policy",
            "`resume_auto` cannot be honoured by a governed agent: a turn resumed in the \
             background would run its pending tool calls with no client connected to approve \
             them. Set [checkpoint] policy = \"resume_on_request\" in acton-ai.toml, which is \
             what `_garrison/session/resume` drives. This is a refusal to start (exit 2), not \
             a crash: restarting will not change the answer",
        ));
    }

    let agent_id = load_or_create_agent_id(&crate::enrollment::config_dir())?;
    let store = SessionStore::new(handle, agent_id);

    let keeper = SessionKeeper::spawn(
        runtime,
        KeeperSettings {
            store: store.clone(),
            retention: config.sessions.retention(),
        },
    )
    .await;

    tracing::info!(
        retain_days = config.sessions.retain_days,
        "sessions will survive a restart",
    );

    Ok(Some((keeper, store)))
}
