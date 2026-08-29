//! The actor that refuses turns the store cannot stand behind, and sweeps
//! what the store should no longer hold.
//!
//! # It is a gate
//!
//! The keeper answers [`AdmitTurn`], so it is pushed onto a session's gates in
//! `launch.rs` alongside every other gate and asked through
//! [`crate::admission::admit`]. Two sentences are its whole rule:
//!
//! - **A store that cannot be asked does not admit a turn.** A turn that ran
//!   anyway would produce an exchange nothing recorded, and the operator
//!   would find it gone at the next restart. That is
//!   [`TurnRefusal::StoreUnavailable`].
//! - **A session holding an interrupted turn does not start a second one.**
//!   The half-done turn is resumed or abandoned first, deliberately, by
//!   somebody. That is [`TurnRefusal::TurnInterrupted`], and it is what stops
//!   a restart from silently re-running work an operator already paid for.
//!
//! A resume is admitted, because a resumed turn carries the very identifier
//! the record names: the gate refuses a turn that is *different* from the one
//! left open, not the one picking it up.
//!
//! # It is a describer
//!
//! [`Describe`] answers with the store's health, how many sessions survive a
//! restart, how many of them are blocked on an interrupted turn, and the last
//! checkpoint written. That is the section an operator reads when prompts
//! start coming back with `-32018`.
//!
//! # It sweeps
//!
//! Retention runs at startup and then on a schedule, each tick re-arming the
//! next from inside the handler so the timer lives in the model and dies with
//! the actor. What to delete is [`plan_retention`]'s decision, made from
//! values; this actor only carries it out.

use crate::admission::{Admission, AdmitTurn, TurnRefusal};
use crate::protocol::acp;
use crate::protocol::conn::{Describe, StatusPart};
use crate::session::meta::SessionMeta;
use crate::session::retention::{plan_retention, RetentionPlan, RetentionPolicy};
use crate::session::store::{SessionStore, StoredSession};
use crate::types::TurnId;
use acton_ai::checkpoint::CheckpointRecord;
use acton_reactive::prelude::*;

/// Everything the keeper needs, settled once at launch.
#[derive(Clone, Debug)]
pub struct KeeperSettings {
    /// The store every answer here comes from.
    pub store: SessionStore,
    /// How long sessions live, and how often that is enforced.
    pub retention: RetentionPolicy,
}

/// Runs the retention sweep now, and arms the next one.
#[acton_message]
struct SweepRetention;

/// The keeper telling itself how a sweep went.
#[acton_message]
struct NoteSwept {
    at: String,
    error: Option<String>,
}

/// What the store holds, reduced to the three numbers the status reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreSnapshot {
    /// Sessions this agent can read back.
    pub sessions: usize,
    /// Of those, how many hold a turn a restart interrupted.
    pub interrupted: usize,
    /// The most recent checkpoint written, by identifier.
    pub last_checkpoint: Option<String>,
}

/// Keeps sessions durable: refuses turns the store cannot stand behind, and
/// removes what retention says should be gone.
#[acton_actor]
pub struct SessionKeeper {
    /// `None` only in the default value the actor macro requires; every
    /// spawned keeper has settings before it starts.
    settings: Option<KeeperSettings>,
    /// When the sweep last ran.
    last_swept: Option<String>,
    /// What the store last failed at, when it has failed.
    last_error: Option<String>,
    /// The next sweep, held so the schedule dies with the actor.
    next_sweep: Option<ScheduledSend>,
}

impl SessionKeeper {
    /// Spawns the keeper and runs the first sweep.
    pub async fn spawn(runtime: &mut ActorRuntime, settings: KeeperSettings) -> ActorHandle {
        let mut builder = runtime.new_actor_with_name::<Self>("session_keeper".to_string());

        builder.model.settings = Some(settings);
        configure_handlers(&mut builder);

        let handle = builder.start().await;

        // At startup rather than only on the first tick: a daemon that has
        // been down for a month should not carry the month's expired sessions
        // until tomorrow.
        handle.send(SweepRetention).await;
        handle
    }
}

/// Whether a turn may start, given what the store said about its session.
///
/// Pure, and the whole gate rule. A store that answered with an error has not
/// said the turn is safe to run, so it is refused — the same reasoning the
/// audit gate applies to a writer that will not answer.
#[must_use]
pub fn gate_decision(
    resolved: &Result<Option<StoredSession>, crate::error::GarrisonError>,
    turn_id: &TurnId,
) -> Admission {
    let Ok(found) = resolved else {
        return Admission::Refuse(TurnRefusal::StoreUnavailable);
    };

    let Some(session) = found else {
        // Nothing stored under that name. The session is running out of
        // memory alone, which is what a session created before the store came
        // up looks like; there is no interrupted turn to protect.
        return Admission::Admit;
    };

    match interrupted_other_than(&session.meta, turn_id) {
        Some(open) => Admission::Refuse(TurnRefusal::TurnInterrupted { turn_id: open }),
        None => Admission::Admit,
    }
}

/// The interrupted turn blocking this one, if it is not this one.
///
/// Pure. A resume runs under the identifier the record already names, so it
/// passes; anything else is a second turn on a session whose first has not
/// been settled.
#[must_use]
fn interrupted_other_than(meta: &SessionMeta, turn_id: &TurnId) -> Option<TurnId> {
    meta.interrupted()
        .filter(|open| open.turn_id != *turn_id)
        .map(|open| open.turn_id.clone())
}

/// What the store holds, counted. Pure.
#[must_use]
pub fn snapshot(sessions: &[StoredSession], checkpoints: &[CheckpointRecord]) -> StoreSnapshot {
    StoreSnapshot {
        sessions: sessions.len(),
        interrupted: sessions
            .iter()
            .filter(|session| session.meta.interrupted().is_some())
            .count(),
        // Checkpoint identifiers are UUIDv7-backed, so the greatest is the
        // most recently minted.
        last_checkpoint: checkpoints.iter().map(|record| record.id.to_string()).max(),
    }
}

/// The status the keeper contributes.
///
/// Pure over plain values, so every state it can report — including the one
/// where the store did not answer at all — is testable without a database.
#[must_use]
pub fn status_part(
    retention: RetentionPolicy,
    snapshot: Option<&StoreSnapshot>,
    last_swept: Option<&str>,
    last_error: Option<&str>,
) -> acp::SessionStoreStatus {
    let counted = snapshot.cloned().unwrap_or_default();

    acp::SessionStoreStatus {
        healthy: snapshot.is_some(),
        sessions: counted.sessions,
        interrupted: counted.interrupted,
        last_checkpoint: counted.last_checkpoint,
        retain_days: retention.retain_days,
        last_swept: last_swept.map(ToString::to_string),
        last_error: last_error.map(ToString::to_string),
    }
}

/// Reads the store, or says why it could not be read.
async fn probe(store: &SessionStore) -> Result<StoreSnapshot, crate::error::GarrisonError> {
    let sessions = store.list().await?;
    let checkpoints = store.checkpoints().await?;
    Ok(snapshot(&sessions, &checkpoints))
}

/// Carries out a plan, and answers with what could not be done.
///
/// A failure on one deletion does not stop the rest: the next sweep will come
/// back to it, and one wedged row must not keep a disk filling.
async fn apply(store: &SessionStore, plan: &RetentionPlan) -> Option<String> {
    let mut failures = Vec::new();

    for name in &plan.sessions {
        if let Err(error) = store.delete(name).await {
            failures.push(error.to_string());
        }
    }
    for id in &plan.checkpoints {
        if let Err(error) = store.delete_checkpoint(id).await {
            failures.push(error.to_string());
        }
    }

    if failures.is_empty() {
        if !plan.is_empty() {
            tracing::info!(
                sessions = plan.sessions.len(),
                checkpoints = plan.checkpoints.len(),
                "retention swept expired sessions",
            );
        }
        None
    } else {
        Some(failures.join("; "))
    }
}

/// Plans and runs one sweep.
async fn sweep(settings: &KeeperSettings) -> Option<String> {
    let sessions = match settings.store.list().await {
        Ok(sessions) => sessions,
        Err(error) => return Some(error.to_string()),
    };
    let checkpoints = match settings.store.checkpoints().await {
        Ok(checkpoints) => checkpoints,
        Err(error) => return Some(error.to_string()),
    };

    let plan = plan_retention(
        chrono::Utc::now(),
        &sessions,
        &checkpoints,
        &settings.retention,
    );
    apply(&settings.store, &plan).await
}

/// Wires the keeper's handlers.
fn configure_handlers(builder: &mut ManagedActor<Idle, SessionKeeper>) {
    builder.mutate_on::<SweepRetention>(|actor, _| {
        let Some(settings) = actor.model.settings.clone() else {
            return Reply::ready();
        };

        // Re-armed here, on the loop, so the schedule is owned by the model
        // and stops when the actor does.
        actor.model.next_sweep = Some(
            actor
                .handle()
                .send_after(SweepRetention, settings.retention.sweep_interval),
        );

        let handle = actor.handle().clone();
        Reply::pending(async move {
            let error = sweep(&settings).await;
            handle
                .send(NoteSwept {
                    at: chrono::Utc::now().to_rfc3339(),
                    error,
                })
                .await;
        })
    });

    builder.mutate_on::<NoteSwept>(|actor, envelope| {
        let message = envelope.message();
        actor.model.last_swept = Some(message.at.clone());
        if let Some(error) = &message.error {
            tracing::warn!(%error, "the session retention sweep did not finish");
        }
        actor.model.last_error.clone_from(&message.error);
        Reply::ready()
    });

    builder.act_on::<AdmitTurn>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let request = envelope.message().clone();
        let Some(settings) = actor.model.settings.clone() else {
            // A keeper with no store is a keeper that was never armed, and an
            // unarmed gate has nothing to say about a turn.
            return Reply::pending(async move {
                reply.send(Admission::Admit).await;
            });
        };

        Reply::pending(async move {
            let resolved = settings.store.resolve(&request.thread_id).await;
            if let Err(error) = &resolved {
                tracing::error!(%error, thread_id = %request.thread_id, "the session store did not answer the gate");
            }
            reply
                .send(gate_decision(&resolved, &request.turn_id))
                .await;
        })
    });

    builder.act_on::<Describe>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let last_swept = actor.model.last_swept.clone();
        let noted = actor.model.last_error.clone();
        let Some(settings) = actor.model.settings.clone() else {
            return Reply::ready();
        };

        Reply::pending(async move {
            let (snapshot, error) = match probe(&settings.store).await {
                Ok(snapshot) => (Some(snapshot), noted),
                Err(error) => (None, Some(error.to_string())),
            };
            reply
                .send(StatusPart::SessionStore(status_part(
                    settings.retention,
                    snapshot.as_ref(),
                    last_swept.as_deref(),
                    error.as_deref(),
                )))
                .await;
        })
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GarrisonError;
    use acton_ai::types::ConversationId;
    use std::path::PathBuf;

    fn stored(meta: SessionMeta) -> StoredSession {
        StoredSession {
            name: "thread_a".to_string(),
            meta,
            created_at: "2026-06-01 09:00:00".to_string(),
            last_active: "2026-06-01 09:00:00".to_string(),
        }
    }

    fn meta() -> SessionMeta {
        SessionMeta::opening(
            ConversationId::new(),
            PathBuf::from("/srv/work"),
            crate::session::identity::CLIENT_SOCKET,
        )
    }

    #[test]
    fn a_store_that_cannot_be_asked_refuses_the_turn() {
        let unreachable: Result<Option<StoredSession>, GarrisonError> =
            Err(GarrisonError::store("resolve a session", "no answer"));

        assert_eq!(
            gate_decision(&unreachable, &TurnId::new()),
            Admission::Refuse(TurnRefusal::StoreUnavailable),
            "a turn nothing can record is a turn nobody admitted",
        );
    }

    #[test]
    fn a_session_the_store_has_never_seen_is_admitted() {
        assert_eq!(gate_decision(&Ok(None), &TurnId::new()), Admission::Admit);
    }

    #[test]
    fn an_idle_stored_session_is_admitted() {
        assert_eq!(
            gate_decision(&Ok(Some(stored(meta()))), &TurnId::new()),
            Admission::Admit
        );
    }

    #[test]
    fn a_session_holding_an_interrupted_turn_refuses_a_new_one() {
        let interrupted = TurnId::new();
        let mut meta = meta();
        meta.open(
            interrupted.clone(),
            "2026-06-01T09:00:00Z".to_string(),
            "keep going".to_string(),
        );

        assert_eq!(
            gate_decision(&Ok(Some(stored(meta))), &TurnId::new()),
            Admission::Refuse(TurnRefusal::TurnInterrupted {
                turn_id: interrupted
            }),
        );
    }

    #[test]
    fn the_interrupted_turn_is_admitted_when_it_is_the_one_being_resumed() {
        let interrupted = TurnId::new();
        let mut meta = meta();
        meta.open(
            interrupted.clone(),
            "2026-06-01T09:00:00Z".to_string(),
            "keep going".to_string(),
        );

        assert_eq!(
            gate_decision(&Ok(Some(stored(meta))), &interrupted),
            Admission::Admit,
            "a resume is the settling of that turn, not a second one",
        );
    }

    #[test]
    fn a_store_that_did_not_answer_is_reported_as_unhealthy() {
        let status = status_part(
            RetentionPolicy::default(),
            None,
            None,
            Some("the store did not answer"),
        );

        assert!(!status.healthy);
        assert_eq!(status.sessions, 0);
        assert_eq!(
            status.last_error.as_deref(),
            Some("the store did not answer")
        );
    }

    #[test]
    fn the_status_counts_sessions_and_the_ones_blocked_on_a_turn() {
        let mut blocked = meta();
        blocked.open(TurnId::new(), "then".to_string(), "go".to_string());

        let counted = snapshot(&[stored(meta()), stored(blocked)], &[]);
        let status = status_part(RetentionPolicy::default(), Some(&counted), None, None);

        assert!(status.healthy);
        assert_eq!(status.sessions, 2);
        assert_eq!(status.interrupted, 1);
        assert_eq!(status.retain_days, 30);
    }

    #[test]
    fn nothing_stored_reports_no_last_checkpoint() {
        assert_eq!(snapshot(&[], &[]), StoreSnapshot::default());
    }
}
