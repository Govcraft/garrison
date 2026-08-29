//! The actor that keeps the anchor current and refuses turns over a broken
//! writer.
//!
//! # It subscribes; it is not told
//!
//! The keeper learns that a turn finished by subscribing to acton-ai's
//! [`TurnLifecycle`] on the runtime's broker, not by a message a session
//! sends it. That is deliberate and is the rule for everything that wants to
//! act at turn end: issue #8's trail shipper wants exactly the same moment,
//! and if each such subsystem were sent its own nudge from `thread.rs` then
//! every one of them would edit the same thirty lines of the turn path and
//! each would have its own idea of what "finished" means. A broadcast has one
//! definition, published by the loop that owns it, and any number of
//! subscribers.
//!
//! # It is a gate
//!
//! The keeper answers [`AdmitTurn`], so it is pushed onto a session's gates in
//! `launch.rs` alongside every other gate and asked through
//! [`crate::admission::admit`]. Its rule is one sentence: **with a strict
//! trail, a writer that has failed an append does not run another turn.**
//! Best-effort trails admit everything, which is what keeps a developer
//! install working exactly as it did before this module existed.
//!
//! A writer that does not answer the gate is refused too. That is the whole
//! point of a strict trail: "I could not find out whether this will be
//! recorded" and "this will not be recorded" have the same consequence for
//! the record, so they get the same answer.
//!
//! # It writes the anchor from a future, and notes the result to itself
//!
//! A `mutate_on` handler cannot touch its model after an await, so the write
//! happens in the returned future and its outcome comes back as
//! [`NoteAnchored`] — the same self-note pattern acton-ai's audit actor uses,
//! and for the same borrow reason. Mailboxes are FIFO, so a `Describe` sent
//! after an anchor write is served after the note is folded.

use crate::admission::{Admission, AdmitTurn, TurnRefusal};
use crate::audit::anchor::{self, Anchor};
use crate::audit::state::{state_for, state_when_unreachable, AuditState};
use crate::protocol::acp;
use crate::protocol::conn::{Describe, StatusPart};
use acton_ai::audit::{AuditDurability, AuditHealth, AuditHealthChanged};
use acton_ai::facade::ActonAI;
use acton_ai::messages::TurnLifecycle;
use acton_reactive::prelude::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long the keeper waits on the audit writer before treating its silence
/// as an answer.
///
/// Comfortably inside [`crate::admission::GATE_DEADLINE`], so a wedged writer
/// produces the audit refusal a client can act on rather than the generic
/// "a gate could not be asked".
pub const WRITER_DEADLINE: Duration = Duration::from_secs(3);

/// Everything the keeper needs, settled once at launch.
#[derive(Clone, Debug)]
pub struct KeeperSettings {
    /// The runtime whose trail is being anchored.
    pub runtime: ActonAI,
    /// The trail on disk, canonicalized.
    pub trail_path: PathBuf,
    /// Where the anchor is written.
    pub anchor_path: PathBuf,
    /// The plane's row id for this install, when it has enrolled.
    pub install: Option<String>,
    /// What an append must promise before a turn may run.
    pub durability: AuditDurability,
}

/// Writes the anchor now and answers with what happened.
///
/// Asked at launch, so the first turn runs over a fresh anchor, and at a
/// clean shutdown, so a stopped daemon leaves the anchor at the head.
#[acton_message]
pub struct AnchorNow;

/// What an anchor attempt produced.
#[acton_message]
pub enum AnchorOutcome {
    /// The anchor was written and now vouches for this head.
    Anchored(Anchor),
    /// It was not, and this is why.
    Failed(String),
}

impl Request for AnchorNow {
    type Response = AnchorOutcome;
}

/// The keeper telling itself how an anchor write went.
#[acton_message]
struct NoteAnchored {
    outcome: AnchorOutcome,
}

/// Keeps the trail's head anchored outside the trail, and gates turns on the
/// writer's health.
#[acton_actor]
pub struct AnchorKeeper {
    /// `None` only in the default value the actor macro requires; every
    /// spawned keeper has settings before it starts.
    settings: Option<KeeperSettings>,
    /// The last anchor written.
    last: Option<Anchor>,
    /// Why the last attempt failed, when one did.
    last_error: Option<String>,
}

impl AnchorKeeper {
    /// Spawns the keeper, subscribed before it starts.
    ///
    /// Subscriptions registered after `start` are silently ignored, which
    /// would leave a keeper that runs happily and anchors nothing.
    pub async fn spawn(runtime: &mut ActorRuntime, settings: KeeperSettings) -> ActorHandle {
        let mut builder = runtime.new_actor_with_name::<Self>("audit_anchor".to_string());

        builder.model.settings = Some(settings);
        configure_handlers(&mut builder);

        builder.handle().subscribe::<TurnLifecycle>().await;
        builder.handle().subscribe::<AuditHealthChanged>().await;

        builder.start().await
    }
}

/// Whether a turn may run, given what the trail promises and how the writer
/// is doing. Pure, and the whole gate rule.
///
/// `health` is `None` when the writer could not be asked, which is a refusal
/// under a strict trail for the same reason a degraded writer is: neither
/// case can promise the turn will be recorded.
#[must_use]
pub fn gate_decision(durability: AuditDurability, health: Option<&AuditHealth>) -> Admission {
    if !durability.is_strict() {
        return Admission::Admit;
    }

    let Some(health) = health else {
        return Admission::Refuse(TurnRefusal::AuditDegraded {
            reason: format!(
                "the audit writer did not answer within {}s, so this turn cannot be promised \
                 a record; the trail is strict, so it is refused rather than run unrecorded",
                WRITER_DEADLINE.as_secs()
            ),
        });
    };

    match state_for(health) {
        AuditState::Healthy | AuditState::Configured => Admission::Admit,
        AuditState::Degraded => Admission::Refuse(TurnRefusal::AuditDegraded {
            reason: degraded_reason(health),
        }),
        AuditState::Disabled => Admission::Refuse(TurnRefusal::AuditDegraded {
            reason: "the trail is configured strict and no audit trail is armed, so nothing \
                     this turn does would be recorded"
                .to_string(),
        }),
    }
}

/// The sentence an operator reads when a turn is refused. Pure.
fn degraded_reason(health: &AuditHealth) -> String {
    let mut reason = format!(
        "the audit writer is degraded: {} append(s) did not reach the disk",
        health.failures
    );
    if let Some(sequence) = health.first_failed_sequence {
        reason.push_str(&format!(", first at sequence {sequence}"));
    }
    if let Some(error) = health.last_error.as_deref() {
        reason.push_str(&format!(" ({error})"));
    }
    reason.push_str(
        ". The trail is strict, so turns are refused until the trail is repaired and the \
         daemon restarted over it; run `garrison-agent audit verify` and keep the trail as \
         evidence",
    );
    reason
}

/// The status part the keeper contributes.
///
/// Pure over plain values rather than over the settings struct, so every
/// state it can report is testable without a runtime to hold.
fn status_part(
    anchor_path: &Path,
    durability: AuditDurability,
    health: Option<&AuditHealth>,
    last: Option<&Anchor>,
    last_error: Option<&str>,
) -> acp::AuditStatus {
    let anchor = acp::AnchorStatus {
        path: anchor_path.display().to_string(),
        sequence: last.map(|anchor| anchor.sequence),
        hash: last.map(|anchor| anchor.hash.clone()),
        anchored_at: last.map(|anchor| anchor.anchored_at.clone()),
        last_error: last_error.map(ToString::to_string),
    };

    let Some(health) = health else {
        return acp::AuditStatus {
            enabled: true,
            state: state_when_unreachable(),
            durability: Some(durability.to_string()),
            chain_head: None,
            sequence: None,
            trail_id: None,
            appended: 0,
            failures: 0,
            first_failed_sequence: None,
            last_error: Some("the audit writer did not answer".to_string()),
            degraded_since: None,
            anchor: Some(anchor),
        };
    };

    acp::AuditStatus {
        enabled: true,
        state: state_for(health),
        durability: Some(durability.to_string()),
        chain_head: Some(health.head.hash.clone()),
        sequence: Some(health.head.sequence),
        trail_id: health.head.trail_id.as_ref().map(ToString::to_string),
        appended: health.appended,
        failures: health.failures,
        first_failed_sequence: health.first_failed_sequence,
        last_error: health.last_error.clone(),
        degraded_since: health.degraded_since.clone(),
        anchor: Some(anchor),
    }
}

/// Asks the writer for its health, treating silence as no answer at all.
///
/// `audit_health()` is a barrier — it asks for the head first, which cannot
/// be served until every append queued before it has finished — so what comes
/// back reflects the outcome of everything recorded so far, not merely what
/// has been sealed.
async fn ask_health(runtime: &ActonAI) -> Option<AuditHealth> {
    match tokio::time::timeout(WRITER_DEADLINE, runtime.audit_health()).await {
        Ok(Ok(health)) => Some(health),
        Ok(Err(error)) => {
            tracing::error!(%error, "the audit writer could not be asked for its health");
            None
        }
        Err(_) => {
            tracing::error!(
                deadline_secs = WRITER_DEADLINE.as_secs(),
                "the audit writer did not answer within its deadline",
            );
            None
        }
    }
}

/// Reads the head and writes the anchor.
///
/// Everything that can go wrong here — an unreachable writer, an unwritable
/// state directory — becomes a message rather than an error, because a
/// failure to anchor must never fail the turn that provoked it. It surfaces
/// in `_garrison/status` as `audit.anchor.lastError`, which is where an
/// operator looks when the anchor stops advancing.
async fn anchor_now(settings: &KeeperSettings) -> AnchorOutcome {
    let head = match settings.runtime.audit_head().await {
        Ok(head) => head,
        Err(error) => {
            return AnchorOutcome::Failed(format!("the trail's head is unknown: {error}"))
        }
    };

    let anchor = Anchor::from_head(
        &settings.trail_path,
        &head,
        settings.install.clone(),
        chrono::Utc::now().to_rfc3339(),
    );

    match anchor::write(&settings.anchor_path, &anchor) {
        Ok(()) => {
            tracing::debug!(
                sequence = anchor.sequence,
                path = %settings.anchor_path.display(),
                "anchored the audit chain head",
            );
            AnchorOutcome::Anchored(anchor)
        }
        Err(error) => AnchorOutcome::Failed(error.to_string()),
    }
}

/// Wires the keeper's handlers.
fn configure_handlers(builder: &mut ManagedActor<Idle, AnchorKeeper>) {
    // The keeper's own address, captured by the anchor futures so they can
    // report back as a message rather than by touching the model after an
    // await.
    let self_handle = builder.handle().clone();

    // Re-anchor at the end of every turn, not only at shutdown. The window in
    // which an attacker could delete entries written past the anchor is
    // exactly the gap between the last anchor and now, so the gap is one turn
    // rather than one session.
    let handle = self_handle.clone();
    builder.mutate_on::<TurnLifecycle>(move |actor, envelope| {
        if !matches!(envelope.message(), TurnLifecycle::TurnFinished { .. }) {
            return Reply::ready();
        }
        let Some(settings) = actor.model.settings.clone() else {
            return Reply::ready();
        };
        let handle = handle.clone();

        Reply::pending(async move {
            let outcome = anchor_now(&settings).await;
            handle.send(NoteAnchored { outcome }).await;
        })
    });

    let handle = self_handle;
    builder.mutate_on::<AnchorNow>(move |actor, envelope| {
        let reply = envelope.reply_envelope();
        let Some(settings) = actor.model.settings.clone() else {
            return Reply::pending(async move {
                reply
                    .send(AnchorOutcome::Failed(
                        "the keeper has no settings".to_string(),
                    ))
                    .await;
            });
        };
        let handle = handle.clone();

        Reply::pending(async move {
            let outcome = anchor_now(&settings).await;
            // The self-note goes out before the reply, so a caller that asks
            // `Describe` after this answers sees the anchor it just took.
            handle
                .send(NoteAnchored {
                    outcome: outcome.clone(),
                })
                .await;
            reply.send(outcome).await;
        })
    });

    builder.mutate_on::<NoteAnchored>(|actor, envelope| {
        match &envelope.message().outcome {
            AnchorOutcome::Anchored(anchor) => {
                actor.model.last = Some(anchor.clone());
                actor.model.last_error = None;
            }
            AnchorOutcome::Failed(error) => {
                tracing::error!(%error, "could not anchor the audit chain head");
                actor.model.last_error = Some(error.clone());
            }
        }
        Reply::ready()
    });

    // The operational alert the issue asks for: one structured error event on
    // the healthy-to-degraded transition, carrying what an operator needs to
    // decide whether to stop the daemon.
    builder.act_on::<AuditHealthChanged>(|_, envelope| {
        let health = &envelope.message().health;
        tracing::error!(
            target: "garrison.audit.degraded",
            failures = health.failures,
            first_failed_sequence = ?health.first_failed_sequence,
            last_error = ?health.last_error,
            degraded_since = ?health.degraded_since,
            durability = %health.durability,
            "the audit writer is degraded; tool calls from here on may not be recorded",
        );
        Reply::ready()
    });

    builder.act_on::<AdmitTurn>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let Some(settings) = actor.model.settings.clone() else {
            return Reply::pending(async move {
                reply.send(Admission::Admit).await;
            });
        };

        Reply::pending(async move {
            let health = ask_health(&settings.runtime).await;
            reply
                .send(gate_decision(settings.durability, health.as_ref()))
                .await;
        })
    });

    builder.act_on::<Describe>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let last = actor.model.last.clone();
        let last_error = actor.model.last_error.clone();
        let Some(settings) = actor.model.settings.clone() else {
            return Reply::pending(async move {
                reply
                    .send(StatusPart::Audit(Box::new(acp::AuditStatus::undescribed(
                        false,
                    ))))
                    .await;
            });
        };

        Reply::pending(async move {
            let health = ask_health(&settings.runtime).await;
            let part = status_part(
                &settings.anchor_path,
                settings.durability,
                health.as_ref(),
                last.as_ref(),
                last_error.as_deref(),
            );
            reply.send(StatusPart::Audit(Box::new(part))).await;
        })
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use acton_ai::audit::{AuditHealthState, ChainHead};

    fn healthy(appended: u64) -> AuditHealth {
        let mut health = AuditHealth::armed(ChainHead::empty(), AuditDurability::Strict);
        health.appended = appended;
        health
    }

    fn degraded() -> AuditHealth {
        let mut health = healthy(4);
        health.state = AuditHealthState::Degraded;
        health.failures = 2;
        health.first_failed_sequence = Some(5);
        health.last_error = Some("Is a directory (os error 21)".to_string());
        health.degraded_since = Some("2026-08-29T10:00:00Z".to_string());
        health
    }

    #[test]
    fn a_best_effort_trail_never_refuses_a_turn() {
        for health in [Some(healthy(0)), Some(degraded()), None] {
            assert_eq!(
                gate_decision(AuditDurability::BestEffort, health.as_ref()),
                Admission::Admit,
                "best effort must not change how an existing install behaves",
            );
        }
    }

    #[test]
    fn a_strict_trail_admits_while_the_writer_is_well() {
        assert_eq!(
            gate_decision(AuditDurability::Strict, Some(&healthy(0))),
            Admission::Admit
        );
        assert_eq!(
            gate_decision(AuditDurability::Strict, Some(&healthy(9))),
            Admission::Admit
        );
    }

    #[test]
    fn a_strict_trail_refuses_once_an_append_has_failed() {
        let Admission::Refuse(TurnRefusal::AuditDegraded { reason }) =
            gate_decision(AuditDurability::Strict, Some(&degraded()))
        else {
            panic!("a degraded strict writer must refuse the turn");
        };

        assert!(reason.contains("2 append(s)"), "{reason}");
        assert!(reason.contains("sequence 5"), "{reason}");
        assert!(reason.contains("Is a directory"), "{reason}");
        assert!(reason.contains("audit verify"), "{reason}");
    }

    #[test]
    fn a_writer_that_does_not_answer_is_itself_a_refusal() {
        let Admission::Refuse(TurnRefusal::AuditDegraded { reason }) =
            gate_decision(AuditDurability::Strict, None)
        else {
            panic!("an unanswered health ask must refuse the turn, not pass it");
        };

        assert!(reason.contains("did not answer"), "{reason}");
    }

    #[test]
    fn a_strict_mode_with_no_trail_refuses_rather_than_pretending() {
        let Admission::Refuse(TurnRefusal::AuditDegraded { .. }) =
            gate_decision(AuditDurability::Strict, Some(&AuditHealth::disabled()))
        else {
            panic!("strict with nothing armed must refuse");
        };
    }

    /// Every status test asks about the same anchor file.
    fn anchor_path() -> &'static Path {
        Path::new("/state/anchor.json")
    }

    #[test]
    fn the_status_reports_configured_before_anything_is_written() {
        let part = status_part(
            anchor_path(),
            AuditDurability::Strict,
            Some(&healthy(0)),
            None,
            None,
        );

        assert_eq!(part.state, AuditState::Configured);
        assert_eq!(part.durability.as_deref(), Some("strict"));
        assert_eq!(part.appended, 0);
        assert!(part.enabled);
        assert_eq!(
            part.anchor.expect("an anchor is always named").sequence,
            None
        );
    }

    #[test]
    fn the_status_reports_healthy_once_the_writer_has_written() {
        let part = status_part(
            anchor_path(),
            AuditDurability::Strict,
            Some(&healthy(3)),
            None,
            None,
        );

        assert_eq!(part.state, AuditState::Healthy);
        assert_eq!(part.appended, 3);
        assert_eq!(part.failures, 0);
    }

    #[test]
    fn a_best_effort_trail_says_so_in_the_status() {
        let part = status_part(
            anchor_path(),
            AuditDurability::BestEffort,
            Some(&healthy(1)),
            None,
            None,
        );

        assert_eq!(part.durability.as_deref(), Some("best_effort"));
    }

    #[test]
    fn a_disabled_writer_reports_disabled_rather_than_absent() {
        let part = status_part(
            anchor_path(),
            AuditDurability::BestEffort,
            Some(&AuditHealth::disabled()),
            None,
            None,
        );

        assert_eq!(part.state, AuditState::Disabled);
    }

    #[test]
    fn the_status_reports_degraded_with_everything_an_operator_needs() {
        let part = status_part(
            anchor_path(),
            AuditDurability::Strict,
            Some(&degraded()),
            None,
            None,
        );

        assert_eq!(part.state, AuditState::Degraded);
        assert_eq!(part.failures, 2);
        assert_eq!(part.first_failed_sequence, Some(5));
        assert_eq!(part.degraded_since.as_deref(), Some("2026-08-29T10:00:00Z"));
        assert!(part.last_error.is_some());
    }

    #[test]
    fn a_writer_that_does_not_answer_is_never_reported_healthy() {
        let part = status_part(anchor_path(), AuditDurability::Strict, None, None, None);

        assert_eq!(part.state, AuditState::Degraded);
        assert_eq!(part.chain_head, None);
        assert!(part
            .last_error
            .expect("the reason is stated")
            .contains("did not answer"));
    }

    #[test]
    fn the_status_carries_the_anchor_and_why_it_last_failed() {
        let anchor = Anchor::from_head(
            Path::new("/trail/audit.jsonl"),
            &ChainHead {
                sequence: 7,
                hash: "abc".to_string(),
                entries: 7,
                trail_id: None,
            },
            None,
            "2026-08-29T11:00:00Z".to_string(),
        );

        let part = status_part(
            anchor_path(),
            AuditDurability::Strict,
            Some(&healthy(7)),
            Some(&anchor),
            Some("read-only file system"),
        );

        let reported = part.anchor.expect("an anchor is always named");
        assert_eq!(reported.sequence, Some(7));
        assert_eq!(reported.hash.as_deref(), Some("abc"));
        assert_eq!(
            reported.anchored_at.as_deref(),
            Some("2026-08-29T11:00:00Z")
        );
        assert_eq!(
            reported.last_error.as_deref(),
            Some("read-only file system")
        );
        assert_eq!(reported.path, "/state/anchor.json");
    }
}
