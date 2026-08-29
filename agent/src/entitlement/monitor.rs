//! The actor that holds this install's seat standing, and gates turns on it.
//!
//! # It answers from what it knows, and never from the network
//!
//! [`AdmitTurn`] is answered out of the standing in the model, in one message
//! pass, with no await on the plane. That is not an optimization; it is what
//! keeps the two refusals distinguishable. A gate has five seconds
//! ([`crate::admission::GATE_DEADLINE`]) to answer, and a seat check is three
//! plane calls behind an exchange. A gate that went to the network on the
//! turn path would, on a slow plane, blow that deadline and come back as
//! "a gate could not be asked" — collapsing "your seat was revoked" and
//! "the plane is unreachable" into one generic failure, which is the exact
//! outcome this issue exists to prevent.
//!
//! Freshness is the timer's job instead. [`Refresh`] runs on
//! `send_every(.., Cadence::FixedDelay)`, so a slow check delays the next one
//! rather than stacking behind it, and [`verdict::admit`] decides whether
//! what the timer last learned is still worth spending.
//!
//! # A turn in flight is not grandfathered
//!
//! When a refresh turns an admitting standing into a refusing one, the
//! monitor broadcasts [`EntitlementLost`] on the runtime's broker. Sessions
//! subscribe to it and end the turn they are running with that refusal, so a
//! revocation reaches a turn that has already started rather than only the
//! next one. A broadcast rather than a message from `thread.rs`, for the same
//! reason the audit keeper subscribes to turn ends: one publisher, any number
//! of subscribers, and no subsystem editing the turn path to be told.
//!
//! # Fail closed
//!
//! Every path that cannot produce an answer produces a refusal. No standing
//! is a refusal. A standing past its grace is a refusal. A monitor with no
//! plane handle — which cannot happen through [`SeatMonitor::spawn`] — is a
//! refusal. The one thing that is never a refusal is a plane that is simply
//! slow to answer a *refresh*, because that is what the grace window is for.

use std::time::Duration;

use acton_reactive::prelude::*;
use chrono::{DateTime, Utc};

use crate::admission::{Admission, AdmitTurn, TurnRefusal};
use crate::protocol::acp::EntitlementStatus;
use crate::protocol::conn::{Describe, StatusPart};

use super::verdict::{self, SeatAdmission, Standing, Verdict};
use super::{fetch, store};

/// Everything the monitor is given once and never changes.
#[derive(Clone, Debug)]
pub struct MonitorSettings {
    /// The daemon's credential holder. Every plane call goes through it.
    pub plane: ActorHandle,
    /// The plane's origin, named in a refusal so an operator knows which one.
    pub plane_url: String,
    /// How often the standing is refreshed.
    pub interval: Duration,
    /// The deployment's ceiling on offline grace, when it set one. It may
    /// only shorten the table's window; see [`verdict::grace_period`].
    pub grace_cap: Option<Duration>,
    /// Where the standing is cached across restarts.
    pub cache: std::path::PathBuf,
}

/// Refreshes the standing from the plane.
///
/// Sent by the timer, and once at launch. A refresh already in flight
/// swallows another, so a stalled plane cannot queue a backlog of checks.
#[acton_message]
pub struct Refresh;

/// Waits for the standing to be current, and answers with it.
///
/// Used once, at launch, so the daemon knows whether it holds a seat before
/// it accepts a connection. Askers are parked behind the in-flight refresh
/// rather than starting another.
#[acton_message]
pub struct CheckNow;

impl Request for CheckNow {
    type Response = EntitlementStatus;
}

/// The monitor telling itself how a refresh went.
///
/// The self-note pattern the audit keeper uses, and for the same reason: a
/// `mutate_on` handler cannot touch its model after an await, so the network
/// result comes back as a message.
#[acton_message]
struct Refreshed {
    outcome: Result<Box<Standing>, String>,
}

/// This install no longer holds a seat, and a turn in flight must stop.
///
/// Broadcast on the runtime's broker. Carries the refusal already in the
/// admission vocabulary so a subscriber ends its turn with the same words a
/// refused `session/prompt` would have carried.
#[acton_message]
pub struct EntitlementLost {
    /// Why, in the form the protocol reports.
    pub refusal: TurnRefusal,
}

/// The daemon's seat standing, and the gate that spends it.
///
/// `settings` is `None` only in the `Default` value the actor macro requires.
/// Every handler treats that as a refusal rather than panicking, which is the
/// fail-closed reading of a monitor that was never told where the plane is.
#[acton_actor]
pub struct SeatMonitor {
    settings: Option<MonitorSettings>,
    standing: Option<Standing>,
    last_error: Option<String>,
    refreshing: bool,
    parked: Vec<OutboundEnvelope>,
    schedule: Option<ScheduledSend>,
    checked_count: u64,
    next_check_at: Option<DateTime<Utc>>,
}

impl SeatMonitor {
    /// Spawns the monitor with whatever standing survived the last run.
    ///
    /// Subscriptions are not needed here — the monitor publishes rather than
    /// listens — but the timer is armed and the first refresh fired before
    /// the handle is returned, so a caller that immediately asks
    /// [`CheckNow`] is parked behind a check that is already running.
    pub async fn spawn(runtime: &mut ActorRuntime, settings: MonitorSettings) -> ActorHandle {
        let mut builder = runtime.new_actor_with_name::<Self>("seat_monitor".to_string());

        builder.model.standing = store::load(&settings.cache);
        if let Some(standing) = &builder.model.standing {
            tracing::info!(
                checked_at = %standing.checked_at,
                impact = %standing.impact,
                "a cached seat standing was restored; the plane will be asked again now"
            );
        }
        builder.model.settings = Some(settings);
        configure_handlers(&mut builder);

        let handle = builder.start().await;
        handle.send(Refresh).await;
        handle
    }
}

/// Wires the monitor's handlers.
fn configure_handlers(builder: &mut ManagedActor<Idle, SeatMonitor>) {
    let self_handle = builder.handle().clone();

    let handle = self_handle.clone();
    builder.mutate_on::<Refresh>(move |actor, _| {
        let Some(settings) = actor.model.settings.clone() else {
            return Reply::ready();
        };

        // Arm the repeating tick on the first refresh rather than at spawn,
        // so there is exactly one place the cadence is decided.
        if actor.model.schedule.is_none() {
            actor.model.schedule = Interval::new(settings.interval)
                .map(|every| handle.send_every(Refresh, every, Cadence::FixedDelay));
        }
        actor.model.next_check_at = next_check_at(Utc::now(), settings.interval);

        if actor.model.refreshing {
            return Reply::ready();
        }
        actor.model.refreshing = true;

        let handle = handle.clone();
        Reply::pending(async move {
            let outcome = run_check(&settings).await;
            handle.send(Refreshed { outcome }).await;
        })
    });

    let handle = self_handle.clone();
    builder.mutate_on::<Refreshed>(move |actor, envelope| {
        let outcome = envelope.message().outcome.clone();
        actor.model.refreshing = false;

        let now = Utc::now();
        let before = admission_of(&actor.model, now);

        match outcome {
            Ok(standing) => {
                actor.model.last_error = None;
                actor.model.checked_count += 1;
                actor.model.standing = Some(*standing);
                if let Some((settings, standing)) =
                    actor.model.settings.as_ref().zip(actor.model.standing.as_ref())
                {
                    store::save(&settings.cache, standing);
                }
                announce(&actor.model);
            }
            Err(error) => {
                tracing::warn!(%error, "the seat standing could not be refreshed");
                actor.model.last_error = Some(error);
            }
        }

        let after = admission_of(&actor.model, now);
        let lost = lost_entitlement(&before, &after, actor.model.plane_url());
        let status = describe(&actor.model, now);
        let waiting = std::mem::take(&mut actor.model.parked);
        let handle = handle.clone();

        Reply::pending(async move {
            if let Some(refusal) = lost {
                tracing::warn!(%refusal, "this install lost its entitlement; turns in flight end now");
                handle.broadcast(EntitlementLost { refusal }).await;
            }
            for reply in waiting {
                reply.send(status.clone()).await;
            }
        })
    });

    // The gate. One message pass, no await on the network: see the module
    // docs on why a seat check must never happen on the turn path.
    builder.mutate_on::<AdmitTurn>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let answer = gate_decision(&actor.model, Utc::now());

        // A standing that has gone stale is worth chasing, but the answer
        // above stands: this turn is decided by what is known now.
        let stale = !verdict::is_fresh(
            actor.model.standing.as_ref(),
            actor.model.interval(),
            Utc::now(),
        );
        let self_envelope = if stale { actor.new_envelope() } else { None };

        Reply::pending(async move {
            if let Some(envelope) = self_envelope {
                envelope.send(Refresh).await;
            }
            reply.send(answer).await;
        })
    });

    builder.mutate_on::<CheckNow>(|actor, envelope| {
        let reply = envelope.reply_envelope();

        if actor.model.refreshing {
            actor.model.parked.push(reply);
            return Reply::ready();
        }

        let status = describe(&actor.model, Utc::now());
        Reply::pending(async move {
            reply.send(status).await;
        })
    });

    builder.mutate_on::<Describe>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let part = StatusPart::Entitlement(describe(&actor.model, Utc::now()));
        Reply::pending(async move {
            reply.send(part).await;
        })
    });

    builder.before_stop(|actor| {
        // A monitor that has stopped must not leave a timer waking a mailbox
        // nobody is reading.
        if let Some(schedule) = actor.model.schedule.as_ref() {
            schedule.cancel();
        }
        async {}
    });
}

impl SeatMonitor {
    /// The refresh cadence, or a minute when the monitor was never told one.
    fn interval(&self) -> Duration {
        self.settings
            .as_ref()
            .map_or(Duration::from_secs(60), |settings| settings.interval)
    }

    /// The plane this monitor speaks for, for a refusal that names it.
    fn plane_url(&self) -> &str {
        self.settings
            .as_ref()
            .map_or("the control plane", |settings| settings.plane_url.as_str())
    }
}

/// What the seat rule says about this model right now. Pure over the model.
fn admission_of(model: &SeatMonitor, now: DateTime<Utc>) -> SeatAdmission {
    verdict::admit(model.standing.as_ref(), model.last_error.as_deref(), now)
}

/// The gate's answer. Pure over the model, which is what makes it testable
/// without a plane, a socket, or a clock that moves.
fn gate_decision(model: &SeatMonitor, now: DateTime<Utc>) -> Admission {
    if model.settings.is_none() {
        return Admission::Refuse(TurnRefusal::PlaneUnavailable {
            reason: "the seat monitor was never told where the control plane is, so no seat \
                     can be confirmed"
                .to_string(),
        });
    }

    match verdict::turn_refusal(&admission_of(model, now), model.plane_url()) {
        Some(refusal) => Admission::Refuse(refusal),
        None => Admission::Admit,
    }
}

/// The refusal to broadcast when a turn in flight must stop. Pure.
///
/// Only a transition matters. Broadcasting on every refresh while a seat
/// stays revoked would cancel each new turn twice: once by the gate that
/// refused it and once by a broadcast about a state nothing changed.
fn lost_entitlement(
    before: &SeatAdmission,
    after: &SeatAdmission,
    plane_url: &str,
) -> Option<TurnRefusal> {
    match (before, after) {
        (SeatAdmission::Admit { .. }, other) => verdict::turn_refusal(other, plane_url),
        _ => None,
    }
}

/// The status part this monitor contributes. Pure over the model.
fn describe(model: &SeatMonitor, now: DateTime<Utc>) -> EntitlementStatus {
    let admission = admission_of(model, now);
    let (state, reason) = match &admission {
        SeatAdmission::Admit { .. } => ("entitled", None),
        SeatAdmission::Refuse(refusal) => (refusal.kind(), Some(refusal.to_string())),
        SeatAdmission::Unavailable { .. } if model.standing.is_none() => ("unchecked", None),
        SeatAdmission::Unavailable { .. } => ("unavailable", None),
    };

    let seat = model
        .standing
        .as_ref()
        .and_then(|standing| match &standing.verdict {
            Verdict::Entitled { seat, .. } => Some(seat.clone()),
            Verdict::Refused(_) => None,
        });
    let tier = match &admission {
        SeatAdmission::Admit { tier } => Some(tier.to_string()),
        _ => None,
    };

    EntitlementStatus {
        state: state.to_string(),
        seat,
        tier,
        reason,
        impact_level: model
            .standing
            .as_ref()
            .map(|standing| standing.impact.to_string()),
        checked_at: model
            .standing
            .as_ref()
            .map(|standing| stamp(standing.checked_at)),
        grace_secs: model.standing.as_ref().map(|standing| standing.grace_secs),
        grace_until: model
            .standing
            .as_ref()
            .and_then(Standing::grace_until)
            .map(stamp),
        next_check_at: model.next_check_at.map(stamp),
        check_interval_secs: model.interval().as_secs(),
        checks: model.checked_count,
        last_error: model.last_error.clone(),
    }
}

/// When the timer will look again. Pure.
fn next_check_at(now: DateTime<Utc>, interval: Duration) -> Option<DateTime<Utc>> {
    now.checked_add_signed(chrono::TimeDelta::seconds(
        i64::try_from(interval.as_secs()).unwrap_or(i64::MAX),
    ))
}

/// RFC 3339 to the second, matching every other timestamp in the status.
fn stamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Says what the plane just decided, once per refresh, at a level an operator
/// can leave on.
fn announce(model: &SeatMonitor) {
    match model.standing.as_ref().map(|standing| &standing.verdict) {
        Some(Verdict::Entitled { seat, tier }) => tracing::info!(
            %seat,
            %tier,
            grace_secs = model.standing.as_ref().map_or(0, |standing| standing.grace_secs),
            "this install holds an active seat"
        ),
        Some(Verdict::Refused(refusal)) => {
            tracing::warn!(kind = refusal.kind(), "{refusal}");
        }
        None => {}
    }
}

/// One whole check, bounded so a plane that never answers cannot hold the
/// refresh open forever.
async fn run_check(settings: &MonitorSettings) -> Result<Box<Standing>, String> {
    let check = fetch::check(
        &settings.plane,
        &settings.plane_url,
        settings.grace_cap,
        Utc::now(),
    );

    match tokio::time::timeout(fetch::CHECK_DEADLINE, check).await {
        Ok(Ok(standing)) => Ok(Box::new(standing)),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(format!(
            "the control plane did not answer a seat check within {}s",
            fetch::CHECK_DEADLINE.as_secs()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entitlement::verdict::{ImpactLevel, Refusal, Tier};

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .expect("a fixed instant")
            .with_timezone(&Utc)
    }

    fn now() -> DateTime<Utc> {
        at("2026-08-29T12:00:00Z")
    }

    fn model(standing: Option<Standing>, last_error: Option<&str>) -> SeatMonitor {
        SeatMonitor {
            settings: Some(MonitorSettings {
                plane: ActorHandle::default(),
                plane_url: "https://plane.test".to_string(),
                interval: Duration::from_secs(60),
                grace_cap: None,
                cache: std::path::PathBuf::from("/nonexistent/entitlement.json"),
            }),
            standing,
            last_error: last_error.map(ToString::to_string),
            refreshing: false,
            parked: Vec::new(),
            schedule: None,
            checked_count: 1,
            next_check_at: Some(at("2026-08-29T12:01:00Z")),
        }
    }

    fn entitled(checked_at: DateTime<Utc>, grace_secs: u64) -> Standing {
        Standing {
            verdict: Verdict::Entitled {
                seat: "seat_01".to_string(),
                tier: Tier::Standard,
            },
            checked_at,
            grace_secs,
            impact: ImpactLevel::FedrampHigh,
        }
    }

    fn revoked(checked_at: DateTime<Utc>) -> Standing {
        Standing {
            verdict: Verdict::Refused(Refusal::SeatRevoked {
                reason: "offboarded".to_string(),
                revoked_at: Some("2026-08-29T11:00:00Z".to_string()),
            }),
            checked_at,
            grace_secs: 0,
            impact: ImpactLevel::FedrampHigh,
        }
    }

    #[test]
    fn a_live_seat_admits_the_turn() {
        let model = model(Some(entitled(now(), 4 * 3600)), None);

        assert_eq!(gate_decision(&model, now()), Admission::Admit);
    }

    #[test]
    fn a_revoked_seat_refuses_under_the_seat_code() {
        let model = model(Some(revoked(now())), None);

        let Admission::Refuse(TurnRefusal::Seat { reason }) = gate_decision(&model, now()) else {
            panic!("a revoked seat must refuse as a seat");
        };
        assert!(reason.contains("offboarded"));
    }

    #[test]
    fn an_exhausted_grace_refuses_under_the_plane_code() {
        let model = model(
            Some(entitled(at("2026-08-29T07:00:00Z"), 4 * 3600)),
            Some("connection refused"),
        );

        let Admission::Refuse(TurnRefusal::PlaneUnavailable { reason }) =
            gate_decision(&model, now())
        else {
            panic!("an exhausted grace must refuse as an unreachable plane");
        };
        assert!(reason.contains("https://plane.test"));
        assert!(reason.contains("connection refused"));
    }

    #[test]
    fn a_daemon_that_has_never_reached_the_plane_refuses_its_first_turn() {
        let model = model(None, Some("connection refused"));

        assert!(matches!(
            gate_decision(&model, now()),
            Admission::Refuse(TurnRefusal::PlaneUnavailable { .. })
        ));
    }

    #[test]
    fn a_monitor_that_was_never_configured_refuses_everything() {
        let mut model = model(Some(entitled(now(), 4 * 3600)), None);
        model.settings = None;

        assert!(
            matches!(
                gate_decision(&model, now()),
                Admission::Refuse(TurnRefusal::PlaneUnavailable { .. })
            ),
            "a monitor with no plane cannot confirm a seat, so it says no"
        );
    }

    #[test]
    fn losing_a_seat_mid_turn_is_broadcast_once() {
        let before = SeatAdmission::Admit {
            tier: Tier::Standard,
        };
        let after = SeatAdmission::Refuse(Refusal::SeatRevoked {
            reason: "offboarded".to_string(),
            revoked_at: None,
        });

        assert!(matches!(
            lost_entitlement(&before, &after, "https://plane.test"),
            Some(TurnRefusal::Seat { .. })
        ));
    }

    #[test]
    fn a_seat_that_was_already_gone_is_not_broadcast_again() {
        let refusal = SeatAdmission::Refuse(Refusal::NoSeat);

        assert_eq!(
            lost_entitlement(&refusal, &refusal, "https://plane.test"),
            None,
            "a state that did not change cancels nothing"
        );
    }

    #[test]
    fn a_grace_running_out_mid_turn_also_ends_the_turn() {
        let before = SeatAdmission::Admit {
            tier: Tier::Standard,
        };
        let after = SeatAdmission::Unavailable {
            since: Some(now()),
            grace_until: Some(now()),
            last_error: Some("connection refused".to_string()),
        };

        assert!(matches!(
            lost_entitlement(&before, &after, "https://plane.test"),
            Some(TurnRefusal::PlaneUnavailable { .. })
        ));
    }

    #[test]
    fn regaining_a_seat_broadcasts_nothing() {
        let before = SeatAdmission::Refuse(Refusal::NoSeat);
        let after = SeatAdmission::Admit {
            tier: Tier::Standard,
        };

        assert_eq!(
            lost_entitlement(&before, &after, "https://plane.test"),
            None
        );
    }

    #[test]
    fn the_status_of_a_live_seat_names_it_and_when_it_was_confirmed() {
        let status = describe(&model(Some(entitled(now(), 4 * 3600)), None), now());

        assert_eq!(status.state, "entitled");
        assert_eq!(status.seat.as_deref(), Some("seat_01"));
        assert_eq!(status.tier.as_deref(), Some("standard"));
        assert_eq!(status.checked_at.as_deref(), Some("2026-08-29T12:00:00Z"));
        assert_eq!(status.grace_until.as_deref(), Some("2026-08-29T16:00:00Z"));
        assert_eq!(
            status.next_check_at.as_deref(),
            Some("2026-08-29T12:01:00Z")
        );
        assert_eq!(status.check_interval_secs, 60);
        assert_eq!(status.reason, None);
    }

    #[test]
    fn the_status_of_a_revoked_seat_reports_the_kind_and_the_prose() {
        let status = describe(&model(Some(revoked(now())), None), now());

        assert_eq!(status.state, "seat_revoked");
        assert_eq!(status.seat, None);
        assert_eq!(status.tier, None);
        assert!(status
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("offboarded")));
    }

    #[test]
    fn the_status_of_an_expired_grace_reports_the_outage_and_its_cause() {
        let status = describe(
            &model(
                Some(entitled(at("2026-08-29T07:00:00Z"), 4 * 3600)),
                Some("connection refused"),
            ),
            now(),
        );

        assert_eq!(status.state, "unavailable");
        assert_eq!(status.last_error.as_deref(), Some("connection refused"));
        assert_eq!(status.grace_until.as_deref(), Some("2026-08-29T11:00:00Z"));
    }

    #[test]
    fn a_daemon_that_has_never_checked_says_so_rather_than_looking_healthy() {
        let status = describe(&model(None, None), now());

        assert_eq!(status.state, "unchecked");
        assert_eq!(status.checked_at, None);
        assert_eq!(status.grace_until, None);
    }
}
