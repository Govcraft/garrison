//! The written rule for when an unshipped audit stops the work.
//!
//! Everything here is pure: a status and a clock in, an admission out. The
//! actor that calls it holds no part of the decision, which is what lets
//! every branch of the rule be a test rather than a claim.
//!
//! # The rule
//!
//! An unreachable control plane never stops a turn on its own. The trail file
//! is the buffer, and a laptop on a train is not a governance failure. What
//! stops a turn is the backlog outliving its bound, or the plane deciding
//! that what it was sent is not what was sealed.
//!
//! - **Halted** refuses always, `fail_closed` or not. The plane refused an
//!   entry as forked or edited, or the local trail was rewritten under the
//!   cursor. Neither heals on its own and neither is an outage.
//! - **A backlog past its bound** refuses when `fail_closed`. The default
//!   bound is generous on purpose — a day, or ten thousand entries — so an
//!   ordinary outage costs nothing and an install that has kept a day of
//!   evidence to itself is exactly the case an auditor asks about.
//! - Everything else admits.

use crate::admission::{Admission, TurnRefusal};
use crate::protocol::acp::{ShipState, ShippingStatus};
use chrono::{DateTime, Utc};
use std::time::Duration;

/// The terms shipping runs under, resolved from `[plane.shipping]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShippingPolicy {
    /// How often the trail is checked for new entries.
    pub poll_interval: Duration,
    /// How often the daemon's own account of the trail is reported to the
    /// plane, even when nothing changed.
    pub report_interval: Duration,
    /// How many entries one batch may carry.
    pub batch: usize,
    /// How old the oldest unshipped entry may get before turns are refused.
    pub max_unshipped_age: Duration,
    /// How many entries may go unshipped before turns are refused.
    pub max_unshipped_entries: u64,
    /// Whether a backlog past its bound refuses turns.
    ///
    /// A halt refuses either way; this only governs the backlog bound. Set it
    /// false for an install that must keep working through a long outage, and
    /// accept that the evidence stays on the box until it does not.
    pub fail_closed: bool,
    /// The first delay after a failed batch.
    pub backoff_base: Duration,
    /// The longest that delay grows to.
    pub backoff_ceiling: Duration,
}

impl Default for ShippingPolicy {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
            report_interval: Duration::from_secs(60),
            batch: 50,
            max_unshipped_age: Duration::from_secs(86_400),
            max_unshipped_entries: 10_000,
            fail_closed: true,
            backoff_base: Duration::from_secs(1),
            backoff_ceiling: Duration::from_secs(300),
        }
    }
}

/// How long to wait before the next attempt after `failures` in a row.
///
/// Pure. Doubles from `base` to `ceiling` and then stays there, with
/// `sample` (a fraction in `[0, 1)`) spreading the delay over the last
/// doubling so a fleet that lost the plane at once does not come back at
/// once. `failures` of 0 or 1 is the first retry.
#[must_use]
pub fn backoff_delay(failures: u32, base: Duration, ceiling: Duration, sample: f64) -> Duration {
    let steps = failures.saturating_sub(1).min(24);
    let grown = base.saturating_mul(1_u32 << steps.min(24));
    let capped = grown.min(ceiling);
    let spread = capped.as_secs_f64() * (0.5 + 0.5 * sample.clamp(0.0, 1.0));
    Duration::from_secs_f64(spread.max(base.as_secs_f64().min(capped.as_secs_f64())))
}

/// Whether a turn may run, given where the trail's copy has got to.
///
/// Pure, and the whole gate rule. See the module docs for why an unreachable
/// plane is not on its own a refusal.
#[must_use]
pub fn admit_turn(
    status: &ShippingStatus,
    policy: &ShippingPolicy,
    now: DateTime<Utc>,
) -> Admission {
    if !status.enabled {
        return Admission::Admit;
    }

    if status.state == ShipState::Halted {
        return Admission::Refuse(TurnRefusal::AuditShipping {
            reason: halted_reason(status),
        });
    }

    if !policy.fail_closed {
        return Admission::Admit;
    }

    if status.backlog > policy.max_unshipped_entries {
        return Admission::Refuse(TurnRefusal::AuditShipping {
            reason: backlog_reason(status, policy),
        });
    }

    if let Some(age) = unshipped_age(status, now) {
        if age > policy.max_unshipped_age {
            return Admission::Refuse(TurnRefusal::AuditShipping {
                reason: stale_reason(status, policy, age),
            });
        }
    }

    Admission::Admit
}

/// How long the oldest unshipped entry has been waiting. Pure.
///
/// `None` when nothing is waiting, or when the timestamp on the oldest
/// unshipped entry is in the future, which is a clock that moved rather than
/// a backlog that aged.
#[must_use]
pub fn unshipped_age(status: &ShippingStatus, now: DateTime<Utc>) -> Option<Duration> {
    let written = status.oldest_unshipped_at.as_deref()?;
    let written = DateTime::parse_from_rfc3339(written)
        .ok()?
        .with_timezone(&Utc);
    now.signed_duration_since(written).to_std().ok()
}

/// The sentence an operator reads when shipping has halted.
fn halted_reason(status: &ShippingStatus) -> String {
    let what = status
        .halted_reason
        .as_deref()
        .or(status.last_error.as_deref())
        .unwrap_or("the control plane refused an entry");
    format!(
        "audit shipping has halted: {what}. This is a finding, not an outage: the control \
         plane's copy of this trail and the trail on this machine no longer agree, so turns \
         are refused rather than run into a record nobody can verify. Keep the trail and its \
         `.shipped` cursor, and have a security officer compare them against the plane's \
         AuditChain for this trail before restarting the daemon"
    )
}

/// The sentence an operator reads when too many entries are waiting.
fn backlog_reason(status: &ShippingStatus, policy: &ShippingPolicy) -> String {
    format!(
        "{} audit entries have not reached the control plane, past the bound of {}. {} Turns \
         are refused until the backlog drains: an audit that cannot leave the box is a reason \
         to stop working, not a warning to log. Raise [plane.shipping] max_unshipped_entries \
         only if you have decided that is acceptable",
        status.backlog,
        policy.max_unshipped_entries,
        last_error_clause(status),
    )
}

/// The sentence an operator reads when the backlog has aged out.
fn stale_reason(status: &ShippingStatus, policy: &ShippingPolicy, age: Duration) -> String {
    format!(
        "the control plane has not accepted an audit entry written {} ago, past the bound of \
         {}; {} entries are waiting. {} Turns are refused until shipping resumes",
        humanize(age),
        humanize(policy.max_unshipped_age),
        status.backlog,
        last_error_clause(status),
    )
}

/// What the last attempt said, as a sentence, or nothing when it said nothing.
fn last_error_clause(status: &ShippingStatus) -> String {
    match status.last_error.as_deref() {
        Some(error) => format!("The last attempt failed: {error}."),
        None => "The control plane has not been reachable.".to_string(),
    }
}

/// A duration in the coarsest unit that still says something. Pure.
#[must_use]
pub fn humanize(duration: Duration) -> String {
    let seconds = duration.as_secs();
    match seconds {
        0..=119 => format!("{seconds}s"),
        120..=3599 => format!("{}m", seconds / 60),
        3600..=172_799 => format!("{}h", seconds / 3600),
        _ => format!("{}d", seconds / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(state: ShipState) -> ShippingStatus {
        ShippingStatus {
            enabled: true,
            state,
            trail_id: Some("trail_abc".to_string()),
            trail: Some("audittrail_01".to_string()),
            shipped_through: 10,
            local_head: 10,
            backlog: 0,
            oldest_unshipped_at: None,
            last_shipped_at: None,
            last_error: None,
            halted_reason: None,
            retry_at: None,
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-29T12:00:00Z")
            .expect("a fixed clock")
            .with_timezone(&Utc)
    }

    fn ago(seconds: i64) -> String {
        (now() - chrono::Duration::seconds(seconds)).to_rfc3339()
    }

    #[test]
    fn a_current_trail_admits() {
        assert_eq!(
            admit_turn(
                &status(ShipState::Current),
                &ShippingPolicy::default(),
                now()
            ),
            Admission::Admit
        );
    }

    #[test]
    fn an_install_that_ships_nothing_is_never_gated_on_shipping() {
        let mut status = status(ShipState::Halted);
        status.enabled = false;

        assert_eq!(
            admit_turn(&status, &ShippingPolicy::default(), now()),
            Admission::Admit
        );
    }

    #[test]
    fn an_unreachable_plane_within_the_bound_does_not_stop_a_turn() {
        let mut status = status(ShipState::Backoff);
        status.backlog = 12;
        status.local_head = 22;
        status.oldest_unshipped_at = Some(ago(600));
        status.last_error = Some("503 hook_unavailable".to_string());

        assert_eq!(
            admit_turn(&status, &ShippingPolicy::default(), now()),
            Admission::Admit,
            "the trail file is the buffer; an outage is not a governance failure"
        );
    }

    #[test]
    fn a_halted_shipper_refuses_and_names_what_it_is_stuck_on() {
        let mut status = status(ShipState::Halted);
        status.halted_reason = Some("chain broken at sequence 7: HashMismatch".to_string());

        let Admission::Refuse(TurnRefusal::AuditShipping { reason }) =
            admit_turn(&status, &ShippingPolicy::default(), now())
        else {
            panic!("a halt must refuse");
        };

        assert!(reason.contains("HashMismatch"), "{reason}");
        assert!(reason.contains("security officer"), "{reason}");
    }

    #[test]
    fn a_halt_refuses_even_when_the_install_asked_not_to_fail_closed() {
        let policy = ShippingPolicy {
            fail_closed: false,
            ..ShippingPolicy::default()
        };
        let mut status = status(ShipState::Halted);
        status.halted_reason = Some("credential refused".to_string());

        assert!(matches!(
            admit_turn(&status, &policy, now()),
            Admission::Refuse(TurnRefusal::AuditShipping { .. })
        ));
    }

    #[test]
    fn a_backlog_past_its_count_bound_refuses_with_both_numbers() {
        let policy = ShippingPolicy {
            max_unshipped_entries: 100,
            ..ShippingPolicy::default()
        };
        let mut status = status(ShipState::Behind);
        status.backlog = 101;
        status.last_error = Some("connection refused".to_string());

        let Admission::Refuse(TurnRefusal::AuditShipping { reason }) =
            admit_turn(&status, &policy, now())
        else {
            panic!("a full backlog must refuse");
        };

        assert!(reason.contains("101"), "{reason}");
        assert!(reason.contains("100"), "{reason}");
        assert!(reason.contains("connection refused"), "{reason}");
    }

    #[test]
    fn a_backlog_exactly_at_its_count_bound_still_admits() {
        let policy = ShippingPolicy {
            max_unshipped_entries: 100,
            ..ShippingPolicy::default()
        };
        let mut status = status(ShipState::Behind);
        status.backlog = 100;

        assert_eq!(admit_turn(&status, &policy, now()), Admission::Admit);
    }

    #[test]
    fn a_backlog_older_than_its_age_bound_refuses_and_says_how_old() {
        let policy = ShippingPolicy {
            max_unshipped_age: Duration::from_secs(3600),
            ..ShippingPolicy::default()
        };
        let mut status = status(ShipState::Behind);
        status.backlog = 3;
        status.oldest_unshipped_at = Some(ago(7200));

        let Admission::Refuse(TurnRefusal::AuditShipping { reason }) =
            admit_turn(&status, &policy, now())
        else {
            panic!("a stale backlog must refuse");
        };

        assert!(reason.contains("2h"), "{reason}");
        assert!(reason.contains("1h"), "{reason}");
    }

    #[test]
    fn a_backlog_past_its_age_bound_admits_when_the_install_asked_not_to_fail_closed() {
        let policy = ShippingPolicy {
            max_unshipped_age: Duration::from_secs(60),
            fail_closed: false,
            ..ShippingPolicy::default()
        };
        let mut status = status(ShipState::Behind);
        status.backlog = 500;
        status.oldest_unshipped_at = Some(ago(7200));

        assert_eq!(admit_turn(&status, &policy, now()), Admission::Admit);
    }

    #[test]
    fn a_timestamp_in_the_future_is_a_clock_that_moved_and_not_a_backlog_that_aged() {
        let mut status = status(ShipState::Behind);
        status.oldest_unshipped_at = Some(ago(-600));

        assert_eq!(unshipped_age(&status, now()), None);
        assert_eq!(
            admit_turn(&status, &ShippingPolicy::default(), now()),
            Admission::Admit
        );
    }

    #[test]
    fn an_unparsable_timestamp_is_not_treated_as_infinitely_old() {
        let mut status = status(ShipState::Behind);
        status.oldest_unshipped_at = Some("yesterday".to_string());

        assert_eq!(unshipped_age(&status, now()), None);
    }

    #[test]
    fn the_first_retry_waits_about_the_base_delay() {
        let base = Duration::from_secs(1);
        let delay = backoff_delay(1, base, Duration::from_secs(300), 0.0);

        assert!(delay >= Duration::from_millis(500), "{delay:?}");
        assert!(delay <= base, "{delay:?}");
    }

    #[test]
    fn the_delay_doubles_and_then_stops_at_the_ceiling() {
        let base = Duration::from_secs(1);
        let ceiling = Duration::from_secs(64);
        let full = |failures| backoff_delay(failures, base, ceiling, 1.0);

        assert_eq!(full(1), Duration::from_secs(1));
        assert_eq!(full(2), Duration::from_secs(2));
        assert_eq!(full(4), Duration::from_secs(8));
        assert_eq!(full(7), ceiling);
        assert_eq!(full(30), ceiling, "and it never grows past it");
    }

    #[test]
    fn the_jitter_sample_spreads_a_delay_over_its_last_doubling() {
        let base = Duration::from_secs(1);
        let ceiling = Duration::from_secs(300);
        let low = backoff_delay(6, base, ceiling, 0.0);
        let high = backoff_delay(6, base, ceiling, 1.0);

        assert_eq!(high, Duration::from_secs(32));
        assert_eq!(low, Duration::from_secs(16));
    }

    #[test]
    fn a_sample_outside_the_unit_interval_is_clamped_rather_than_trusted() {
        let base = Duration::from_secs(1);
        let ceiling = Duration::from_secs(300);

        assert_eq!(
            backoff_delay(6, base, ceiling, 9.0),
            backoff_delay(6, base, ceiling, 1.0)
        );
        assert_eq!(
            backoff_delay(6, base, ceiling, -3.0),
            backoff_delay(6, base, ceiling, 0.0)
        );
    }

    #[test]
    fn a_duration_is_printed_in_the_coarsest_unit_that_still_says_something() {
        assert_eq!(humanize(Duration::from_secs(45)), "45s");
        assert_eq!(humanize(Duration::from_secs(300)), "5m");
        assert_eq!(
            humanize(Duration::from_secs(3600)),
            "1h",
            "an hour reads as an hour; sixty minutes is a bound nobody typed"
        );
        assert_eq!(humanize(Duration::from_secs(7200)), "2h");
        assert_eq!(humanize(Duration::from_secs(172_800)), "2d");
    }
}
