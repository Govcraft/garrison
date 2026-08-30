//! Waiting for the trail to leave a machine that is about to stop existing.
//!
//! # Why an ephemeral runner is a different problem
//!
//! The shipping policy in [`super::policy`] is written for a machine that
//! persists. Its central rule is that an unreachable plane never stops a turn,
//! because the trail file is the buffer: a laptop on a train catches up when
//! it lands, and refusing to work in the meantime would get the daemon turned
//! off within a week.
//!
//! That rule depends entirely on the file outliving the outage. In a CI
//! container it does not. The runner is deleted minutes after the review ends,
//! and an entry still sitting in its buffer is not delayed evidence, it is
//! destroyed evidence. Same backlog, same status fields, opposite meaning.
//!
//! So a run on an ephemeral machine has to wait for the trail to be accepted
//! before it exits, and has to say so plainly when it was not. That is what
//! this module decides. It is pure: it takes a status and a clock and returns
//! what to do, so every awkward case is a test rather than a timing bug.
//!
//! # The race this module exists to handle
//!
//! A turn's last entries are sealed asynchronously. Draining the instant a
//! turn returns can therefore observe `backlog == 0` because nothing has been
//! written yet, not because everything has been shipped. Those two states are
//! identical in the status and opposite in meaning, and treating the first as
//! success would certify a review whose evidence never existed.
//!
//! [`Progress::settled`] is the guard: a drain is complete only when the
//! backlog is empty *and* the local head has stopped moving between
//! observations. A writer still sealing entries moves the head, which is what
//! makes the difference observable at all.

use crate::protocol::acp::{ShipState, ShippingStatus};
use std::time::Duration;

/// What a drain should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Everything sealed has been accepted, and the writer has gone quiet.
    Complete {
        /// The sequence the plane has accepted through.
        shipped_through: u64,
    },
    /// Still working. Poll again after this long.
    Waiting {
        /// How many entries are still on the machine.
        backlog: u64,
        /// How long to wait before looking again.
        next_poll: Duration,
    },
    /// Shipping has stopped and will not resume without a human.
    ///
    /// Never worth waiting out: a halt means the plane refused an entry as
    /// forked or edited, the credential was rejected, or the trail was
    /// rewritten. None of those heal on their own, so the remaining deadline
    /// would be spent learning nothing.
    Halted {
        /// What the shipper said.
        reason: String,
    },
    /// The deadline passed with entries still on the machine.
    Expired {
        /// How many never left.
        backlog: u64,
    },
    /// This install does not ship at all.
    ///
    /// Its own answer rather than an error, because whether it is one depends
    /// on where the run is. On a workstation it is a configuration choice. On
    /// a runner that is about to be deleted it means the review will leave no
    /// evidence anywhere, and the caller is the one that knows which it is.
    NotShipping,
}

/// What the previous observation saw, for spotting a writer still working.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    /// The local head at the last look, if there was one.
    pub last_head: Option<u64>,
}

impl Progress {
    /// Whether the trail has stopped moving and everything is accepted.
    ///
    /// Both halves are load-bearing. An empty backlog alone is satisfied by a
    /// writer that has not started; an unchanged head alone is satisfied by a
    /// writer that finished long ago and a plane that has accepted nothing.
    #[must_use]
    pub fn settled(self, status: &ShippingStatus) -> bool {
        status.backlog == 0 && self.last_head == Some(status.local_head)
    }

    /// This observation, to compare the next one against.
    #[must_use]
    pub const fn observing(status_head: u64) -> Self {
        Self {
            last_head: Some(status_head),
        }
    }
}

/// How long to wait between looks.
///
/// Short, and deliberately not backing off. A drain is bounded by its deadline
/// and every second of it is a CI runner sitting idle, so the cost of polling
/// briskly is small and the cost of sleeping through the moment the backlog
/// clears is the whole remaining deadline.
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Decides the next step of a drain.
///
/// `elapsed` is time spent draining so far and `deadline` is the bound. The
/// deadline is checked *after* the completion and halt cases, so a drain that
/// finished on the last poll is not reported as expired for being slow.
#[must_use]
pub fn step(
    status: &ShippingStatus,
    progress: Progress,
    elapsed: Duration,
    deadline: Duration,
) -> Step {
    if !status.enabled || status.state == ShipState::Disabled {
        return Step::NotShipping;
    }

    if status.state == ShipState::Halted {
        return Step::Halted {
            reason: status
                .halted_reason
                .clone()
                .unwrap_or_else(|| "shipping halted without a stated reason".to_string()),
        };
    }

    if progress.settled(status) {
        return Step::Complete {
            shipped_through: status.shipped_through,
        };
    }

    if elapsed >= deadline {
        return Step::Expired {
            backlog: status.backlog,
        };
    }

    Step::Waiting {
        backlog: status.backlog,
        next_poll: POLL_INTERVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(state: ShipState, backlog: u64, head: u64, shipped: u64) -> ShippingStatus {
        ShippingStatus {
            enabled: true,
            state,
            trail_id: Some("trail-1".into()),
            trail: None,
            shipped_through: shipped,
            local_head: head,
            backlog,
            oldest_unshipped_at: None,
            last_shipped_at: None,
            last_error: None,
            halted_reason: None,
            retry_at: None,
        }
    }

    const DEADLINE: Duration = Duration::from_secs(30);
    const FRESH: Duration = Duration::from_secs(0);

    #[test]
    fn an_empty_backlog_on_a_settled_trail_is_complete() {
        let current = status(ShipState::Current, 0, 12, 12);
        let seen = Progress::observing(12);
        assert_eq!(
            step(&current, seen, FRESH, DEADLINE),
            Step::Complete {
                shipped_through: 12
            }
        );
    }

    #[test]
    fn an_empty_backlog_on_the_first_look_is_not_yet_complete() {
        // The race this module exists for. A turn's last entries are sealed
        // asynchronously, so a backlog of zero one millisecond after the turn
        // may mean "nothing written yet", not "everything shipped". Calling
        // that complete would certify a review whose evidence never existed.
        let current = status(ShipState::Current, 0, 12, 12);
        assert!(
            matches!(
                step(&current, Progress::default(), FRESH, DEADLINE),
                Step::Waiting { .. }
            ),
            "a first observation cannot know the writer has finished"
        );
    }

    #[test]
    fn a_head_that_moved_since_the_last_look_is_not_settled() {
        // The writer is still sealing. Backlog is zero right now only because
        // the shipper has kept up with a trail that is still growing.
        let current = status(ShipState::Current, 0, 13, 13);
        let seen = Progress::observing(12);
        assert!(matches!(
            step(&current, seen, FRESH, DEADLINE),
            Step::Waiting { .. }
        ));
    }

    #[test]
    fn a_backlog_keeps_the_drain_waiting_and_says_how_much() {
        let behind = status(ShipState::Behind, 7, 19, 12);
        let seen = Progress::observing(19);
        assert_eq!(
            step(&behind, seen, FRESH, DEADLINE),
            Step::Waiting {
                backlog: 7,
                next_poll: POLL_INTERVAL
            }
        );
    }

    #[test]
    fn a_halt_stops_the_drain_immediately_rather_than_waiting_it_out() {
        // A halt does not heal. Spending the remaining deadline on it would
        // teach the operator nothing and cost the pipeline the time.
        let mut halted = status(ShipState::Halted, 4, 19, 15);
        halted.halted_reason = Some("the plane refused entry 16 as forked".into());
        match step(&halted, Progress::observing(19), FRESH, DEADLINE) {
            Step::Halted { reason } => assert!(reason.contains("forked"), "{reason}"),
            other => panic!("a halt must not be waited out: {other:?}"),
        }
    }

    #[test]
    fn a_halt_with_no_stated_reason_still_says_something() {
        let halted = status(ShipState::Halted, 1, 2, 1);
        match step(&halted, Progress::observing(2), FRESH, DEADLINE) {
            Step::Halted { reason } => assert!(!reason.is_empty()),
            other => panic!("expected a halt: {other:?}"),
        }
    }

    #[test]
    fn a_backlog_still_present_at_the_deadline_expires() {
        let behind = status(ShipState::Behind, 3, 19, 16);
        assert_eq!(
            step(&behind, Progress::observing(19), DEADLINE, DEADLINE),
            Step::Expired { backlog: 3 }
        );
    }

    #[test]
    fn a_drain_that_finished_on_the_last_poll_is_complete_not_expired() {
        // Completion is checked before the deadline, so a drain that made it
        // just in time is not failed for being slow.
        let current = status(ShipState::Current, 0, 12, 12);
        assert_eq!(
            step(&current, Progress::observing(12), DEADLINE, DEADLINE),
            Step::Complete {
                shipped_through: 12
            }
        );
    }

    #[test]
    fn a_halt_at_the_deadline_reports_the_halt_rather_than_the_timeout() {
        // The reason matters more than the clock: one is a finding, the other
        // is a slow network, and an operator triages them differently.
        let mut halted = status(ShipState::Halted, 2, 5, 3);
        halted.halted_reason = Some("the credential was rejected".into());
        assert!(matches!(
            step(&halted, Progress::observing(5), DEADLINE, DEADLINE),
            Step::Halted { .. }
        ));
    }

    #[test]
    fn an_install_that_does_not_ship_says_so_rather_than_draining_forever() {
        let mut off = status(ShipState::Disabled, 0, 0, 0);
        off.enabled = false;
        assert_eq!(
            step(&off, Progress::default(), FRESH, DEADLINE),
            Step::NotShipping
        );
    }

    #[test]
    fn an_enabled_shipper_reporting_disabled_is_still_not_shipping() {
        // Belt and braces: the two fields can disagree, and draining against
        // a shipper that will never send anything would burn the deadline.
        let off = status(ShipState::Disabled, 0, 0, 0);
        assert_eq!(
            step(&off, Progress::default(), FRESH, DEADLINE),
            Step::NotShipping
        );
    }

    #[test]
    fn backoff_is_waited_out_because_it_heals_on_its_own() {
        // Unlike a halt. A plane that is briefly unreachable comes back, and
        // the deadline is the right bound on how long to care.
        let backoff = status(ShipState::Backoff, 2, 9, 7);
        assert!(matches!(
            step(&backoff, Progress::observing(9), FRESH, DEADLINE),
            Step::Waiting { .. }
        ));
    }
}
