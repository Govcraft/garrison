//! The one word an operator reads off `_garrison/status`.
//!
//! acton-ai reports three states, and they are the right three for a writer:
//! `disabled`, `healthy`, `degraded`. An operator asking "is this daemon
//! recording?" needs a fourth distinction that the writer cannot make on its
//! own, because it is about the deployment rather than the disk: a trail that
//! is armed and correct but has never been written to. That is `configured`.
//!
//! Without it, a freshly started daemon and a daemon that has been recording
//! all day both read `healthy`, and "the audit is working" is claimed by a
//! process that has not yet proved it can write anything. Splitting the two
//! is what lets a deployment check say "this agent has recorded at least one
//! call" and mean it.
//!
//! Everything here is pure: a health value in, a word out.

use acton_ai::audit::{AuditHealth, AuditHealthState};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Where the audit stands, in one word, for a human.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditState {
    /// No trail is armed. Nothing is being recorded, and the status says so
    /// rather than omitting the subject.
    #[default]
    Disabled,
    /// A trail is armed and intact, and nothing has been written to it in
    /// this process yet.
    Configured,
    /// A trail is armed and every append in this process reached the disk.
    Healthy,
    /// At least one append failed. The record is incomplete, and it stays
    /// incomplete until an operator repairs the trail and restarts.
    Degraded,
}

impl fmt::Display for AuditState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = match self {
            Self::Disabled => "disabled",
            Self::Configured => "configured",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
        };
        f.write_str(word)
    }
}

impl AuditState {
    /// Whether a turn recorded now would land on an incomplete record.
    #[must_use]
    pub const fn is_degraded(self) -> bool {
        matches!(self, Self::Degraded)
    }
}

/// The state a health value describes. Pure.
///
/// The split acton-ai does not make: a healthy writer that has appended
/// nothing is `configured`, not `healthy`.
#[must_use]
pub fn state_for(health: &AuditHealth) -> AuditState {
    match health.state {
        AuditHealthState::Disabled => AuditState::Disabled,
        AuditHealthState::Degraded => AuditState::Degraded,
        AuditHealthState::Healthy if health.appended == 0 => AuditState::Configured,
        AuditHealthState::Healthy => AuditState::Healthy,
        // acton-ai marks the enum non-exhaustive so it can name a fourth
        // writer state later. Until this crate learns what that state means,
        // the honest answer is the conservative one: a writer whose condition
        // this build cannot interpret is not a writer to claim is healthy.
        _ => AuditState::Degraded,
    }
}

/// The state to report when the audit actor could not be asked at all.
///
/// Never `healthy`. A writer that does not answer has not said the record is
/// complete, and a status that guesses on its behalf is the one lie an audit
/// surface must not tell.
#[must_use]
pub const fn state_when_unreachable() -> AuditState {
    AuditState::Degraded
}

#[cfg(test)]
mod tests {
    use super::*;
    use acton_ai::audit::{AuditDurability, ChainHead};

    fn healthy(appended: u64) -> AuditHealth {
        let mut health = AuditHealth::armed(ChainHead::empty(), AuditDurability::Strict);
        health.appended = appended;
        health
    }

    #[test]
    fn no_trail_reads_as_disabled() {
        assert_eq!(state_for(&AuditHealth::disabled()), AuditState::Disabled);
    }

    #[test]
    fn an_armed_but_unwritten_trail_reads_as_configured() {
        assert_eq!(state_for(&healthy(0)), AuditState::Configured);
    }

    #[test]
    fn a_trail_that_has_recorded_something_reads_as_healthy() {
        assert_eq!(state_for(&healthy(1)), AuditState::Healthy);
    }

    #[test]
    fn a_failed_append_reads_as_degraded_however_many_succeeded() {
        let mut health = healthy(9);
        health.state = AuditHealthState::Degraded;
        health.failures = 1;
        health.first_failed_sequence = Some(10);

        assert_eq!(state_for(&health), AuditState::Degraded);
        assert!(state_for(&health).is_degraded());
    }

    #[test]
    fn a_writer_that_does_not_answer_is_never_reported_healthy() {
        assert_eq!(state_when_unreachable(), AuditState::Degraded);
    }

    #[test]
    fn every_state_prints_the_word_the_wire_uses() {
        for (state, word) in [
            (AuditState::Disabled, "disabled"),
            (AuditState::Configured, "configured"),
            (AuditState::Healthy, "healthy"),
            (AuditState::Degraded, "degraded"),
        ] {
            assert_eq!(state.to_string(), word);
            assert_eq!(
                serde_json::to_value(state).expect("serializable"),
                serde_json::Value::String(word.to_string())
            );
        }
    }

    #[test]
    fn only_degraded_is_degraded() {
        assert!(!AuditState::Disabled.is_degraded());
        assert!(!AuditState::Configured.is_degraded());
        assert!(!AuditState::Healthy.is_degraded());
        assert!(AuditState::Degraded.is_degraded());
    }
}
