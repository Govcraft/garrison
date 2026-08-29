//! How long a stored session is kept, decided as a pure function.
//!
//! Persistence without retention is a growing disk and a growing disclosure:
//! every prompt an operator ever typed, kept forever, on a machine an agency
//! has to be able to say something definite about. So the daemon sweeps.
//!
//! The sweep is split in two on purpose. [`plan_retention`] decides *what*
//! should go, from values alone — a clock reading, what the store holds, and
//! the policy — and the actor does the deleting. That is what makes "a
//! session with an interrupted turn is never swept" a test rather than a
//! hope.

use crate::session::store::StoredSession;
use acton_ai::checkpoint::{CheckpointRecord, CheckpointStatus};
use acton_ai::types::CheckpointId;
use chrono::{DateTime, NaiveDateTime, Utc};
use std::time::Duration;

/// How long sessions live, and how often that is enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Days a session may go untouched before it is swept. Never zero: a
    /// zero-day retention would delete a session the moment the operator
    /// stopped typing into it.
    pub retain_days: u32,
    /// How often the sweep runs.
    pub sweep_interval: Duration,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            retain_days: 30,
            sweep_interval: Duration::from_secs(24 * 60 * 60),
        }
    }
}

/// What a sweep should remove.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetentionPlan {
    /// Sessions to delete by name, with their conversations and messages.
    pub sessions: Vec<String>,
    /// Checkpoints to delete: turns that finished, or that an operator
    /// abandoned, and so have no work left in them.
    pub checkpoints: Vec<CheckpointId>,
}

impl RetentionPlan {
    /// Whether there is anything to do.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty() && self.checkpoints.is_empty()
    }
}

/// What the sweep should remove, given the clock and what is stored.
///
/// Pure. Three of its four rules are refusals to delete something:
///
/// - a session touched inside the window stays;
/// - a session whose last-active date cannot be read stays, because a date
///   this daemon cannot parse is not evidence that the session is stale;
/// - a session holding an interrupted turn stays at any age, because the
///   operator has not yet said whether to resume it, and sweeping it would
///   make that decision for them.
///
/// The fourth: a checkpoint in a terminal state goes whatever its age. A
/// completed turn has already been committed to the session's history and an
/// abandoned one was abandoned on purpose. In-progress and failed records are
/// exactly what a resume needs, so they leave only when their session does.
#[must_use]
pub fn plan_retention(
    now: DateTime<Utc>,
    sessions: &[StoredSession],
    checkpoints: &[CheckpointRecord],
    policy: &RetentionPolicy,
) -> RetentionPlan {
    let cutoff = now - chrono::Duration::days(i64::from(policy.retain_days));

    let sessions = sessions
        .iter()
        .filter(|session| session.meta.interrupted().is_none())
        .filter(|session| {
            parse_last_active(&session.last_active).is_some_and(|active| active < cutoff)
        })
        .map(|session| session.name.clone())
        .collect();

    let checkpoints = checkpoints
        .iter()
        .filter(|record| {
            matches!(
                record.status,
                CheckpointStatus::Completed | CheckpointStatus::Abandoned
            )
        })
        .map(|record| record.id.clone())
        .collect();

    RetentionPlan {
        sessions,
        checkpoints,
    }
}

/// Reads a stored timestamp, in either spelling the store produces.
///
/// libSQL's `datetime('now')` writes `YYYY-MM-DD HH:MM:SS` in UTC; anything
/// this daemon writes itself is RFC 3339. Both are accepted; nothing else is,
/// and an unreadable date is `None` rather than a guess, because the only use
/// of the answer is deciding whether to delete.
fn parse_last_active(text: &str) -> Option<DateTime<Utc>> {
    if let Ok(stamped) = DateTime::parse_from_rfc3339(text) {
        return Some(stamped.with_timezone(&Utc));
    }

    NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|naive| naive.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::meta::SessionMeta;
    use acton_ai::checkpoint::TurnFingerprint;
    use acton_ai::types::ConversationId;
    use std::path::PathBuf;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-01T12:00:00Z")
            .expect("a fixed clock")
            .with_timezone(&Utc)
    }

    fn session(name: &str, last_active: &str) -> StoredSession {
        StoredSession {
            name: name.to_string(),
            meta: SessionMeta::opening(
                ConversationId::new(),
                PathBuf::from("/srv/work"),
                crate::session::identity::CLIENT_SOCKET,
            ),
            created_at: "2026-01-01 00:00:00".to_string(),
            last_active: last_active.to_string(),
        }
    }

    /// A checkpoint in a given state.
    ///
    /// The fingerprint is a constant because nothing here reads it: what is
    /// under test is the status and the identity, and the identity is minted
    /// fresh on every call. Two records built here are distinguishable
    /// because their [`CheckpointId`]s differ, never because their inputs do.
    fn record(status: CheckpointStatus) -> CheckpointRecord {
        let mut record = CheckpointRecord::opening(
            CheckpointId::new(),
            None,
            TurnFingerprint::from_hex("00"),
            vec![],
        );
        record.status = status;
        record
    }

    fn policy() -> RetentionPolicy {
        RetentionPolicy {
            retain_days: 30,
            sweep_interval: Duration::from_secs(3600),
        }
    }

    #[test]
    fn a_session_touched_inside_the_window_is_kept() {
        let plan = plan_retention(
            now(),
            &[session("thread_a", "2026-05-20 09:00:00")],
            &[],
            &policy(),
        );

        assert!(plan.sessions.is_empty());
    }

    #[test]
    fn a_session_older_than_the_window_is_swept() {
        let plan = plan_retention(
            now(),
            &[session("thread_a", "2026-01-02 09:00:00")],
            &[],
            &policy(),
        );

        assert_eq!(plan.sessions, vec!["thread_a".to_string()]);
    }

    #[test]
    fn an_interrupted_turn_outlives_the_retention_window() {
        let mut stale = session("thread_a", "2026-01-02 09:00:00");
        stale.meta.open(
            crate::types::TurnId::new(),
            "2026-01-02T09:00:00Z".to_string(),
            "keep going".to_string(),
        );

        let plan = plan_retention(now(), &[stale], &[], &policy());

        assert!(
            plan.sessions.is_empty(),
            "an operator has not yet said what to do with it",
        );
    }

    #[test]
    fn a_date_this_agent_cannot_read_is_not_evidence_of_staleness() {
        let plan = plan_retention(
            now(),
            &[session("thread_a", "last tuesday")],
            &[],
            &policy(),
        );

        assert!(plan.sessions.is_empty());
    }

    #[test]
    fn both_spellings_of_a_stored_date_are_understood() {
        assert!(parse_last_active("2026-01-02 09:00:00").is_some());
        assert!(parse_last_active("2026-01-02T09:00:00Z").is_some());
        assert!(parse_last_active("").is_none());
    }

    #[test]
    fn a_finished_or_abandoned_turn_is_swept_and_a_resumable_one_is_not() {
        let completed = record(CheckpointStatus::Completed);
        let abandoned = record(CheckpointStatus::Abandoned);
        let expected = vec![completed.id.clone(), abandoned.id.clone()];

        let plan = plan_retention(
            now(),
            &[],
            &[
                completed,
                abandoned,
                record(CheckpointStatus::InProgress),
                record(CheckpointStatus::Failed),
            ],
            &policy(),
        );

        assert_eq!(plan.checkpoints, expected);
    }

    #[test]
    fn a_plan_with_nothing_in_it_says_so() {
        assert!(plan_retention(now(), &[], &[], &policy()).is_empty());
    }

    #[test]
    fn the_default_window_is_a_month_swept_daily() {
        let policy = RetentionPolicy::default();

        assert_eq!(policy.retain_days, 30);
        assert_eq!(policy.sweep_interval, Duration::from_secs(86_400));
    }
}
