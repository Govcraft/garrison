//! What a review's result means for the pipeline that asked for it.
//!
//! # Advisory first
//!
//! Failing a build on a model's opinion is a strong claim, and a reviewer that
//! makes it on day one gets switched off in week two. So blocking is opt-in:
//! by default every finding is posted and the build still passes, and a team
//! that has watched the reviewer for a while can turn blocking on when they
//! believe it.
//!
//! # The exception that is not negotiable
//!
//! A run whose answer could not be read is a **failure regardless of policy**.
//! Advisory mode means "I will not fail your build over a finding"; it does
//! not mean "I will tell you the review passed when it did not happen". Those
//! are different promises, and collapsing them would let a broken reviewer
//! report green forever.

use super::finding::Review;

/// Whether findings may fail the build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Blocking {
    /// Post findings, always exit zero. The default.
    #[default]
    Advisory,
    /// Exit non-zero when a blocker-severity finding is present.
    Enforcing,
}

/// What the run concluded, and what it should exit with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Reviewed, nothing found.
    Clean,
    /// Reviewed, findings posted, the build is not failed.
    Advised {
        /// How many findings were reported.
        total: usize,
        /// How many were blocker-severity but not enforced.
        blocking: usize,
    },
    /// Reviewed, and a blocker was found while enforcing.
    Blocked {
        /// How many blocker-severity findings there were.
        blocking: usize,
    },
    /// The review did not happen, whatever the answer looked like.
    Failed {
        /// Why, for an operator.
        reason: String,
    },
}

impl Outcome {
    /// The process exit code.
    ///
    /// `0` clean or advisory, `3` blocked, `1` failed. Three matches the
    /// binary's existing meaning for a deliberate rejection, which a blocked
    /// merge is; one is the existing meaning for a malfunction, which a review
    /// that could not be read is.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Clean | Self::Advised { .. } => 0,
            Self::Blocked { .. } => 3,
            Self::Failed { .. } => 1,
        }
    }

    /// The build state to report to Bitbucket.
    ///
    /// A failed run reports `FAILED` rather than staying silent: a pull
    /// request with no status looks like a pipeline that has not run yet, and
    /// a reviewer that breaks quietly is indistinguishable from one that was
    /// never wired up.
    #[must_use]
    pub const fn build_state(&self) -> garrison_bitbucket::BuildState {
        match self {
            Self::Clean | Self::Advised { .. } => garrison_bitbucket::BuildState::Successful,
            Self::Blocked { .. } | Self::Failed { .. } => garrison_bitbucket::BuildState::Failed,
        }
    }

    /// One line for the build status, and for a human reading the pipeline log.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Clean => "no findings".into(),
            Self::Advised { total, blocking: 0 } => format!("{total} finding(s), advisory"),
            Self::Advised { total, blocking } => {
                format!("{total} finding(s) including {blocking} blocker(s), advisory")
            }
            Self::Blocked { blocking } => format!("{blocking} blocker(s)"),
            Self::Failed { reason } => format!("the review did not complete: {reason}"),
        }
    }
}

/// Decides what a parsed review means under a blocking policy.
#[must_use]
pub fn decide(review: &Review, blocking: Blocking) -> Outcome {
    if let Review::Unreadable { reason, excerpt } = review {
        // Note that `blocking` is not consulted. An unreadable answer fails
        // in advisory mode too, because "advisory" is a promise about
        // findings and this is the absence of a review.
        return Outcome::Failed {
            reason: format!("{reason} (answer began: {excerpt})"),
        };
    }

    let findings = review.findings();
    if findings.is_empty() {
        return Outcome::Clean;
    }

    let blockers = review.blocking_count();
    match blocking {
        Blocking::Enforcing if blockers > 0 => Outcome::Blocked { blocking: blockers },
        Blocking::Advisory | Blocking::Enforcing => Outcome::Advised {
            total: findings.len(),
            blocking: blockers,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::super::finding::parse_findings;
    use super::*;

    const BLOCKER: &str =
        r#"[{"file":"a.rs","line":1,"severity":"blocker","message":"unchecked index"}]"#;
    const MINOR: &str = r#"[{"file":"a.rs","line":1,"severity":"minor","message":"typo"}]"#;

    #[test]
    fn a_clean_review_passes_and_reports_success() {
        let outcome = decide(&parse_findings("[]"), Blocking::Advisory);
        assert_eq!(outcome, Outcome::Clean);
        assert_eq!(outcome.exit_code(), 0);
        assert_eq!(
            outcome.build_state(),
            garrison_bitbucket::BuildState::Successful
        );
    }

    #[test]
    fn a_blocker_does_not_fail_the_build_by_default() {
        // The whole advisory-first posture in one assertion.
        let outcome = decide(&parse_findings(BLOCKER), Blocking::Advisory);
        assert_eq!(outcome.exit_code(), 0);
        assert!(matches!(outcome, Outcome::Advised { blocking: 1, .. }));
        assert!(outcome.description().contains("advisory"), "{outcome:?}");
    }

    #[test]
    fn a_blocker_fails_the_build_once_enforcing_is_switched_on() {
        let outcome = decide(&parse_findings(BLOCKER), Blocking::Enforcing);
        assert_eq!(outcome, Outcome::Blocked { blocking: 1 });
        assert_eq!(outcome.exit_code(), 3);
        assert_eq!(
            outcome.build_state(),
            garrison_bitbucket::BuildState::Failed
        );
    }

    #[test]
    fn a_minor_finding_never_fails_the_build_even_enforcing() {
        // Enforcing means "blockers fail", not "any finding fails". A team
        // that opted into the first has not opted into the second.
        let outcome = decide(&parse_findings(MINOR), Blocking::Enforcing);
        assert_eq!(outcome.exit_code(), 0);
        assert!(matches!(outcome, Outcome::Advised { blocking: 0, .. }));
    }

    #[test]
    fn an_unreadable_answer_fails_even_in_advisory_mode() {
        // The one thing advisory mode does not excuse. A pipeline that
        // reported this as clean would be certifying a review that never ran.
        let outcome = decide(
            &parse_findings("I could not read the diff."),
            Blocking::Advisory,
        );
        assert_eq!(outcome.exit_code(), 1);
        assert!(matches!(outcome, Outcome::Failed { .. }));
        assert_eq!(
            outcome.build_state(),
            garrison_bitbucket::BuildState::Failed
        );
    }

    #[test]
    fn a_failed_run_says_what_came_back_so_it_can_be_triaged() {
        let outcome = decide(
            &parse_findings("I'm sorry, I can't help with that."),
            Blocking::Advisory,
        );
        assert!(outcome.description().contains("can't help"), "{outcome:?}");
    }

    #[test]
    fn a_failed_run_reports_a_status_rather_than_staying_silent() {
        // No status on a pull request looks like a pipeline that has not run.
        // A reviewer that breaks must not be mistakable for one not wired up.
        let outcome = decide(&parse_findings("nonsense"), Blocking::Advisory);
        assert_eq!(
            outcome.build_state(),
            garrison_bitbucket::BuildState::Failed
        );
    }

    #[test]
    fn advisory_is_the_default_policy() {
        assert_eq!(Blocking::default(), Blocking::Advisory);
    }

    #[test]
    fn the_description_counts_what_it_found() {
        let answer = r#"[
            {"file":"a.rs","line":1,"severity":"blocker","message":"b"},
            {"file":"b.rs","line":2,"severity":"minor","message":"m"}
        ]"#;
        let outcome = decide(&parse_findings(answer), Blocking::Advisory);
        let text = outcome.description();
        assert!(text.contains('2'), "{text}");
        assert!(text.contains('1'), "{text}");
    }
}
