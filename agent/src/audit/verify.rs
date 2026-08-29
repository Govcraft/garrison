//! `garrison-agent audit verify`: the chain, and the anchor it is measured
//! against.
//!
//! # Two questions, two exit codes
//!
//! Verifying a trail asks two things that fail for different reasons and need
//! different answers:
//!
//! 1. **Is the chain internally consistent?** acton-ai's `verify_chain`
//!    answers that, and a broken link is a rewrite or an insertion. Exit 3.
//! 2. **Does the chain still end where it used to?** Nothing inside the file
//!    can answer that, because a prefix of a valid chain is a valid chain.
//!    Only the anchor can, and disagreeing with it is exit 4 — the only user
//!    of that code in this binary.
//!
//! A trail with its last ten entries deleted passes the first question and
//! fails the second, which is precisely why both are asked.
//!
//! Everything that decides anything here is pure: [`report`] takes what was
//! read and returns the finding, and [`Outcome::of`] turns a finding into an
//! exit code. [`run`] is the thin shell that reads two files.

use crate::audit::anchor::{self, Anchor, HeadComparison};
use crate::error::GarrisonError;
use acton_ai::audit::{parse_entries, verify_chain, AuditEntry, ChainBreak};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// What a verification found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct VerifyReport {
    /// The trail that was read.
    pub trail: String,
    /// How many entries it holds.
    pub entries: u64,
    /// Where the chain ends.
    pub head_sequence: u64,
    /// The hash at that end.
    pub head_hash: String,
    /// The trail's identity, when it carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trail_id: Option<String>,
    /// Whether the chain verified on its own terms.
    pub chain: ChainVerdict,
    /// What the anchor had to say, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<AnchorReport>,
}

/// Whether the chain hangs together.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
#[non_exhaustive]
pub enum ChainVerdict {
    /// Every link follows the one before it.
    Intact,
    /// It does not, and this is the first place it stops.
    Broken {
        /// Where the walk stopped.
        finding: String,
        /// The line the broken entry sits on.
        line: usize,
        /// The sequence number it carries.
        sequence: u64,
    },
}

/// What the anchor says about this trail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AnchorReport {
    /// The anchor file that was read.
    pub path: String,
    /// The sequence number it vouches for.
    pub sequence: u64,
    /// The hash it vouches for.
    pub hash: String,
    /// When it was written.
    pub anchored_at: String,
    /// The comparison.
    pub comparison: HeadComparison,
    /// The comparison as a sentence.
    pub finding: String,
}

/// What the command exits with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// The chain verified and agrees with its anchor.
    Clean,
    /// The chain does not verify: exit 3.
    ChainBroken,
    /// The chain verifies but has lost or altered history the anchor
    /// remembers: exit 4.
    AnchorMismatch,
}

impl Outcome {
    /// What a report means. Pure.
    ///
    /// A broken chain is reported ahead of an anchor mismatch: the chain is
    /// the stronger evidence, and a trail that does not verify at all makes
    /// the anchor comparison a detail of a larger finding.
    #[must_use]
    pub fn of(report: &VerifyReport) -> Self {
        if matches!(report.chain, ChainVerdict::Broken { .. }) {
            return Self::ChainBroken;
        }

        match report.anchor.as_ref() {
            Some(anchor) if anchor.comparison.is_mismatch() => Self::AnchorMismatch,
            _ => Self::Clean,
        }
    }
}

/// Builds the finding from what was read. Pure.
///
/// The anchor is compared against the *entries* rather than the head, so a
/// chain that was rewritten below the anchor and then extended past it is
/// caught rather than read as ordinary growth. An anchor written for a
/// different trail is left out of the report entirely: it is evidence about
/// another file and saying anything about this one would be a guess.
#[must_use]
pub fn report(trail_path: &Path, entries: &[AuditEntry], anchor: Option<&Anchor>) -> VerifyReport {
    let (chain, head_sequence, head_hash, trail_id) = match verify_chain(entries) {
        Ok(head) => (
            ChainVerdict::Intact,
            head.sequence,
            head.hash,
            head.trail_id.as_ref().map(ToString::to_string),
        ),
        Err(ChainBreak {
            line,
            sequence,
            kind,
        }) => (
            ChainVerdict::Broken {
                finding: kind.to_string(),
                line,
                sequence,
            },
            entries.last().map_or(0, |entry| entry.sequence),
            entries
                .last()
                .map_or_else(String::new, |entry| entry.hash.clone()),
            entries
                .iter()
                .find_map(|entry| entry.trail_id.as_ref().map(ToString::to_string)),
        ),
    };

    let anchor = anchor
        .filter(|anchor| anchor.trail_path == trail_path)
        .map(|anchor| {
            let comparison = anchor::compare_entries(entries, anchor);
            AnchorReport {
                path: String::new(),
                sequence: anchor.sequence,
                hash: anchor.hash.clone(),
                anchored_at: anchor.anchored_at.clone(),
                finding: comparison.to_string(),
                comparison,
            }
        });

    VerifyReport {
        trail: trail_path.display().to_string(),
        entries: entries.len() as u64,
        head_sequence,
        head_hash,
        trail_id,
        chain,
        anchor,
    }
}

/// Reads a trail and its anchor and reports on both.
///
/// # Errors
///
/// [`GarrisonErrorKind::Configuration`](crate::error::GarrisonErrorKind::Configuration)
/// when the trail cannot be read or is not a trail, or when an anchor exists
/// and cannot be parsed. Neither is a verdict about the chain, so neither
/// reports as one.
pub fn run(trail_path: &Path, anchor_path: &Path) -> Result<VerifyReport, GarrisonError> {
    let contents = std::fs::read_to_string(trail_path).map_err(|error| {
        GarrisonError::configuration(
            "audit.trail",
            format!(
                "the audit trail at {} could not be read: {error}",
                trail_path.display()
            ),
        )
    })?;

    let entries = parse_entries(&contents).map_err(|error| {
        GarrisonError::configuration(
            "audit.trail",
            format!(
                "the file at {} is not an audit trail: {error}",
                trail_path.display()
            ),
        )
    })?;

    let anchor = anchor::read(anchor_path)?;
    let mut report = report(trail_path, &entries, anchor.as_ref());
    if let Some(reported) = report.anchor.as_mut() {
        reported.path = anchor_path.display().to_string();
    }

    Ok(report)
}

/// Renders a report for a human, in the order the questions are asked.
#[must_use]
pub fn render(report: &VerifyReport) -> String {
    let mut lines = vec![
        format!("audit trail: {}", report.trail),
        format!("entries:     {}", report.entries),
        format!(
            "head:        {} @ {}",
            report.head_sequence, report.head_hash
        ),
    ];

    if let Some(trail_id) = report.trail_id.as_deref() {
        lines.push(format!("trail:       {trail_id}"));
    }

    match &report.chain {
        ChainVerdict::Intact => lines.push("chain:       verified".to_string()),
        ChainVerdict::Broken {
            finding,
            line,
            sequence,
        } => lines.push(format!(
            "chain:       BROKEN at line {line}, sequence {sequence}: {finding}"
        )),
    }

    match report.anchor.as_ref() {
        Some(anchor) => {
            lines.push(format!(
                "anchor:      {} @ {} ({}, written {})",
                anchor.sequence, anchor.hash, anchor.path, anchor.anchored_at
            ));
            lines.push(format!("finding:     {}", anchor.finding));
        }
        None => lines.push(
            "anchor:      none for this trail; tail truncation cannot be detected".to_string(),
        ),
    }

    lines.join("\n")
}

/// The trail this daemon's acton-ai configuration arms, when it arms one.
///
/// Resolved from acton-ai's own config rather than duplicated in
/// `garrison.toml`: there is one trail, and the file that names it is the
/// file that arms it.
#[must_use]
pub fn configured_trail(acton_config: Option<&Path>) -> Option<PathBuf> {
    let config = match acton_config {
        Some(path) => acton_ai::config::from_path(path).ok()?,
        None => acton_ai::config::load().ok()?,
    };

    config
        .audit
        .and_then(|audit| audit.to_audit().ok())
        .map(|audit| audit.path().to_path_buf())
}

/// The error a finding becomes, or `None` when there is nothing to report.
///
/// The mapping onto exit codes lives here rather than in the command, because
/// the two enums it reads are `#[non_exhaustive]` and a later verdict must
/// land on a deliberate code rather than on a wildcard somebody wrote once.
#[must_use]
pub fn refusal(report: &VerifyReport) -> Option<GarrisonError> {
    match Outcome::of(report) {
        Outcome::Clean => None,
        Outcome::ChainBroken => Some(GarrisonError::audit_chain_broken(match &report.chain {
            ChainVerdict::Broken {
                finding,
                line,
                sequence,
            } => format!("line {line}, sequence {sequence}: {finding}"),
            ChainVerdict::Intact => "the chain is intact".to_string(),
        })),
        Outcome::AnchorMismatch => Some(GarrisonError::audit_anchor_mismatch(
            report
                .anchor
                .as_ref()
                .map_or_else(|| "no anchor".to_string(), |anchor| anchor.finding.clone()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor_report(comparison: HeadComparison) -> AnchorReport {
        AnchorReport {
            path: "/state/anchor.json".to_string(),
            sequence: 3,
            hash: "c".to_string(),
            anchored_at: "2026-08-29T09:00:00Z".to_string(),
            finding: comparison.to_string(),
            comparison,
        }
    }

    fn reported(chain: ChainVerdict, anchor: Option<AnchorReport>) -> VerifyReport {
        VerifyReport {
            trail: "/trail/audit.jsonl".to_string(),
            entries: 3,
            head_sequence: 3,
            head_hash: "c".to_string(),
            trail_id: None,
            chain,
            anchor,
        }
    }

    fn broken() -> ChainVerdict {
        ChainVerdict::Broken {
            finding: "the entry's hash does not cover its contents".to_string(),
            line: 2,
            sequence: 2,
        }
    }

    fn anchor_for(trail_path: &Path, sequence: u64, hash: &str) -> Anchor {
        Anchor {
            schema_version: anchor::SCHEMA_VERSION,
            install: None,
            trail_path: trail_path.to_path_buf(),
            trail_id: None,
            sequence,
            hash: hash.to_string(),
            entries: sequence,
            anchored_at: "2026-08-29T09:00:00Z".to_string(),
        }
    }

    #[test]
    fn a_verified_chain_with_a_matching_anchor_is_clean() {
        let report = reported(
            ChainVerdict::Intact,
            Some(anchor_report(HeadComparison::Matches)),
        );

        assert_eq!(Outcome::of(&report), Outcome::Clean);
        assert!(refusal(&report).is_none());
    }

    #[test]
    fn a_chain_that_grew_past_its_anchor_is_clean() {
        let report = reported(
            ChainVerdict::Intact,
            Some(anchor_report(HeadComparison::Advanced { by: 4 })),
        );

        assert_eq!(Outcome::of(&report), Outcome::Clean);
    }

    #[test]
    fn a_verified_chain_that_lost_its_tail_exits_four() {
        let report = reported(
            ChainVerdict::Intact,
            Some(anchor_report(HeadComparison::Truncated {
                anchored_sequence: 3,
                found_sequence: 1,
            })),
        );

        assert_eq!(Outcome::of(&report), Outcome::AnchorMismatch);
        let error = refusal(&report).expect("a mismatch is reported");
        assert!(error.is_audit_anchor_mismatch());
        assert_eq!(crate::daemon::exit_code(&error), 4);
        assert!(error.to_string().contains("truncated"), "{error}");
    }

    #[test]
    fn a_rewritten_entry_below_the_anchor_exits_four() {
        let report = reported(
            ChainVerdict::Intact,
            Some(anchor_report(HeadComparison::Diverged {
                anchored_hash: "c".to_string(),
                found_hash: "x".to_string(),
            })),
        );

        assert_eq!(
            crate::daemon::exit_code(&refusal(&report).expect("reported")),
            4
        );
    }

    #[test]
    fn a_broken_chain_exits_three() {
        let report = reported(broken(), None);

        assert_eq!(Outcome::of(&report), Outcome::ChainBroken);
        let error = refusal(&report).expect("a broken chain is reported");
        assert_eq!(crate::daemon::exit_code(&error), 3);
        assert!(error.to_string().contains("line 2"), "{error}");
    }

    #[test]
    fn a_broken_chain_outranks_an_anchor_mismatch() {
        let report = reported(
            broken(),
            Some(anchor_report(HeadComparison::Truncated {
                anchored_sequence: 3,
                found_sequence: 1,
            })),
        );

        assert_eq!(Outcome::of(&report), Outcome::ChainBroken);
    }

    #[test]
    fn without_an_anchor_nothing_can_be_said_about_the_tail() {
        let report = reported(ChainVerdict::Intact, None);

        assert_eq!(Outcome::of(&report), Outcome::Clean);
        assert!(render(&report).contains("cannot be detected"));
    }

    #[test]
    fn the_rendering_states_the_finding_a_human_acts_on() {
        let report = reported(
            ChainVerdict::Intact,
            Some(anchor_report(HeadComparison::Truncated {
                anchored_sequence: 3,
                found_sequence: 1,
            })),
        );

        let text = render(&report);

        assert!(text.contains("chain:       verified"), "{text}");
        assert!(text.contains("anchor:      3 @ c"), "{text}");
        assert!(
            text.contains("2 entries were removed from the tail"),
            "{text}"
        );
    }

    #[test]
    fn a_broken_chain_says_where_it_broke() {
        let text = render(&reported(broken(), None));

        assert!(text.contains("BROKEN at line 2, sequence 2"), "{text}");
    }

    #[test]
    fn an_empty_trail_against_a_real_anchor_is_a_truncation() {
        let path = Path::new("/trail/audit.jsonl");

        // An empty chain verifies; only the anchor knows three entries are
        // missing, which is the whole reason it exists.
        let report = report(path, &[], Some(&anchor_for(path, 3, "c")));

        assert_eq!(report.chain, ChainVerdict::Intact);
        assert_eq!(Outcome::of(&report), Outcome::AnchorMismatch);
    }

    #[test]
    fn an_anchor_for_another_trail_is_left_out_of_the_report() {
        let anchor = anchor_for(Path::new("/elsewhere/audit.jsonl"), 3, "c");

        let report = report(Path::new("/trail/audit.jsonl"), &[], Some(&anchor));

        assert!(report.anchor.is_none());
        assert_eq!(Outcome::of(&report), Outcome::Clean);
    }

    #[test]
    fn reading_an_empty_trail_and_its_anchor_finds_the_truncation() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let trail_path = dir.path().join("audit.jsonl");
        let anchor_path = dir.path().join("anchor.json");
        std::fs::write(&trail_path, "").expect("the trail is writable");
        anchor::write(&anchor_path, &anchor_for(&trail_path, 2, "b"))
            .expect("the anchor is writable");

        let report = run(&trail_path, &anchor_path).expect("both files read");

        assert_eq!(Outcome::of(&report), Outcome::AnchorMismatch);
        assert_eq!(
            report.anchor.as_ref().expect("compared").path,
            anchor_path.display().to_string()
        );
    }

    #[test]
    fn a_trail_with_no_anchor_file_verifies_without_one() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let trail_path = dir.path().join("audit.jsonl");
        std::fs::write(&trail_path, "").expect("the trail is writable");

        let report = run(&trail_path, &dir.path().join("absent.json")).expect("read");

        assert!(report.anchor.is_none());
        assert_eq!(Outcome::of(&report), Outcome::Clean);
    }

    #[test]
    fn a_missing_trail_is_a_configuration_error_and_not_a_verdict() {
        let dir = tempfile::tempdir().expect("a temp dir");

        let error = run(&dir.path().join("absent.jsonl"), &dir.path().join("a.json"))
            .expect_err("a missing trail cannot be verified");

        assert!(error.is_configuration());
        assert_eq!(crate::daemon::exit_code(&error), 2);
    }

    #[test]
    fn a_file_that_is_not_a_trail_is_a_configuration_error() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let trail_path = dir.path().join("audit.jsonl");
        std::fs::write(&trail_path, "not an entry\n").expect("writable");

        let error = run(&trail_path, &dir.path().join("a.json")).expect_err("not a trail");

        assert!(error.is_configuration());
    }
}
