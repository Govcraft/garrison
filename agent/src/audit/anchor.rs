//! The chain head, remembered somewhere the trail is not.
//!
//! # Why an anchor exists at all
//!
//! A hash chain detects a rewrite and detects an insertion. It does not
//! detect a **truncation**, because a prefix of a valid chain is itself a
//! valid chain: delete the last ten entries of a trail and `verify_chain`
//! still reports it intact, at a lower head, with nothing to say about what
//! used to be above it. The only thing that can notice is a record of where
//! the chain *used to end*, kept outside the file being verified.
//!
//! That record is the anchor: a small JSON file holding the last head this
//! daemon saw, written after every finished turn and at a clean shutdown. It
//! is not a security boundary — it sits on the same host, under the same
//! user, as the trail — but it turns silent tail deletion into a refusal to
//! start and a non-zero exit from `garrison-agent audit verify`, which is
//! precisely the failure that would otherwise leave no trace.
//!
//! # The seam for the plane
//!
//! The independently protected copy of this same value is the control
//! plane's `AuditChain` row, which issue #8 writes. [`Anchor`] carries
//! exactly the fields that row wants — head hash, sequence, entry count,
//! trail identity, install — so #8 adds a second sink for the value this
//! module already computes rather than a second mechanism. Nothing here
//! reaches for the plane, and nothing here may: the plane is not on the
//! durability path, and a turn is never blocked on it.
//!
//! # Purity
//!
//! [`Anchor::compare`], [`compare_entries`], [`verdict`] and
//! [`startup_decision`] are pure functions over values. Only [`read`] and
//! [`write`] touch a disk, and they do nothing else.

use crate::config::AnchorMismatchAction;
use crate::error::GarrisonError;
use acton_ai::audit::{AuditEntry, ChainHead};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The version stamped into every anchor this build writes.
pub const SCHEMA_VERSION: u32 = 1;

/// The last chain head this install vouched for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Anchor {
    /// The layout of this file, so a later field is an upgrade rather than a
    /// parse error.
    pub schema_version: u32,
    /// The plane's row id for this install, when it has enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<String>,
    /// The trail this head belongs to, canonicalized.
    ///
    /// Compared before the head is: an anchor describing a different file is
    /// not evidence about this one, and treating it as such would refuse a
    /// perfectly good trail the first time an operator moved one.
    pub trail_path: PathBuf,
    /// The trail's identity, once acton-ai has sealed one into the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trail_id: Option<String>,
    /// The sequence number of the last entry.
    pub sequence: u64,
    /// The hash of that entry.
    pub hash: String,
    /// How many entries the chain held.
    pub entries: u64,
    /// When this anchor was written, RFC 3339.
    pub anchored_at: String,
}

impl Anchor {
    /// Records a head as this install's anchor.
    #[must_use]
    pub fn from_head(
        trail_path: &Path,
        head: &ChainHead,
        install: Option<String>,
        anchored_at: String,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            install,
            trail_path: trail_path.to_path_buf(),
            trail_id: head.trail_id.as_ref().map(ToString::to_string),
            sequence: head.sequence,
            hash: head.hash.clone(),
            entries: head.entries,
            anchored_at,
        }
    }

    /// How a trail's head stands against this anchor. Pure.
    ///
    /// The order of the checks is the order of decreasing certainty about
    /// what happened: a different trail identity is unambiguous, a shorter
    /// chain can only be a truncation, and a same-length chain with a
    /// different hash can only be a rewrite. `Advanced` is last because it is
    /// the ordinary case — the daemon wrote entries after its last anchor.
    #[must_use]
    pub fn compare(&self, head: &ChainHead) -> HeadComparison {
        let found_trail = head.trail_id.as_ref().map(ToString::to_string);
        if let (Some(anchored), Some(found)) = (self.trail_id.as_ref(), found_trail.as_ref()) {
            if anchored != found {
                return HeadComparison::TrailChanged {
                    anchored: anchored.clone(),
                    found: found.clone(),
                };
            }
        }

        if head.sequence < self.sequence {
            return HeadComparison::Truncated {
                anchored_sequence: self.sequence,
                found_sequence: head.sequence,
            };
        }

        if head.sequence == self.sequence {
            return if head.hash == self.hash {
                HeadComparison::Matches
            } else {
                HeadComparison::Diverged {
                    anchored_hash: self.hash.clone(),
                    found_hash: head.hash.clone(),
                }
            };
        }

        HeadComparison::Advanced {
            by: head.sequence - self.sequence,
        }
    }
}

/// What comparing a trail against an anchor found.
///
/// Non-exhaustive: a later integrity check adds a verdict, and a client
/// matching on these must not break when it does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
#[non_exhaustive]
pub enum HeadComparison {
    /// The trail ends exactly where the anchor says it should.
    Matches,
    /// The trail has grown past the anchor, which is what a daemon that
    /// wrote entries after its last anchor looks like.
    Advanced {
        /// How many entries past the anchor the chain now runs.
        by: u64,
    },
    /// The trail ends *before* the anchor: entries were removed from the
    /// tail. This is the failure the anchor exists to catch.
    Truncated {
        /// Where the anchor says the chain ended.
        anchored_sequence: u64,
        /// Where it ends now.
        found_sequence: u64,
    },
    /// The chain reaches the anchored sequence carrying a different hash:
    /// an entry at or below the anchor was rewritten.
    Diverged {
        /// The hash the anchor vouched for.
        anchored_hash: String,
        /// The hash found in its place.
        found_hash: String,
    },
    /// The file at the trail's path is a different trail entirely.
    TrailChanged {
        /// The identity the anchor was written under.
        anchored: String,
        /// The identity the file carries now.
        found: String,
    },
}

impl HeadComparison {
    /// Whether this verdict says the trail lost or altered recorded history.
    ///
    /// `Matches` and `Advanced` are not mismatches: a chain that grew is what
    /// a running daemon produces between anchors.
    #[must_use]
    pub const fn is_mismatch(&self) -> bool {
        !matches!(self, Self::Matches | Self::Advanced { .. })
    }
}

impl std::fmt::Display for HeadComparison {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Matches => f.write_str("the trail ends where the anchor says it should"),
            Self::Advanced { by } => write!(
                f,
                "the trail has grown {by} entries past the anchor, which is what a daemon \
                 that ran after its last anchor looks like"
            ),
            Self::Truncated {
                anchored_sequence,
                found_sequence,
            } => {
                let lost = anchored_sequence.saturating_sub(*found_sequence);
                write!(
                    f,
                    "the trail is truncated: the anchor vouches for {anchored_sequence} entries \
                     and only {found_sequence} remain, so {lost} {} removed from the tail",
                    if lost == 1 {
                        "entry was"
                    } else {
                        "entries were"
                    }
                )
            }
            Self::Diverged {
                anchored_hash,
                found_hash,
            } => write!(
                f,
                "the trail diverges from the anchor: the entry at the anchored sequence was \
                 expected to hash to {anchored_hash} and hashes to {found_hash}, so recorded \
                 history was rewritten"
            ),
            Self::TrailChanged { anchored, found } => write!(
                f,
                "the file is a different trail: the anchor was written for {anchored} and \
                 the file carries {found}"
            ),
        }
    }
}

/// One link of a chain, reduced to what an anchor comparison needs.
///
/// The comparison cares about two numbers and a string, so it takes those
/// rather than whole entries: that is what lets every verdict be tested as a
/// table of values instead of a fixture of sealed records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// Its position in the chain.
    pub sequence: u64,
    /// Its hash.
    pub hash: String,
}

impl From<&AuditEntry> for Link {
    fn from(entry: &AuditEntry) -> Self {
        Self {
            sequence: entry.sequence,
            hash: entry.hash.clone(),
        }
    }
}

/// The stronger comparison, for a verifier holding the whole chain.
///
/// [`Anchor::compare`] sees only the head, so a chain that was rewritten
/// below the anchor and then extended past it reads as `Advanced`. With every
/// link in hand the anchored sequence can be looked up directly, which closes
/// that hole. Pure.
///
/// The links must already have been verified as a chain; this asks only
/// whether the anchor's claim about one of them still holds.
#[must_use]
pub fn compare_links(links: &[Link], anchor: &Anchor) -> HeadComparison {
    let last = links.last().map_or(0, |link| link.sequence);

    let Some(link) = links.iter().find(|link| link.sequence == anchor.sequence) else {
        // Sequence 0 is the empty chain, which every trail is a suffix of.
        if anchor.sequence == 0 {
            return HeadComparison::Matches;
        }
        return HeadComparison::Truncated {
            anchored_sequence: anchor.sequence,
            found_sequence: last,
        };
    };

    if link.hash != anchor.hash {
        return HeadComparison::Diverged {
            anchored_hash: anchor.hash.clone(),
            found_hash: link.hash.clone(),
        };
    }

    if last > anchor.sequence {
        HeadComparison::Advanced {
            by: last - anchor.sequence,
        }
    } else {
        HeadComparison::Matches
    }
}

/// [`compare_links`] over sealed entries.
#[must_use]
pub fn compare_entries(entries: &[AuditEntry], anchor: &Anchor) -> HeadComparison {
    let links: Vec<Link> = entries.iter().map(Link::from).collect();
    compare_links(&links, anchor)
}

/// What an anchor had to say about a trail.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnchorVerdict {
    /// No anchor has ever been written, which is every first run.
    NoAnchor,
    /// The anchor describes a different trail, so it is evidence about
    /// something else.
    OtherTrail {
        /// The trail the anchor was written for.
        anchored: PathBuf,
        /// The trail being checked.
        found: PathBuf,
    },
    /// The anchor and the trail were compared.
    Compared(HeadComparison),
}

/// Reads an anchor against a trail. Pure.
#[must_use]
pub fn verdict(anchor: Option<&Anchor>, trail_path: &Path, head: &ChainHead) -> AnchorVerdict {
    let Some(anchor) = anchor else {
        return AnchorVerdict::NoAnchor;
    };

    if anchor.trail_path != trail_path {
        return AnchorVerdict::OtherTrail {
            anchored: anchor.trail_path.clone(),
            found: trail_path.to_path_buf(),
        };
    }

    AnchorVerdict::Compared(anchor.compare(head))
}

/// What startup does about a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupDecision {
    /// Start, saying nothing.
    Proceed,
    /// Start, but say this first.
    Warn(String),
    /// Do not start, and say this.
    Refuse(String),
}

/// Turns a verdict into a decision. Pure, and the whole startup rule.
///
/// - No anchor, or an anchor for another trail, proceeds with a note. An
///   operator who moved a trail, or who is starting a daemon for the first
///   time, must not be met with a refusal they cannot act on.
/// - `Advanced` proceeds with a note. The daemon that wrote past the anchor
///   died before re-anchoring, which a crash produces routinely. The residual
///   risk — an attacker deleting only the entries above the anchor — is why
///   the keeper re-anchors after every finished turn rather than only at
///   shutdown, and why #8 pushes the same head to the plane.
/// - Everything else is a mismatch, and
///   [`AnchorMismatchAction`] decides whether that stops the daemon.
#[must_use]
pub fn startup_decision(verdict: &AnchorVerdict, action: AnchorMismatchAction) -> StartupDecision {
    match verdict {
        AnchorVerdict::NoAnchor => StartupDecision::Proceed,
        AnchorVerdict::OtherTrail { anchored, found } => StartupDecision::Warn(format!(
            "the audit anchor was written for {} and this daemon writes {}; \
             it is being re-anchored to the trail in use",
            anchored.display(),
            found.display()
        )),
        AnchorVerdict::Compared(comparison) if !comparison.is_mismatch() => match comparison {
            HeadComparison::Advanced { .. } => StartupDecision::Warn(comparison.to_string()),
            _ => StartupDecision::Proceed,
        },
        AnchorVerdict::Compared(comparison) => {
            let finding = comparison.to_string();
            match action {
                AnchorMismatchAction::Refuse => StartupDecision::Refuse(format!(
                    "{finding}. This is a refusal to start (exit 2), not a crash: restarting \
                     will not change the answer. Keep the trail and the anchor as evidence, \
                     run `garrison-agent audit verify` for the full finding, and only once \
                     an operator has decided what happened move the trail aside so a new \
                     chain begins, or set [audit] on_anchor_mismatch = \"warn\" if this \
                     deployment would rather run than stop"
                )),
                AnchorMismatchAction::Warn => StartupDecision::Warn(format!(
                    "{finding}. [audit] on_anchor_mismatch = \"warn\" is set, so the daemon \
                     is starting anyway and appending to a trail known to be incomplete"
                )),
            }
        }
    }
}

/// Reads the anchor at `path`.
///
/// A missing file is `None` and not an error: never having anchored is the
/// first run. A present but unreadable one *is* an error, because silently
/// treating a corrupt anchor as absent would discard the one record that can
/// notice a truncation.
///
/// # Errors
///
/// [`GarrisonErrorKind::Configuration`](crate::error::GarrisonErrorKind::Configuration)
/// when the file exists and cannot be read or parsed.
pub fn read(path: &Path) -> Result<Option<Anchor>, GarrisonError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(GarrisonError::configuration(
                "audit.anchor_path",
                format!(
                    "the audit anchor at {} could not be read: {error}",
                    path.display()
                ),
            ))
        }
    };

    serde_json::from_str(&text).map(Some).map_err(|error| {
        GarrisonError::configuration(
            "audit.anchor_path",
            format!(
                "the audit anchor at {} is not an anchor: {error}. Move it aside only after \
                 an operator has looked at it: it is the record of where the trail ended",
                path.display()
            ),
        )
    })
}

/// Writes an anchor, atomically, readable only by its owner.
///
/// Temp file, fsync, rename: a crash mid-write leaves the previous anchor
/// intact rather than a half-written one, because an anchor that cannot be
/// parsed is an anchor that refuses to start the daemon.
///
/// # Errors
///
/// [`GarrisonErrorKind::Runtime`](crate::error::GarrisonErrorKind::Runtime)
/// when the directory cannot be created or the file cannot be written.
pub fn write(path: &Path, anchor: &Anchor) -> Result<(), GarrisonError> {
    use std::io::Write as _;

    let failed = |what: &str, error: &dyn std::fmt::Display| {
        GarrisonError::runtime(format!(
            "the audit anchor at {} could not be {what}: {error}",
            path.display()
        ))
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| failed("created", &error))?;
    }

    let json = serde_json::to_string_pretty(anchor).map_err(|error| failed("encoded", &error))?;
    let temp = path.with_extension("json.tmp");

    let mut file = std::fs::File::create(&temp).map_err(|error| failed("created", &error))?;
    restrict(&file).map_err(|error| failed("restricted to its owner", &error))?;
    file.write_all(json.as_bytes())
        .map_err(|error| failed("written", &error))?;
    file.write_all(b"\n")
        .map_err(|error| failed("written", &error))?;
    file.sync_all().map_err(|error| failed("synced", &error))?;
    drop(file);

    std::fs::rename(&temp, path).map_err(|error| failed("renamed into place", &error))
}

/// Mode 0600: the anchor states where a compliance record ends, and only the
/// user who owns the daemon has any business reading or writing it.
#[cfg(unix)]
fn restrict(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use acton_ai::audit::GENESIS_HASH;

    fn head(sequence: u64, hash: &str) -> ChainHead {
        ChainHead {
            sequence,
            hash: hash.to_string(),
            entries: sequence,
            trail_id: None,
        }
    }

    fn anchor_at(sequence: u64, hash: &str) -> Anchor {
        Anchor::from_head(
            Path::new("/trail/audit.jsonl"),
            &head(sequence, hash),
            None,
            "2026-08-29T00:00:00Z".to_string(),
        )
    }

    #[test]
    fn an_unchanged_trail_matches_its_anchor() {
        assert_eq!(
            anchor_at(3, "abc").compare(&head(3, "abc")),
            HeadComparison::Matches
        );
    }

    #[test]
    fn a_trail_that_grew_since_the_anchor_has_advanced() {
        assert_eq!(
            anchor_at(3, "abc").compare(&head(7, "zzz")),
            HeadComparison::Advanced { by: 4 }
        );
    }

    #[test]
    fn a_shorter_trail_is_a_truncation() {
        assert_eq!(
            anchor_at(3, "abc").compare(&head(2, "bbb")),
            HeadComparison::Truncated {
                anchored_sequence: 3,
                found_sequence: 2,
            }
        );
    }

    #[test]
    fn the_same_length_with_a_different_hash_is_a_rewrite() {
        assert_eq!(
            anchor_at(3, "abc").compare(&head(3, "xyz")),
            HeadComparison::Diverged {
                anchored_hash: "abc".to_string(),
                found_hash: "xyz".to_string(),
            }
        );
    }

    #[test]
    fn a_different_identity_at_the_same_path_is_a_different_trail() {
        let mine = acton_ai::types::TrailId::new();
        let theirs = acton_ai::types::TrailId::new();
        let mut anchor = anchor_at(3, "abc");
        anchor.trail_id = Some(mine.to_string());
        let mut found = head(9, "zzz");
        found.trail_id = Some(theirs.clone());

        // The identity is checked before the sequence, so a longer chain
        // under a new identity does not read as ordinary growth.
        assert_eq!(
            anchor.compare(&found),
            HeadComparison::TrailChanged {
                anchored: mine.to_string(),
                found: theirs.to_string(),
            }
        );
    }

    #[test]
    fn the_same_identity_compares_by_head_as_usual() {
        let id = acton_ai::types::TrailId::new();
        let mut anchor = anchor_at(3, "abc");
        anchor.trail_id = Some(id.to_string());
        let mut found = head(3, "abc");
        found.trail_id = Some(id);

        assert_eq!(anchor.compare(&found), HeadComparison::Matches);
    }

    #[test]
    fn an_emptied_trail_is_a_truncation_to_genesis() {
        assert_eq!(
            anchor_at(5, "abc").compare(&head(0, GENESIS_HASH)),
            HeadComparison::Truncated {
                anchored_sequence: 5,
                found_sequence: 0,
            }
        );
    }

    #[test]
    fn a_finding_an_operator_reads_counts_in_english() {
        // An audit finding is read by a person deciding whether to escalate,
        // so it says "1 entry was" rather than "1 entries were".
        let one = HeadComparison::Truncated {
            anchored_sequence: 3,
            found_sequence: 2,
        };
        let several = HeadComparison::Truncated {
            anchored_sequence: 9,
            found_sequence: 2,
        };

        assert!(one.to_string().contains("1 entry was removed"), "{one}");
        assert!(
            several.to_string().contains("7 entries were removed"),
            "{several}"
        );
    }

    #[test]
    fn a_comparison_serializes_in_the_case_the_status_wire_uses() {
        // The verify report and `_garrison/status` are camelCase; a nested
        // verdict that spelled its fields differently would be a second
        // convention in one document.
        let json = serde_json::to_value(HeadComparison::Truncated {
            anchored_sequence: 3,
            found_sequence: 2,
        })
        .expect("serializable");

        assert_eq!(json["kind"], "truncated");
        assert_eq!(json["anchoredSequence"], 3);
        assert_eq!(json["foundSequence"], 2);
    }

    #[test]
    fn only_losing_or_altering_history_counts_as_a_mismatch() {
        assert!(!HeadComparison::Matches.is_mismatch());
        assert!(!HeadComparison::Advanced { by: 2 }.is_mismatch());
        assert!(HeadComparison::Truncated {
            anchored_sequence: 3,
            found_sequence: 1
        }
        .is_mismatch());
        assert!(HeadComparison::Diverged {
            anchored_hash: "a".to_string(),
            found_hash: "b".to_string()
        }
        .is_mismatch());
        assert!(HeadComparison::TrailChanged {
            anchored: "a".to_string(),
            found: "b".to_string()
        }
        .is_mismatch());
    }

    fn links(hashes: &[&str]) -> Vec<Link> {
        hashes
            .iter()
            .enumerate()
            .map(|(index, hash)| Link {
                sequence: index as u64 + 1,
                hash: (*hash).to_string(),
            })
            .collect()
    }

    #[test]
    fn a_whole_chain_matches_an_anchor_at_its_end() {
        assert_eq!(
            compare_links(&links(&["a", "b", "c"]), &anchor_at(3, "c")),
            HeadComparison::Matches
        );
    }

    #[test]
    fn a_chain_missing_its_tail_is_a_truncation_against_the_anchor() {
        assert_eq!(
            compare_links(&links(&["a", "b"]), &anchor_at(3, "c")),
            HeadComparison::Truncated {
                anchored_sequence: 3,
                found_sequence: 2,
            }
        );
    }

    #[test]
    fn a_rewrite_below_the_anchor_is_caught_even_when_the_chain_grew() {
        // The head comparison alone cannot see this: sequence 5 is past the
        // anchor's 2, so it reads as ordinary growth.
        let anchor = anchor_at(2, "b");
        let grown = links(&["a", "rewritten", "c", "d", "e"]);

        assert_eq!(
            anchor.compare(&head(5, "e")),
            HeadComparison::Advanced { by: 3 },
            "the head alone cannot see a rewrite below it",
        );
        assert_eq!(
            compare_links(&grown, &anchor),
            HeadComparison::Diverged {
                anchored_hash: "b".to_string(),
                found_hash: "rewritten".to_string(),
            },
        );
    }

    #[test]
    fn a_chain_that_grew_past_a_still_valid_anchor_has_advanced() {
        assert_eq!(
            compare_links(&links(&["a", "b", "c", "d"]), &anchor_at(2, "b")),
            HeadComparison::Advanced { by: 2 }
        );
    }

    #[test]
    fn an_anchor_at_genesis_is_satisfied_by_any_chain() {
        assert_eq!(
            compare_links(&[], &anchor_at(0, GENESIS_HASH)),
            HeadComparison::Matches
        );
        assert_eq!(
            compare_links(&links(&["a"]), &anchor_at(0, GENESIS_HASH)),
            HeadComparison::Matches
        );
    }

    #[test]
    fn an_emptied_file_is_a_truncation_against_a_real_anchor() {
        assert_eq!(
            compare_links(&[], &anchor_at(2, "b")),
            HeadComparison::Truncated {
                anchored_sequence: 2,
                found_sequence: 0,
            }
        );
    }

    #[test]
    fn no_anchor_is_the_first_run_and_not_a_verdict() {
        assert_eq!(
            verdict(None, Path::new("/trail/audit.jsonl"), &head(4, "abc")),
            AnchorVerdict::NoAnchor
        );
        assert_eq!(
            startup_decision(&AnchorVerdict::NoAnchor, AnchorMismatchAction::Refuse),
            StartupDecision::Proceed
        );
    }

    #[test]
    fn an_anchor_for_another_trail_is_evidence_about_something_else() {
        let anchor = anchor_at(3, "abc");

        let verdict = verdict(
            Some(&anchor),
            Path::new("/other/audit.jsonl"),
            &head(0, "x"),
        );

        assert!(matches!(verdict, AnchorVerdict::OtherTrail { .. }));
        assert!(matches!(
            startup_decision(&verdict, AnchorMismatchAction::Refuse),
            StartupDecision::Warn(_)
        ));
    }

    #[test]
    fn a_truncated_trail_refuses_the_daemon_by_default() {
        let anchor = anchor_at(3, "abc");
        let verdict = verdict(
            Some(&anchor),
            Path::new("/trail/audit.jsonl"),
            &head(1, "a"),
        );

        let StartupDecision::Refuse(message) =
            startup_decision(&verdict, AnchorMismatchAction::Refuse)
        else {
            panic!("a truncated trail must refuse to start");
        };

        assert!(message.contains("truncated"), "{message}");
        assert!(message.contains("exit 2"), "{message}");
        assert!(message.contains("audit verify"), "{message}");
    }

    #[test]
    fn warn_mode_starts_over_a_truncated_trail_and_says_so() {
        let anchor = anchor_at(3, "abc");
        let verdict = verdict(
            Some(&anchor),
            Path::new("/trail/audit.jsonl"),
            &head(1, "a"),
        );

        let StartupDecision::Warn(message) = startup_decision(&verdict, AnchorMismatchAction::Warn)
        else {
            panic!("warn mode must start");
        };

        assert!(message.contains("incomplete"), "{message}");
    }

    #[test]
    fn a_grown_trail_starts_but_says_why_the_anchor_is_behind() {
        let anchor = anchor_at(3, "abc");
        let verdict = verdict(
            Some(&anchor),
            Path::new("/trail/audit.jsonl"),
            &head(5, "e"),
        );

        assert!(matches!(
            startup_decision(&verdict, AnchorMismatchAction::Refuse),
            StartupDecision::Warn(_)
        ));
    }

    #[test]
    fn a_matching_trail_starts_silently() {
        let anchor = anchor_at(3, "abc");
        let verdict = verdict(
            Some(&anchor),
            Path::new("/trail/audit.jsonl"),
            &head(3, "abc"),
        );

        assert_eq!(
            startup_decision(&verdict, AnchorMismatchAction::Refuse),
            StartupDecision::Proceed
        );
    }

    #[test]
    fn an_anchor_round_trips_through_a_file_readable_only_by_its_owner() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("nested").join("audit-anchor.json");
        let anchor = anchor_at(4, "deadbeef");

        write(&path, &anchor).expect("the anchor must be writable");

        assert_eq!(read(&path).expect("readable"), Some(anchor));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the anchor must not be world-readable");
        }
    }

    #[test]
    fn a_missing_anchor_reads_as_never_anchored() {
        let dir = tempfile::tempdir().expect("a temp dir");

        assert_eq!(
            read(&dir.path().join("absent.json")).expect("no error"),
            None
        );
    }

    #[test]
    fn a_corrupt_anchor_is_an_error_rather_than_a_fresh_start() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("audit-anchor.json");
        std::fs::write(&path, "{not json").expect("writable");

        let error = read(&path).expect_err("a corrupt anchor must not read as absent");

        assert!(error.is_configuration());
    }

    #[test]
    fn writing_an_anchor_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("audit-anchor.json");

        write(&path, &anchor_at(1, "a")).expect("writable");
        write(&path, &anchor_at(2, "b")).expect("writable again");

        let names: Vec<_> = std::fs::read_dir(dir.path())
            .expect("readable")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["audit-anchor.json".to_string()]);
    }
}
