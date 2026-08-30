//! Turning findings into comments a pull request will accept.
//!
//! # The gap this module is about
//!
//! A finding names a file and a margin line from the prompt. A Bitbucket
//! comment needs a path, a real destination line, and a side of the diff.
//! Between those two lies every way a review can quietly go wrong: a file the
//! diff does not contain, a line past the end of what was shown, a model that
//! answered about the wrong pull request.
//!
//! None of those are dropped silently. A finding that cannot be anchored is
//! still reported, as a comment on the pull request itself, because a real
//! defect with a bad line number is still a real defect. What is lost is the
//! inline placement, and the comment says so.

use super::finding::Finding;
use garrison_bitbucket::{Anchor, ChangedFile, Comment, Severity as WireSeverity};

/// A finding paired with where it will be posted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placed {
    /// The comment to post.
    pub comment: Comment,
    /// Whether it landed on the line it named.
    ///
    /// False means the finding survived but its placement did not, which is
    /// worth counting: a review where half the findings could not be anchored
    /// is a review whose line numbers should not be trusted.
    pub anchored: bool,
}

/// How Garrison signs a comment it wrote.
///
/// Present on every comment, without exception. A person reading a pull
/// request must never have to guess whether a comment came from a colleague or
/// a model, and a footer that appears only sometimes is worse than none: it
/// teaches readers that unmarked comments are human.
const ATTRIBUTION: &str = "\n\n---\n_Posted by Garrison review._";

/// Renders one finding as the comment text a reviewer will read.
///
/// The severity is stated in the body rather than left to Bitbucket's own
/// styling, because Bitbucket has two levels and this has three: a "major"
/// and a "minor" both post as NORMAL and would otherwise be indistinguishable.
#[must_use]
pub fn render(finding: &Finding, anchored: bool) -> String {
    let mut text = format!("**{}**: {}", finding.severity.as_str(), finding.message);

    if !anchored {
        // Say where it was meant to go. Without this the reader sees a
        // file-level comment about line 40 and cannot tell whether the
        // reviewer meant a different file or simply missed.
        text.push_str(&format!(
            "\n\n_(reported at `{}:{}`, which is not a line in this diff, so this \
             could not be posted inline)_",
            finding.file, finding.line
        ));
    }

    text.push_str(ATTRIBUTION);
    text
}

/// Bitbucket carries two severities; this carries three. The collapse is here,
/// in one place, where it can be read.
const fn to_wire(severity: super::finding::Severity) -> WireSeverity {
    if severity.is_blocking() {
        WireSeverity::Blocker
    } else {
        WireSeverity::Normal
    }
}

/// Places every finding, inline where possible.
///
/// `blocking` decides whether a blocker-severity finding posts as a Bitbucket
/// BLOCKER, which surfaces as an unresolved task and can gate a merge. In
/// advisory mode it does not: a comment that blocks a merge is a block,
/// whatever the build status says, so advisory has to mean advisory here too
/// or the setting is a lie.
#[must_use]
pub fn place(
    findings: &[Finding],
    files: &[ChangedFile],
    blocking: super::outcome::Blocking,
) -> Vec<Placed> {
    findings
        .iter()
        .map(|finding| {
            let anchor = files
                .iter()
                .find(|file| file.path == finding.file)
                .and_then(|file| {
                    // Two hops, and both can fail: the margin line the model
                    // named may be past what it was shown, and the resolved
                    // destination line may still not anchor.
                    let line = file.destination_line_at(finding.line as usize)?;
                    Anchor::for_line(file, line)
                });

            let anchored = anchor.is_some();
            let severity = match blocking {
                super::outcome::Blocking::Enforcing => to_wire(finding.severity),
                super::outcome::Blocking::Advisory => WireSeverity::Normal,
            };

            Placed {
                comment: Comment {
                    text: render(finding, anchored),
                    anchor,
                    severity,
                },
                anchored,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::finding::Severity;
    use super::super::outcome::Blocking;
    use super::*;

    const DIFF: &str = r#"{
      "diffs": [{
        "destination": {"toString": "src/a.rs"},
        "hunks": [{
          "segments": [
            {"type": "CONTEXT", "lines": [{"source": 9, "destination": 9, "line": "before"}]},
            {"type": "ADDED", "lines": [
              {"source": 10, "destination": 10, "line": "let x = 2;"},
              {"source": 10, "destination": 11, "line": "let y = 3;"}
            ]}
          ]
        }],
        "truncated": false
      }]
    }"#;

    fn files() -> Vec<ChangedFile> {
        garrison_bitbucket::parse_diff(DIFF).unwrap()
    }

    fn finding(file: &str, line: u64, severity: Severity) -> Finding {
        Finding {
            file: file.into(),
            line,
            severity,
            message: "something is wrong".into(),
        }
    }

    #[test]
    fn a_finding_on_a_shown_line_anchors_to_the_real_destination_line() {
        // Margin 2 is destination line 10, not line 2.
        let placed = place(
            &[finding("src/a.rs", 2, Severity::Major)],
            &files(),
            Blocking::Advisory,
        );
        assert!(placed[0].anchored);
        let anchor = placed[0].comment.anchor.as_ref().unwrap();
        assert_eq!(anchor.line, 10);
        assert_eq!(anchor.path, "src/a.rs");
    }

    #[test]
    fn a_finding_past_the_end_of_the_excerpt_survives_without_its_placement() {
        // The defect may be real even when the line number is not. Dropping it
        // would lose a finding; clamping it would misplace one.
        let placed = place(
            &[finding("src/a.rs", 99, Severity::Blocker)],
            &files(),
            Blocking::Advisory,
        );
        assert_eq!(placed.len(), 1, "the finding was dropped");
        assert!(!placed[0].anchored);
        assert!(placed[0].comment.anchor.is_none());
        assert!(
            placed[0]
                .comment
                .text
                .contains("could not be posted inline"),
            "{}",
            placed[0].comment.text
        );
    }

    #[test]
    fn a_finding_about_a_file_not_in_the_diff_survives_the_same_way() {
        let placed = place(
            &[finding("src/elsewhere.rs", 1, Severity::Major)],
            &files(),
            Blocking::Advisory,
        );
        assert!(!placed[0].anchored);
        assert!(placed[0].comment.text.contains("src/elsewhere.rs"));
    }

    #[test]
    fn advisory_mode_does_not_post_a_blocker_that_would_gate_the_merge() {
        // A BLOCKER comment is an unresolved task in Bitbucket, which blocks
        // regardless of build status. Advisory has to mean advisory here or
        // the setting does not do what it says.
        let placed = place(
            &[finding("src/a.rs", 1, Severity::Blocker)],
            &files(),
            Blocking::Advisory,
        );
        assert_eq!(placed[0].comment.severity, WireSeverity::Normal);
    }

    #[test]
    fn enforcing_mode_posts_a_blocker_as_a_blocker() {
        let placed = place(
            &[finding("src/a.rs", 1, Severity::Blocker)],
            &files(),
            Blocking::Enforcing,
        );
        assert_eq!(placed[0].comment.severity, WireSeverity::Blocker);
    }

    #[test]
    fn a_major_finding_is_never_a_wire_blocker_even_enforcing() {
        let placed = place(
            &[finding("src/a.rs", 1, Severity::Major)],
            &files(),
            Blocking::Enforcing,
        );
        assert_eq!(placed[0].comment.severity, WireSeverity::Normal);
    }

    #[test]
    fn every_comment_says_garrison_wrote_it() {
        // Both the anchored and unanchored paths, because an attribution that
        // appears only sometimes teaches readers that unmarked comments are
        // from a person.
        for line in [1_u64, 99] {
            let placed = place(
                &[finding("src/a.rs", line, Severity::Minor)],
                &files(),
                Blocking::Advisory,
            );
            assert!(
                placed[0].comment.text.contains("Garrison review"),
                "line {line}: {}",
                placed[0].comment.text
            );
        }
    }

    #[test]
    fn the_severity_is_stated_in_the_body_because_the_wire_has_only_two() {
        // A major and a minor both post as NORMAL. Without this the reader
        // cannot tell them apart.
        let text = render(&finding("a.rs", 1, Severity::Major), true);
        assert!(text.contains("major"), "{text}");
        let minor = render(&finding("a.rs", 1, Severity::Minor), true);
        assert!(minor.contains("minor"), "{minor}");
    }

    #[test]
    fn no_findings_places_nothing() {
        assert!(place(&[], &files(), Blocking::Advisory).is_empty());
    }
}
