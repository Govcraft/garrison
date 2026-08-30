//! What a review found, and getting it out of a model's answer intact.
//!
//! # Why findings are JSON and not prose
//!
//! A finding that cannot be resolved to a file and a line cannot be posted
//! inline on a pull request, which is the entire point of review mode. Prose
//! that says "the input handling in the request parser looks unsafe" is not
//! actionable by a machine and barely actionable by a human: nobody knows
//! which of four parsers it means.
//!
//! So the review prompt asks for a JSON array and this module parses it. The
//! cost is that a model sometimes answers in a shape the prompt did not ask
//! for. That cost is paid here, in [`parse_findings`], rather than by a
//! pipeline that silently reports zero findings because the answer had a
//! markdown fence around it.
//!
//! # The rule this module exists to enforce
//!
//! An unparseable answer is **not** an empty review. Those two outcomes look
//! identical to a caller that returns `Vec::new()` on error, and they mean
//! opposite things: one is "this code is fine", the other is "nobody looked".
//! A pipeline that treats the second as the first ships unreviewed code with
//! a green check on it, which is worse than having no review at all, because
//! now there is evidence of a review that did not happen.

use serde::{Deserialize, Serialize};

/// How seriously the reviewer means a finding.
///
/// Three levels rather than Bitbucket's two, because a reviewer that can only
/// say "blocker" or "not a blocker" says "blocker" too often. The collapse to
/// Bitbucket's pair happens at the boundary, in [`Self::is_blocking`], where
/// it can be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing, not worth stopping for.
    Minor,
    /// A real defect that should be fixed, but does not risk correctness or
    /// security on its own.
    Major,
    /// Correctness, security, or data loss. The only level that can fail a
    /// build, and then only when blocking is switched on.
    Blocker,
}

impl Severity {
    /// Whether a finding at this level can fail a build.
    ///
    /// Note what this does *not* decide: whether it actually does. Blocking is
    /// opt-in policy, and a reviewer that fails builds by default would be
    /// asserting that a model's opinion outranks a developer's on their first
    /// day in the pipeline. This answers "is this the kind of finding that
    /// could", and the run's policy answers the rest.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Blocker)
    }

    /// The name to print, matching what the prompt asks the model to emit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minor => "minor",
            Self::Major => "major",
            Self::Blocker => "blocker",
        }
    }
}

/// One thing the reviewer noticed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// The file, as the diff named it.
    pub file: String,
    /// The line in the destination, which is the side a reviewer reads.
    pub line: u64,
    /// How seriously this is meant.
    pub severity: Severity,
    /// What is wrong, in one or two sentences.
    pub message: String,
}

/// What came back from asking a model to review a diff.
///
/// This is an enum rather than a `Result<Vec<Finding>, _>` so that the third
/// case cannot be quietly folded into the first by a `unwrap_or_default`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Review {
    /// The reviewer looked and found nothing.
    ///
    /// A real outcome and a common one. It is distinct from
    /// [`Unreadable`](Self::Unreadable) on purpose.
    Clean,
    /// The reviewer looked and found these, worst first.
    Findings(Vec<Finding>),
    /// The answer could not be read as a review at all.
    ///
    /// The pipeline must treat this as a failed run, not a clean one.
    Unreadable {
        /// Why it could not be read.
        reason: String,
        /// The first part of what came back, for an operator to look at.
        excerpt: String,
    },
}

impl Review {
    /// The findings, or none when the review was clean.
    ///
    /// Returns an empty slice for [`Unreadable`](Self::Unreadable) too, so
    /// this must never be the only thing a caller looks at. Ask
    /// [`is_unreadable`](Self::is_unreadable) first.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        match self {
            Self::Findings(findings) => findings,
            Self::Clean | Self::Unreadable { .. } => &[],
        }
    }

    /// Whether the answer could not be read as a review.
    #[must_use]
    pub const fn is_unreadable(&self) -> bool {
        matches!(self, Self::Unreadable { .. })
    }

    /// How many findings are at a level that could fail a build.
    #[must_use]
    pub fn blocking_count(&self) -> usize {
        self.findings()
            .iter()
            .filter(|finding| finding.severity.is_blocking())
            .count()
    }
}

/// Pulls the JSON array out of an answer that may have prose wrapped around it.
///
/// Models are asked for bare JSON and frequently supply a markdown fence, a
/// sentence of preamble, or both. Refusing those would turn a good review into
/// an [`Unreadable`](Review::Unreadable) over punctuation, so this looks for
/// the outermost bracketed span rather than demanding the whole answer be
/// JSON.
fn extract_array(answer: &str) -> Option<&str> {
    let start = answer.find('[')?;
    // Scan for the matching bracket rather than taking the last one in the
    // string: a message field containing "[sic]" would otherwise swallow the
    // rest of the answer.
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;

    for (offset, character) in answer[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '[' if !in_string => depth += 1,
            ']' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(&answer[start..=start + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

/// The first `limit` characters of `text`, for an error an operator will read.
fn excerpt(text: &str, limit: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= limit {
        return trimmed.to_string();
    }
    let head: String = trimmed.chars().take(limit).collect();
    format!("{head}...")
}

/// Reads a model's answer into a review.
///
/// Findings come back sorted worst-first, because a reviewer that leads with
/// three nitpicks before a security hole has buried the thing that mattered.
/// Ties keep the model's own order, which tends to follow the file.
#[must_use]
pub fn parse_findings(answer: &str) -> Review {
    let Some(array) = extract_array(answer) else {
        // No brackets at all. Usually a model that answered in prose, or
        // refused, or emitted an apology. Whatever it is, it is not a review.
        return Review::Unreadable {
            reason: "the answer contained no JSON array of findings".into(),
            excerpt: excerpt(answer, 300),
        };
    };

    let parsed: Vec<Finding> = match serde_json::from_str(array) {
        Ok(findings) => findings,
        Err(error) => {
            return Review::Unreadable {
                reason: format!("the findings array did not parse: {error}"),
                excerpt: excerpt(array, 300),
            }
        }
    };

    if parsed.is_empty() {
        return Review::Clean;
    }

    let mut findings = parsed;
    // Stable, so equal severities stay in the order the model listed them.
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
    Review::Findings(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_array_of_findings_parses() {
        let review = parse_findings(
            r#"[{"file":"src/a.rs","line":12,"severity":"blocker","message":"unchecked index"}]"#,
        );
        assert_eq!(review.findings().len(), 1);
        assert_eq!(review.findings()[0].file, "src/a.rs");
        assert_eq!(review.findings()[0].line, 12);
        assert_eq!(review.blocking_count(), 1);
    }

    #[test]
    fn an_empty_array_is_clean_and_not_a_failure() {
        // The reviewer looked and found nothing. This has to be sharply
        // distinct from the unreadable case below.
        assert_eq!(parse_findings("[]"), Review::Clean);
        assert!(!parse_findings("[]").is_unreadable());
    }

    #[test]
    fn a_markdown_fence_does_not_cost_a_good_review() {
        let answer = "Here is what I found:\n\n```json\n[{\"file\":\"a.rs\",\"line\":1,\
                      \"severity\":\"minor\",\"message\":\"typo\"}]\n```\n\nThat is all.";
        assert_eq!(parse_findings(answer).findings().len(), 1);
    }

    #[test]
    fn findings_come_back_worst_first() {
        let answer = r#"[
            {"file":"a.rs","line":1,"severity":"minor","message":"m"},
            {"file":"b.rs","line":2,"severity":"blocker","message":"b"},
            {"file":"c.rs","line":3,"severity":"major","message":"j"}
        ]"#;
        let review = parse_findings(answer);
        let severities: Vec<_> = review
            .findings()
            .iter()
            .map(|finding| finding.severity)
            .collect();
        assert_eq!(
            severities,
            vec![Severity::Blocker, Severity::Major, Severity::Minor],
            "a security hole listed after two nitpicks has been buried"
        );
    }

    #[test]
    fn equal_severities_keep_the_order_the_model_gave_them() {
        let answer = r#"[
            {"file":"z.rs","line":1,"severity":"major","message":"first"},
            {"file":"a.rs","line":2,"severity":"major","message":"second"}
        ]"#;
        let review = parse_findings(answer);
        assert_eq!(review.findings()[0].message, "first");
    }

    #[test]
    fn prose_with_no_array_is_unreadable_rather_than_clean() {
        // The failure this whole module exists to prevent: a pipeline reading
        // "I could not access the files" as "no findings" and going green.
        let review = parse_findings("I was unable to review the diff.");
        assert!(review.is_unreadable());
        assert_ne!(review, Review::Clean);
        assert_eq!(review.blocking_count(), 0);
    }

    #[test]
    fn a_refusal_is_unreadable_and_names_what_came_back() {
        let review = parse_findings("I'm sorry, I can't help with that.");
        match review {
            Review::Unreadable { excerpt, .. } => {
                assert!(excerpt.contains("can't help"), "{excerpt}");
            }
            other => panic!("a refusal is not a review: {other:?}"),
        }
    }

    #[test]
    fn a_malformed_array_is_unreadable_and_says_so() {
        let review = parse_findings(r#"[{"file":"a.rs","line":"not a number"}]"#);
        assert!(review.is_unreadable());
        match review {
            Review::Unreadable { reason, .. } => {
                assert!(reason.contains("did not parse"), "{reason}")
            }
            other => panic!("expected unreadable: {other:?}"),
        }
    }

    #[test]
    fn an_unknown_severity_makes_the_review_unreadable_not_silently_minor() {
        // Downgrading an unrecognized level to the mildest one would let a
        // model's "critical" finding pass as advisory.
        let review =
            parse_findings(r#"[{"file":"a.rs","line":1,"severity":"critical","message":"m"}]"#);
        assert!(review.is_unreadable());
    }

    #[test]
    fn a_bracket_inside_a_message_does_not_swallow_the_answer() {
        // Scanning for the matching bracket rather than the last one in the
        // string is what keeps this from parsing as one giant broken span.
        let answer = r#"[{"file":"a.rs","line":1,"severity":"minor","message":"typo [sic] here"}]

        Some trailing prose with ] a stray bracket."#;
        let review = parse_findings(answer);
        assert_eq!(review.findings().len(), 1);
        assert!(review.findings()[0].message.contains("[sic]"));
    }

    #[test]
    fn an_escaped_quote_in_a_message_does_not_break_the_scan() {
        let answer = r#"[{"file":"a.rs","line":1,"severity":"minor","message":"said \"hi\""}]"#;
        assert_eq!(parse_findings(answer).findings().len(), 1);
    }

    #[test]
    fn only_blockers_count_as_blocking() {
        let answer = r#"[
            {"file":"a.rs","line":1,"severity":"major","message":"m"},
            {"file":"b.rs","line":2,"severity":"blocker","message":"b"},
            {"file":"c.rs","line":3,"severity":"minor","message":"n"}
        ]"#;
        assert_eq!(parse_findings(answer).blocking_count(), 1);
    }

    #[test]
    fn severity_names_round_trip_through_the_prompt_spelling() {
        // The prompt tells the model these three words. If they drift from
        // what serde accepts, every review becomes unreadable at once.
        for severity in [Severity::Minor, Severity::Major, Severity::Blocker] {
            let json = format!(
                r#"[{{"file":"a.rs","line":1,"severity":"{}","message":"m"}}]"#,
                severity.as_str()
            );
            assert_eq!(
                parse_findings(&json).findings()[0].severity,
                severity,
                "the prompt spells {severity:?} in a way serde will not read back"
            );
        }
    }
}
