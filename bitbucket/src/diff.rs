//! Reading a pull request's diff, and finding a line to hang a comment on.
//!
//! # Why this is not a unified-diff parser
//!
//! Bitbucket DC does not serve `/pull-requests/{id}/diff` as text. It serves
//! JSON: a list of changed files, each with a list of hunks, each with a list
//! of segments tagged `ADDED`, `REMOVED` or `CONTEXT`, each segment holding
//! lines that carry **both** their source and destination line numbers.
//!
//! That shape is the whole reason inline comments work. To anchor a comment
//! Bitbucket wants a line number *and* which side of the diff it belongs to,
//! and getting that wrong does not fail loudly — it silently attaches the
//! comment to a different line, which is worse than not posting it. So the
//! anchoring rule lives in [`Anchor::for_line`] as a pure function with the
//! awkward cases written down as tests.

use serde::Deserialize;

/// Which side of a diff a line is on, and where.
///
/// Bitbucket's rule, restated because it is easy to get backwards: `TO` means
/// the line exists in the destination and is anchored by `destination`; `FROM`
/// means it existed only in the source and is anchored by `source`. A context
/// line exists on both sides, and Bitbucket wants it anchored to the
/// destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// The path in the destination, which is what a reviewer is looking at.
    pub path: String,
    /// The line number on whichever side `file_type` names.
    pub line: u64,
    /// `TO` for added and context lines, `FROM` for removed ones.
    pub file_type: &'static str,
    /// Always `COMMIT` for a pull-request review: the comment belongs to the
    /// change, not to a file's whole history.
    pub diff_type: &'static str,
}

impl Anchor {
    /// Where a comment about `line` in `file` should hang, if anywhere.
    ///
    /// Returns `None` when the line is not part of the diff at all. That is a
    /// refusal on purpose: a reviewer that found something on an unchanged
    /// line is either confused or reviewing more than the pull request
    /// changed, and posting the comment somewhere approximate would put words
    /// next to code that did not cause them.
    #[must_use]
    pub fn for_line(file: &ChangedFile, line: u64) -> Option<Self> {
        for hunk in &file.hunks {
            for segment in &hunk.segments {
                for entry in &segment.lines {
                    let (matches, number, side) = match segment.kind.as_str() {
                        // A removed line only exists on the source side.
                        "REMOVED" => (entry.source == line, entry.source, "FROM"),
                        // Added and context lines both live in the
                        // destination, which is the side a reviewer reads.
                        _ => (entry.destination == line, entry.destination, "TO"),
                    };
                    if matches {
                        return Some(Self {
                            path: file.path.clone(),
                            line: number,
                            file_type: side,
                            diff_type: "COMMIT",
                        });
                    }
                }
            }
        }
        None
    }
}

/// One line inside a segment.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Line {
    /// Line number on the source side.
    #[serde(default)]
    pub source: u64,
    /// Line number on the destination side.
    #[serde(default)]
    pub destination: u64,
    /// The text, without a trailing newline.
    #[serde(default)]
    pub line: String,
}

/// A run of lines that are all the same kind of change.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Segment {
    /// `ADDED`, `REMOVED`, or `CONTEXT`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The lines in this run.
    #[serde(default)]
    pub lines: Vec<Line>,
}

/// A contiguous region of a file that changed, with its context.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Hunk {
    /// The runs of lines making up this hunk.
    #[serde(default)]
    pub segments: Vec<Segment>,
}

/// One file the pull request touches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedFile {
    /// The path in the destination, or the source path for a deletion.
    pub path: String,
    /// The regions that changed.
    pub hunks: Vec<Hunk>,
    /// Whether Bitbucket declined to diff this file.
    ///
    /// True for a binary file, and for one past the server's size limit. A
    /// reviewer must not be handed an empty hunk list for such a file and
    /// conclude nothing changed.
    pub truncated: bool,
}

impl ChangedFile {
    /// The destination text of this file's changed regions, as a reviewer
    /// would read it: added and context lines in order, removed lines gone.
    ///
    /// This is what a review prompt is built from, so it is deliberately not
    /// the raw diff. A model asked to review `-` and `+` markers tends to
    /// comment on the markers.
    #[must_use]
    pub fn destination_text(&self) -> String {
        let mut out = String::new();
        for hunk in &self.hunks {
            for segment in &hunk.segments {
                if segment.kind == "REMOVED" {
                    continue;
                }
                for entry in &segment.lines {
                    out.push_str(&entry.line);
                    out.push('\n');
                }
            }
        }
        out
    }
}

/// The envelope Bitbucket wraps a diff in.
#[derive(Debug, Deserialize)]
struct DiffResponse {
    #[serde(default)]
    diffs: Vec<RawDiff>,
}

#[derive(Debug, Deserialize)]
struct RawDiff {
    #[serde(default)]
    source: Option<PathRef>,
    #[serde(default)]
    destination: Option<PathRef>,
    #[serde(default)]
    hunks: Vec<Hunk>,
    #[serde(default)]
    truncated: bool,
}

#[derive(Debug, Deserialize)]
struct PathRef {
    #[serde(rename = "toString")]
    to_string: String,
}

/// Reads a `/changes`-style diff response into changed files.
///
/// # Errors
///
/// [`BitbucketError::Malformed`](crate::BitbucketError::Malformed) when the
/// body is not the shape this client understands. A diff whose `destination`
/// and `source` are both absent is skipped rather than failing the whole
/// review: one unnameable entry should not cost the other forty files their
/// comments.
pub fn parse_diff(body: &str) -> Result<Vec<ChangedFile>, crate::BitbucketError> {
    let parsed: DiffResponse = serde_json::from_str(body)
        .map_err(|error| crate::BitbucketError::Malformed(format!("diff response: {error}")))?;

    Ok(parsed
        .diffs
        .into_iter()
        .filter_map(|diff| {
            // A deletion has no destination; fall back to the source path so
            // the file is still named.
            let path = diff
                .destination
                .or(diff.source)
                .map(|reference| reference.to_string)?;
            Some(ChangedFile {
                path,
                hunks: diff.hunks,
                truncated: diff.truncated,
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A two-line change: line 10 removed, lines 10 and 11 added, with
    /// context either side. The line numbers are the awkward part — source
    /// and destination diverge after the change, and every anchoring bug
    /// lives in that gap.
    const DIFF: &str = r#"{
      "diffs": [{
        "source": {"toString": "src/lib.rs"},
        "destination": {"toString": "src/lib.rs"},
        "hunks": [{
          "segments": [
            {"type": "CONTEXT", "lines": [
              {"source": 9, "destination": 9, "line": "fn before() {}"}
            ]},
            {"type": "REMOVED", "lines": [
              {"source": 10, "destination": 9, "line": "let x = 1;"}
            ]},
            {"type": "ADDED", "lines": [
              {"source": 10, "destination": 10, "line": "let x = 2;"},
              {"source": 10, "destination": 11, "line": "let y = 3;"}
            ]},
            {"type": "CONTEXT", "lines": [
              {"source": 11, "destination": 12, "line": "fn after() {}"}
            ]}
          ]
        }],
        "truncated": false
      }]
    }"#;

    fn changed() -> ChangedFile {
        parse_diff(DIFF).unwrap().pop().unwrap()
    }

    #[test]
    fn a_diff_names_its_file_and_keeps_its_hunks() {
        let files = parse_diff(DIFF).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/lib.rs");
        assert_eq!(files[0].hunks.len(), 1);
        assert!(!files[0].truncated);
    }

    #[test]
    fn an_added_line_anchors_to_the_destination() {
        let anchor = Anchor::for_line(&changed(), 11).expect("line 11 was added");
        assert_eq!(anchor.file_type, "TO");
        assert_eq!(anchor.line, 11);
        assert_eq!(anchor.path, "src/lib.rs");
        assert_eq!(anchor.diff_type, "COMMIT");
    }

    #[test]
    fn a_context_line_anchors_to_the_destination_not_the_source() {
        // Source 11 and destination 12 are the same line of code. Anchoring
        // it to 11 would put the comment one line up in the reviewer's view.
        let anchor = Anchor::for_line(&changed(), 12).expect("line 12 is context");
        assert_eq!(anchor.file_type, "TO");
        assert_eq!(anchor.line, 12);
    }

    #[test]
    fn a_line_outside_the_diff_gets_no_anchor() {
        // Not a lookup failure to paper over: a finding on an unchanged line
        // is a finding about code this pull request did not touch.
        assert!(Anchor::for_line(&changed(), 900).is_none());
    }

    #[test]
    fn the_reviewable_text_drops_removed_lines_and_keeps_the_rest() {
        let text = changed().destination_text();
        assert!(text.contains("let x = 2;"), "{text}");
        assert!(text.contains("fn after() {}"), "{text}");
        assert!(
            !text.contains("let x = 1;"),
            "a removed line is not in the destination: {text}"
        );
    }

    #[test]
    fn a_deleted_file_is_still_named_by_its_source_path() {
        let body = r#"{"diffs":[{"source":{"toString":"gone.rs"},"hunks":[],"truncated":false}]}"#;
        let files = parse_diff(body).unwrap();
        assert_eq!(files[0].path, "gone.rs");
    }

    #[test]
    fn a_binary_file_reports_truncated_rather_than_looking_unchanged() {
        let body =
            r#"{"diffs":[{"destination":{"toString":"logo.png"},"hunks":[],"truncated":true}]}"#;
        let files = parse_diff(body).unwrap();
        assert!(
            files[0].truncated,
            "a reviewer must not read empty hunks as 'nothing changed'"
        );
    }

    #[test]
    fn a_diff_naming_no_path_is_skipped_rather_than_failing_the_review() {
        let body = r#"{"diffs":[{"hunks":[],"truncated":false},
                                 {"destination":{"toString":"kept.rs"},"hunks":[],"truncated":false}]}"#;
        let files = parse_diff(body).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "kept.rs");
    }

    #[test]
    fn a_body_that_is_not_a_diff_is_malformed_rather_than_empty() {
        assert!(parse_diff("not json").is_err());
    }

    #[test]
    fn an_empty_diff_list_is_a_pull_request_that_changed_nothing() {
        assert!(parse_diff(r#"{"diffs":[]}"#).unwrap().is_empty());
    }
}
