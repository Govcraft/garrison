//! The instruction a reviewer is given, built from the diff it is reviewing.
//!
//! Review is a mode, not a vibe. The difference is in here: a fixed set of
//! rules about what to look at, what to say, and what shape to say it in,
//! with the diff appended rather than described.

use std::fmt::Write as _;

/// One file's worth of reviewable text.
///
/// Deliberately not [`garrison_bitbucket::ChangedFile`]: review mode also runs
/// against a local `git diff`, and coupling the prompt to Bitbucket's model
/// would mean no reviewing anything that is not already a pull request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewFile {
    /// The path, as the diff named it.
    pub path: String,
    /// The destination text of the changed regions, with context.
    pub text: String,
    /// Whether the diff for this file was withheld.
    ///
    /// A binary file, or one past the server's size limit. The reviewer is
    /// told rather than handed nothing, so it does not report a file as clean
    /// having never seen it.
    pub truncated: bool,
}

/// The rules a reviewer works under, independent of any particular diff.
///
/// Kept as a constant so the whole of review mode's behaviour is one thing to
/// read, and so a test can assert the rules that matter are still in it.
const RULES: &str = "\
You are reviewing a pull request diff. Report only defects you can point at in \
the code shown.

Rules:
- Findings first. No preamble, no summary, no restating the diff.
- Only comment on lines present in the diff below. You cannot see the rest of \
the file, so a finding about code you were not shown is a guess.
- Prefer silence to speculation. An empty result is a valid and common answer, \
and a reviewer that always finds something is not read twice.
- Do not comment on style, formatting, or naming unless it causes a defect.
- One finding per problem. Do not split one bug across three entries.

Severity, and mean it:
- \"blocker\": correctness, security, or data loss.
- \"major\": a real defect worth fixing that is none of the above.
- \"minor\": worth knowing, not worth stopping for.

Answer with a JSON array and nothing else:

[{\"file\": \"path/as/shown.rs\", \"line\": 42, \"severity\": \"blocker\", \
\"message\": \"one or two sentences\"}]

The \"line\" must be a line number shown in the margin of the file below. \
Answer [] if you found nothing.";

/// Builds the full prompt for one review.
///
/// Line numbers are rendered in a left margin rather than left to the model to
/// count. Counting is exactly the kind of task a model is unreliable at, and
/// an off-by-one here does not fail loudly: it posts a correct finding onto
/// the wrong line, where it reads as a false positive and teaches a team to
/// ignore the reviewer.
#[must_use]
pub fn build(files: &[ReviewFile]) -> String {
    let mut prompt = String::from(RULES);
    prompt.push_str("\n\n---\n");

    for file in files {
        let _ = write!(prompt, "\n## {}\n", file.path);

        if file.truncated {
            // Say it rather than showing an empty body. A reviewer handed
            // nothing concludes there is nothing wrong.
            prompt.push_str(
                "\n(this file's diff was withheld by the server, as binary or \
                 too large; it has not been reviewed)\n",
            );
            continue;
        }

        prompt.push_str("\n```\n");
        for (offset, line) in file.text.lines().enumerate() {
            let _ = writeln!(prompt, "{:>5} | {line}", offset + 1);
        }
        prompt.push_str("```\n");
    }

    prompt
}

/// The margin line numbers the prompt showed, in order, for one file.
///
/// The prompt renders a 1-based margin over the *destination text*, which is
/// not the same as the file's real line numbers. A caller resolving a
/// finding's line back to somewhere in the pull request needs this mapping,
/// and reconstructing it by re-counting is how the two drift apart.
#[must_use]
pub fn margin_len(file: &ReviewFile) -> usize {
    if file.truncated {
        0
    } else {
        file.text.lines().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, text: &str) -> ReviewFile {
        ReviewFile {
            path: path.into(),
            text: text.into(),
            truncated: false,
        }
    }

    #[test]
    fn the_prompt_shows_line_numbers_rather_than_asking_for_counting() {
        let prompt = build(&[file("a.rs", "one\ntwo\nthree")]);
        assert!(prompt.contains("    1 | one"), "{prompt}");
        assert!(prompt.contains("    3 | three"), "{prompt}");
    }

    #[test]
    fn the_prompt_names_each_file_so_a_finding_can_say_which() {
        let prompt = build(&[file("src/a.rs", "x"), file("src/b.rs", "y")]);
        assert!(prompt.contains("## src/a.rs"), "{prompt}");
        assert!(prompt.contains("## src/b.rs"), "{prompt}");
    }

    #[test]
    fn a_withheld_file_is_declared_rather_than_shown_empty() {
        // The failure this prevents: a binary file rendered as an empty code
        // block, which reads to a reviewer as "nothing wrong here".
        let prompt = build(&[ReviewFile {
            path: "logo.png".into(),
            text: String::new(),
            truncated: true,
        }]);
        assert!(prompt.contains("logo.png"), "{prompt}");
        assert!(prompt.contains("has not been reviewed"), "{prompt}");
    }

    #[test]
    fn the_rules_ask_for_the_three_severities_the_parser_accepts() {
        // These strings are the contract between the prompt and
        // `finding::Severity`. If they drift, every review parses as
        // unreadable and the cause is two files apart.
        let prompt = build(&[]);
        for name in ["blocker", "major", "minor"] {
            assert!(prompt.contains(&format!("\"{name}\"")), "missing {name}");
        }
    }

    #[test]
    fn the_rules_ask_for_an_empty_array_rather_than_prose_when_clean() {
        // Without this the model writes "I found no issues", which parses as
        // unreadable and fails a run that should have passed.
        assert!(build(&[]).contains("Answer [] if you found nothing"));
    }

    #[test]
    fn the_rules_forbid_commenting_outside_the_diff() {
        // A finding on a line the diff does not contain cannot be anchored,
        // so asking for it wastes a finding.
        assert!(build(&[]).contains("Only comment on lines present in the diff"));
    }

    #[test]
    fn the_margin_length_matches_what_was_rendered() {
        let subject = file("a.rs", "one\ntwo\nthree");
        assert_eq!(margin_len(&subject), 3);
    }

    #[test]
    fn a_withheld_file_has_no_margin_because_nothing_was_shown() {
        let subject = ReviewFile {
            path: "logo.png".into(),
            text: "ignored".into(),
            truncated: true,
        };
        assert_eq!(margin_len(&subject), 0);
    }

    #[test]
    fn an_empty_review_still_carries_the_rules() {
        // A diff with no files is a real case (a pull request that only moves
        // a branch pointer), and the prompt must still be well-formed.
        let prompt = build(&[]);
        assert!(prompt.contains("Findings first"), "{prompt}");
    }
}
