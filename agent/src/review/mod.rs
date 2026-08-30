//! Review mode: read a diff, say what is wrong with it, and nothing else.
//!
//! # What makes this a mode rather than a prompt
//!
//! Three things, and all of them are enforced here rather than requested of
//! the model:
//!
//! 1. **It writes nothing.** Review is read-only by nature, and a pipeline has
//!    nobody to answer a permission prompt. So a tool that wants to write is
//!    refused rather than auto-approved. See [`Permissions`].
//! 2. **Its output has a shape.** Findings are JSON with a file and a line, so
//!    they can be posted where the code is. Prose cannot be anchored.
//! 3. **It distinguishes "nothing wrong" from "nobody looked".** The two are
//!    one careless `unwrap_or_default` apart, and confusing them puts a green
//!    check on unreviewed code.
//!
//! # Layout
//!
//! [`prompt`] builds the instruction, [`finding`] reads the answer, and
//! [`outcome`] decides what the answer means for the build. All three are pure
//! and tested without a model, a socket, or a Bitbucket. What is left over is
//! the part that cannot be pure: connecting, prompting, and posting.

pub mod finding;
pub mod outcome;
pub mod post;
pub mod prompt;

pub use finding::{parse_findings, Finding, Review, Severity};
pub use outcome::{decide, Blocking, Outcome};
pub use post::{place, render, Placed};
pub use prompt::{build as build_prompt, margin_len, ReviewFile};

/// How review mode answers a permission request.
///
/// There is exactly one policy, and it is not configurable: refuse. The issue
/// that asked for this mode called out that a pipeline "cannot answer a
/// permission request", and offered auto-approval as the alternative. Refusing
/// is the honest one. A review that needed to write to do its job was not a
/// review, and a mode that silently granted writes because nobody was watching
/// would be the exact opposite of what Garrison claims to be.
///
/// Note this is about *tool* permissions, not about whether the run may read
/// the diff. Reading is what it is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Permissions;

impl Permissions {
    /// Whether a tool call may proceed.
    ///
    /// Always false. The signature takes the tool's name so that a refusal can
    /// say which tool asked, which is the difference between a debuggable
    /// pipeline log and a mysterious one.
    #[must_use]
    pub const fn allows(self, _tool: &str) -> bool {
        false
    }

    /// What to tell the model when it asks.
    ///
    /// Phrased as a statement about the mode rather than about the tool, so a
    /// model does not conclude the call failed and retry it three times.
    #[must_use]
    pub fn refusal(self, tool: &str) -> String {
        format!(
            "{tool} was refused: review mode is read-only and runs unattended, \
             so no tool that changes anything can be approved. Report what you \
             found in the diff you were given."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_mode_refuses_every_tool_that_asks() {
        // Including ones that sound harmless. A mode that reasons about which
        // writes are safe is a mode that eventually approves one.
        for tool in ["write_file", "apply_patch", "bash", "read_file"] {
            assert!(
                !Permissions.allows(tool),
                "{tool} was allowed in a read-only mode"
            );
        }
    }

    #[test]
    fn a_refusal_names_the_tool_so_a_pipeline_log_is_debuggable() {
        let message = Permissions.refusal("apply_patch");
        assert!(message.contains("apply_patch"), "{message}");
    }

    #[test]
    fn a_refusal_explains_the_mode_rather_than_reading_as_a_transient_failure() {
        // A model told only "denied" retries. One told why does not.
        let message = Permissions.refusal("bash");
        assert!(message.contains("read-only"), "{message}");
    }
}
