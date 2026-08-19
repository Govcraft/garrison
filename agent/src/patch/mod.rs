//! `apply_patch`: a structural edit tool with a safety assessment.
//!
//! # Why not string replacement
//!
//! An agent that edits by exact-string replacement fails the moment the file
//! has changed since it was read — a reformat, another agent's edit, a rebase.
//! It then either fails loudly on every second edit or, worse, matches
//! somewhere it did not mean to. This module addresses lines by their
//! *surrounding content* instead, with bounded tolerance for drift, which is
//! the idea Garrison takes from OpenAI Codex's `apply-patch` crate (see
//! `NOTICE`).
//!
//! # The pipeline
//!
//! 1. [`parse`] — text to a [`Patch`]. Pure. Fails with a line number.
//! 2. [`safety::assess`] — is this allowed? Reads the tree's shape, writes
//!    nothing. Refuses anything outside the session's writable roots, whatever
//!    the operator says.
//! 3. [`apply::plan`] — resolve every hunk against the tree. Reads files,
//!    writes none. Fails with the hunk index and either every ambiguous
//!    candidate or the closest near miss.
//! 4. [`apply::commit`] — write.
//!
//! Steps 1 to 3 all fail before a single byte moves, which is why a patch that
//! breaks on its third hunk leaves the tree exactly as it was.
//!
//! # Where the human fits
//!
//! [`preflight`] is consulted by the approval hook before it interrupts
//! anybody: a patch that only creates new files inside the root is approved
//! without a dialog, an impossible one is refused without a dialog, and
//! everything that destroys existing content goes to the operator through the
//! ACP `session/request_permission` round-trip like any other tool call.

pub mod apply;
pub mod format;
pub mod parse;
pub mod safety;
pub mod seek;
pub mod tool;

pub use apply::{commit, plan, Change, Planned};
pub use format::{Chunk, Hunk, Patch};
pub use parse::parse;
pub use safety::{assess, SafetyCheck};
pub use seek::{locate, Fidelity, Located};
pub use tool::{definition, install, TOOL_NAME};

use acton_ai::policy::{ApprovalDecision, ToolInvocation};
use std::path::Path;

/// What the model is told `apply_patch` is and how to write one.
///
/// Deliberately verbatim-detailed. A model that has never seen this format
/// will otherwise produce a unified diff, and a unified diff addresses lines
/// by number — which is exactly the thing this format exists to avoid.
pub const DESCRIPTION: &str = r#"Edit files by describing changes in Garrison's patch format.

Prefer this over writing whole files: it states only what changes, and it
locates each change by its surrounding context rather than by line number, so
an edit still applies if the file has shifted since you read it.

The patch is one string, opening with "*** Begin Patch" and closing with
"*** End Patch". Between them come one or more file operations:

  *** Add File: path/to/new.rs
  +every line of the new file
  +prefixed with a plus

  *** Delete File: path/to/old.rs

  *** Update File: path/to/existing.rs
  *** Move to: path/to/renamed.rs        (optional; omit unless renaming)
  @@ fn the_enclosing_function()
   a context line, prefixed with one space
  -a line to remove
  +a line to put in its place
   another context line

Rules that matter:

- Paths are relative to the session's project root. Absolute paths and ".."
  are refused.
- Inside an update, every line starts with a space (context), "-" (remove), or
  "+" (add). The character after that marker is the first character of the
  line's real content.
- "@@" opens a chunk and may name the region it sits in — a function or class
  signature. Use it: it is how two identical-looking edits are told apart.
- Include two or three unchanged lines above and below each change. Context is
  what makes the edit land; too little context and the patch will be refused
  as ambiguous, naming every place it could have meant.
- Several chunks in one file must appear in file order, each opened by its own
  "@@".
- Add "*** End of File" after a chunk that sits at the very end of the file.
- One patch may contain many operations across many files. They are all
  resolved before any of them is written: if one fails, nothing is written.

Failures come back with the hunk number and either the closest near match or
every ambiguous candidate. Read them — they say precisely what to fix."#;

/// Decides an `apply_patch` call before a human is interrupted.
///
/// Returns `None` when this is not an `apply_patch` call, or when the patch
/// needs a human — in which case the caller falls through to the ACP
/// round-trip. Returns `Some` when the answer is knowable without asking:
/// approve a patch that only creates new files inside the root, deny one that
/// is unparseable or that reaches outside it.
///
/// Pure but for reading the tree's shape.
#[must_use]
pub fn preflight(invocation: &ToolInvocation, root: &Path) -> Option<ApprovalDecision> {
    if invocation.tool_name != TOOL_NAME {
        return None;
    }

    let text = invocation.arguments.get("patch")?.as_str()?;

    let patch = match parse(text) {
        Ok(patch) => patch,
        // Refusing here rather than asking spares the operator a dialog about
        // a patch that could not have been applied whatever they answered.
        Err(error) => return Some(ApprovalDecision::deny(error.to_string())),
    };

    match assess(&patch, root) {
        SafetyCheck::AutoApprove => Some(ApprovalDecision::Approve),
        SafetyCheck::Reject { reason } => Some(ApprovalDecision::deny(reason)),
        SafetyCheck::AskUser => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acton_ai::types::{CorrelationId, TurnId};
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    fn invocation(tool_name: &str, arguments: serde_json::Value) -> ToolInvocation {
        ToolInvocation {
            tool_name: tool_name.to_string(),
            arguments,
            correlation_id: CorrelationId::new(),
            turn_id: TurnId::new(),
        }
    }

    fn root(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("garrison-preflight-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("the test root must be creatable");
        path.canonicalize().expect("the test root must resolve")
    }

    #[test]
    fn another_tool_is_none_of_this_modules_business() {
        assert_eq!(
            preflight(
                &invocation("bash", json!({"command": "ls"})),
                Path::new("/")
            ),
            None
        );
    }

    #[test]
    fn a_call_with_no_patch_argument_falls_through_to_the_operator() {
        assert_eq!(
            preflight(&invocation(TOOL_NAME, json!({})), Path::new("/")),
            None
        );
    }

    #[test]
    fn a_patch_that_only_creates_files_needs_no_dialog() {
        let root = root("creates");

        let decision = preflight(
            &invocation(
                TOOL_NAME,
                json!({"patch": "*** Begin Patch\n*** Add File: new.txt\n+hi\n*** End Patch\n"}),
            ),
            &root,
        );

        assert_eq!(decision, Some(ApprovalDecision::Approve));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_patch_that_escapes_the_root_is_denied_without_a_dialog() {
        let root = root("escapes");

        let decision = preflight(
            &invocation(
                TOOL_NAME,
                json!({
                    "patch": "*** Begin Patch\n*** Add File: ../out.txt\n+hi\n*** End Patch\n"
                }),
            ),
            &root,
        );

        assert!(
            matches!(decision, Some(ApprovalDecision::Deny { .. })),
            "{decision:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unparseable_patch_is_denied_with_its_parse_error() {
        let root = root("garbage");

        let Some(ApprovalDecision::Deny { reason }) = preflight(
            &invocation(TOOL_NAME, json!({"patch": "just some prose"})),
            &root,
        ) else {
            panic!("an unparseable patch must be denied");
        };

        assert!(reason.contains("invalid patch at line 1"), "{reason}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_destructive_patch_goes_to_the_operator() {
        let root = root("destroys");
        fs::write(root.join("there.txt"), "old\n").expect("the fixture must be writable");

        let decision = preflight(
            &invocation(
                TOOL_NAME,
                json!({
                    "patch": "*** Begin Patch\n*** Delete File: there.txt\n*** End Patch\n"
                }),
            ),
            &root,
        );

        assert_eq!(decision, None, "a delete must reach a human");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_description_teaches_every_operation() {
        for marker in [
            "*** Begin Patch",
            "*** Add File:",
            "*** Delete File:",
            "*** Update File:",
            "*** Move to:",
            "*** End of File",
            "@@",
        ] {
            assert!(
                DESCRIPTION.contains(marker),
                "the model is never told about {marker}",
            );
        }
    }
}
