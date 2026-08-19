//! `apply_patch` as a tool the model can call.
//!
//! # Why a tool and not a builtin
//!
//! acton-ai's builtin set is closed — `with_builtin_tools` takes names from a
//! hardcoded list — and there is no runtime-wide registration API for a
//! downstream crate. What there is, and all Garrison needs, is
//! [`PromptBuilder::with_tool`](acton_ai::prompt::PromptBuilder::with_tool):
//! Garrison already builds every turn's prompt itself, so [`install`] adds the
//! tool to each one. That is exactly how acton-ai injects its own MCP and
//! skill tools, and it means the policy gate, the approval hook, and the audit
//! chain all see `apply_patch` as they see everything else.
//!
//! # The description is the specification
//!
//! A model that has not been taught this format will write a unified diff. The
//! description below is therefore long on purpose: it is the only place the
//! grammar is ever explained to the thing expected to produce it.

use super::{apply, safety, DESCRIPTION};
use crate::error::GarrisonError;
use acton_ai::prompt::PromptBuilder;
use acton_ai::tools::{ToolDefinition, ToolError};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// The name the model calls.
pub const TOOL_NAME: &str = "apply_patch";

/// The tool as the model is shown it.
#[must_use]
pub fn definition() -> ToolDefinition {
    ToolDefinition {
        name: TOOL_NAME.to_string(),
        description: DESCRIPTION.to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "patch": {
                    "type": "string",
                    "description":
                        "The complete patch text, beginning with '*** Begin Patch' and ending \
                         with '*** End Patch'.",
                }
            },
            "required": ["patch"],
            "additionalProperties": false,
        }),
    }
}

/// Adds `apply_patch` to a prompt, rooted at `root`.
///
/// Every path in every patch this tool receives is resolved against `root` and
/// refused if it escapes it, so a session cannot edit another session's tree
/// however the model phrases the request.
#[must_use]
pub fn install(builder: PromptBuilder, root: PathBuf) -> PromptBuilder {
    builder.with_tool(definition(), move |arguments| {
        let root = root.clone();
        async move { run(&arguments, &root) }
    })
}

/// Parses, assesses, plans, and writes — in that order, stopping at the first
/// thing that says no.
///
/// # Errors
///
/// A [`ToolError`] the model is shown: the parse diagnostic with its line
/// number, the safety refusal with its reason, or the apply diagnostic naming
/// the hunk and its closest match.
pub fn run(arguments: &Value, root: &Path) -> Result<Value, ToolError> {
    let text = arguments
        .get("patch")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ToolError::validation_failed(
                TOOL_NAME,
                "the 'patch' argument is required and must be a string",
            )
        })?;

    let patch = super::parse(text).map_err(failed)?;

    // Assessed here as well as in the approval hook, because the thing that
    // writes must be the thing that checked. A refusal is enforcement; an
    // `AskUser` that reaches this point means the gate already asked and the
    // operator already said yes.
    if let safety::SafetyCheck::Reject { reason } = safety::assess(&patch, root) {
        return Err(ToolError::execution_failed(TOOL_NAME, reason));
    }

    let planned = apply::plan(&patch, root).map_err(failed)?;
    apply::commit(&planned.changes).map_err(failed)?;

    Ok(json!({
        "applied": true,
        "files": planned
            .changes
            .iter()
            .map(|change| relative(change.path(), root))
            .collect::<Vec<String>>(),
        "match_fidelity": planned.fidelity.describe(),
    }))
}

/// Flattens a Garrison error into the model's view of a tool failure.
fn failed(error: GarrisonError) -> ToolError {
    ToolError::execution_failed(TOOL_NAME, error.to_string())
}

/// Renders a path the way the model wrote it, where it can.
fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A throwaway project root, removed when the test ends.
    struct Root {
        path: PathBuf,
    }

    impl Root {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("garrison-tool-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("the test root must be creatable");
            Self {
                path: path.canonicalize().expect("the test root must resolve"),
            }
        }

        fn write(&self, name: &str, contents: &str) {
            fs::write(self.path.join(name), contents).expect("the fixture must be writable");
        }

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.path.join(name)).expect("the file must be readable")
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn call(root: &Root, patch: &str) -> Result<Value, ToolError> {
        run(&json!({ "patch": patch }), &root.path)
    }

    #[test]
    fn the_schema_demands_a_patch_string() {
        let definition = definition();

        assert_eq!(definition.name, TOOL_NAME);
        assert_eq!(definition.input_schema["required"], json!(["patch"]));
        assert!(definition.description.contains("*** Begin Patch"));
    }

    #[test]
    fn a_missing_patch_argument_is_a_validation_failure() {
        let root = Root::new("noargs");

        let error = run(&json!({}), &root.path).expect_err("this must fail");

        assert!(error.to_string().contains("required"), "{error}");
    }

    #[test]
    fn an_added_file_lands_byte_for_byte() {
        let root = Root::new("add");

        let result = call(
            &root,
            "*** Begin Patch\n*** Add File: hello.txt\n+one\n+two\n*** End Patch\n",
        )
        .expect("this patch must apply");

        assert_eq!(root.read("hello.txt"), "one\ntwo\n");
        assert_eq!(result["applied"], json!(true));
        assert_eq!(result["files"], json!(["hello.txt"]));
    }

    #[test]
    fn an_update_lands_byte_for_byte() {
        let root = Root::new("update");
        root.write("a.txt", "one\ntwo\nthree\n");

        call(
            &root,
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@\n\
             \x20one\n\
             -two\n\
             +TWO\n\
             *** End Patch\n",
        )
        .expect("this patch must apply");

        assert_eq!(root.read("a.txt"), "one\nTWO\nthree\n");
    }

    #[test]
    fn a_rename_moves_the_file_and_leaves_nothing_behind() {
        let root = Root::new("rename");
        root.write("old.txt", "content\n");

        call(
            &root,
            "*** Begin Patch\n\
             *** Update File: old.txt\n\
             *** Move to: new.txt\n\
             -content\n\
             +moved\n\
             *** End Patch\n",
        )
        .expect("this patch must apply");

        assert_eq!(root.read("new.txt"), "moved\n");
        assert!(!root.path.join("old.txt").exists());
    }

    #[test]
    fn a_write_outside_the_root_is_refused_and_nothing_is_written() {
        let root = Root::new("escape");

        let error = call(
            &root,
            "*** Begin Patch\n*** Add File: ../escaped.txt\n+hi\n*** End Patch\n",
        )
        .expect_err("this patch must be refused");

        assert!(error.to_string().contains("escaped.txt"), "{error}");
        assert!(!root.path.join("../escaped.txt").exists());
    }

    #[test]
    fn a_failing_hunk_leaves_the_tree_untouched() {
        let root = Root::new("atomic");
        root.write("first.txt", "one\n");
        root.write("second.txt", "two\n");

        let error = call(
            &root,
            "*** Begin Patch\n\
             *** Update File: first.txt\n\
             @@\n\
             -one\n\
             +ONE\n\
             *** Update File: second.txt\n\
             @@\n\
             -nothing like this\n\
             +whatever\n\
             *** End Patch\n",
        )
        .expect_err("the second hunk must fail");

        assert!(error.to_string().contains("hunk 1"), "{error}");
        assert_eq!(
            root.read("first.txt"),
            "one\n",
            "the first hunk must not have been written",
        );
    }

    #[test]
    fn a_loose_match_is_reported_in_the_result() {
        let root = Root::new("fidelity");
        root.write("a.rs", "fn main() {\n        let x = 1;\n}\n");

        let result = call(
            &root,
            "*** Begin Patch\n\
             *** Update File: a.rs\n\
             @@ fn main() {\n\
             -    let x = 1;\n\
             +    let x = 2;\n\
             *** End Patch\n",
        )
        .expect("this patch must apply");

        assert_eq!(
            result["match_fidelity"],
            json!("ignoring indentation"),
            "a drifted match must be reported, not silently accepted",
        );
    }

    #[test]
    fn an_unparseable_patch_reports_its_line() {
        let root = Root::new("parse");

        let error = call(&root, "not a patch at all\n").expect_err("this must fail");

        assert!(error.to_string().contains("line 1"), "{error}");
    }
}
