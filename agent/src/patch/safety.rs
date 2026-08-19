//! What a patch is allowed to do, decided before any bytes move.
//!
//! # Three answers
//!
//! [`SafetyCheck::Reject`] is Garrison's own refusal and is not negotiable: no
//! operator clicking "allow" can authorize a write outside the session's
//! writable roots, because the roots are the boundary the deployment agreed
//! to, not a suggestion to the model.
//!
//! [`SafetyCheck::AskUser`] means the patch is inside the boundary but
//! destroys something — it overwrites, deletes, or renames over existing
//! content. That is exactly the question the Phase 1 approval round-trip
//! exists to put to a human, so the answer routes there.
//!
//! [`SafetyCheck::AutoApprove`] means the patch only creates files that do not
//! yet exist, inside the roots. Nothing that exists is lost, so asking would
//! train the operator to click through dialogs, which is how a governance gate
//! stops working.
//!
//! # Where the boundary comes from
//!
//! acton-ai's [`PathValidator`] does the enforcement: it canonicalizes (so a
//! symlink out of the tree is caught), refuses `..` before canonicalizing at
//! all, and blocks `.git` and `.env` by pattern. Garrison narrows its allowed
//! roots to the session's project root, replacing the validator's defaults of
//! "the working directory and the system temp directory" — a server serving
//! many sessions must not let one session's patch land in another's tree, and
//! a temp directory is nobody's project.
//!
//! # Assessed twice, deliberately
//!
//! The hook consults this before asking a human, so an impossible patch is
//! refused without an interruption and a harmless one runs without one. The
//! tool consults it again immediately before writing, because the hook is
//! advisory and could be reconfigured, and the thing that writes must be the
//! thing that checked.

use super::format::{Hunk, Patch};
use acton_ai::tools::security::PathValidator;
use std::path::{Path, PathBuf};

/// What may be done with a patch.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SafetyCheck {
    /// Apply it without asking anybody.
    AutoApprove,
    /// Put it to the operator through the approval round-trip.
    AskUser,
    /// Refuse it, whatever anybody says.
    Reject {
        /// Why, in words the model can act on.
        reason: String,
    },
}

impl SafetyCheck {
    /// Refuses with a reason.
    #[must_use]
    pub fn reject(reason: impl Into<String>) -> Self {
        Self::Reject {
            reason: reason.into(),
        }
    }

    /// Whether this is a refusal.
    #[must_use]
    pub const fn is_rejection(&self) -> bool {
        matches!(self, Self::Reject { .. })
    }
}

/// Builds the validator a session's patches are checked against.
///
/// The session's project root is the only writable root. Everything the
/// validator refuses by default — `..`, `.git`, `.env` — stays refused.
#[must_use]
pub fn validator(root: &Path) -> PathValidator {
    PathValidator::new()
        .clear_allowed_roots()
        .with_allowed_root(root.to_path_buf())
}

/// Assesses a whole patch against a session's root.
///
/// Pure but for reading the filesystem's shape — it asks whether paths exist
/// and where they resolve to, and reads no contents and writes nothing.
#[must_use]
pub fn assess(patch: &Patch, root: &Path) -> SafetyCheck {
    if patch.is_empty() {
        return SafetyCheck::reject(
            "the patch contains no hunks; a patch that changes nothing is a mistake",
        );
    }

    let validator = validator(root);
    let mut destructive = false;

    for hunk in &patch.hunks {
        match check_hunk(hunk, root, &validator) {
            Ok(destroys) => destructive |= destroys,
            Err(reason) => return SafetyCheck::Reject { reason },
        }
    }

    if destructive {
        SafetyCheck::AskUser
    } else {
        SafetyCheck::AutoApprove
    }
}

/// Checks one hunk, reporting whether it destroys anything.
fn check_hunk(hunk: &Hunk, root: &Path, validator: &PathValidator) -> Result<bool, String> {
    match hunk {
        Hunk::Add { path, .. } => {
            let absolute = writable(path, root, validator)?;
            Ok(absolute.exists())
        }
        Hunk::Delete { path } => {
            readable(path, root, validator)?;
            writable(path, root, validator)?;
            Ok(true)
        }
        Hunk::Update {
            path,
            move_to,
            chunks,
        } => {
            if chunks.is_empty() {
                return Err(format!("the update of '{}' has no chunks", path.display()));
            }
            readable(path, root, validator)?;
            writable(path, root, validator)?;
            if let Some(destination) = move_to {
                writable(destination, root, validator)?;
            }
            Ok(true)
        }
    }
}

/// Checks that a path may be written, returning where it resolves to.
fn writable(path: &Path, root: &Path, validator: &PathValidator) -> Result<PathBuf, String> {
    let absolute = resolve(path, root)?;
    validator
        .validate_parent(&absolute)
        .map_err(|error| format!("'{}' may not be written: {error}", path.display()))
}

/// Checks that a path may be read, and that it is a file that exists.
fn readable(path: &Path, root: &Path, validator: &PathValidator) -> Result<PathBuf, String> {
    let absolute = resolve(path, root)?;
    validator
        .validate_file(&absolute)
        .map_err(|error| format!("'{}' may not be read: {error}", path.display()))
}

/// Joins a patch path onto the session root, refusing absolute paths.
///
/// `Path::join` silently *replaces* the root when given an absolute path, so
/// `root.join("/etc/passwd")` is `/etc/passwd`. Refusing here rather than
/// letting the validator catch it later gives the model a message about what
/// it did wrong instead of one about canonicalization.
fn resolve(path: &Path, root: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Err(format!(
            "'{}' is an absolute path; patch paths are relative to the session root",
            path.display()
        ));
    }
    Ok(root.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::parse::parse;
    use std::fs;

    /// A throwaway project root, removed when the test ends.
    struct Root {
        path: PathBuf,
    }

    impl Root {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("garrison-safety-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("the test root must be creatable");
            Self {
                path: path.canonicalize().expect("the test root must resolve"),
            }
        }

        fn write(&self, name: &str, contents: &str) {
            let path = self.path.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("the parent must be creatable");
            }
            fs::write(path, contents).expect("the fixture must be writable");
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn patch(text: &str) -> Patch {
        parse(text).expect("this patch must parse")
    }

    #[test]
    fn an_empty_patch_is_rejected_rather_than_succeeding_at_nothing() {
        let root = Root::new("empty");

        let check = assess(&patch("*** Begin Patch\n*** End Patch\n"), &root.path);

        assert!(check.is_rejection());
    }

    #[test]
    fn creating_a_new_file_needs_nobody() {
        let root = Root::new("create");

        let check = assess(
            &patch("*** Begin Patch\n*** Add File: new.txt\n+hi\n*** End Patch\n"),
            &root.path,
        );

        assert_eq!(check, SafetyCheck::AutoApprove);
    }

    #[test]
    fn creating_a_file_in_a_new_directory_needs_nobody() {
        let root = Root::new("nested");

        let check = assess(
            &patch("*** Begin Patch\n*** Add File: a/b/c.txt\n+hi\n*** End Patch\n"),
            &root.path,
        );

        assert_eq!(check, SafetyCheck::AutoApprove);
    }

    #[test]
    fn overwriting_an_existing_file_asks() {
        let root = Root::new("overwrite");
        root.write("there.txt", "old\n");

        let check = assess(
            &patch("*** Begin Patch\n*** Add File: there.txt\n+new\n*** End Patch\n"),
            &root.path,
        );

        assert_eq!(check, SafetyCheck::AskUser);
    }

    #[test]
    fn deleting_asks() {
        let root = Root::new("delete");
        root.write("gone.txt", "bye\n");

        let check = assess(
            &patch("*** Begin Patch\n*** Delete File: gone.txt\n*** End Patch\n"),
            &root.path,
        );

        assert_eq!(check, SafetyCheck::AskUser);
    }

    #[test]
    fn updating_asks() {
        let root = Root::new("update");
        root.write("a.txt", "one\n");

        let check = assess(
            &patch("*** Begin Patch\n*** Update File: a.txt\n@@\n-one\n+two\n*** End Patch\n"),
            &root.path,
        );

        assert_eq!(check, SafetyCheck::AskUser);
    }

    #[test]
    fn deleting_a_file_that_is_not_there_is_rejected_before_anybody_is_asked() {
        let root = Root::new("absent");

        let check = assess(
            &patch("*** Begin Patch\n*** Delete File: never.txt\n*** End Patch\n"),
            &root.path,
        );

        assert!(check.is_rejection(), "{check:?}");
    }

    #[test]
    fn a_write_outside_the_root_is_rejected() {
        let root = Root::new("escape");

        let check = assess(
            &patch("*** Begin Patch\n*** Add File: ../escaped.txt\n+hi\n*** End Patch\n"),
            &root.path,
        );

        let SafetyCheck::Reject { reason } = check else {
            panic!("a traversal must be refused");
        };
        assert!(reason.contains("escaped.txt"), "{reason}");
    }

    #[test]
    fn an_absolute_path_is_rejected_with_a_message_about_paths() {
        let root = Root::new("absolute");

        let check = assess(
            &patch("*** Begin Patch\n*** Add File: /etc/nope.txt\n+hi\n*** End Patch\n"),
            &root.path,
        );

        let SafetyCheck::Reject { reason } = check else {
            panic!("an absolute path must be refused");
        };
        assert!(reason.contains("relative to the session root"), "{reason}");
    }

    #[test]
    fn writing_inside_dot_git_is_rejected() {
        let root = Root::new("git");

        let check = assess(
            &patch("*** Begin Patch\n*** Add File: .git/config\n+hi\n*** End Patch\n"),
            &root.path,
        );

        assert!(check.is_rejection(), "{check:?}");
    }

    #[test]
    fn one_bad_hunk_rejects_the_whole_patch() {
        let root = Root::new("mixed");

        let check = assess(
            &patch(
                "*** Begin Patch\n\
                 *** Add File: fine.txt\n\
                 +hi\n\
                 *** Add File: /etc/nope.txt\n\
                 +hi\n\
                 *** End Patch\n",
            ),
            &root.path,
        );

        assert!(check.is_rejection(), "{check:?}");
    }

    #[test]
    fn renaming_over_an_existing_file_asks() {
        let root = Root::new("rename");
        root.write("old.txt", "one\n");
        root.write("new.txt", "other\n");

        let check = assess(
            &patch(
                "*** Begin Patch\n\
                 *** Update File: old.txt\n\
                 *** Move to: new.txt\n\
                 -one\n\
                 +two\n\
                 *** End Patch\n",
            ),
            &root.path,
        );

        assert_eq!(check, SafetyCheck::AskUser);
    }
}
