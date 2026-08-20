//! The one filesystem boundary a session is held to.
//!
//! An ACP client names the directory it wants a session rooted at. Taking that
//! at its word would let any client pick any directory on the host and then
//! read and write inside it, which makes the administrator's configured root a
//! suggestion rather than a boundary. So every requested root passes through
//! here first, and what comes out is a canonical path inside a directory an
//! administrator approved, or a refusal naming why.
//!
//! # Canonical, always
//!
//! Resolution is [`Path::canonicalize`], which requires the directory to exist
//! and resolves every symlink and `..` on the way. That is deliberate: a
//! textual check on `..` can be defeated by a symlink, and a symlink check can
//! be defeated by `..`. Comparing fully resolved paths defeats both, and it is
//! also what makes two spellings of the same directory one root rather than
//! two.
//!
//! Approved roots are canonicalized too, and at the same moment, so the
//! comparison is between two resolved paths and never between a resolved one
//! and a textual one.

use std::path::{Path, PathBuf};

/// Why a requested root was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The path does not exist, or the agent cannot resolve it.
    ///
    /// A session rooted at a directory that is not there has no boundary to
    /// enforce, so this is a refusal rather than something to create.
    Unresolvable {
        /// What was asked for.
        requested: PathBuf,
        /// What the filesystem said.
        reason: String,
    },
    /// The path resolves outside every approved root.
    Outside {
        /// The resolved path, which is the one worth reporting: a client that
        /// reached here via a symlink should see where it actually landed.
        resolved: PathBuf,
        /// The roots it was measured against.
        approved: Vec<PathBuf>,
    },
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unresolvable { requested, reason } => {
                write!(f, "cannot resolve '{}': {reason}", requested.display())
            }
            Self::Outside { resolved, approved } => {
                let roots: Vec<String> = approved.iter().map(|r| r.display().to_string()).collect();
                write!(
                    f,
                    "'{}' is outside the approved roots [{}]",
                    resolved.display(),
                    roots.join(", ")
                )
            }
        }
    }
}

/// Canonicalizes the roots an administrator approved, dropping any that do not
/// resolve.
///
/// Done once at launch: a root that cannot be resolved then would be compared
/// textually forever after, which is the failure this module exists to avoid.
/// A dropped root is logged rather than fatal, because a deployment listing
/// several workspaces should not fail to start over one that is not mounted.
#[must_use]
pub fn approve(roots: &[PathBuf]) -> Vec<PathBuf> {
    roots
        .iter()
        .filter_map(|root| match root.canonicalize() {
            Ok(canonical) => Some(canonical),
            Err(error) => {
                tracing::warn!(
                    root = %root.display(),
                    %error,
                    "configured root does not resolve; sessions cannot be opened there",
                );
                None
            }
        })
        .collect()
}

/// Resolves a client's requested root against the approved ones.
///
/// A relative request is taken as a client bug rather than an attack and is
/// resolved against `fallback` — it cannot expand authority, because the
/// result still has to clear the boundary check like everything else.
///
/// # Errors
///
/// [`Rejection::Unresolvable`] when the directory does not exist or cannot be
/// resolved, and [`Rejection::Outside`] when it resolves outside every
/// approved root.
pub fn resolve(
    requested: &Path,
    fallback: &Path,
    approved: &[PathBuf],
) -> Result<PathBuf, Rejection> {
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        fallback.join(requested)
    };

    let resolved = candidate
        .canonicalize()
        .map_err(|error| Rejection::Unresolvable {
            requested: candidate.clone(),
            reason: error.to_string(),
        })?;

    if approved.iter().any(|root| resolved.starts_with(root)) {
        Ok(resolved)
    } else {
        Err(Rejection::Outside {
            resolved,
            approved: approved.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A workspace tree: `root/`, `root/nested/`, and a `sibling/` beside it.
    struct Tree {
        _dir: tempfile::TempDir,
        root: PathBuf,
        nested: PathBuf,
        sibling: PathBuf,
    }

    fn tree() -> Tree {
        let dir = tempfile::tempdir().expect("a temp dir");
        let base = dir.path().canonicalize().expect("the temp dir resolves");
        let root = base.join("root");
        let nested = root.join("nested");
        let sibling = base.join("sibling");
        std::fs::create_dir_all(&nested).expect("creates the tree");
        std::fs::create_dir_all(&sibling).expect("creates the sibling");
        Tree {
            _dir: dir,
            root,
            nested,
            sibling,
        }
    }

    #[test]
    fn the_approved_root_itself_is_accepted() {
        let tree = tree();
        let approved = approve(std::slice::from_ref(&tree.root));

        assert_eq!(
            resolve(&tree.root, &tree.root, &approved).expect("the root is inside itself"),
            tree.root
        );
    }

    #[test]
    fn a_directory_under_an_approved_root_is_accepted() {
        let tree = tree();
        let approved = approve(std::slice::from_ref(&tree.root));

        assert_eq!(
            resolve(&tree.nested, &tree.root, &approved).expect("nested is inside"),
            tree.nested
        );
    }

    #[test]
    fn a_sibling_of_an_approved_root_is_refused() {
        // The one that matters: `/srv/work` and `/srv/workspace-of-someone-else`
        // share a prefix as strings and share nothing as directories.
        let tree = tree();
        let approved = approve(std::slice::from_ref(&tree.root));

        let rejection =
            resolve(&tree.sibling, &tree.root, &approved).expect_err("a sibling is outside");

        assert!(matches!(rejection, Rejection::Outside { .. }));
    }

    #[test]
    fn a_string_prefix_of_an_approved_root_is_not_a_descendant() {
        let tree = tree();
        let decoy = tree.root.with_file_name("rootless");
        std::fs::create_dir_all(&decoy).expect("creates the decoy");
        let approved = approve(std::slice::from_ref(&tree.root));

        let rejection = resolve(&decoy, &tree.root, &approved)
            .expect_err("sharing a name prefix is not being inside");

        assert!(matches!(rejection, Rejection::Outside { .. }));
    }

    #[test]
    fn traversal_out_of_an_approved_root_is_refused() {
        let tree = tree();
        let approved = approve(std::slice::from_ref(&tree.root));
        let escape = tree.nested.join("..").join("..").join("sibling");

        let rejection = resolve(&escape, &tree.root, &approved)
            .expect_err("`..` must be resolved, not merely tolerated");

        assert!(matches!(rejection, Rejection::Outside { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_pointing_out_of_an_approved_root_is_refused() {
        let tree = tree();
        let link = tree.root.join("escape-hatch");
        std::os::unix::fs::symlink(&tree.sibling, &link).expect("creates the symlink");
        let approved = approve(std::slice::from_ref(&tree.root));

        let rejection = resolve(&link, &tree.root, &approved)
            .expect_err("a link inside the root is not a directory inside the root");

        match rejection {
            Rejection::Outside { resolved, .. } => assert_eq!(
                resolved, tree.sibling,
                "the refusal should name where the link actually goes"
            ),
            other => panic!("expected an Outside rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_root_that_does_not_exist_is_refused_rather_than_created() {
        let tree = tree();
        let approved = approve(std::slice::from_ref(&tree.root));
        let missing = tree.root.join("not-here");

        let rejection = resolve(&missing, &tree.root, &approved)
            .expect_err("a session cannot be rooted at nothing");

        assert!(matches!(rejection, Rejection::Unresolvable { .. }));
    }

    #[test]
    fn the_system_temp_directory_is_not_reachable_by_default() {
        let tree = tree();
        let approved = approve(std::slice::from_ref(&tree.root));

        let rejection = resolve(&std::env::temp_dir(), &tree.root, &approved)
            .expect_err("/tmp is not implied by anything");

        assert!(matches!(rejection, Rejection::Outside { .. }));
    }

    #[test]
    fn a_relative_request_resolves_under_the_fallback_and_is_still_checked() {
        let tree = tree();
        let approved = approve(std::slice::from_ref(&tree.root));

        assert_eq!(
            resolve(Path::new("nested"), &tree.root, &approved).expect("relative lands inside"),
            tree.nested
        );

        let rejection = resolve(Path::new("../sibling"), &tree.root, &approved)
            .expect_err("a relative path cannot escape either");
        assert!(matches!(rejection, Rejection::Outside { .. }));
    }

    #[test]
    fn several_approved_roots_are_each_their_own_boundary() {
        let tree = tree();
        let approved = approve(&[tree.root.clone(), tree.sibling.clone()]);

        assert!(resolve(&tree.nested, &tree.root, &approved).is_ok());
        assert!(resolve(&tree.sibling, &tree.root, &approved).is_ok());
        assert!(
            resolve(tree.root.parent().expect("a parent"), &tree.root, &approved).is_err(),
            "approving two roots does not approve what contains them"
        );
    }

    #[test]
    fn an_unresolvable_configured_root_is_dropped_rather_than_trusted_textually() {
        let tree = tree();
        let approved = approve(&[tree.root.clone(), tree.root.join("gone")]);

        assert_eq!(approved, vec![tree.root]);
    }
}
