//! The patch format's types and markers.
//!
//! # Grammar
//!
//! ```text
//! patch    = begin LF hunk* end LF?
//! begin    = "*** Begin Patch"
//! end      = "*** End Patch"
//!
//! hunk     = add | delete | update
//! add      = "*** Add File: " path LF added*
//! added    = "+" text LF
//! delete   = "*** Delete File: " path LF
//! update   = "*** Update File: " path LF move? chunk+
//! move     = "*** Move to: " path LF
//!
//! chunk    = anchor? change+ eof?
//! anchor   = "@@" (" " text)? LF
//! change   = (" " | "-" | "+" | "") text LF
//! eof      = "*** End of File" LF
//! ```
//!
//! A leading space marks a context line, `-` a line to remove, `+` a line to
//! add. A wholly empty line is a blank context line: models emit one rather
//! than a line containing a single space, and refusing it would fail on
//! nothing but invisible characters.
//!
//! # Why this format and not a unified diff
//!
//! A unified diff addresses lines by number, and a model's line numbers are
//! stale the moment anything else edits the file. This format addresses them
//! by *surrounding content*, so a hunk still lands after the file has drifted.
//! The `@@` anchor is not decoration: it names the enclosing function or class
//! and narrows where the body may match.
//!
//! # Newlines
//!
//! Every line here is stored without its terminator. Rendering re-joins with
//! `\n` and ensures a trailing newline, which is why a patch cannot express
//! "remove the final newline". That is a deliberate limitation: it makes the
//! format total, and a file that needs no trailing newline is better served by
//! writing it whole.

use std::path::{Path, PathBuf};

/// The line that opens a patch.
pub const BEGIN_PATCH: &str = "*** Begin Patch";
/// The line that closes a patch.
pub const END_PATCH: &str = "*** End Patch";
/// Introduces a file to create.
pub const ADD_FILE: &str = "*** Add File: ";
/// Introduces a file to remove.
pub const DELETE_FILE: &str = "*** Delete File: ";
/// Introduces a file to change in place.
pub const UPDATE_FILE: &str = "*** Update File: ";
/// Renames the file an update addresses.
pub const MOVE_TO: &str = "*** Move to: ";
/// Says the preceding chunk sits at the end of the file.
pub const END_OF_FILE: &str = "*** End of File";
/// Opens a chunk, optionally naming the region it sits in.
pub const ANCHOR: &str = "@@";

/// A parsed patch: an ordered list of file operations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Patch {
    /// The operations, in the order the model wrote them.
    pub hunks: Vec<Hunk>,
}

impl Patch {
    /// Whether the patch would change nothing.
    ///
    /// An empty patch is not applied but refused: a model that emitted one
    /// meant to do something, and reporting success would teach it that the
    /// nothing it did was the something it wanted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hunks.is_empty()
    }

    /// Every path this patch would read or write, in hunk order.
    ///
    /// A rename contributes both ends, because both are writes: the old name
    /// disappears and the new one appears, and a safety assessment that
    /// checked only one of them would let a patch move a file out of the
    /// project or into it.
    #[must_use]
    pub fn paths(&self) -> Vec<&Path> {
        let mut paths = Vec::new();
        for hunk in &self.hunks {
            match hunk {
                Hunk::Add { path, .. } | Hunk::Delete { path } => paths.push(path.as_path()),
                Hunk::Update { path, move_to, .. } => {
                    paths.push(path.as_path());
                    if let Some(destination) = move_to {
                        paths.push(destination.as_path());
                    }
                }
            }
        }
        paths
    }
}

/// One file operation.
///
/// `#[non_exhaustive]` because a coding agent grows operations — a chmod, a
/// symlink — and a downstream `match` should not break when one arrives.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Hunk {
    /// Create a file, or overwrite one that exists.
    Add {
        /// Where it goes, relative to the session root.
        path: PathBuf,
        /// Its whole contents, newline-terminated.
        contents: String,
    },
    /// Remove a file.
    Delete {
        /// The file to remove, relative to the session root.
        path: PathBuf,
    },
    /// Change a file in place, and optionally rename it.
    Update {
        /// The file to read, relative to the session root.
        path: PathBuf,
        /// Where to write the result, when the patch renames it.
        move_to: Option<PathBuf>,
        /// The edits, in file order.
        chunks: Vec<Chunk>,
    },
}

impl Hunk {
    /// The path this hunk writes to, which for a rename is the destination.
    #[must_use]
    pub fn target(&self) -> &Path {
        match self {
            Self::Add { path, .. } | Self::Delete { path } => path,
            Self::Update {
                path,
                move_to: None,
                ..
            } => path,
            Self::Update {
                move_to: Some(destination),
                ..
            } => destination,
        }
    }

    /// The path this hunk reads from.
    #[must_use]
    pub fn source(&self) -> &Path {
        match self {
            Self::Add { path, .. } | Self::Delete { path } | Self::Update { path, .. } => path,
        }
    }
}

/// One contiguous edit within a file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Chunk {
    /// The text after `@@`, naming the region this chunk sits in.
    ///
    /// `None` when the chunk opened with a bare `@@`, or with no anchor line
    /// at all.
    pub anchor: Option<String>,
    /// The lines as they are expected to be found, context included.
    pub old_lines: Vec<String>,
    /// The lines to put in their place, context included.
    pub new_lines: Vec<String>,
    /// Whether `old_lines` must sit at the end of the file.
    pub at_end_of_file: bool,
}

impl Chunk {
    /// Records a context line, which appears unchanged on both sides.
    pub fn push_context(&mut self, line: String) {
        self.old_lines.push(line.clone());
        self.new_lines.push(line);
    }

    /// Records a line to remove.
    pub fn push_removal(&mut self, line: String) {
        self.old_lines.push(line);
    }

    /// Records a line to add.
    pub fn push_addition(&mut self, line: String) {
        self.new_lines.push(line);
    }

    /// Whether the chunk says nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.old_lines.is_empty() && self.new_lines.is_empty()
    }

    /// Whether the chunk only inserts, with nothing to locate but its anchor.
    #[must_use]
    pub fn is_pure_insertion(&self) -> bool {
        self.old_lines.is_empty() && !self.new_lines.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_patch_says_so() {
        assert!(Patch::default().is_empty());
    }

    #[test]
    fn a_rename_is_two_paths_because_it_is_two_writes() {
        let patch = Patch {
            hunks: vec![Hunk::Update {
                path: PathBuf::from("old.rs"),
                move_to: Some(PathBuf::from("new.rs")),
                chunks: Vec::new(),
            }],
        };

        assert_eq!(
            patch.paths(),
            vec![Path::new("old.rs"), Path::new("new.rs")]
        );
    }

    #[test]
    fn a_rename_reads_the_old_name_and_writes_the_new_one() {
        let hunk = Hunk::Update {
            path: PathBuf::from("old.rs"),
            move_to: Some(PathBuf::from("new.rs")),
            chunks: Vec::new(),
        };

        assert_eq!(hunk.source(), Path::new("old.rs"));
        assert_eq!(hunk.target(), Path::new("new.rs"));
    }

    #[test]
    fn a_context_line_appears_on_both_sides() {
        let mut chunk = Chunk::default();
        chunk.push_context("keep me".to_string());

        assert_eq!(chunk.old_lines, vec!["keep me".to_string()]);
        assert_eq!(chunk.new_lines, vec!["keep me".to_string()]);
    }

    #[test]
    fn a_chunk_with_only_additions_has_nothing_to_locate() {
        let mut chunk = Chunk::default();
        chunk.push_addition("new line".to_string());

        assert!(chunk.is_pure_insertion());
        assert!(!chunk.is_empty());
    }
}
