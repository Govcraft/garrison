//! Turning a parsed patch into new file contents, and then into bytes on disk.
//!
//! # Plan, then commit
//!
//! Every hunk is resolved against the tree *before* anything is written. A
//! patch that fails on its third hunk leaves the working tree exactly as it
//! was, rather than half-edited. Codex applies eagerly and documents the
//! partial-success case as expected behaviour; for a governed agent it is not
//! acceptable, because "what did the agent change?" must have one answer and
//! not two.
//!
//! [`plan`] does all the reading and all the thinking and returns
//! [`Change`]s. [`commit`] does nothing but write them. The interesting logic
//! is in [`rewrite`], which is pure: a string and some chunks in, a string
//! out.
//!
//! # Line endings
//!
//! A file's dominant terminator is detected on the way in and restored on the
//! way out, so editing three lines of a CRLF file does not leave those three
//! lines as the only LF lines in it. A file of genuinely mixed endings is
//! normalized to whichever it has more of, which is a change the patch did not
//! ask for and is therefore called out in the summary.

use super::format::{Chunk, Hunk, Patch};
use super::seek::{locate, Fidelity, Located};
use crate::error::GarrisonError;
use std::path::{Path, PathBuf};

/// One file operation the patch resolved to.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// Write these contents, creating the file and its parents if needed.
    Write {
        /// The absolute path to write.
        path: PathBuf,
        /// The complete new contents.
        contents: String,
    },
    /// Remove this file.
    Remove {
        /// The absolute path to remove.
        path: PathBuf,
    },
}

impl Change {
    /// The path this change touches.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Write { path, .. } | Self::Remove { path } => path,
        }
    }
}

/// A patch resolved against the tree, ready to be written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Planned {
    /// The changes, in the order they must be applied.
    pub changes: Vec<Change>,
    /// The loosest tier any hunk had to be matched at.
    ///
    /// [`Fidelity::Exact`] means every hunk landed byte-for-byte. Anything
    /// else is worth a reviewer's attention, and travels into the tool result
    /// so the model reports it too.
    pub fidelity: Fidelity,
}

/// The terminator a file uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Newline {
    /// `\n`.
    Lf,
    /// `\r\n`.
    Crlf,
}

impl Newline {
    /// The bytes to join lines with.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Lf => "\n",
            Self::Crlf => "\r\n",
        }
    }
}

/// A file split into lines, remembering how to put it back together.
struct Split {
    lines: Vec<String>,
    newline: Newline,
}

impl Split {
    /// Splits text into terminator-free lines.
    fn of(text: &str) -> Self {
        let crlf = text.matches("\r\n").count();
        let lf = text.matches('\n').count() - crlf;
        let newline = if crlf > lf {
            Newline::Crlf
        } else {
            Newline::Lf
        };

        let mut lines: Vec<String> = text
            .split('\n')
            .map(|line| line.strip_suffix('\r').unwrap_or(line).to_string())
            .collect();

        // `split` yields a trailing empty element for a terminated final line.
        // Dropping it makes `lines.len()` the number of lines a human counts.
        if lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }

        Self { lines, newline }
    }

    /// Rejoins lines, always terminating the last one.
    fn join(lines: &[String], newline: Newline) -> String {
        if lines.is_empty() {
            return String::new();
        }
        let mut text = lines.join(newline.as_str());
        text.push_str(newline.as_str());
        text
    }
}

/// Applies an update hunk's chunks to a file's text.
///
/// Pure. `hunk` and `path` appear only in error messages, so a caller can
/// blame the right hunk without this function knowing anything about patches
/// as a whole.
///
/// # Errors
///
/// [`GarrisonErrorKind::PatchApply`](crate::error::GarrisonErrorKind::PatchApply)
/// when a chunk's anchor or context cannot be located unambiguously. The
/// message carries the chunk number and the diagnostic from
/// [`Located::describe`], which names either every candidate line or the
/// closest near miss.
pub fn rewrite(
    original: &str,
    chunks: &[Chunk],
    hunk: usize,
    path: &str,
) -> Result<(String, Fidelity), GarrisonError> {
    let split = Split::of(original);
    let lines = &split.lines;

    let mut replacements: Vec<(usize, usize, Vec<String>)> = Vec::new();
    let mut cursor = 0;
    let mut fidelity = Fidelity::Exact;

    for (number, chunk) in chunks.iter().enumerate() {
        let blame = |detail: String| {
            GarrisonError::patch_apply(hunk, path, format!("chunk {}: {detail}", number + 1))
        };

        if let Some(anchor) = &chunk.anchor {
            match locate(lines, std::slice::from_ref(anchor), cursor, false) {
                Located::At(found) => {
                    fidelity = fidelity.max(found.fidelity);
                    cursor = found.index + 1;
                }
                other => {
                    return Err(blame(format!("anchor {anchor:?}: {}", other.describe())));
                }
            }
        }

        if chunk.old_lines.is_empty() {
            let at = if chunk.at_end_of_file {
                lines.len()
            } else {
                cursor
            };
            replacements.push((at, 0, chunk.new_lines.clone()));
            cursor = at;
            continue;
        }

        let (pattern, replacement, found) = find_body(lines, chunk, cursor).map_err(blame)?;
        fidelity = fidelity.max(found.fidelity);
        replacements.push((found.index, pattern.len(), replacement.to_vec()));
        cursor = found.index + pattern.len();
    }

    let rewritten = splice(split.lines.clone(), &replacements);
    Ok((Split::join(&rewritten, split.newline), fidelity))
}

/// Locates a chunk's body, retrying without a trailing blank sentinel.
///
/// A chunk that reaches the end of a file often ends in an empty context line
/// standing for the final newline. The file has no such line — the terminator
/// belongs to the line before it — so a first search fails on nothing but a
/// convention.
type Body<'a> = (&'a [String], &'a [String], super::seek::Found);

fn find_body<'a>(lines: &[String], chunk: &'a Chunk, cursor: usize) -> Result<Body<'a>, String> {
    let mut pattern: &[String] = &chunk.old_lines;
    let mut replacement: &[String] = &chunk.new_lines;

    let mut located = locate(lines, pattern, cursor, chunk.at_end_of_file);

    if matches!(located, Located::Missing { .. }) && pattern.last().is_some_and(String::is_empty) {
        pattern = &pattern[..pattern.len() - 1];
        if replacement.last().is_some_and(String::is_empty) {
            replacement = &replacement[..replacement.len() - 1];
        }
        located = locate(lines, pattern, cursor, chunk.at_end_of_file);
    }

    match located {
        Located::At(found) => Ok((pattern, replacement, found)),
        other => Err(other.describe()),
    }
}

/// Applies `(start, old_len, new)` replacements, last first.
///
/// Descending order means an earlier replacement never shifts a later one's
/// index out from under it.
fn splice(mut lines: Vec<String>, replacements: &[(usize, usize, Vec<String>)]) -> Vec<String> {
    for (start, old_len, new) in replacements.iter().rev() {
        let end = (start + old_len).min(lines.len());
        let start = (*start).min(lines.len());
        lines.splice(start..end, new.iter().cloned());
    }
    lines
}

/// Resolves a patch against the tree without writing anything.
///
/// `root` is the directory relative paths are resolved against. Paths are
/// taken as given; whether they are *allowed* is
/// [`super::safety::assess`]'s question, and a caller must ask it first.
///
/// # Errors
///
/// [`GarrisonErrorKind::PatchApply`](crate::error::GarrisonErrorKind::PatchApply)
/// when a file an update or delete names cannot be read, or when a hunk does
/// not locate.
pub fn plan(patch: &Patch, root: &Path) -> Result<Planned, GarrisonError> {
    let mut changes = Vec::new();
    let mut fidelity = Fidelity::Exact;

    for (index, hunk) in patch.hunks.iter().enumerate() {
        match hunk {
            Hunk::Add { path, contents } => changes.push(Change::Write {
                path: root.join(path),
                contents: contents.clone(),
            }),
            Hunk::Delete { path } => {
                let absolute = root.join(path);
                if !absolute.is_file() {
                    return Err(GarrisonError::patch_apply(
                        index,
                        path.display().to_string(),
                        "there is no such file to delete",
                    ));
                }
                changes.push(Change::Remove { path: absolute });
            }
            Hunk::Update {
                path,
                move_to,
                chunks,
            } => {
                let absolute = root.join(path);
                let display = path.display().to_string();
                let original = std::fs::read_to_string(&absolute).map_err(|error| {
                    GarrisonError::patch_apply(
                        index,
                        &display,
                        format!("cannot read the file to update: {error}"),
                    )
                })?;

                let (contents, reached) = rewrite(&original, chunks, index, &display)?;
                fidelity = fidelity.max(reached);

                match move_to {
                    Some(destination) if destination != path => {
                        changes.push(Change::Write {
                            path: root.join(destination),
                            contents,
                        });
                        changes.push(Change::Remove { path: absolute });
                    }
                    _ => changes.push(Change::Write {
                        path: absolute,
                        contents,
                    }),
                }
            }
        }
    }

    Ok(Planned { changes, fidelity })
}

/// Writes a plan to disk.
///
/// # Errors
///
/// [`GarrisonErrorKind::PatchApply`](crate::error::GarrisonErrorKind::PatchApply)
/// naming the path that failed. A failure here can leave earlier changes
/// applied — the filesystem offers no transaction — but every change was
/// already known to be resolvable, so the remaining causes are the ones no
/// amount of planning prevents: a full disk, a revoked permission.
pub fn commit(changes: &[Change]) -> Result<(), GarrisonError> {
    for (index, change) in changes.iter().enumerate() {
        let blame = |reason: String| {
            GarrisonError::patch_apply(index, change.path().display().to_string(), reason)
        };

        match change {
            Change::Write { path, contents } => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|error| {
                        blame(format!("cannot create {}: {error}", parent.display()))
                    })?;
                }
                std::fs::write(path, contents)
                    .map_err(|error| blame(format!("cannot write: {error}")))?;
            }
            Change::Remove { path } => {
                std::fs::remove_file(path)
                    .map_err(|error| blame(format!("cannot remove: {error}")))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::parse::parse;

    fn chunks(patch: &str) -> Vec<Chunk> {
        let parsed = parse(patch).expect("this patch must parse");
        match &parsed.hunks[0] {
            Hunk::Update { chunks, .. } => chunks.clone(),
            _ => panic!("expected an update hunk"),
        }
    }

    #[test]
    fn a_matching_chunk_replaces_exactly_its_lines() {
        let original = "one\ntwo\nthree\n";
        let chunks = chunks(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@\n\
             \x20one\n\
             -two\n\
             +TWO\n\
             \x20three\n\
             *** End Patch\n",
        );

        let (rewritten, fidelity) = rewrite(original, &chunks, 0, "a.txt").expect("must apply");

        assert_eq!(rewritten, "one\nTWO\nthree\n");
        assert_eq!(fidelity, Fidelity::Exact);
    }

    #[test]
    fn a_drifted_context_still_applies_and_reports_the_tier() {
        // The file was reindented after the model read it.
        let original = "fn main() {\n        let x = 1;\n}\n";
        let chunks = chunks(
            "*** Begin Patch\n\
             *** Update File: a.rs\n\
             @@ fn main() {\n\
             -    let x = 1;\n\
             +    let x = 2;\n\
             *** End Patch\n",
        );

        let (rewritten, fidelity) = rewrite(original, &chunks, 0, "a.rs").expect("must apply");

        assert_eq!(rewritten, "fn main() {\n    let x = 2;\n}\n");
        assert_eq!(fidelity, Fidelity::Whitespace);
    }

    #[test]
    fn an_ambiguous_context_fails_with_every_candidate() {
        let original = "log()\nlog()\n";
        let chunks = chunks(
            "*** Begin Patch\n\
             *** Update File: a.rs\n\
             @@\n\
             -log()\n\
             +trace()\n\
             *** End Patch\n",
        );

        let error = rewrite(original, &chunks, 3, "a.rs").expect_err("must not apply");
        let message = error.to_string();

        assert!(
            message.starts_with("hunk 3 does not apply to a.rs:"),
            "{message}"
        );
        assert!(message.contains("chunk 1"), "{message}");
        assert!(message.contains("lines 1, 2"), "{message}");
    }

    #[test]
    fn a_missing_context_fails_with_the_closest_match() {
        let original = "let x = 1;\nlet y = 9;\n";
        let chunks = chunks(
            "*** Begin Patch\n\
             *** Update File: a.rs\n\
             @@\n\
             \x20let x = 1;\n\
             -let y = 2;\n\
             +let y = 3;\n\
             *** End Patch\n",
        );

        let error = rewrite(original, &chunks, 0, "a.rs").expect_err("must not apply");
        let message = error.to_string();

        assert!(message.contains("closest match"), "{message}");
        assert!(message.contains("let y = 9;"), "{message}");
    }

    #[test]
    fn a_missing_anchor_names_the_anchor() {
        let original = "nothing here\n";
        let chunks = chunks(
            "*** Begin Patch\n\
             *** Update File: a.rs\n\
             @@ fn absent()\n\
             -nothing here\n\
             +something\n\
             *** End Patch\n",
        );

        let error = rewrite(original, &chunks, 0, "a.rs").expect_err("must not apply");

        assert!(error.to_string().contains("fn absent()"), "{error}");
    }

    #[test]
    fn an_anchor_chooses_between_identical_bodies() {
        let original = "fn one() {\n    call();\n}\nfn two() {\n    call();\n}\n";
        let chunks = chunks(
            "*** Begin Patch\n\
             *** Update File: a.rs\n\
             @@ fn two() {\n\
             -    call();\n\
             +    call_twice();\n\
             *** End Patch\n",
        );

        let (rewritten, _) = rewrite(original, &chunks, 0, "a.rs").expect("must apply");

        assert_eq!(
            rewritten,
            "fn one() {\n    call();\n}\nfn two() {\n    call_twice();\n}\n"
        );
    }

    #[test]
    fn two_chunks_apply_in_file_order() {
        let original = "a\nb\nc\nd\n";
        let chunks = chunks(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@\n\
             -a\n\
             +A\n\
             @@\n\
             -d\n\
             +D\n\
             *** End Patch\n",
        );

        let (rewritten, _) = rewrite(original, &chunks, 0, "a.txt").expect("must apply");

        assert_eq!(rewritten, "A\nb\nc\nD\n");
    }

    #[test]
    fn a_pure_insertion_lands_at_its_anchor() {
        let original = "one\nthree\n";
        let chunks = chunks(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@ one\n\
             +two\n\
             *** End Patch\n",
        );

        let (rewritten, _) = rewrite(original, &chunks, 0, "a.txt").expect("must apply");

        assert_eq!(rewritten, "one\ntwo\nthree\n");
    }

    #[test]
    fn a_deletion_only_chunk_removes_its_lines() {
        let original = "keep\ndrop\nkeep too\n";
        let chunks = chunks(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@\n\
             -drop\n\
             *** End Patch\n",
        );

        let (rewritten, _) = rewrite(original, &chunks, 0, "a.txt").expect("must apply");

        assert_eq!(rewritten, "keep\nkeep too\n");
    }

    #[test]
    fn a_file_without_a_final_newline_gets_one() {
        let original = "only line";
        let chunks = chunks(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@\n\
             -only line\n\
             +new line\n\
             *** End Patch\n",
        );

        let (rewritten, _) = rewrite(original, &chunks, 0, "a.txt").expect("must apply");

        assert_eq!(rewritten, "new line\n");
    }

    #[test]
    fn crlf_survives_an_edit() {
        let original = "one\r\ntwo\r\nthree\r\n";
        let chunks = chunks(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@\n\
             -two\n\
             +TWO\n\
             *** End Patch\n",
        );

        let (rewritten, _) = rewrite(original, &chunks, 0, "a.txt").expect("must apply");

        assert_eq!(rewritten, "one\r\nTWO\r\nthree\r\n");
    }

    #[test]
    fn an_end_of_file_chunk_lands_at_the_end() {
        let original = "x\ny\nx\ny\n";
        let chunks = chunks(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@\n\
             -x\n\
             -y\n\
             +z\n\
             *** End of File\n\
             *** End Patch\n",
        );

        let (rewritten, _) = rewrite(original, &chunks, 0, "a.txt").expect("must apply");

        assert_eq!(rewritten, "x\ny\nz\n");
    }
}
