//! Turning patch text into a [`Patch`].
//!
//! Pure: a `&str` in, a `Patch` or a [`GarrisonError`] out, no filesystem
//! touched. Whether the patch *applies* is [`super::apply`]'s question; this
//! module only answers whether it is well-formed.
//!
//! # Diagnostics
//!
//! Every failure carries the one-based line number within the patch text. A
//! model that gets the format wrong is shown exactly where, which is the
//! difference between it fixing the line and it rewriting the whole patch.
//!
//! # Leniency, and its limit
//!
//! Marker lines are matched after trimming, because models pad them. Content
//! lines are never trimmed: their leading character is the operator and their
//! remainder is bytes destined for a file.
//!
//! One further indulgence: a patch wrapped in a `<<'EOF' … EOF` heredoc is
//! unwrapped first. Models trained to invoke `apply_patch` as a shell command
//! emit that wrapper, and the alternative to accepting it is a turn wasted on
//! a syntax error about a shell that was never involved.

use super::format::{
    Chunk, Hunk, Patch, ADD_FILE, ANCHOR, BEGIN_PATCH, DELETE_FILE, END_OF_FILE, END_PATCH,
    MOVE_TO, UPDATE_FILE,
};
use crate::error::GarrisonError;
use std::path::PathBuf;

/// Parses patch text.
///
/// # Errors
///
/// [`GarrisonErrorKind::PatchParse`](crate::error::GarrisonErrorKind::PatchParse)
/// with the offending line number: a missing or misplaced envelope, an
/// unrecognized line where a hunk header belongs, an empty file name, an
/// update hunk with no chunks, or a chunk whose body says nothing.
pub fn parse(text: &str) -> Result<Patch, GarrisonError> {
    let lines = unwrap_heredoc(&numbered(text));
    let body = envelope(&lines)?;

    let mut hunks = Vec::new();
    let mut cursor = 0;

    while cursor < body.len() {
        let (hunk, next) = hunk(body, cursor)?;
        hunks.push(hunk);
        cursor = next;
    }

    Ok(Patch { hunks })
}

/// One line of the patch text with the line number a human would name it by.
type Line<'a> = (usize, &'a str);

/// Pairs every line with its one-based number.
fn numbered(text: &str) -> Vec<Line<'_>> {
    text.lines().enumerate().map(|(i, l)| (i + 1, l)).collect()
}

/// Strips a `<<'EOF' … EOF` wrapper, if the whole text is inside one.
fn unwrap_heredoc<'a>(lines: &[Line<'a>]) -> Vec<Line<'a>> {
    let opens = |line: &str| matches!(line.trim(), "<<EOF" | "<<'EOF'" | "<<\"EOF\"");

    match lines {
        [first, middle @ .., last] if opens(first.1) && last.1.trim_end().ends_with("EOF") => {
            middle.to_vec()
        }
        other => other.to_vec(),
    }
}

/// Checks the envelope and returns what it contains.
fn envelope<'a, 'b>(lines: &'b [Line<'a>]) -> Result<&'b [Line<'a>], GarrisonError> {
    let content: Vec<&Line<'a>> = lines.iter().filter(|(_, l)| !l.trim().is_empty()).collect();

    let Some(first) = content.first() else {
        return Err(GarrisonError::patch_parse(
            1,
            format!("a patch must begin with '{BEGIN_PATCH}'; this text is empty"),
        ));
    };

    if first.1.trim() != BEGIN_PATCH {
        return Err(GarrisonError::patch_parse(
            first.0,
            format!("expected '{BEGIN_PATCH}' here"),
        ));
    }

    let last = content
        .last()
        .expect("a slice with a first element has a last one");
    if last.1.trim() != END_PATCH {
        return Err(GarrisonError::patch_parse(
            last.0,
            format!("expected '{END_PATCH}' here; the patch is unterminated"),
        ));
    }

    let start = lines
        .iter()
        .position(|(n, _)| *n == first.0)
        .expect("the first content line came from this slice");
    let end = lines
        .iter()
        .position(|(n, _)| *n == last.0)
        .expect("the last content line came from this slice");

    Ok(&lines[start + 1..end])
}

/// Parses one hunk beginning at `cursor`, returning it and the next cursor.
fn hunk<'a>(lines: &[Line<'a>], cursor: usize) -> Result<(Hunk, usize), GarrisonError> {
    let (number, header) = lines[cursor];
    let header = header.trim();

    // Matched without the marker's trailing space: a header whose file name
    // was blank has already lost that space to the trim above, and blaming an
    // empty name reads better than blaming an unrecognized header.
    if let Some(path) = header.strip_prefix(ADD_FILE.trim_end()) {
        return add_hunk(lines, cursor, filename(number, path)?);
    }
    if let Some(path) = header.strip_prefix(DELETE_FILE.trim_end()) {
        return Ok((
            Hunk::Delete {
                path: filename(number, path)?,
            },
            cursor + 1,
        ));
    }
    if let Some(path) = header.strip_prefix(UPDATE_FILE.trim_end()) {
        return update_hunk(lines, cursor, filename(number, path)?);
    }

    Err(GarrisonError::patch_parse(
        number,
        format!(
            "expected a hunk header ('{}', '{}', or '{}'), found '{header}'",
            ADD_FILE.trim_end(),
            DELETE_FILE.trim_end(),
            UPDATE_FILE.trim_end()
        ),
    ))
}

/// Validates and builds a file name from a header's tail.
fn filename(number: usize, raw: &str) -> Result<PathBuf, GarrisonError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(GarrisonError::patch_parse(number, "the file name is empty"));
    }
    Ok(PathBuf::from(trimmed))
}

/// Whether a line starts a new hunk, and therefore ends the current one.
fn starts_a_hunk(line: &str) -> bool {
    let line = line.trim();
    line.starts_with(ADD_FILE.trim_end())
        || line.starts_with(DELETE_FILE.trim_end())
        || line.starts_with(UPDATE_FILE.trim_end())
}

/// Parses the `+` lines that make up a new file.
fn add_hunk<'a>(
    lines: &[Line<'a>],
    cursor: usize,
    path: PathBuf,
) -> Result<(Hunk, usize), GarrisonError> {
    let mut contents = String::new();
    let mut index = cursor + 1;

    while index < lines.len() {
        let (number, line) = lines[index];
        if starts_a_hunk(line) {
            break;
        }
        let Some(added) = line.strip_prefix('+') else {
            return Err(GarrisonError::patch_parse(
                number,
                format!("every line of an added file must start with '+', found '{line}'"),
            ));
        };
        contents.push_str(added);
        contents.push('\n');
        index += 1;
    }

    Ok((Hunk::Add { path, contents }, index))
}

/// Parses an update hunk: an optional rename, then one or more chunks.
fn update_hunk<'a>(
    lines: &[Line<'a>],
    cursor: usize,
    path: PathBuf,
) -> Result<(Hunk, usize), GarrisonError> {
    let header_line = lines[cursor].0;
    let mut index = cursor + 1;
    let mut move_to = None;

    if let Some((number, line)) = lines.get(index) {
        if let Some(destination) = line.trim().strip_prefix(MOVE_TO) {
            move_to = Some(filename(*number, destination)?);
            index += 1;
        }
    }

    let mut chunks: Vec<Chunk> = Vec::new();
    let mut current: Option<Chunk> = None;

    while index < lines.len() {
        let (number, line) = lines[index];
        if starts_a_hunk(line) {
            break;
        }
        index += 1;

        let trimmed = line.trim();

        if trimmed == END_OF_FILE {
            let chunk = current.as_mut().ok_or_else(|| {
                GarrisonError::patch_parse(
                    number,
                    format!("'{END_OF_FILE}' must follow a chunk, not open one"),
                )
            })?;
            chunk.at_end_of_file = true;
            continue;
        }

        if trimmed == ANCHOR || trimmed.starts_with("@@ ") {
            if let Some(chunk) = current.take() {
                chunks.push(finish(chunk, number)?);
            }
            let anchor = trimmed
                .strip_prefix(ANCHOR)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(ToString::to_string);
            current = Some(Chunk {
                anchor,
                ..Chunk::default()
            });
            continue;
        }

        let chunk = current.get_or_insert_with(Chunk::default);
        change(chunk, number, line)?;
    }

    if let Some(chunk) = current.take() {
        chunks.push(finish(
            chunk,
            lines.get(index).map_or(header_line, |l| l.0),
        )?);
    }

    if chunks.is_empty() {
        return Err(GarrisonError::patch_parse(
            header_line,
            format!(
                "the update hunk for '{}' has no chunks; an update that changes nothing is a \
                 mistake, not a no-op",
                path.display()
            ),
        ));
    }

    Ok((
        Hunk::Update {
            path,
            move_to,
            chunks,
        },
        index,
    ))
}

/// Records one context, removal, or addition line.
fn change(chunk: &mut Chunk, number: usize, line: &str) -> Result<(), GarrisonError> {
    // A wholly empty line is a blank context line. Models write one rather
    // than a line holding a single space, and every editor on earth strips
    // that space back out again.
    if line.is_empty() {
        chunk.push_context(String::new());
        return Ok(());
    }

    let (marker, text) = line.split_at(1);
    match marker {
        " " => chunk.push_context(text.to_string()),
        "-" => chunk.push_removal(text.to_string()),
        "+" => chunk.push_addition(text.to_string()),
        other => {
            return Err(GarrisonError::patch_parse(
                number,
                format!(
                    "a chunk line must start with ' ', '-', or '+', found '{other}' in '{line}'"
                ),
            ))
        }
    }
    Ok(())
}

/// Rejects a chunk that says nothing.
fn finish(chunk: Chunk, number: usize) -> Result<Chunk, GarrisonError> {
    if chunk.is_empty() {
        return Err(GarrisonError::patch_parse(
            number,
            "this chunk has no lines; a '@@' with nothing under it changes nothing",
        ));
    }
    Ok(chunk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch(text: &str) -> Patch {
        parse(text).expect("this patch must parse")
    }

    #[test]
    fn an_added_file_carries_its_whole_contents() {
        let parsed = patch(
            "*** Begin Patch\n\
             *** Add File: notes/hello.txt\n\
             +first\n\
             +second\n\
             *** End Patch\n",
        );

        assert_eq!(
            parsed.hunks,
            vec![Hunk::Add {
                path: PathBuf::from("notes/hello.txt"),
                contents: "first\nsecond\n".to_string(),
            }]
        );
    }

    #[test]
    fn a_deleted_file_is_just_its_name() {
        let parsed = patch("*** Begin Patch\n*** Delete File: gone.txt\n*** End Patch\n");

        assert_eq!(
            parsed.hunks,
            vec![Hunk::Delete {
                path: PathBuf::from("gone.txt")
            }]
        );
    }

    #[test]
    fn an_update_separates_context_removals_and_additions() {
        let parsed = patch(
            "*** Begin Patch\n\
             *** Update File: src/lib.rs\n\
             @@ fn main()\n\
             \x20    let x = 1;\n\
             -    let y = 2;\n\
             +    let y = 3;\n\
             *** End Patch\n",
        );

        let Hunk::Update { chunks, .. } = &parsed.hunks[0] else {
            panic!("expected an update hunk");
        };
        assert_eq!(chunks[0].anchor.as_deref(), Some("fn main()"));
        assert_eq!(
            chunks[0].old_lines,
            vec!["    let x = 1;", "    let y = 2;"]
        );
        assert_eq!(
            chunks[0].new_lines,
            vec!["    let x = 1;", "    let y = 3;"]
        );
    }

    #[test]
    fn a_bare_anchor_names_no_region() {
        let parsed = patch(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@\n\
             -old\n\
             +new\n\
             *** End Patch\n",
        );

        let Hunk::Update { chunks, .. } = &parsed.hunks[0] else {
            panic!("expected an update hunk");
        };
        assert_eq!(chunks[0].anchor, None);
    }

    #[test]
    fn each_anchor_opens_a_new_chunk() {
        let parsed = patch(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@ one\n\
             -a\n\
             +b\n\
             @@ two\n\
             -c\n\
             +d\n\
             *** End Patch\n",
        );

        let Hunk::Update { chunks, .. } = &parsed.hunks[0] else {
            panic!("expected an update hunk");
        };
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[1].anchor.as_deref(), Some("two"));
    }

    #[test]
    fn a_rename_is_an_update_with_a_destination() {
        let parsed = patch(
            "*** Begin Patch\n\
             *** Update File: old/name.txt\n\
             *** Move to: new/dir/name.txt\n\
             -a\n\
             +b\n\
             *** End Patch\n",
        );

        let Hunk::Update { move_to, .. } = &parsed.hunks[0] else {
            panic!("expected an update hunk");
        };
        assert_eq!(
            move_to.as_deref(),
            Some(std::path::Path::new("new/dir/name.txt"))
        );
    }

    #[test]
    fn the_end_of_file_marker_binds_to_the_chunk_before_it() {
        let parsed = patch(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@\n\
             -last\n\
             +final\n\
             *** End of File\n\
             *** End Patch\n",
        );

        let Hunk::Update { chunks, .. } = &parsed.hunks[0] else {
            panic!("expected an update hunk");
        };
        assert!(chunks[0].at_end_of_file);
    }

    #[test]
    fn several_hunks_parse_in_order() {
        let parsed = patch(
            "*** Begin Patch\n\
             *** Add File: new.txt\n\
             +hi\n\
             *** Delete File: old.txt\n\
             *** Update File: mid.txt\n\
             -a\n\
             +b\n\
             *** End Patch\n",
        );

        assert_eq!(parsed.hunks.len(), 3);
        assert!(matches!(parsed.hunks[0], Hunk::Add { .. }));
        assert!(matches!(parsed.hunks[1], Hunk::Delete { .. }));
        assert!(matches!(parsed.hunks[2], Hunk::Update { .. }));
    }

    #[test]
    fn a_blank_line_inside_a_chunk_is_blank_context() {
        let parsed = patch(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@\n\
             \x20one\n\
             \n\
             -two\n\
             +three\n\
             *** End Patch\n",
        );

        let Hunk::Update { chunks, .. } = &parsed.hunks[0] else {
            panic!("expected an update hunk");
        };
        assert_eq!(chunks[0].old_lines, vec!["one", "", "two"]);
        assert_eq!(chunks[0].new_lines, vec!["one", "", "three"]);
    }

    #[test]
    fn padded_markers_are_tolerated() {
        let parsed = patch(
            "  *** Begin Patch  \n\
             \x20 *** Delete File: gone.txt \n\
             \x20 *** End Patch  \n",
        );

        assert_eq!(
            parsed.hunks,
            vec![Hunk::Delete {
                path: PathBuf::from("gone.txt")
            }]
        );
    }

    #[test]
    fn a_heredoc_wrapper_is_unwrapped_rather_than_rejected() {
        let parsed = patch(
            "<<'EOF'\n\
             *** Begin Patch\n\
             *** Delete File: gone.txt\n\
             *** End Patch\n\
             EOF\n",
        );

        assert_eq!(parsed.hunks.len(), 1);
    }

    #[test]
    fn an_empty_patch_parses_to_no_hunks() {
        // Well-formed but pointless. Refusing it is the safety assessment's
        // job, not the parser's: the two failures read differently and a
        // caller wants to tell them apart.
        assert!(patch("*** Begin Patch\n*** End Patch\n").is_empty());
    }

    #[test]
    fn text_without_the_opening_marker_is_refused_at_its_first_line() {
        let error = parse("*** Update File: a.txt\n-a\n+b\n").expect_err("this must not parse");

        assert_eq!(
            error.to_string(),
            "invalid patch at line 1: expected '*** Begin Patch' here"
        );
    }

    #[test]
    fn an_unterminated_patch_is_refused_at_its_last_line() {
        let error =
            parse("*** Begin Patch\n*** Delete File: a.txt\n").expect_err("this must not parse");

        assert!(
            error.to_string().starts_with("invalid patch at line 2:"),
            "expected the last line to be blamed, got: {error}"
        );
    }

    #[test]
    fn an_unrecognized_hunk_header_names_itself() {
        let error = parse("*** Begin Patch\n*** Rewrite File: a.txt\n*** End Patch\n")
            .expect_err("this must not parse");

        assert!(
            error.to_string().contains("*** Rewrite File: a.txt"),
            "the offending line must be quoted back: {error}"
        );
    }

    #[test]
    fn an_update_with_no_chunks_is_refused() {
        let error = parse("*** Begin Patch\n*** Update File: a.txt\n*** End Patch\n")
            .expect_err("this must not parse");

        assert!(
            error.to_string().contains("has no chunks"),
            "unexpected message: {error}"
        );
    }

    #[test]
    fn an_anchor_with_nothing_under_it_is_refused() {
        let error = parse(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@ one\n\
             @@ two\n\
             -a\n\
             +b\n\
             *** End Patch\n",
        )
        .expect_err("this must not parse");

        assert!(
            error.to_string().contains("has no lines"),
            "unexpected message: {error}"
        );
    }

    #[test]
    fn an_added_file_line_without_a_plus_is_refused() {
        let error = parse(
            "*** Begin Patch\n\
             *** Add File: a.txt\n\
             +good\n\
             bad\n\
             *** End Patch\n",
        )
        .expect_err("this must not parse");

        assert!(
            error.to_string().starts_with("invalid patch at line 4:"),
            "the offending line must be blamed: {error}"
        );
    }

    #[test]
    fn a_chunk_line_with_an_unknown_marker_is_refused() {
        let error = parse(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@\n\
             ?what\n\
             *** End Patch\n",
        )
        .expect_err("this must not parse");

        assert!(
            error.to_string().contains("must start with"),
            "unexpected message: {error}"
        );
    }

    #[test]
    fn an_empty_file_name_is_refused() {
        let error = parse("*** Begin Patch\n*** Delete File:   \n*** End Patch\n")
            .expect_err("this must not parse");

        assert!(
            error.to_string().contains("file name is empty"),
            "unexpected message: {error}"
        );
    }

    #[test]
    fn an_end_of_file_marker_with_no_chunk_is_refused() {
        let error = parse(
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             *** End of File\n\
             *** End Patch\n",
        )
        .expect_err("this must not parse");

        assert!(
            error.to_string().contains("must follow a chunk"),
            "unexpected message: {error}"
        );
    }

    #[test]
    fn empty_text_is_refused_rather_than_parsed_as_an_empty_patch() {
        let error = parse("   \n\n").expect_err("this must not parse");

        assert!(
            error.to_string().contains("this text is empty"),
            "unexpected message: {error}"
        );
    }
}
