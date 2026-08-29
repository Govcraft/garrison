//! Reading complete entries out of a trail that is still being written to.
//!
//! The audit writer appends; the shipper reads behind it. The one hazard in
//! that arrangement is the last line: at any instant the writer may have
//! flushed half of it. A half line parsed as an entry would be a parse error
//! the shipper had no way to distinguish from a corrupt trail, so this reader
//! never looks at a line that has no newline yet. It comes back on the next
//! tick, whole.
//!
//! # A malformed complete line is not a partial one
//!
//! A line that ends in a newline and still does not parse is a trail that has
//! something in it a daemon did not write. That is reported, not skipped:
//! skipping it would ship the entries after it and leave the plane's chain
//! with a hole nobody recorded.

use acton_ai::audit::AuditEntry;
use std::fmt;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

/// One entry and where the line after it starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// The sealed entry.
    pub entry: AuditEntry,
    /// The byte just past this line's newline.
    pub end_offset: u64,
}

/// What one read of the trail found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Batch {
    /// Complete entries, in file order.
    pub lines: Vec<Line>,
    /// The trail's length at the moment it was read.
    pub file_len: u64,
    /// Whether a line without a newline was left for next time.
    pub partial_tail: bool,
}

impl Batch {
    /// Whether there is nothing to ship right now.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

/// A line that ended properly and still was not an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalformedLine {
    /// Where the line started.
    pub offset: u64,
    /// What the parser said.
    pub reason: String,
}

impl fmt::Display for MalformedLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the audit trail has a complete line at byte {} that is not a sealed entry: {}. \
             Shipping stops rather than skipping past it and leaving the control plane's chain \
             with an unrecorded hole",
            self.offset, self.reason
        )
    }
}

/// Everything reading a batch can find that is not a batch.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReadFault {
    /// The trail could not be read.
    Io(io::Error),
    /// A complete line is not an entry.
    Malformed(MalformedLine),
}

impl fmt::Display for ReadFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "the audit trail could not be read: {error}"),
            Self::Malformed(line) => write!(f, "{line}"),
        }
    }
}

impl std::error::Error for ReadFault {}

impl From<io::Error> for ReadFault {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Reads up to `max_lines` complete entries starting at `offset`.
///
/// # Errors
///
/// [`ReadFault::Io`] when the trail cannot be opened, seeked, or read, and
/// [`ReadFault::Malformed`] when a newline-terminated line is not an entry.
pub fn read_batch(path: &Path, offset: u64, max_lines: usize) -> Result<Batch, ReadFault> {
    let file = std::fs::File::open(path)?;
    let file_len = file.metadata()?.len();
    if offset >= file_len {
        return Ok(Batch {
            lines: Vec::new(),
            file_len,
            partial_tail: false,
        });
    }

    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(offset))?;

    let mut lines = Vec::with_capacity(max_lines.min(64));
    let mut position = offset;
    let mut partial_tail = false;
    let mut raw = Vec::new();

    while lines.len() < max_lines {
        raw.clear();
        let read = reader.read_until(b'\n', &mut raw)?;
        if read == 0 {
            break;
        }
        if raw.last() != Some(&b'\n') {
            // The writer is mid-line. Leave it; it will be whole next tick.
            partial_tail = true;
            break;
        }
        position += read as u64;
        let text = String::from_utf8_lossy(&raw);
        let trimmed = text.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(trimmed) {
            Ok(entry) => lines.push(Line {
                entry,
                end_offset: position,
            }),
            Err(error) => {
                return Err(ReadFault::Malformed(MalformedLine {
                    offset: position - read as u64,
                    reason: error.to_string(),
                }))
            }
        }
    }

    Ok(Batch {
        lines,
        file_len,
        partial_tail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use acton_ai::types::TrailId;
    use garrison_wire::audit::fixture;
    use std::io::Write as _;

    /// Writes a trail of `count` sealed entries and returns it with the file.
    fn trail(count: u64) -> (tempfile::TempDir, std::path::PathBuf, Vec<AuditEntry>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let entries = fixture::chain(count, &TrailId::new());
        let mut file = std::fs::File::create(&path).expect("create");
        for entry in &entries {
            writeln!(file, "{}", entry.to_jsonl().expect("jsonl")).expect("write");
        }
        (dir, path, entries)
    }

    #[test]
    fn an_empty_trail_yields_nothing_and_says_how_long_it_is() {
        let (_dir, path, _) = trail(0);

        let batch = read_batch(&path, 0, 50).expect("read");

        assert!(batch.is_empty());
        assert_eq!(batch.file_len, 0);
        assert!(!batch.partial_tail);
    }

    #[test]
    fn every_entry_is_read_in_file_order_with_where_the_next_line_starts() {
        let (_dir, path, entries) = trail(3);

        let batch = read_batch(&path, 0, 50).expect("read");

        assert_eq!(batch.lines.len(), 3);
        for (line, expected) in batch.lines.iter().zip(&entries) {
            assert_eq!(&line.entry, expected);
        }
        assert_eq!(
            batch.lines.last().expect("a last line").end_offset,
            batch.file_len,
            "the last line ends where the file does"
        );
    }

    #[test]
    fn reading_resumes_from_an_offset_a_previous_batch_reported() {
        let (_dir, path, entries) = trail(4);
        let first = read_batch(&path, 0, 2).expect("read");
        let offset = first.lines.last().expect("a line").end_offset;

        let second = read_batch(&path, offset, 50).expect("read");

        assert_eq!(second.lines.len(), 2);
        assert_eq!(second.lines[0].entry, entries[2]);
    }

    #[test]
    fn no_more_than_the_asked_for_number_of_lines_comes_back() {
        let (_dir, path, _) = trail(10);

        assert_eq!(read_batch(&path, 0, 4).expect("read").lines.len(), 4);
    }

    #[test]
    fn a_line_the_writer_has_not_finished_is_left_for_next_time() {
        let (_dir, path, entries) = trail(2);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append");
        // Half of a third entry, with no newline yet.
        let half = &entries[1].to_jsonl().expect("jsonl")[..20];
        file.write_all(half.as_bytes()).expect("write");
        drop(file);

        let batch = read_batch(&path, 0, 50).expect("read");

        assert_eq!(batch.lines.len(), 2, "only the complete lines are shipped");
        assert!(batch.partial_tail);
    }

    #[test]
    fn a_complete_line_that_is_not_an_entry_stops_shipping_rather_than_being_skipped() {
        let (_dir, path, _) = trail(1);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append");
        writeln!(file, "{{\"not\":\"an entry\"}}").expect("write");
        drop(file);

        let fault = read_batch(&path, 0, 50).expect_err("must refuse");

        let ReadFault::Malformed(line) = fault else {
            panic!("expected a malformed line, got {fault}");
        };
        assert!(line.to_string().contains("unrecorded hole"));
    }

    #[test]
    fn a_blank_line_is_not_an_entry_and_is_not_an_error_either() {
        let (_dir, path, _) = trail(1);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append");
        writeln!(file).expect("write");
        drop(file);

        let batch = read_batch(&path, 0, 50).expect("read");

        assert_eq!(batch.lines.len(), 1);
    }

    #[test]
    fn an_offset_at_the_end_of_the_trail_finds_nothing_new() {
        let (_dir, path, _) = trail(2);
        let whole = read_batch(&path, 0, 50).expect("read");

        let nothing = read_batch(&path, whole.file_len, 50).expect("read");

        assert!(nothing.is_empty());
        assert_eq!(nothing.file_len, whole.file_len);
    }

    #[test]
    fn a_trail_that_is_not_there_is_an_io_fault_not_an_empty_batch() {
        let fault = read_batch(Path::new("/nonexistent/garrison/audit.jsonl"), 0, 50)
            .expect_err("must fail");

        assert!(matches!(fault, ReadFault::Io(_)), "{fault}");
    }
}
