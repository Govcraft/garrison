//! How far the trail has been shipped, remembered across restarts.
//!
//! The trail file is the buffer. Shipping is a reader of it with a durable
//! byte offset, which is what makes an unreachable plane a backlog rather
//! than a loss: nothing is held in memory that a crash would drop, and
//! nothing is deleted once it has been accepted.
//!
//! # Why a byte offset and a chain position
//!
//! The offset is where to resume reading. The sequence and hash are how the
//! shipper checks that the file it is resuming into is the same file it left.
//! A trail that was truncated, rotated, or rewritten under the cursor is not
//! a trail to keep appending to blindly: the entries the plane already holds
//! would no longer be the prefix of what is on disk, and the plane's chain
//! would fork against a local file nobody could reproduce. Detecting that at
//! resume, and saying so, is the whole reason both are stored.
//!
//! # Fail closed
//!
//! Every fault here stops shipping and is reported. None of them silently
//! reset the cursor: "start again from zero" over a rewritten trail is how a
//! deletion becomes invisible.

use acton_ai::audit::AuditEntry;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// Where shipping has got to on one trail.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// The trail this cursor is about, as acton-ai sealed it.
    ///
    /// A cursor whose trail id is not the live trail's belongs to a trail
    /// that was rotated away, and is discarded rather than resumed; see
    /// [`Cursor::resume`].
    pub trail_id: String,
    /// The `AuditTrail` row on the plane, once one is known.
    ///
    /// Cached so an ordinary batch costs no lookup. `None` on a first run and
    /// after a trail rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trail_row: Option<String>,
    /// The byte just past the last shipped line, including its newline.
    pub byte_offset: u64,
    /// The sequence number of the last shipped entry, 0 for none.
    pub sequence: u64,
    /// That entry's hash, empty for none.
    #[serde(default)]
    pub hash: String,
}

impl Cursor {
    /// A cursor that has shipped nothing of `trail_id`.
    #[must_use]
    pub fn genesis(trail_id: &str) -> Self {
        Self {
            trail_id: trail_id.to_string(),
            trail_row: None,
            byte_offset: 0,
            sequence: 0,
            hash: String::new(),
        }
    }

    /// Advances past one shipped entry.
    ///
    /// `end_offset` is the byte just past that entry's line, which the reader
    /// reports; it is not derived from the entry, because the line's length
    /// on disk is the only thing that says where the next one starts.
    pub fn advance(&mut self, entry: &AuditEntry, end_offset: u64) {
        self.byte_offset = end_offset;
        self.sequence = entry.sequence;
        self.hash.clone_from(&entry.hash);
    }

    /// The cursor to resume from, given what is on disk now.
    ///
    /// Pure. `stored` is what the last run persisted, `trail_id` is the
    /// identity acton-ai reports for the live trail, and `file_len` is its
    /// current length. Returns the cursor to use, or the fault that stops
    /// shipping.
    ///
    /// A cursor for a different trail is not a fault: the trail was rotated,
    /// the plane will get a new `AuditTrail` row, and shipping starts from
    /// the beginning of the new file. A cursor for *this* trail pointing past
    /// the end of it is a fault, because the entries it says were shipped are
    /// no longer there.
    ///
    /// # Errors
    ///
    /// [`ResumeFault::LocalTruncation`] when the trail is shorter than the
    /// cursor.
    pub fn resume(
        stored: Option<Self>,
        trail_id: &str,
        file_len: u64,
    ) -> Result<Self, ResumeFault> {
        let Some(stored) = stored else {
            return Ok(Self::genesis(trail_id));
        };
        if stored.trail_id != trail_id {
            return Ok(Self::genesis(trail_id));
        }
        if stored.byte_offset > file_len {
            return Err(ResumeFault::LocalTruncation {
                offset: stored.byte_offset,
                file_len,
            });
        }
        Ok(stored)
    }

    /// Whether the next entry on disk really follows this cursor.
    ///
    /// Pure. Called once per resume, on the first entry read after the stored
    /// offset. A cursor at genesis vouches for nothing and accepts whatever
    /// the file starts with; acton-ai's own chain verification is what
    /// catches a file that does not start at sequence 1.
    ///
    /// # Errors
    ///
    /// [`ResumeFault::RewrittenUnderCursor`] when the entry at the offset is
    /// not the successor of the last shipped one.
    pub fn check_successor(&self, next: &AuditEntry) -> Result<(), ResumeFault> {
        if self.sequence == 0 && self.hash.is_empty() {
            return Ok(());
        }
        if next.sequence != self.sequence.saturating_add(1) {
            return Err(ResumeFault::RewrittenUnderCursor {
                reason: format!(
                    "the entry at byte {} is sequence {} where the shipped cursor expected {}",
                    self.byte_offset,
                    next.sequence,
                    self.sequence.saturating_add(1)
                ),
            });
        }
        if next.prev_hash != self.hash {
            return Err(ResumeFault::RewrittenUnderCursor {
                reason: format!(
                    "the entry at sequence {} points at predecessor {} but the last entry \
                     shipped from this trail hashed to {}",
                    next.sequence, next.prev_hash, self.hash
                ),
            });
        }
        if let Some(carried) = next.trail_id.as_ref() {
            if carried.to_string() != self.trail_id {
                return Err(ResumeFault::RewrittenUnderCursor {
                    reason: format!(
                        "the entry at sequence {} belongs to trail {carried} but this cursor \
                         is shipping trail {}",
                        next.sequence, self.trail_id
                    ),
                });
            }
        }
        Ok(())
    }
}

/// Why shipping cannot resume where it left off.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResumeFault {
    /// The trail is shorter than the cursor: entries that were shipped are
    /// no longer on disk.
    LocalTruncation {
        /// Where the cursor said to resume.
        offset: u64,
        /// How long the trail actually is.
        file_len: u64,
    },
    /// The entry at the cursor is not the successor of the last shipped one:
    /// the trail was rewritten underneath it.
    RewrittenUnderCursor {
        /// Which link does not hold, in words.
        reason: String,
    },
}

impl fmt::Display for ResumeFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalTruncation { offset, file_len } => write!(
                f,
                "the audit trail is {file_len} bytes but {offset} bytes of it have already been \
                 shipped: the file was truncated or replaced. The entries the control plane \
                 holds are no longer the start of this file, so shipping stops here. Keep the \
                 trail and the `.shipped` cursor as evidence and have a security officer \
                 compare them against the plane's AuditChain"
            ),
            Self::RewrittenUnderCursor { reason } => write!(
                f,
                "the audit trail was rewritten under the shipping cursor: {reason}. Shipping \
                 stops here rather than forking the control plane's chain; keep the trail as \
                 evidence and have a security officer compare it against the plane's AuditChain"
            ),
        }
    }
}

impl std::error::Error for ResumeFault {}

/// Where the cursor for a trail lives: the trail path with `.shipped` added.
///
/// Beside the trail and its `.trail` identity sidecar, because the three are
/// one artifact: copying a trail without its cursor and re-shipping it is a
/// replay the plane answers with 409s, and copying the cursor without the
/// trail is a cursor that fails its own resume check.
#[must_use]
pub fn cursor_path(trail: &Path) -> PathBuf {
    let mut name = trail.as_os_str().to_os_string();
    name.push(".shipped");
    PathBuf::from(name)
}

/// Reads the cursor, or `None` when this trail has never been shipped.
///
/// A missing file is the first-run case. A present but unparsable one is an
/// error: treating it as absent would re-ship the whole trail, and treating
/// it as genesis would hide whatever corrupted it.
///
/// # Errors
///
/// The underlying I/O error, or [`io::ErrorKind::InvalidData`] when the file
/// is not a cursor.
pub fn read(path: &Path) -> io::Result<Option<Cursor>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    serde_json::from_str(&text).map(Some).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the shipping cursor at '{}' is not readable: {error}. Remove it to re-ship \
                 this trail from the beginning; the control plane answers a replay with 409 \
                 and records nothing twice",
                path.display()
            ),
        )
    })
}

/// Writes the cursor atomically.
///
/// Temp file plus rename, so a crash mid-write leaves either the old cursor
/// or the new one and never half of either. A cursor that lands truncated
/// would re-ship entries, which is harmless, or skip them, which is not.
///
/// # Errors
///
/// The underlying I/O error.
pub fn write(path: &Path, cursor: &Cursor) -> io::Result<()> {
    let encoded = serde_json::to_vec_pretty(cursor)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let temporary = temp_path(path);
    std::fs::write(&temporary, &encoded)?;
    std::fs::rename(&temporary, path)
}

/// The staging path for an atomic write, distinct per process.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acton_ai::audit::GENESIS_HASH;
    use acton_ai::types::TrailId;
    use garrison_wire::audit::fixture;

    fn trail() -> TrailId {
        TrailId::new()
    }

    fn chain(count: u64, id: &TrailId) -> Vec<AuditEntry> {
        fixture::chain(count, id)
    }

    #[test]
    fn a_trail_never_shipped_before_starts_at_the_beginning() {
        let cursor = Cursor::resume(None, "trail_abc", 4096).expect("a first run resumes");

        assert_eq!(cursor.byte_offset, 0);
        assert_eq!(cursor.sequence, 0);
        assert_eq!(cursor.trail_id, "trail_abc");
        assert_eq!(cursor.trail_row, None);
    }

    #[test]
    fn a_cursor_for_another_trail_is_discarded_because_the_trail_was_rotated() {
        let stale = Cursor {
            trail_id: "trail_old".to_string(),
            trail_row: Some("audittrail_old".to_string()),
            byte_offset: 900,
            sequence: 12,
            hash: "abc".to_string(),
        };

        let cursor = Cursor::resume(Some(stale), "trail_new", 40).expect("a rotation resumes");

        assert_eq!(cursor, Cursor::genesis("trail_new"));
    }

    #[test]
    fn a_cursor_past_the_end_of_its_own_trail_is_a_truncation() {
        let stored = Cursor {
            trail_id: "trail_abc".to_string(),
            trail_row: None,
            byte_offset: 5000,
            sequence: 9,
            hash: "abc".to_string(),
        };

        let fault = Cursor::resume(Some(stored), "trail_abc", 400).expect_err("must refuse");

        assert_eq!(
            fault,
            ResumeFault::LocalTruncation {
                offset: 5000,
                file_len: 400
            }
        );
        assert!(fault.to_string().contains("security officer"));
    }

    #[test]
    fn a_cursor_exactly_at_the_end_of_its_trail_resumes() {
        let stored = Cursor {
            trail_id: "trail_abc".to_string(),
            trail_row: None,
            byte_offset: 400,
            sequence: 9,
            hash: "abc".to_string(),
        };

        let cursor = Cursor::resume(Some(stored.clone()), "trail_abc", 400).expect("resumes");

        assert_eq!(cursor, stored);
    }

    #[test]
    fn the_entry_after_a_cursor_must_be_the_next_link_in_the_chain() {
        let id = trail();
        let entries = chain(3, &id);
        let mut cursor = Cursor::genesis(&id.to_string());
        cursor.advance(&entries[0], 200);
        cursor.advance(&entries[1], 400);

        cursor
            .check_successor(&entries[2])
            .expect("the third entry follows the second");
    }

    #[test]
    fn an_entry_that_skips_a_sequence_means_the_trail_was_rewritten() {
        let id = trail();
        let entries = chain(3, &id);
        let mut cursor = Cursor::genesis(&id.to_string());
        cursor.advance(&entries[0], 200);

        let fault = cursor
            .check_successor(&entries[2])
            .expect_err("a skipped entry must be caught");

        assert!(
            matches!(fault, ResumeFault::RewrittenUnderCursor { .. }),
            "{fault:?}"
        );
        assert!(fault.to_string().contains("sequence 3"));
    }

    #[test]
    fn an_entry_that_points_at_a_different_predecessor_means_the_trail_was_rewritten() {
        let id = trail();
        let entries = chain(2, &id);
        let mut cursor = Cursor::genesis(&id.to_string());
        cursor.advance(&entries[0], 200);
        cursor.hash = "a-hash-that-is-not-the-first-entrys".to_string();

        let fault = cursor
            .check_successor(&entries[1])
            .expect_err("a broken link must be caught");

        assert!(fault.to_string().contains("predecessor"), "{fault}");
    }

    #[test]
    fn an_entry_from_another_trail_at_the_cursor_is_refused() {
        let mine = trail();
        let theirs = trail();
        let mut cursor = Cursor::genesis(&mine.to_string());
        cursor.sequence = 1;
        cursor.hash = GENESIS_HASH.to_string();

        let intruder = fixture::entry(
            2,
            GENESIS_HASH,
            Some(&theirs),
            "bash",
            serde_json::json!({}),
            acton_ai::audit::AuditOutcome::Success {
                summary: "ok".to_string(),
            },
            acton_ai::audit::AuditDecision::approved(acton_ai::policy::Decider::Rules),
        );

        let fault = cursor
            .check_successor(&intruder)
            .expect_err("another trail's entry must be caught");

        assert!(fault.to_string().contains(&theirs.to_string()), "{fault}");
    }

    #[test]
    fn a_genesis_cursor_vouches_for_nothing_and_accepts_the_first_entry() {
        let id = trail();
        let entries = chain(1, &id);

        Cursor::genesis(&id.to_string())
            .check_successor(&entries[0])
            .expect("a first run has nothing to disagree with");
    }

    #[test]
    fn the_cursor_lives_beside_the_trail_it_is_about() {
        assert_eq!(
            cursor_path(Path::new("/var/lib/garrison/audit.jsonl")),
            PathBuf::from("/var/lib/garrison/audit.jsonl.shipped")
        );
    }

    #[test]
    fn a_cursor_round_trips_through_the_file_it_is_written_to() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = cursor_path(&dir.path().join("audit.jsonl"));

        assert_eq!(read(&path).expect("a missing cursor is not an error"), None);

        let cursor = Cursor {
            trail_id: "trail_abc".to_string(),
            trail_row: Some("audittrail_01".to_string()),
            byte_offset: 1024,
            sequence: 7,
            hash: "0f0f".to_string(),
        };
        write(&path, &cursor).expect("write");

        assert_eq!(read(&path).expect("read"), Some(cursor));
    }

    #[test]
    fn a_cursor_file_that_is_not_a_cursor_is_an_error_rather_than_a_fresh_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl.shipped");
        std::fs::write(&path, "not json").expect("write");

        let error = read(&path).expect_err("must refuse");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("409"));
    }

    #[test]
    fn advancing_records_where_the_next_line_starts_and_what_was_shipped() {
        let id = trail();
        let entries = chain(2, &id);
        let mut cursor = Cursor::genesis(&id.to_string());

        cursor.advance(&entries[0], 311);

        assert_eq!(cursor.byte_offset, 311);
        assert_eq!(cursor.sequence, 1);
        assert_eq!(cursor.hash, entries[0].hash);
    }
}
