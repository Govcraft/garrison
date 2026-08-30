//! The 1.0 audit format, frozen against a trail this repository carries.
//!
//! # Why a fixture and not a round trip
//!
//! Every other audit test writes a trail and reads it back with the same
//! code, so it passes by construction: a change to the hash pre-image, the
//! JSONL field names, or the sidecar changes both sides at once and nothing
//! notices. What an auditor is promised is stronger than that. A trail
//! written by the Garrison that recorded the work must still verify under the
//! Garrison that reads it back, years later, on a different machine.
//!
//! So the trail in `tests/fixtures/audit-1.0/` is checked in. A real daemon
//! wrote it, over a real socket, from a real turn, and nothing regenerates it
//! in CI. If a change to the entry format, the pre-image, the field order, or
//! the sidecar makes today's code disagree with it, these tests fail. That is
//! the point, and the failure is the prompt to decide whether the break is
//! deliberate and worth a format version.
//!
//! # Regenerating it
//!
//! `regenerate_the_frozen_audit_fixture` in `audit.rs`, where the daemon
//! harness lives. Only for a break that has been decided on.

use acton_ai::audit::{parse_entries, verify_chain, ChainBreakKind};

/// The trail as the daemon sealed it, byte for byte.
const FIXTURE: &str = include_str!("fixtures/audit-1.0/audit.jsonl");

/// The sidecar beside it, byte for byte, newline included.
const SIDECAR: &str = include_str!("fixtures/audit-1.0/audit.jsonl.trail");

/// The identity the fixture's entries are sealed under.
const TRAIL_ID: &str = "trail_01m180ktsgexg87mmkwgdqfjsb";

/// The hash of the fixture's last entry.
///
/// Pinned rather than recomputed. Recomputing it would make this test agree
/// with whatever the code does today, which is the failure mode the whole
/// file exists to avoid.
const HEAD_HASH: &str = "1d3a1f9c93065ca9276d4a56a99ba58452f8f39fff0572b5d2b33ab100961323";

/// How many entries the fixture holds.
const ENTRY_COUNT: usize = 4;

#[test]
fn the_frozen_trail_still_parses_and_verifies() {
    let entries = parse_entries(FIXTURE).expect("the frozen trail still parses");
    assert_eq!(
        entries.len(),
        ENTRY_COUNT,
        "the fixture is complete: a short read is a parser change, not a pass",
    );

    let head = verify_chain(&entries).expect("the frozen trail still verifies");

    assert_eq!(head.entries, ENTRY_COUNT as u64);
    assert_eq!(head.sequence, ENTRY_COUNT as u64, "sequences start at one");
    assert_eq!(
        head.hash, HEAD_HASH,
        "the head hash is frozen: a difference is a change to the hash \
         pre-image, and it strands every trail already on disk",
    );
    assert_eq!(
        head.trail_id.as_ref().map(ToString::to_string).as_deref(),
        Some(TRAIL_ID),
        "the chain is sealed under the pinned trail identity",
    );
}

#[test]
fn the_sidecar_still_names_the_trail_the_chain_is_sealed_under() {
    assert_eq!(
        SIDECAR.trim_end(),
        TRAIL_ID,
        "the sidecar format is one trail id and nothing else",
    );
    assert!(
        SIDECAR.ends_with('\n'),
        "the sidecar is newline-terminated, as `write_trail_id` writes it",
    );
}

#[test]
fn an_edited_argument_breaks_the_chain_where_it_was_edited() {
    let mut entries = parse_entries(FIXTURE).expect("the frozen trail still parses");
    let target = entries
        .get_mut(1)
        .expect("the fixture holds more than one entry");
    target.arguments = serde_json::json!({ "path": "/edited/after/the/fact" });

    let broken = verify_chain(&entries).expect_err("an edited entry must not verify");

    assert_eq!(broken.sequence, 2, "the break is reported where it is");
    assert!(
        matches!(broken.kind, ChainBreakKind::HashMismatch { .. }),
        "editing an argument is a hash mismatch, not a link or sequence \
         fault: {:?}",
        broken.kind,
    );
}

#[test]
fn dropping_the_last_entry_is_not_detectable_from_the_chain_alone() {
    let mut entries = parse_entries(FIXTURE).expect("the frozen trail still parses");
    entries.pop().expect("the fixture holds entries");

    let head = verify_chain(&entries).expect("a truncated chain is still a valid chain");

    assert_ne!(
        head.hash, HEAD_HASH,
        "the head moved, which is the only trace truncation leaves behind",
    );
    // This is why the audit has to leave the box. A prefix of a valid chain
    // verifies perfectly, so nothing on this machine can tell that the last
    // hour was deleted. Only a copy the machine cannot reach can, by holding
    // a head this one no longer matches. See `garrison_agent::shipping`.
}
