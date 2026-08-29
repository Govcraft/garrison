//! The policy bundle, and the pure functions that decide under one.
//!
//! # Why this is its own crate
//!
//! A policy bundle is authored in one place, checksummed in a second, and
//! enforced in a third. If the hook service that stamps a bundle's checksum
//! and the daemon that verifies it ran different code, every install in the
//! fleet would report drift and refuse turns — fail-closed, but fleet-wide,
//! and for no reason. So the canonical form, the argv canonicalization, the
//! rule matching, and the self-tests live here, in a crate both compile, and
//! neither end owns a private copy.
//!
//! It is deliberately pure: no async, no IO, no clock, no network. Everything
//! here can be reasoned about by reading it, which is what an auditor asking
//! "show me the rule that stopped this" is entitled to.
//!
//! # The four things it does
//!
//! - [`bundle`] — what a bundle is, deserialized from the plane's own rows.
//! - [`checksum`] — the one canonical form a bundle hashes to, so "is this
//!   machine running the policy we published" has an answer.
//! - [`argv`] — reading a shell command as the programs it will actually run,
//!   so `bash -lc "rm -rf /"` cannot launder a decision.
//! - [`decide`] — one bundle plus one tool call, in, one of three answers out,
//!   plus the self-tests that stop an unreviewable rule from being published.
//! - [`endpoints`] — which of a machine's configured providers the
//!   organization actually approved.
//!
//! # What it does not do
//!
//! It never decides whether a bundle is *trustworthy*. Freshness, the offline
//! grace period, and what happens when the control plane cannot be reached
//! are the daemon's, because they need a clock and a network. This crate only
//! answers "given this bundle, what does it say".

#![forbid(unsafe_code)]

pub mod argv;
pub mod bundle;
pub mod checksum;
pub mod decide;
pub mod endpoints;

pub use argv::{commands_of, ArgvError, Command};
pub use bundle::{
    ApprovalMode, Bundle, BundleHeader, CommandDecision, CommandRule, ModelEndpoint, NetworkEgress,
    ToolDecision, ToolRule,
};
pub use checksum::{canonical_bytes, checksum, normalize_base_url, verify, ChecksumMismatch};
pub use decide::{
    decide, name_matches, pattern_matches, self_test, validate, Context, Disposition, Expectation,
    SelfTestFailure,
};
pub use endpoints::{approved_providers, ConfiguredProvider};
