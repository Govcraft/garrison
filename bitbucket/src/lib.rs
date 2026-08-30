//! Bitbucket Data Center, as much of it as a governed review needs.
//!
//! # Scope, and why it is this narrow
//!
//! A pipeline that reviews a pull request needs three things from Bitbucket
//! and nothing else: the diff to read, somewhere to put what it found, and a
//! way to tell the pull request whether the run succeeded. So this crate is
//! three calls — [`Client::pull_request_diff`], [`Client::post_comment`], and
//! [`Client::set_build_status`] — and the types they need.
//!
//! Data Center rather than Cloud. The two are different products with
//! different REST surfaces and different auth: DC is `/rest/api/1.0` under a
//! host an agency runs, Cloud is `api.bitbucket.org/2.0` with OAuth. The
//! on-premises posture Garrison is built for is DC's, and picking one first
//! is what keeps the client honest rather than lowest-common-denominator.
//!
//! # What is a pure function here, and why that matters
//!
//! Everything that interprets bytes is pure and tested against recorded
//! responses: [`parse_diff`], [`parse_error`], [`Anchor::for_line`]. The
//! [`Client`] only moves them. That split is the same one
//! `hooks-service/src/directory/graph.rs` makes, for the same reason — it
//! lets this module state precisely what it has proved.
//!
//! What is proved: the parsers turn each response shape into the right
//! decision, and the transport sends the method, path, query, headers and
//! body this crate believes DC wants, over a real socket to a real HTTP
//! listener (see `tests/transport.rs`).
//!
//! What is **not** proved: that Bitbucket DC agrees with any of it. Standing
//! a real one up was tried and does not work — a fresh container reaches
//! `FIRST_RUN` and its setup wizard demands a licence key from
//! my.atlassian.com before it will create so much as an admin account, so
//! there is no hermetic path to an authenticated REST call. Every expectation
//! here is therefore this crate's *model* of DC 10, taken from Atlassian's
//! published reference. A contract test catches a client that drifts from its
//! own model; it cannot catch a model that was wrong from the start.
//!
//! One thing was checked against a running instance: the unauthenticated
//! error envelope and version string in `error.rs`, recorded from
//! `atlassian/bitbucket:10` reporting `10.4.2`. Everything else is waiting on
//! the first licensed instance Garrison is pointed at, and `tests/transport.rs`
//! is the list to check when that happens.

#![forbid(unsafe_code)]

mod client;
mod diff;
mod error;
mod model;

pub use client::{Client, Credentials};
pub use diff::{parse_diff, Anchor, ChangedFile, Hunk};
pub use error::{parse_error, BitbucketError};
pub use model::{BuildState, BuildStatus, Comment, PullRequest, Severity};
