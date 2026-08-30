//! Getting the audit trail off the machine that wrote it.
//!
//! A hash chain proves that nobody edited the middle of a record. It proves
//! nothing at all about the end of one, because a prefix of a valid chain is
//! itself a valid chain: an operator who deletes the last hour and restarts
//! leaves a file that verifies perfectly. The only defence against that is a
//! copy somewhere the machine cannot reach. This module is how the copy gets
//! there.
//!
//! # The shape
//!
//! - [`cursor`] remembers how far the trail has been shipped, durably, beside
//!   the trail itself.
//! - [`reader`] reads whole entries out of a file the audit writer is still
//!   appending to.
//! - [`policy`] holds the written rule for when an unshipped backlog stops
//!   the work, as pure functions over a status and a clock.
//! - [`drain`] holds the rule for a machine that is about to be deleted, where
//!   an unshipped entry is destroyed evidence rather than delayed evidence.
//! - [`actor`] is the one thing with I/O in it: [`TrailShipper`], which polls
//!   the trail, posts entries through the shared plane component, and answers
//!   both `AdmitTurn` and `Describe`.
//!
//! # It is a gate, and that is the point
//!
//! The shipper is on the ordered `gates` vector in `launch.rs`, so a turn is
//! admitted only when the audit is still leaving the box. That is a stronger
//! claim than it sounds, so the rule is written down rather than implied:
//!
//! - An **unreachable** control plane never stops a turn on its own. The
//!   trail file is the buffer. A laptop on a train is not a governance
//!   failure, and a daemon that stopped working every time a VPN dropped
//!   would be turned off within a week.
//! - A **backlog past its bound** does stop turns, when `fail_closed`. The
//!   default bound is a day or ten thousand entries, which no ordinary outage
//!   reaches and which an install that has kept a day of evidence to itself
//!   has very much reached.
//! - A **halt** stops turns always. The plane refused an entry as forked or
//!   edited, the credential was rejected, or the local trail was rewritten
//!   under the cursor. None of those heal by waiting, and all of them are
//!   findings rather than outages.
//!
//! # Nothing here mints a token
//!
//! Every plane call goes through [`crate::plane::PlaneSession`]: the shipper
//! asks for an authenticated [`Api`](crate::plane::Api) and never builds one.
//! See that module for why that is a rule.

pub mod actor;
pub mod cursor;
pub mod drain;
pub mod policy;
pub mod reader;

pub use actor::{ShipperSettings, TrailShipper};
pub use cursor::{Cursor, ResumeFault};
pub use drain::{step as drain_step, Progress, Step};
pub use policy::{admit_turn, backoff_delay, ShippingPolicy};
pub use reader::{read_batch, Batch, ReadFault};
