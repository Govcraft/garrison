//! Seat entitlement: an install runs only while the plane says it may.
//!
//! The README claims seats are entitled. This module is what makes that a
//! property of the daemon rather than a sentence in a document: a governed
//! install asks the control plane whether the operator behind it holds an
//! active seat, and refuses every turn until the answer is yes.
//!
//! # The rule, in full
//!
//! 1. **The plane owns the facts.** Three rows decide it: `AgentInstall`
//!    (which names the operator and whether this machine is still in
//!    service), `Seat` (the entitlement itself), and `Organization` (whose
//!    `impact_level` sets how long a stale answer may be spent). Nothing in
//!    `garrison.toml` can create an entitlement, and nothing in it can
//!    lengthen one.
//! 2. **Only `active` entitles.** A seat in `assigned` is one an
//!    administrator has not turned on; the schema says "no active seat, no
//!    turns" and this reads it strictly.
//! 3. **A refusal is explained.** A revoked seat carries the reason the
//!    plane's own `@require` rule forced whoever revoked it to record, and
//!    that reason reaches the client in the error frame.
//! 4. **An unreachable plane is not a refused seat.** They arrive as
//!    different JSON-RPC codes ([`SEAT_REFUSED`] and [`PLANE_UNREACHABLE`]),
//!    because one is a decision to take to an administrator and the other is
//!    an outage to take to whoever runs the plane.
//! 5. **Grace comes from the plane, and only shortens locally.** The table in
//!    [`verdict::grace_period`] runs from 72 hours at commercial/standard to
//!    zero at `il5` and at every level this build does not recognize.
//!    `[plane] offline_grace_secs` may cap it lower; nothing may raise it.
//! 6. **A cached refusal never expires into permission.** Grace applies to a
//!    yes, never to a no.
//! 7. **A revocation reaches a turn already running.** See
//!    [`monitor::EntitlementLost`].
//!
//! # How long a revocation takes
//!
//! At most `[plane] seat_check_secs` (default 60, clamped to 15..=900) for
//! the next turn, and the same bound for a turn already in flight, which is
//! ended rather than allowed to finish.
//!
//! # Shape
//!
//! - [`verdict`] is the whole rule, pure, over rows and a clock.
//! - [`fetch`] reads the three rows through the daemon's one authenticated
//!   path ([`crate::plane`]).
//! - [`store`] keeps the last verdict so a restart during an outage inherits
//!   the grace window rather than starting from nothing.
//! - [`monitor`] is the actor: it polls, it answers
//!   [`AdmitTurn`](crate::admission::AdmitTurn) as a gate, it answers
//!   [`Describe`](crate::protocol::conn::Describe) for `_garrison/status`,
//!   and it broadcasts when entitlement is lost.
//!
//! [`SEAT_REFUSED`]: crate::protocol::jsonrpc::error_code::SEAT_REFUSED
//! [`PLANE_UNREACHABLE`]: crate::protocol::jsonrpc::error_code::PLANE_UNREACHABLE

pub mod fetch;
pub mod monitor;
pub mod store;
pub mod verdict;

pub use monitor::{CheckNow, EntitlementLost, MonitorSettings, SeatMonitor};
pub use store::{standing_path, STANDING_FILE};
pub use verdict::{
    adjudicate, admit, grace_period, ImpactLevel, Refusal, SeatAdmission, Standing, Tier, Verdict,
};

use std::time::Duration;

use acton_reactive::prelude::*;

use crate::config::PlaneConfig;

/// How long the first seat check may hold the daemon's start.
///
/// The first check runs before the listener accepts anything, so an editor
/// that autostarts the daemon and prompts immediately is answered from a real
/// verdict rather than from "never checked". A plane that is down must not
/// turn that into a hung start, so the wait is bounded and a timeout is a
/// warning: the check keeps running, and the gate refuses until it lands.
const FIRST_CHECK_DEADLINE: Duration = Duration::from_secs(10);

/// Brings the seat monitor up on a governed install.
///
/// Returns `None` on a standalone agent — no `[plane]` section, or an install
/// that has not enrolled — which has no organization to hold a seat in and
/// therefore no entitlement to check. That is the developer install, and it
/// behaves exactly as it did before this module existed.
///
/// The first check is awaited, so `build_setup` returns with the daemon
/// already knowing whether it holds a seat. It is bounded by
/// [`FIRST_CHECK_DEADLINE`]; a plane that does not answer in that time costs a
/// warning and the first turns, not the start.
pub async fn spawn(
    runtime: &mut ActorRuntime,
    config: Option<&PlaneConfig>,
    plane: Option<&ActorHandle>,
) -> Option<ActorHandle> {
    let (config, plane) = config.zip(plane)?;

    let monitor = SeatMonitor::spawn(
        runtime,
        MonitorSettings {
            plane: plane.clone(),
            plane_url: config.url.clone(),
            interval: config.seat_check_interval(),
            grace_cap: config.offline_grace_cap(),
            cache: standing_path(&crate::enrollment::config_dir()),
        },
    )
    .await;

    match monitor
        .ask_with_timeout(CheckNow, FIRST_CHECK_DEADLINE)
        .await
    {
        Ok(status) => tracing::info!(
            state = %status.state,
            interval_secs = status.check_interval_secs,
            "the seat check is running"
        ),
        Err(error) => tracing::warn!(
            ?error,
            deadline_secs = FIRST_CHECK_DEADLINE.as_secs(),
            "the first seat check did not finish before the daemon came up; turns are refused \
             until it does"
        ),
    }

    Some(monitor)
}
