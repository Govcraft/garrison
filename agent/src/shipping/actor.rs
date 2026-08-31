//! The actor that walks the trail forward and posts it to the plane.
//!
//! # One batch in flight, ever
//!
//! Entries go up in chain order, one at a time, and only one batch is in
//! flight at once. That is not a performance choice; it is what makes the
//! plane's `AuditChain` a single-writer structure. Two concurrent posts of
//! sequences 8 and 9 would race the hook's read-then-patch of the chain head
//! and produce a gap finding out of a healthy trail. The mailbox provides the
//! serialization: a `Tick` that arrives while `in_flight` is set does
//! nothing, and the batch that is running self-sends a `Tick` when it
//! finishes so a backlog drains without waiting for the poll interval.
//!
//! # It subscribes to turn end; nothing sends it a nudge
//!
//! Entries are worth shipping promptly, and the moment worth shipping at is
//! the end of a turn. The shipper learns that from acton-ai's
//! [`TurnLifecycle`] broadcast, exactly as the anchor keeper does, rather
//! than from a message `thread.rs` sends it. One definition of "finished",
//! published once, any number of subscribers, and the turn path is not edited
//! by every subsystem that wants to hear about it.
//!
//! # A halt is a verdict, not an error
//!
//! Three things stop the shipper for good: the plane refusing an entry as
//! forked or edited, the credential being refused, and the local trail having
//! been rewritten under the cursor. All three mean the copy the plane holds
//! and the file on this machine have stopped being the same record. Retrying
//! would either fork the plane's chain or hammer a control plane that has
//! already decided. So the shipper stops, says why in `_garrison/status`, and
//! refuses turns until a human has looked.

use crate::admission::AdmitTurn;
use crate::plane::api::{eq, Api, PlaneError};
use crate::plane::session::{Authenticate, RevokeBearer};
use crate::protocol::acp::{ShipState, ShippingStatus};
use crate::protocol::conn::{Describe, StatusPart};
use crate::shipping::cursor::{self, Cursor, ResumeFault};
use crate::shipping::policy::{self, ShippingPolicy};
use crate::shipping::reader::{self, ReadFault};
use acton_ai::audit::AuditEntry;
use acton_ai::facade::ActonAI;
use acton_ai::messages::TurnLifecycle;
use acton_reactive::prelude::*;
use chrono::{DateTime, SecondsFormat, Utc};
use garrison_wire::audit::{project, ProjectionContext, INGEST_UNAVAILABLE};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

/// The plane schema holding one row per trail.
const TRAIL_SCHEMA: &str = "AuditTrail";

/// The plane schema holding one row per shipped entry.
const EVENT_SCHEMA: &str = "AuditEvent";

/// Everything the shipper is given at launch and never changes.
#[derive(Clone, Debug)]
pub struct ShipperSettings {
    /// The acton-ai runtime, asked for the trail's head and nothing else.
    pub runtime: ActonAI,
    /// The credential holder. Every plane call starts with an ask to this.
    pub plane: ActorHandle,
    /// The trail file, canonicalized.
    pub trail_path: PathBuf,
    /// Where this shipper's cursor is persisted.
    pub cursor_path: PathBuf,
    /// The trail's identity as acton-ai settled it.
    pub trail_id: String,
    /// Whether this daemon's writing tools run in the process sandbox, which
    /// the projection reports per entry.
    pub sandbox_enabled: bool,
    /// This binary's version, recorded on the trail row.
    pub agent_version: String,
    /// The version of the crate that sealed the entries.
    pub acton_ai_version: String,
    /// The terms shipping runs under.
    pub policy: ShippingPolicy,
}

/// Run one batch now.
#[acton_message]
pub struct Tick;

/// What one batch came to. Delivered by the batch's own future to the
/// shipper's mailbox, which is where it becomes model state.
#[acton_message]
pub struct BatchReport {
    /// Where the cursor stands now.
    cursor: Cursor,
    /// How many entries the plane accepted this time.
    shipped: u64,
    /// Whether there is more on disk to ship straight away.
    more: bool,
    /// What stopped the batch, when something did.
    fault: Option<BatchFault>,
    /// The trail's head, when the writer could be asked.
    local_head: Option<u64>,
    /// That head's hash.
    local_head_hash: Option<String>,
    /// When the oldest still-unshipped entry was written.
    oldest_unshipped_at: Option<String>,
    /// Whether the trail row was reported to the plane this time.
    reported: bool,
}

/// Why a batch stopped early.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BatchFault {
    /// Try again after a delay: the plane, or the ingest behind it, is not
    /// answering right now.
    Transient(String),
    /// The bearer was refused. Re-exchanged once already; the next batch
    /// starts with a fresh one.
    Unauthorized(String),
    /// Stop until a human has looked.
    Halt(String),
}

impl BatchFault {
    /// What an operator reads.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Transient(why) | Self::Unauthorized(why) | Self::Halt(why) => why,
        }
    }

    /// Whether this ends shipping rather than delaying it.
    #[must_use]
    pub const fn is_halt(&self) -> bool {
        matches!(self, Self::Halt(_))
    }
}

/// What the plane's answer to one `AuditEvent` create means.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreateVerdict {
    /// The plane already holds this entry. An acknowledgement, not a failure:
    /// the unique index on `entry_hash` is what answers a replay, and a
    /// shipper that re-sent an entry after a crash must be able to move on.
    AlreadyRecorded,
    /// The bearer was refused; re-exchange and try the same entry again.
    Unauthorized,
    /// The plane could not take it right now.
    Transient(String),
    /// The plane refused it on the merits.
    Halt(String),
}

/// What one refusal from the plane means for shipping. Pure.
///
/// The two cases worth separating are a plane that cannot answer and a plane
/// that has answered no, because the remedies are opposite: wait, or fetch a
/// human. Everything a hook says arrives as one status, so the hook's own
/// [`INGEST_UNAVAILABLE`] sentence is what distinguishes "I could not look
/// your entry up" from "I do not believe your entry".
#[must_use]
pub fn verdict_for(error: &PlaneError) -> CreateVerdict {
    match error {
        PlaneError::Unreachable(why) => CreateVerdict::Transient(why.clone()),
        // A 404 on a create route is a plane mid-deploy or a schema not yet
        // applied. Waiting is right, and the backlog bound is what stops this
        // from being silent forever.
        PlaneError::NotFound(what) => CreateVerdict::Transient(format!("no such route: {what}")),
        PlaneError::Malformed(what) => CreateVerdict::Transient(what.clone()),
        PlaneError::Rejected { status, message } => rejection_verdict(*status, message),
    }
}

/// The verdict for a status the plane actually chose. Pure.
///
/// A halt is permanent and costs a human, so it is reserved for statuses that
/// mean the plane looked at the entry and said no. A plane that is throttling
/// or falling over has not looked at anything yet, and treating either as a
/// verdict would stop an install's work over a load spike.
fn rejection_verdict(status: u16, message: &str) -> CreateVerdict {
    if message.contains(INGEST_UNAVAILABLE) {
        return CreateVerdict::Transient(format!("{status}: {message}"));
    }
    match status {
        409 => CreateVerdict::AlreadyRecorded,
        401 => CreateVerdict::Unauthorized,
        429 | 500..=599 => CreateVerdict::Transient(format!("{status}: {message}")),
        _ => CreateVerdict::Halt(format!("{status}: {message}")),
    }
}

/// Where shipping stands after a batch. Pure.
#[must_use]
pub fn state_after(fault: Option<&BatchFault>, backlog: u64) -> ShipState {
    match fault {
        Some(fault) if fault.is_halt() => ShipState::Halted,
        Some(_) => ShipState::Backoff,
        None if backlog > 0 => ShipState::Behind,
        None => ShipState::Current,
    }
}

/// The shipper.
///
/// `settings` is `None` on a governed install that turned shipping off, and
/// in the `Default` value the actor macro requires. Such a shipper describes
/// itself as disabled and admits every turn, which is a plainer answer than
/// an absent status field.
#[acton_actor]
pub struct TrailShipper {
    settings: Option<Arc<ShipperSettings>>,
    cursor: Cursor,
    state: ShipState,
    in_flight: bool,
    /// Whether the next batch must prove the file still follows the cursor.
    check_successor: bool,
    failures: u32,
    retry_at: Option<DateTime<Utc>>,
    local_head: u64,
    local_head_hash: Option<String>,
    oldest_unshipped_at: Option<String>,
    last_shipped_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    halted_reason: Option<String>,
    reported_at: Option<DateTime<Utc>>,
    schedule: Option<ScheduledSend>,
}

impl TrailShipper {
    /// Spawns a shipper that ships nothing and says so.
    ///
    /// For a governed install with `[plane.shipping] enabled = false`. It
    /// still joins the describers, because "this install does not send its
    /// audit anywhere" is an answer an auditor needs and an absent field is
    /// not one.
    pub async fn spawn_disabled(runtime: &mut ActorRuntime) -> ActorHandle {
        let mut builder = runtime.new_actor_with_name::<Self>("trail_shipper".to_string());
        configure(&mut builder);
        builder.start().await
    }

    /// Spawns a shipper for one trail, resuming where the last run stopped.
    ///
    /// A cursor that cannot be resumed does not stop the daemon: it starts
    /// halted with the fault as its reason, so an operator asking
    /// `_garrison/status` finds out why turns are being refused instead of
    /// finding a process that would not come up.
    pub async fn spawn(runtime: &mut ActorRuntime, settings: ShipperSettings) -> ActorHandle {
        let mut builder = runtime.new_actor_with_name::<Self>("trail_shipper".to_string());
        let resumed = resume(&settings);

        match resumed {
            Ok(cursor) => {
                builder.model.cursor = cursor;
                builder.model.state = ShipState::Behind;
            }
            Err(fault) => {
                tracing::error!(
                    trail = %settings.trail_path.display(),
                    "audit shipping cannot resume: {fault}",
                );
                builder.model.cursor = Cursor::genesis(&settings.trail_id);
                builder.model.state = ShipState::Halted;
                builder.model.halted_reason = Some(fault.to_string());
            }
        }
        builder.model.check_successor = true;
        builder.model.settings = Some(Arc::new(settings.clone()));
        configure(&mut builder);

        // Before `start`: a subscription registered afterwards is silently
        // ignored, which would leave a shipper that polls but never reacts to
        // a finished turn.
        builder.handle().subscribe::<TurnLifecycle>().await;

        let handle = builder.start().await;
        if let Some(every) = Interval::new(settings.policy.poll_interval) {
            let schedule = handle.send_every(Tick, every, Cadence::FixedDelay);
            handle.send(HoldSchedule(schedule)).await;
        }
        handle.send(Tick).await;
        handle
    }
}

/// Hands the shipper the schedule to keep alive.
///
/// A `ScheduledSend` stops when it is dropped, and `send_every` can only be
/// called on the started handle, so the value has to travel back into the
/// model rather than being parked before `start`.
#[acton_message]
struct HoldSchedule(ScheduledSend);

/// The cursor to start from, given what is on disk.
///
/// # Errors
///
/// [`ResumeFault`] when the trail is shorter than the cursor that was
/// persisted for it, or when the cursor file is unreadable.
fn resume(settings: &ShipperSettings) -> Result<Cursor, ResumeFault> {
    let stored =
        cursor::read(&settings.cursor_path).map_err(|error| ResumeFault::RewrittenUnderCursor {
            reason: error.to_string(),
        })?;
    let file_len = std::fs::metadata(&settings.trail_path)
        .map(|meta| meta.len())
        .unwrap_or(0);
    Cursor::resume(stored, &settings.trail_id, file_len)
}

/// Wires the handlers.
#[allow(clippy::cognitive_complexity)]
fn configure(builder: &mut ManagedActor<Idle, TrailShipper>) {
    let self_handle = builder.handle().clone();

    builder.mutate_on::<HoldSchedule>(|actor, envelope| {
        actor.model.schedule = Some(envelope.message().0.clone());
        Reply::ready()
    });

    // A finished turn is the moment new entries exist. Ship them now rather
    // than at the next poll, so the window in which evidence exists only on
    // this machine is one turn wide.
    let handle = self_handle.clone();
    builder.act_on::<TurnLifecycle>(move |_, envelope| {
        if !matches!(envelope.message(), TurnLifecycle::TurnFinished { .. }) {
            return Reply::ready();
        }
        let handle = handle.clone();
        Reply::pending(async move { handle.send(Tick).await })
    });

    let handle = self_handle;
    builder.mutate_on::<Tick>(move |actor, _| {
        let now = Utc::now();
        let Some(settings) = actor.model.settings.clone() else {
            return Reply::ready();
        };
        if actor.model.in_flight
            || actor.model.state == ShipState::Halted
            || actor.model.retry_at.is_some_and(|at| at > now)
        {
            return Reply::ready();
        }

        actor.model.in_flight = true;
        let cursor = actor.model.cursor.clone();
        let check_successor = actor.model.check_successor;
        let due_report = actor.model.reported_at.is_none_or(|at| {
            now.signed_duration_since(at)
                .to_std()
                .is_ok_and(|since| since >= settings.policy.report_interval)
        });
        let handle = handle.clone();

        Reply::pending(async move {
            let report = ship_one_batch(&settings, cursor, check_successor, due_report).await;
            handle.send(report).await;
        })
    });

    builder.mutate_on::<BatchReport>(|actor, envelope| {
        let report = envelope.message();
        let now = Utc::now();
        actor.model.in_flight = false;
        actor.model.cursor = report.cursor.clone();
        if report.shipped > 0 {
            actor.model.last_shipped_at = Some(now);
        }
        if report.fault.is_none() {
            actor.model.check_successor = false;
        }
        if let Some(head) = report.local_head {
            actor.model.local_head = head.max(report.cursor.sequence);
        }
        if report.local_head_hash.is_some() {
            actor
                .model
                .local_head_hash
                .clone_from(&report.local_head_hash);
        }
        if report.reported {
            actor.model.reported_at = Some(now);
        }
        actor
            .model
            .oldest_unshipped_at
            .clone_from(&report.oldest_unshipped_at);

        let backlog = actor
            .model
            .local_head
            .saturating_sub(report.cursor.sequence);
        actor.model.state = state_after(report.fault.as_ref(), backlog);

        match report.fault.as_ref() {
            None => {
                actor.model.failures = 0;
                actor.model.retry_at = None;
                actor.model.last_error = None;
            }
            Some(fault) if fault.is_halt() => {
                actor.model.halted_reason = Some(fault.reason().to_string());
                actor.model.last_error = Some(fault.reason().to_string());
                tracing::error!(
                    target: "garrison.audit.shipping",
                    reason = fault.reason(),
                    "audit shipping has halted; turns will be refused until a human looks",
                );
            }
            Some(fault) => {
                actor.model.failures = actor.model.failures.saturating_add(1);
                actor.model.last_error = Some(fault.reason().to_string());
                let delay = policy::backoff_delay(
                    actor.model.failures,
                    actor.model.settings.as_ref().map_or_else(
                        || ShippingPolicy::default().backoff_base,
                        |settings| settings.policy.backoff_base,
                    ),
                    actor.model.settings.as_ref().map_or_else(
                        || ShippingPolicy::default().backoff_ceiling,
                        |settings| settings.policy.backoff_ceiling,
                    ),
                    jitter(),
                );
                actor.model.retry_at = chrono::Duration::from_std(delay).ok().map(|d| now + d);
                tracing::warn!(
                    target: "garrison.audit.shipping",
                    reason = fault.reason(),
                    retry_in_secs = delay.as_secs(),
                    "audit shipping is behind",
                );
            }
        }

        // Catch up without waiting for the next poll.
        let catch_up = report.more && report.fault.is_none();
        let handle = actor.handle().clone();
        Reply::pending(async move {
            if catch_up {
                handle.send(Tick).await;
            }
        })
    });

    builder.act_on::<AdmitTurn>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let status = actor.model.status();
        let policy = actor
            .model
            .settings
            .as_ref()
            .map_or_else(ShippingPolicy::default, |settings| settings.policy);
        let admission = policy::admit_turn(&status, &policy, Utc::now());
        Reply::pending(async move {
            reply.send(admission).await;
        })
    });

    builder.act_on::<Describe>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let part = StatusPart::Shipping(actor.model.status());
        Reply::pending(async move {
            reply.send(part).await;
        })
    });
}

/// A fraction in `[0, 1)` for backoff jitter.
///
/// Derived from the wall clock's sub-second part rather than a random-number
/// dependency: the property that matters is that two daemons which lost the
/// plane at the same instant do not come back at the same instant, and
/// nanoseconds-since-the-second already differ between processes.
fn jitter() -> f64 {
    f64::from(Utc::now().timestamp_subsec_nanos()) / 1_000_000_000.0
}

impl TrailShipper {
    /// What this shipper reports to `_garrison/status` and to its own gate.
    fn status(&self) -> ShippingStatus {
        let Some(settings) = self.settings.as_ref() else {
            return ShippingStatus::disabled();
        };
        ShippingStatus {
            enabled: true,
            state: self.state,
            trail_id: Some(settings.trail_id.clone()),
            trail: self.cursor.trail_row.clone(),
            shipped_through: self.cursor.sequence,
            local_head: self.local_head.max(self.cursor.sequence),
            backlog: self.local_head.saturating_sub(self.cursor.sequence),
            oldest_unshipped_at: self.oldest_unshipped_at.clone(),
            last_shipped_at: self.last_shipped_at.map(stamp),
            last_error: self.last_error.clone(),
            halted_reason: self.halted_reason.clone(),
            retry_at: self.retry_at.map(stamp),
        }
    }
}

/// An instant as the wire spells it.
fn stamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

// =============================================================================
// The batch itself
// =============================================================================

/// Ships up to one batch of entries, then reports what happened.
///
/// Free of the actor, so what it does is readable as a sequence of calls: get
/// a bearer, make sure the trail row exists, post entries in order, then say
/// where the local head is. Every failure becomes a [`BatchFault`] on the
/// report rather than an error, because a shipper that returned `Err` would
/// have no way to persist how far it did get.
async fn ship_one_batch(
    settings: &ShipperSettings,
    mut cursor: Cursor,
    check_successor: bool,
    due_report: bool,
) -> BatchReport {
    let batch = match reader::read_batch(
        &settings.trail_path,
        cursor.byte_offset,
        settings.policy.batch,
    ) {
        Ok(batch) => batch,
        Err(ReadFault::Malformed(line)) => {
            return halted(cursor, line.to_string());
        }
        Err(ReadFault::Io(error)) => {
            return faulted(cursor, BatchFault::Transient(error.to_string()));
        }
    };

    if check_successor {
        if let Some(first) = batch.lines.first() {
            if let Err(fault) = cursor.check_successor(&first.entry) {
                return halted(cursor, fault.to_string());
            }
        }
    }

    if batch.is_empty() {
        // Nothing to send, but the plane still wants to hear that this trail
        // is alive; silence is the thing the sweep is looking for.
        let mut report = finish(settings, cursor, 0, false, None, due_report).await;
        report.more = false;
        return report;
    }

    let session = match settings.plane.ask(Authenticate).await {
        Ok(Ok(session)) => session,
        Ok(Err(error)) => return faulted(cursor, plane_fault(&error)),
        Err(error) => {
            return faulted(
                cursor,
                BatchFault::Transient(format!("the credential holder did not answer: {error:?}")),
            )
        }
    };

    let trail_row = match ensure_trail_row(
        &session.api,
        settings,
        &cursor,
        &session.organization,
        &session.install,
    )
    .await
    {
        Ok(id) => id,
        Err(error) => return faulted(cursor, plane_fault(&error)),
    };
    cursor.trail_row = Some(trail_row.clone());

    let context = ProjectionContext {
        organization: session.organization.clone(),
        install: session.install.clone(),
        trail: trail_row,
        sandbox_enabled: settings.sandbox_enabled,
    };

    let mut shipped = 0_u64;
    let total = batch.lines.len();
    for (index, line) in batch.lines.iter().enumerate() {
        match post_entry(&session.api, settings, &context, &line.entry).await {
            Ok(()) => {
                cursor.advance(&line.entry, line.end_offset);
                persist(settings, &cursor);
                shipped += 1;
            }
            Err(fault) => {
                let more = index < total;
                let mut report =
                    finish(settings, cursor, shipped, more, Some(fault), due_report).await;
                report.more = more;
                return report;
            }
        }
    }

    let more = total >= settings.policy.batch || batch.partial_tail;
    finish(settings, cursor, shipped, more, None, due_report).await
}

/// Posts one entry, re-exchanging the bearer once if it was refused.
async fn post_entry(
    api: &Api,
    settings: &ShipperSettings,
    context: &ProjectionContext,
    entry: &AuditEntry,
) -> Result<(), BatchFault> {
    let fields = project(entry, context);
    match api.create(EVENT_SCHEMA, &fields).await {
        Ok(_) => return Ok(()),
        Err(error) => match verdict_for(&error) {
            CreateVerdict::AlreadyRecorded => {
                tracing::debug!(
                    sequence = entry.sequence,
                    "the control plane already holds this entry; treating it as acknowledged",
                );
                return Ok(());
            }
            CreateVerdict::Unauthorized => {
                settings.plane.send(RevokeBearer).await;
            }
            CreateVerdict::Transient(why) => return Err(BatchFault::Transient(why)),
            CreateVerdict::Halt(why) => return Err(BatchFault::Halt(why)),
        },
    }

    // One retry with a fresh bearer. A second 401 is a credential the plane
    // no longer accepts, which the backlog bound escalates on its own; it is
    // not a halt, because an expiry race and a revocation look identical from
    // here and only one of them deserves a security officer.
    let session = match settings.plane.ask(Authenticate).await {
        Ok(Ok(session)) => session,
        Ok(Err(error)) => return Err(plane_fault(&error)),
        Err(error) => {
            return Err(BatchFault::Transient(format!(
                "the credential holder did not answer: {error:?}"
            )))
        }
    };
    match session.api.create(EVENT_SCHEMA, &fields).await {
        Ok(_) => Ok(()),
        Err(error) => match verdict_for(&error) {
            CreateVerdict::AlreadyRecorded => Ok(()),
            CreateVerdict::Unauthorized => Err(BatchFault::Unauthorized(
                "the control plane refused this install's bearer twice".to_string(),
            )),
            CreateVerdict::Transient(why) => Err(BatchFault::Transient(why)),
            CreateVerdict::Halt(why) => Err(BatchFault::Halt(why)),
        },
    }
}

/// The `AuditTrail` row for this trail, creating it once if needed.
///
/// `trail_id` is unique per tenant, so a create that loses a race answers 409
/// and the row is read back rather than retried. A second daemon reaching
/// here for the same trail id would be a second writer of one chain, which
/// acton-ai's trail lock already prevents; this only has to be correct when
/// the same daemon restarts.
async fn ensure_trail_row(
    api: &Api,
    settings: &ShipperSettings,
    cursor: &Cursor,
    organization: &str,
    install: &str,
) -> Result<String, PlaneError> {
    if let Some(row) = cursor.trail_row.as_ref() {
        return Ok(row.clone());
    }
    if let Some(row) = find_trail_row(api, &settings.trail_id).await? {
        return Ok(row);
    }

    let fields = json!({
        "trail_id": settings.trail_id,
        "install": install,
        "organization": organization,
        "agent_version": settings.agent_version,
        "acton_ai_version": settings.acton_ai_version,
        "started_at": stamp(Utc::now()),
        "local_head_seq": 0,
        "shipped_through": 0,
        "reported_at": stamp(Utc::now()),
    });
    match api.create(TRAIL_SCHEMA, &fields).await {
        Ok(id) => Ok(id),
        Err(PlaneError::Rejected { status: 409, .. }) => find_trail_row(api, &settings.trail_id)
            .await?
            .ok_or_else(|| {
                PlaneError::Malformed(
                    "the control plane refused a duplicate trail and then had no trail".to_string(),
                )
            }),
        Err(error) => Err(error),
    }
}

/// One row's id, by the trail's identity.
async fn find_trail_row(api: &Api, trail_id: &str) -> Result<Option<String>, PlaneError> {
    #[derive(serde::Deserialize)]
    struct Row {
        id: String,
    }
    let rows: Vec<Row> = api
        .query(TRAIL_SCHEMA, &eq("trail_id", trail_id, 2))
        .await?;
    Ok(rows.into_iter().next().map(|row| row.id))
}

/// Reads the local head, reports the trail row when due, and assembles the
/// batch's report.
async fn finish(
    settings: &ShipperSettings,
    cursor: Cursor,
    shipped: u64,
    more: bool,
    fault: Option<BatchFault>,
    due_report: bool,
) -> BatchReport {
    let head = settings.runtime.audit_head().await.ok();
    let oldest = oldest_unshipped(settings, &cursor);

    let reported = if due_report || fault.as_ref().is_some_and(BatchFault::is_halt) {
        report_trail(settings, &cursor, head.as_ref(), fault.as_ref()).await
    } else {
        false
    };

    BatchReport {
        cursor,
        shipped,
        more,
        fault,
        local_head: head.as_ref().map(|head| head.sequence),
        local_head_hash: head.as_ref().map(|head| head.hash.clone()),
        oldest_unshipped_at: oldest,
        reported,
    }
}

/// When the oldest entry the plane has not seen was written.
///
/// One line read past the cursor, which is what the backlog's age is measured
/// from. A trail that cannot be read here reports nothing rather than
/// pretending the backlog is fresh.
fn oldest_unshipped(settings: &ShipperSettings, cursor: &Cursor) -> Option<String> {
    reader::read_batch(&settings.trail_path, cursor.byte_offset, 1)
        .ok()?
        .lines
        .first()
        .map(|line| line.entry.timestamp.clone())
}

/// Tells the plane where this daemon says its trail stands.
///
/// Best effort, and deliberately so: the trail row is the install's claim,
/// and failing to file a claim must never cost an entry. Returns whether the
/// report landed, which is what paces the next one.
async fn report_trail(
    settings: &ShipperSettings,
    cursor: &Cursor,
    head: Option<&acton_ai::audit::ChainHead>,
    fault: Option<&BatchFault>,
) -> bool {
    let Some(row) = cursor.trail_row.as_ref() else {
        return false;
    };
    let Ok(Ok(session)) = settings.plane.ask(Authenticate).await else {
        return false;
    };

    let mut fields = json!({
        "shipped_through": cursor.sequence,
        "reported_at": stamp(Utc::now()),
        "halted_reason": fault.filter(|fault| fault.is_halt()).map_or("", BatchFault::reason),
    });
    if let Some(head) = head {
        fields["local_head_seq"] = json!(head.sequence);
        fields["local_head_hash"] = json!(head.hash);
    }

    match session.api.patch(TRAIL_SCHEMA, row, &fields).await {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!(%error, "the trail's own report did not reach the control plane");
            false
        }
    }
}

/// Writes the cursor, complaining loudly if it cannot.
///
/// A cursor that stops advancing on disk means a restart re-ships entries the
/// plane already holds, which costs 409s and nothing else. Worth a log line,
/// not worth stopping for.
fn persist(settings: &ShipperSettings, cursor: &Cursor) {
    if let Err(error) = cursor::write(&settings.cursor_path, cursor) {
        tracing::error!(
            path = %settings.cursor_path.display(),
            %error,
            "the audit shipping cursor could not be written; a restart will re-ship entries the \
             control plane already holds and answer them with 409s",
        );
    }
}

/// A plane error as a batch fault.
fn plane_fault(error: &PlaneError) -> BatchFault {
    match verdict_for(error) {
        CreateVerdict::Halt(why) => BatchFault::Halt(why),
        CreateVerdict::Unauthorized => BatchFault::Unauthorized(error.to_string()),
        CreateVerdict::AlreadyRecorded | CreateVerdict::Transient(_) => {
            BatchFault::Transient(error.to_string())
        }
    }
}

/// A report for a batch that stopped before it reached the plane.
fn faulted(cursor: Cursor, fault: BatchFault) -> BatchReport {
    BatchReport {
        cursor,
        shipped: 0,
        more: true,
        fault: Some(fault),
        local_head: None,
        local_head_hash: None,
        oldest_unshipped_at: None,
        reported: false,
    }
}

/// A report for a batch that found a reason to stop for good.
fn halted(cursor: Cursor, reason: String) -> BatchReport {
    faulted(cursor, BatchFault::Halt(reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::Admission;

    #[test]
    fn a_duplicate_entry_is_an_acknowledgement_not_a_failure() {
        let error = PlaneError::Rejected {
            status: 409,
            message: "unique_violation on entry_hash".to_string(),
        };

        assert_eq!(verdict_for(&error), CreateVerdict::AlreadyRecorded);
    }

    #[test]
    fn an_unreachable_plane_is_transient_so_the_trail_file_stays_the_buffer() {
        let error = PlaneError::Unreachable("connection refused".to_string());

        assert!(matches!(verdict_for(&error), CreateVerdict::Transient(_)));
    }

    #[test]
    fn a_five_hundred_reaches_here_as_unreachable_and_stays_transient() {
        let error = PlaneError::Unreachable("503: hook_unavailable".to_string());

        assert!(matches!(verdict_for(&error), CreateVerdict::Transient(_)));
    }

    #[test]
    fn an_ingest_that_could_not_look_the_entry_up_is_waited_out_not_halted_on() {
        let error = PlaneError::Rejected {
            status: 422,
            message: format!("hook_aborted: {INGEST_UNAVAILABLE}: connection refused"),
        };

        assert!(
            matches!(verdict_for(&error), CreateVerdict::Transient(_)),
            "a hook that could not reach the plane has not judged the entry"
        );
    }

    #[test]
    fn an_entry_the_plane_refused_on_the_merits_halts_shipping() {
        let error = PlaneError::Rejected {
            status: 422,
            message: "hook_aborted: chain broken at sequence 7: HashMismatch".to_string(),
        };

        let CreateVerdict::Halt(reason) = verdict_for(&error) else {
            panic!("a refused entry must halt");
        };
        assert!(reason.contains("HashMismatch"), "{reason}");
    }

    #[test]
    fn a_refused_credential_halts_because_it_is_a_decision_somebody_made() {
        let error = PlaneError::Rejected {
            status: 403,
            message: "credential revoked".to_string(),
        };

        assert!(matches!(verdict_for(&error), CreateVerdict::Halt(_)));
    }

    #[test]
    fn a_throttled_or_failing_plane_is_waited_out_rather_than_halted_on() {
        // Neither status is a verdict on the entry: the plane has not looked
        // at it yet. Halting here would stop an install's work over a load
        // spike, and the backlog bound is what keeps the wait from being
        // forever.
        for status in [429, 500, 502, 503] {
            let error = PlaneError::Rejected {
                status,
                message: "Too many requests".to_string(),
            };

            assert!(
                matches!(verdict_for(&error), CreateVerdict::Transient(_)),
                "status {status} must be waited out"
            );
        }
    }

    #[test]
    fn a_spent_bearer_is_re_exchanged_rather_than_halted_on() {
        let error = PlaneError::Rejected {
            status: 401,
            message: "token expired".to_string(),
        };

        assert_eq!(verdict_for(&error), CreateVerdict::Unauthorized);
    }

    #[test]
    fn a_missing_route_is_waited_out_because_a_plane_mid_deploy_is_not_a_finding() {
        let error = PlaneError::NotFound("AuditEvent".to_string());

        assert!(matches!(verdict_for(&error), CreateVerdict::Transient(_)));
    }

    #[test]
    fn a_clean_batch_with_nothing_left_is_current() {
        assert_eq!(state_after(None, 0), ShipState::Current);
    }

    #[test]
    fn a_clean_batch_with_more_to_send_is_behind() {
        assert_eq!(state_after(None, 12), ShipState::Behind);
    }

    #[test]
    fn a_transient_fault_backs_off_rather_than_halting() {
        let fault = BatchFault::Transient("503".to_string());

        assert_eq!(state_after(Some(&fault), 3), ShipState::Backoff);
    }

    #[test]
    fn a_refused_bearer_backs_off_rather_than_halting() {
        let fault = BatchFault::Unauthorized("401 twice".to_string());

        assert_eq!(state_after(Some(&fault), 3), ShipState::Backoff);
    }

    #[test]
    fn a_halt_is_a_halt_whatever_the_backlog_is() {
        let fault = BatchFault::Halt("forked".to_string());

        assert_eq!(state_after(Some(&fault), 0), ShipState::Halted);
        assert_eq!(state_after(Some(&fault), 900), ShipState::Halted);
    }

    #[test]
    fn a_fault_says_what_an_operator_should_read() {
        assert_eq!(
            BatchFault::Halt("chain broken".to_string()).reason(),
            "chain broken"
        );
        assert!(!BatchFault::Transient("503".to_string()).is_halt());
    }

    #[test]
    fn jitter_is_a_fraction_of_one_second() {
        let sample = jitter();

        assert!((0.0..1.0).contains(&sample), "{sample}");
    }

    #[tokio::test]
    async fn a_disabled_shipper_says_so_and_stops_nothing() {
        let mut runtime = ActonApp::launch_async().await;
        let handle = TrailShipper::spawn_disabled(&mut runtime).await;

        let StatusPart::Shipping(status) = handle.ask(Describe).await.expect("describes") else {
            panic!("the shipper describes shipping");
        };
        assert!(!status.enabled);
        assert_eq!(status.state, ShipState::Disabled);

        let admission = handle
            .ask(AdmitTurn {
                work: crate::admission::Work::Turn,
                thread_id: crate::types::ThreadId::new(),
                turn_id: crate::types::TurnId::new(),
            })
            .await
            .expect("answers the gate");
        assert_eq!(admission, Admission::Admit);

        runtime.shutdown_all().await.expect("clean shutdown");
    }
}
