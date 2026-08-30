//! `AuditEvent.before_validate`: the verifying ingest.
//!
//! An install ships one sealed entry at a time. This hook decides, before the
//! row exists, whether the plane believes it: whether the flat columns agree
//! with the sealed entry they were derived from, whether the entry belongs to
//! the trail it arrived on, and whether it is the next link after the head the
//! plane already holds. Only then does the row land.
//!
//! # Why the plane's chain can never be broken
//!
//! An entry that would break the chain is refused, so a stored chain of stored
//! entries is intact-or-gapped by construction. `integrity = "broken"` is a
//! state the ingest never writes, and that is the point: the tamper-evidence
//! is that the tampered entry is *not here*, and that the daemon halts and
//! says so rather than the plane quietly recording a contradiction.
//!
//! # A gap is accepted, a fork is not
//!
//! Entries that never arrived leave a hole. The hole is worth recording and
//! the entry after it is worth keeping, so an entry past the head is accepted
//! and the chain is marked `gap` with what is missing. An entry *at or behind*
//! the head is either the same entry arriving twice, which is an
//! acknowledgement, or different content claiming an occupied position, which
//! is a fork and is refused.
//!
//! # Attribution is not the client's to make
//!
//! `operator` and `organization` are filled here from the `AgentInstall` row
//! the trail belongs to. The daemon never sends them; a field the client
//! cannot set is a field the client cannot forge. Every other column that is
//! a pure function of the sealed entry (the decision, the decider, the
//! outcome, the tool, the command, the timestamp) is re-derived here and
//! overwritten, so an install cannot ship a truthful entry beside a flattering
//! export.
//!
//! # One channel, two meanings
//!
//! A hook can only refuse one way: `abort_reason`. "I do not believe your
//! entry" and "I could not reach the plane to check" demand opposite
//! responses from the daemon, so the second is prefixed with
//! [`INGEST_UNAVAILABLE`], which lives in `garrison-wire` where both ends
//! compile the same bytes.

use std::collections::BTreeMap;

use chrono::{SecondsFormat, Utc};
use garrison_wire::audit::{
    command_of, decider_of, decision_of, kind_column, outcome_of, projection_disagreement,
    refusal_reason, truncate, verify_next, AuditEntry, ChainBreakKind, ChainHead, EventProjection,
    GENESIS_HASH, INGEST_UNAVAILABLE, REASON_MAX,
};
use serde_json::{json, Value};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::pb::audit_event::audit_event_hooks_server::AuditEventHooks;
use crate::pb::audit_event::*;
use crate::plane::{AuditChainRow, AuditEventRow, AuditTrailRow, Plane, PlaneError};

/// The refusal for any operation other than a create.
///
/// The schema grants `operator` the write verb, which covers updates as well
/// as creates. An ingested entry that could be edited afterwards is not
/// evidence, so the one hook that runs on both refuses the one that is not an
/// append.
pub const APPEND_ONLY: &str =
    "audit events are append-only; an entry that has been ingested cannot be changed";

/// The `integrity` value for a chain the plane has verified link by link.
pub const INTACT: &str = "intact";

/// The `integrity` value for a chain with entries missing from the middle.
pub const GAP: &str = "gap";

/// What the plane makes of one arriving entry. Pure output of
/// [`adjudicate_entry`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// The next link. Advance the chain to it.
    Accept {
        /// Where the chain head moves to.
        head_seq: u64,
        /// The hash it moves to.
        head_hash: String,
    },
    /// Past the head: entries are missing. Keep the evidence, record the hole.
    AcceptWithGap {
        /// Where the chain head moves to.
        head_seq: u64,
        /// The hash it moves to.
        head_hash: String,
        /// What is missing, for `AuditChain.finding`.
        finding: String,
    },
    /// The plane already holds this exact entry.
    Duplicate,
    /// The entry contradicts what the plane holds.
    Broken(String),
    /// The flat columns contradict the sealed entry they came from.
    Disagreement(String),
}

/// Whether this entry could be one the plane has already ingested. Pure.
///
/// Only an entry at or behind the chain head can be, and the lookup that
/// settles it costs a round trip, so the ordinary case, an entry that extends
/// the chain, never pays for it.
#[must_use]
pub fn is_resend(chain: Option<&AuditChainRow>, entry: &AuditEntry) -> bool {
    chain.is_some_and(|row| row.head_seq >= 0 && entry.sequence <= row.head_seq.unsigned_abs())
}

/// The head the plane holds for a trail, as `verify_next` wants it. Pure.
///
/// `trail_id` is left unset on purpose: trail identity is checked against the
/// `AuditTrail` row before this, so letting `verify_next` re-litigate it would
/// mean two authorities for one question and two different messages for one
/// fault.
#[must_use]
pub fn head_of(chain: Option<&AuditChainRow>) -> ChainHead {
    let Some(row) = chain else {
        return ChainHead::empty();
    };
    let sequence = row.head_seq.unsigned_abs();
    ChainHead {
        sequence,
        hash: if row.head_hash.is_empty() {
            GENESIS_HASH.to_string()
        } else {
            row.head_hash.clone()
        },
        entries: sequence,
        trail_id: None,
    }
}

/// Decide what one arriving entry is. Pure, and the whole of the ingest's
/// judgement.
///
/// The order is deliberate: the columns must agree with the entry before the
/// entry is worth reading, the entry must belong to this trail before its
/// position means anything, and only then does chain arithmetic apply.
#[must_use]
pub fn adjudicate_entry(
    chain: Option<&AuditChainRow>,
    existing: Option<&AuditEventRow>,
    trail: &AuditTrailRow,
    entry: &AuditEntry,
    projection: &EventProjection,
) -> Verdict {
    if let Some(why) = projection_disagreement(entry, projection, &trail.install) {
        return Verdict::Disagreement(why);
    }
    if let Some(claimed) = entry.trail_id.as_ref() {
        let claimed = claimed.to_string();
        if claimed != trail.trail_id {
            return Verdict::Broken(format!(
                "the entry is sealed under trail {claimed} but was shipped into trail {}",
                trail.trail_id
            ));
        }
    }

    let head = head_of(chain);
    let broken = match verify_next(&head, entry, entry.sequence as usize) {
        Ok(next) => {
            return Verdict::Accept {
                head_seq: next.sequence,
                head_hash: next.hash,
            }
        }
        Err(broken) => broken,
    };

    match broken.kind {
        // Ahead of the head: entries never arrived. The hole is the finding;
        // this entry is still evidence. Its own seal is checked here because
        // `verify_next` stopped at the sequence and never reached the hash.
        ChainBreakKind::SequenceGap { expected, found } if found > expected => {
            if entry.recompute_hash() != entry.hash {
                return Verdict::Broken(format!(
                    "the entry at sequence {found} does not hash to the hash it carries"
                ));
            }
            Verdict::AcceptWithGap {
                head_seq: found,
                head_hash: entry.hash.clone(),
                finding: format!(
                    "entries {expected} through {} were never shipped",
                    found.saturating_sub(1)
                ),
            }
        }
        // At or behind the head. The same entry twice is an acknowledgement;
        // different content in an occupied position is a fork.
        ChainBreakKind::SequenceGap { found, .. } => {
            if existing.is_some() {
                Verdict::Duplicate
            } else {
                Verdict::Broken(format!(
                    "sequence {found} is already on the chain with different contents; \
                     the trail has forked"
                ))
            }
        }
        other => Verdict::Broken(other.to_string()),
    }
}

/// What `integrity` and `finding` become after one accepted entry. Pure.
///
/// A chain never heals. An entry that happens to be consecutive after a gap
/// does not turn a hole into an intact record, so a previous finding survives
/// until somebody looks at it.
#[must_use]
pub fn integrity_after(previous: Option<&AuditChainRow>, gap: Option<&str>) -> (String, String) {
    if let Some(finding) = gap {
        return (GAP.to_string(), finding.to_string());
    }
    match previous {
        Some(row) if row.integrity == GAP || row.integrity == "broken" => (
            row.integrity.clone(),
            row.finding.clone().unwrap_or_default(),
        ),
        _ => (INTACT.to_string(), String::new()),
    }
}

/// How far the chain has been walked without a hole. Pure.
///
/// Advances with the head only while the chain is intact: past a gap the walk
/// cannot continue, and claiming otherwise would report a verification that
/// never happened.
#[must_use]
pub fn verified_after(previous: Option<&AuditChainRow>, integrity: &str, head_seq: u64) -> u64 {
    if integrity == INTACT {
        head_seq
    } else {
        previous.map_or(0, |row| row.verified_through.unsigned_abs())
    }
}

/// The columns the hook re-derives from the sealed entry rather than trusting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derived {
    /// What the entry is: `tool_call` for one invocation, `turn` for one
    /// attempted model turn. Read from the entry's own discriminator, which
    /// an invocation omits.
    pub kind: &'static str,
    /// The tool the entry names, empty on a turn.
    pub tool_name: String,
    /// The shell command, empty for every other tool.
    ///
    /// Empty rather than absent so a fabricated command is erased: an unset
    /// optional in the hook response leaves whatever the client sent.
    pub command: String,
    /// How the call, or the turn, was decided.
    pub decision: &'static str,
    /// Which gate decided it.
    pub decider: &'static str,
    /// The rendered reason a refusal came with, empty when there was none.
    ///
    /// Empty for the same reason `command` is: an install that could write
    /// this column freely could explain away its own refusals.
    pub justification: String,
    /// What it came to, absent for a call or a turn that never ran.
    pub outcome: Option<&'static str>,
    /// When it happened, as the entry recorded it.
    pub occurred_at: String,
    /// How long it took. Zero on a turn, which records no duration.
    pub elapsed_ms: i64,
    /// The provider billed for a turn, empty on a tool call.
    pub provider: String,
    /// The model a turn ran against, empty on a tool call.
    pub model: String,
    /// Prompt length in bytes, zero when the entry records none.
    pub prompt_bytes: i64,
    /// Response length in bytes, zero when the entry records none.
    pub response_bytes: i64,
    /// Input tokens summed across the turn.
    pub input_tokens: i64,
    /// Output tokens summed across the turn.
    pub output_tokens: i64,
}

/// Re-derive every column that is a function of the sealed entry. Pure.
///
/// Every field here is written back over whatever the client sent. The turn
/// columns are derived for the same reason the tool columns always were: an
/// install that could set its own token counts could under-report what it
/// spent, and one that could set `kind` could file a turn as a tool call and
/// disappear from a turn-level export.
#[must_use]
pub fn derive(entry: &AuditEntry) -> Derived {
    Derived {
        kind: kind_column(entry),
        tool_name: entry.tool_name.clone().unwrap_or_default(),
        command: command_of(entry).unwrap_or_default(),
        decision: decision_of(entry),
        decider: decider_of(entry),
        justification: refusal_reason(entry)
            .map(|reason| truncate(reason, REASON_MAX))
            .unwrap_or_default(),
        outcome: outcome_of(entry),
        occurred_at: entry.timestamp.clone(),
        elapsed_ms: count(entry.duration_ms),
        provider: entry.provider.clone().unwrap_or_default(),
        model: entry.model.clone().unwrap_or_default(),
        prompt_bytes: count(entry.prompt_size_bytes),
        response_bytes: count(entry.response_size_bytes),
        input_tokens: count(entry.input_tokens),
        output_tokens: count(entry.output_tokens),
    }
}

/// One optional count as the column carries it. Pure.
///
/// Absent becomes zero rather than being left unset, so a count the client
/// invented for an entry that records none is erased instead of surviving.
fn count(value: Option<u64>) -> i64 {
    value.map_or(0, |value| i64::try_from(value).unwrap_or(i64::MAX))
}

/// The one derived column the hook can refuse but cannot correct. Pure.
///
/// `outcome` is an enum, so there is no value that means "nothing happened";
/// an unset optional in the response leaves the client's value in place. A
/// denied call has no outcome, so a client that sent one for a denied entry is
/// claiming a tool ran that never did, and that is a refusal rather than a
/// correction.
#[must_use]
pub fn uncorrectable(derived: &Derived, sent: Option<&str>) -> Option<String> {
    let sent = sent.map(str::trim).filter(|value| !value.is_empty())?;
    if derived.outcome.is_some() {
        return None;
    }
    Some(format!(
        "the row claims outcome {sent} but the sealed entry records a call that never ran"
    ))
}

/// The verifying ingest, holding the `audit_service` bearer.
pub struct Service {
    plane: Plane,
}

impl Service {
    /// Build the ingest from a plane client.
    #[must_use]
    pub const fn new(plane: Plane) -> Self {
        Self { plane }
    }
}

#[tonic::async_trait]
impl AuditEventHooks for Service {
    /// Verify the shipped entry against the trail's chain state; refuse forks
    /// and edits, record gaps.
    async fn before_validate(
        &self,
        request: Request<AuditEventBeforeValidateRequest>,
    ) -> Result<Response<AuditEventBeforeValidateResponse>, Status> {
        let req = request.into_inner();
        if req.operation != "create" {
            return Ok(Response::new(abort(APPEND_ONLY)));
        }
        match self.ingest(&req).await {
            Ok(response) => Ok(Response::new(response)),
            // The plane being unreachable is not a verdict on the entry. The
            // daemon reads the prefix, backs off, and keeps the entry in its
            // backlog; nothing is recorded and nothing is lost.
            Err(error) => {
                warn!(
                    target: "garrison.audit.ingest",
                    trail = %req.trail,
                    chain_seq = req.chain_seq,
                    "audit entry could not be adjudicated: {error}"
                );
                Ok(Response::new(abort(&format!(
                    "{INGEST_UNAVAILABLE}: {error}"
                ))))
            }
        }
    }
}

impl Service {
    /// Fetch what the decision needs, decide, and apply it.
    ///
    /// `Err` means only one thing: the plane could not be asked. Every verdict
    /// about the entry itself, including a refusal, comes back as `Ok`.
    async fn ingest(
        &self,
        req: &AuditEventBeforeValidateRequest,
    ) -> Result<AuditEventBeforeValidateResponse, PlaneError> {
        let entry: AuditEntry = match serde_json::from_str(&req.entry) {
            Ok(entry) => entry,
            // Not a transient fault: the column the whole record rests on is
            // not a sealed entry, and no retry changes that.
            Err(error) => {
                return Ok(refuse(
                    req,
                    &format!("the entry column is not a sealed audit entry: {error}"),
                ))
            }
        };

        let Some(trail) = self.plane.audit_trail(&req.trail).await? else {
            // The forge resolved the relation, so the row exists; this hook
            // not seeing it is a grant or a replication problem, which is
            // worth retrying rather than halting an install over.
            return Err(PlaneError::Malformed(format!(
                "trail {} is not visible to the audit service",
                req.trail
            )));
        };
        let Some(install) = self.plane.agent_install(&trail.install).await? else {
            return Err(PlaneError::Malformed(format!(
                "install {} is not visible to the audit service",
                trail.install
            )));
        };
        let Some(operator) = install.operator.clone() else {
            return Err(PlaneError::Malformed(format!(
                "install {} names no operator; entries cannot be attributed",
                install.id
            )));
        };

        let chain = self.plane.audit_chain(&trail.trail_id).await?;
        let existing = if is_resend(chain.as_ref(), &entry) {
            self.plane.audit_event_by_hash(&entry.hash).await?
        } else {
            None
        };

        let projection = EventProjection {
            chain_seq: req.chain_seq,
            entry_hash: req.entry_hash.clone(),
            prev_hash: req.prev_hash.clone(),
            install: req.install.clone(),
        };
        let verdict = adjudicate_entry(
            chain.as_ref(),
            existing.as_ref(),
            &trail,
            &entry,
            &projection,
        );

        let derived = derive(&entry);
        if let Some(why) = uncorrectable(&derived, req.outcome.as_deref()) {
            return Ok(refuse(req, &why));
        }

        match verdict {
            Verdict::Accept {
                head_seq,
                head_hash,
            } => {
                self.record(chain.as_ref(), &trail, &entry, head_seq, &head_hash, None)
                    .await?;
                Ok(accept(&trail, &operator, &derived))
            }
            Verdict::AcceptWithGap {
                head_seq,
                head_hash,
                finding,
            } => {
                warn!(
                    target: "garrison.audit.ingest",
                    trail = %trail.trail_id,
                    install = %trail.install,
                    chain_seq = head_seq,
                    "audit chain has a hole: {finding}"
                );
                self.record(
                    chain.as_ref(),
                    &trail,
                    &entry,
                    head_seq,
                    &head_hash,
                    Some(&finding),
                )
                .await?;
                Ok(accept(&trail, &operator, &derived))
            }
            // Filled out exactly like an acceptance so the row fails on the
            // unique index rather than on a missing required field: the daemon
            // reads that 409 as an acknowledgement and moves its cursor on.
            Verdict::Duplicate => {
                info!(
                    target: "garrison.audit.ingest",
                    trail = %trail.trail_id,
                    chain_seq = req.chain_seq,
                    "audit entry was already ingested; the create will collide"
                );
                Ok(accept(&trail, &operator, &derived))
            }
            Verdict::Broken(why) | Verdict::Disagreement(why) => Ok(refuse(req, &why)),
        }
    }

    /// Move the plane's own record of the chain to this entry.
    async fn record(
        &self,
        chain: Option<&AuditChainRow>,
        trail: &AuditTrailRow,
        entry: &AuditEntry,
        head_seq: u64,
        head_hash: &str,
        gap: Option<&str>,
    ) -> Result<(), PlaneError> {
        let (integrity, finding) = integrity_after(chain, gap);
        let verified_through = verified_after(chain, &integrity, head_seq);
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);

        let mut fields: BTreeMap<String, Value> = BTreeMap::new();
        fields.insert("head_hash".into(), json!(head_hash));
        fields.insert("head_seq".into(), json!(head_seq));
        fields.insert("verified_through".into(), json!(verified_through));
        fields.insert("integrity".into(), json!(integrity));
        fields.insert("finding".into(), json!(finding));
        fields.insert("last_entry_at".into(), json!(entry.timestamp));
        fields.insert("last_verified_at".into(), json!(now));

        match chain {
            Some(row) => self
                .plane
                .patch("AuditChain", &row.id, fields)
                .await
                .map(drop),
            None => {
                fields.insert("trail_id".into(), json!(trail.trail_id));
                fields.insert("trail".into(), json!(trail.id));
                fields.insert("organization".into(), json!(trail.organization));
                fields.insert("install".into(), json!(trail.install));
                self.plane.create("AuditChain", fields).await.map(drop)
            }
        }
    }
}

/// The response for an entry the plane believes.
///
/// Every field set here is one the client no longer decides.
fn accept(
    trail: &AuditTrailRow,
    operator: &str,
    derived: &Derived,
) -> AuditEventBeforeValidateResponse {
    AuditEventBeforeValidateResponse {
        organization: Some(trail.organization.clone()),
        operator: Some(operator.to_string()),
        install: Some(trail.install.clone()),
        kind: Some(derived.kind.to_string()),
        tool_name: Some(derived.tool_name.clone()),
        command: Some(derived.command.clone()),
        decision: Some(derived.decision.to_string()),
        decider: Some(derived.decider.to_string()),
        justification: Some(derived.justification.clone()),
        outcome: derived.outcome.map(ToString::to_string),
        occurred_at: Some(derived.occurred_at.clone()),
        elapsed_ms: Some(derived.elapsed_ms),
        provider: Some(derived.provider.clone()),
        model: Some(derived.model.clone()),
        prompt_bytes: Some(derived.prompt_bytes),
        response_bytes: Some(derived.response_bytes),
        input_tokens: Some(derived.input_tokens),
        output_tokens: Some(derived.output_tokens),
        ..Default::default()
    }
}

/// A refusal on the merits: the daemon halts and a human looks.
fn refuse(req: &AuditEventBeforeValidateRequest, why: &str) -> AuditEventBeforeValidateResponse {
    warn!(
        target: "garrison.audit.ingest",
        trail = %req.trail,
        install = %req.install,
        chain_seq = req.chain_seq,
        entry_hash = %req.entry_hash,
        "audit entry refused: {why}"
    );
    abort(why)
}

/// The one way a hook can say no.
fn abort(reason: &str) -> AuditEventBeforeValidateResponse {
    AuditEventBeforeValidateResponse {
        abort_reason: Some(reason.to_string()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use garrison_wire::audit::{
        fixture, AuditDecision, AuditOutcome, Decider, TrailId, TurnAuditOutcome,
    };

    /// A fresh trail identity. Reached through `garrison-wire`, like every
    /// other acton-ai type this crate touches: the hook service does not
    /// depend on the daemon's engine, it depends on the wire between them.
    fn trail_id() -> TrailId {
        TrailId::new()
    }

    fn trail_row(id: &TrailId) -> AuditTrailRow {
        AuditTrailRow {
            id: "audittrail_01".into(),
            trail_id: id.to_string(),
            install: "agentinstall_01".into(),
            organization: "organization_01".into(),
            local_head_seq: 0,
            local_head_hash: None,
            shipped_through: 0,
            reported_at: None,
            halted_reason: None,
        }
    }

    fn chain_row(head_seq: i64, head_hash: &str) -> AuditChainRow {
        AuditChainRow {
            id: "auditchain_01".into(),
            trail_id: "trail_x".into(),
            trail: "audittrail_01".into(),
            organization: "organization_01".into(),
            install: "agentinstall_01".into(),
            head_hash: head_hash.into(),
            head_seq,
            verified_through: head_seq,
            integrity: INTACT.into(),
            finding: None,
            last_entry_at: None,
        }
    }

    fn projection_of(entry: &AuditEntry, install: &str) -> EventProjection {
        EventProjection {
            chain_seq: entry.sequence as i64,
            entry_hash: entry.hash.clone(),
            prev_hash: entry.prev_hash.clone(),
            install: install.to_string(),
        }
    }

    fn event_row(entry: &AuditEntry) -> AuditEventRow {
        AuditEventRow {
            id: "auditevent_01".into(),
            trail: "audittrail_01".into(),
            chain_seq: entry.sequence as i64,
            entry_hash: entry.hash.clone(),
            prev_hash: entry.prev_hash.clone(),
        }
    }

    #[test]
    fn the_first_entry_of_a_trail_opens_the_chain() {
        let id = trail_id();
        let chain = fixture::chain(1, &id);
        let entry = &chain[0];
        let trail = trail_row(&id);

        let verdict = adjudicate_entry(
            None,
            None,
            &trail,
            entry,
            &projection_of(entry, &trail.install),
        );

        assert_eq!(
            verdict,
            Verdict::Accept {
                head_seq: 1,
                head_hash: entry.hash.clone()
            }
        );
    }

    #[test]
    fn the_next_link_advances_the_head() {
        let id = trail_id();
        let entries = fixture::chain(2, &id);
        let trail = trail_row(&id);
        let chain = chain_row(1, &entries[0].hash);

        let verdict = adjudicate_entry(
            Some(&chain),
            None,
            &trail,
            &entries[1],
            &projection_of(&entries[1], &trail.install),
        );

        assert_eq!(
            verdict,
            Verdict::Accept {
                head_seq: 2,
                head_hash: entries[1].hash.clone()
            }
        );
    }

    #[test]
    fn an_entry_past_the_head_is_kept_and_the_hole_is_named() {
        let id = trail_id();
        let entries = fixture::chain(5, &id);
        let trail = trail_row(&id);
        let chain = chain_row(1, &entries[0].hash);

        let verdict = adjudicate_entry(
            Some(&chain),
            None,
            &trail,
            &entries[4],
            &projection_of(&entries[4], &trail.install),
        );

        let Verdict::AcceptWithGap {
            head_seq, finding, ..
        } = verdict
        else {
            panic!("a gap, got {verdict:?}");
        };
        assert_eq!(head_seq, 5);
        assert!(finding.contains('2') && finding.contains('4'), "{finding}");
    }

    #[test]
    fn an_entry_past_the_head_is_still_checked_against_its_own_seal() {
        let id = trail_id();
        let mut entries = fixture::chain(5, &id);
        let trail = trail_row(&id);
        let chain = chain_row(1, &entries[0].hash);
        // Edit the entry after sealing: the hash it carries is now a lie, and
        // the sequence check would otherwise have stopped before the hash one.
        entries[4].tool_name = Some("rm".to_string());
        let projection = projection_of(&entries[4], &trail.install);

        let verdict = adjudicate_entry(Some(&chain), None, &trail, &entries[4], &projection);

        assert!(
            matches!(&verdict, Verdict::Broken(why) if why.contains("hash")),
            "{verdict:?}"
        );
    }

    #[test]
    fn the_same_entry_arriving_twice_is_an_acknowledgement() {
        let id = trail_id();
        let entries = fixture::chain(2, &id);
        let trail = trail_row(&id);
        let chain = chain_row(2, &entries[1].hash);
        let existing = event_row(&entries[1]);

        let verdict = adjudicate_entry(
            Some(&chain),
            Some(&existing),
            &trail,
            &entries[1],
            &projection_of(&entries[1], &trail.install),
        );

        assert_eq!(verdict, Verdict::Duplicate);
    }

    #[test]
    fn different_content_in_an_occupied_position_is_a_fork() {
        let id = trail_id();
        let entries = fixture::chain(2, &id);
        let trail = trail_row(&id);
        let chain = chain_row(2, &entries[1].hash);
        // A second entry sealed at sequence 2 behind the same predecessor.
        let forked = fixture::entry(
            2,
            &entries[0].hash,
            Some(&id),
            "bash",
            json!({ "command": "curl evil.example" }),
            AuditOutcome::Success {
                summary: "ok".into(),
            },
            AuditDecision::approved(Decider::Callback),
        );

        let verdict = adjudicate_entry(
            Some(&chain),
            None,
            &trail,
            &forked,
            &projection_of(&forked, &trail.install),
        );

        assert!(
            matches!(&verdict, Verdict::Broken(why) if why.contains("forked")),
            "{verdict:?}"
        );
    }

    #[test]
    fn an_entry_that_does_not_point_at_the_head_is_refused() {
        let id = trail_id();
        let entries = fixture::chain(2, &id);
        let trail = trail_row(&id);
        // A chain head with the right sequence and the wrong hash: an entry
        // was rewritten under the plane's copy.
        let chain = chain_row(1, "0".repeat(64).as_str());

        let verdict = adjudicate_entry(
            Some(&chain),
            None,
            &trail,
            &entries[1],
            &projection_of(&entries[1], &trail.install),
        );

        assert!(matches!(verdict, Verdict::Broken(_)), "{verdict:?}");
    }

    #[test]
    fn an_entry_sealed_under_another_trail_is_refused() {
        let id = trail_id();
        let entries = fixture::chain(1, &id);
        let mut trail = trail_row(&id);
        trail.trail_id = trail_id().to_string();

        let verdict = adjudicate_entry(
            None,
            None,
            &trail,
            &entries[0],
            &projection_of(&entries[0], &trail.install),
        );

        assert!(
            matches!(&verdict, Verdict::Broken(why) if why.contains("sealed under")),
            "{verdict:?}"
        );
    }

    #[test]
    fn columns_that_contradict_the_sealed_entry_are_a_disagreement() {
        let id = trail_id();
        let entries = fixture::chain(1, &id);
        let trail = trail_row(&id);
        let mut projection = projection_of(&entries[0], &trail.install);
        projection.entry_hash = "deadbeef".into();

        let verdict = adjudicate_entry(None, None, &trail, &entries[0], &projection);

        assert!(matches!(verdict, Verdict::Disagreement(_)), "{verdict:?}");
    }

    #[test]
    fn shipping_into_another_installs_trail_is_a_disagreement() {
        let id = trail_id();
        let entries = fixture::chain(1, &id);
        let trail = trail_row(&id);
        let projection = projection_of(&entries[0], "agentinstall_intruder");

        let verdict = adjudicate_entry(None, None, &trail, &entries[0], &projection);

        assert!(matches!(verdict, Verdict::Disagreement(_)), "{verdict:?}");
    }

    #[test]
    fn only_an_entry_at_or_behind_the_head_costs_a_lookup() {
        let id = trail_id();
        let entries = fixture::chain(3, &id);
        let chain = chain_row(2, &entries[1].hash);

        assert!(is_resend(Some(&chain), &entries[1]));
        assert!(is_resend(Some(&chain), &entries[0]));
        assert!(!is_resend(Some(&chain), &entries[2]));
        assert!(!is_resend(None, &entries[0]));
    }

    #[test]
    fn an_empty_chain_row_still_starts_at_genesis() {
        let mut row = chain_row(0, "");
        row.head_hash = String::new();

        let head = head_of(Some(&row));

        assert_eq!(head.sequence, 0);
        assert_eq!(head.hash, GENESIS_HASH);
    }

    #[test]
    fn a_chain_that_has_gapped_never_heals() {
        let mut gapped = chain_row(4, "abc");
        gapped.integrity = GAP.into();
        gapped.finding = Some("entries 2 through 3 were never shipped".into());

        let (integrity, finding) = integrity_after(Some(&gapped), None);

        assert_eq!(integrity, GAP);
        assert!(finding.contains("never shipped"));
    }

    #[test]
    fn a_gap_always_records_what_is_missing() {
        let (integrity, finding) = integrity_after(None, Some("entries 2 through 3"));

        assert_eq!(integrity, GAP);
        assert!(
            !finding.is_empty(),
            "the schema refuses a gap with no finding"
        );
    }

    #[test]
    fn verification_stops_at_the_hole_and_advances_only_while_intact() {
        let mut gapped = chain_row(4, "abc");
        gapped.integrity = GAP.into();
        gapped.verified_through = 1;

        assert_eq!(verified_after(Some(&gapped), GAP, 9), 1);
        assert_eq!(verified_after(Some(&gapped), INTACT, 9), 9);
        assert_eq!(verified_after(None, INTACT, 3), 3);
    }

    #[test]
    fn the_derived_columns_come_from_the_entry_and_not_the_client() {
        let id = trail_id();
        let entry = fixture::entry(
            1,
            GENESIS_HASH,
            Some(&id),
            "bash",
            json!({ "command": "echo hi" }),
            AuditOutcome::Success {
                summary: "ok".into(),
            },
            AuditDecision::approved(Decider::Allowlist),
        );

        let derived = derive(&entry);

        assert_eq!(derived.decision, "auto_approved");
        assert_eq!(derived.decider, "policy");
        assert_eq!(derived.outcome, Some("success"));
        assert_eq!(derived.command, "echo hi");
        assert_eq!(derived.elapsed_ms, 42);
    }

    #[test]
    fn a_fabricated_command_is_erased_rather_than_left_standing() {
        let id = trail_id();
        let entry = fixture::entry(
            1,
            GENESIS_HASH,
            Some(&id),
            "read_file",
            json!({ "path": "a", "command": "sudo rm -rf /" }),
            AuditOutcome::Success {
                summary: "ok".into(),
            },
            AuditDecision::approved(Decider::Rules),
        );

        assert_eq!(derive(&entry).command, "");
    }

    #[test]
    fn an_outcome_claimed_for_a_call_that_never_ran_is_refused() {
        let id = trail_id();
        let denied = fixture::entry(
            1,
            GENESIS_HASH,
            Some(&id),
            "bash",
            json!({ "command": "rm -rf /" }),
            AuditOutcome::Denied {
                reason: "denylist".into(),
            },
            AuditDecision::refused(Decider::Denylist),
        );
        let derived = derive(&denied);

        assert!(uncorrectable(&derived, Some("success")).is_some());
        assert!(uncorrectable(&derived, None).is_none());
        assert!(uncorrectable(&derived, Some("")).is_none());
    }

    #[test]
    fn a_turn_entry_derives_a_turn_row_and_names_no_tool() {
        let id = trail_id();
        let entry = fixture::turn(1, GENESIS_HASH, Some(&id), TurnAuditOutcome::Completed);

        let derived = derive(&entry);

        assert_eq!(derived.kind, "turn");
        assert_eq!(derived.tool_name, "");
        assert_eq!(derived.command, "");
        assert_eq!(derived.decision, "auto_approved");
        assert_eq!(derived.decider, "default");
        assert_eq!(derived.outcome, Some("success"));
        assert_eq!(derived.provider, "anthropic");
        assert_eq!(derived.model, "claude-opus-5");
        assert_eq!(derived.prompt_bytes, 64);
        assert_eq!(derived.response_bytes, 512);
        assert_eq!(derived.input_tokens, 900);
        assert_eq!(derived.output_tokens, 120);
    }

    #[test]
    fn a_refused_turn_derives_a_refusal_and_carries_its_reason() {
        let id = trail_id();
        let entry = fixture::turn(
            1,
            GENESIS_HASH,
            Some(&id),
            TurnAuditOutcome::Refused {
                decision: "draining".into(),
                reason: "the daemon is draining".into(),
            },
        );

        let derived = derive(&entry);

        assert_eq!(derived.decision, "forbidden");
        assert_eq!(derived.decider, "policy");
        assert_eq!(derived.justification, "the daemon is draining");
        assert_eq!(derived.outcome, None);
    }

    #[test]
    fn an_outcome_claimed_for_a_turn_that_never_ran_is_refused() {
        // The same rule the denied tool call gets: a row saying a refused turn
        // succeeded is claiming a provider round that was never paid for.
        let id = trail_id();
        let entry = fixture::turn(
            1,
            GENESIS_HASH,
            Some(&id),
            TurnAuditOutcome::Refused {
                decision: "paused".into(),
                reason: "admission is paused".into(),
            },
        );
        let derived = derive(&entry);

        assert!(uncorrectable(&derived, Some("success")).is_some());
        assert!(uncorrectable(&derived, None).is_none());
    }

    #[test]
    fn a_tool_call_derives_none_of_the_turn_columns() {
        // Empty and zero rather than unset: an unset optional in the response
        // leaves whatever the client sent, so an install could otherwise
        // decorate a tool call with invented token counts.
        let id = trail_id();
        let entries = fixture::chain(1, &id);

        let derived = derive(&entries[0]);

        assert_eq!(derived.kind, "tool_call");
        assert_eq!(derived.provider, "");
        assert_eq!(derived.model, "");
        assert_eq!(derived.prompt_bytes, 0);
        assert_eq!(derived.input_tokens, 0);
        assert_eq!(derived.output_tokens, 0);
        assert_eq!(derived.justification, "");
    }

    #[test]
    fn a_turn_row_overwrites_every_count_the_client_sent() {
        let id = trail_id();
        let entry = fixture::turn(1, GENESIS_HASH, Some(&id), TurnAuditOutcome::Completed);
        let trail = trail_row(&id);

        let response = accept(&trail, "operator_01", &derive(&entry));

        assert_eq!(response.kind.as_deref(), Some("turn"));
        assert_eq!(response.input_tokens, Some(900));
        assert_eq!(response.output_tokens, Some(120));
        assert_eq!(response.prompt_bytes, Some(64));
        assert_eq!(response.response_bytes, Some(512));
        assert_eq!(response.model.as_deref(), Some("claude-opus-5"));
    }

    #[test]
    fn a_turn_entry_adjudicates_on_the_chain_like_any_other() {
        // Turn and invocation entries share one chain, so the ingest must
        // link them together rather than treating a turn as an interloper.
        let id = trail_id();
        let entries = fixture::mixed_chain(2, &id);
        let trail = trail_row(&id);
        let chain = chain_row(1, &entries[0].hash);

        let verdict = adjudicate_entry(
            Some(&chain),
            None,
            &trail,
            &entries[1],
            &projection_of(&entries[1], &trail.install),
        );

        assert!(
            matches!(&verdict, Verdict::Accept { head_seq, .. } if *head_seq == 2),
            "{verdict:?}"
        );
    }

    #[test]
    fn an_update_is_refused_because_the_trail_is_append_only() {
        let response = abort(APPEND_ONLY);

        assert_eq!(response.abort_reason.as_deref(), Some(APPEND_ONLY));
        assert!(response.operator.is_none());
    }

    #[test]
    fn an_acceptance_names_the_operator_the_client_never_sent() {
        let id = trail_id();
        let entries = fixture::chain(1, &id);
        let trail = trail_row(&id);

        let response = accept(&trail, "operator_01", &derive(&entries[0]));

        assert!(response.abort_reason.is_none());
        assert_eq!(response.operator.as_deref(), Some("operator_01"));
        assert_eq!(response.organization.as_deref(), Some("organization_01"));
    }
}
