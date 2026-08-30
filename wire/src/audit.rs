//! One definition of what a sealed audit entry looks like as a plane row.
//!
//! An entry leaves the daemon twice over: verbatim, in the `entry` column,
//! and as a set of flat columns an auditor can filter and export. The flat
//! columns are a *projection* of the verbatim one, and this module is the
//! only place that projection is written down.
//!
//! # Why both ends compile the same function
//!
//! The daemon computes the columns; the ingest hook has to decide whether to
//! believe them. If the hook trusted whatever the daemon sent, an install
//! could ship a truthful `entry` beside a flattering `decision` and the
//! export an auditor reads would disagree with the evidence it was derived
//! from. So the hook re-runs [`project`] over the entry it was handed and
//! compares. Two implementations of that mapping would eventually differ, and
//! the difference would read as tampering.
//!
//! # What is not projected
//!
//! `operator` and `organization` are absent on purpose. An install must not
//! be able to attribute its own entries: the hook fills both from the
//! `AgentInstall` row the trail belongs to, exactly as the enrollment hook
//! fills `organization` on a redemption. A field the client cannot set is a
//! field the client cannot forge.

// Re-exported rather than merely used: the ingest hook has to deserialize the
// same sealed entry the daemon serialized, and a service that reached for
// `acton_ai` itself would be a second, independently versioned definition of
// what an entry is. One crate names the type; both ends read it from there.
pub use acton_ai::audit::{AuditDecision, AuditEntry, AuditOutcome};
pub use acton_ai::policy::Decider;
pub use acton_ai::types::TrailId;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

pub use acton_ai::audit::{verify_next, ChainBreak, ChainBreakKind, ChainHead, GENESIS_HASH};

/// What the ingest hook says when it is the *plane* it could not reach, not
/// the entry it could not believe.
///
/// A hook has exactly one way to refuse: `abort_reason`, which the plane
/// turns into one status. So the daemon cannot tell "your entry is forged"
/// from "I could not look it up" by status code alone, and the two demand
/// opposite behaviour: halt and fetch a human, or back off and try again.
/// This sentence is the discriminator, and it lives here so the side that
/// writes it and the side that reads it compile the same bytes.
pub const INGEST_UNAVAILABLE: &str = "audit ingest temporarily unavailable";

/// The longest a projected `command` may be, matching `text(max: 2048)` on
/// the schema. A longer one is truncated here rather than refused by the
/// plane, because losing the tail of an argument list is a smaller loss than
/// losing the entry.
pub const COMMAND_MAX: usize = 2048;

/// The suffix a truncated command carries, so a reader can tell.
pub const TRUNCATED: &str = "…";

/// The denial reason Garrison's approval gate writes when nobody answered.
///
/// Duplicated from `garrison_agent::approval::TIMEOUT_REASON` rather than
/// depended on: this crate is compiled into the hook service, which must not
/// pull in the daemon. The agent's own test asserts the two agree.
pub const TIMEOUT_REASON: &str = "approval timed out";

/// The tools whose effects the process sandbox actually confines.
///
/// A read-only tool runs in-process whether or not a sandbox is configured,
/// so reporting `sandboxed = true` for it would overclaim. The list is the
/// set acton-ai routes through the sandbox child.
pub const SANDBOXED_TOOLS: [&str; 4] = ["bash", "write_file", "edit_file", "apply_patch"];

/// What the daemon knows that the entry does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionContext {
    /// The `Organization` row this install belongs to.
    pub organization: String,
    /// The `AgentInstall` row this daemon is.
    pub install: String,
    /// The `AuditTrail` row the entry is being appended to.
    pub trail: String,
    /// Whether this daemon's writing tools run in the process sandbox.
    pub sandbox_enabled: bool,
}

/// The `fields` body for one `AuditEvent` create.
///
/// Pure: the same entry in the same context always produces the same body,
/// which is what lets the ingest hook recompute it and compare.
#[must_use]
pub fn project(entry: &AuditEntry, context: &ProjectionContext) -> Value {
    let mut fields = Map::new();
    fields.insert("organization".into(), json!(context.organization));
    fields.insert("install".into(), json!(context.install));
    fields.insert("trail".into(), json!(context.trail));

    fields.insert("chain_seq".into(), json!(entry.sequence));
    fields.insert("entry_hash".into(), json!(entry.hash));
    fields.insert("prev_hash".into(), json!(entry.prev_hash));
    fields.insert(
        "entry".into(),
        serde_json::to_value(entry).unwrap_or(Value::Null),
    );

    fields.insert("occurred_at".into(), json!(entry.timestamp));
    fields.insert("kind".into(), json!("tool_call"));
    fields.insert("tool_name".into(), json!(entry.tool_name));
    if let Some(command) = command_of(entry) {
        fields.insert("command".into(), json!(command));
    }

    fields.insert("decision".into(), json!(decision_of(entry)));
    fields.insert("decider".into(), json!(decider_of(entry.decision)));
    if let Some(outcome) = outcome_of(&entry.outcome) {
        fields.insert("outcome".into(), json!(outcome));
    }
    fields.insert(
        "sandboxed".into(),
        json!(context.sandbox_enabled && is_sandboxed_tool(&entry.tool_name)),
    );
    fields.insert("elapsed_ms".into(), json!(entry.duration_ms));

    Value::Object(fields)
}

/// The command an entry ran, for a shell tool, truncated to the column.
///
/// Only `bash` has one: for every other tool the arguments are structured and
/// a flattened rendering would be a worse copy of `entry`.
#[must_use]
pub fn command_of(entry: &AuditEntry) -> Option<String> {
    if entry.tool_name != "bash" {
        return None;
    }
    let command = entry.arguments.get("command")?.as_str()?;
    Some(truncate(command, COMMAND_MAX))
}

/// Clips a string to `max` characters, marking that it was clipped.
///
/// Counts characters rather than bytes and never splits one, because the
/// column is `text(max: 2048)` and a half-written UTF-8 sequence is not text.
#[must_use]
pub fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let keep = max.saturating_sub(TRUNCATED.chars().count());
    let mut clipped: String = text.chars().take(keep).collect();
    clipped.push_str(TRUNCATED);
    clipped
}

/// Whether the sandbox, when configured, actually confines this tool.
#[must_use]
pub fn is_sandboxed_tool(tool: &str) -> bool {
    SANDBOXED_TOOLS.contains(&tool)
}

/// The `decision` enum value for a sealed entry. Pure.
///
/// Four outcomes an auditor cares to tell apart: a human said yes
/// (`approved`), a rule said yes (`auto_approved`), a human declined
/// (`denied`), and a rule declined (`forbidden`). A prompt nobody answered is
/// `timed_out`, which is the one case where "denied" would be a lie about a
/// person.
#[must_use]
pub fn decision_of(entry: &AuditEntry) -> &'static str {
    let by_human = matches!(entry.decision.decided_by, Decider::Callback);
    match (entry.decision.approved, by_human) {
        (true, true) => "approved",
        (true, false) => "auto_approved",
        (false, true) if timed_out(&entry.outcome) => "timed_out",
        (false, true) => "denied",
        (false, false) => "forbidden",
    }
}

/// Whether a refusal was a timeout rather than a decision. Pure.
fn timed_out(outcome: &AuditOutcome) -> bool {
    matches!(outcome, AuditOutcome::Denied { reason } if reason.starts_with(TIMEOUT_REASON))
}

/// The `decider` enum value: which gate reached the verdict. Pure.
#[must_use]
pub fn decider_of(decision: AuditDecision) -> &'static str {
    match decision.decided_by {
        Decider::NoPolicy => "default",
        Decider::Callback => "callback",
        _ => "policy",
    }
}

/// The `outcome` enum value, when the call produced one. Pure.
///
/// A denied call has no outcome: the tool never ran, and recording `error`
/// for it would put a refusal in the same bucket as a failure.
#[must_use]
pub fn outcome_of(outcome: &AuditOutcome) -> Option<&'static str> {
    match outcome {
        AuditOutcome::Success { .. } => Some("success"),
        AuditOutcome::Error { .. } => Some("error"),
        AuditOutcome::Uncertain { .. } => Some("aborted"),
        AuditOutcome::Denied { .. } => None,
        // acton-ai marks the enum non-exhaustive. An outcome this build does
        // not understand is left unstated rather than guessed at: the
        // verbatim entry still carries it.
        _ => None,
    }
}

/// The projected columns as the ingest hook receives them back.
///
/// Only the fields whose agreement with the entry is worth checking. The rest
/// are either filled by the hook or re-derivable from `entry`, so a
/// disagreement there is not evidence of anything.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventProjection {
    /// The chain position the client claims.
    pub chain_seq: i64,
    /// The hash the client claims.
    pub entry_hash: String,
    /// The predecessor the client claims.
    pub prev_hash: String,
    /// The install the client claims to be.
    pub install: String,
}

/// Whether the flat columns say the same thing the sealed entry does.
///
/// Pure, and the whole reason both ends compile [`project`]. Returns the
/// sentence naming the first disagreement, or `None` when they agree.
///
/// `install` is checked against the trail's install rather than the client's
/// claim, because the trail row is the plane's own record of whose trail this
/// is; a daemon shipping into someone else's trail is exactly what this
/// catches.
#[must_use]
pub fn projection_disagreement(
    entry: &AuditEntry,
    projection: &EventProjection,
    trail_install: &str,
) -> Option<String> {
    if projection.chain_seq < 0 || projection.chain_seq as u64 != entry.sequence {
        return Some(format!(
            "the row claims chain_seq {} but the sealed entry is sequence {}",
            projection.chain_seq, entry.sequence
        ));
    }
    if projection.entry_hash != entry.hash {
        return Some(format!(
            "the row claims entry_hash {} but the sealed entry carries {}",
            projection.entry_hash, entry.hash
        ));
    }
    if projection.prev_hash != entry.prev_hash {
        return Some(format!(
            "the row claims prev_hash {} but the sealed entry carries {}",
            projection.prev_hash, entry.prev_hash
        ));
    }
    if projection.install != trail_install {
        return Some(format!(
            "the row claims install {} but the trail belongs to {trail_install}",
            projection.install
        ));
    }
    None
}

/// Building sealed chains without acton-ai's writer.
///
/// `InvocationRecord` is `#[non_exhaustive]`, so no crate outside acton-ai
/// can call `AuditEntry::seal`. A verifier's tests still need real chains —
/// a chain built by hand and then *re-sealed with the same hash rule* is the
/// only way to exercise [`verify_next`] over a fork, a gap, or an edit
/// without running a daemon. [`AuditEntry`] is an ordinary public struct and
/// [`AuditEntry::recompute_hash`] is the same function verification uses, so
/// what comes out of here is indistinguishable from what a writer produces.
///
/// Behind a feature so it can never be linked into a shipped binary: a
/// process that can seal entries is a process that can forge them.
#[cfg(any(test, feature = "testing"))]
pub mod fixture {
    use acton_ai::audit::{AuditDecision, AuditEntry, AuditOutcome, GENESIS_HASH};
    use acton_ai::policy::Decider;
    use acton_ai::types::{CorrelationId, TrailId, TurnId};
    use serde_json::Value;

    /// Seals one entry behind `prev_hash` at `sequence`, under `trail_id`.
    #[must_use]
    pub fn entry(
        sequence: u64,
        prev_hash: &str,
        trail_id: Option<&TrailId>,
        tool: &str,
        arguments: Value,
        outcome: AuditOutcome,
        decision: AuditDecision,
    ) -> AuditEntry {
        let mut built = AuditEntry {
            sequence,
            timestamp: format!("2026-08-29T12:00:{:02}Z", sequence % 60),
            correlation_id: CorrelationId::new(),
            conversation_id: None,
            user: None,
            turn_id: TurnId::new(),
            tool_call_id: format!("toolu_{sequence}"),
            tool_name: tool.to_string(),
            arguments,
            outcome,
            decision,
            duration_ms: 42,
            response_size_bytes: Some(11),
            resumed: false,
            trail_id: trail_id.cloned(),
            prev_hash: prev_hash.to_string(),
            hash: String::new(),
        };
        built.hash = built.recompute_hash();
        built
    }

    /// A chain of `count` successful `bash` calls under one trail.
    #[must_use]
    pub fn chain(count: u64, trail_id: &TrailId) -> Vec<AuditEntry> {
        let mut entries: Vec<AuditEntry> = Vec::with_capacity(count as usize);
        let mut prev = GENESIS_HASH.to_string();
        for sequence in 1..=count {
            let sealed = entry(
                sequence,
                &prev,
                Some(trail_id),
                "bash",
                serde_json::json!({ "command": format!("echo {sequence}") }),
                AuditOutcome::Success {
                    summary: "ok".to_string(),
                },
                AuditDecision::approved(Decider::Callback),
            );
            prev.clone_from(&sealed.hash);
            entries.push(sealed);
        }
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acton_ai::audit::GENESIS_HASH;
    use acton_ai::types::TrailId;

    /// What one invocation was, before it has a place in a chain.
    type Invocation = (&'static str, Value, AuditOutcome, AuditDecision);

    const fn record(
        tool: &'static str,
        arguments: Value,
        outcome: AuditOutcome,
        decision: AuditDecision,
    ) -> Invocation {
        (tool, arguments, outcome, decision)
    }

    fn sealed(invocation: Invocation) -> AuditEntry {
        let (tool, arguments, outcome, decision) = invocation;
        fixture::entry(
            1,
            GENESIS_HASH,
            Some(&TrailId::new()),
            tool,
            arguments,
            outcome,
            decision,
        )
    }

    fn context() -> ProjectionContext {
        ProjectionContext {
            organization: "organization_01".to_string(),
            install: "agentinstall_01".to_string(),
            trail: "audittrail_01".to_string(),
            sandbox_enabled: true,
        }
    }

    fn success() -> AuditOutcome {
        AuditOutcome::Success {
            summary: "ok".to_string(),
        }
    }

    #[test]
    fn a_projected_row_carries_the_entry_verbatim_beside_its_columns() {
        let entry = sealed(record(
            "bash",
            json!({ "command": "ls -la" }),
            success(),
            AuditDecision::approved(Decider::Callback),
        ));

        let fields = project(&entry, &context());

        assert_eq!(fields["chain_seq"], json!(entry.sequence));
        assert_eq!(fields["entry_hash"], json!(entry.hash));
        assert_eq!(fields["prev_hash"], json!(entry.prev_hash));
        assert_eq!(fields["occurred_at"], json!(entry.timestamp));
        assert_eq!(fields["kind"], json!("tool_call"));
        assert_eq!(fields["elapsed_ms"], json!(42));
        assert_eq!(
            fields["entry"],
            serde_json::to_value(&entry).expect("an entry serializes")
        );
    }

    #[test]
    fn a_projection_never_names_the_operator_because_the_install_must_not_choose_one() {
        let entry = sealed(record(
            "read_file",
            json!({ "path": "a" }),
            success(),
            AuditDecision::approved(Decider::Rules),
        ));

        let fields = project(&entry, &context());

        assert!(fields.get("operator").is_none());
    }

    #[test]
    fn only_a_shell_call_projects_a_command() {
        let shell = sealed(record(
            "bash",
            json!({ "command": "echo hi" }),
            success(),
            AuditDecision::approved(Decider::Rules),
        ));
        let other = sealed(record(
            "read_file",
            json!({ "command": "echo hi" }),
            success(),
            AuditDecision::approved(Decider::Rules),
        ));

        assert_eq!(command_of(&shell).as_deref(), Some("echo hi"));
        assert_eq!(command_of(&other), None);
    }

    #[test]
    fn a_command_longer_than_the_column_is_clipped_and_says_so() {
        let long = "x".repeat(COMMAND_MAX + 100);
        let clipped = truncate(&long, COMMAND_MAX);

        assert_eq!(clipped.chars().count(), COMMAND_MAX);
        assert!(clipped.ends_with(TRUNCATED));
    }

    #[test]
    fn a_command_of_multibyte_characters_is_never_split_mid_character() {
        let long = "é".repeat(COMMAND_MAX + 10);
        let clipped = truncate(&long, COMMAND_MAX);

        assert_eq!(clipped.chars().count(), COMMAND_MAX);
        assert!(clipped.is_char_boundary(clipped.len()));
    }

    #[test]
    fn a_human_approval_and_a_rule_approval_are_different_facts() {
        let human = sealed(record(
            "bash",
            json!({}),
            success(),
            AuditDecision::approved(Decider::Callback),
        ));
        let rule = sealed(record(
            "bash",
            json!({}),
            success(),
            AuditDecision::approved(Decider::Allowlist),
        ));

        assert_eq!(decision_of(&human), "approved");
        assert_eq!(decision_of(&rule), "auto_approved");
    }

    #[test]
    fn a_prompt_nobody_answered_is_timed_out_and_not_denied() {
        let entry = sealed(record(
            "bash",
            json!({}),
            AuditOutcome::Denied {
                reason: format!("{TIMEOUT_REASON} after 120s"),
            },
            AuditDecision::refused(Decider::Callback),
        ));

        assert_eq!(decision_of(&entry), "timed_out");
    }

    #[test]
    fn a_human_who_said_no_is_denied_and_a_rule_that_said_no_is_forbidden() {
        let human = sealed(record(
            "bash",
            json!({}),
            AuditOutcome::Denied {
                reason: "not this one".to_string(),
            },
            AuditDecision::refused(Decider::Callback),
        ));
        let rule = sealed(record(
            "bash",
            json!({}),
            AuditOutcome::Denied {
                reason: "denylist".to_string(),
            },
            AuditDecision::refused(Decider::Denylist),
        ));

        assert_eq!(decision_of(&human), "denied");
        assert_eq!(decision_of(&rule), "forbidden");
    }

    #[test]
    fn the_decider_column_separates_no_policy_from_a_human_from_a_rule() {
        assert_eq!(
            decider_of(AuditDecision::approved(Decider::NoPolicy)),
            "default"
        );
        assert_eq!(
            decider_of(AuditDecision::approved(Decider::Callback)),
            "callback"
        );
        assert_eq!(
            decider_of(AuditDecision::approved(Decider::Allowlist)),
            "policy"
        );
    }

    #[test]
    fn a_refused_call_has_no_outcome_because_the_tool_never_ran() {
        assert_eq!(
            outcome_of(&AuditOutcome::Denied {
                reason: "no".to_string()
            }),
            None
        );
        assert_eq!(outcome_of(&success()), Some("success"));
        assert_eq!(
            outcome_of(&AuditOutcome::Error {
                message: "boom".to_string()
            }),
            Some("error")
        );
        assert_eq!(
            outcome_of(&AuditOutcome::Uncertain {
                message: "unknown".to_string()
            }),
            Some("aborted")
        );
    }

    #[test]
    fn only_the_tools_the_sandbox_confines_are_reported_sandboxed() {
        let shell = sealed(record(
            "bash",
            json!({}),
            success(),
            AuditDecision::approved(Decider::Rules),
        ));
        let reader = sealed(record(
            "read_file",
            json!({}),
            success(),
            AuditDecision::approved(Decider::Rules),
        ));

        assert_eq!(project(&shell, &context())["sandboxed"], json!(true));
        assert_eq!(project(&reader, &context())["sandboxed"], json!(false));
    }

    #[test]
    fn no_tool_is_reported_sandboxed_when_this_daemon_runs_without_one() {
        let entry = sealed(record(
            "bash",
            json!({}),
            success(),
            AuditDecision::approved(Decider::Rules),
        ));
        let mut context = context();
        context.sandbox_enabled = false;

        assert_eq!(project(&entry, &context)["sandboxed"], json!(false));
    }

    fn projection_of(entry: &AuditEntry, install: &str) -> EventProjection {
        EventProjection {
            chain_seq: entry.sequence as i64,
            entry_hash: entry.hash.clone(),
            prev_hash: entry.prev_hash.clone(),
            install: install.to_string(),
        }
    }

    #[test]
    fn columns_that_match_the_sealed_entry_raise_no_disagreement() {
        let entry = sealed(record(
            "bash",
            json!({}),
            success(),
            AuditDecision::approved(Decider::Rules),
        ));

        assert_eq!(
            projection_disagreement(
                &entry,
                &projection_of(&entry, "agentinstall_01"),
                "agentinstall_01"
            ),
            None
        );
    }

    #[test]
    fn a_row_whose_hash_column_disagrees_with_its_entry_is_named() {
        let entry = sealed(record(
            "bash",
            json!({}),
            success(),
            AuditDecision::approved(Decider::Rules),
        ));
        let mut projection = projection_of(&entry, "agentinstall_01");
        projection.entry_hash = "deadbeef".to_string();

        let disagreement = projection_disagreement(&entry, &projection, "agentinstall_01")
            .expect("a disagreement");

        assert!(disagreement.contains("entry_hash"), "{disagreement}");
    }

    #[test]
    fn a_row_shipped_into_another_installs_trail_is_named() {
        let entry = sealed(record(
            "bash",
            json!({}),
            success(),
            AuditDecision::approved(Decider::Rules),
        ));
        let projection = projection_of(&entry, "agentinstall_intruder");

        let disagreement = projection_disagreement(&entry, &projection, "agentinstall_01")
            .expect("a disagreement");

        assert!(
            disagreement.contains("agentinstall_intruder"),
            "{disagreement}"
        );
    }

    #[test]
    fn a_negative_sequence_column_is_a_disagreement_rather_than_a_wrap_around() {
        let entry = sealed(record(
            "bash",
            json!({}),
            success(),
            AuditDecision::approved(Decider::Rules),
        ));
        let mut projection = projection_of(&entry, "agentinstall_01");
        projection.chain_seq = -1;

        assert!(projection_disagreement(&entry, &projection, "agentinstall_01").is_some());
    }
}
