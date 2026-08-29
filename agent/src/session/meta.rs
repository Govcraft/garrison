//! What Garrison keeps about a stored session, beyond its messages.
//!
//! acton-ai's store holds a session's name, its conversation, and one opaque
//! `metadata` string it never reads. That string is this: everything the
//! daemon has to know about a session before it will hand it back after a
//! restart, and nothing that could be derived from the messages themselves.
//!
//! # Why the field names are the plane's
//!
//! They mirror `AgentSession` in `schemas/fleet.schema` — `project_root`,
//! `client`, `organization`, `status`, `turns`, `input_tokens`,
//! `output_tokens`. A session that survives a restart is the same session the
//! fleet view is reporting on, and two spellings of one fact are two facts
//! that can disagree.
//!
//! # Why the conversation is here as well
//!
//! The store mints a conversation when a session is created and never lets
//! that pointer be moved. Compaction rewrites a history in place — a prefix
//! of messages becomes one summary — and the only way to store a rewritten
//! history through an append-only conversation is to write a fresh one and
//! point at that. So the conversation Garrison reads back is the one named
//! here, not the one the store minted; see
//! [`SessionStore::rewrite`](super::store::SessionStore::rewrite).
//!
//! Everything in this module is pure.

use crate::error::GarrisonError;
use crate::types::TurnId;
use acton_ai::types::ConversationId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The metadata layout this daemon writes and understands.
///
/// Bumped when a field's meaning changes, never when one is added. A session
/// written by a newer daemon is left alone rather than reinterpreted; see
/// [`decode`].
pub const SCHEMA: u32 = 1;

/// How a stored session stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Usable: it can be loaded, and prompted.
    #[default]
    Open,
    /// Loadable, but not promptable until the operator says what to do with
    /// the turn a restart interrupted.
    Degraded,
    /// Finished. Kept for the record until retention sweeps it.
    Closed,
}

/// A turn that was running when its record was last written.
///
/// Its presence after a restart is the whole of the interrupted-turn
/// detection: the daemon that started the turn clears this when the turn
/// ends, however it ends, so a record that still names one is a record whose
/// writer did not survive to clear it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenTurn {
    /// The turn Garrison announced to the client.
    pub turn_id: TurnId,
    /// When it started, RFC 3339.
    pub started_at: String,
    /// What the operator asked for, kept so a resumed turn can be replayed to
    /// a client that never saw the prompt land.
    pub content: String,
}

/// Who a session belongs to, as far as the control plane is concerned.
///
/// Settled once at launch and stamped onto every session this daemon opens,
/// so a `AgentSession` row shipped to the fleet view later carries the tenant
/// chain it needs. A row written without one lands unattributed and is
/// invisible to a tenant-scoped reader, which is why this travels with the
/// session rather than being looked up when it is wanted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attribution {
    /// The plane's row id for this install.
    pub install: Option<String>,
    /// The tenant the install belongs to.
    pub organization: Option<String>,
    /// The operator it answers for, as a userPrincipalName.
    pub operator_upn: Option<String>,
}

/// Everything Garrison stores about a session that is not one of its
/// messages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionMeta {
    /// The layout this record was written in. See [`SCHEMA`].
    pub schema: u32,
    /// The conversation the session's history actually lives in.
    pub conversation: ConversationId,
    /// The directory the session is rooted at, canonical.
    pub project_root: PathBuf,
    /// Which kind of client opened it, as the fleet view spells it.
    pub client: String,
    /// The plane's row id for this install, when the daemon is enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<String>,
    /// The tenant the install belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// The operator the install answers for, as a userPrincipalName.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_upn: Option<String>,
    /// How the session stands.
    pub status: SessionStatus,
    /// The turn in flight when this was written, if there was one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_turn: Option<OpenTurn>,
    /// How many turns have completed.
    pub turns: u64,
    /// Tokens sent, over the session's whole life.
    pub input_tokens: u64,
    /// Tokens received, likewise.
    pub output_tokens: u64,
}

impl SessionMeta {
    /// A fresh session's metadata.
    #[must_use]
    pub fn opening(conversation: ConversationId, project_root: PathBuf, client: &str) -> Self {
        Self {
            schema: SCHEMA,
            conversation,
            project_root,
            client: client.to_string(),
            install: None,
            organization: None,
            operator_upn: None,
            status: SessionStatus::Open,
            open_turn: None,
            turns: 0,
            input_tokens: 0,
            output_tokens: 0,
        }
    }

    /// The same metadata, attributed to the install that wrote it.
    #[must_use]
    pub fn attributed(mut self, attribution: &Attribution) -> Self {
        self.install.clone_from(&attribution.install);
        self.organization.clone_from(&attribution.organization);
        self.operator_upn.clone_from(&attribution.operator_upn);
        self
    }

    /// Records that a turn is under way.
    pub fn open(&mut self, turn_id: TurnId, started_at: String, content: String) {
        self.open_turn = Some(OpenTurn {
            turn_id,
            started_at,
            content,
        });
    }

    /// Records that the turn ended, whatever it produced.
    pub fn close_turn(&mut self, input_tokens: u64, output_tokens: u64) {
        self.open_turn = None;
        self.turns = self.turns.saturating_add(1);
        self.input_tokens = self.input_tokens.saturating_add(input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(output_tokens);
    }

    /// Whether a turn this record names was interrupted rather than finished.
    ///
    /// True of a record read back from the store, because the daemon that
    /// wrote it clears the turn when it ends. Never true of a record this
    /// process is holding for a turn it is running: that one is live.
    #[must_use]
    pub const fn interrupted(&self) -> Option<&OpenTurn> {
        self.open_turn.as_ref()
    }
}

/// The metadata as the store will hold it.
///
/// # Errors
///
/// [`GarrisonErrorKind::Store`](crate::error::GarrisonErrorKind::Store) when
/// the record cannot be encoded, which would mean a session whose state
/// could not be written down.
pub fn encode(meta: &SessionMeta) -> Result<String, GarrisonError> {
    serde_json::to_string(meta)
        .map_err(|error| GarrisonError::store("encode a session's metadata", error.to_string()))
}

/// The metadata a stored session was written with.
///
/// A record from a newer schema is refused rather than read: its fields may
/// mean something else, and a session silently reinterpreted is worse than a
/// session that will not load.
///
/// # Errors
///
/// [`GarrisonErrorKind::Store`](crate::error::GarrisonErrorKind::Store) when
/// the string is absent, unparseable, or written in a schema this daemon does
/// not know.
pub fn decode(metadata: Option<&str>) -> Result<SessionMeta, GarrisonError> {
    let text = metadata.ok_or_else(|| {
        GarrisonError::store(
            "read a session's metadata",
            "the stored session carries none, so it was not written by this agent",
        )
    })?;

    let meta: SessionMeta = serde_json::from_str(text)
        .map_err(|error| GarrisonError::store("read a session's metadata", error.to_string()))?;

    if meta.schema > SCHEMA {
        return Err(GarrisonError::store(
            "read a session's metadata",
            format!(
                "it was written in schema {} and this agent understands {SCHEMA}; \
                 upgrade the agent rather than loading it",
                meta.schema
            ),
        ));
    }

    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> SessionMeta {
        SessionMeta::opening(ConversationId::new(), PathBuf::from("/srv/work"), "socket")
    }

    #[test]
    fn a_new_session_has_no_turn_in_flight() {
        assert!(meta().interrupted().is_none());
    }

    #[test]
    fn metadata_survives_a_round_trip_through_the_store() {
        let original = meta().attributed(&Attribution {
            install: Some("inst_1".to_string()),
            organization: Some("org_1".to_string()),
            operator_upn: Some("kim@agency.gov".to_string()),
        });

        let encoded = encode(&original).expect("encodes");
        let decoded = decode(Some(&encoded)).expect("decodes");

        assert_eq!(decoded, original);
    }

    #[test]
    fn an_open_turn_names_the_turn_and_the_prompt_it_was_running() {
        let mut meta = meta();
        let turn = TurnId::new();

        meta.open(
            turn.clone(),
            "2026-01-01T00:00:00Z".to_string(),
            "go".into(),
        );

        let open = meta.interrupted().expect("a turn is in flight");
        assert_eq!(open.turn_id, turn);
        assert_eq!(open.content, "go");
    }

    #[test]
    fn closing_a_turn_clears_it_and_counts_what_it_cost() {
        let mut meta = meta();
        meta.open(TurnId::new(), "then".to_string(), "go".to_string());

        meta.close_turn(120, 45);

        assert!(meta.interrupted().is_none());
        assert_eq!(meta.turns, 1);
        assert_eq!(meta.input_tokens, 120);
        assert_eq!(meta.output_tokens, 45);
    }

    #[test]
    fn token_counts_accumulate_over_a_sessions_turns() {
        let mut meta = meta();

        meta.close_turn(10, 5);
        meta.close_turn(7, 3);

        assert_eq!(meta.turns, 2);
        assert_eq!(meta.input_tokens, 17);
        assert_eq!(meta.output_tokens, 8);
    }

    #[test]
    fn a_session_written_by_a_newer_agent_is_refused_rather_than_reinterpreted() {
        let mut original = meta();
        original.schema = SCHEMA + 1;
        let encoded = encode(&original).expect("encodes");

        let error = decode(Some(&encoded)).expect_err("a newer schema must not be read");

        assert!(error.to_string().contains("upgrade the agent"), "{error}");
    }

    #[test]
    fn a_session_somebody_else_wrote_is_not_mistaken_for_one_of_ours() {
        assert!(decode(None).is_err());
        assert!(decode(Some("not json")).is_err());
    }
}
