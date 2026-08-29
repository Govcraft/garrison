//! The one way Garrison reaches the session database.
//!
//! acton-ai's `MemoryStore` actor owns the libSQL file that `[checkpoint]`
//! names: the `conversations`, `messages`, `sessions` and `turn_checkpoints`
//! tables, the schema, the migrations, and the writer's serialization.
//! Garrison never opens that file, never writes SQL, and never keeps a second
//! copy of what is in it. [`SessionStore`] is a thin, cloneable facade whose
//! every method is one ask to that actor, translated into Garrison's error
//! type so a caller can say what failed without knowing what a
//! `PersistenceError` is.
//!
//! # Why a facade and not the handle
//!
//! Three reasons, all of them about being able to fail closed. The handle
//! alone would let any caller invent its own idea of what a session's name
//! is; here [`ids::session_name`](super::ids::session_name) is the only
//! answer. The handle alone answers with `Result<_, PersistenceError>` inside
//! a reply struct inside an `AskError`, three layers a caller would have to
//! unwrap identically every time and could unwrap wrongly once; here that
//! collapses to one `Result`. And the handle alone has no place to put the
//! `AgentId` every write needs, so each caller would carry one and they could
//! drift.
//!
//! # Why a compaction writes a new conversation
//!
//! A conversation in the store is append-only: there is a `SaveMessage` and
//! there is no way to remove one. Compaction rewrites a history in place,
//! replacing a prefix with a summary, so the shape a session ends up with is
//! not reachable by appending to the shape it had. [`SessionStore::rewrite`]
//! is the answer: mint a fresh conversation, write the rewritten history into
//! it, point the session's metadata at it, and delete the old one. The
//! session's identity — its name, which is the ACP session id — never moves.

use crate::error::GarrisonError;
use crate::session::ids;
use crate::session::meta::{self, SessionMeta};
use crate::types::ThreadId;
use acton_ai::checkpoint::{CheckpointRecord, CheckpointStatus};
use acton_ai::memory::{
    CheckpointList, CheckpointLoaded, CheckpointSaved, ConversationCreated, ConversationLoaded,
    CreateConversation, CreateSession, DeleteCheckpoint, DeleteConversation, DeleteSession,
    ListCheckpoints, ListSessions, LoadCheckpoint, LoadConversation, MessageSaved,
    OperationCompleted, ResolveSession, SaveCheckpoint, SaveMessage, SessionCreated, SessionInfo,
    SessionList, SessionResolved, TouchSession, UpdateSessionMetadata,
};
use acton_ai::messages::Message;
use acton_ai::types::{AgentId, CheckpointId, ConversationId};
use acton_reactive::prelude::*;

/// One session as the store holds it, with its metadata already read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSession {
    /// The session's name, which is the ACP session id.
    pub name: String,
    /// Everything Garrison recorded about it.
    pub meta: SessionMeta,
    /// When the store created it.
    pub created_at: String,
    /// When it was last touched.
    pub last_active: String,
}

/// How the turns this daemon has checkpointed stand, counted by state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheckpointTally {
    /// Turns whose records say they were still running.
    pub in_progress: usize,
    /// Turns that ended in an error and could be resumed.
    pub failed: usize,
    /// Turns that produced an answer nobody has claimed yet.
    pub completed: usize,
    /// Turns an operator declined to resume.
    pub abandoned: usize,
}

/// Counts a set of records by state. Pure.
#[must_use]
pub fn tally(records: &[CheckpointRecord]) -> CheckpointTally {
    records
        .iter()
        .fold(CheckpointTally::default(), |mut tally, record| {
            match record.status {
                CheckpointStatus::InProgress => tally.in_progress += 1,
                CheckpointStatus::Failed => tally.failed += 1,
                CheckpointStatus::Completed => tally.completed += 1,
                CheckpointStatus::Abandoned => tally.abandoned += 1,
            }
            tally
        })
}

/// Garrison's access to the stored half of a session.
#[derive(Clone, Debug)]
pub struct SessionStore {
    store: ActorHandle,
    agent_id: AgentId,
}

impl SessionStore {
    /// Wraps the store actor `[checkpoint]` spawned.
    #[must_use]
    pub const fn new(store: ActorHandle, agent_id: AgentId) -> Self {
        Self { store, agent_id }
    }

    /// The store actor itself, for the one caller that needs it: a prompt
    /// builder's `.checkpoint(store, id)`, which takes the handle because
    /// acton-ai's own loop does the writing.
    #[must_use]
    pub const fn handle(&self) -> &ActorHandle {
        &self.store
    }

    /// The identity every conversation and session this daemon writes is
    /// owned by.
    #[must_use]
    pub const fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// Creates the stored half of a new session and returns its conversation.
    ///
    /// The store mints the conversation; the caller puts it into the metadata
    /// it then writes with [`Self::write_meta`], because the conversation a
    /// session's history lives in can move and the one the store minted is
    /// only ever the first.
    ///
    /// # Errors
    ///
    /// [`GarrisonErrorKind::Store`](crate::error::GarrisonErrorKind::Store)
    /// when the store cannot be asked, or refuses — a name collision is a
    /// refusal, because two sessions with one id is not something to paper
    /// over.
    pub async fn create(
        &self,
        thread_id: &ThreadId,
        system_prompt: Option<String>,
    ) -> Result<ConversationId, GarrisonError> {
        let created: SessionCreated = self
            .ask(
                CreateSession {
                    name: ids::session_name(thread_id),
                    agent_id: self.agent_id.clone(),
                    system_prompt,
                    metadata: None,
                },
                "create a session",
            )
            .await?;

        created
            .result
            .map_err(|error| GarrisonError::store("create a session", error.to_string()))
    }

    /// Replaces a session's recorded metadata.
    ///
    /// # Errors
    ///
    /// As [`Self::create`]. A session that is not there is a failure, not a
    /// no-op: a caller keeping state for a session it believes exists needs
    /// to learn that it does not.
    pub async fn write_meta(
        &self,
        thread_id: &ThreadId,
        meta: &SessionMeta,
    ) -> Result<(), GarrisonError> {
        let encoded = meta::encode(meta)?;
        let completed: OperationCompleted = self
            .ask(
                UpdateSessionMetadata {
                    name: ids::session_name(thread_id),
                    metadata: Some(encoded),
                },
                "record a session's state",
            )
            .await?;

        completed
            .result
            .map_err(|error| GarrisonError::store("record a session's state", error.to_string()))
    }

    /// Looks a session up by its ACP id.
    ///
    /// `Ok(None)` means no session has that name. A stored session whose
    /// metadata this daemon cannot read is also `Ok(None)`: it is a session,
    /// but not one of Garrison's, and presenting it as loadable would offer a
    /// client a session with no root to check and no history shape to trust.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub async fn resolve(
        &self,
        thread_id: &ThreadId,
    ) -> Result<Option<StoredSession>, GarrisonError> {
        let resolved: SessionResolved = self
            .ask(
                ResolveSession {
                    name: ids::session_name(thread_id),
                },
                "resolve a session",
            )
            .await?;

        let found = resolved
            .result
            .map_err(|error| GarrisonError::store("resolve a session", error.to_string()))?;

        Ok(found.and_then(|info| stored_session(&info)))
    }

    /// Every session this store holds, most recently active first.
    ///
    /// Sessions whose metadata this daemon cannot read are left out, for the
    /// reason [`Self::resolve`] gives.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub async fn list(&self) -> Result<Vec<StoredSession>, GarrisonError> {
        let listed: SessionList = self.ask(ListSessions, "list sessions").await?;

        let sessions = listed
            .result
            .map_err(|error| GarrisonError::store("list sessions", error.to_string()))?;

        Ok(sessions.iter().filter_map(stored_session).collect())
    }

    /// Marks a session active now.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub async fn touch(&self, thread_id: &ThreadId) -> Result<(), GarrisonError> {
        let completed: OperationCompleted = self
            .ask(
                TouchSession {
                    name: ids::session_name(thread_id),
                },
                "touch a session",
            )
            .await?;

        completed
            .result
            .map_err(|error| GarrisonError::store("touch a session", error.to_string()))
    }

    /// Deletes a session, its conversation, and every message in it.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub async fn delete(&self, name: &str) -> Result<(), GarrisonError> {
        let completed: OperationCompleted = self
            .ask(
                DeleteSession {
                    name: name.to_string(),
                },
                "delete a session",
            )
            .await?;

        completed
            .result
            .map_err(|error| GarrisonError::store("delete a session", error.to_string()))
    }

    /// The messages of one conversation, oldest first.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub async fn history(
        &self,
        conversation: &ConversationId,
    ) -> Result<Vec<Message>, GarrisonError> {
        let loaded: ConversationLoaded = self
            .ask(
                LoadConversation {
                    conversation_id: conversation.clone(),
                },
                "load a session's history",
            )
            .await?;

        loaded
            .result
            .map_err(|error| GarrisonError::store("load a session's history", error.to_string()))
    }

    /// Appends messages to a conversation, in order.
    ///
    /// Awaited one at a time rather than fired off together: the store
    /// serializes writes on its own message loop, but a caller that did not
    /// wait could not tell which of them failed, and a half-written exchange
    /// is exactly the state this whole module exists to make impossible.
    ///
    /// # Errors
    ///
    /// As [`Self::create`], on the first message that does not land.
    pub async fn append(
        &self,
        conversation: &ConversationId,
        messages: &[Message],
    ) -> Result<(), GarrisonError> {
        for message in messages {
            let saved: MessageSaved = self
                .ask(
                    SaveMessage {
                        conversation_id: conversation.clone(),
                        message: message.clone(),
                    },
                    "append to a session's history",
                )
                .await?;

            saved.result.map_err(|error| {
                GarrisonError::store("append to a session's history", error.to_string())
            })?;
        }
        Ok(())
    }

    /// Replaces a session's whole history with `history`, in a fresh
    /// conversation.
    ///
    /// What compaction needs: the summarized history is not an append onto
    /// the old one, so it goes into a new conversation and the session's
    /// metadata is re-pointed at it. The old conversation is deleted last, so
    /// a failure anywhere before that leaves the session still pointing at a
    /// history that exists.
    ///
    /// Returns the conversation the caller must now hold.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub async fn rewrite(
        &self,
        thread_id: &ThreadId,
        meta: &SessionMeta,
        history: &[Message],
    ) -> Result<ConversationId, GarrisonError> {
        let created: ConversationCreated = self
            .ask(
                CreateConversation {
                    agent_id: self.agent_id.clone(),
                },
                "rewrite a session's history",
            )
            .await?;

        let fresh = created.result.map_err(|error| {
            GarrisonError::store("rewrite a session's history", error.to_string())
        })?;

        self.append(&fresh, history).await?;

        let previous = meta.conversation.clone();
        let mut repointed = meta.clone();
        repointed.conversation = fresh.clone();
        self.write_meta(thread_id, &repointed).await?;

        // Last, and its failure is not the caller's problem: the session is
        // already correct, and an orphaned conversation is disk, not damage.
        let dropped: Result<OperationCompleted, GarrisonError> = self
            .ask(
                DeleteConversation {
                    conversation_id: previous,
                },
                "drop a rewritten conversation",
            )
            .await;
        if let Err(error) = dropped {
            tracing::warn!(%error, "a compacted session left its previous conversation behind");
        }

        Ok(fresh)
    }

    /// The record a turn's progress was written under, if there is one.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub async fn checkpoint(
        &self,
        id: &CheckpointId,
    ) -> Result<Option<CheckpointRecord>, GarrisonError> {
        let loaded: CheckpointLoaded = self
            .ask(LoadCheckpoint { id: id.clone() }, "load a turn's progress")
            .await?;

        loaded
            .result
            .map_err(|error| GarrisonError::store("load a turn's progress", error.to_string()))
    }

    /// Every checkpoint in the store, whatever its state.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub async fn checkpoints(&self) -> Result<Vec<CheckpointRecord>, GarrisonError> {
        let listed: CheckpointList = self
            .ask(ListCheckpoints { status: None }, "list turn progress")
            .await?;

        listed
            .result
            .map_err(|error| GarrisonError::store("list turn progress", error.to_string()))
    }

    /// Writes a record back as abandoned, closing it to further resumes.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub async fn abandon_checkpoint(&self, record: CheckpointRecord) -> Result<(), GarrisonError> {
        let saved: CheckpointSaved = self
            .ask(
                SaveCheckpoint {
                    record: acton_ai::checkpoint::abandon(record),
                },
                "abandon a turn",
            )
            .await?;

        saved
            .result
            .map_err(|error| GarrisonError::store("abandon a turn", error.to_string()))
    }

    /// Removes a checkpoint. Removing one that is not there succeeds.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub async fn delete_checkpoint(&self, id: &CheckpointId) -> Result<(), GarrisonError> {
        let completed: OperationCompleted = self
            .ask(
                DeleteCheckpoint { id: id.clone() },
                "delete a turn's progress",
            )
            .await?;

        completed
            .result
            .map_err(|error| GarrisonError::store("delete a turn's progress", error.to_string()))
    }

    /// One ask, with the store's silence turned into words.
    async fn ask<R>(&self, request: R, operation: &str) -> Result<R::Response, GarrisonError>
    where
        R: Request + 'static,
    {
        self.store.ask(request).await.map_err(|error| {
            GarrisonError::store(operation, format!("the store did not answer ({error:?})"))
        })
    }
}

/// One stored session, with its metadata read. `None` when it is not
/// Garrison's to load.
fn stored_session(info: &SessionInfo) -> Option<StoredSession> {
    match meta::decode(info.metadata.as_deref()) {
        Ok(meta) => Some(StoredSession {
            name: info.name.clone(),
            meta,
            created_at: info.created_at.clone(),
            last_active: info.last_active.clone(),
        }),
        Err(error) => {
            tracing::debug!(
                session = %info.name,
                %error,
                "leaving out a stored session this agent did not write",
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acton_ai::checkpoint::TurnFingerprint;

    /// A checkpoint in a given state.
    ///
    /// The fingerprint is a constant because nothing here reads it: what is
    /// under test is the status and the identity, and the identity is minted
    /// fresh on every call. Two records built here are distinguishable
    /// because their [`CheckpointId`]s differ, never because their inputs do.
    fn record(status: CheckpointStatus) -> CheckpointRecord {
        let mut record = CheckpointRecord::opening(
            CheckpointId::new(),
            None,
            TurnFingerprint::from_hex("00"),
            vec![],
        );
        record.status = status;
        record
    }

    #[test]
    fn nothing_stored_tallies_to_nothing() {
        assert_eq!(tally(&[]), CheckpointTally::default());
    }

    #[test]
    fn every_state_is_counted_under_its_own_name() {
        let records = [
            record(CheckpointStatus::InProgress),
            record(CheckpointStatus::InProgress),
            record(CheckpointStatus::Failed),
            record(CheckpointStatus::Completed),
            record(CheckpointStatus::Abandoned),
        ];

        assert_eq!(
            tally(&records),
            CheckpointTally {
                in_progress: 2,
                failed: 1,
                completed: 1,
                abandoned: 1,
            }
        );
    }

    #[test]
    fn a_stored_session_without_garrisons_metadata_is_not_offered_as_loadable() {
        let info = SessionInfo {
            name: "thread_a".to_string(),
            conversation_id: ConversationId::new(),
            agent_id: AgentId::new(),
            system_prompt: None,
            created_at: "2026-06-01 09:00:00".to_string(),
            last_active: "2026-06-01 09:00:00".to_string(),
            message_count: 0,
            metadata: None,
        };

        assert!(
            stored_session(&info).is_none(),
            "acton-ai's own CLI sessions are not Garrison sessions",
        );
    }

    #[test]
    fn a_stored_session_this_agent_wrote_reads_back_whole() {
        let meta = SessionMeta::opening(
            ConversationId::new(),
            std::path::PathBuf::from("/srv/work"),
            crate::session::CLIENT_SOCKET,
        );
        let info = SessionInfo {
            name: "thread_a".to_string(),
            conversation_id: meta.conversation.clone(),
            agent_id: AgentId::new(),
            system_prompt: None,
            created_at: "2026-06-01 09:00:00".to_string(),
            last_active: "2026-06-02 09:00:00".to_string(),
            message_count: 4,
            metadata: Some(meta::encode(&meta).expect("encodes")),
        };

        let stored = stored_session(&info).expect("reads back");

        assert_eq!(stored.name, "thread_a");
        assert_eq!(stored.meta, meta);
        assert_eq!(stored.last_active, "2026-06-02 09:00:00");
    }
}
