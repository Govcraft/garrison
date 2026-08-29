//! Translating between Garrison's identifiers and acton-ai's.
//!
//! Two identity systems meet at the session store. Garrison names a session
//! with a [`ThreadId`] and a turn with a [`TurnId`]; acton-ai names a stored
//! session by an arbitrary string and a resumable turn with a
//! [`CheckpointId`]. Both are TypeIDs — a prefix, an underscore, and the
//! base32 spelling of a UUIDv7 — so the translation is a prefix swap and
//! nothing else.
//!
//! # Why a swap rather than a mapping table
//!
//! A checkpoint is the key a resume looks saved progress up by, and the
//! resume happens in a *different process* to the one that wrote it. A table
//! would have to survive the restart too, which makes it one more thing that
//! can be lost at exactly the moment the checkpoint is needed. Deriving the
//! checkpoint's name from the turn's means a daemon that knows a turn id
//! knows where its progress is, with nothing else read from anywhere.
//!
//! Every function here is pure.

use crate::types::{ThreadId, TurnId};
use acton_ai::types::CheckpointId;

/// A TypeID could not be re-spelled with a different prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntranslatableId {
    /// The identifier that could not be translated, as it was given.
    pub given: String,
    /// The prefix the translation was aiming for.
    pub wanted: &'static str,
}

impl std::fmt::Display for UntranslatableId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "'{}' cannot be re-spelled as a '{}' identifier",
            self.given, self.wanted
        )
    }
}

impl std::error::Error for UntranslatableId {}

/// The part of a TypeID after its prefix, or `None` if there is no prefix.
fn suffix(id: &str) -> Option<&str> {
    id.split_once('_').map(|(_, suffix)| suffix)
}

/// The checkpoint one Garrison turn records its progress under.
///
/// # Errors
///
/// [`UntranslatableId`] if the turn identifier is not a prefixed TypeID,
/// which a [`TurnId`] built through its own constructor never is.
pub fn checkpoint_id_for(turn_id: &TurnId) -> Result<CheckpointId, UntranslatableId> {
    let text = turn_id.to_string();
    let translated = suffix(&text)
        .map(|suffix| format!("{}_{suffix}", CheckpointId::PREFIX))
        .ok_or_else(|| UntranslatableId {
            given: text.clone(),
            wanted: CheckpointId::PREFIX,
        })?;

    CheckpointId::parse(&translated).map_err(|_| UntranslatableId {
        given: text,
        wanted: CheckpointId::PREFIX,
    })
}

/// The Garrison turn a checkpoint belongs to.
///
/// The inverse of [`checkpoint_id_for`], so a record found in the store after
/// a restart can name the turn a client was waiting on.
///
/// # Errors
///
/// [`UntranslatableId`] if the checkpoint identifier is not a prefixed
/// TypeID.
pub fn turn_id_for(checkpoint: &CheckpointId) -> Result<TurnId, UntranslatableId> {
    let text = checkpoint.to_string();
    let translated = suffix(&text)
        .map(|suffix| format!("{}_{suffix}", TurnId::PREFIX))
        .ok_or_else(|| UntranslatableId {
            given: text.clone(),
            wanted: TurnId::PREFIX,
        })?;

    TurnId::parse(&translated).map_err(|_| UntranslatableId {
        given: text,
        wanted: TurnId::PREFIX,
    })
}

/// The name a session is stored under.
///
/// The thread's own identifier, spelled out. Stored sessions are keyed by a
/// name of the embedder's choosing, and using anything but the identity the
/// protocol already speaks would mean a second thing to keep in step.
#[must_use]
pub fn session_name(thread_id: &ThreadId) -> String {
    thread_id.to_string()
}

/// Garrison's turn identity, in the form acton-ai's prompt loop takes.
///
/// Both crates prefix a turn `turn`, so this is a re-parse rather than a
/// swap: nothing about the identifier changes. It exists so every
/// `TurnLifecycle` broadcast, every audit entry and every checkpoint row
/// carries the identifier the client already saw in `_meta.garrison.turnId`,
/// instead of one the prompt loop minted for itself and never disclosed.
///
/// # Errors
///
/// [`UntranslatableId`] if the identifier is not one acton-ai will accept,
/// which a [`TurnId`] built through its own constructor never is.
pub fn acton_turn_id(turn_id: &TurnId) -> Result<acton_ai::types::TurnId, UntranslatableId> {
    let text = turn_id.to_string();
    acton_ai::types::TurnId::parse(&text).map_err(|_| UntranslatableId {
        given: text,
        wanted: acton_ai::types::TurnId::PREFIX,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_turn_and_its_checkpoint_name_the_same_moment() {
        let turn = TurnId::new();
        let checkpoint = checkpoint_id_for(&turn).expect("a turn id translates");

        assert!(checkpoint.to_string().starts_with("ckpt_"));
        assert_eq!(
            checkpoint.to_string().split_once('_').map(|split| split.1),
            turn.to_string().split_once('_').map(|split| split.1),
            "the two names differ only in what they say they are",
        );
    }

    #[test]
    fn the_translation_round_trips() {
        let turn = TurnId::new();
        let checkpoint = checkpoint_id_for(&turn).expect("a turn id translates");

        assert_eq!(turn_id_for(&checkpoint).expect("and back again"), turn);
    }

    #[test]
    fn two_turns_never_share_a_checkpoint() {
        let first = checkpoint_id_for(&TurnId::new()).expect("translates");
        let second = checkpoint_id_for(&TurnId::new()).expect("translates");

        assert_ne!(first, second);
    }

    #[test]
    fn a_session_is_stored_under_the_name_the_protocol_uses() {
        let thread = ThreadId::new();

        assert_eq!(session_name(&thread), thread.to_string());
    }

    #[test]
    fn an_unprefixed_identifier_is_refused_rather_than_guessed_at() {
        assert_eq!(suffix("nothing-here"), None);
    }

    #[test]
    fn the_prompt_loop_is_handed_garrisons_own_turn_identity() {
        let turn = TurnId::new();

        let acton = acton_turn_id(&turn).expect("both crates prefix a turn 'turn'");

        assert_eq!(acton.to_string(), turn.to_string());
    }
}
