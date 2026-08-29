//! The identity every stored session is written under.
//!
//! acton-ai's store owns conversations by [`AgentId`]. Garrison mints one per
//! install and keeps it, for the same reason the install id is kept: an agent
//! that minted a fresh identity on each boot would leave every previous
//! process's sessions orphaned in a database it can still read but no longer
//! recognizes.
//!
//! It lives beside the install key and the install record, in the config
//! directory, because it is part of what this installation *is* rather than
//! part of what it has done.

use crate::error::GarrisonError;
use acton_ai::types::AgentId;
use std::path::{Path, PathBuf};

/// What a session opened over the daemon's socket is recorded as.
///
/// One of `AgentSession.client`'s values in `schemas/fleet.schema`. Named
/// here rather than spelled out at each call site so the fleet view and the
/// local store never disagree about what opened a session.
pub const CLIENT_SOCKET: &str = "socket";

/// What a session opened by the bundled terminal client is recorded as.
pub const CLIENT_CLI: &str = "cli";

/// The agent id file's place under the Garrison config directory.
#[must_use]
pub fn agent_id_path(config_dir: &Path) -> PathBuf {
    config_dir.join("agent-id")
}

/// Reads this install's agent id, minting and recording one on first run.
///
/// A file that exists and cannot be read or parsed is an error rather than a
/// reason to mint a replacement: a new identity would silently orphan every
/// session this install has ever stored, which is exactly the loss the file
/// exists to prevent.
///
/// # Errors
///
/// [`GarrisonErrorKind::Store`](crate::error::GarrisonErrorKind::Store) when
/// the file is present but unusable, or when a new one cannot be written.
pub fn load_or_create_agent_id(config_dir: &Path) -> Result<AgentId, GarrisonError> {
    let path = agent_id_path(config_dir);

    match std::fs::read_to_string(&path) {
        Ok(text) => AgentId::parse(text.trim()).map_err(|error| {
            GarrisonError::store(
                "read its agent identity",
                format!(
                    "'{}' does not hold one ({error}). Move it aside to mint a fresh identity, \
                     which orphans every session stored under the old one",
                    path.display()
                ),
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => write_new(&path),
        Err(error) => Err(GarrisonError::store(
            "read its agent identity",
            format!("'{}' could not be read: {error}", path.display()),
        )),
    }
}

/// Mints an identity and records it before returning it.
fn write_new(path: &Path) -> Result<AgentId, GarrisonError> {
    let agent_id = AgentId::new();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            GarrisonError::store(
                "record its agent identity",
                format!("'{}' could not be created: {error}", parent.display()),
            )
        })?;
    }

    std::fs::write(path, format!("{agent_id}\n")).map_err(|error| {
        GarrisonError::store(
            "record its agent identity",
            format!("'{}' could not be written: {error}", path.display()),
        )
    })?;

    tracing::info!(agent_id = %agent_id, path = %path.display(), "minted this install's session identity");
    Ok(agent_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_first_run_mints_an_identity_and_writes_it_down() {
        let dir = tempfile::tempdir().expect("a temp dir");

        let minted = load_or_create_agent_id(dir.path()).expect("mints on first run");

        assert!(agent_id_path(dir.path()).exists());
        assert!(minted.to_string().starts_with("agent_"));
    }

    #[test]
    fn every_later_run_reads_the_same_identity_back() {
        let dir = tempfile::tempdir().expect("a temp dir");

        let first = load_or_create_agent_id(dir.path()).expect("mints");
        let second = load_or_create_agent_id(dir.path()).expect("reads back");

        assert_eq!(first, second, "a restart must not orphan stored sessions");
    }

    #[test]
    fn a_corrupt_identity_file_is_refused_rather_than_replaced() {
        let dir = tempfile::tempdir().expect("a temp dir");
        std::fs::write(
            agent_id_path(dir.path()),
            "thread_01h455vb4pex5vsknk084sn02q\n",
        )
        .expect("writes");

        let error = load_or_create_agent_id(dir.path()).expect_err("must refuse");

        assert!(error.to_string().contains("Move it aside"), "{error}");
    }

    #[test]
    fn the_identity_is_written_beside_the_install_record() {
        let dir = PathBuf::from("/home/agent/.config/garrison");

        assert_eq!(agent_id_path(&dir), dir.join("agent-id"));
    }
}
