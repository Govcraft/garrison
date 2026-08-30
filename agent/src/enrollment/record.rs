//! The two files enrollment reads and writes: the packet in, the record out.
//!
//! # Why the packet carries one field
//!
//! The enrollment artifact is a PASETO **v4.local** token, which is symmetric:
//! it is encrypted with the plane's own key, so the daemon holding it cannot
//! read a single one of its claims. A machine has no business inspecting its
//! own grant, and it turns out it has no business naming it either.
//!
//! The packet used to carry the grant's public id beside the artifact, because
//! the plane's rule compared a submitted `token_id` against the artifact's
//! subject. It no longer does: the redemption hook takes the subject straight
//! from the authenticated principal, so the field is one the daemon cannot
//! express at all. That is the stronger property. A client that has no field
//! to put a token id in cannot present one grant while spending another, and
//! there is no mismatch left to refuse.
//!
//! What remains is the secret and nothing else, which is why the packet is
//! deleted the moment it has been spent.

use crate::error::GarrisonError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// What whoever provisioned this machine left for it to redeem.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    /// The PASETO artifact proving the daemon holds a grant.
    ///
    /// Which grant is the plane's to say, from the artifact's own subject.
    pub artifact: String,
}

impl Packet {
    /// Reads a packet from a TOML file.
    ///
    /// # Errors
    ///
    /// [`GarrisonErrorKind::Enrollment`](crate::error::GarrisonErrorKind::Enrollment)
    /// when the file cannot be read, cannot be parsed, or leaves the artifact
    /// blank. A packet with an empty artifact would fail at the plane with a
    /// 401 that says nothing useful; failing here names the file.
    pub fn read(path: &Path) -> Result<Self, GarrisonError> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            GarrisonError::enrollment(format!(
                "enrollment packet '{}' could not be read: {error}",
                path.display()
            ))
        })?;
        let packet: Self = toml::from_str(&text).map_err(|error| {
            GarrisonError::enrollment(format!(
                "enrollment packet '{}' could not be parsed: {error}",
                path.display()
            ))
        })?;
        packet.validate(path)?;
        Ok(packet)
    }

    fn validate(&self, path: &Path) -> Result<(), GarrisonError> {
        if self.artifact.trim().is_empty() {
            return Err(GarrisonError::enrollment(format!(
                "enrollment packet '{}' leaves 'artifact' empty",
                path.display()
            )));
        }
        Ok(())
    }

    /// Removes a spent packet, best effort.
    ///
    /// A single-use grant left lying on disk is a liability and nothing else:
    /// it has already been redeemed, so the only thing it can still do is leak.
    /// Failure to delete is a warning rather than an error, because the
    /// enrollment itself has already succeeded and unwinding it would be worse
    /// than a stale file.
    pub fn discard(path: &Path) {
        match std::fs::remove_file(path) {
            Ok(()) => tracing::info!(packet = %path.display(), "spent enrollment packet removed"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                packet = %path.display(),
                %error,
                "spent enrollment packet could not be removed; delete it by hand"
            ),
        }
    }
}

/// What a successful enrollment left behind, and what proves it happened.
///
/// Its presence is the whole "first run" test. There is no separate flag: a
/// daemon is enrolled if and only if it can read this file back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The identifier this daemon minted for itself and will keep.
    pub install_id: String,
    /// The plane's row id for the install.
    pub install: String,
    /// The plane's row id for the credential registered at enrollment.
    pub credential: String,
    /// The tenant the plane resolved for this machine.
    pub organization: String,
    /// The hostname reported at enrollment, kept so a rename is visible.
    pub hostname: String,
    /// When the plane decided, in its own words.
    pub enrolled_at: String,
}

impl Record {
    /// Reads the record, or `None` when this install has never enrolled.
    ///
    /// A missing file is the first-run case and not an error. A present but
    /// unreadable one *is* an error: silently re-enrolling over a corrupt
    /// record would spend a second grant and leave two installs in the fleet
    /// for one machine.
    ///
    /// # Errors
    ///
    /// [`GarrisonErrorKind::Enrollment`](crate::error::GarrisonErrorKind::Enrollment)
    /// when the file exists and cannot be read or parsed.
    pub fn read(path: &Path) -> Result<Option<Self>, GarrisonError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(GarrisonError::enrollment(format!(
                    "install record '{}' could not be read: {error}",
                    path.display()
                )))
            }
        };
        serde_json::from_str(&text).map(Some).map_err(|error| {
            GarrisonError::enrollment(format!(
                "install record '{}' could not be parsed: {error}. \
                 Move it aside to re-enroll, which will spend another grant.",
                path.display()
            ))
        })
    }

    /// Writes the record.
    ///
    /// # Errors
    ///
    /// [`GarrisonErrorKind::Enrollment`](crate::error::GarrisonErrorKind::Enrollment)
    /// when the file cannot be written. This is worth failing the start over:
    /// an enrollment that succeeded at the plane but left no record here would
    /// spend a fresh grant on the next boot.
    pub fn write(&self, path: &Path) -> Result<(), GarrisonError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                GarrisonError::enrollment(format!(
                    "'{}' could not be created: {error}",
                    parent.display()
                ))
            })?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|error| {
            GarrisonError::enrollment(format!("install record could not be encoded: {error}"))
        })?;
        std::fs::write(path, format!("{json}\n")).map_err(|error| {
            GarrisonError::enrollment(format!(
                "install record '{}' could not be written: {error}",
                path.display()
            ))
        })
    }
}

/// The install record's place under the Garrison config directory.
#[must_use]
pub fn record_path(config_dir: &Path) -> PathBuf {
    config_dir.join("install.json")
}

/// Where an enrollment packet is looked for when the config names no path.
#[must_use]
pub fn default_packet_path(config_dir: &Path) -> PathBuf {
    config_dir.join("enrollment.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            install_id: "inst_01h455vb4pex5vsknk084sn02q".into(),
            install: "agentinstall_01".into(),
            credential: "installcredential_01".into(),
            organization: "organization_01".into(),
            hostname: "ws-01".into(),
            enrolled_at: "2026-08-29T04:50:23.579Z".into(),
        }
    }

    #[test]
    fn a_record_round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = record_path(dir.path());
        record().write(&path).unwrap();

        assert_eq!(Record::read(&path).unwrap(), Some(record()));
    }

    #[test]
    fn a_missing_record_is_the_first_run_and_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Record::read(&record_path(dir.path())).unwrap(), None);
    }

    #[test]
    fn a_corrupt_record_refuses_rather_than_re_enrolling() {
        let dir = tempfile::tempdir().unwrap();
        let path = record_path(dir.path());
        std::fs::write(&path, b"{ this is not json").unwrap();

        let error = Record::read(&path).unwrap_err();
        assert!(error.to_string().contains("could not be parsed"));
        assert!(error.to_string().contains("spend another grant"));
    }

    #[test]
    fn a_packet_is_the_artifact_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let path = default_packet_path(dir.path());
        std::fs::write(&path, "artifact = \"v4.local.abc\"\n").unwrap();

        assert_eq!(Packet::read(&path).unwrap().artifact, "v4.local.abc");
    }

    #[test]
    fn a_packet_naming_a_token_is_refused_rather_than_ignored() {
        // `deny_unknown_fields` is what makes the format freeze mean anything.
        // A two-field packet left over from before this change fails here,
        // naming the file, rather than being silently half-read.
        let dir = tempfile::tempdir().unwrap();
        let path = default_packet_path(dir.path());
        std::fs::write(
            &path,
            "token_id = \"tok_7f3a\"\nartifact = \"v4.local.abc\"\n",
        )
        .unwrap();

        let error = Packet::read(&path).unwrap_err().to_string();
        assert!(error.contains("token_id"), "{error}");
        assert!(error.contains("enrollment.toml"), "{error}");
    }

    #[test]
    fn an_empty_artifact_names_the_file_and_the_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = default_packet_path(dir.path());
        std::fs::write(&path, "artifact = \"\"\n").unwrap();

        let error = Packet::read(&path).unwrap_err();
        assert!(error.to_string().contains("'artifact' empty"));
        assert!(error.to_string().contains("enrollment.toml"));
    }

    #[test]
    fn a_spent_packet_is_removed_and_removing_a_gone_one_is_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let path = default_packet_path(dir.path());
        std::fs::write(&path, "artifact = \"a\"\n").unwrap();

        Packet::discard(&path);
        assert!(!path.exists());
        Packet::discard(&path);
    }
}
