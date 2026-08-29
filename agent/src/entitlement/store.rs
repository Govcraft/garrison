//! The last verdict, kept across restarts.
//!
//! A daemon that restarts during a plane outage would otherwise start with no
//! standing at all, which is a refusal — correct, but needlessly harsh when
//! the plane said yes ten minutes ago and the organization allows four hours
//! of slack. The cache is what makes the grace window survive a restart.
//!
//! # Why it is not signed
//!
//! An earlier design signed the file with the install key. The key sits in
//! the same directory under the same uid, so anyone who can forge the file
//! can sign the forgery, and the signature would buy nothing but a false
//! sense of tamper-evidence. What actually bounds the damage is the grace
//! table: at `fedramp_high` elevated, `il4` elevated, `il5` and any level
//! this build does not recognize the window is zero, so a forged standing
//! entitles nothing at all. Above that, the next successful check overwrites
//! it and the plane's own `Seat` row is the record an auditor reads.
//!
//! The file is written 0600 for the same reason the install key is: it names
//! this machine's organization and operator, and that is nobody else's
//! business on a shared host.

use std::path::{Path, PathBuf};

use super::verdict::Standing;

/// The cache's name beside `install.json` and `install-key.pem`.
pub const STANDING_FILE: &str = "entitlement.json";

/// Where the cached standing lives under the Garrison config directory.
#[must_use]
pub fn standing_path(config_dir: &Path) -> PathBuf {
    config_dir.join(STANDING_FILE)
}

/// Reads the cached standing, or nothing.
///
/// Every failure is `None` with a warning rather than an error. A daemon that
/// refused to start over an unreadable cache would be refusing over a file
/// whose only purpose is to soften an outage, and the fail-closed answer to a
/// missing standing is already "refuse turns until the plane answers".
#[must_use]
pub fn load(path: &Path) -> Option<Standing> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "the cached seat standing could not be read");
            return None;
        }
    };

    match serde_json::from_str::<Standing>(&text) {
        Ok(standing) => Some(standing),
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "the cached seat standing was unreadable and is being ignored; the plane will \
                 be asked again"
            );
            None
        }
    }
}

/// Writes the standing at 0600, best effort.
///
/// Failing to cache a verdict never fails the check that produced it: the
/// daemon holds the standing in memory either way, and the only thing lost is
/// the grace window surviving a restart. It surfaces as a warning, and in
/// `_garrison/status` as nothing at all, because there is nothing an operator
/// should do about it except fix the directory.
pub fn save(path: &Path, standing: &Standing) {
    if let Err(error) = write(path, standing) {
        tracing::warn!(
            path = %path.display(),
            %error,
            "the seat standing could not be cached; a restart during an outage will refuse turns"
        );
    }
}

/// The write itself, so [`save`] is only about what a failure means.
fn write(path: &Path, standing: &Standing) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(standing)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    crate::enrollment::key::write_private(path, format!("{json}\n").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entitlement::verdict::{ImpactLevel, Refusal, Tier, Verdict};
    use chrono::{DateTime, Utc};

    fn standing() -> Standing {
        Standing {
            verdict: Verdict::Entitled {
                seat: "seat_01".to_string(),
                tier: Tier::Standard,
            },
            checked_at: DateTime::parse_from_rfc3339("2026-08-29T12:00:00Z")
                .expect("a fixed instant")
                .with_timezone(&Utc),
            grace_secs: 4 * 3600,
            impact: ImpactLevel::FedrampHigh,
        }
    }

    #[test]
    fn a_saved_standing_comes_back_exactly_as_it_went_in() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = standing_path(dir.path());

        save(&path, &standing());

        assert_eq!(load(&path), Some(standing()));
    }

    #[test]
    fn a_refusal_survives_the_cache_too() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = standing_path(dir.path());
        let mut refused = standing();
        refused.verdict = Verdict::Refused(Refusal::SeatRevoked {
            reason: "offboarded".to_string(),
            revoked_at: None,
        });

        save(&path, &refused);

        assert_eq!(load(&path), Some(refused));
    }

    #[test]
    fn a_machine_that_has_never_checked_has_no_standing() {
        let dir = tempfile::tempdir().expect("tempdir");

        assert_eq!(load(&standing_path(dir.path())), None);
    }

    #[test]
    fn a_corrupt_cache_is_ignored_rather_than_trusted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = standing_path(dir.path());
        std::fs::write(&path, "{ this is not json").expect("write");

        assert_eq!(load(&path), None);
    }

    #[test]
    fn the_cache_is_readable_by_its_owner_and_nobody_else() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = standing_path(dir.path());

        save(&path, &standing());

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_rewrite_over_a_world_readable_file_still_ends_up_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = standing_path(dir.path());
        std::fs::write(&path, "{}").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        save(&path, &standing());

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
