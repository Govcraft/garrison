//! The bundle this install last verified, kept where a restart can find it.
//!
//! # What the cache is for
//!
//! A daemon that could only run while the plane answered would be a daemon
//! that stops working when a VPN drops, which is how governance gets turned
//! off in practice. So the last bundle that passed every check is written to
//! disk, and a daemon that cannot reach the plane keeps enforcing it for as
//! long as the organization allows.
//!
//! # What the cache is not
//!
//! It is not a second source of policy. It holds exactly what the plane sent,
//! it is re-verified against its own checksum every time it is read, and it
//! carries the moment it was fetched so the grace window is measured from
//! when the plane last spoke rather than from when this process started.
//! Restarting the daemon does not buy another day of offline operation.
//!
//! # The residual risk, stated
//!
//! The file is 0600 and owned by the user the daemon runs as. Someone with
//! that uid can rewrite the bundle *and* its checksum consistently, and this
//! module would accept it. That is not a hole this file can close: the same
//! uid could edit `garrison.toml`, or run a different binary. What closes it
//! is the plane. The install writes the checksum it is running to its
//! `AgentInstall` row, and a row whose checksum is not the bundle the plane
//! assigned is drift somebody can see. The cache buys availability, not
//! integrity.

use chrono::{DateTime, Utc};
use garrison_policy::Bundle;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A verified bundle and when the plane handed it over.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cached {
    /// When this was pulled. The grace window is measured from here.
    pub fetched_at: DateTime<Utc>,
    /// The `AgentInstall` row it was pulled for.
    ///
    /// A cache written by a different install is not this install's policy;
    /// see [`Cached::belongs_to`].
    pub install: String,
    /// The bundle itself, checksum included.
    pub bundle: Bundle,
}

impl Cached {
    /// Whether this cache was written by the install now reading it.
    #[must_use]
    pub fn belongs_to(&self, install: &str) -> bool {
        self.install == install
    }
}

/// Why a cached bundle could not be used.
///
/// Every variant means the same thing to a caller (there is no bundle here)
/// but they read differently in a status line, and an operator triaging a
/// grounded machine needs to know whether the file is missing or wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheError {
    /// Nothing has been cached yet.
    Missing,
    /// The file is there and could not be read or parsed.
    Unreadable(String),
    /// It parsed, and its content does not match its own checksum.
    Corrupt(String),
    /// It belongs to a different install.
    Foreign {
        /// The install that wrote it.
        written_by: String,
    },
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("no policy bundle has been cached on this machine"),
            Self::Unreadable(why) => write!(f, "the cached policy bundle cannot be read: {why}"),
            Self::Corrupt(why) => write!(
                f,
                "the cached policy bundle does not match its own checksum: {why}"
            ),
            Self::Foreign { written_by } => write!(
                f,
                "the cached policy bundle was written by install {written_by}, not this one"
            ),
        }
    }
}

/// Where the cache lives under the Garrison config directory.
#[must_use]
pub fn path(config_dir: &Path) -> PathBuf {
    config_dir.join("bundle.json")
}

/// Reads the cached bundle, re-verifying it before handing it back.
///
/// # Errors
///
/// [`CacheError`], one variant per way a cache can fail to be one.
pub fn read(path: &Path, install: &str) -> Result<Cached, CacheError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(CacheError::Missing)
        }
        Err(error) => return Err(CacheError::Unreadable(error.to_string())),
    };

    let cached: Cached =
        serde_json::from_str(&text).map_err(|error| CacheError::Unreadable(error.to_string()))?;

    if !cached.belongs_to(install) {
        return Err(CacheError::Foreign {
            written_by: cached.install,
        });
    }

    garrison_policy::verify(&cached.bundle)
        .map_err(|mismatch| CacheError::Corrupt(mismatch.to_string()))?;

    Ok(cached)
}

/// Writes the cache at mode 0600, creating the directory if it is missing.
///
/// # Errors
///
/// The underlying IO failure. A cache that could not be written is logged and
/// otherwise ignored: it costs this install its offline grace, not its turn.
pub fn write(path: &Path, cached: &Cached) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec_pretty(cached)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    crate::enrollment::key::write_private(path, &body)
}

/// Removes the cache, if there is one.
///
/// Called when the plane has answered and the answer was no: a bundle this
/// install is no longer entitled to run must not survive a restart into the
/// offline grace window.
pub fn discard(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => tracing::info!(path = %path.display(), "discarded the cached policy bundle"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(
                %error,
                path = %path.display(),
                "the cached policy bundle could not be removed",
            );
        }
    }
}

/// Whether a bundle fetched at `fetched_at` may still be enforced at `now`.
///
/// Pure, and the whole offline rule. A zero grace forbids cached operation
/// outright, which is what an organization sets when a machine that cannot
/// reach the plane must not run at all. A `fetched_at` in the future is not
/// fresh: a clock that disagrees with the plane's is a reason to go and ask
/// the plane, not a reason to trust the file for longer.
#[must_use]
pub fn is_fresh(fetched_at: DateTime<Utc>, now: DateTime<Utc>, grace: Duration) -> bool {
    if grace.is_zero() {
        return false;
    }
    now.signed_duration_since(fetched_at)
        .to_std()
        .is_ok_and(|age| age <= grace)
}

/// How far past its grace a bundle is, for the sentence an operator reads.
///
/// Pure. `None` while it is still fresh.
#[must_use]
pub fn staleness(
    fetched_at: DateTime<Utc>,
    now: DateTime<Utc>,
    grace: Duration,
) -> Option<Duration> {
    let age = now.signed_duration_since(fetched_at).to_std().ok()?;
    age.checked_sub(grace).filter(|over| !over.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use garrison_policy::{BundleHeader, CommandDecision, CommandRule};

    fn bundle() -> Bundle {
        let mut bundle = Bundle {
            header: BundleHeader {
                id: "policybundle_01".into(),
                name: "Baseline".into(),
                version: 2,
                status: "published".into(),
                ..BundleHeader::default()
            },
            command_rules: vec![CommandRule {
                name: "no rm".into(),
                program: "rm".into(),
                decision: CommandDecision::Forbid,
                enabled: true,
                priority: 10,
                ..CommandRule::default()
            }],
            ..Bundle::default()
        };
        bundle.header.checksum = garrison_policy::checksum(&bundle);
        bundle
    }

    fn cached(now: DateTime<Utc>) -> Cached {
        Cached {
            fetched_at: now,
            install: "agentinstall_01".into(),
            bundle: bundle(),
        }
    }

    #[test]
    fn a_bundle_written_and_read_back_is_the_same_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let file = path(dir.path());

        write(&file, &cached(Utc::now())).unwrap();
        let read_back = read(&file, "agentinstall_01").unwrap();

        assert_eq!(read_back.bundle, bundle());
        assert_eq!(read_back.install, "agentinstall_01");
    }

    #[test]
    fn the_cache_is_not_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let file = path(dir.path());

        write(&file, &cached(Utc::now())).unwrap();

        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn no_cache_yet_is_a_missing_cache_and_not_a_failure_to_read_one() {
        let dir = tempfile::tempdir().unwrap();

        assert_eq!(
            read(&path(dir.path()), "agentinstall_01").unwrap_err(),
            CacheError::Missing
        );
    }

    #[test]
    fn a_cache_edited_under_the_daemon_is_refused_rather_than_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let file = path(dir.path());
        let mut tampered = cached(Utc::now());
        tampered.bundle.command_rules[0].decision = CommandDecision::Allow;
        write(&file, &tampered).unwrap();

        let error = read(&file, "agentinstall_01").unwrap_err();

        assert!(matches!(error, CacheError::Corrupt(_)), "{error}");
    }

    #[test]
    fn a_cache_belonging_to_another_install_is_not_this_installs_policy() {
        let dir = tempfile::tempdir().unwrap();
        let file = path(dir.path());
        write(&file, &cached(Utc::now())).unwrap();

        let error = read(&file, "agentinstall_99").unwrap_err();

        assert_eq!(
            error,
            CacheError::Foreign {
                written_by: "agentinstall_01".to_string()
            }
        );
    }

    #[test]
    fn unparseable_json_reads_as_unreadable_rather_than_missing() {
        let dir = tempfile::tempdir().unwrap();
        let file = path(dir.path());
        std::fs::write(&file, "{").unwrap();

        assert!(matches!(
            read(&file, "agentinstall_01").unwrap_err(),
            CacheError::Unreadable(_)
        ));
    }

    #[test]
    fn discarding_a_cache_that_is_not_there_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        discard(&path(dir.path()));
    }

    #[test]
    fn a_bundle_inside_the_grace_window_may_still_be_enforced() {
        let now = Utc::now();
        let fetched = now - chrono::Duration::hours(6);

        assert!(is_fresh(fetched, now, Duration::from_secs(86_400)));
        assert_eq!(staleness(fetched, now, Duration::from_secs(86_400)), None);
    }

    #[test]
    fn a_bundle_past_the_grace_window_is_not_trusted() {
        let now = Utc::now();
        let fetched = now - chrono::Duration::hours(30);

        assert!(!is_fresh(fetched, now, Duration::from_secs(86_400)));
        let over = staleness(fetched, now, Duration::from_secs(86_400)).expect("it is stale");
        assert!(over.as_secs() >= 6 * 3600 - 5, "{over:?}");
    }

    #[test]
    fn a_zero_grace_forbids_running_on_a_cache_at_all() {
        let now = Utc::now();

        assert!(
            !is_fresh(now, now, Duration::ZERO),
            "a bundle fetched this instant is still not enforceable offline"
        );
    }

    #[test]
    fn a_bundle_fetched_in_the_future_is_not_fresh() {
        let now = Utc::now();
        let fetched = now + chrono::Duration::hours(1);

        assert!(
            !is_fresh(fetched, now, Duration::from_secs(86_400)),
            "a clock that disagrees with the plane is a reason to ask the plane"
        );
    }
}
