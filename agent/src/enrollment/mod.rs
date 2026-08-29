//! Joining the fleet, once, on the first start that finds a plane configured.
//!
//! # What "first run" means
//!
//! There is no flag and no marker file whose only job is to say "done". A
//! daemon is enrolled if and only if it can read back an install record, and
//! that record exists only because a redemption succeeded. One fact, one
//! place, no way for the two to disagree.
//!
//! # The four outcomes, and why each behaves as it does
//!
//! | Situation | What happens |
//! |---|---|
//! | No `[plane]` section | Nothing. A standalone agent starts as it always did. |
//! | Already enrolled | The record is logged and the daemon starts. No call is made. |
//! | Not enrolled, plane says yes | Identity is recorded, the packet is destroyed, the daemon starts. |
//! | Not enrolled, anything else | The daemon refuses to start. |
//!
//! That last row is the one worth defending. A governed agent that starts
//! anyway when the plane turned it away is not governed; it is an agent with a
//! policy document next to it. The same applies to an unreachable plane on a
//! machine that has never enrolled: without an install record there is no
//! organization, no seat, and nothing to attribute a session to, so starting
//! would produce exactly the unattributable activity the control plane exists
//! to prevent.
//!
//! An *already enrolled* daemon is deliberately not held to that. It does not
//! call the plane at all, so a plane outage cannot ground a fleet that has
//! already been admitted. Enrollment is a one-time gate, not a heartbeat.
//!
//! # What the daemon reports
//!
//! Everything in [`InstallFacts`] is observed by this process at the moment it
//! starts, not read from configuration. `sandbox_hardening` is what the kernel
//! actually granted, so a machine whose landlock support degraded says so, and
//! the fleet view shows it. A config file could only ever record what somebody
//! intended.

pub mod key;
pub mod record;
pub mod redeem;

use crate::config::PlaneConfig;
use crate::error::GarrisonError;
use crate::protocol::acp::SandboxStatus;
use crate::types::InstallId;
use std::path::{Path, PathBuf};

pub use record::Record;
pub use redeem::{InstallFacts, Outcome};

/// Enrolls this install if it has not enrolled before.
///
/// Returns the install's identity when a plane is configured, and `None` when
/// none is — a standalone agent has no identity to have.
///
/// # Errors
///
/// [`GarrisonErrorKind::Enrollment`](crate::error::GarrisonErrorKind::Enrollment)
/// when the plane refuses this machine, cannot be reached on a first run, or
/// when the packet, key, or record on disk cannot be used. Every one of these
/// stops the daemon starting; see the module docs for why.
pub async fn ensure(
    plane: &PlaneConfig,
    sandbox: &SandboxStatus,
) -> Result<Option<Record>, GarrisonError> {
    let dir = config_dir();
    let record_path = record::record_path(&dir);

    if let Some(existing) = Record::read(&record_path)? {
        tracing::info!(
            install = %existing.install,
            organization = %existing.organization,
            "already enrolled with the control plane"
        );
        return Ok(Some(existing));
    }

    if plane.url.trim().is_empty() {
        return Err(GarrisonError::enrollment(
            "a [plane] section is present but names no url; \
             remove the section to run standalone, or set plane.url",
        ));
    }

    let packet_path = plane
        .enrollment_packet
        .clone()
        .unwrap_or_else(|| record::default_packet_path(&dir));
    if !packet_path.is_file() {
        return Err(GarrisonError::enrollment(format!(
            "this install has not enrolled and no enrollment packet is at '{}'. \
             Ask whoever provisions this fleet for one.",
            packet_path.display()
        )));
    }
    let packet = record::Packet::read(&packet_path)?;

    let install_key = key::InstallKey::load_or_create(&key::key_path(&dir))?;
    let public_key = install_key.public_spki_base64()?;

    let facts = facts(sandbox, plane.operator_upn.clone())?;
    tracing::info!(
        plane = %plane.url,
        install_id = %facts.install_id,
        hostname = %facts.hostname,
        "enrolling with the control plane"
    );

    let outcome = redeem::redeem(
        &plane.url,
        &packet.artifact,
        &packet.token_id,
        &facts,
        &public_key,
    )
    .await?;

    let Outcome::Accepted {
        install,
        credential,
        organization,
        decided_at,
    } = outcome
    else {
        let Outcome::Refused { reason } = outcome else {
            unreachable!("Outcome has exactly two variants")
        };
        return Err(GarrisonError::enrollment(format!(
            "the control plane refused this install: {reason}"
        )));
    };

    let record = Record {
        install_id: facts.install_id,
        install,
        credential,
        organization,
        hostname: facts.hostname,
        enrolled_at: decided_at,
    };
    record.write(&record_path)?;
    record::Packet::discard(&packet_path);

    tracing::info!(
        install = %record.install,
        credential = %record.credential,
        organization = %record.organization,
        "enrolled with the control plane"
    );
    Ok(Some(record))
}

/// Assembles what this process can honestly say about itself.
fn facts(
    sandbox: &SandboxStatus,
    operator_upn: Option<String>,
) -> Result<InstallFacts, GarrisonError> {
    Ok(InstallFacts {
        install_id: InstallId::new().to_string(),
        hostname: hostname()?,
        platform: platform()?,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        sandbox_hardening: hardening(sandbox),
        isolation_active: sandbox.enabled,
        operator_upn,
    })
}

/// This machine's hostname.
fn hostname() -> Result<String, GarrisonError> {
    hostname::get()
        .map_err(|error| {
            GarrisonError::enrollment(format!("no hostname for this machine: {error}"))
        })
        .map(|name| name.to_string_lossy().into_owned())
}

/// The platform, in the three spellings the control plane accepts.
///
/// An unrecognized target is an error rather than a guess. The plane's enum is
/// closed, so guessing would produce a 422 whose message points at a field
/// rather than at the actual problem, which is that nobody has decided what
/// this platform is called yet.
fn platform() -> Result<&'static str, GarrisonError> {
    match std::env::consts::OS {
        "linux" => Ok("linux"),
        "macos" => Ok("macos"),
        "windows" => Ok("windows"),
        other => Err(GarrisonError::enrollment(format!(
            "the control plane has no name for this platform ('{other}')"
        ))),
    }
}

/// Translates the agent's own sandbox report into the plane's vocabulary.
///
/// The two enums are deliberately not the same. The agent distinguishes "no
/// sandbox configured" from "configured, hardening off"; the plane cares only
/// whether the kernel is enforcing anything, so both collapse to
/// `unavailable`. Collapsing here rather than widening the schema keeps the
/// fleet view answering one question instead of two.
fn hardening(sandbox: &SandboxStatus) -> &'static str {
    if !sandbox.enabled {
        return "unavailable";
    }
    match sandbox.hardening.as_deref() {
        Some("enforce") => "enforce",
        Some("besteffort") => "best_effort",
        _ => "unavailable",
    }
}

/// The `~/.config/garrison` directory, mirroring where provider keys live.
fn config_dir() -> PathBuf {
    resolve_config_dir(
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

/// The directory rule, from explicit inputs so it tests without environment.
fn resolve_config_dir(xdg_config_home: Option<PathBuf>, home: Option<PathBuf>) -> PathBuf {
    match (xdg_config_home, home) {
        (Some(xdg), _) if !xdg.as_os_str().is_empty() => xdg.join("garrison"),
        (_, Some(home)) => home.join(".config").join("garrison"),
        _ => PathBuf::from(".config").join("garrison"),
    }
}

/// Whether a path names a readable file, for the caller's own diagnostics.
#[must_use]
pub fn is_enrolled(config_dir: &Path) -> bool {
    matches!(Record::read(&record::record_path(config_dir)), Ok(Some(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(enabled: bool, hardening: Option<&str>) -> SandboxStatus {
        SandboxStatus {
            enabled,
            hardening: hardening.map(str::to_owned),
            timeout_secs: None,
            memory_limit_bytes: None,
        }
    }

    #[test]
    fn an_enforcing_sandbox_is_reported_as_enforcing() {
        assert_eq!(hardening(&sandbox(true, Some("enforce"))), "enforce");
    }

    #[test]
    fn best_effort_crosses_the_wire_in_the_planes_spelling() {
        assert_eq!(hardening(&sandbox(true, Some("besteffort"))), "best_effort");
    }

    #[test]
    fn no_sandbox_and_a_sandbox_with_hardening_off_both_read_as_unavailable() {
        assert_eq!(hardening(&sandbox(false, None)), "unavailable");
        assert_eq!(hardening(&sandbox(true, Some("off"))), "unavailable");
    }

    #[test]
    fn an_unrecognized_hardening_mode_is_not_reported_as_protection() {
        assert_eq!(hardening(&sandbox(true, Some("selinux"))), "unavailable");
    }

    #[test]
    fn this_platform_has_a_name_the_plane_accepts() {
        let name = platform().expect("a supported build target");
        assert!(["linux", "macos", "windows"].contains(&name));
    }

    #[test]
    fn the_config_directory_follows_xdg_then_home() {
        assert_eq!(
            resolve_config_dir(Some(PathBuf::from("/xdg")), Some(PathBuf::from("/home/u"))),
            PathBuf::from("/xdg/garrison")
        );
        assert_eq!(
            resolve_config_dir(None, Some(PathBuf::from("/home/u"))),
            PathBuf::from("/home/u/.config/garrison")
        );
        assert_eq!(
            resolve_config_dir(Some(PathBuf::new()), Some(PathBuf::from("/home/u"))),
            PathBuf::from("/home/u/.config/garrison")
        );
    }

    #[test]
    fn facts_describe_this_process_rather_than_a_config_file() {
        let facts = facts(&sandbox(true, Some("enforce")), None).unwrap();

        assert!(facts.install_id.starts_with("inst_"));
        assert_eq!(facts.agent_version, env!("CARGO_PKG_VERSION"));
        assert!(!facts.hostname.is_empty());
        assert!(facts.isolation_active);
    }

    #[test]
    fn a_fresh_directory_reports_this_install_as_unenrolled() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_enrolled(dir.path()));
    }

    #[test]
    fn a_written_record_reports_this_install_as_enrolled() {
        let dir = tempfile::tempdir().unwrap();
        Record {
            install_id: "inst_01".into(),
            install: "agentinstall_01".into(),
            credential: "installcredential_01".into(),
            organization: "organization_01".into(),
            hostname: "ws-01".into(),
            enrolled_at: "2026-08-29T04:50:23.579Z".into(),
        }
        .write(&record::record_path(dir.path()))
        .unwrap();

        assert!(is_enrolled(dir.path()));
    }
}
