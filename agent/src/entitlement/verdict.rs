//! The seat rule, as arithmetic over three rows and a clock.
//!
//! Everything here is pure. The plane owns the facts — who this install
//! belongs to, what seats that operator holds, what impact level the
//! organization runs at — and this module owns nothing but the reasoning over
//! them. That split is the point: an auditor asking "prove a revoked seat
//! stops turns" is shown [`adjudicate`] and its tests rather than a daemon
//! and a stopwatch.
//!
//! # The three questions, in order
//!
//! 1. **Is the install still one the fleet recognizes?** [`adjudicate`]
//!    refuses a `quarantined` or `retired` install before it looks at a seat
//!    at all, because a machine the plane has taken out of service does not
//!    get to run on the strength of its operator's entitlement.
//! 2. **Does its operator hold an active seat?** Only `active` entitles.
//!    `assigned` is a seat somebody has not turned on yet, and the schema is
//!    explicit that no active seat means no turns.
//! 3. **How long may the last answer be trusted if the plane goes quiet?**
//!    [`grace_period`] answers that from the organization's own
//!    `impact_level` and the seat's tier, both of which come from the plane.
//!    There is no `garrison.toml` key that lengthens it; see the table.
//!
//! # Why a cached refusal never expires
//!
//! [`admit`] honours a cached `Entitled` verdict for the grace period and a
//! cached `Refused` one forever. A grace window exists so a network blip does
//! not ground a fleet; letting a revocation age back into permission would
//! turn the same window into the offboarding hole it exists to avoid.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::admission::TurnRefusal;

// =============================================================================
// The rows this rule reads
// =============================================================================

/// The `AgentInstall` row this daemon is, in the fields the seat rule reads.
///
/// `operator` is a relation column and arrives as the related row's id, which
/// is what the seat query filters on.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct InstallRow {
    /// `enrolled`, `active`, `quarantined` or `retired`.
    #[serde(default)]
    pub status: String,
    /// The operator this machine acts for.
    #[serde(default)]
    pub operator: Option<String>,
}

/// One `Seat` row, in the fields that decide whether it entitles anything.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct SeatRow {
    /// The seat's row id, reported in the status so an admin can find it.
    pub id: String,
    /// Whose seat it is.
    #[serde(default)]
    pub operator: Option<String>,
    /// `assigned`, `active`, `revoked` or `expired`.
    #[serde(default)]
    pub status: String,
    /// `standard` or `elevated`.
    #[serde(default)]
    pub tier: String,
    /// When it stops entitling, RFC 3339, when it is time-limited.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// When it was revoked, RFC 3339.
    #[serde(default)]
    pub revoked_at: Option<String>,
    /// Why it was revoked. The plane's own `@require` makes this non-empty
    /// on every revoked seat, which is what lets a refusal name a cause.
    #[serde(default)]
    pub revocation_reason: Option<String>,
}

/// The tenant's own row, read for one field.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct OrganizationRow {
    /// The impact level the whole grace table keys on.
    #[serde(default)]
    pub impact_level: String,
}

// =============================================================================
// The vocabulary
// =============================================================================

/// How much a seat is allowed to do, and therefore how little slack it gets
/// when the plane cannot be reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Tier {
    /// The ordinary seat.
    #[default]
    Standard,
    /// A seat with wider reach, and correspondingly less offline slack.
    Elevated,
}

impl Tier {
    /// Reads the plane's spelling.
    ///
    /// An unrecognized tier is `Elevated`, which is the shortest grace in
    /// every row of the table. A tier this build has never heard of is not a
    /// tier to be generous with.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value {
            "standard" => Self::Standard,
            _ => Self::Elevated,
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Standard => "standard",
            Self::Elevated => "elevated",
        })
    }
}

/// The organization's impact level, which is what the grace table keys on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ImpactLevel {
    /// Commercial.
    Commercial,
    /// FedRAMP Moderate.
    FedrampModerate,
    /// FedRAMP High.
    FedrampHigh,
    /// DoD Impact Level 2.
    Il2,
    /// DoD Impact Level 4.
    Il4,
    /// DoD Impact Level 5.
    Il5,
    /// A level this build does not recognize, or none read yet.
    #[default]
    Unknown,
}

impl ImpactLevel {
    /// Reads the plane's spelling.
    ///
    /// Unknown is not a synonym for commercial. A level this build cannot
    /// interpret gets the strictest row of the table, because the alternative
    /// is a deployment that quietly widens its own offline window by naming
    /// its impact level something newer than the daemon.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value {
            "commercial" => Self::Commercial,
            "fedramp_moderate" => Self::FedrampModerate,
            "fedramp_high" => Self::FedrampHigh,
            "il2" => Self::Il2,
            "il4" => Self::Il4,
            "il5" => Self::Il5,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for ImpactLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Commercial => "commercial",
            Self::FedrampModerate => "fedramp_moderate",
            Self::FedrampHigh => "fedramp_high",
            Self::Il2 => "il2",
            Self::Il4 => "il4",
            Self::Il5 => "il5",
            Self::Unknown => "unknown",
        })
    }
}

/// Why this install is not entitled to run a turn.
///
/// Each variant is a different thing for an operator to do about it, which is
/// why they are not one string: `NoSeat` is a request to an org admin,
/// `InstallNotActive` is a machine somebody quarantined, and
/// `CredentialRejected` is a key the plane no longer accepts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Refusal {
    /// An org admin took the seat away, and said why.
    SeatRevoked {
        /// The recorded reason, which the plane's own rule makes mandatory.
        reason: String,
        /// When, RFC 3339.
        revoked_at: Option<String>,
    },
    /// The seat had an expiry and it has passed.
    SeatExpired {
        /// The expiry the plane recorded.
        expires_at: Option<String>,
    },
    /// A seat exists but has never been turned on.
    SeatNotActive {
        /// The status it is sitting in.
        status: String,
    },
    /// This operator holds no seat at all.
    NoSeat,
    /// The plane has taken this machine out of service.
    InstallNotActive {
        /// The status the plane records for it.
        status: String,
    },
    /// The install row names no operator, so there is nobody to be entitled.
    InstallUnbound,
    /// The plane refused this install's credential outright.
    CredentialRejected {
        /// The HTTP status it refused with.
        status: u16,
        /// What it said.
        message: String,
    },
}

impl Refusal {
    /// The one word a status surface reports, matching the wire tag.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::SeatRevoked { .. } => "seat_revoked",
            Self::SeatExpired { .. } => "seat_expired",
            Self::SeatNotActive { .. } => "seat_not_active",
            Self::NoSeat => "no_seat",
            Self::InstallNotActive { .. } => "install_not_active",
            Self::InstallUnbound => "install_unbound",
            Self::CredentialRejected { .. } => "credential_rejected",
        }
    }
}

impl fmt::Display for Refusal {
    /// Prose an operator can act on, because a refusal that only says "no" is
    /// a support ticket rather than an answer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SeatRevoked { reason, revoked_at } => {
                write!(f, "this operator's seat was revoked: {reason}")?;
                if let Some(at) = revoked_at {
                    write!(f, " (at {at})")?;
                }
                write!(
                    f,
                    ". Ask an organization administrator to reinstate it if this is wrong"
                )
            }
            Self::SeatExpired { expires_at } => {
                write!(f, "this operator's seat has expired")?;
                if let Some(at) = expires_at {
                    write!(f, " (it ran to {at})")?;
                }
                write!(f, ". Ask an organization administrator to extend it")
            }
            Self::SeatNotActive { status } => write!(
                f,
                "this operator holds a seat in the '{status}' state, and only an active seat \
                 entitles a turn. Ask an organization administrator to activate it"
            ),
            Self::NoSeat => f.write_str(
                "this operator holds no seat in this organization. Ask an organization \
                 administrator to assign and activate one",
            ),
            Self::InstallNotActive { status } => write!(
                f,
                "the control plane records this install as '{status}', which is not a state \
                 that runs turns. Ask a fleet administrator to restore it, or enroll this \
                 machine again"
            ),
            Self::InstallUnbound => f.write_str(
                "the control plane's record for this install names no operator, so there is \
                 no seat to check. Re-enroll this machine against an operator-scoped grant",
            ),
            Self::CredentialRejected { status, message } => write!(
                f,
                "the control plane refused this install's credential ({status}: {message}). \
                 It has most likely been revoked; re-enroll this machine"
            ),
        }
    }
}

/// What the plane's rows come to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Verdict {
    /// A seat entitles this install, and this is which one.
    Entitled {
        /// The seat's row id.
        seat: String,
        /// Its tier, which sets the offline grace.
        tier: Tier,
    },
    /// It does not, and this is why.
    Refused(Refusal),
}

/// One plane-issued verdict, and how long it may outlive the plane.
///
/// `grace_secs` is stored rather than recomputed so a cached standing carries
/// the window it was granted under. An organization that raises its impact
/// level shortens the window on the next successful check, which is the
/// direction that fails closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Standing {
    /// What the plane's rows came to.
    pub verdict: Verdict,
    /// When they were read.
    pub checked_at: DateTime<Utc>,
    /// How long an `Entitled` verdict stays honoured without the plane.
    pub grace_secs: u64,
    /// The impact level that window came from, reported in the status.
    pub impact: ImpactLevel,
}

impl Standing {
    /// When this standing stops entitling anything, absent for a refusal.
    #[must_use]
    pub fn grace_until(&self) -> Option<DateTime<Utc>> {
        match self.verdict {
            Verdict::Entitled { .. } => {
                self.checked_at
                    .checked_add_signed(chrono::TimeDelta::seconds(
                        i64::try_from(self.grace_secs).unwrap_or(i64::MAX),
                    ))
            }
            Verdict::Refused(_) => None,
        }
    }
}

/// Whether a turn may run, from the seat's point of view.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeatAdmission {
    /// A seat entitles it.
    Admit {
        /// The tier that seat carries.
        tier: Tier,
    },
    /// The plane said no, and this is what it said.
    Refuse(Refusal),
    /// The plane could not be asked and the last answer is too old to spend.
    Unavailable {
        /// When the last successful check happened, if there ever was one.
        since: Option<DateTime<Utc>>,
        /// When the grace on it ran out, if there was any.
        grace_until: Option<DateTime<Utc>>,
        /// What the last attempt failed with.
        last_error: Option<String>,
    },
}

// =============================================================================
// The rules
// =============================================================================

/// The offline grace table, in one function.
///
/// | impact level | standard | elevated |
/// |---|---|---|
/// | commercial | 72 h | 24 h |
/// | `fedramp_moderate`, il2 | 24 h | 4 h |
/// | `fedramp_high`, il4 | 4 h | none |
/// | il5, unknown | none | none |
///
/// A grace of zero means the plane must answer for every turn. `cap` is the
/// deployment's `[plane] offline_grace_secs`, and it may only **shorten** the
/// window: a file on the machine being governed must never be able to widen
/// how long that machine runs unsupervised.
#[must_use]
pub fn grace_period(impact: ImpactLevel, tier: Tier, cap: Option<Duration>) -> Duration {
    const HOUR: u64 = 3600;

    let hours = match (impact, tier) {
        (ImpactLevel::Commercial, Tier::Standard) => 72,
        (ImpactLevel::Commercial, Tier::Elevated)
        | (ImpactLevel::FedrampModerate | ImpactLevel::Il2, Tier::Standard) => 24,
        (ImpactLevel::FedrampModerate | ImpactLevel::Il2, Tier::Elevated)
        | (ImpactLevel::FedrampHigh | ImpactLevel::Il4, Tier::Standard) => 4,
        (ImpactLevel::FedrampHigh | ImpactLevel::Il4, Tier::Elevated)
        | (ImpactLevel::Il5 | ImpactLevel::Unknown, _) => 0,
    };

    let table = Duration::from_secs(hours * HOUR);
    match cap {
        Some(cap) if cap < table => cap,
        _ => table,
    }
}

/// The seat rule over the plane's rows. Pure.
///
/// Order matters and is the order of the module docs: the install first, then
/// its operator, then the seats that operator holds. Among several seats the
/// most generous live one wins, because holding two seats is not a reason to
/// be refused; among several dead ones the most specific reason wins, because
/// "revoked, here is why" helps and "no seat" does not.
#[must_use]
pub fn adjudicate(install: &InstallRow, seats: &[SeatRow], now: DateTime<Utc>) -> Verdict {
    if !matches!(install.status.as_str(), "enrolled" | "active") {
        return Verdict::Refused(Refusal::InstallNotActive {
            status: install.status.clone(),
        });
    }

    let Some(operator) = install.operator.as_deref().filter(|id| !id.is_empty()) else {
        return Verdict::Refused(Refusal::InstallUnbound);
    };

    let held: Vec<&SeatRow> = seats
        .iter()
        .filter(|seat| seat.operator.as_deref() == Some(operator))
        .collect();

    if let Some(seat) = best_live_seat(&held, now) {
        return Verdict::Entitled {
            seat: seat.id.clone(),
            tier: Tier::parse(&seat.tier),
        };
    }

    Verdict::Refused(refusal_for(&held, now))
}

/// The live seat to run on: the one that lasts longest.
///
/// A seat with no expiry outlasts every dated one, so it sorts above them.
fn best_live_seat<'a>(seats: &[&'a SeatRow], now: DateTime<Utc>) -> Option<&'a SeatRow> {
    seats
        .iter()
        .filter(|seat| seat.status == "active" && !has_expired(seat, now))
        .max_by_key(
            |seat| match seat.expires_at.as_deref().and_then(parse_time) {
                Some(at) => (0, at),
                // No expiry: the maximum of the ordered pair, whatever the dates.
                None => (1, DateTime::<Utc>::MIN_UTC),
            },
        )
        .copied()
}

/// Whether a seat's own expiry has passed.
///
/// An `expires_at` that does not parse counts as expired. The daemon cannot
/// tell whether an unreadable date is in the future, and a seat it cannot
/// date is not a seat it may spend.
fn has_expired(seat: &SeatRow, now: DateTime<Utc>) -> bool {
    match seat.expires_at.as_deref() {
        None => false,
        Some(text) if text.trim().is_empty() => false,
        Some(text) => parse_time(text).is_none_or(|at| at <= now),
    }
}

/// The most useful reason among a set of seats that do not entitle. Pure.
fn refusal_for(seats: &[&SeatRow], now: DateTime<Utc>) -> Refusal {
    if let Some(revoked) = seats
        .iter()
        .filter(|seat| seat.status == "revoked")
        .max_by_key(|seat| seat.revoked_at.as_deref().and_then(parse_time))
    {
        return Refusal::SeatRevoked {
            reason: revoked
                .revocation_reason
                .clone()
                .filter(|reason| !reason.trim().is_empty())
                .unwrap_or_else(|| "no reason was recorded".to_string()),
            revoked_at: revoked.revoked_at.clone(),
        };
    }

    if let Some(expired) = seats
        .iter()
        .find(|seat| seat.status == "expired" || has_expired(seat, now))
    {
        return Refusal::SeatExpired {
            expires_at: expired.expires_at.clone(),
        };
    }

    match seats.first() {
        Some(seat) => Refusal::SeatNotActive {
            status: seat.status.clone(),
        },
        None => Refusal::NoSeat,
    }
}

/// Reads an RFC 3339 timestamp, or nothing.
fn parse_time(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|at| at.with_timezone(&Utc))
}

/// Whether a turn may run now, given the last thing the plane said. Pure.
///
/// The three answers are three different frames on the wire, which is the
/// acceptance criterion this whole module exists for: "your seat was taken
/// away" and "I cannot ask whether you have one" are not the same message and
/// must not arrive as the same error.
#[must_use]
pub fn admit(
    standing: Option<&Standing>,
    last_error: Option<&str>,
    now: DateTime<Utc>,
) -> SeatAdmission {
    let Some(standing) = standing else {
        return SeatAdmission::Unavailable {
            since: None,
            grace_until: None,
            last_error: last_error.map(ToString::to_string),
        };
    };

    match &standing.verdict {
        // A revocation does not age into permission.
        Verdict::Refused(refusal) => SeatAdmission::Refuse(refusal.clone()),
        Verdict::Entitled { tier, .. } => {
            let grace_until = standing.grace_until();
            if grace_until.is_some_and(|until| now <= until) {
                SeatAdmission::Admit { tier: *tier }
            } else {
                SeatAdmission::Unavailable {
                    since: Some(standing.checked_at),
                    grace_until,
                    last_error: last_error.map(ToString::to_string),
                }
            }
        }
    }
}

/// Whether the standing is recent enough that a turn need not wait on a
/// fresh check. Pure.
///
/// One interval, not the grace: the grace is how long a stale answer may
/// still be *spent*, and this is how long it may be spent without the monitor
/// having tried again. They differ by orders of magnitude on purpose.
#[must_use]
pub fn is_fresh(standing: Option<&Standing>, interval: Duration, now: DateTime<Utc>) -> bool {
    standing.is_some_and(|standing| {
        now.signed_duration_since(standing.checked_at)
            .to_std()
            .is_ok_and(|age| age <= interval)
    })
}

/// Turns a seat answer into the refusal the admission seam speaks. Pure.
///
/// `Admit` is `None`; everything else is a [`TurnRefusal`] whose variant
/// decides the JSON-RPC code the client sees. The two refusing variants are
/// deliberately different codes: a revoked seat is a decision to take to an
/// administrator, and an unreachable plane is an outage to take to whoever
/// runs it.
#[must_use]
pub fn turn_refusal(admission: &SeatAdmission, plane_url: &str) -> Option<TurnRefusal> {
    match admission {
        SeatAdmission::Admit { .. } => None,
        SeatAdmission::Refuse(refusal) => Some(TurnRefusal::Seat {
            reason: refusal.to_string(),
        }),
        SeatAdmission::Unavailable {
            since,
            grace_until,
            last_error,
        } => Some(TurnRefusal::PlaneUnavailable {
            reason: unavailable_reason(plane_url, since.as_ref(), grace_until.as_ref(), last_error),
        }),
    }
}

/// The sentence an operator reads when the plane cannot confirm a seat. Pure.
fn unavailable_reason(
    plane_url: &str,
    since: Option<&DateTime<Utc>>,
    grace_until: Option<&DateTime<Utc>>,
    last_error: &Option<String>,
) -> String {
    let mut reason = format!(
        "the control plane at {plane_url} could not confirm this install's \
                              seat"
    );
    if let Some(error) = last_error {
        reason.push_str(&format!(" ({error})"));
    }
    match (since, grace_until) {
        (Some(since), Some(until)) => reason.push_str(&format!(
            ". The last confirmation was at {}, and the offline grace for this organization's \
             impact level ended at {}",
            stamp(since),
            stamp(until)
        )),
        (Some(since), None) => reason.push_str(&format!(
            ". The last confirmation was at {}, and this organization's impact level allows no \
             offline grace",
            stamp(since)
        )),
        _ => reason.push_str(
            ". It has never confirmed one, so there is nothing to run on. Check \
             `_garrison/status` for what the exchange is failing with",
        ),
    }
    reason
}

/// RFC 3339 to the second, which is as precise as a grace window needs to be.
fn stamp(at: &DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .expect("a fixed instant")
            .with_timezone(&Utc)
    }

    fn now() -> DateTime<Utc> {
        at("2026-08-29T12:00:00Z")
    }

    fn install(status: &str, operator: Option<&str>) -> InstallRow {
        InstallRow {
            status: status.to_string(),
            operator: operator.map(str::to_owned),
        }
    }

    fn seat(id: &str, status: &str) -> SeatRow {
        SeatRow {
            id: id.to_string(),
            operator: Some("operator_01".to_string()),
            status: status.to_string(),
            tier: "standard".to_string(),
            expires_at: None,
            revoked_at: None,
            revocation_reason: None,
        }
    }

    fn entitled(grace_secs: u64, checked_at: DateTime<Utc>) -> Standing {
        Standing {
            verdict: Verdict::Entitled {
                seat: "seat_01".to_string(),
                tier: Tier::Standard,
            },
            checked_at,
            grace_secs,
            impact: ImpactLevel::FedrampHigh,
        }
    }

    // -- adjudication ------------------------------------------------------

    #[test]
    fn an_active_seat_entitles_an_enrolled_install() {
        let verdict = adjudicate(
            &install("enrolled", Some("operator_01")),
            &[seat("seat_01", "active")],
            now(),
        );

        assert_eq!(
            verdict,
            Verdict::Entitled {
                seat: "seat_01".to_string(),
                tier: Tier::Standard
            }
        );
    }

    #[test]
    fn a_quarantined_install_is_refused_before_any_seat_is_read() {
        let verdict = adjudicate(
            &install("quarantined", Some("operator_01")),
            &[seat("seat_01", "active")],
            now(),
        );

        assert_eq!(
            verdict,
            Verdict::Refused(Refusal::InstallNotActive {
                status: "quarantined".to_string()
            })
        );
    }

    #[test]
    fn a_retired_install_is_refused_however_good_its_seat_is() {
        let verdict = adjudicate(
            &install("retired", Some("operator_01")),
            &[seat("seat_01", "active")],
            now(),
        );

        assert!(matches!(
            verdict,
            Verdict::Refused(Refusal::InstallNotActive { .. })
        ));
    }

    #[test]
    fn an_install_bound_to_nobody_has_no_seat_to_check() {
        let verdict = adjudicate(&install("active", None), &[], now());

        assert_eq!(verdict, Verdict::Refused(Refusal::InstallUnbound));
    }

    #[test]
    fn an_install_whose_operator_field_is_blank_is_unbound() {
        let verdict = adjudicate(&install("active", Some("")), &[], now());

        assert_eq!(verdict, Verdict::Refused(Refusal::InstallUnbound));
    }

    #[test]
    fn an_assigned_seat_does_not_entitle_a_turn() {
        let verdict = adjudicate(
            &install("active", Some("operator_01")),
            &[seat("seat_01", "assigned")],
            now(),
        );

        assert_eq!(
            verdict,
            Verdict::Refused(Refusal::SeatNotActive {
                status: "assigned".to_string()
            })
        );
    }

    #[test]
    fn an_operator_with_no_seat_at_all_is_told_so() {
        let verdict = adjudicate(&install("active", Some("operator_01")), &[], now());

        assert_eq!(verdict, Verdict::Refused(Refusal::NoSeat));
    }

    #[test]
    fn another_operators_seat_does_not_entitle_this_install() {
        let mut other = seat("seat_02", "active");
        other.operator = Some("operator_99".to_string());

        let verdict = adjudicate(&install("active", Some("operator_01")), &[other], now());

        assert_eq!(verdict, Verdict::Refused(Refusal::NoSeat));
    }

    #[test]
    fn a_revoked_seat_is_refused_with_the_reason_the_plane_recorded() {
        let mut revoked = seat("seat_01", "revoked");
        revoked.revocation_reason = Some("offboarded".to_string());
        revoked.revoked_at = Some("2026-08-29T11:00:00Z".to_string());

        let verdict = adjudicate(&install("active", Some("operator_01")), &[revoked], now());

        assert_eq!(
            verdict,
            Verdict::Refused(Refusal::SeatRevoked {
                reason: "offboarded".to_string(),
                revoked_at: Some("2026-08-29T11:00:00Z".to_string()),
            })
        );
    }

    #[test]
    fn the_most_recent_revocation_is_the_one_reported() {
        let mut older = seat("seat_01", "revoked");
        older.revocation_reason = Some("laptop returned".to_string());
        older.revoked_at = Some("2026-01-01T00:00:00Z".to_string());
        let mut newer = seat("seat_02", "revoked");
        newer.revocation_reason = Some("offboarded".to_string());
        newer.revoked_at = Some("2026-08-01T00:00:00Z".to_string());

        let verdict = adjudicate(
            &install("active", Some("operator_01")),
            &[older, newer],
            now(),
        );

        assert_eq!(
            verdict,
            Verdict::Refused(Refusal::SeatRevoked {
                reason: "offboarded".to_string(),
                revoked_at: Some("2026-08-01T00:00:00Z".to_string()),
            })
        );
    }

    #[test]
    fn an_active_seat_wins_over_a_revoked_one_the_same_operator_also_holds() {
        let mut revoked = seat("seat_01", "revoked");
        revoked.revocation_reason = Some("rotated".to_string());

        let verdict = adjudicate(
            &install("active", Some("operator_01")),
            &[revoked, seat("seat_02", "active")],
            now(),
        );

        assert_eq!(
            verdict,
            Verdict::Entitled {
                seat: "seat_02".to_string(),
                tier: Tier::Standard
            }
        );
    }

    #[test]
    fn a_seat_that_expired_a_second_ago_no_longer_entitles() {
        let mut dated = seat("seat_01", "active");
        dated.expires_at = Some("2026-08-29T11:59:59Z".to_string());

        let verdict = adjudicate(&install("active", Some("operator_01")), &[dated], now());

        assert_eq!(
            verdict,
            Verdict::Refused(Refusal::SeatExpired {
                expires_at: Some("2026-08-29T11:59:59Z".to_string())
            })
        );
    }

    #[test]
    fn a_seat_expiring_exactly_now_has_expired() {
        let mut dated = seat("seat_01", "active");
        dated.expires_at = Some("2026-08-29T12:00:00Z".to_string());

        assert!(matches!(
            adjudicate(&install("active", Some("operator_01")), &[dated], now()),
            Verdict::Refused(Refusal::SeatExpired { .. })
        ));
    }

    #[test]
    fn a_seat_expiring_a_second_from_now_still_entitles() {
        let mut dated = seat("seat_01", "active");
        dated.expires_at = Some("2026-08-29T12:00:01Z".to_string());

        assert!(matches!(
            adjudicate(&install("active", Some("operator_01")), &[dated], now()),
            Verdict::Entitled { .. }
        ));
    }

    #[test]
    fn a_seat_whose_expiry_cannot_be_read_is_treated_as_expired() {
        let mut dated = seat("seat_01", "active");
        dated.expires_at = Some("whenever".to_string());

        assert!(matches!(
            adjudicate(&install("active", Some("operator_01")), &[dated], now()),
            Verdict::Refused(Refusal::SeatExpired { .. })
        ));
    }

    #[test]
    fn a_seat_with_no_expiry_outlasts_a_dated_one() {
        let mut dated = seat("seat_01", "active");
        dated.expires_at = Some("2026-09-01T00:00:00Z".to_string());
        let open = seat("seat_02", "active");

        let verdict = adjudicate(
            &install("active", Some("operator_01")),
            &[dated, open],
            now(),
        );

        assert_eq!(
            verdict,
            Verdict::Entitled {
                seat: "seat_02".to_string(),
                tier: Tier::Standard
            }
        );
    }

    #[test]
    fn the_seat_that_lasts_longest_is_the_one_run_on() {
        let mut soon = seat("seat_01", "active");
        soon.expires_at = Some("2026-09-01T00:00:00Z".to_string());
        let mut later = seat("seat_02", "active");
        later.expires_at = Some("2026-12-01T00:00:00Z".to_string());

        let verdict = adjudicate(
            &install("active", Some("operator_01")),
            &[soon, later],
            now(),
        );

        assert_eq!(
            verdict,
            Verdict::Entitled {
                seat: "seat_02".to_string(),
                tier: Tier::Standard
            }
        );
    }

    #[test]
    fn a_revoked_seat_with_no_recorded_reason_still_says_something() {
        let revoked = seat("seat_01", "revoked");

        let verdict = adjudicate(&install("active", Some("operator_01")), &[revoked], now());

        assert_eq!(
            verdict,
            Verdict::Refused(Refusal::SeatRevoked {
                reason: "no reason was recorded".to_string(),
                revoked_at: None,
            })
        );
    }

    #[test]
    fn an_elevated_seat_reports_its_tier() {
        let mut elevated = seat("seat_01", "active");
        elevated.tier = "elevated".to_string();

        assert_eq!(
            adjudicate(&install("active", Some("operator_01")), &[elevated], now()),
            Verdict::Entitled {
                seat: "seat_01".to_string(),
                tier: Tier::Elevated
            }
        );
    }

    // -- the grace table ---------------------------------------------------

    #[test]
    fn every_row_of_the_grace_table_is_the_documented_one() {
        let hours = |impact, tier| grace_period(impact, tier, None).as_secs() / 3600;

        assert_eq!(hours(ImpactLevel::Commercial, Tier::Standard), 72);
        assert_eq!(hours(ImpactLevel::Commercial, Tier::Elevated), 24);
        assert_eq!(hours(ImpactLevel::FedrampModerate, Tier::Standard), 24);
        assert_eq!(hours(ImpactLevel::FedrampModerate, Tier::Elevated), 4);
        assert_eq!(hours(ImpactLevel::Il2, Tier::Standard), 24);
        assert_eq!(hours(ImpactLevel::Il2, Tier::Elevated), 4);
        assert_eq!(hours(ImpactLevel::FedrampHigh, Tier::Standard), 4);
        assert_eq!(hours(ImpactLevel::FedrampHigh, Tier::Elevated), 0);
        assert_eq!(hours(ImpactLevel::Il4, Tier::Standard), 4);
        assert_eq!(hours(ImpactLevel::Il4, Tier::Elevated), 0);
        assert_eq!(hours(ImpactLevel::Il5, Tier::Standard), 0);
        assert_eq!(hours(ImpactLevel::Il5, Tier::Elevated), 0);
    }

    #[test]
    fn an_impact_level_this_build_does_not_know_gets_no_grace_at_all() {
        assert_eq!(ImpactLevel::parse("il6"), ImpactLevel::Unknown);
        assert_eq!(
            grace_period(ImpactLevel::Unknown, Tier::Standard, None),
            Duration::ZERO
        );
    }

    #[test]
    fn a_tier_this_build_does_not_know_gets_the_stricter_row() {
        assert_eq!(Tier::parse("privileged"), Tier::Elevated);
        assert_eq!(
            grace_period(ImpactLevel::Commercial, Tier::parse("privileged"), None),
            Duration::from_secs(24 * 3600)
        );
    }

    #[test]
    fn a_local_cap_may_shorten_the_window() {
        let capped = grace_period(
            ImpactLevel::Commercial,
            Tier::Standard,
            Some(Duration::from_secs(600)),
        );

        assert_eq!(capped, Duration::from_secs(600));
    }

    #[test]
    fn a_local_cap_may_never_lengthen_the_window() {
        let capped = grace_period(
            ImpactLevel::FedrampHigh,
            Tier::Elevated,
            Some(Duration::from_secs(30 * 24 * 3600)),
        );

        assert_eq!(
            capped,
            Duration::ZERO,
            "a file on the governed machine cannot widen its own offline window"
        );
    }

    // -- admission ---------------------------------------------------------

    #[test]
    fn a_fresh_entitlement_admits_a_turn() {
        let standing = entitled(4 * 3600, now());

        assert_eq!(
            admit(Some(&standing), None, now()),
            SeatAdmission::Admit {
                tier: Tier::Standard
            }
        );
    }

    #[test]
    fn an_entitlement_inside_its_grace_still_admits() {
        let standing = entitled(4 * 3600, at("2026-08-29T09:00:00Z"));

        assert_eq!(
            admit(Some(&standing), Some("connection refused"), now()),
            SeatAdmission::Admit {
                tier: Tier::Standard
            }
        );
    }

    #[test]
    fn an_entitlement_exactly_at_the_end_of_its_grace_still_admits() {
        let standing = entitled(4 * 3600, at("2026-08-29T08:00:00Z"));

        assert!(matches!(
            admit(Some(&standing), None, now()),
            SeatAdmission::Admit { .. }
        ));
    }

    #[test]
    fn an_entitlement_a_second_past_its_grace_is_unavailable() {
        let standing = entitled(4 * 3600, at("2026-08-29T07:59:59Z"));

        assert_eq!(
            admit(Some(&standing), Some("connection refused"), now()),
            SeatAdmission::Unavailable {
                since: Some(at("2026-08-29T07:59:59Z")),
                grace_until: Some(at("2026-08-29T11:59:59Z")),
                last_error: Some("connection refused".to_string()),
            }
        );
    }

    #[test]
    fn a_zero_grace_organization_needs_the_plane_for_every_turn() {
        let standing = entitled(0, at("2026-08-29T11:59:59Z"));

        assert!(
            matches!(
                admit(Some(&standing), None, now()),
                SeatAdmission::Unavailable { .. }
            ),
            "one second past a zero-length window is already outside it"
        );
    }

    #[test]
    fn a_cached_refusal_never_ages_into_permission() {
        let standing = Standing {
            verdict: Verdict::Refused(Refusal::SeatRevoked {
                reason: "offboarded".to_string(),
                revoked_at: None,
            }),
            checked_at: at("2020-01-01T00:00:00Z"),
            grace_secs: 72 * 3600,
            impact: ImpactLevel::Commercial,
        };

        assert_eq!(
            admit(Some(&standing), Some("connection refused"), now()),
            SeatAdmission::Refuse(Refusal::SeatRevoked {
                reason: "offboarded".to_string(),
                revoked_at: None,
            })
        );
    }

    #[test]
    fn a_daemon_that_has_never_reached_the_plane_admits_nothing() {
        assert_eq!(
            admit(None, Some("connection refused"), now()),
            SeatAdmission::Unavailable {
                since: None,
                grace_until: None,
                last_error: Some("connection refused".to_string()),
            }
        );
    }

    // -- freshness and refusal mapping -------------------------------------

    #[test]
    fn a_standing_younger_than_one_interval_is_fresh() {
        let standing = entitled(0, at("2026-08-29T11:59:30Z"));

        assert!(is_fresh(Some(&standing), Duration::from_secs(60), now()));
    }

    #[test]
    fn a_standing_older_than_one_interval_is_not_fresh() {
        let standing = entitled(0, at("2026-08-29T11:58:00Z"));

        assert!(!is_fresh(Some(&standing), Duration::from_secs(60), now()));
    }

    #[test]
    fn no_standing_is_never_fresh() {
        assert!(!is_fresh(None, Duration::from_secs(60), now()));
    }

    #[test]
    fn a_seat_refusal_and_an_outage_are_different_refusals() {
        let revoked = SeatAdmission::Refuse(Refusal::SeatRevoked {
            reason: "offboarded".to_string(),
            revoked_at: None,
        });
        let outage = SeatAdmission::Unavailable {
            since: Some(now()),
            grace_until: Some(now()),
            last_error: Some("connection refused".to_string()),
        };

        assert!(matches!(
            turn_refusal(&revoked, "https://plane.test"),
            Some(TurnRefusal::Seat { .. })
        ));
        assert!(matches!(
            turn_refusal(&outage, "https://plane.test"),
            Some(TurnRefusal::PlaneUnavailable { .. })
        ));
    }

    #[test]
    fn an_admitted_seat_produces_no_refusal() {
        let admitted = SeatAdmission::Admit {
            tier: Tier::Elevated,
        };

        assert!(turn_refusal(&admitted, "https://plane.test").is_none());
    }

    #[test]
    fn a_seat_refusal_carries_the_reason_an_operator_acts_on() {
        let refusal = turn_refusal(
            &SeatAdmission::Refuse(Refusal::SeatRevoked {
                reason: "offboarded".to_string(),
                revoked_at: Some("2026-08-29T11:00:00Z".to_string()),
            }),
            "https://plane.test",
        )
        .expect("a revoked seat refuses");

        let TurnRefusal::Seat { reason } = refusal else {
            panic!("a seat refusal must be a seat refusal");
        };
        assert!(reason.contains("offboarded"));
        assert!(reason.contains("organization administrator"));
    }

    #[test]
    fn an_outage_refusal_names_the_plane_and_when_the_grace_ended() {
        let refusal = turn_refusal(
            &SeatAdmission::Unavailable {
                since: Some(at("2026-08-29T07:00:00Z")),
                grace_until: Some(at("2026-08-29T11:00:00Z")),
                last_error: Some("connection refused".to_string()),
            },
            "https://plane.test",
        )
        .expect("an outage refuses");

        let TurnRefusal::PlaneUnavailable { reason } = refusal else {
            panic!("an outage must be a plane refusal");
        };
        assert!(reason.contains("https://plane.test"));
        assert!(reason.contains("connection refused"));
        assert!(reason.contains("2026-08-29T11:00:00Z"));
    }

    #[test]
    fn a_daemon_that_never_confirmed_a_seat_says_exactly_that() {
        let refusal = turn_refusal(
            &SeatAdmission::Unavailable {
                since: None,
                grace_until: None,
                last_error: None,
            },
            "https://plane.test",
        )
        .expect("an outage refuses");

        let TurnRefusal::PlaneUnavailable { reason } = refusal else {
            panic!("an outage must be a plane refusal");
        };
        assert!(reason.contains("never confirmed"));
    }

    #[test]
    fn a_zero_grace_entitlement_names_the_absence_of_grace() {
        let refusal = turn_refusal(
            &SeatAdmission::Unavailable {
                since: Some(at("2026-08-29T11:00:00Z")),
                grace_until: None,
                last_error: None,
            },
            "https://plane.test",
        )
        .expect("an outage refuses");

        let TurnRefusal::PlaneUnavailable { reason } = refusal else {
            panic!("an outage must be a plane refusal");
        };
        assert!(reason.contains("no offline grace"));
    }

    // -- the wire ----------------------------------------------------------

    #[test]
    fn a_standing_survives_a_round_trip_through_its_cache_form() {
        let standing = entitled(4 * 3600, now());
        let text = serde_json::to_string(&standing).expect("serializable");

        assert_eq!(
            serde_json::from_str::<Standing>(&text).expect("readable"),
            standing
        );
    }

    #[test]
    fn every_refusal_reports_the_word_its_wire_tag_uses() {
        let cases = [
            (
                Refusal::SeatRevoked {
                    reason: String::new(),
                    revoked_at: None,
                },
                "seat_revoked",
            ),
            (Refusal::SeatExpired { expires_at: None }, "seat_expired"),
            (
                Refusal::SeatNotActive {
                    status: String::new(),
                },
                "seat_not_active",
            ),
            (Refusal::NoSeat, "no_seat"),
            (
                Refusal::InstallNotActive {
                    status: String::new(),
                },
                "install_not_active",
            ),
            (Refusal::InstallUnbound, "install_unbound"),
            (
                Refusal::CredentialRejected {
                    status: 403,
                    message: String::new(),
                },
                "credential_rejected",
            ),
        ];

        for (refusal, word) in cases {
            assert_eq!(refusal.kind(), word);
            let encoded = serde_json::to_value(&refusal).expect("serializable");
            assert_eq!(encoded["kind"], serde_json::Value::String(word.to_string()));
        }
    }

    #[test]
    fn a_row_reads_with_every_optional_field_absent() {
        let row: SeatRow =
            serde_json::from_value(serde_json::json!({ "id": "seat_01" })).expect("readable");

        assert_eq!(row.id, "seat_01");
        assert_eq!(row.status, "");
        assert_eq!(row.expires_at, None);
    }
}
