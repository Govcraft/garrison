//! Reading the three rows the seat rule adjudicates.
//!
//! Three plane calls, in the order the rule needs them: the install (which
//! names its operator), that operator's seats, and the organization (whose
//! impact level sets the offline grace). Nothing is decided here;
//! [`super::verdict::adjudicate`] does that over the rows this returns.
//!
//! # A rejection is an answer, not an outage
//!
//! A 401 or 403 on any of these calls means the plane looked at this
//! install's bearer and refused it, which is a verdict and gets cached as
//! one: [`Refusal::CredentialRejected`] carries no grace, so the turn after
//! it is refused with a seat code rather than an unreachable-plane code. That
//! distinction is the whole reason [`PlaneError`] separates the two, and
//! collapsing them here would let a revoked credential ride out a 72-hour
//! window meant for a network blip.
//!
//! A 401 is retried exactly once, with the bearer revoked first: the one
//! benign cause of a 401 is a bearer that expired between being handed out
//! and being spent, and re-exchanging costs one round trip. A second 401 is
//! the plane meaning it.

use std::time::Duration;

use acton_reactive::prelude::*;
use chrono::{DateTime, Utc};

use crate::plane::api::{eq, PlaneError, PAGE};
use crate::plane::session::{Authenticate, RevokeBearer, Session};

use super::verdict::{
    adjudicate, grace_period, ImpactLevel, InstallRow, OrganizationRow, Refusal, SeatRow, Standing,
    Tier, Verdict,
};

/// How long the whole three-call check may take.
///
/// Each call is bounded by [`crate::plane::api::TIMEOUT`] on its own; this
/// bounds the sequence, including the exchange that may precede it, so a
/// plane that accepts connections and never answers cannot hold the monitor's
/// refresh open indefinitely.
pub const CHECK_DEADLINE: Duration = Duration::from_secs(20);

/// Reads the plane and returns what this install's standing is.
///
/// `cap` is the deployment's offline-grace ceiling; see
/// [`grace_period`]. `now` is passed rather than read so a test can fix the
/// clock the seat's expiry is measured against.
///
/// # Errors
///
/// [`PlaneError`] when the plane could not be reached or answered with
/// something unreadable. A plane that answered and said no is an `Ok`
/// carrying a refusing [`Standing`], because that is a verdict to cache
/// rather than an attempt to retry.
pub async fn fetch(
    session: &Session,
    cap: Option<Duration>,
    now: DateTime<Utc>,
) -> Result<Standing, PlaneError> {
    let install: InstallRow = session.api.get("AgentInstall", &session.install).await?;

    let seats = match install.operator.as_deref().filter(|id| !id.is_empty()) {
        Some(operator) => {
            session
                .api
                .query::<SeatRow>("Seat", &eq("operator", operator, PAGE))
                .await?
        }
        // No operator, no seats worth asking for: `adjudicate` refuses on the
        // install alone, and a query with an empty filter would read the
        // whole tenant's seats to learn nothing.
        None => Vec::new(),
    };

    let organization: OrganizationRow = session
        .api
        .get("Organization", &session.organization)
        .await?;

    let impact = ImpactLevel::parse(&organization.impact_level);
    let verdict = adjudicate(&install, &seats, now);
    let tier = match &verdict {
        Verdict::Entitled { tier, .. } => *tier,
        // A refusal carries no grace anyway; the stricter tier keeps the
        // stored window from ever being the generous one.
        Verdict::Refused(_) => Tier::Elevated,
    };

    Ok(Standing {
        verdict,
        checked_at: now,
        grace_secs: grace_period(impact, tier, cap).as_secs(),
        impact,
    })
}

/// Obtains a session, reads the rows, and turns a rejection into a verdict.
///
/// This is the whole network side of one seat check: authenticate through the
/// one component allowed to hold a bearer, spend it, and hand back either a
/// standing to cache or the reason the plane could not be asked. A 401 costs
/// one re-exchange; anything else is taken at face value.
///
/// # Errors
///
/// [`PlaneError`] when the plane could not be reached. Every answer the plane
/// actually gave — including a refusal of the credential — comes back as a
/// [`Standing`].
pub async fn check(
    plane: &ActorHandle,
    plane_url: &str,
    cap: Option<Duration>,
    now: DateTime<Utc>,
) -> Result<Standing, PlaneError> {
    let first = fetch(&authenticate(plane).await?, cap, now).await;

    let outcome = match first {
        // The one benign 401: a bearer that expired in the caller's hand.
        // Revoke it, exchange a fresh assertion, and take the second answer
        // as final however it comes back.
        Err(PlaneError::Rejected { status: 401, .. }) => {
            plane.send(RevokeBearer).await;
            fetch(&authenticate(plane).await?, cap, now).await
        }
        other => other,
    };

    match outcome {
        Ok(standing) => Ok(standing),
        Err(error) => {
            tracing::debug!(%error, plane = %plane_url, "the seat check did not read the plane");
            rejection_or_error(error, plane_url, cap, now)
        }
    }
}

/// Asks the one component that holds a bearer for an authenticated view.
///
/// An `AskError` is the plane session being gone, which is the daemon coming
/// apart rather than the plane being down; it reports as unreachable because
/// that is what it is from here, and the gate refuses either way.
async fn authenticate(plane: &ActorHandle) -> Result<Session, PlaneError> {
    match plane.ask(Authenticate).await {
        Ok(result) => result,
        Err(error) => Err(PlaneError::Unreachable(format!(
            "the daemon's credential holder did not answer ({error:?})"
        ))),
    }
}

/// Turns a plane answer into either a cached verdict or a transport failure.
///
/// Pure over the error. A rejection is a decision and becomes a `Standing`
/// with no grace; a missing install row is the same kind of fact, reported as
/// an install the plane no longer has. Everything else is the plane being
/// unavailable, which the grace table exists for.
fn rejection_or_error(
    error: PlaneError,
    plane_url: &str,
    cap: Option<Duration>,
    now: DateTime<Utc>,
) -> Result<Standing, PlaneError> {
    let refusal = match error {
        PlaneError::Rejected { status, message } => Refusal::CredentialRejected { status, message },
        PlaneError::NotFound(what) => {
            tracing::warn!(plane = %plane_url, %what, "the control plane has no row for this install");
            Refusal::InstallNotActive {
                status: "missing".to_string(),
            }
        }
        other => return Err(other),
    };

    Ok(Standing {
        verdict: Verdict::Refused(refusal),
        checked_at: now,
        grace_secs: grace_period(ImpactLevel::Unknown, Tier::Elevated, cap).as_secs(),
        impact: ImpactLevel::Unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-29T12:00:00Z")
            .expect("a fixed instant")
            .with_timezone(&Utc)
    }

    #[test]
    fn a_refused_credential_becomes_a_verdict_rather_than_an_outage() {
        let standing = rejection_or_error(
            PlaneError::Rejected {
                status: 403,
                message: "credential revoked".to_string(),
            },
            "https://plane.test",
            None,
            now(),
        )
        .expect("a rejection is an answer");

        assert_eq!(
            standing.verdict,
            Verdict::Refused(Refusal::CredentialRejected {
                status: 403,
                message: "credential revoked".to_string(),
            })
        );
        assert_eq!(standing.grace_secs, 0, "a rejection carries no grace");
    }

    #[test]
    fn a_missing_install_row_is_a_verdict_about_this_machine() {
        let standing = rejection_or_error(
            PlaneError::NotFound("AgentInstall x".to_string()),
            "https://plane.test",
            None,
            now(),
        )
        .expect("a missing row is an answer");

        assert_eq!(
            standing.verdict,
            Verdict::Refused(Refusal::InstallNotActive {
                status: "missing".to_string()
            })
        );
    }

    #[test]
    fn an_unreachable_plane_is_not_turned_into_a_verdict() {
        let error = rejection_or_error(
            PlaneError::Unreachable("connection refused".to_string()),
            "https://plane.test",
            None,
            now(),
        )
        .expect_err("an outage is not a verdict");

        assert!(error.is_unreachable());
    }

    #[test]
    fn an_unreadable_answer_is_not_turned_into_a_verdict() {
        let error = rejection_or_error(
            PlaneError::Malformed("Seat: expected a string".to_string()),
            "https://plane.test",
            None,
            now(),
        )
        .expect_err("a shape failure is not a verdict about a seat");

        assert!(matches!(error, PlaneError::Malformed(_)));
    }
}
