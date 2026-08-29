//! Whether one enrollment token may be spent right now.
//!
//! This is deliberately pure: it takes the token row and the current instant
//! and returns a verdict. No network, no clock read, no database. Every rule
//! that decides whether a machine joins the fleet is therefore testable by
//! constructing a struct, and the tests below are the specification.
//!
//! The order of the checks is the order a reader would ask the questions, and
//! the refusal text is written for the security officer reading the refused
//! row later — not for the daemon, which is not entitled to know why.

use chrono::{DateTime, Utc};

use crate::plane::EnrollmentTokenRow;

/// What the plane decided about a redemption request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Admit the install. Carries the tenant the token is bound to.
    Accept { organization: String },
    /// Refuse, with the reason recorded on the row.
    Refuse(String),
}

impl Verdict {
    /// The recorded reason, or an empty string for an acceptance.
    ///
    /// Only the tests read this: the hook matches on the variant so that a new
    /// verdict cannot be silently treated as a refusal with an odd message.
    #[cfg(test)]
    fn reason(&self) -> &str {
        match self {
            Self::Accept { .. } => "",
            Self::Refuse(reason) => reason,
        }
    }
}

/// Decide whether `token` may be spent at `now`.
///
/// `expected_issuer` is the `iss` the plane mints enrollment artifacts under.
/// The row records the issuer it was created for, and a mismatch means the
/// artifact was signed for some other purpose against the same key — the one
/// thing a shared signing key makes possible and a row can still catch.
#[must_use]
pub fn adjudicate(
    token: &EnrollmentTokenRow,
    expected_issuer: &str,
    now: DateTime<Utc>,
) -> Verdict {
    if token.issuer != expected_issuer {
        return Verdict::Refuse(format!(
            "token was issued for '{}', not '{expected_issuer}'",
            token.issuer
        ));
    }

    match token.status.as_str() {
        "issued" => {}
        "revoked" => return Verdict::Refuse("token has been revoked".into()),
        "redeemed" => return Verdict::Refuse("token has already been fully redeemed".into()),
        "expired" => return Verdict::Refuse("token is marked expired".into()),
        other => return Verdict::Refuse(format!("token is in unexpected state '{other}'")),
    }

    match token.expires_at.as_deref().map(parse_instant) {
        // No expiry recorded is a refusal, not a licence. A provisioning
        // grant that never lapses is the one thing this model must not have.
        None => return Verdict::Refuse("token records no expiry".into()),
        Some(None) => {
            return Verdict::Refuse("token expiry could not be read".into());
        }
        Some(Some(expiry)) if expiry <= now => {
            return Verdict::Refuse("token expired".into());
        }
        Some(Some(_)) => {}
    }

    if token.uses >= token.max_uses {
        return Verdict::Refuse(format!(
            "token is spent: {} of {} uses",
            token.uses, token.max_uses
        ));
    }

    match token.organization.as_deref() {
        Some(org) if !org.is_empty() => Verdict::Accept {
            organization: org.to_string(),
        },
        _ => Verdict::Refuse("token is not bound to an organization".into()),
    }
}

/// Which operator an accepted install belongs to.
///
/// An operator-scoped token already answers this, and its answer wins: a
/// grant that named a person is not overridden by a claim from the machine.
/// Only a broader token falls back to the reported UPN, which the caller must
/// then resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorSource {
    /// Use this operator id directly; the token named it.
    Bound(String),
    /// Resolve this UPN against the Operator table.
    ReportedUpn(String),
    /// Neither the token nor the daemon identified anyone.
    Unknown,
}

/// Decide where the install's operator comes from.
#[must_use]
pub fn operator_source(token: &EnrollmentTokenRow, reported_upn: &str) -> OperatorSource {
    if token.scope == "operator" {
        return match token.operator.as_deref() {
            Some(id) if !id.is_empty() => OperatorSource::Bound(id.to_string()),
            _ => OperatorSource::Unknown,
        };
    }
    let upn = reported_upn.trim();
    if upn.is_empty() {
        OperatorSource::Unknown
    } else {
        OperatorSource::ReportedUpn(upn.to_string())
    }
}

/// The token's state after a successful redemption.
///
/// Returns the new use count and the status that count implies, so the caller
/// patches one consistent pair rather than deriving the status separately and
/// risking a token that is spent but still reads `issued`.
#[must_use]
pub fn spend(token: &EnrollmentTokenRow) -> (i64, &'static str) {
    let uses = token.uses.saturating_add(1);
    if uses >= token.max_uses {
        (uses, "redeemed")
    } else {
        (uses, "issued")
    }
}

fn parse_instant(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "garrison-enrollment";

    fn now() -> DateTime<Utc> {
        parse_instant("2026-08-29T00:00:00Z").expect("fixture instant parses")
    }

    fn token() -> EnrollmentTokenRow {
        EnrollmentTokenRow {
            id: "enrollmenttoken_01".into(),
            issuer: ISSUER.into(),
            organization: Some("organization_01".into()),
            scope: "organization".into(),
            operator: None,
            max_uses: 5,
            uses: 0,
            status: "issued".into(),
            expires_at: Some("2026-08-31T00:00:00Z".into()),
            first_redeemed_at: None,
        }
    }

    #[test]
    fn a_live_token_is_accepted_and_names_its_tenant() {
        let verdict = adjudicate(&token(), ISSUER, now());
        assert_eq!(
            verdict,
            Verdict::Accept {
                organization: "organization_01".into()
            }
        );
        assert_eq!(verdict.reason(), "");
    }

    #[test]
    fn a_token_minted_for_another_purpose_is_refused() {
        let mut row = token();
        row.issuer = "garrison-control-plane".into();
        let verdict = adjudicate(&row, ISSUER, now());
        assert!(verdict.reason().contains("garrison-control-plane"));
    }

    #[test]
    fn each_terminal_status_refuses_with_its_own_reason() {
        for (status, expected) in [
            ("revoked", "revoked"),
            ("redeemed", "already been fully redeemed"),
            ("expired", "marked expired"),
        ] {
            let mut row = token();
            row.status = status.into();
            let verdict = adjudicate(&row, ISSUER, now());
            assert!(
                verdict.reason().contains(expected),
                "{status} refusal said {:?}",
                verdict.reason()
            );
        }
    }

    #[test]
    fn an_unknown_status_is_refused_rather_than_assumed_live() {
        let mut row = token();
        row.status = "provisional".into();
        assert!(adjudicate(&row, ISSUER, now())
            .reason()
            .contains("provisional"));
    }

    #[test]
    fn an_expired_token_is_refused_and_the_boundary_is_exclusive() {
        let mut row = token();
        row.expires_at = Some("2026-08-29T00:00:00Z".into());
        assert_eq!(
            adjudicate(&row, ISSUER, now()),
            Verdict::Refuse("token expired".into())
        );
    }

    #[test]
    fn a_token_without_an_expiry_is_refused_not_admitted_forever() {
        let mut row = token();
        row.expires_at = None;
        assert!(adjudicate(&row, ISSUER, now())
            .reason()
            .contains("no expiry"));
    }

    #[test]
    fn an_unreadable_expiry_is_refused_rather_than_ignored() {
        let mut row = token();
        row.expires_at = Some("whenever".into());
        assert!(adjudicate(&row, ISSUER, now())
            .reason()
            .contains("could not be read"));
    }

    #[test]
    fn a_spent_token_is_refused_and_says_the_count() {
        let mut row = token();
        row.uses = 5;
        assert!(adjudicate(&row, ISSUER, now()).reason().contains("5 of 5"));
    }

    #[test]
    fn a_token_bound_to_no_organization_is_refused() {
        let mut row = token();
        row.organization = None;
        assert!(adjudicate(&row, ISSUER, now())
            .reason()
            .contains("not bound to an organization"));
    }

    #[test]
    fn an_operator_scoped_token_ignores_the_reported_upn() {
        let mut row = token();
        row.scope = "operator".into();
        row.operator = Some("operator_01".into());
        assert_eq!(
            operator_source(&row, "someone.else@agency.gov"),
            OperatorSource::Bound("operator_01".into())
        );
    }

    #[test]
    fn an_operator_scoped_token_with_no_operator_identifies_nobody() {
        let mut row = token();
        row.scope = "operator".into();
        assert_eq!(
            operator_source(&row, "dev@agency.gov"),
            OperatorSource::Unknown
        );
    }

    #[test]
    fn a_broader_token_falls_back_to_the_reported_upn() {
        assert_eq!(
            operator_source(&token(), "  dev@agency.gov  "),
            OperatorSource::ReportedUpn("dev@agency.gov".into())
        );
    }

    #[test]
    fn a_broader_token_with_no_reported_upn_identifies_nobody() {
        assert_eq!(operator_source(&token(), "   "), OperatorSource::Unknown);
    }

    #[test]
    fn spending_the_last_use_marks_the_token_redeemed() {
        let mut row = token();
        row.uses = 4;
        assert_eq!(spend(&row), (5, "redeemed"));
    }

    #[test]
    fn spending_a_multi_use_token_leaves_it_issued() {
        assert_eq!(spend(&token()), (1, "issued"));
    }

    #[test]
    fn a_single_use_token_is_redeemed_by_its_first_spend() {
        let mut row = token();
        row.max_uses = 1;
        assert_eq!(spend(&row), (1, "redeemed"));
    }
}
