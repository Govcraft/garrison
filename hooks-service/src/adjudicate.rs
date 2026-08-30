//! Whether one enrollment token may be spent right now.
//!
//! This is deliberately pure: it takes the token row and the current instant
//! and returns a verdict. No network, no clock read, no database. Every rule
//! that decides whether a machine joins the fleet is therefore testable by
//! constructing a struct, and the tests below are the specification.
//!
//! The order of the checks is the order a reader would ask the questions, and
//! the refusal text is written for the security officer reading the refused
//! row later, not for the daemon, which is not entitled to know why.
//!
//! The second half of the file is the operator's side of the same question
//! (R4 in `docs/control-plane.md`): once the token has named a person, is
//! that person still someone the directory says may hold a machine?

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::plane::{EnrollmentTokenRow, OperatorRow, OrganizationRow};

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
/// There is deliberately no issuer check here. The row used to carry an
/// `issuer` column compared against the plane's configured one, and the
/// comment above it claimed that refused an artifact signed for some other
/// purpose against the same key. It could not: acton-service validates `iss`
/// against exactly one configured issuer, so every artifact that reaches this
/// function was minted under that one, and an attacker holding the signing key
/// mints under it too. What the check actually caught was a provisioning typo
/// in a hand-written row, at the price of a `required` column on a frozen
/// surface and a doc comment that read like a security control.
///
/// What separates an enrollment artifact from a session token is its role set.
/// `enrollee` is granted write on `Redemption` and nothing else anywhere in the
/// bundle, and Cedar enforces that before this function is reached.
#[must_use]
pub fn adjudicate(token: &EnrollmentTokenRow, now: DateTime<Utc>) -> Verdict {
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

/// Whether the person the install would belong to may hold one (R4).
///
/// An operator must be `active`. When the directory is the authority, they
/// must also be a directory identity: a hand-typed row the sync has not yet
/// linked is a person the directory has not vouched for, and the refusal
/// says so, because the fix is a UPN that matches or a wait for the next
/// sync, not a new token.
pub fn operator_admissible(operator: &OperatorRow, directory_enabled: bool) -> Result<(), String> {
    if operator.status != "active" {
        return Err(format!("operator is not active ({})", operator.status));
    }
    if directory_enabled
        && operator
            .entra_object_id
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Err("operator is not linked to the directory".into());
    }
    Ok(())
}

/// Whether the organization's directory view is recent enough to enrol
/// against (R4).
///
/// A view older than `staleness` is one the sync has been failing to refresh
/// for longer than the operator allowed, and an enrollment against it could
/// admit someone the directory disabled after the last good tick. Fail
/// closed: refuse until a sync succeeds. A view that never synced is stale
/// by definition.
pub fn directory_fresh(
    organization: &OrganizationRow,
    now: DateTime<Utc>,
    staleness: Duration,
) -> Result<(), String> {
    const REFUSAL: &str =
        "directory view is stale; enrollment refused until the next successful sync";
    let synced = organization
        .directory_synced_at
        .as_deref()
        .and_then(parse_instant)
        .ok_or_else(|| REFUSAL.to_string())?;
    if organization.directory_sync_status.as_deref() != Some("ok") {
        return Err(REFUSAL.to_string());
    }
    let allowed = chrono::Duration::from_std(staleness).map_err(|_| REFUSAL.to_string())?;
    if now - synced > allowed {
        return Err(REFUSAL.to_string());
    }
    Ok(())
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

/// An RFC 3339 instant, or `None` if the text is not one.
#[must_use]
pub fn parse_instant(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        parse_instant("2026-08-29T00:00:00Z").expect("fixture instant parses")
    }

    fn token() -> EnrollmentTokenRow {
        EnrollmentTokenRow {
            id: "enrollmenttoken_01".into(),
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

    fn operator(status: &str, oid: Option<&str>) -> OperatorRow {
        OperatorRow {
            id: "operator_01".into(),
            upn: "dev@agency.gov".into(),
            display_name: "Dev".into(),
            email: None,
            entra_object_id: oid.map(str::to_owned),
            status: status.into(),
            organization: Some("organization_01".into()),
        }
    }

    fn organization(synced_at: Option<&str>, status: Option<&str>) -> OrganizationRow {
        OrganizationRow {
            id: "organization_01".into(),
            slug: "agency".into(),
            entra_tenant_id: Some("tenant".into()),
            entra_group_id: None,
            directory_synced_at: synced_at.map(str::to_owned),
            directory_sync_status: status.map(str::to_owned),
            active: true,
        }
    }

    #[test]
    fn a_live_token_is_accepted_and_names_its_tenant() {
        let verdict = adjudicate(&token(), now());
        assert_eq!(
            verdict,
            Verdict::Accept {
                organization: "organization_01".into()
            }
        );
        assert_eq!(verdict.reason(), "");
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
            let verdict = adjudicate(&row, now());
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
        assert!(adjudicate(&row, now()).reason().contains("provisional"));
    }

    #[test]
    fn an_expired_token_is_refused_and_the_boundary_is_exclusive() {
        let mut row = token();
        row.expires_at = Some("2026-08-29T00:00:00Z".into());
        assert_eq!(
            adjudicate(&row, now()),
            Verdict::Refuse("token expired".into())
        );
    }

    #[test]
    fn a_token_without_an_expiry_is_refused_not_admitted_forever() {
        let mut row = token();
        row.expires_at = None;
        assert!(adjudicate(&row, now()).reason().contains("no expiry"));
    }

    #[test]
    fn an_unreadable_expiry_is_refused_rather_than_ignored() {
        let mut row = token();
        row.expires_at = Some("whenever".into());
        assert!(adjudicate(&row, now())
            .reason()
            .contains("could not be read"));
    }

    #[test]
    fn a_spent_token_is_refused_and_says_the_count() {
        let mut row = token();
        row.uses = 5;
        assert!(adjudicate(&row, now()).reason().contains("5 of 5"));
    }

    #[test]
    fn a_token_bound_to_no_organization_is_refused() {
        let mut row = token();
        row.organization = None;
        assert!(adjudicate(&row, now())
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

    #[test]
    fn an_active_linked_operator_is_admissible_either_way() {
        assert_eq!(
            operator_admissible(&operator("active", Some("A")), false),
            Ok(())
        );
        assert_eq!(
            operator_admissible(&operator("active", Some("A")), true),
            Ok(())
        );
    }

    #[test]
    fn a_suspended_or_invited_operator_is_refused_and_the_status_is_named() {
        for status in ["suspended", "offboarded", "invited"] {
            let err = operator_admissible(&operator(status, Some("A")), false).unwrap_err();
            assert_eq!(err, format!("operator is not active ({status})"));
        }
    }

    #[test]
    fn an_unlinked_operator_is_refused_only_when_the_directory_is_the_authority() {
        assert_eq!(
            operator_admissible(&operator("active", None), false),
            Ok(())
        );
        assert_eq!(
            operator_admissible(&operator("active", Some("")), true),
            Err("operator is not linked to the directory".into())
        );
    }

    #[test]
    fn a_recently_synced_organization_is_fresh() {
        let org = organization(Some("2026-08-28T23:50:00Z"), Some("ok"));
        assert_eq!(
            directory_fresh(&org, now(), Duration::from_secs(900)),
            Ok(())
        );
    }

    #[test]
    fn a_view_older_than_the_staleness_bound_is_refused() {
        let org = organization(Some("2026-08-28T23:40:00Z"), Some("ok"));
        assert!(directory_fresh(&org, now(), Duration::from_secs(900)).is_err());
    }

    #[test]
    fn a_never_synced_organization_is_stale_by_definition() {
        assert!(
            directory_fresh(&organization(None, None), now(), Duration::from_secs(900)).is_err()
        );
    }

    #[test]
    fn a_recent_stamp_with_a_failed_status_is_still_refused() {
        let org = organization(Some("2026-08-28T23:59:00Z"), Some("failed"));
        assert!(directory_fresh(&org, now(), Duration::from_secs(900)).is_err());
    }
}
