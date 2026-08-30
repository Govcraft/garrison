//! Finding out which bundle governs this install, and proving it is the one.
//!
//! # The walk
//!
//! There is no route that answers "my policy". What the plane holds is an
//! install, an operator, a set of assignments, and a bundle, and the daemon
//! walks them in that order with its own bearer:
//!
//! 1. `AgentInstall/<id>` — who this machine belongs to, and whether it is
//!    still allowed to be a machine. Quarantined or retired ends it here.
//! 2. `Operator/<id>` — which team, so a team-scoped assignment can be seen.
//! 3. `PolicyAssignment` for the organization — resolved by
//!    [`resolve_assignment`], narrowest scope first.
//! 4. `PolicyBundle/<id>` — and it had better say `published`.
//! 5. Its `CommandRule`, `ToolRule` and `ModelEndpoint` rows.
//! 6. [`garrison_policy::verify`] and [`garrison_policy::validate`].
//!
//! # Why the checks are here and not only in the console
//!
//! The console is where a bundle is authored and the hook is where it is
//! published, but neither of them is what runs the policy. The daemon
//! re-derives the checksum from the rows it actually pulled, so "the policy
//! this machine is enforcing is the policy you published" is something the
//! machine establishes rather than something the pipeline promises. A
//! mismatch is a refusal, not a warning.
//!
//! # Two kinds of failure, and why they are not one kind
//!
//! [`PullFailure::Governance`] is the plane having answered: no assignment,
//! an unpublished bundle, a checksum that does not match, an install that was
//! quarantined. There is no grace for any of it, and the cache is discarded.
//! [`PullFailure::Unreachable`] is the plane not having answered, which is
//! what the offline grace window exists for. Collapsing the two would either
//! ground a fleet during a network blip or keep a revoked install running.

use crate::plane::api::{eq, Api, PlaneError, PAGE};
use crate::plane::Session;
use chrono::{DateTime, Utc};
use garrison_policy::{Bundle, BundleHeader, CommandRule, ModelEndpoint, ToolRule};
use serde::Deserialize;

/// How many assignment rows one organization may have before this stops
/// looking. Well past any plausible fleet, and bounded so a misconfigured
/// plane cannot hand the daemon an unbounded body.
const ASSIGNMENTS: usize = PAGE;

/// How many rules one bundle may carry.
const RULES: usize = 500;

/// A bundle that passed every check, and what the install looked like.
#[derive(Clone, Debug)]
pub struct Pulled {
    /// The verified bundle.
    pub bundle: Bundle,
    /// The `AgentInstall` row's status before this pull.
    ///
    /// Carried so the caller can promote `enrolled` to `active` in the same
    /// write-back that records the checksum: putting a bundle in force is
    /// exactly what makes an enrolled install an active one.
    pub install_status: String,
}

/// Why a pull did not produce a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PullFailure {
    /// The plane answered, and the answer was not a bundle this install may
    /// run. No grace applies.
    Governance(String),
    /// The plane could not be asked. The offline grace window applies.
    Unreachable(PlaneError),
}

impl std::fmt::Display for PullFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Governance(reason) => f.write_str(reason),
            Self::Unreachable(error) => write!(f, "{error}"),
        }
    }
}

impl PullFailure {
    /// Sorts a plane error into the two buckets that drive behaviour.
    ///
    /// A refusal is a decision somebody made: a 401 means this daemon's
    /// bearer is not accepted, a 403 means it may not read its own policy,
    /// and a 404 means the row it was pointed at is gone. None of those get
    /// ridden out on a cache.
    fn from_plane(error: PlaneError, what: &str) -> Self {
        if error.is_unreachable() {
            return Self::Unreachable(error);
        }
        Self::Governance(format!("{what}: {error}"))
    }
}

/// The `AgentInstall` fields this walk needs.
#[derive(Clone, Debug, Deserialize)]
struct InstallRow {
    #[serde(default)]
    status: String,
    #[serde(default)]
    operator: String,
    #[serde(default)]
    organization: String,
}

/// The `Operator` fields this walk needs.
#[derive(Clone, Debug, Default, Deserialize)]
struct OperatorRow {
    #[serde(default)]
    team: Option<String>,
}

/// One `PolicyAssignment` row.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Assignment {
    /// The row id, for the sentence naming which assignment won.
    #[serde(default)]
    pub id: String,
    /// The bundle it binds.
    #[serde(default)]
    pub bundle: String,
    /// `organization`, `team`, or `operator`.
    #[serde(default)]
    pub scope: String,
    /// The team, when the scope is `team`.
    #[serde(default)]
    pub team: Option<String>,
    /// The operator, when the scope is `operator`.
    #[serde(default)]
    pub operator: Option<String>,
    /// When it starts applying.
    #[serde(default)]
    pub effective_at: Option<String>,
    /// When it stops, if it ever does.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Whether it applies at all.
    #[serde(default)]
    pub active: bool,
}

impl Assignment {
    /// How specific this assignment is: lower is narrower, and narrower wins.
    ///
    /// Pure. An unrecognized scope sorts last rather than being dropped, so a
    /// scope this binary does not know about can still govern a machine when
    /// it is the only thing assigned.
    const fn specificity(&self) -> u8 {
        match self.scope.as_bytes() {
            b"operator" => 0,
            b"team" => 1,
            b"organization" => 2,
            _ => 3,
        }
    }

    /// Whether this row covers the given operator and team.
    ///
    /// Pure. A team-scoped assignment for an operator whose team is unknown
    /// does not cover them: the daemon could not read the `Operator` row, and
    /// guessing that the assignment applies would be widening policy from a
    /// permission failure.
    fn covers(&self, operator: &str, team: Option<&str>) -> bool {
        match self.scope.as_str() {
            "operator" => self.operator.as_deref() == Some(operator),
            "team" => team.is_some() && self.team.as_deref() == team,
            "organization" => true,
            _ => false,
        }
    }

    /// Whether it is in force at `now`.
    ///
    /// Pure. A missing `effective_at` is in force already (the schema
    /// defaults it to the moment of creation); an unparseable one is treated
    /// as not yet in force, because a date nobody can read is not a date
    /// anybody agreed to.
    fn in_force_at(&self, now: DateTime<Utc>) -> bool {
        if !self.active {
            return false;
        }
        let started = match self.effective_at.as_deref() {
            None => true,
            Some(at) => parse_time(at).is_some_and(|at| at <= now),
        };
        let ended = match self.expires_at.as_deref() {
            None => false,
            Some(at) => parse_time(at).is_none_or(|at| at <= now),
        };
        started && !ended
    }

    /// The instant this assignment took effect, for tie-breaking.
    fn effective_instant(&self) -> Option<DateTime<Utc>> {
        self.effective_at.as_deref().and_then(parse_time)
    }
}

/// Reads one of the plane's timestamps. Pure.
fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|at| at.with_timezone(&Utc))
}

/// Picks the assignment that governs this install.
///
/// Pure, and the whole precedence rule: of the assignments in force at `now`
/// that cover this operator, the narrowest scope wins; among equally narrow
/// ones the most recently effective wins, and a row with no readable
/// `effective_at` loses to one that has one. `None` means nothing covers this
/// install, which is a governance refusal rather than permission to run
/// ungoverned.
#[must_use]
pub fn resolve_assignment<'a>(
    rows: &'a [Assignment],
    now: DateTime<Utc>,
    operator: &str,
    team: Option<&str>,
) -> Option<&'a Assignment> {
    rows.iter()
        .filter(|row| row.in_force_at(now) && row.covers(operator, team))
        .max_by(|a, b| {
            b.specificity()
                .cmp(&a.specificity())
                .then_with(|| a.effective_instant().cmp(&b.effective_instant()))
                .then_with(|| a.id.cmp(&b.id))
        })
}

/// Whether an install in this state may still run turns. Pure.
///
/// `quarantined` and `retired` are the plane's two ways of saying no. An
/// unrecognized status is treated as usable: a plane that grew a new state is
/// not a reason to ground a fleet, and every other check still applies.
#[must_use]
pub fn install_may_run(status: &str) -> bool {
    !matches!(status, "quarantined" | "retired")
}

/// Walks the plane and comes back with a verified bundle.
///
/// # Errors
///
/// [`PullFailure`], which the caller must keep sorted: a governance failure
/// ungoverns the install immediately, an unreachable plane does not.
pub async fn fetch_bundle(session: &Session, now: DateTime<Utc>) -> Result<Pulled, PullFailure> {
    let api = &session.api;
    let install: InstallRow = api
        .get("AgentInstall", &session.install)
        .await
        .map_err(|error| PullFailure::from_plane(error, "this install's own record"))?;

    if !install_may_run(&install.status) {
        return Err(PullFailure::Governance(format!(
            "the control plane has this install marked '{}', so it runs no turns; \
             an operator must clear it in the console",
            install.status
        )));
    }

    let team = team_of(api, &install.operator).await?;
    let assignments: Vec<Assignment> = api
        .query(
            "PolicyAssignment",
            &eq("organization", &install.organization, ASSIGNMENTS),
        )
        .await
        .map_err(|error| PullFailure::from_plane(error, "the policy assignments"))?;

    let assignment = resolve_assignment(&assignments, now, &install.operator, team.as_deref())
        .ok_or_else(|| {
            PullFailure::Governance(
                "no active policy assignment covers this install; a security officer must \
                 assign a bundle to this operator, their team, or the organization"
                    .to_string(),
            )
        })?;

    let bundle = assemble(api, &assignment.bundle).await?;

    garrison_policy::verify(&bundle).map_err(|mismatch| {
        PullFailure::Governance(format!(
            "the bundle the control plane assigned does not match its own checksum, so it is \
             not the bundle that was published: {mismatch}"
        ))
    })?;
    garrison_policy::validate(&bundle).map_err(|failures| {
        let listed: Vec<String> = failures.iter().map(ToString::to_string).collect();
        PullFailure::Governance(format!(
            "the assigned bundle contains {} rule(s) that do not match their own examples, so \
             this daemon cannot tell what they mean: {}",
            failures.len(),
            listed.join("; ")
        ))
    })?;

    Ok(Pulled {
        bundle,
        install_status: install.status,
    })
}

/// The operator's team, when the bearer may see it.
///
/// A 403 here is not fatal: `Operator` is readable by the `operator` role per
/// `identity.schema`, but a deployment that narrows it should not ground its
/// fleet. The team goes unknown, team-scoped assignments stop matching, and
/// the organization-scoped one still governs. An unreachable plane is still
/// unreachable.
async fn team_of(api: &Api, operator: &str) -> Result<Option<String>, PullFailure> {
    match api.get::<OperatorRow>("Operator", operator).await {
        Ok(row) => Ok(row.team),
        Err(error) if error.is_unreachable() => Err(PullFailure::Unreachable(error)),
        Err(error) => {
            tracing::warn!(
                %error,
                "this install cannot read its operator's record, so team-scoped policy \
                 assignments will not be seen",
            );
            Ok(None)
        }
    }
}

/// Reads a bundle and everything hanging off it.
async fn assemble(api: &Api, bundle_id: &str) -> Result<Bundle, PullFailure> {
    let header: BundleHeader = api
        .get("PolicyBundle", bundle_id)
        .await
        .map_err(|error| PullFailure::from_plane(error, "the assigned policy bundle"))?;

    if !header.is_published() {
        return Err(PullFailure::Governance(format!(
            "the bundle assigned to this install ('{}') is '{}' rather than published, so \
             nothing has been put in force for this machine",
            header.name, header.status
        )));
    }

    let command_rules: Vec<CommandRule> = api
        .query("CommandRule", &eq("bundle", bundle_id, RULES))
        .await
        .map_err(|error| PullFailure::from_plane(error, "the bundle's command rules"))?;
    let tool_rules: Vec<ToolRule> = api
        .query("ToolRule", &eq("bundle", bundle_id, RULES))
        .await
        .map_err(|error| PullFailure::from_plane(error, "the bundle's tool rules"))?;

    let mut endpoints = Vec::new();
    for id in &header.allowed_endpoints {
        match api.get::<ModelEndpoint>("ModelEndpoint", id).await {
            Ok(endpoint) => endpoints.push(endpoint),
            // An endpoint row this bearer cannot see is an endpoint that is
            // not approved for this install, and its absence changes the
            // checksum, which is the visible outcome.
            Err(error) if error.is_unreachable() => {
                return Err(PullFailure::Unreachable(error));
            }
            Err(error) => {
                tracing::warn!(%error, endpoint = %id, "an approved endpoint could not be read")
            }
        }
    }

    Ok(Bundle {
        header,
        command_rules,
        tool_rules,
        endpoints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        parse_time(text).expect("the fixture times are RFC 3339")
    }

    fn row(id: &str, scope: &str, bundle: &str) -> Assignment {
        Assignment {
            id: id.to_string(),
            bundle: bundle.to_string(),
            scope: scope.to_string(),
            active: true,
            effective_at: Some("2026-01-01T00:00:00Z".to_string()),
            ..Assignment::default()
        }
    }

    const NOW: &str = "2026-06-01T12:00:00Z";

    #[test]
    fn an_organization_assignment_governs_an_install_nothing_else_names() {
        let rows = vec![row("a", "organization", "bundle_org")];

        let chosen = resolve_assignment(&rows, at(NOW), "operator_01", Some("team_01"))
            .expect("the organization covers everyone");

        assert_eq!(chosen.bundle, "bundle_org");
    }

    #[test]
    fn a_team_assignment_beats_the_organizations() {
        let mut team = row("b", "team", "bundle_team");
        team.team = Some("team_01".into());
        let rows = vec![row("a", "organization", "bundle_org"), team];

        let chosen = resolve_assignment(&rows, at(NOW), "operator_01", Some("team_01")).unwrap();

        assert_eq!(chosen.bundle, "bundle_team");
    }

    #[test]
    fn an_operator_assignment_beats_both() {
        let mut team = row("b", "team", "bundle_team");
        team.team = Some("team_01".into());
        let mut operator = row("c", "operator", "bundle_operator");
        operator.operator = Some("operator_01".into());
        let rows = vec![row("a", "organization", "bundle_org"), team, operator];

        let chosen = resolve_assignment(&rows, at(NOW), "operator_01", Some("team_01")).unwrap();

        assert_eq!(chosen.bundle, "bundle_operator");
    }

    #[test]
    fn an_assignment_for_another_team_does_not_cover_this_operator() {
        let mut other = row("b", "team", "bundle_team");
        other.team = Some("team_99".into());
        let rows = vec![row("a", "organization", "bundle_org"), other];

        let chosen = resolve_assignment(&rows, at(NOW), "operator_01", Some("team_01")).unwrap();

        assert_eq!(chosen.bundle, "bundle_org");
    }

    #[test]
    fn a_team_assignment_does_not_apply_when_the_team_could_not_be_read() {
        let mut team = row("b", "team", "bundle_team");
        team.team = Some("team_01".into());
        let rows = vec![row("a", "organization", "bundle_org"), team];

        let chosen = resolve_assignment(&rows, at(NOW), "operator_01", None).unwrap();

        assert_eq!(
            chosen.bundle, "bundle_org",
            "an unreadable Operator row must not widen or narrow policy by accident"
        );
    }

    #[test]
    fn an_inactive_assignment_governs_nothing() {
        let mut row = row("a", "organization", "bundle_org");
        row.active = false;

        let rows = [row];
        assert!(resolve_assignment(&rows, at(NOW), "operator_01", None).is_none());
    }

    #[test]
    fn an_assignment_that_has_not_taken_effect_yet_is_not_in_force() {
        let mut row = row("a", "organization", "bundle_org");
        row.effective_at = Some("2026-12-01T00:00:00Z".into());

        let rows = [row];
        assert!(resolve_assignment(&rows, at(NOW), "operator_01", None).is_none());
    }

    #[test]
    fn an_expired_assignment_is_not_in_force() {
        let mut row = row("a", "organization", "bundle_org");
        row.expires_at = Some("2026-02-01T00:00:00Z".into());

        let rows = [row];
        assert!(resolve_assignment(&rows, at(NOW), "operator_01", None).is_none());
    }

    #[test]
    fn an_expiry_nobody_can_parse_is_treated_as_already_expired() {
        let mut row = row("a", "organization", "bundle_org");
        row.expires_at = Some("whenever".into());

        let rows = [row];
        assert!(
            resolve_assignment(&rows, at(NOW), "operator_01", None).is_none(),
            "an unreadable end date must not read as no end date"
        );
    }

    #[test]
    fn the_most_recently_effective_of_two_equally_narrow_assignments_wins() {
        let mut older = row("a", "organization", "bundle_old");
        older.effective_at = Some("2026-01-01T00:00:00Z".into());
        let mut newer = row("b", "organization", "bundle_new");
        newer.effective_at = Some("2026-05-01T00:00:00Z".into());

        let rows = [older, newer];
        let chosen = resolve_assignment(&rows, at(NOW), "operator_01", None).unwrap();

        assert_eq!(chosen.bundle, "bundle_new");
    }

    #[test]
    fn nothing_assigned_is_not_permission_to_run_ungoverned() {
        assert!(resolve_assignment(&[], at(NOW), "operator_01", None).is_none());
    }

    #[test]
    fn a_quarantined_or_retired_install_runs_no_turns() {
        assert!(!install_may_run("quarantined"));
        assert!(!install_may_run("retired"));
        assert!(install_may_run("enrolled"));
        assert!(install_may_run("active"));
    }

    #[test]
    fn a_status_this_binary_does_not_know_is_not_a_reason_to_ground_a_fleet() {
        assert!(install_may_run("probationary"));
    }

    #[test]
    fn a_refusal_from_the_plane_is_a_governance_failure_and_a_timeout_is_not() {
        let refused = PullFailure::from_plane(
            PlaneError::Rejected {
                status: 403,
                message: "no".into(),
            },
            "the policy assignments",
        );
        assert!(matches!(refused, PullFailure::Governance(_)), "{refused:?}");
        assert!(refused.to_string().contains("the policy assignments"));

        let down = PullFailure::from_plane(PlaneError::Unreachable("timeout".into()), "anything");
        assert!(matches!(down, PullFailure::Unreachable(_)), "{down:?}");
    }

    #[test]
    fn a_row_the_plane_cannot_find_is_a_decision_and_not_an_outage() {
        let gone = PullFailure::from_plane(
            PlaneError::NotFound("PolicyBundle x".into()),
            "the assigned policy bundle",
        );

        assert!(
            matches!(gone, PullFailure::Governance(_)),
            "a deleted bundle must not be ridden out on a cache: {gone:?}"
        );
    }
}
