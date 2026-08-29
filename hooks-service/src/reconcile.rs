//! What one directory listing means for the plane's rows.
//!
//! This is the specification of the directory sync, and it is pure on
//! purpose: a listing, the operators, the console users, and a policy go in;
//! a plan of changes, or a refusal, comes out. No clock, no network. Every
//! rule in `docs/control-plane.md` (R1 through R5) is a branch here with a
//! test below, and the actor in `sync.rs` does nothing but fetch the inputs
//! and apply the outputs.
//!
//! The join key is `entra_object_id` (R1). A hand-typed operator without one
//! is linked exactly once by case-insensitive UPN match; after that the UPN
//! is a directory-owned attribute like any other and a rename patches the
//! same row (R2). Deprovisioning is the one place the sync takes something
//! away, and it is bounded: an empty listing is a refusal, and a listing that
//! would deprovision more than the policy's fraction of the active fleet is
//! refused whole (R5).

use std::collections::{HashMap, HashSet};

use crate::directory::DirectoryUser;
use crate::plane::{OperatorRow, SeatRow, UserRow};

/// The reason stamped on a seat revoked because the account was disabled.
pub const REASON_DISABLED: &str = "directory: account disabled";
/// The reason stamped on a seat revoked because the member was removed.
pub const REASON_REMOVED: &str = "directory: account removed";

/// Operator statuses, as the schema spells them.
pub mod status {
    pub const ACTIVE: &str = "active";
    pub const SUSPENDED: &str = "suspended";
    pub const OFFBOARDED: &str = "offboarded";
}

/// The guard rails a reconciliation runs under.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    /// The largest share of currently active operators one plan may suspend
    /// or offboard.
    pub max_offboard_fraction: f64,
}

/// One change to an `Operator` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorChange {
    /// A directory member with no operator row.
    Create {
        upn: String,
        display_name: String,
        email: Option<String>,
        entra_object_id: String,
        /// `active` for an enabled member, `suspended` for a disabled one.
        status: &'static str,
    },
    /// The one-time UPN link of a hand-typed row.
    Link { id: String, entra_object_id: String },
    /// Directory-owned attributes changed.
    Rename {
        id: String,
        upn: String,
        display_name: String,
        email: Option<String>,
    },
    /// Present and enabled, but not `active`.
    Reactivate { id: String },
    /// Present and `accountEnabled = false`.
    Suspend { id: String },
    /// Absent from the listing.
    Offboard { id: String },
}

impl OperatorChange {
    /// The row this change targets, if it targets an existing one.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Create { .. } => None,
            Self::Link { id, .. }
            | Self::Rename { id, .. }
            | Self::Reactivate { id }
            | Self::Suspend { id }
            | Self::Offboard { id } => Some(id),
        }
    }
}

/// One change to a console `User` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserChange {
    /// Record which directory identity this login is.
    Stamp {
        id: String,
        entra_object_id: String,
        org_slug: String,
    },
    /// The login's email follows the directory UPN.
    Rename { id: String, email: String },
    /// Login refused from now on.
    Deactivate { id: String, reason: &'static str },
}

/// Everything a reconciliation decided.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub operators: Vec<OperatorChange>,
    pub users: Vec<UserChange>,
    /// Operator ids the directory confirmed this round, for the per-row
    /// `directory_synced_at` stamp.
    pub confirmed: Vec<String>,
    /// Hand-typed operators with no object id and no UPN match. Reported,
    /// never offboarded: the directory never knew them.
    pub unlinked: Vec<String>,
}

impl Plan {
    /// A one-line summary for `Organization.directory_sync_detail`.
    #[must_use]
    pub fn summary(&self) -> String {
        let count =
            |pred: fn(&OperatorChange) -> bool| self.operators.iter().filter(|c| pred(c)).count();
        format!(
            "created {}, linked {}, renamed {}, reactivated {}, suspended {}, offboarded {}, unlinked {}, users changed {}",
            count(|c| matches!(c, OperatorChange::Create { .. })),
            count(|c| matches!(c, OperatorChange::Link { .. })),
            count(|c| matches!(c, OperatorChange::Rename { .. })),
            count(|c| matches!(c, OperatorChange::Reactivate { .. })),
            count(|c| matches!(c, OperatorChange::Suspend { .. })),
            count(|c| matches!(c, OperatorChange::Offboard { .. })),
            self.unlinked.len(),
            self.users.len(),
        )
    }
}

/// Why a listing was not acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The directory answered "nobody". Never treated as "everyone left".
    EmptyDirectory,
    /// The plan would deprovision too much of the active fleet at once.
    OffboardFractionExceeded {
        would_deprovision: usize,
        active: usize,
    },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyDirectory => write!(f, "directory returned no members"),
            Self::OffboardFractionExceeded {
                would_deprovision,
                active,
            } => write!(
                f,
                "refused: would deprovision {would_deprovision} of {active} active operators"
            ),
        }
    }
}

/// Decide what the listing means for this organization's rows.
pub fn reconcile(
    directory: &[DirectoryUser],
    operators: &[OperatorRow],
    users: &[UserRow],
    org_slug: &str,
    policy: &Policy,
) -> Result<Plan, Refusal> {
    if directory.is_empty() {
        return Err(Refusal::EmptyDirectory);
    }

    let by_oid: HashMap<&str, &DirectoryUser> = directory
        .iter()
        .rev()
        .map(|u| (u.object_id.as_str(), u))
        .collect();
    let by_upn: HashMap<String, &DirectoryUser> = directory
        .iter()
        .rev()
        .map(|u| (u.upn.to_lowercase(), u))
        .collect();

    let mut plan = Plan::default();
    let mut claimed: HashSet<&str> = HashSet::new();

    for operator in operators {
        match object_id_of(operator) {
            Some(oid) => match by_oid.get(oid) {
                Some(member) => {
                    claimed.insert(member.object_id.as_str());
                    plan.confirmed.push(operator.id.clone());
                    reconcile_present(operator, member, &mut plan.operators);
                }
                None => {
                    if operator.status != status::OFFBOARDED {
                        plan.operators.push(OperatorChange::Offboard {
                            id: operator.id.clone(),
                        });
                    }
                }
            },
            None => match by_upn.get(&operator.upn.to_lowercase()) {
                Some(member) if !claimed.contains(member.object_id.as_str()) => {
                    claimed.insert(member.object_id.as_str());
                    plan.confirmed.push(operator.id.clone());
                    plan.operators.push(OperatorChange::Link {
                        id: operator.id.clone(),
                        entra_object_id: member.object_id.clone(),
                    });
                    reconcile_present(operator, member, &mut plan.operators);
                }
                _ => plan.unlinked.push(operator.id.clone()),
            },
        }
    }

    for member in directory {
        if claimed.insert(member.object_id.as_str()) {
            plan.operators.push(OperatorChange::Create {
                upn: member.upn.clone(),
                display_name: member.display_name.clone(),
                email: member.mail.clone(),
                entra_object_id: member.object_id.clone(),
                status: if member.enabled {
                    status::ACTIVE
                } else {
                    status::SUSPENDED
                },
            });
        }
    }

    guard_fraction(operators, &plan.operators, policy)?;

    plan.users = reconcile_users(users, &by_oid, &by_upn, org_slug);
    Ok(plan)
}

fn object_id_of(operator: &OperatorRow) -> Option<&str> {
    operator
        .entra_object_id
        .as_deref()
        .filter(|oid| !oid.is_empty())
}

/// A member the directory lists: rename if the attributes drifted, then
/// follow `accountEnabled`.
fn reconcile_present(
    operator: &OperatorRow,
    member: &DirectoryUser,
    changes: &mut Vec<OperatorChange>,
) {
    if operator.upn != member.upn
        || operator.display_name != member.display_name
        || operator.email != member.mail
    {
        changes.push(OperatorChange::Rename {
            id: operator.id.clone(),
            upn: member.upn.clone(),
            display_name: member.display_name.clone(),
            email: member.mail.clone(),
        });
    }
    if member.enabled {
        if operator.status != status::ACTIVE {
            changes.push(OperatorChange::Reactivate {
                id: operator.id.clone(),
            });
        }
    } else if operator.status != status::SUSPENDED {
        changes.push(OperatorChange::Suspend {
            id: operator.id.clone(),
        });
    }
}

/// Refuse a plan that takes entitlement from too much of the fleet at once.
///
/// Counts suspensions and offboardings of operators that are `active` today
/// against the number that are `active` today. A fleet with no active
/// operator has nothing to protect and passes.
fn guard_fraction(
    operators: &[OperatorRow],
    changes: &[OperatorChange],
    policy: &Policy,
) -> Result<(), Refusal> {
    let active: HashSet<&str> = operators
        .iter()
        .filter(|o| o.status == status::ACTIVE)
        .map(|o| o.id.as_str())
        .collect();
    if active.is_empty() {
        return Ok(());
    }
    let would_deprovision = changes
        .iter()
        .filter(|c| {
            matches!(
                c,
                OperatorChange::Suspend { .. } | OperatorChange::Offboard { .. }
            )
        })
        .filter_map(OperatorChange::id)
        .filter(|id| active.contains(id))
        .count();
    let limit = policy.max_offboard_fraction * active.len() as f64;
    if would_deprovision as f64 > limit {
        return Err(Refusal::OffboardFractionExceeded {
            would_deprovision,
            active: active.len(),
        });
    }
    Ok(())
}

/// Console logins follow the same identity, with two differences: the sync
/// never creates one, and a `platform_admin` is never deactivated by it.
fn reconcile_users(
    users: &[UserRow],
    by_oid: &HashMap<&str, &DirectoryUser>,
    by_upn: &HashMap<String, &DirectoryUser>,
    org_slug: &str,
) -> Vec<UserChange> {
    let mut changes = Vec::new();
    for user in users {
        let oid = user
            .entra_object_id
            .as_deref()
            .filter(|oid| !oid.is_empty());
        match oid {
            Some(oid) => match by_oid.get(oid) {
                Some(member) => {
                    if user.org_slug.as_deref() != Some(org_slug) {
                        changes.push(UserChange::Stamp {
                            id: user.id.clone(),
                            entra_object_id: member.object_id.clone(),
                            org_slug: org_slug.to_string(),
                        });
                    }
                    if !user.email.eq_ignore_ascii_case(&member.upn) {
                        changes.push(UserChange::Rename {
                            id: user.id.clone(),
                            email: member.upn.clone(),
                        });
                    }
                    if !member.enabled {
                        deactivate(user, REASON_DISABLED, &mut changes);
                    }
                }
                // Stamped for this organization and gone from its listing.
                // Another organization's users are not ours to judge.
                None if user.org_slug.as_deref() == Some(org_slug) => {
                    deactivate(user, REASON_REMOVED, &mut changes);
                }
                None => {}
            },
            None => {
                if let Some(member) = by_upn.get(&user.email.to_lowercase()) {
                    changes.push(UserChange::Stamp {
                        id: user.id.clone(),
                        entra_object_id: member.object_id.clone(),
                        org_slug: org_slug.to_string(),
                    });
                    if !member.enabled {
                        deactivate(user, REASON_DISABLED, &mut changes);
                    }
                }
            }
        }
    }
    changes
}

fn deactivate(user: &UserRow, reason: &'static str, changes: &mut Vec<UserChange>) {
    if !user.active || user.roles.iter().any(|r| r == "platform_admin") {
        return;
    }
    changes.push(UserChange::Deactivate {
        id: user.id.clone(),
        reason,
    });
}

/// A seat to revoke and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatRevocation {
    pub seat_id: String,
    pub reason: &'static str,
}

/// The seats a plan's suspensions and offboardings take away.
///
/// Only `assigned` and `active` seats are touched; a seat already `revoked`
/// or `expired` keeps its own history. Reactivation never re-assigns a seat;
/// that is an org_admin decision.
#[must_use]
pub fn seat_revocations(changes: &[OperatorChange], seats: &[SeatRow]) -> Vec<SeatRevocation> {
    let mut revocations = Vec::new();
    for change in changes {
        let (operator, reason) = match change {
            OperatorChange::Suspend { id } => (id, REASON_DISABLED),
            OperatorChange::Offboard { id } => (id, REASON_REMOVED),
            _ => continue,
        };
        for seat in seats
            .iter()
            .filter(|s| &s.operator == operator)
            .filter(|s| s.status == "assigned" || s.status == "active")
        {
            revocations.push(SeatRevocation {
                seat_id: seat.id.clone(),
                reason,
            });
        }
    }
    revocations
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORG: &str = "example-agency";

    fn policy() -> Policy {
        Policy {
            max_offboard_fraction: 0.5,
        }
    }

    fn member(oid: &str, upn: &str, enabled: bool) -> DirectoryUser {
        DirectoryUser {
            object_id: oid.into(),
            upn: upn.into(),
            display_name: format!("Person {oid}"),
            mail: Some(upn.into()),
            enabled,
        }
    }

    fn operator(id: &str, upn: &str, oid: Option<&str>, status: &str) -> OperatorRow {
        OperatorRow {
            id: id.into(),
            upn: upn.into(),
            display_name: format!("Person {}", oid.unwrap_or("?")),
            email: Some(upn.into()),
            entra_object_id: oid.map(str::to_owned),
            status: status.into(),
            organization: Some("org_1".into()),
        }
    }

    fn user(id: &str, email: &str, oid: Option<&str>, org: Option<&str>) -> UserRow {
        UserRow {
            id: id.into(),
            email: email.into(),
            roles: vec!["auditor".into()],
            active: true,
            entra_object_id: oid.map(str::to_owned),
            org_slug: org.map(str::to_owned),
        }
    }

    #[test]
    fn an_empty_directory_is_refused_not_treated_as_everyone_left() {
        let ops = [operator("o1", "a@x.gov", Some("A"), "active")];
        assert_eq!(
            reconcile(&[], &ops, &[], ORG, &policy()),
            Err(Refusal::EmptyDirectory)
        );
    }

    #[test]
    fn a_new_member_is_created_active() {
        let plan = reconcile(&[member("A", "a@x.gov", true)], &[], &[], ORG, &policy()).unwrap();
        assert_eq!(
            plan.operators,
            vec![OperatorChange::Create {
                upn: "a@x.gov".into(),
                display_name: "Person A".into(),
                email: Some("a@x.gov".into()),
                entra_object_id: "A".into(),
                status: "active",
            }]
        );
        assert!(plan.confirmed.is_empty());
    }

    #[test]
    fn a_new_disabled_member_is_created_suspended() {
        let plan = reconcile(&[member("A", "a@x.gov", false)], &[], &[], ORG, &policy()).unwrap();
        assert!(matches!(
            plan.operators[0],
            OperatorChange::Create {
                status: "suspended",
                ..
            }
        ));
    }

    #[test]
    fn a_present_enabled_member_with_matching_attributes_changes_nothing() {
        let ops = [operator("o1", "a@x.gov", Some("A"), "active")];
        let plan = reconcile(&[member("A", "a@x.gov", true)], &ops, &[], ORG, &policy()).unwrap();
        assert!(plan.operators.is_empty());
        assert_eq!(plan.confirmed, vec!["o1"]);
    }

    #[test]
    fn a_upn_change_renames_the_same_row_and_nothing_else() {
        let ops = [operator("o1", "a@x.gov", Some("A"), "active")];
        let plan = reconcile(
            &[member("A", "a.smith@x.gov", true)],
            &ops,
            &[],
            ORG,
            &policy(),
        )
        .unwrap();
        assert_eq!(
            plan.operators,
            vec![OperatorChange::Rename {
                id: "o1".into(),
                upn: "a.smith@x.gov".into(),
                display_name: "Person A".into(),
                email: Some("a.smith@x.gov".into()),
            }]
        );
    }

    #[test]
    fn a_disabled_member_is_suspended_once() {
        // Two active operators, so suspending one stays within the fraction.
        let ops = [
            operator("o1", "a@x.gov", Some("A"), "active"),
            operator("o2", "b@x.gov", Some("B"), "active"),
        ];
        let listing = [member("A", "a@x.gov", false), member("B", "b@x.gov", true)];
        let plan = reconcile(&listing, &ops, &[], ORG, &policy()).unwrap();
        assert_eq!(
            plan.operators,
            vec![OperatorChange::Suspend { id: "o1".into() }]
        );

        let already = [
            operator("o1", "a@x.gov", Some("A"), "suspended"),
            operator("o2", "b@x.gov", Some("B"), "active"),
        ];
        let plan = reconcile(&listing, &already, &[], ORG, &policy()).unwrap();
        assert!(plan.operators.is_empty());
    }

    #[test]
    fn a_lone_operator_cannot_be_suspended_under_the_default_fraction() {
        // One of one is more than half: the guard holds even for a fleet of
        // one, and an operator who wants that behaviour sets `fraction = 1`.
        let ops = [operator("o1", "a@x.gov", Some("A"), "active")];
        let listing = [member("A", "a@x.gov", false)];
        assert!(matches!(
            reconcile(&listing, &ops, &[], ORG, &policy()),
            Err(Refusal::OffboardFractionExceeded {
                would_deprovision: 1,
                active: 1
            })
        ));
        let lenient = Policy {
            max_offboard_fraction: 1.0,
        };
        assert!(reconcile(&listing, &ops, &[], ORG, &lenient).is_ok());
    }

    #[test]
    fn an_absent_member_is_offboarded_once() {
        let ops = [
            operator("o1", "a@x.gov", Some("A"), "active"),
            operator("o2", "b@x.gov", Some("B"), "active"),
        ];
        let listing = [member("A", "a@x.gov", true)];
        let plan = reconcile(&listing, &ops, &[], ORG, &policy()).unwrap();
        assert_eq!(
            plan.operators,
            vec![OperatorChange::Offboard { id: "o2".into() }]
        );

        let already = [
            operator("o1", "a@x.gov", Some("A"), "active"),
            operator("o2", "b@x.gov", Some("B"), "offboarded"),
        ];
        let plan = reconcile(&listing, &already, &[], ORG, &policy()).unwrap();
        assert!(plan.operators.is_empty());
    }

    #[test]
    fn a_member_that_reappears_enabled_is_reactivated() {
        for status in ["suspended", "offboarded", "invited"] {
            let ops = [operator("o1", "a@x.gov", Some("A"), status)];
            let plan =
                reconcile(&[member("A", "a@x.gov", true)], &ops, &[], ORG, &policy()).unwrap();
            assert_eq!(
                plan.operators,
                vec![OperatorChange::Reactivate { id: "o1".into() }],
                "from {status}"
            );
        }
    }

    #[test]
    fn a_hand_typed_row_is_linked_once_by_case_insensitive_upn() {
        let ops = [operator("o1", "Dev@Agency.gov", None, "active")];
        let plan = reconcile(
            &[member("D", "dev@agency.gov", true)],
            &ops,
            &[],
            ORG,
            &policy(),
        )
        .unwrap();
        assert_eq!(
            plan.operators[0],
            OperatorChange::Link {
                id: "o1".into(),
                entra_object_id: "D".into()
            }
        );
        // The link also normalises the directory-owned attributes.
        assert!(matches!(plan.operators[1], OperatorChange::Rename { .. }));
        assert_eq!(plan.confirmed, vec!["o1"]);
        assert!(plan.unlinked.is_empty());
    }

    #[test]
    fn a_hand_typed_row_matching_nobody_is_reported_not_offboarded() {
        let ops = [operator("o1", "ghost@agency.gov", None, "active")];
        let plan = reconcile(&[member("A", "a@x.gov", true)], &ops, &[], ORG, &policy()).unwrap();
        assert_eq!(plan.unlinked, vec!["o1"]);
        assert!(plan
            .operators
            .iter()
            .all(|c| matches!(c, OperatorChange::Create { .. })));
    }

    #[test]
    fn a_member_already_claimed_by_object_id_is_not_linked_to_a_second_row_by_upn() {
        let ops = [
            operator("o1", "a@x.gov", Some("A"), "active"),
            operator("o2", "a@x.gov", None, "active"),
        ];
        let plan = reconcile(&[member("A", "a@x.gov", true)], &ops, &[], ORG, &policy()).unwrap();
        assert!(!plan
            .operators
            .iter()
            .any(|c| matches!(c, OperatorChange::Link { .. })));
        assert_eq!(plan.unlinked, vec!["o2"]);
    }

    #[test]
    fn a_plan_that_would_deprovision_more_than_the_fraction_is_refused_whole() {
        let ops = [
            operator("o1", "a@x.gov", Some("A"), "active"),
            operator("o2", "b@x.gov", Some("B"), "active"),
            operator("o3", "c@x.gov", Some("C"), "active"),
        ];
        let listing = [member("A", "a@x.gov", true)];
        assert_eq!(
            reconcile(&listing, &ops, &[], ORG, &policy()),
            Err(Refusal::OffboardFractionExceeded {
                would_deprovision: 2,
                active: 3
            })
        );
    }

    #[test]
    fn the_fraction_guard_counts_suspensions_and_ignores_already_inactive_rows() {
        let ops = [
            operator("o1", "a@x.gov", Some("A"), "active"),
            operator("o2", "b@x.gov", Some("B"), "active"),
            operator("o3", "c@x.gov", Some("C"), "suspended"),
        ];
        // Half of the two active operators: exactly at the limit, allowed.
        let listing = [member("A", "a@x.gov", false), member("B", "b@x.gov", true)];
        let plan = reconcile(&listing, &ops, &[], ORG, &policy()).unwrap();
        assert!(plan
            .operators
            .iter()
            .any(|c| matches!(c, OperatorChange::Suspend { id } if id == "o1")));
        assert!(plan
            .operators
            .iter()
            .any(|c| matches!(c, OperatorChange::Offboard { id } if id == "o3")));
    }

    #[test]
    fn a_fleet_with_no_active_operator_has_nothing_to_guard() {
        let ops = [operator("o1", "a@x.gov", Some("A"), "invited")];
        let plan = reconcile(&[member("B", "b@x.gov", true)], &ops, &[], ORG, &policy()).unwrap();
        assert!(plan
            .operators
            .iter()
            .any(|c| matches!(c, OperatorChange::Offboard { .. })));
    }

    #[test]
    fn a_console_user_is_stamped_by_upn_then_followed_by_object_id() {
        let users = [user("u1", "A@X.GOV", None, None)];
        let plan = reconcile(&[member("A", "a@x.gov", true)], &[], &users, ORG, &policy()).unwrap();
        assert_eq!(
            plan.users,
            vec![UserChange::Stamp {
                id: "u1".into(),
                entra_object_id: "A".into(),
                org_slug: ORG.into()
            }]
        );

        let stamped = [user("u1", "a@x.gov", Some("A"), Some(ORG))];
        let plan = reconcile(
            &[member("A", "a.smith@x.gov", true)],
            &[],
            &stamped,
            ORG,
            &policy(),
        )
        .unwrap();
        assert_eq!(
            plan.users,
            vec![UserChange::Rename {
                id: "u1".into(),
                email: "a.smith@x.gov".into()
            }]
        );
    }

    #[test]
    fn a_disabled_or_removed_member_deactivates_their_console_login() {
        let users = [
            user("u1", "a@x.gov", Some("A"), Some(ORG)),
            user("u2", "b@x.gov", Some("B"), Some(ORG)),
        ];
        let plan = reconcile(
            &[member("A", "a@x.gov", false)],
            &[],
            &users,
            ORG,
            &policy(),
        )
        .unwrap();
        assert_eq!(
            plan.users,
            vec![
                UserChange::Deactivate {
                    id: "u1".into(),
                    reason: REASON_DISABLED
                },
                UserChange::Deactivate {
                    id: "u2".into(),
                    reason: REASON_REMOVED
                },
            ]
        );
    }

    #[test]
    fn a_platform_admin_is_never_deactivated_and_another_orgs_user_is_not_touched() {
        let mut admin = user("u1", "a@x.gov", Some("A"), Some(ORG));
        admin.roles = vec!["platform_admin".into()];
        let elsewhere = user("u2", "b@y.gov", Some("B"), Some("other-agency"));
        let mut inactive = user("u3", "c@x.gov", Some("C"), Some(ORG));
        inactive.active = false;
        let plan = reconcile(
            &[member("A", "a@x.gov", false)],
            &[],
            &[admin, elsewhere, inactive],
            ORG,
            &policy(),
        )
        .unwrap();
        assert!(plan.users.is_empty());
    }

    #[test]
    fn suspending_and_offboarding_revoke_only_live_seats_with_a_reason() {
        let changes = [
            OperatorChange::Suspend { id: "o1".into() },
            OperatorChange::Offboard { id: "o2".into() },
            OperatorChange::Reactivate { id: "o3".into() },
        ];
        let seat = |id: &str, operator: &str, status: &str| SeatRow {
            id: id.into(),
            operator: operator.into(),
            status: status.into(),
        };
        let seats = [
            seat("s1", "o1", "active"),
            seat("s2", "o1", "revoked"),
            seat("s3", "o2", "assigned"),
            seat("s4", "o2", "expired"),
            seat("s5", "o3", "active"),
        ];
        assert_eq!(
            seat_revocations(&changes, &seats),
            vec![
                SeatRevocation {
                    seat_id: "s1".into(),
                    reason: REASON_DISABLED
                },
                SeatRevocation {
                    seat_id: "s3".into(),
                    reason: REASON_REMOVED
                },
            ]
        );
    }

    #[test]
    fn the_summary_counts_every_kind_of_change() {
        let plan = Plan {
            operators: vec![
                OperatorChange::Suspend { id: "o1".into() },
                OperatorChange::Link {
                    id: "o2".into(),
                    entra_object_id: "B".into(),
                },
            ],
            users: vec![],
            confirmed: vec![],
            unlinked: vec!["o9".into()],
        };
        let summary = plan.summary();
        assert!(summary.contains("linked 1"));
        assert!(summary.contains("suspended 1"));
        assert!(summary.contains("unlinked 1"));
    }

    #[test]
    fn refusals_read_as_a_sentence() {
        assert_eq!(
            Refusal::EmptyDirectory.to_string(),
            "directory returned no members"
        );
        assert!(Refusal::OffboardFractionExceeded {
            would_deprovision: 2,
            active: 3
        }
        .to_string()
        .contains("2 of 3"));
    }
}
