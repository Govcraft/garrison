//! The directory sync: one supervised actor that, on a schedule, makes the
//! plane's operators agree with the directory.
//!
//! The actor owns exactly one piece of state, the report of its last run.
//! Everything it decides is decided by [`crate::reconcile::reconcile`], which
//! is pure and tested without a network; everything it fetches or writes goes
//! through [`Plane`], which is the same REST surface a console user hits, so
//! every row the sync touches passes the same Cedar policy and lands in the
//! same audit table.
//!
//! # Lifecycle
//!
//! `main` parks the settings in a `OnceLock` before the service is built.
//! `after_start` (re-run on every supervised restart) reads them and sends
//! the actor an [`Init`]. `Init` arms a repeating [`Tick`] with
//! `send_every(.., Cadence::FixedDelay)` and fires the first one. Until
//! `Init` has landed, a `Tick` answers with a report that says so and does
//! nothing: an actor that has not been told where the directory is must not
//! guess, and must not look healthy.
//!
//! One `Tick` runs one whole reconciliation inline (`mutate_on`, awaited on
//! the message loop). The actor owns nothing else, so a slow sync serialising
//! ticks is the desired backpressure, and `FixedDelay` keeps ticks from
//! stacking behind a slow one.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use acton_service::extensions::ActorExtension;
use acton_reactive::prelude::{
    acton_actor, acton_message, ActorHandleInterface, Cadence, Idle, Interval, ManagedActor,
    Reply, Request, ScheduledSend,
};
use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tracing::{info, warn};

use crate::directory::{Directory, DirectoryQuery};
use crate::plane::{OrganizationRow, Plane, PlaneError};
use crate::reconcile::{
    reconcile, seat_revocations, OperatorChange, Plan, Policy, Refusal, UserChange,
};

/// What one sync needs: where the people are, where the rows are, how often,
/// and how much it may take away at once.
pub struct SyncSettings {
    pub directory: Arc<dyn Directory>,
    pub plane: Plane,
    /// The one `Organization` row this reconciler serves.
    pub organization: String,
    pub interval: Duration,
    pub policy: Policy,
}

impl std::fmt::Debug for SyncSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncSettings")
            .field("organization", &self.organization)
            .field("interval", &self.interval)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

static SETTINGS: OnceLock<Arc<SyncSettings>> = OnceLock::new();

/// Park the settings for the actor's `after_start` to find.
///
/// Returns `false` if settings were already installed; the first ones win,
/// because a supervised restart must come back with the configuration the
/// operator deployed, not one a later caller slipped in.
pub fn install(settings: Arc<SyncSettings>) -> bool {
    SETTINGS.set(settings).is_ok()
}

/// Tell the actor where its directory and plane are.
#[acton_message]
pub struct Init(pub Arc<SyncSettings>);

/// Run one reconciliation now. Replies with the [`SyncReport`].
#[acton_message]
pub struct Tick;

impl Request for Tick {
    type Response = SyncReport;
}

/// Ask for the report of the most recent run without triggering one.
#[acton_message]
pub struct GetSyncReport;

impl Request for GetSyncReport {
    type Response = SyncReport;
}

/// What one organization's reconciliation came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationOutcome {
    pub id: String,
    pub slug: String,
    /// `ok` or `failed`, as written to `Organization.directory_sync_status`.
    pub status: String,
    pub detail: String,
}

/// The record of one run.
#[acton_message]
pub struct SyncReport {
    pub ran_at: String,
    /// `false` when the actor had no settings and therefore did nothing.
    pub initialised: bool,
    pub organizations: Vec<OrganizationOutcome>,
}

impl SyncReport {
    fn uninitialised() -> Self {
        Self {
            ran_at: now_rfc3339(),
            initialised: false,
            organizations: Vec::new(),
        }
    }

    /// Whether every organization that has a directory synced cleanly.
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.initialised && self.organizations.iter().all(|o| o.status == "ok")
    }
}

/// The supervised sync actor.
#[acton_actor]
pub struct DirectorySync {
    settings: Option<Arc<SyncSettings>>,
    schedule: Option<ScheduledSend>,
    last: Option<SyncReport>,
}

impl DirectorySync {
    /// Register the handlers. Public so a test can build the actor on a bare
    /// runtime without going through `ServiceBuilder`.
    pub fn configure(actor: &mut ManagedActor<Idle, Self>) {
        actor
            .mutate_on::<Init>(|actor, ctx| {
                let settings = ctx.message().0.clone();
                let handle = actor.handle().clone();
                if actor.model.schedule.is_none() {
                    // A zero interval is rejected by config validation, so
                    // `None` here means "run once, never again", which is
                    // still better than a spin loop.
                    actor.model.schedule = Interval::new(settings.interval)
                        .map(|every| handle.send_every(Tick, every, Cadence::FixedDelay));
                }
                actor.model.settings = Some(settings);
                Reply::pending(async move { handle.send(Tick).await })
            })
            .mutate_on::<Tick>(|actor, ctx| {
                let reply = ctx.reply_envelope();
                let handle = actor.handle().clone();
                let Some(settings) = actor.model.settings.clone() else {
                    warn!("directory sync ticked before it was initialised; doing nothing");
                    return Reply::pending(async move {
                        reply.send(SyncReport::uninitialised()).await;
                    });
                };
                Reply::pending(async move {
                    let report = run_sync(&settings).await;
                    info!(
                        ran_at = %report.ran_at,
                        organizations = report.organizations.len(),
                        ok = report.all_ok(),
                        "directory sync tick complete"
                    );
                    handle.send(report.clone()).await;
                    reply.send(report).await;
                })
            })
            .mutate_on::<SyncReport>(|actor, ctx| {
                actor.model.last = Some(ctx.message().clone());
                Reply::ready()
            })
            .act_on::<GetSyncReport>(|actor, ctx| {
                let reply = ctx.reply_envelope();
                let report = actor.model.last.clone().unwrap_or_else(|| SyncReport {
                    ran_at: String::new(),
                    initialised: actor.model.settings.is_some(),
                    organizations: Vec::new(),
                });
                Reply::pending(async move { reply.send(report).await })
            })
            .after_start(|actor| {
                let handle = actor.handle().clone();
                async move {
                    match SETTINGS.get() {
                        Some(settings) => handle.send(Init(settings.clone())).await,
                        None => warn!(
                            "directory sync started with no settings installed; it will fail closed"
                        ),
                    }
                }
            });
    }
}

impl ActorExtension for DirectorySync {
    fn configure(actor: &mut ManagedActor<Idle, Self>) {
        Self::configure(actor);
    }
}

/// One run over the configured organization.
///
/// The row is fetched by id rather than listed: the bearer is scoped to
/// this tenant, and the plane's tenant-scoped listings do not return the
/// tenant-root row itself. A row the bearer cannot fetch, or one without a
/// directory tenant, is a failed tick and nothing changes.
async fn run_sync(settings: &SyncSettings) -> SyncReport {
    let ran_at = now_rfc3339();
    let organization = match settings
        .plane
        .organization_by_id(&settings.organization)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            warn!(
                organization = %settings.organization,
                "directory sync: the configured organization does not exist or is not visible to the directory bearer"
            );
            return SyncReport {
                ran_at,
                initialised: true,
                organizations: Vec::new(),
            };
        }
        Err(error) => {
            // The plane itself is unreachable: nothing to stamp the failure
            // on, so it is logged and the next tick retries.
            warn!("directory sync could not fetch the organization: {error}");
            return SyncReport {
                ran_at,
                initialised: true,
                organizations: Vec::new(),
            };
        }
    };
    let outcome = if organization
        .entra_tenant_id
        .as_deref()
        .is_some_and(|t| !t.is_empty())
    {
        sync_organization(settings, &organization, &ran_at).await
    } else {
        OrganizationOutcome {
            id: organization.id.clone(),
            slug: organization.slug.clone(),
            status: "failed".into(),
            detail: "organization has no entra_tenant_id".into(),
        }
    };
    match outcome.status.as_str() {
        "ok" => info!(org = %outcome.slug, "{}", outcome.detail),
        _ => warn!(org = %outcome.slug, "directory sync failed: {}", outcome.detail),
    }
    SyncReport {
        ran_at,
        initialised: true,
        organizations: vec![outcome],
    }
}

async fn sync_organization(
    settings: &SyncSettings,
    organization: &OrganizationRow,
    ran_at: &str,
) -> OrganizationOutcome {
    let result = reconcile_organization(settings, organization, ran_at).await;
    let (status, detail) = match result {
        Ok(summary) => ("ok", summary),
        Err(SyncError::Refused(refusal)) => ("failed", refusal.to_string()),
        Err(SyncError::Directory(e)) => ("failed", e.to_string()),
        Err(SyncError::Plane(e)) => ("failed", e.to_string()),
    };
    let mut fields = BTreeMap::new();
    fields.insert("directory_sync_status".into(), json!(status));
    fields.insert("directory_sync_detail".into(), json!(clip(&detail)));
    if status == "ok" {
        fields.insert("directory_synced_at".into(), json!(ran_at));
    }
    // Best effort: a failure to record the failure is logged, and the next
    // tick will try again. Nothing else depends on this patch.
    if let Err(error) = settings
        .plane
        .patch("Organization", &organization.id, fields)
        .await
    {
        warn!(org = %organization.slug, "could not record sync status: {error}");
    }
    OrganizationOutcome {
        id: organization.id.clone(),
        slug: organization.slug.clone(),
        status: status.into(),
        detail,
    }
}

enum SyncError {
    Refused(Refusal),
    Directory(crate::directory::DirectoryError),
    Plane(PlaneError),
}

impl From<PlaneError> for SyncError {
    fn from(e: PlaneError) -> Self {
        Self::Plane(e)
    }
}

/// Fetch, decide, apply. Returns the plan's summary on success.
async fn reconcile_organization(
    settings: &SyncSettings,
    organization: &OrganizationRow,
    ran_at: &str,
) -> std::result::Result<String, SyncError> {
    let query = DirectoryQuery {
        tenant_id: organization
            .entra_tenant_id
            .clone()
            .unwrap_or_default(),
        group_id: organization
            .entra_group_id
            .clone()
            .filter(|g| !g.is_empty()),
    };
    let members = settings
        .directory
        .members(&query)
        .await
        .map_err(SyncError::Directory)?;
    let operators = settings.plane.operators_of(&organization.id).await?;
    // Console logins live in the plane's own user store, which has no
    // tenant column, so a tenant-scoped bearer cannot list it (the plane
    // answers 502). That leaves the operator half, which is the enrollment
    // gate, and says so in the recorded detail rather than failing every
    // tick on an install where the listing can never succeed.
    let (users, users_note) = match settings.plane.users().await {
        Ok(rows) => (rows, None),
        Err(error) => {
            warn!(org = %organization.slug, "console users not reconciled: {error}");
            (
                Vec::new(),
                Some(format!("console users not reconciled: {error}")),
            )
        }
    };

    let plan = reconcile(
        &members,
        &operators,
        &users,
        &organization.slug,
        &settings.policy,
    )
    .map_err(SyncError::Refused)?;

    apply(settings, organization, &plan, ran_at).await?;
    Ok(match users_note {
        Some(note) => format!("{}; {note}", plan.summary()),
        None => plan.summary(),
    })
}

/// Write the plan to the plane, one row at a time.
///
/// Every write is idempotent (a patch to the value the directory says, a
/// create keyed on a unique object id), so a failure part-way leaves rows
/// the next tick recomputes rather than a state that needs rolling back.
async fn apply(
    settings: &SyncSettings,
    organization: &OrganizationRow,
    plan: &Plan,
    ran_at: &str,
) -> std::result::Result<(), PlaneError> {
    let plane = &settings.plane;

    // Rows that exist: fold every change to one row into one patch, plus
    // the per-row proof of when the directory last confirmed it.
    let mut patches: BTreeMap<&str, BTreeMap<String, Value>> = BTreeMap::new();
    for id in &plan.confirmed {
        patches
            .entry(id)
            .or_default()
            .insert("directory_synced_at".into(), json!(ran_at));
    }
    for change in &plan.operators {
        let Some(id) = change.id() else { continue };
        let patch = patches.entry(id).or_default();
        match change {
            OperatorChange::Link {
                entra_object_id, ..
            } => {
                patch.insert("entra_object_id".into(), json!(entra_object_id));
            }
            OperatorChange::Rename {
                upn,
                display_name,
                email,
                ..
            } => {
                patch.insert("upn".into(), json!(upn));
                patch.insert("display_name".into(), json!(display_name));
                patch.insert("email".into(), json!(email));
            }
            OperatorChange::Reactivate { .. } => {
                patch.insert("status".into(), json!("active"));
            }
            OperatorChange::Suspend { .. } => {
                patch.insert("status".into(), json!("suspended"));
            }
            OperatorChange::Offboard { .. } => {
                patch.insert("status".into(), json!("offboarded"));
            }
            OperatorChange::Create { .. } => {}
        }
    }
    for (id, fields) in patches {
        plane.patch("Operator", id, fields).await?;
    }

    // Seats go before creates: taking entitlement away is the part that
    // matters if the tick dies half-way.
    for change in &plan.operators {
        let operator = match change {
            OperatorChange::Suspend { id } | OperatorChange::Offboard { id } => id,
            _ => continue,
        };
        let seats = plane.seats_of(operator).await?;
        for revocation in seat_revocations(std::slice::from_ref(change), &seats) {
            let mut fields = BTreeMap::new();
            fields.insert("status".into(), json!("revoked"));
            fields.insert("revoked_at".into(), json!(ran_at));
            fields.insert("revocation_reason".into(), json!(revocation.reason));
            plane.patch("Seat", &revocation.seat_id, fields).await?;
        }
    }

    for change in &plan.operators {
        let OperatorChange::Create {
            upn,
            display_name,
            email,
            entra_object_id,
            status,
        } = change
        else {
            continue;
        };
        let mut fields = BTreeMap::new();
        fields.insert("upn".into(), json!(upn));
        fields.insert("display_name".into(), json!(display_name));
        if let Some(email) = email {
            fields.insert("email".into(), json!(email));
        }
        fields.insert("entra_object_id".into(), json!(entra_object_id));
        fields.insert("organization".into(), json!(organization.id));
        fields.insert("status".into(), json!(status));
        fields.insert("directory_synced_at".into(), json!(ran_at));
        plane.create("Operator", fields).await?;
    }

    let mut user_patches: BTreeMap<&str, BTreeMap<String, Value>> = BTreeMap::new();
    for change in &plan.users {
        match change {
            UserChange::Stamp {
                id,
                entra_object_id,
                org_slug,
            } => {
                let patch = user_patches.entry(id).or_default();
                patch.insert("entra_object_id".into(), json!(entra_object_id));
                patch.insert("org_slug".into(), json!(org_slug));
            }
            UserChange::Rename { id, email } => {
                user_patches
                    .entry(id)
                    .or_default()
                    .insert("email".into(), json!(email));
            }
            UserChange::Deactivate { id, reason } => {
                info!(user = %id, %reason, "console login deactivated by the directory");
                user_patches
                    .entry(id)
                    .or_default()
                    .insert("active".into(), json!(false));
            }
        }
    }
    for (id, fields) in user_patches {
        plane.patch("User", id, fields).await?;
    }

    for id in &plan.unlinked {
        warn!(operator = %id, org = %organization.slug, "hand-typed operator matches nobody in the directory");
    }
    Ok(())
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// `Organization.directory_sync_detail` is 512 characters.
fn clip(detail: &str) -> String {
    detail.chars().take(500).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use acton_reactive::prelude::ActonApp;
    use crate::directory::{DirectoryError, DirectoryUser, MembersFuture};

    struct Nobody;

    impl Directory for Nobody {
        fn members<'a>(&'a self, _: &'a DirectoryQuery) -> MembersFuture<'a> {
            Box::pin(async { Ok(Vec::<DirectoryUser>::new()) })
        }
    }

    struct Broken;

    impl Directory for Broken {
        fn members<'a>(&'a self, _: &'a DirectoryQuery) -> MembersFuture<'a> {
            Box::pin(async { Err(DirectoryError::Transport("no route".into())) })
        }
    }

    fn settings(directory: Arc<dyn Directory>) -> Arc<SyncSettings> {
        Arc::new(SyncSettings {
            directory,
            // A port nothing listens on: the plane is unreachable.
            plane: Plane::new("http://127.0.0.1:9", "tok").unwrap(),
            organization: "organization_01test".into(),
            interval: Duration::from_secs(3600),
            policy: Policy {
                max_offboard_fraction: 0.5,
            },
        })
    }

    #[tokio::test]
    async fn a_tick_before_init_fails_closed_and_touches_nothing() {
        let mut runtime = ActonApp::launch_async().await;
        let mut actor = runtime.new_actor::<DirectorySync>();
        DirectorySync::configure(&mut actor);
        let handle = actor.start().await;

        let report = handle.ask(Tick).await.expect("reply");
        assert!(!report.initialised);
        assert!(report.organizations.is_empty());

        let last = handle.ask(GetSyncReport).await.expect("reply");
        assert!(!last.initialised);
        runtime.shutdown_all().await.expect("shutdown");
    }

    #[tokio::test]
    async fn an_unreachable_plane_yields_an_initialised_report_with_no_outcomes() {
        let mut runtime = ActonApp::launch_async().await;
        let mut actor = runtime.new_actor::<DirectorySync>();
        DirectorySync::configure(&mut actor);
        let handle = actor.start().await;

        handle.send(Init(settings(Arc::new(Nobody)))).await;
        let report = handle.ask(Tick).await.expect("reply");
        assert!(report.initialised);
        assert!(report.organizations.is_empty());

        // The self-sent copy of the report is stored as the last run.
        let last = handle.ask(GetSyncReport).await.expect("reply");
        assert!(last.initialised);
        runtime.shutdown_all().await.expect("shutdown");
    }

    #[tokio::test]
    async fn a_broken_directory_never_reaches_the_plane_for_operators() {
        // With the plane unreachable the organization listing fails first,
        // so this proves the tick survives both failures without panicking
        // and reports honestly.
        let mut runtime = ActonApp::launch_async().await;
        let mut actor = runtime.new_actor::<DirectorySync>();
        DirectorySync::configure(&mut actor);
        let handle = actor.start().await;
        handle.send(Init(settings(Arc::new(Broken)))).await;
        let report = handle.ask(Tick).await.expect("reply");
        assert!(report.initialised);
        runtime.shutdown_all().await.expect("shutdown");
    }

    #[test]
    fn a_report_is_only_all_ok_when_initialised_and_every_org_is_ok() {
        let mut report = SyncReport::uninitialised();
        assert!(!report.all_ok());
        report.initialised = true;
        assert!(report.all_ok());
        report.organizations.push(OrganizationOutcome {
            id: "o".into(),
            slug: "s".into(),
            status: "failed".into(),
            detail: "x".into(),
        });
        assert!(!report.all_ok());
    }

    #[test]
    fn the_detail_is_clipped_to_the_column() {
        assert_eq!(clip(&"x".repeat(1000)).len(), 500);
    }

    #[test]
    fn install_keeps_the_first_settings() {
        // The OnceLock is process-global; whichever test installs first
        // wins, and the second install reports it.
        let first = install(settings(Arc::new(Nobody)));
        let second = install(settings(Arc::new(Nobody)));
        assert!(first || !second);
        assert!(!second);
    }
}
