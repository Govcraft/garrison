//! The liveness sweep: an install that stops shipping is itself an event.
//!
//! A hash chain proves nobody edited the middle of a record. Nothing in it
//! proves the record is still being written, because a prefix of a valid chain
//! is a valid chain. The only way to notice an install that went quiet is to
//! look for the absence, on a schedule, from somewhere the install cannot
//! reach. That is this actor.
//!
//! # Three vantage points, and the difference between them
//!
//! `AuditTrail` is what the daemon claims: where its local head is and how far
//! it says it has shipped. `AuditChain` is what the plane verified: the head it
//! re-derived as entries arrived. Neither alone is a liveness signal. Silence
//! is their difference over time:
//!
//! - the chain is behind the trail's local head: the install is writing
//!   evidence it is not sending;
//! - the trail has not reported at all inside the window: the install is not
//!   even claiming anything;
//! - the chain carries a gap or the daemon recorded a halt: shipping stopped
//!   for a reason somebody has to read.
//!
//! # A retired install is supposed to be quiet
//!
//! Silence from a machine that was decommissioned is the expected outcome of
//! decommissioning it, and a sweep that warned about it every five minutes
//! would train everyone to ignore the warning. A retired install is exempt
//! from the silence and backlog findings, and from nothing else: a broken or
//! gapped chain is a finding whether or not the machine still exists.
//!
//! # It reports, it does not write
//!
//! Every finding is a `tracing::warn!` on the `garrison.audit.liveness`
//! target, which is where the deployment's log pipeline already looks. The
//! sweep deliberately writes nothing to the plane: `AuditChain.integrity` is
//! the ingest's record of what it verified link by link, and a background job
//! that could set it from inference would put a guess in the same column as a
//! proof.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use acton_reactive::prelude::{
    acton_actor, acton_message, ActorHandleInterface, Cadence, Idle, Interval, ManagedActor, Reply,
    Request, ScheduledSend,
};
use acton_service::extensions::ActorExtension;
use chrono::{DateTime, SecondsFormat, Utc};
use tracing::{info, warn};

use crate::plane::{AuditChainRow, AuditTrailRow, Plane};

/// The `AgentInstall.status` a decommissioned machine carries.
pub const RETIRED: &str = "retired";

/// What one sweep needs: where the rows are, how often to look, and how long
/// quiet is allowed to last.
pub struct SilenceSettings {
    pub plane: Plane,
    /// How long a trail may go without reporting before it is silent.
    pub silence: Duration,
    /// How often the sweep runs.
    pub sweep: Duration,
}

impl std::fmt::Debug for SilenceSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SilenceSettings")
            .field("silence", &self.silence)
            .field("sweep", &self.sweep)
            .finish_non_exhaustive()
    }
}

static SETTINGS: OnceLock<Arc<SilenceSettings>> = OnceLock::new();

/// Park the settings for the actor's `after_start` to find.
///
/// Returns `false` if settings were already installed; the first ones win, so
/// a supervised restart comes back with the configuration the operator
/// deployed.
pub fn install(settings: Arc<SilenceSettings>) -> bool {
    SETTINGS.set(settings).is_ok()
}

/// Tell the actor where the plane is.
#[acton_message]
pub struct Init(pub Arc<SilenceSettings>);

/// Run one sweep now. Replies with the [`SilenceReport`].
#[acton_message]
pub struct Tick;

impl Request for Tick {
    type Response = SilenceReport;
}

/// Ask for the most recent sweep without triggering one.
#[acton_message]
pub struct GetSilenceReport;

impl Request for GetSilenceReport {
    type Response = SilenceReport;
}

/// What is wrong with one trail, most serious first.
///
/// The order of the variants is the precedence: a chain that is both broken
/// and behind is reported as broken, because that is the finding somebody has
/// to act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Liveness {
    /// The daemon halted shipping, or the plane's chain is broken.
    Broken,
    /// Entries are missing from the middle of the plane's chain.
    Gap,
    /// The trail has not reported inside the silence window.
    Silent,
    /// The plane holds less than the daemon says it has written.
    Backlog,
}

impl std::fmt::Display for Liveness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let word = match self {
            Self::Broken => "broken",
            Self::Gap => "gap",
            Self::Silent => "silent",
            Self::Backlog => "backlog",
        };
        f.write_str(word)
    }
}

/// One trail the sweep has something to say about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub trail_id: String,
    pub install: String,
    pub liveness: Liveness,
    pub detail: String,
}

/// The record of one sweep.
#[acton_message]
pub struct SilenceReport {
    pub ran_at: String,
    /// `false` when the actor had no settings and therefore did nothing.
    pub initialised: bool,
    /// How many trails were examined.
    pub trails: usize,
    pub findings: Vec<Finding>,
}

impl SilenceReport {
    fn uninitialised() -> Self {
        Self {
            ran_at: now_rfc3339(),
            initialised: false,
            trails: 0,
            findings: Vec::new(),
        }
    }

    /// Whether every trail the sweep could see is still shipping.
    #[must_use]
    pub fn all_live(&self) -> bool {
        self.initialised && self.findings.is_empty()
    }
}

/// What one trail's three vantage points come to. Pure.
///
/// `None` means the install is doing what it is supposed to: reporting inside
/// the window, with the plane's verified head level with what the daemon says
/// it has written.
#[must_use]
pub fn classify_trail(
    trail: &AuditTrailRow,
    chain: Option<&AuditChainRow>,
    install_status: &str,
    now: DateTime<Utc>,
    silence: Duration,
) -> Option<Liveness> {
    let halted = trail
        .halted_reason
        .as_deref()
        .is_some_and(|why| !why.trim().is_empty());
    if halted || chain.is_some_and(|row| row.integrity == "broken") {
        return Some(Liveness::Broken);
    }
    if chain.is_some_and(|row| row.integrity == "gap") {
        return Some(Liveness::Gap);
    }
    // A decommissioned machine is supposed to be quiet. Everything above this
    // line is a finding regardless; everything below is the expected outcome of
    // retiring it.
    if install_status == RETIRED {
        return None;
    }
    if quiet_for(trail.reported_at.as_deref(), now) > silence {
        return Some(Liveness::Silent);
    }
    let verified = chain.map_or(0, |row| row.head_seq);
    if verified < trail.local_head_seq {
        return Some(Liveness::Backlog);
    }
    None
}

/// How long a trail has been quiet. Pure.
///
/// A trail that has never reported has been quiet forever, which is what
/// [`Duration::MAX`] says: a row created by an install that then died before
/// its first report is exactly the case a liveness sweep exists to catch.
#[must_use]
pub fn quiet_for(reported_at: Option<&str>, now: DateTime<Utc>) -> Duration {
    let Some(reported) = reported_at.filter(|when| !when.trim().is_empty()) else {
        return Duration::MAX;
    };
    let Ok(when) = DateTime::parse_from_rfc3339(reported) else {
        return Duration::MAX;
    };
    now.signed_duration_since(when.with_timezone(&Utc))
        .to_std()
        .unwrap_or(Duration::ZERO)
}

/// Classify every trail against what the plane verified. Pure.
///
/// Findings come back in trail order rather than severity order: a sweep is
/// read as a list of machines, and re-sorting it would make two consecutive
/// runs hard to diff.
#[must_use]
pub fn findings(
    trails: &[AuditTrailRow],
    chains: &BTreeMap<String, AuditChainRow>,
    statuses: &BTreeMap<String, String>,
    now: DateTime<Utc>,
    silence: Duration,
) -> Vec<Finding> {
    trails
        .iter()
        .filter_map(|trail| {
            let chain = chains.get(&trail.trail_id);
            let status = statuses.get(&trail.install).map_or("", String::as_str);
            let liveness = classify_trail(trail, chain, status, now, silence)?;
            Some(Finding {
                trail_id: trail.trail_id.clone(),
                install: trail.install.clone(),
                liveness,
                detail: detail_for(liveness, trail, chain),
            })
        })
        .collect()
}

/// The sentence an operator reads for one finding. Pure.
///
/// Clipped to a line, because the halted reason it may quote comes from a
/// daemon and a log record is not the place to find out how long that can be.
#[must_use]
pub fn detail_for(
    liveness: Liveness,
    trail: &AuditTrailRow,
    chain: Option<&AuditChainRow>,
) -> String {
    let detail = match liveness {
        Liveness::Broken => trail
            .halted_reason
            .as_deref()
            .filter(|why| !why.trim().is_empty())
            .map_or_else(
                || {
                    chain
                        .and_then(|row| row.finding.clone())
                        .unwrap_or_else(|| "the plane's chain for this trail is broken".to_string())
                },
                |why| format!("the daemon halted shipping: {why}"),
            ),
        Liveness::Gap => chain
            .and_then(|row| row.finding.clone())
            .unwrap_or_else(|| "entries are missing from the plane's chain".to_string()),
        Liveness::Silent => format!(
            "no report since {}",
            trail.reported_at.as_deref().unwrap_or("ever")
        ),
        Liveness::Backlog => format!(
            "the daemon has written {} entries and the plane has verified {}",
            trail.local_head_seq,
            chain.map_or(0, |row| row.head_seq)
        ),
    };
    detail.chars().take(500).collect()
}

/// The supervised liveness sweep.
#[acton_actor]
pub struct SilenceSweep {
    settings: Option<Arc<SilenceSettings>>,
    schedule: Option<ScheduledSend>,
    last: Option<SilenceReport>,
}

impl SilenceSweep {
    /// Register the handlers. Public so a test can build the actor on a bare
    /// runtime without going through `ServiceBuilder`.
    pub fn configure(actor: &mut ManagedActor<Idle, Self>) {
        actor
            .mutate_on::<Init>(|actor, ctx| {
                let settings = ctx.message().0.clone();
                let handle = actor.handle().clone();
                if actor.model.schedule.is_none() {
                    actor.model.schedule = Interval::new(settings.sweep)
                        .map(|every| handle.send_every(Tick, every, Cadence::FixedDelay));
                }
                actor.model.settings = Some(settings);
                Reply::pending(async move { handle.send(Tick).await })
            })
            .mutate_on::<Tick>(|actor, ctx| {
                let reply = ctx.reply_envelope();
                let handle = actor.handle().clone();
                let Some(settings) = actor.model.settings.clone() else {
                    warn!("the liveness sweep ticked before it was initialised; doing nothing");
                    return Reply::pending(async move {
                        reply.send(SilenceReport::uninitialised()).await;
                    });
                };
                Reply::pending(async move {
                    let report = sweep(&settings).await;
                    announce(&report);
                    handle.send(report.clone()).await;
                    reply.send(report).await;
                })
            })
            .mutate_on::<SilenceReport>(|actor, ctx| {
                actor.model.last = Some(ctx.message().clone());
                Reply::ready()
            })
            .act_on::<GetSilenceReport>(|actor, ctx| {
                let reply = ctx.reply_envelope();
                let report = actor.model.last.clone().unwrap_or_else(|| SilenceReport {
                    ran_at: String::new(),
                    initialised: actor.model.settings.is_some(),
                    trails: 0,
                    findings: Vec::new(),
                });
                Reply::pending(async move { reply.send(report).await })
            })
            .after_start(|actor| {
                let handle = actor.handle().clone();
                async move {
                    match SETTINGS.get() {
                        Some(settings) => handle.send(Init(settings.clone())).await,
                        None => warn!(
                            "the liveness sweep started with no settings installed; it will do nothing"
                        ),
                    }
                }
            });
    }
}

impl ActorExtension for SilenceSweep {
    fn configure(actor: &mut ManagedActor<Idle, Self>) {
        Self::configure(actor);
    }
}

/// One pass over every trail the audit bearer can see.
///
/// A plane that cannot be listed produces an empty report rather than a
/// panic: the next tick tries again, and a sweep that crashed its actor would
/// take the liveness signal down with the thing it was meant to watch.
async fn sweep(settings: &SilenceSettings) -> SilenceReport {
    let ran_at = now_rfc3339();
    let trails = match settings.plane.audit_trails().await {
        Ok(rows) => rows,
        Err(error) => {
            warn!(target: "garrison.audit.liveness", "the liveness sweep could not list trails: {error}");
            return SilenceReport {
                ran_at,
                initialised: true,
                trails: 0,
                findings: Vec::new(),
            };
        }
    };
    let chains = match settings.plane.audit_chains().await {
        Ok(rows) => rows
            .into_iter()
            .map(|row| (row.trail_id.clone(), row))
            .collect::<BTreeMap<_, _>>(),
        Err(error) => {
            warn!(target: "garrison.audit.liveness", "the liveness sweep could not list chains: {error}");
            return SilenceReport {
                ran_at,
                initialised: true,
                trails: trails.len(),
                findings: Vec::new(),
            };
        }
    };

    // One fetch per distinct install, not per trail: a machine that has opened
    // several trails is one machine.
    let mut statuses: BTreeMap<String, String> = BTreeMap::new();
    for trail in &trails {
        if statuses.contains_key(&trail.install) {
            continue;
        }
        match settings.plane.agent_install(&trail.install).await {
            Ok(Some(row)) => {
                statuses.insert(trail.install.clone(), row.status);
            }
            // An install the sweep cannot see is not evidence of retirement,
            // so it stays subject to every finding.
            Ok(None) => {
                statuses.insert(trail.install.clone(), String::new());
            }
            Err(error) => {
                warn!(
                    target: "garrison.audit.liveness",
                    install = %trail.install,
                    "the liveness sweep could not read an install: {error}"
                );
            }
        }
    }

    SilenceReport {
        ran_at,
        initialised: true,
        trails: trails.len(),
        findings: findings(&trails, &chains, &statuses, Utc::now(), settings.silence),
    }
}

/// Put every finding where the deployment's log pipeline already looks.
fn announce(report: &SilenceReport) {
    for finding in &report.findings {
        warn!(
            target: "garrison.audit.liveness",
            ran_at = %report.ran_at,
            trail = %finding.trail_id,
            install = %finding.install,
            liveness = %finding.liveness,
            "audit trail is not shipping: {}",
            finding.detail
        );
    }
    if report.all_live() {
        info!(
            target: "garrison.audit.liveness",
            ran_at = %report.ran_at,
            trails = report.trails,
            "every audit trail is still shipping"
        );
    }
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acton_reactive::prelude::ActonApp;

    const WINDOW: Duration = Duration::from_secs(900);

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-29T12:00:00Z")
            .expect("a fixed clock")
            .with_timezone(&Utc)
    }

    fn trail(reported_at: &str, local_head_seq: i64) -> AuditTrailRow {
        AuditTrailRow {
            id: "audittrail_01".into(),
            trail_id: "trail_01".into(),
            install: "agentinstall_01".into(),
            organization: "organization_01".into(),
            local_head_seq,
            local_head_hash: Some("abc".into()),
            shipped_through: local_head_seq,
            reported_at: Some(reported_at.into()),
            halted_reason: None,
        }
    }

    fn chain(head_seq: i64, integrity: &str) -> AuditChainRow {
        AuditChainRow {
            id: "auditchain_01".into(),
            trail_id: "trail_01".into(),
            trail: "audittrail_01".into(),
            organization: "organization_01".into(),
            install: "agentinstall_01".into(),
            head_hash: "abc".into(),
            head_seq,
            verified_through: head_seq,
            integrity: integrity.into(),
            finding: None,
            last_entry_at: None,
        }
    }

    #[test]
    fn a_trail_reporting_inside_the_window_and_level_with_the_plane_is_healthy() {
        let trail = trail("2026-08-29T11:55:00Z", 10);

        assert_eq!(
            classify_trail(&trail, Some(&chain(10, "intact")), "active", now(), WINDOW),
            None
        );
    }

    #[test]
    fn a_trail_that_stopped_reporting_is_silent() {
        let trail = trail("2026-08-29T11:00:00Z", 10);

        assert_eq!(
            classify_trail(&trail, Some(&chain(10, "intact")), "active", now(), WINDOW),
            Some(Liveness::Silent)
        );
    }

    #[test]
    fn a_trail_that_never_reported_has_been_quiet_forever() {
        let mut trail = trail("", 0);
        trail.reported_at = None;

        assert_eq!(quiet_for(None, now()), Duration::MAX);
        assert_eq!(
            classify_trail(&trail, None, "active", now(), WINDOW),
            Some(Liveness::Silent)
        );
    }

    #[test]
    fn a_daemon_writing_more_than_the_plane_has_verified_is_a_backlog() {
        let trail = trail("2026-08-29T11:59:00Z", 40);

        assert_eq!(
            classify_trail(&trail, Some(&chain(10, "intact")), "active", now(), WINDOW),
            Some(Liveness::Backlog)
        );
    }

    #[test]
    fn a_trail_with_no_chain_at_all_is_a_backlog_once_it_has_written_anything() {
        let trail = trail("2026-08-29T11:59:00Z", 3);

        assert_eq!(
            classify_trail(&trail, None, "active", now(), WINDOW),
            Some(Liveness::Backlog)
        );
    }

    #[test]
    fn a_gap_outranks_silence_because_it_is_the_finding_somebody_must_read() {
        let trail = trail("2026-08-29T09:00:00Z", 10);

        assert_eq!(
            classify_trail(&trail, Some(&chain(10, "gap")), "active", now(), WINDOW),
            Some(Liveness::Gap)
        );
    }

    #[test]
    fn a_halt_the_daemon_recorded_outranks_everything() {
        let mut trail = trail("2026-08-29T09:00:00Z", 90);
        trail.halted_reason = Some("the plane refused sequence 12 as forked".into());

        assert_eq!(
            classify_trail(&trail, Some(&chain(10, "gap")), "active", now(), WINDOW),
            Some(Liveness::Broken)
        );
    }

    #[test]
    fn a_blank_halted_reason_is_a_healthy_trail_and_not_a_halt() {
        let mut trail = trail("2026-08-29T11:59:00Z", 10);
        trail.halted_reason = Some("   ".into());

        assert_eq!(
            classify_trail(&trail, Some(&chain(10, "intact")), "active", now(), WINDOW),
            None
        );
    }

    #[test]
    fn a_retired_install_is_allowed_to_be_quiet() {
        let trail = trail("2026-08-20T09:00:00Z", 40);

        assert_eq!(
            classify_trail(&trail, Some(&chain(10, "intact")), RETIRED, now(), WINDOW),
            None
        );
    }

    #[test]
    fn a_retired_install_with_a_gapped_chain_is_still_a_finding() {
        let trail = trail("2026-08-20T09:00:00Z", 40);

        assert_eq!(
            classify_trail(&trail, Some(&chain(10, "gap")), RETIRED, now(), WINDOW),
            Some(Liveness::Gap)
        );
    }

    #[test]
    fn an_unparsable_report_time_counts_as_never_having_reported() {
        assert_eq!(quiet_for(Some("last tuesday"), now()), Duration::MAX);
    }

    #[test]
    fn a_report_time_in_the_future_is_not_a_negative_silence() {
        assert_eq!(
            quiet_for(Some("2026-08-29T13:00:00Z"), now()),
            Duration::ZERO
        );
    }

    #[test]
    fn a_sweep_reports_one_finding_per_unhealthy_trail_in_trail_order() {
        let mut healthy = trail("2026-08-29T11:59:00Z", 10);
        healthy.trail_id = "trail_a".into();
        let mut behind = trail("2026-08-29T11:59:00Z", 99);
        behind.trail_id = "trail_b".into();
        let chains = BTreeMap::from([("trail_a".to_string(), chain(10, "intact"))]);
        let statuses = BTreeMap::from([("agentinstall_01".to_string(), "active".to_string())]);

        let found = findings(&[healthy, behind], &chains, &statuses, now(), WINDOW);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].trail_id, "trail_b");
        assert_eq!(found[0].liveness, Liveness::Backlog);
        assert!(found[0].detail.contains("99"), "{}", found[0].detail);
    }

    #[test]
    fn a_halt_detail_quotes_what_the_daemon_said() {
        let mut halted = trail("2026-08-29T11:59:00Z", 10);
        halted.halted_reason = Some("the plane refused sequence 12".into());

        let detail = detail_for(Liveness::Broken, &halted, None);

        assert!(detail.contains("sequence 12"), "{detail}");
    }

    #[test]
    fn a_detail_is_clipped_to_the_line_an_operator_reads() {
        let mut halted = trail("2026-08-29T11:59:00Z", 10);
        halted.halted_reason = Some("x".repeat(2000));

        assert!(detail_for(Liveness::Broken, &halted, None).len() <= 500);
    }

    #[test]
    fn findings_are_ordered_most_serious_first_when_sorted() {
        let mut all = vec![
            Liveness::Backlog,
            Liveness::Silent,
            Liveness::Broken,
            Liveness::Gap,
        ];
        all.sort_unstable();

        assert_eq!(
            all,
            vec![
                Liveness::Broken,
                Liveness::Gap,
                Liveness::Silent,
                Liveness::Backlog
            ]
        );
    }

    fn settings() -> Arc<SilenceSettings> {
        Arc::new(SilenceSettings {
            // A port nothing listens on: the plane is unreachable.
            plane: Plane::new("http://127.0.0.1:9", "tok").expect("a client"),
            silence: WINDOW,
            sweep: Duration::from_secs(3600),
        })
    }

    #[tokio::test]
    async fn a_tick_before_init_does_nothing_and_says_so() {
        let mut runtime = ActonApp::launch_async().await;
        let mut actor = runtime.new_actor::<SilenceSweep>();
        SilenceSweep::configure(&mut actor);
        let handle = actor.start().await;

        let report = handle.ask(Tick).await.expect("reply");
        assert!(!report.initialised);
        assert!(report.findings.is_empty());

        runtime.shutdown_all().await.expect("shutdown");
    }

    #[tokio::test]
    async fn an_unreachable_plane_produces_an_empty_sweep_rather_than_a_crash() {
        let mut runtime = ActonApp::launch_async().await;
        let mut actor = runtime.new_actor::<SilenceSweep>();
        SilenceSweep::configure(&mut actor);
        let handle = actor.start().await;

        handle.send(Init(settings())).await;
        let report = handle.ask(Tick).await.expect("reply");
        assert!(report.initialised);
        assert_eq!(report.trails, 0);

        let last = handle.ask(GetSilenceReport).await.expect("reply");
        assert!(last.initialised);
        runtime.shutdown_all().await.expect("shutdown");
    }
}
