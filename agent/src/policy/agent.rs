//! The actor that holds the policy in force, and refuses turns without one.
//!
//! # Three states, and only three
//!
//! [`PolicyState`] is the whole answer to "what governs this machine":
//!
//! - **Standalone** — there is no `[plane]` section. `garrison.toml` governs,
//!   exactly as it did before any of this existed, and the local
//!   auto-approve list is read. This is the developer's laptop.
//! - **Governed** — a bundle the plane assigned, whose content hashes to the
//!   checksum the plane recorded and whose every rule matches its own
//!   examples. The local auto-approve list is not read at all.
//! - **Ungoverned** — the plane said no, or said nothing for longer than the
//!   organization allows. Every turn is refused and every tool call is
//!   denied. The daemon still starts and still answers `_garrison/status`,
//!   because an operator who cannot find out *why* their machine stopped
//!   working will go and turn the governance off.
//!
//! There is deliberately no fourth state in which a governed install falls
//! back to its local file. That would make policy something a laptop can
//! edit, which is the thing this whole subsystem exists to prevent.
//!
//! # It is a gate and a decider
//!
//! Two different questions arrive here. [`AdmitTurn`] asks whether a turn may
//! start at all, and is folded with every other gate in
//! [`crate::admission`]. [`Decide`] asks what to do about one tool call, and
//! is asked by the approval hook on the prompt loop's own task. The second is
//! answered from the same bundle as the first, so a turn that was admitted
//! cannot have its tools decided by a different policy than the one that
//! admitted it.
//!
//! # The refresh is a timer, not a poll on the turn path
//!
//! `send_every` drives a [`Refresh`] on a fixed delay and the first one is
//! sent at startup. Nothing on the turn path waits for the network: a turn
//! asks this actor, which answers from what it already holds. That is what
//! keeps a slow plane from becoming slow prompts.

use crate::admission::{Admission, AdmitTurn, TurnRefusal};
use crate::plane::{Authenticate, PlaneError, RevokeBearer, Session};
use crate::policy::cache::{self, Cached};
use crate::policy::pull::{self, PullFailure};
use crate::protocol::acp;
use crate::protocol::conn::{Describe, StatusPart};
use acton_reactive::prelude::*;
use chrono::{DateTime, Utc};
use garrison_policy::{AgentsMdDiscovery, Bundle, ConfiguredProvider, Context, Disposition};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// How long the policy agent waits on the plane session before giving up on
/// one refresh.
///
/// The refresh runs off the turn path, so this is generous compared with the
/// gate deadline: it bounds a wedged exchange, it is not in anybody's way.
pub const REFRESH_DEADLINE: Duration = Duration::from_secs(30);

/// Where a bundle in force came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Pulled from the control plane on the last refresh.
    Plane,
    /// Read from this machine's cache, because the plane could not be asked.
    Cache,
}

impl Source {
    /// The word `_garrison/status` reports.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Plane => "plane",
            Self::Cache => "cache",
        }
    }
}

/// What governs this install right now.
#[derive(Clone, Debug)]
pub enum PolicyState {
    /// No control plane. `garrison.toml` governs.
    Standalone,
    /// A verified bundle is in force.
    Governed {
        /// The bundle, shared rather than cloned per decision.
        bundle: Arc<Bundle>,
        /// Where it came from.
        source: Source,
        /// When the plane last handed it over.
        fetched_at: DateTime<Utc>,
        /// The configured providers this bundle approves, in the order the
        /// operator's own file lists them.
        approved_providers: Arc<Vec<String>>,
    },
    /// Nothing governs this install, so nothing runs on it.
    Ungoverned {
        /// What an operator does about it, in one sentence.
        reason: String,
    },
}

impl PolicyState {
    /// The word `_garrison/status` reports.
    const fn word(&self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Governed { .. } => "governed",
            Self::Ungoverned { .. } => "ungoverned",
        }
    }
}

/// Everything the agent is given at spawn and never changes.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The credential holder, on a governed install. `None` is standalone.
    pub plane: Option<ActorHandle>,
    /// Where the verified bundle is cached.
    pub cache_path: PathBuf,
    /// How often to re-ask the plane.
    pub refresh: Duration,
    /// How long a cached bundle may still be enforced after the plane stops
    /// answering.
    pub grace: Duration,
    /// Whether the writing tools actually run in a sandboxed child.
    ///
    /// Read from what the kernel granted rather than from what was asked
    /// for, so a rule that requires a sandbox refuses on a host where the
    /// sandbox degraded.
    pub sandbox_active: bool,
    /// The providers `acton-ai.toml` configures, for endpoint approval.
    pub providers: Arc<Vec<ConfiguredProvider>>,
    /// The provider a turn uses when nothing names one.
    pub default_provider: Option<String>,
    /// The local auto-approve list, read only while standalone.
    pub auto_approve: Arc<Vec<String>>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            plane: None,
            cache_path: PathBuf::from("bundle.json"),
            refresh: Duration::from_secs(300),
            grace: Duration::from_secs(86_400),
            sandbox_active: false,
            providers: Arc::new(Vec::new()),
            default_provider: None,
            auto_approve: Arc::new(Vec::new()),
        }
    }
}

/// Asks what to do about one tool call.
#[acton_message]
pub struct Decide {
    /// The tool the model asked for.
    pub tool_name: String,
    /// The arguments it proposed.
    pub arguments: Value,
    /// Whether the tool's own definition declares it idempotent.
    ///
    /// Upstream's word, not local configuration, which is why it may exempt a
    /// tool from prompting without widening what a bundle said: acton-ai
    /// declares `read_file` idempotent, and a bundle that wanted it to prompt
    /// says so with a `ToolRule`.
    pub idempotent: bool,
}

impl Request for Decide {
    type Response = Disposition;
}

/// Asks what governs `AGENTS.md` discovery for the next turn.
#[acton_message]
pub struct CurrentAgentsMdPolicy;

impl Request for CurrentAgentsMdPolicy {
    type Response = AgentsMdPolicy;
}

/// What a turn's `AGENTS.md` discovery may do, read off the state in force
/// when it is asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentsMdPolicy {
    /// Whether, and how far, discovery may reach.
    pub discovery: AgentsMdDiscovery,
    /// The paths discovery is confined to when `discovery` is `restricted`.
    /// Empty and unused otherwise.
    pub allowed_paths: Vec<String>,
}

/// Go and ask the plane what governs this install.
#[acton_message]
pub struct Refresh;

/// Start the refresh timer, and pull once now.
///
/// A separate message rather than work done at spawn, because the handle that
/// owns the schedule has to be the running actor's: a `ScheduledSend` dropped
/// on the floor stops firing, so it is parked on the model where the actor
/// keeps it alive for as long as it lives.
#[acton_message]
struct Arm;

/// A refresh finished; delivered by the pending future to its own mailbox.
#[acton_message]
struct Fetched {
    outcome: Result<Box<pull::Pulled>, PullFailure>,
    session: Option<Session>,
    at: DateTime<Utc>,
}

/// What a state transition asks the handler to do afterwards.
///
/// Separated from the transition itself so [`next_state`] stays pure: the
/// rules about when a bundle is cached and when it is thrown away are the
/// part worth testing, and they do not need a filesystem to be tested over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Write this bundle to the cache as of this instant.
    WriteCache,
    /// Remove the cache: the plane has answered, and the answer was no.
    DiscardCache,
    /// Record the bundle and checksum on the `AgentInstall` row, promoting an
    /// `enrolled` install to `active`.
    WriteBack {
        /// The bundle row id.
        bundle: String,
        /// Its checksum, as this daemon computed it.
        checksum: String,
        /// Whether to promote the install to `active`.
        promote: bool,
    },
}

/// The daemon's policy holder.
#[acton_actor]
pub struct PolicyAgent {
    settings: Settings,
    state: Option<PolicyState>,
    /// What the last refresh ran into, kept for the status even when a cached
    /// bundle is still in force.
    last_error: Option<String>,
    /// When the last refresh completed, whatever it concluded.
    last_refresh_at: Option<DateTime<Utc>>,
    /// The refresh timer, kept alive by being held.
    schedule: Option<ScheduledSend>,
}

impl PolicyAgent {
    /// Starts the policy agent.
    ///
    /// A standalone install settles immediately and never touches the
    /// network. A governed one starts in [`PolicyState::Ungoverned`] with a
    /// reason saying so, reads its cache, and asks the plane at once: a
    /// daemon that admitted turns during the seconds before its first
    /// successful pull would have a window in which nothing governed it.
    pub async fn spawn(runtime: &mut ActorRuntime, settings: Settings) -> ActorHandle {
        let mut builder = runtime.new_actor_with_name::<Self>("policy".to_string());
        let governed = settings.plane.is_some();
        builder.model.settings = settings;
        builder.model.state = Some(if governed {
            PolicyState::Ungoverned {
                reason: STARTING.to_string(),
            }
        } else {
            PolicyState::Standalone
        });
        configure(&mut builder);

        let handle = builder.start().await;
        if governed {
            // Armed, not awaited: a plane that is down at boot must cost this
            // daemon its turns, not its startup.
            handle.send(Arm).await;
        }
        handle
    }
}

/// What a governed install says about itself before its first pull lands.
pub const STARTING: &str =
    "this install has not yet pulled its policy bundle from the control plane";

/// Wires the handlers.
fn configure(builder: &mut ManagedActor<Idle, PolicyAgent>) {
    let self_handle = builder.handle().clone();

    builder.mutate_on::<Arm>(|actor, _| {
        let handle = actor.handle().clone();
        if actor.model.schedule.is_none() {
            // A zero refresh is already normalized away by the config, so
            // `None` here means "pull once and never again", which is still
            // better than a spin loop against the control plane.
            actor.model.schedule = Interval::new(actor.model.settings.refresh)
                .map(|every| handle.send_every(Refresh, every, Cadence::FixedDelay));
        }
        Reply::pending(async move {
            handle.send(Refresh).await;
        })
    });

    builder.mutate_on::<Refresh>(move |actor, _| {
        let Some(plane) = actor.model.settings.plane.clone() else {
            return Reply::ready();
        };
        let handle = self_handle.clone();

        Reply::pending(async move {
            let at = Utc::now();
            let (outcome, session) = refresh(&plane, at).await;
            handle
                .send(Fetched {
                    outcome: outcome.map(Box::new),
                    session,
                    at,
                })
                .await;
        })
    });

    builder.mutate_on::<Fetched>(|actor, envelope| {
        let message = envelope.message();
        let now = Utc::now();
        let previous = actor.model.state.clone().unwrap_or(PolicyState::Standalone);

        let outcome = match &message.outcome {
            Ok(pulled) => Ok(pulled.as_ref().clone()),
            Err(failure) => Err(failure.clone()),
        };

        let (state, effects) = next_state(
            &previous,
            outcome,
            &actor.model.settings,
            message.at,
            now,
            &read_cache(&actor.model.settings, message.session.as_ref()),
        );

        announce(&previous, &state);
        actor.model.last_error = match &state {
            PolicyState::Governed { .. } | PolicyState::Standalone => match &message.outcome {
                Ok(_) => None,
                Err(failure) => Some(failure.to_string()),
            },
            PolicyState::Ungoverned { reason } => Some(reason.clone()),
        };
        actor.model.last_refresh_at = Some(now);
        actor.model.state = Some(state.clone());

        let cache_path = actor.model.settings.cache_path.clone();
        let session = message.session.clone();
        let bundle = bundle_of(&state);
        let fetched_at = message.at;

        Reply::pending(async move {
            apply(
                &effects,
                &cache_path,
                bundle.as_deref(),
                session.as_ref(),
                fetched_at,
            )
            .await;
        })
    });

    builder.mutate_on::<Decide>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let message = envelope.message();
        let disposition = decide(
            actor.model.state.as_ref(),
            &actor.model.settings,
            &message.tool_name,
            &message.arguments,
            message.idempotent,
        );
        Reply::pending(async move {
            reply.send(disposition).await;
        })
    });

    builder.mutate_on::<AdmitTurn>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let admission = admit(actor.model.state.as_ref(), &actor.model.settings);
        Reply::pending(async move {
            reply.send(admission).await;
        })
    });

    builder.mutate_on::<CurrentAgentsMdPolicy>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let policy = agents_md_policy(actor.model.state.as_ref());
        Reply::pending(async move {
            reply.send(policy).await;
        })
    });

    builder.mutate_on::<Describe>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let part = StatusPart::Governance(Box::new(describe(
            actor.model.state.as_ref(),
            &actor.model.settings,
            actor.model.last_error.as_deref(),
            actor.model.last_refresh_at,
            Utc::now(),
        )));
        Reply::pending(async move {
            reply.send(part).await;
        })
    });
}

/// The bundle currently in force, if any.
fn bundle_of(state: &PolicyState) -> Option<Arc<Bundle>> {
    match state {
        PolicyState::Governed { bundle, .. } => Some(Arc::clone(bundle)),
        PolicyState::Standalone | PolicyState::Ungoverned { .. } => None,
    }
}

/// What governs `AGENTS.md` discovery right now. Pure.
///
/// `Governed` reads the bundle's own fields, which is the entire point of
/// this issue: a bundle author gets a real gate, not a recorded-but-unenforced
/// one. `Standalone` has no bundle to read and discovery runs unrestricted, on
/// the same reasoning the local auto-approve list is read only while
/// standalone — a developer's laptop with no plane trusts itself.
/// `Ungoverned` and the moment before the agent's first state write are not
/// "no policy", they are "policy that failed to arrive", and every other gate
/// in this daemon fails closed on that distinction; this one does too, even
/// though no turn ever reaches far enough to ask, because an `Ungoverned`
/// install refuses every turn before admission gets here.
fn agents_md_policy(state: Option<&PolicyState>) -> AgentsMdPolicy {
    match state {
        Some(PolicyState::Governed { bundle, .. }) => AgentsMdPolicy {
            discovery: bundle.header.agents_md_discovery,
            allowed_paths: bundle
                .header
                .agents_md_allowed_paths()
                .map(str::to_string)
                .collect(),
        },
        Some(PolicyState::Standalone) => AgentsMdPolicy {
            discovery: AgentsMdDiscovery::Enabled,
            allowed_paths: Vec::new(),
        },
        Some(PolicyState::Ungoverned { .. }) | None => AgentsMdPolicy {
            discovery: AgentsMdDiscovery::Disabled,
            allowed_paths: Vec::new(),
        },
    }
}

/// Reads the cache, if there is an install to read one for.
///
/// A cache that cannot be used at all is reported as `None` rather than as an
/// error, because every reason it might fail already produces the same
/// outcome for the caller: there is no bundle here.
fn read_cache(settings: &Settings, session: Option<&Session>) -> Option<Cached> {
    let install = session.map(|session| session.install.as_str())?;
    match cache::read(&settings.cache_path, install) {
        Ok(cached) => Some(cached),
        Err(cache::CacheError::Missing) => None,
        Err(error) => {
            tracing::warn!(%error, "the cached policy bundle was not usable");
            None
        }
    }
}

/// Asks the plane for this install's bundle, renewing the bearer once on a
/// refusal that says the bearer is the problem.
///
/// The session is returned alongside the outcome so the caller can spend it
/// on the write-back without a second exchange.
async fn refresh(
    plane: &ActorHandle,
    now: DateTime<Utc>,
) -> (Result<pull::Pulled, PullFailure>, Option<Session>) {
    let session = match authenticate(plane).await {
        Ok(session) => session,
        Err(error) => return (Err(plane_failure(error)), None),
    };

    match pull::fetch_bundle(&session, now).await {
        Ok(pulled) => (Ok(pulled), Some(session)),
        // A 401 means the bearer this session handed out is no longer
        // accepted. Exactly one retry, over a fresh one: a daemon that
        // retried a refusal in a loop would be a denial of service against
        // its own control plane.
        Err(PullFailure::Governance(reason)) if reason.contains("(401)") => {
            plane.send(RevokeBearer).await;
            match authenticate(plane).await {
                Ok(session) => {
                    let outcome = pull::fetch_bundle(&session, now).await;
                    (outcome, Some(session))
                }
                Err(error) => (Err(plane_failure(error)), None),
            }
        }
        Err(failure) => (Err(failure), Some(session)),
    }
}

/// Gets an authenticated view of the plane, or says why not.
async fn authenticate(plane: &ActorHandle) -> Result<Session, PlaneError> {
    match plane.ask_with_timeout(Authenticate, REFRESH_DEADLINE).await {
        Ok(result) => result,
        Err(error) => Err(PlaneError::Unreachable(format!(
            "the credential holder did not answer: {error:?}"
        ))),
    }
}

/// A credential failure, sorted the way a pull failure is.
fn plane_failure(error: PlaneError) -> PullFailure {
    if error.is_unreachable() {
        return PullFailure::Unreachable(error);
    }
    PullFailure::Governance(format!(
        "this install could not authenticate to the control plane, so it has no policy: {error}"
    ))
}

/// The whole state machine. Pure.
///
/// The three outcomes and what each does with the cache are the rule an
/// auditor is shown, so they are one function over plain values rather than
/// something spread across a handler.
#[must_use]
pub fn next_state(
    previous: &PolicyState,
    outcome: Result<pull::Pulled, PullFailure>,
    settings: &Settings,
    fetched_at: DateTime<Utc>,
    now: DateTime<Utc>,
    cached: &Option<Cached>,
) -> (PolicyState, Vec<Effect>) {
    if matches!(previous, PolicyState::Standalone) {
        return (PolicyState::Standalone, Vec::new());
    }

    match outcome {
        Ok(pulled) => {
            let checksum = pulled.bundle.header.checksum.clone();
            let bundle_id = pulled.bundle.id().to_string();
            let approved = garrison_policy::approved_providers(&pulled.bundle, &settings.providers);
            (
                PolicyState::Governed {
                    bundle: Arc::new(pulled.bundle),
                    source: Source::Plane,
                    fetched_at,
                    approved_providers: Arc::new(approved),
                },
                vec![
                    Effect::WriteCache,
                    Effect::WriteBack {
                        bundle: bundle_id,
                        checksum,
                        promote: pulled.install_status == "enrolled",
                    },
                ],
            )
        }

        // The plane spoke and the answer was no. No grace, and the cache goes.
        Err(PullFailure::Governance(reason)) => (
            PolicyState::Ungoverned { reason },
            vec![Effect::DiscardCache],
        ),

        // The plane did not answer. Ride it out, if there is something to ride
        // it out on and the organization allows it.
        Err(PullFailure::Unreachable(error)) => {
            (offline(previous, settings, now, cached, &error), Vec::new())
        }
    }
}

/// What governs an install whose plane is not answering. Pure.
fn offline(
    previous: &PolicyState,
    settings: &Settings,
    now: DateTime<Utc>,
    cached: &Option<Cached>,
    error: &PlaneError,
) -> PolicyState {
    if let PolicyState::Governed {
        bundle,
        fetched_at,
        approved_providers,
        ..
    } = previous
    {
        if cache::is_fresh(*fetched_at, now, settings.grace) {
            return PolicyState::Governed {
                bundle: Arc::clone(bundle),
                source: Source::Cache,
                fetched_at: *fetched_at,
                approved_providers: Arc::clone(approved_providers),
            };
        }
    }

    if let Some(cached) = cached {
        if cache::is_fresh(cached.fetched_at, now, settings.grace) {
            let approved = garrison_policy::approved_providers(&cached.bundle, &settings.providers);
            return PolicyState::Governed {
                bundle: Arc::new(cached.bundle.clone()),
                source: Source::Cache,
                fetched_at: cached.fetched_at,
                approved_providers: Arc::new(approved),
            };
        }
    }

    PolicyState::Ungoverned {
        reason: unreachable_reason(settings.grace, cached, previous, now, error),
    }
}

/// The sentence an operator reads when a machine has run out of grace. Pure.
fn unreachable_reason(
    grace: Duration,
    cached: &Option<Cached>,
    previous: &PolicyState,
    now: DateTime<Utc>,
    error: &PlaneError,
) -> String {
    let fetched_at = match previous {
        PolicyState::Governed { fetched_at, .. } => Some(*fetched_at),
        PolicyState::Standalone | PolicyState::Ungoverned { .. } => {
            cached.as_ref().map(|cached| cached.fetched_at)
        }
    };

    let held = match fetched_at.and_then(|at| cache::staleness(at, now, grace)) {
        Some(over) => format!(
            "the last bundle this machine verified is {} past the {} it may be enforced \
             offline for",
            humanize(over),
            humanize(grace)
        ),
        None if grace.is_zero() => {
            "this install is configured never to run on a cached bundle".to_string()
        }
        None => "this machine has no policy bundle it has ever verified".to_string(),
    };

    format!("the control plane is unreachable and {held}: {error}")
}

/// A duration in the largest unit that does not lie. Pure.
fn humanize(duration: Duration) -> String {
    let seconds = duration.as_secs();
    match seconds {
        0..=59 => format!("{seconds}s"),
        60..=3599 => format!("{}m", seconds / 60),
        3600..=86_399 => format!("{}h", seconds / 3600),
        _ => format!("{}d", seconds / 86_400),
    }
}

/// Says out loud when the thing governing this machine changed.
fn announce(previous: &PolicyState, current: &PolicyState) {
    match (previous, current) {
        (
            PolicyState::Governed { bundle: was, .. },
            PolicyState::Governed {
                bundle: now,
                source,
                ..
            },
        ) if was.header.checksum == now.header.checksum => {
            tracing::debug!(source = source.as_str(), "policy refreshed, unchanged");
        }
        (_, PolicyState::Governed { bundle, source, .. }) => tracing::info!(
            bundle = bundle.name(),
            version = bundle.version(),
            checksum = bundle.checksum(),
            source = source.as_str(),
            "this install is governed by a policy bundle from the control plane",
        ),
        (_, PolicyState::Ungoverned { reason }) => {
            tracing::error!(%reason, "this install has no policy in force, so it runs no turns");
        }
        (_, PolicyState::Standalone) => {}
    }
}

/// Carries out what a transition asked for.
async fn apply(
    effects: &[Effect],
    cache_path: &std::path::Path,
    bundle: Option<&Bundle>,
    session: Option<&Session>,
    fetched_at: DateTime<Utc>,
) {
    for effect in effects {
        match effect {
            Effect::WriteCache => {
                let (Some(bundle), Some(session)) = (bundle, session) else {
                    continue;
                };
                let cached = Cached {
                    fetched_at,
                    install: session.install.clone(),
                    bundle: bundle.clone(),
                };
                if let Err(error) = cache::write(cache_path, &cached) {
                    tracing::warn!(
                        %error,
                        path = %cache_path.display(),
                        "the policy bundle could not be cached, so this install has no offline grace",
                    );
                }
            }
            Effect::DiscardCache => cache::discard(cache_path),
            Effect::WriteBack {
                bundle,
                checksum,
                promote,
            } => {
                let Some(session) = session else { continue };
                write_back(session, bundle, checksum, *promote).await;
            }
        }
    }
}

/// Records on the `AgentInstall` row which bundle this machine is running.
///
/// This is what makes drift detectable: the console compares the checksum an
/// install reports against the bundle it assigned. A failure is logged and
/// retried on the next refresh; it does not ungovern the install, because the
/// bundle is authentic whether or not the plane could be told about it.
async fn write_back(session: &Session, bundle: &str, checksum: &str, promote: bool) {
    let mut fields = json!({
        "policy_bundle": bundle,
        "bundle_checksum": checksum,
        "last_heartbeat": Utc::now().to_rfc3339(),
    });
    if promote {
        if let Some(object) = fields.as_object_mut() {
            object.insert("status".to_string(), json!("active"));
        }
    }

    if let Err(error) = session
        .api
        .patch("AgentInstall", &session.install, &fields)
        .await
    {
        tracing::warn!(
            %error,
            "the control plane was not told which bundle this install is running; \
             it will be told on the next refresh",
        );
    } else if promote {
        tracing::info!("this install is now active in the fleet");
    }
}

/// What to do about one tool call. Pure over the state.
///
/// Standalone reads the local auto-approve list; governed does not, which is
/// rule five of the unreachable-plane rule and the reason a laptop cannot
/// widen its own policy by editing a file.
#[must_use]
pub fn decide(
    state: Option<&PolicyState>,
    settings: &Settings,
    tool_name: &str,
    arguments: &Value,
    idempotent: bool,
) -> Disposition {
    match state {
        None => Disposition::Deny {
            rule: None,
            reason: "the policy agent has no state, so nothing may run".to_string(),
        },
        Some(PolicyState::Standalone) => {
            if settings
                .auto_approve
                .iter()
                .any(|pattern| garrison_policy::name_matches(pattern, tool_name))
            {
                Disposition::AutoApprove { rule: None }
            } else {
                Disposition::ask()
            }
        }
        Some(PolicyState::Governed { bundle, .. }) => garrison_policy::decide(
            bundle,
            &Context {
                tool_name,
                arguments,
                sandbox_active: settings.sandbox_active,
                idempotent,
            },
        ),
        Some(PolicyState::Ungoverned { reason }) => Disposition::Deny {
            rule: None,
            reason: reason.clone(),
        },
    }
}

/// Whether a turn may start. Pure over the state.
///
/// A governed install whose configured default provider is not one the bundle
/// approves is refused here rather than at the first token: an operator who
/// learns halfway through a turn that their model was never authorized has
/// already sent it their code.
#[must_use]
pub fn admit(state: Option<&PolicyState>, settings: &Settings) -> Admission {
    match state {
        None => Admission::Refuse(TurnRefusal::Policy {
            reason: "the policy agent has no state".to_string(),
        }),
        Some(PolicyState::Standalone) => Admission::Admit,
        Some(PolicyState::Ungoverned { reason }) => Admission::Refuse(TurnRefusal::Policy {
            reason: reason.clone(),
        }),
        Some(PolicyState::Governed {
            bundle,
            approved_providers,
            ..
        }) => match unapproved_provider(settings, approved_providers) {
            None => Admission::Admit,
            Some(name) => Admission::Refuse(TurnRefusal::Policy {
                reason: format!(
                    "the provider this daemon would send code to ('{name}') is not an approved \
                     model endpoint in bundle '{}' v{}; a security officer must approve the \
                     endpoint or this install must be pointed at one that is approved",
                    bundle.name(),
                    bundle.version()
                ),
            }),
        },
    }
}

/// The default provider's name when the bundle does not approve it. Pure.
///
/// A daemon with no default provider named cannot have an unapproved one, and
/// a bundle that approves no endpoints at all approves the whole configured
/// set: an organization that has not recorded its endpoints has not made a
/// decision about them, and refusing every turn over an empty table would
/// read as a bug rather than as policy.
fn unapproved_provider(settings: &Settings, approved: &[String]) -> Option<String> {
    if approved.is_empty() {
        return None;
    }
    let name = settings.default_provider.as_deref()?;
    (!approved.iter().any(|approved| approved == name)).then(|| name.to_string())
}

/// The status part this agent contributes. Pure.
#[must_use]
pub fn describe(
    state: Option<&PolicyState>,
    settings: &Settings,
    last_error: Option<&str>,
    last_refresh_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> acp::GovernanceStatus {
    let state = state.unwrap_or(&PolicyState::Standalone);

    let bundle = match state {
        PolicyState::Governed {
            bundle,
            source,
            fetched_at,
            ..
        } => Some(acp::BundleStatus {
            id: bundle.id().to_string(),
            name: bundle.name().to_string(),
            version: bundle.version(),
            checksum: bundle.checksum().to_string(),
            source: source.as_str().to_string(),
            fetched_at: fetched_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            stale: cache::staleness(*fetched_at, now, settings.grace).is_some(),
        }),
        PolicyState::Standalone | PolicyState::Ungoverned { .. } => None,
    };

    let governed = matches!(state, PolicyState::Governed { .. });

    acp::GovernanceStatus {
        state: state.word().to_string(),
        bundle,
        reason: match state {
            PolicyState::Ungoverned { reason } => Some(reason.clone()),
            PolicyState::Standalone | PolicyState::Governed { .. } => {
                last_error.map(ToString::to_string)
            }
        },
        approved_providers: match state {
            PolicyState::Governed {
                approved_providers, ..
            } => approved_providers.as_ref().clone(),
            PolicyState::Standalone | PolicyState::Ungoverned { .. } => Vec::new(),
        },
        default_provider: settings.default_provider.clone(),
        not_enforced: Bundle::not_enforced()
            .iter()
            .map(|field| (*field).to_string())
            .collect(),
        local_auto_approve_ignored: governed && !settings.auto_approve.is_empty(),
        offline_grace_secs: settings.grace.as_secs(),
        refresh_secs: settings.refresh.as_secs(),
        last_refresh_at: last_refresh_at
            .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use garrison_policy::{BundleHeader, CommandDecision, CommandRule, ModelEndpoint};

    fn bundle(name: &str) -> Bundle {
        let mut bundle = Bundle {
            header: BundleHeader {
                id: "policybundle_01".into(),
                name: name.into(),
                version: 4,
                status: "published".into(),
                ..BundleHeader::default()
            },
            command_rules: vec![CommandRule {
                name: "no rm".into(),
                program: "rm".into(),
                decision: CommandDecision::Forbid,
                justification: "deleting files is not reviewable after the fact".into(),
                enabled: true,
                priority: 10,
                ..CommandRule::default()
            }],
            ..Bundle::default()
        };
        bundle.header.checksum = garrison_policy::checksum(&bundle);
        bundle
    }

    fn settings() -> Settings {
        Settings {
            plane: Some(ActorHandle::default()),
            grace: Duration::from_secs(86_400),
            ..Settings::default()
        }
    }

    fn governed(at: DateTime<Utc>) -> PolicyState {
        PolicyState::Governed {
            bundle: Arc::new(bundle("Baseline")),
            source: Source::Plane,
            fetched_at: at,
            approved_providers: Arc::new(Vec::new()),
        }
    }

    fn pulled(status: &str) -> pull::Pulled {
        pull::Pulled {
            bundle: bundle("Baseline"),
            install_status: status.to_string(),
        }
    }

    #[test]
    fn a_verified_pull_governs_the_install_and_is_cached() {
        let now = Utc::now();

        let (state, effects) = next_state(
            &PolicyState::Ungoverned {
                reason: STARTING.into(),
            },
            Ok(pulled("active")),
            &settings(),
            now,
            now,
            &None,
        );

        assert!(matches!(
            state,
            PolicyState::Governed {
                source: Source::Plane,
                ..
            }
        ));
        assert!(effects.contains(&Effect::WriteCache));
        assert!(effects
            .iter()
            .any(|effect| matches!(effect, Effect::WriteBack { promote: false, .. })));
    }

    #[test]
    fn an_enrolled_install_that_puts_a_bundle_in_force_becomes_active() {
        let now = Utc::now();

        let (_, effects) = next_state(
            &PolicyState::Ungoverned {
                reason: STARTING.into(),
            },
            Ok(pulled("enrolled")),
            &settings(),
            now,
            now,
            &None,
        );

        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, Effect::WriteBack { promote: true, .. })),
            "putting the assigned policy in force is what makes an install active",
        );
    }

    #[test]
    fn the_write_back_carries_the_checksum_this_daemon_computed() {
        let now = Utc::now();

        let (_, effects) = next_state(
            &PolicyState::Standalone,
            Ok(pulled("active")),
            &settings(),
            now,
            now,
            &None,
        );

        assert!(
            effects.is_empty(),
            "a standalone install never talks to a plane",
        );

        let (_, effects) = next_state(
            &governed(now),
            Ok(pulled("active")),
            &settings(),
            now,
            now,
            &None,
        );
        let checksum = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::WriteBack { checksum, .. } => Some(checksum.clone()),
                _ => None,
            })
            .expect("a governed pull reports its checksum");

        assert_eq!(checksum, bundle("Baseline").header.checksum);
    }

    #[test]
    fn a_governance_refusal_ungoverns_the_install_at_once_and_throws_the_cache_away() {
        let now = Utc::now();

        let (state, effects) = next_state(
            &governed(now),
            Err(PullFailure::Governance(
                "no active policy assignment covers this install".into(),
            )),
            &settings(),
            now,
            now,
            &None,
        );

        assert!(matches!(state, PolicyState::Ungoverned { .. }));
        assert_eq!(effects, vec![Effect::DiscardCache]);
    }

    #[test]
    fn an_unreachable_plane_keeps_the_bundle_already_in_force_and_says_it_is_cached() {
        let now = Utc::now();
        let fetched = now - chrono::Duration::hours(2);

        let (state, effects) = next_state(
            &governed(fetched),
            Err(PullFailure::Unreachable(PlaneError::Unreachable(
                "timeout".into(),
            ))),
            &settings(),
            now,
            now,
            &None,
        );

        match state {
            PolicyState::Governed {
                source, fetched_at, ..
            } => {
                assert_eq!(source, Source::Cache);
                assert_eq!(
                    fetched_at, fetched,
                    "the grace window runs from when the plane last spoke",
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(effects.is_empty(), "an outage neither caches nor discards");
    }

    #[test]
    fn a_restarted_daemon_picks_its_bundle_back_up_off_the_cache() {
        let now = Utc::now();
        let cached = Some(Cached {
            fetched_at: now - chrono::Duration::hours(3),
            install: "agentinstall_01".into(),
            bundle: bundle("Baseline"),
        });

        let (state, _) = next_state(
            &PolicyState::Ungoverned {
                reason: STARTING.into(),
            },
            Err(PullFailure::Unreachable(PlaneError::Unreachable(
                "no route to host".into(),
            ))),
            &settings(),
            now,
            now,
            &cached,
        );

        assert!(
            matches!(
                state,
                PolicyState::Governed {
                    source: Source::Cache,
                    ..
                }
            ),
            "{state:?}",
        );
    }

    #[test]
    fn a_bundle_past_its_grace_stops_governing_and_the_reason_says_how_far_past() {
        let now = Utc::now();

        let (state, _) = next_state(
            &governed(now - chrono::Duration::hours(30)),
            Err(PullFailure::Unreachable(PlaneError::Unreachable(
                "timeout".into(),
            ))),
            &settings(),
            now,
            now,
            &None,
        );

        match state {
            PolicyState::Ungoverned { reason } => {
                assert!(reason.contains("unreachable"), "{reason}");
                assert!(reason.contains("past the 1d"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_zero_grace_refuses_the_moment_the_plane_stops_answering() {
        let now = Utc::now();
        let strict = Settings {
            grace: Duration::ZERO,
            ..settings()
        };

        let (state, _) = next_state(
            &governed(now),
            Err(PullFailure::Unreachable(PlaneError::Unreachable(
                "timeout".into(),
            ))),
            &strict,
            now,
            now,
            &None,
        );

        match state {
            PolicyState::Ungoverned { reason } => {
                assert!(
                    reason.contains("never to run on a cached bundle"),
                    "{reason}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_standalone_install_is_never_moved_off_standalone_by_anything() {
        let now = Utc::now();

        let (state, effects) = next_state(
            &PolicyState::Standalone,
            Err(PullFailure::Governance("no assignment".into())),
            &settings(),
            now,
            now,
            &None,
        );

        assert!(matches!(state, PolicyState::Standalone));
        assert!(effects.is_empty());
    }

    #[test]
    fn a_standalone_install_reads_its_local_auto_approve_list() {
        let settings = Settings {
            plane: None,
            auto_approve: Arc::new(vec!["read_file".into(), "mcp__*".into()]),
            ..Settings::default()
        };
        let arguments = json!({});

        assert!(matches!(
            decide(
                Some(&PolicyState::Standalone),
                &settings,
                "read_file",
                &arguments,
                true
            ),
            Disposition::AutoApprove { .. }
        ));
        assert!(decide(
            Some(&PolicyState::Standalone),
            &settings,
            "bash",
            &arguments,
            false
        )
        .is_prompt());
    }

    #[test]
    fn a_governed_install_does_not_read_its_local_auto_approve_list() {
        let now = Utc::now();
        let settings = Settings {
            auto_approve: Arc::new(vec!["bash".into()]),
            ..settings()
        };
        let arguments = json!({ "command": "rm -rf /tmp/x" });

        let disposition = decide(Some(&governed(now)), &settings, "bash", &arguments, false);

        assert!(
            matches!(disposition, Disposition::Deny { .. }),
            "a local file must not widen a bundle that forbids the command: {disposition:?}",
        );
    }

    #[test]
    fn a_governed_installs_agents_md_policy_comes_from_its_bundle() {
        let now = Utc::now();
        let mut restricted = bundle("Baseline");
        restricted.header.agents_md_discovery = AgentsMdDiscovery::Restricted;
        restricted.header.agents_md_allowed_paths = "packages/api\ndocs".into();
        let state = PolicyState::Governed {
            bundle: Arc::new(restricted),
            source: Source::Plane,
            fetched_at: now,
            approved_providers: Arc::new(Vec::new()),
        };

        let policy = agents_md_policy(Some(&state));

        assert_eq!(policy.discovery, AgentsMdDiscovery::Restricted);
        assert_eq!(policy.allowed_paths, ["packages/api", "docs"]);
    }

    #[test]
    fn a_standalone_install_has_no_bundle_to_restrict_it_so_discovery_runs() {
        let policy = agents_md_policy(Some(&PolicyState::Standalone));

        assert_eq!(policy.discovery, AgentsMdDiscovery::Enabled);
        assert!(policy.allowed_paths.is_empty());
    }

    #[test]
    fn an_ungoverned_install_fails_closed_on_agents_md_discovery_too() {
        let state = PolicyState::Ungoverned {
            reason: "no assignment".into(),
        };

        let policy = agents_md_policy(Some(&state));

        assert_eq!(policy.discovery, AgentsMdDiscovery::Disabled);
    }

    #[test]
    fn no_state_at_all_fails_closed_the_same_way_ungoverned_does() {
        let policy = agents_md_policy(None);

        assert_eq!(policy.discovery, AgentsMdDiscovery::Disabled);
    }

    #[test]
    fn an_ungoverned_install_denies_every_tool_call_with_the_reason() {
        let arguments = json!({});
        let state = PolicyState::Ungoverned {
            reason: "no assignment".into(),
        };

        match decide(Some(&state), &settings(), "read_file", &arguments, true) {
            Disposition::Deny { reason, .. } => assert_eq!(reason, "no assignment"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_agent_with_no_state_denies_rather_than_guessing() {
        let arguments = json!({});

        assert!(matches!(
            decide(None, &settings(), "read_file", &arguments, true),
            Disposition::Deny { .. }
        ));
        assert!(matches!(
            admit(None, &settings()),
            Admission::Refuse(TurnRefusal::Policy { .. })
        ));
    }

    #[test]
    fn a_standalone_install_admits_every_turn() {
        assert_eq!(
            admit(Some(&PolicyState::Standalone), &Settings::default()),
            Admission::Admit
        );
    }

    #[test]
    fn an_ungoverned_install_refuses_every_turn_and_says_why() {
        let state = PolicyState::Ungoverned {
            reason: "the control plane is unreachable".into(),
        };

        assert_eq!(
            admit(Some(&state), &settings()),
            Admission::Refuse(TurnRefusal::Policy {
                reason: "the control plane is unreachable".into()
            })
        );
    }

    #[test]
    fn a_turn_that_would_go_to_an_unapproved_model_is_refused_before_it_starts() {
        let now = Utc::now();
        let state = PolicyState::Governed {
            bundle: Arc::new(bundle("Baseline")),
            source: Source::Plane,
            fetched_at: now,
            approved_providers: Arc::new(vec!["ollama".into()]),
        };
        let settings = Settings {
            default_provider: Some("claude".into()),
            ..settings()
        };

        match admit(Some(&state), &settings) {
            Admission::Refuse(TurnRefusal::Policy { reason }) => {
                assert!(reason.contains("'claude'"), "{reason}");
                assert!(reason.contains("Baseline"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_approved_default_provider_admits_the_turn() {
        let now = Utc::now();
        let state = PolicyState::Governed {
            bundle: Arc::new(bundle("Baseline")),
            source: Source::Plane,
            fetched_at: now,
            approved_providers: Arc::new(vec!["ollama".into()]),
        };
        let settings = Settings {
            default_provider: Some("ollama".into()),
            ..settings()
        };

        assert_eq!(admit(Some(&state), &settings), Admission::Admit);
    }

    #[test]
    fn a_bundle_that_approves_no_endpoints_has_not_decided_anything_about_providers() {
        let now = Utc::now();
        let settings = Settings {
            default_provider: Some("claude".into()),
            ..settings()
        };

        assert_eq!(admit(Some(&governed(now)), &settings), Admission::Admit);
    }

    #[test]
    fn the_status_names_the_bundle_its_source_and_the_two_fields_that_are_not_enforced() {
        let now = Utc::now();
        let settings = Settings {
            auto_approve: Arc::new(vec!["bash".into()]),
            ..settings()
        };

        let status = describe(Some(&governed(now)), &settings, None, Some(now), now);

        assert_eq!(status.state, "governed");
        let reported = status.bundle.expect("a governed install names its bundle");
        assert_eq!(reported.name, "Baseline");
        assert_eq!(reported.version, 4);
        assert_eq!(reported.source, "plane");
        assert!(!reported.stale);
        assert_eq!(reported.checksum.len(), 64);
        assert!(status.not_enforced.contains(&"network_egress".to_string()));
        assert!(
            status.local_auto_approve_ignored,
            "an operator with a local list must be told it is not being read",
        );
    }

    #[test]
    fn a_standalone_status_reports_no_bundle_and_no_ignored_list() {
        let now = Utc::now();

        let status = describe(
            Some(&PolicyState::Standalone),
            &Settings::default(),
            None,
            None,
            now,
        );

        assert_eq!(status.state, "standalone");
        assert!(status.bundle.is_none());
        assert!(!status.local_auto_approve_ignored);
    }

    #[test]
    fn an_ungoverned_status_carries_the_reason_a_turn_would_be_refused_for() {
        let now = Utc::now();
        let state = PolicyState::Ungoverned {
            reason: "no active policy assignment covers this install".into(),
        };

        let status = describe(Some(&state), &settings(), None, Some(now), now);

        assert_eq!(status.state, "ungoverned");
        assert_eq!(
            status.reason.as_deref(),
            Some("no active policy assignment covers this install")
        );
    }

    #[test]
    fn a_cached_bundle_still_inside_its_grace_is_reported_as_not_stale() {
        let now = Utc::now();
        let state = PolicyState::Governed {
            bundle: Arc::new(bundle("Baseline")),
            source: Source::Cache,
            fetched_at: now - chrono::Duration::hours(4),
            approved_providers: Arc::new(Vec::new()),
        };

        let status = describe(Some(&state), &settings(), Some("timeout"), Some(now), now);

        let reported = status.bundle.expect("still governed");
        assert_eq!(reported.source, "cache");
        assert!(!reported.stale);
        assert_eq!(
            status.reason.as_deref(),
            Some("timeout"),
            "a governed install riding out an outage still says what the outage is",
        );
    }

    #[test]
    fn durations_read_in_the_largest_unit_that_does_not_lie() {
        assert_eq!(humanize(Duration::from_secs(45)), "45s");
        assert_eq!(humanize(Duration::from_secs(600)), "10m");
        assert_eq!(humanize(Duration::from_secs(7200)), "2h");
        assert_eq!(humanize(Duration::from_secs(172_800)), "2d");
    }

    #[test]
    fn a_credential_the_plane_refused_is_a_governance_failure_not_an_outage() {
        let failure = plane_failure(PlaneError::Rejected {
            status: 403,
            message: "install quarantined".into(),
        });

        assert!(matches!(failure, PullFailure::Governance(_)), "{failure:?}");
        assert!(failure.to_string().contains("could not authenticate"));
    }

    #[test]
    fn approved_providers_are_derived_from_the_bundles_endpoints() {
        let now = Utc::now();
        let mut with_endpoint = bundle("Baseline");
        with_endpoint.endpoints = vec![ModelEndpoint {
            id: "modelendpoint_01".into(),
            name: "on-prem ollama".into(),
            provider_type: "ollama".into(),
            model: "qwen3.8".into(),
            base_url: Some("http://127.0.0.1:11434/v1".into()),
            authorization: "ato".into(),
            status: "approved".into(),
        }];
        with_endpoint.header.checksum = garrison_policy::checksum(&with_endpoint);

        let settings = Settings {
            providers: Arc::new(vec![ConfiguredProvider {
                name: "ollama".into(),
                provider_type: "ollama".into(),
                model: "qwen3.8".into(),
                base_url: Some("http://127.0.0.1:11434/v1/".into()),
            }]),
            default_provider: Some("ollama".into()),
            ..settings()
        };

        let (state, _) = next_state(
            &governed(now),
            Ok(pull::Pulled {
                bundle: with_endpoint,
                install_status: "active".into(),
            }),
            &settings,
            now,
            now,
            &None,
        );

        assert_eq!(admit(Some(&state), &settings), Admission::Admit);
        let status = describe(Some(&state), &settings, None, Some(now), now);
        assert_eq!(status.approved_providers, vec!["ollama".to_string()]);
    }
}
