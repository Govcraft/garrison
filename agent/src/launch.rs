//! Bringing the whole agent up, in the one order that works.
//!
//! # Order
//!
//! 1. The acton-ai runtime, with Garrison's approval hook already installed.
//!    The hook must be in place before the runtime launches, because a policy
//!    is not something acton-ai lets you attach afterwards — and a window in
//!    which tools ran ungoverned is not a window a governed agent may have.
//! 2. The turn router, subscribed to the broker before it can miss anything.
//! 3. The thread supervisor.
//! 4. The listener, and last of all the accept loop — so no client can connect
//!    to a server whose threads have nowhere to go.

use crate::approval::approval_hook;
use crate::config::GarrisonConfig;
use crate::enrollment::key::InstallKey;
use crate::error::GarrisonError;
use crate::plane::session::{Identity, PlaneSession};
use crate::protocol::acp::{
    AgentCapabilities, CompactionStatus, PromptCapabilities, SandboxStatus, SessionCapabilities,
    SessionListCapabilities,
};
use crate::protocol::conn::ThreadDefaults;
use crate::protocol::server::{self, ServerSetup};
use crate::protocol::transport::{Listener, UnixListener};
use crate::router::TurnRouter;
use crate::thread::ThreadSupervisor;
use acton_ai::facade::ActonAI;
use acton_ai::memory::CompactionConfig;
use acton_ai::policy::ToolPolicy;
use acton_ai::tools::sandbox::{HardeningMode, ProcessSandboxConfig};
use acton_reactive::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A running agent server.
#[derive(Debug)]
pub struct Garrison {
    /// The acton-reactive runtime every Garrison actor lives in.
    pub runtime: ActorRuntime,
    /// The acton-ai runtime turns run on.
    pub ai: ActonAI,
    /// The protocol server actor.
    pub server: ActorHandle,
    /// Where it is listening.
    pub endpoint: String,
}

impl Garrison {
    /// Stops the server and the runtime it owns.
    ///
    /// # Errors
    ///
    /// [`GarrisonErrorKind::Runtime`](crate::error::GarrisonErrorKind::Runtime)
    /// if the actor system did not shut down cleanly.
    pub async fn shutdown(mut self) -> Result<(), GarrisonError> {
        // The server first: cancelling the accept loop before tearing down the
        // actors behind it means no connection is accepted into a half-gone
        // process.
        if let Err(error) = self.server.stop().await {
            tracing::debug!(%error, "protocol server did not stop cleanly");
        }
        self.runtime
            .shutdown_all()
            .await
            .map_err(|error| GarrisonError::runtime(format!("shutdown failed: {error}")))
    }
}

/// Builds the acton-ai runtime with Garrison's governance in place.
///
/// # Errors
///
/// [`GarrisonErrorKind::Configuration`](crate::error::GarrisonErrorKind::Configuration)
/// when acton-ai's own config is present but unusable, or when no provider is
/// configured — an agent with nothing to think with is a misconfiguration, not
/// a server to start.
pub async fn build_ai(acton_config: Option<&Path>) -> Result<ActonAI, GarrisonError> {
    // Builtins are registered per turn rather than automatically, because a
    // turn knows something the runtime does not: which session it belongs to,
    // and therefore which directory its tools may touch. See
    // `thread::run_turn`.
    let mut builder = ActonAI::builder()
        .app_name("garrison-agent")
        .with_builtins()
        .manual_builtins();

    builder = match acton_config {
        Some(path) => builder.from_config_file(path).map_err(|error| {
            GarrisonError::configuration(path.display().to_string(), error.to_string())
        })?,
        None => builder
            .try_from_config()
            .map_err(|error| GarrisonError::configuration("acton-ai.toml", error.to_string()))?,
    };

    // Fail now, with the fix in the message, rather than 401 on the first
    // prompt: a cloud provider selected as the default but holding no key is
    // a setup gap, and the setup command is `garrison-agent login`.
    let file_config = match acton_config {
        Some(path) => acton_ai::config::from_path(path).ok(),
        None => acton_ai::config::load().ok(),
    };
    if let Some(config) = file_config {
        api_key_preflight(&config)?;
    }

    // A policy with a hook and no rules: every call reaches the hook, and the
    // hook decides whether it needs a human. Rules arrive with the prefix-rule
    // engine; until then the decision belongs entirely to Garrison's callback.
    let ai = builder
        .tool_policy(ToolPolicy::new().on_approval(approval_hook))
        .launch()
        .await
        .map_err(|error| {
            GarrisonError::configuration("acton-ai", launch_refusal(&error.to_string()))
        })?;

    if ai.provider_count() == 0 {
        return Err(GarrisonError::configuration(
            "providers",
            "no LLM provider is configured; add one to acton-ai.toml",
        ));
    }

    Ok(ai)
}

/// Rewrites acton-ai's launch failure into something an operator can act on.
///
/// The one case that matters is the audit trail already being owned by
/// another process: acton-ai refuses to spawn a second writer of a hash chain
/// (an exclusive advisory lock on the trail), and the reason is almost always
/// that a `garrison-agent serve` is already running for this user. The
/// message says so and names the two ways out. Everything else passes
/// through unchanged. Pure.
fn launch_refusal(message: &str) -> String {
    if message.contains("already owned by another process") {
        format!(
            "{message}. There is one daemon per user per machine and it owns the audit trail; \
             another `garrison-agent serve` is most likely running (check `garrison-agent ping` \
             or `systemctl --user status garrison-agent`). Stop it, or point this one at a \
             different trail. This is a refusal to start (exit 2), not a crash: restarting \
             will not change the answer"
        )
    } else {
        message.to_string()
    }
}

/// Refuses to launch when the default provider needs an API key it lacks.
///
/// Only the *default* provider is checked: a configured-but-keyless
/// alternate is dormant, not broken.
fn api_key_preflight(config: &acton_ai::config::ActonAIConfig) -> Result<(), GarrisonError> {
    let name = match &config.default_provider {
        Some(name) => name.clone(),
        None if config.providers.len() == 1 => {
            config.providers.keys().next().cloned().unwrap_or_default()
        }
        None => return Ok(()),
    };
    let Some(provider) = config.providers.get(&name) else {
        return Ok(());
    };
    let needs_key = matches!(
        provider.provider_type.to_lowercase().as_str(),
        "anthropic" | "openai"
    );
    if needs_key && provider.resolve_api_key().is_empty() {
        return Err(GarrisonError::configuration(
            format!("providers.{name}"),
            "no API key found; run `garrison-agent login` (Anthropic) or set the \
             provider's api_key_env / api_key_file, or point default_provider \
             at a local provider",
        ));
    }
    Ok(())
}

/// Spawns the router and the thread supervisor, and assembles what a
/// connection needs.
///
/// Separated from [`start`] so a test can bring the whole stack up over a
/// socket pair, with no listener and no filesystem, and still exercise the
/// real actors.
///
/// # There is exactly one runtime
///
/// Garrison's actors are spawned into **acton-ai's own** [`ActorRuntime`],
/// taken from the `ActonAI` passed in, and never into a second one of their
/// own. A broker belongs to a runtime: an actor that subscribes on a different
/// runtime's broker subscribes successfully, runs happily, and receives
/// nothing. [`TurnRouter`] lives entirely on acton-ai's broadcasts, so putting
/// it anywhere else would silently cost every client its tool events. That is
/// why this function takes the runtime out of the `ActonAI` rather than
/// accepting one — there is no way to hand it the wrong one.
///
/// # One actor per `spawn_*`
///
/// The body is a list of small spawns, each returning the handle it made,
/// followed by the assembly. A subsystem that joins the daemon adds one
/// `spawn_*` function, one line here, and pushes its handle onto `gates`
/// (if it decides turns) or `describers` (if it reports status), or both.
/// Nothing else in this function changes.
///
/// # Errors
///
/// [`GarrisonErrorKind::Runtime`](crate::error::GarrisonErrorKind::Runtime)
/// when the configured project root defaults to a working directory the
/// process cannot read.
pub async fn build_setup(
    ai: &ActonAI,
    config: &GarrisonConfig,
) -> Result<ServerSetup, GarrisonError> {
    // A clone of the runtime handle reaches the same system and the same
    // broker. `runtime_mut()` would instead demand the only `ActonAI` handle
    // in existence — which the `ServerSetup` below makes false the moment it
    // takes its own clone.
    // What the kernel actually granted, computed once and used twice: the
    // plane is told it at enrollment, and every client reads it back from
    // `_garrison/status`. Deriving it in one place is what keeps the two
    // answers from drifting.
    let sandbox = sandbox_status(ai.sandbox_config());

    // Before any actor, any listener, and any thread. An install the plane
    // turned away must not reach the point of having somewhere to run a turn.
    let enrollment = match config.plane.as_ref() {
        Some(plane) => crate::enrollment::ensure(plane, &sandbox).await?,
        None => None,
    };

    let mut runtime = ai.runtime().clone();
    let project_root = resolve_project_root(config.threads.project_root.as_deref())?;

    let router = spawn_router(&mut runtime, ai).await;
    let supervisor = spawn_supervisor(&mut runtime).await;
    let lsp = spawn_lsp(&mut runtime, config, &project_root).await;
    let plane = spawn_plane(&mut runtime, config.plane.as_ref(), enrollment.clone()).await?;
    let attribution = attribution(enrollment.as_ref());
    let audit = spawn_audit(&mut runtime, ai, config, enrollment).await?;
    let sessions = spawn_sessions(&mut runtime, ai, config).await?;

    // Ordered lists, because order is the contract: gates are asked first to
    // last and the first refusal wins; describers fill the status in sequence.
    let mut gates: Vec<ActorHandle> = Vec::new();
    let mut describers: Vec<ActorHandle> = vec![supervisor.clone(), router.clone()];
    describers.extend(plane.clone());
    if let Some(keeper) = audit {
        gates.push(keeper.clone());
        describers.push(keeper);
    }
    let store = sessions.map(|(keeper, store)| {
        gates.push(keeper.clone());
        describers.push(keeper);
        store
    });

    Ok(ServerSetup {
        supervisor,
        runtime: ai.clone(),
        router,
        defaults: thread_defaults(config, project_root, lsp, gates, store, attribution),
        capabilities: capabilities(),
        audited: ai.is_audited(),
        sandbox,
        describers,
        plane,
    })
}

/// The turn router, subscribed to the broker before anything can be missed.
///
/// It is handed the resolved compaction policy because it is also the daemon's
/// describer for what happens to a history that outgrows the window.
async fn spawn_router(runtime: &mut ActorRuntime, ai: &ActonAI) -> ActorHandle {
    TurnRouter::spawn(runtime, compaction_status(ai.compaction())).await
}

/// Describes the auto-compaction policy in force, for `_garrison/status`.
///
/// `None` means the oldest exchanges are truncated rather than summarized,
/// which is acton-ai's default and stays the default here: Garrison never
/// calls `.compaction()` on the builder, so `[context] auto_compact` in
/// `acton-ai.toml` is the single source of truth and this only reads it back.
/// Pure.
fn compaction_status(config: Option<&CompactionConfig>) -> Option<CompactionStatus> {
    config.map(|config| CompactionStatus {
        threshold: config.threshold.get(),
        keep_recent_turns: config.keep_recent_turns.get(),
    })
}

/// The session supervisor.
async fn spawn_supervisor(runtime: &mut ActorRuntime) -> ActorHandle {
    ThreadSupervisor::spawn(runtime).await
}

/// The daemon's credential holder, on a governed install.
///
/// `None` on a standalone agent, which has no identity and nothing to
/// authenticate as. Everything that reaches the plane goes through the handle
/// this returns; see [`crate::plane`] for why that is a rule and not a habit.
///
/// # Why an unreadable key stops the daemon
///
/// Enrollment has already succeeded by the time this runs, so the plane holds
/// the public half of a specific key and every subsystem downstream is about
/// to assume this process can prove it holds the private half. A daemon that
/// started anyway would come up looking healthy, refuse every turn the moment
/// a gate asked the plane, and give an operator a symptom four layers from
/// the cause. Refusing here says the actual thing, once, at exit 2. The key is
/// loaded with [`InstallKey::load`] and never `load_or_create`: generating a
/// replacement would leave a daemon that had quietly stopped being itself.
///
/// # Errors
///
/// [`GarrisonErrorKind::Enrollment`](crate::error::GarrisonErrorKind::Enrollment)
/// when an enrolled install's key cannot be read.
async fn spawn_plane(
    runtime: &mut ActorRuntime,
    config: Option<&crate::config::PlaneConfig>,
    enrollment: Option<crate::enrollment::Record>,
) -> Result<Option<ActorHandle>, GarrisonError> {
    let (Some(config), Some(record)) = (config, enrollment) else {
        return Ok(None);
    };

    let key = InstallKey::load(&crate::enrollment::key::key_path(
        &crate::enrollment::config_dir(),
    ))?;

    let identity = Identity {
        record,
        key: Arc::new(key),
        plane_url: config.url.clone(),
        hooks_url: config.hooks_url().to_string(),
    };
    tracing::info!(
        plane = %identity.plane_url,
        exchange = %identity.hooks_url,
        install = %identity.record.install,
        "the install will authenticate to the control plane by signed assertion"
    );
    Ok(Some(PlaneSession::spawn(runtime, identity).await))
}

/// The audit anchor keeper, which is also a turn gate.
///
/// Refuses to start when a required trail is not armed, or when the trail and
/// its anchor disagree; see [`crate::audit::spawn`], which owns both rules.
async fn spawn_audit(
    runtime: &mut ActorRuntime,
    ai: &ActonAI,
    config: &GarrisonConfig,
    enrolled: Option<crate::enrollment::Record>,
) -> Result<Option<ActorHandle>, GarrisonError> {
    let install = enrolled.map(|record| record.install);
    crate::audit::spawn(runtime, ai, config, install).await
}

/// Session persistence, or a refusal to start without it.
///
/// Returns the keeper — which is both a turn gate and a status describer — and
/// the store handle every session is written through. `None` on an install
/// that arms no `[checkpoint]` database and does not require one.
async fn spawn_sessions(
    runtime: &mut ActorRuntime,
    ai: &ActonAI,
    config: &GarrisonConfig,
) -> Result<Option<(ActorHandle, crate::session::SessionStore)>, GarrisonError> {
    crate::session::spawn(runtime, ai, config).await
}

/// The configured language servers.
///
/// Eager, so rust-analyzer indexes while the first prompt is still being
/// written; a server that fails to spawn is a warning inside, not an error.
async fn spawn_lsp(
    runtime: &mut ActorRuntime,
    config: &GarrisonConfig,
    project_root: &Path,
) -> crate::lsp::LspRegistry {
    crate::lsp::spawn_servers(runtime, &config.lsp_servers, project_root).await
}

/// Resolves the directory sessions are rooted at by default.
///
/// Canonical from here on. Everything downstream — the session boundary, the
/// patch tool, the language servers, the builtins a turn registers — compares
/// against this one resolved path, so there is no spelling of a directory that
/// is inside for one tool and outside for another.
fn resolve_project_root(configured: Option<&Path>) -> Result<PathBuf, GarrisonError> {
    let configured = match configured {
        Some(root) => root.to_path_buf(),
        None => std::env::current_dir()
            .map_err(|error| GarrisonError::runtime(format!("no working directory: {error}")))?,
    };

    configured.canonicalize().map_err(|error| {
        GarrisonError::runtime(format!(
            "project root '{}' cannot be resolved: {error}",
            configured.display()
        ))
    })
}

/// What every new session inherits.
fn thread_defaults(
    config: &GarrisonConfig,
    project_root: PathBuf,
    lsp: crate::lsp::LspRegistry,
    gates: Vec<ActorHandle>,
    store: Option<crate::session::SessionStore>,
    attribution: crate::session::Attribution,
) -> ThreadDefaults {
    let mut roots = vec![project_root.clone()];
    roots.extend(config.threads.workspace_roots.iter().cloned());

    ThreadDefaults {
        approved_roots: Arc::new(crate::boundary::approve(&roots)),
        project_root,
        system_prompt: config.threads.system_prompt.clone(),
        approval_timeout: config.approval_timeout(),
        auto_approve: Arc::new(config.approval.auto_approve.clone()),
        lsp: Arc::new(lsp),
        gates,
        store,
        attribution,
    }
}

/// Who the sessions this daemon opens belong to.
///
/// Pure. An unenrolled install has nothing to say here, and its sessions are
/// stored unattributed on purpose: there is no tenant to attribute them to.
/// The operator is not yet named because enrollment identifies the machine
/// rather than the person at it; the field exists so directory identity has
/// somewhere to land without a second migration.
fn attribution(enrolled: Option<&crate::enrollment::Record>) -> crate::session::Attribution {
    crate::session::Attribution {
        install: enrolled.map(|record| record.install.clone()),
        organization: enrolled.map(|record| record.organization.clone()),
        operator_upn: None,
    }
}

/// Describes the isolation in force, for `_garrison/status`.
///
/// The absent case is the one that matters: no configuration means writing
/// tools run in this process, and the status says so plainly rather than
/// omitting the subject.
fn sandbox_status(config: Option<&ProcessSandboxConfig>) -> SandboxStatus {
    let Some(config) = config else {
        return SandboxStatus::disabled();
    };

    SandboxStatus {
        enabled: true,
        hardening: Some(hardening_name(config.hardening).to_string()),
        timeout_secs: Some(config.timeout.as_secs()),
        memory_limit_bytes: config.memory_limit,
    }
}

/// The wire spelling of a hardening mode, matching the one TOML accepts.
const fn hardening_name(mode: HardeningMode) -> &'static str {
    match mode {
        HardeningMode::Off => "off",
        HardeningMode::BestEffort => "besteffort",
        HardeningMode::Enforce => "enforce",
    }
}

/// Starts every Garrison actor and returns the protocol server.
///
/// # Errors
///
/// As [`build_setup`] and [`crate::protocol::server::serve`].
pub async fn start(
    ai: &ActonAI,
    config: &GarrisonConfig,
    listener: Box<dyn Listener>,
) -> Result<ActorHandle, GarrisonError> {
    let setup = build_setup(ai, config).await?;
    let mut runtime = ai.runtime().clone();
    server::serve(&mut runtime, listener, setup).await
}

/// Brings up everything and listens on a Unix socket.
///
/// # Errors
///
/// [`GarrisonErrorKind::Transport`](crate::error::GarrisonErrorKind::Transport)
/// when the socket cannot be bound, or anything [`build_ai`] and [`start`]
/// report.
pub async fn launch(
    config: &GarrisonConfig,
    socket: Option<PathBuf>,
    acton_config: Option<&Path>,
) -> Result<Garrison, GarrisonError> {
    let ai = build_ai(acton_config).await?;

    let path = socket.unwrap_or_else(|| config.server.socket.clone());
    let listener = UnixListener::bind(&path)?;
    let endpoint = listener.endpoint();

    let server = start(&ai, config, Box::new(listener)).await?;
    let runtime = ai.runtime().clone();

    Ok(Garrison {
        runtime,
        ai,
        server,
        endpoint,
    })
}

/// What this agent advertises at `initialize`.
///
/// Deliberately modest, and each `false` is a promise rather than a gap:
///
/// - **`load_session`** is true. Sessions outlive the connection that made
///   them, so an editor that reconnects gets its conversation back.
/// - **`image`, `audio`, `embedded_context`** are false. Garrison flattens a
///   prompt to text ([`crate::protocol::acp::prompt_text`]), so claiming to
///   accept an image would mean silently discarding one.
/// - **`session/list`** is advertised, scoped to the sessions the asking
///   connection holds.
///
/// A tool list is not advertised at all. ACP has no capability for one, and
/// Garrison's answer would be wrong anyway: which tools a session may use is
/// what the policy gate decides per call, not a fixed set stated at handshake.
fn capabilities() -> AgentCapabilities {
    AgentCapabilities::new()
        .load_session(true)
        .prompt_capabilities(
            PromptCapabilities::new()
                .image(false)
                .audio(false)
                .embedded_context(false),
        )
        .session_capabilities(SessionCapabilities::new().list(SessionListCapabilities::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_advertises_only_what_it_can_actually_do() {
        let advertised = capabilities();

        assert!(advertised.load_session);
        assert!(!advertised.prompt_capabilities.image);
        assert!(!advertised.prompt_capabilities.audio);
        assert!(!advertised.prompt_capabilities.embedded_context);
        assert!(advertised.session_capabilities.list.is_some());
    }

    fn ai_config(toml: &str) -> acton_ai::config::ActonAIConfig {
        acton_ai::config::from_str(toml).expect("test config must parse")
    }

    #[test]
    fn a_keyless_default_cloud_provider_is_refused_with_the_fix() {
        let config = ai_config(
            r#"
            default_provider = "claude"

            [providers.claude]
            type = "anthropic"
            model = "claude-sonnet-5"
            api_key_file = "/nonexistent/garrison-test-key"

            [providers.ollama]
            type = "ollama"
            model = "qwen3.8"
            "#,
        );

        let error = api_key_preflight(&config).expect_err("must refuse");
        assert!(error.is_configuration());
        assert!(error.to_string().contains("garrison-agent login"));
    }

    #[test]
    fn a_keyless_cloud_provider_that_is_not_the_default_is_dormant() {
        let config = ai_config(
            r#"
            default_provider = "ollama"

            [providers.claude]
            type = "anthropic"
            model = "claude-sonnet-5"
            api_key_file = "/nonexistent/garrison-test-key"

            [providers.ollama]
            type = "ollama"
            model = "qwen3.8"
            "#,
        );

        api_key_preflight(&config).expect("a local default must pass");
    }

    #[test]
    fn a_default_cloud_provider_with_a_key_file_passes() {
        let path = std::env::temp_dir().join("garrison-preflight-key-test");
        std::fs::write(&path, "sk-ant-test\n").unwrap();

        let config = ai_config(&format!(
            r#"
            [providers.claude]
            type = "anthropic"
            model = "claude-sonnet-5"
            api_key_file = "{}"
            "#,
            path.display()
        ));
        api_key_preflight(&config).expect("a keyed provider must pass");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_locked_trail_is_explained_as_a_second_daemon() {
        let upstream = "configuration error in 'audit.path': the audit trail at /x/audit.jsonl \
                        is already owned by another process (its exclusive lock is held)";
        let explained = launch_refusal(upstream);

        assert!(
            explained.starts_with(upstream),
            "the upstream text is kept verbatim"
        );
        assert!(explained.contains("one daemon per user per machine"));
        assert!(explained.contains("exit 2"));
    }

    #[test]
    fn other_launch_failures_pass_through_unchanged() {
        assert_eq!(
            launch_refusal("no provider configured"),
            "no provider configured"
        );
    }

    #[test]
    fn no_compaction_policy_is_reported_as_no_compaction() {
        assert_eq!(compaction_status(None), None);
    }

    #[test]
    fn a_configured_compaction_policy_reports_the_terms_it_applies() {
        use acton_ai::memory::{CompactionThreshold, KeepRecentTurns};

        let config = CompactionConfig::new()
            .with_threshold(CompactionThreshold::new(0.7).expect("0.7 is a fraction"))
            .with_keep_recent_turns(KeepRecentTurns::new(5).expect("five turns is not zero"));

        let status = compaction_status(Some(&config)).expect("a policy must be reported");

        assert!((status.threshold - 0.7).abs() < f64::EPSILON);
        assert_eq!(status.keep_recent_turns, 5);
    }

    #[test]
    fn no_sandbox_configuration_is_reported_as_no_isolation() {
        let status = sandbox_status(None);

        assert!(!status.enabled);
        assert!(
            status.hardening.is_none(),
            "there is no policy to name when nothing is confined"
        );
    }

    #[test]
    fn a_configured_sandbox_reports_the_terms_it_is_enforcing() {
        let status = sandbox_status(Some(
            &ProcessSandboxConfig::new()
                .with_hardening(HardeningMode::Enforce)
                .with_timeout(std::time::Duration::from_secs(90))
                .with_memory_limit(Some(512 * 1024 * 1024)),
        ));

        assert!(status.enabled);
        assert_eq!(status.hardening.as_deref(), Some("enforce"));
        assert_eq!(status.timeout_secs, Some(90));
        assert_eq!(status.memory_limit_bytes, Some(512 * 1024 * 1024));
    }

    #[test]
    fn the_shipped_config_turns_the_sandbox_on() {
        // The deployment artifact, not a fixture: a `[sandbox]` section that
        // stopped parsing would silently leave tools running in-process.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../acton-ai.toml");
        let config = acton_ai::config::from_path(std::path::Path::new(path))
            .expect("the shipped acton-ai.toml must parse");

        let sandbox = config
            .sandbox
            .expect("the shipped config configures a sandbox");
        assert_eq!(
            sandbox.hardening,
            Some(HardeningMode::BestEffort),
            "`best-effort` in TOML must resolve to the mode it names"
        );
    }

    #[test]
    fn a_sole_local_provider_needs_no_key() {
        let config = ai_config(
            r#"
            [providers.ollama]
            type = "ollama"
            model = "qwen3.8"
            "#,
        );
        api_key_preflight(&config).expect("local providers need no key");
    }
}
