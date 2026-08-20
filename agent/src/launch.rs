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
use crate::error::GarrisonError;
use crate::protocol::acp::{
    AgentCapabilities, PromptCapabilities, SessionCapabilities, SessionListCapabilities,
};
use crate::protocol::conn::ThreadDefaults;
use crate::protocol::server::{self, ServerSetup};
use crate::protocol::transport::{Listener, UnixListener};
use crate::router::TurnRouter;
use crate::thread::ThreadSupervisor;
use acton_ai::facade::ActonAI;
use acton_ai::policy::ToolPolicy;
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
    let mut builder = ActonAI::builder()
        .app_name("garrison-agent")
        .with_builtins();

    builder = match acton_config {
        Some(path) => builder.from_config_file(path).map_err(|error| {
            GarrisonError::configuration(path.display().to_string(), error.to_string())
        })?,
        None => builder
            .try_from_config()
            .map_err(|error| GarrisonError::configuration("acton-ai.toml", error.to_string()))?,
    };

    // A policy with a hook and no rules: every call reaches the hook, and the
    // hook decides whether it needs a human. Rules arrive with the prefix-rule
    // engine; until then the decision belongs entirely to Garrison's callback.
    let ai = builder
        .tool_policy(ToolPolicy::new().on_approval(approval_hook))
        .launch()
        .await
        .map_err(|error| GarrisonError::configuration("acton-ai", error.to_string()))?;

    if ai.provider_count() == 0 {
        return Err(GarrisonError::configuration(
            "providers",
            "no LLM provider is configured; add one to acton-ai.toml",
        ));
    }

    Ok(ai)
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
    let mut runtime = ai.runtime().clone();
    let router = TurnRouter::spawn(&mut runtime).await;
    let supervisor = ThreadSupervisor::spawn(&mut runtime).await;

    let project_root = match &config.threads.project_root {
        Some(root) => root.clone(),
        None => std::env::current_dir()
            .map_err(|error| GarrisonError::runtime(format!("no working directory: {error}")))?,
    };

    Ok(ServerSetup {
        supervisor,
        runtime: ai.clone(),
        router,
        defaults: ThreadDefaults {
            project_root,
            system_prompt: config.threads.system_prompt.clone(),
            approval_timeout: config.approval_timeout(),
            auto_approve: Arc::new(config.approval.auto_approve.clone()),
        },
        capabilities: capabilities(),
        audited: ai.is_audited(),
    })
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
}
