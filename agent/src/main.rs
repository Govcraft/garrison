//! The `garrison-agent` command.
//!
//! One engine and three clients of it:
//!
//! - `serve` is the engine: one daemon per user per machine, owning the
//!   acton-ai runtime, the socket, the sandbox host and the audit trail. It
//!   runs under the user's systemd (`packaging/systemd/garrison-agent.service`)
//!   or is started by the first client that needs it.
//! - `acp` speaks the Agent Client Protocol over stdin and stdout, which is
//!   the mode ACP hosts expect: the editor spawns it as a child process and
//!   talks to it over its pipes. It is a relay to the daemon's socket, not an
//!   engine of its own, so a spawned child can never become a second writer
//!   of the hash chain. A JetBrains, Zed, or Neovim ACP client needs no
//!   configuration beyond a path to this binary.
//! - `ping` performs the handshake against a running daemon and prints what
//!   came back, including Garrison's own `_garrison/status`. It never starts
//!   a daemon: "not running" is one of its answers.
//! - `chat` drives one session end to end over the socket, rendering updates as
//!   they arrive and answering permission requests at the terminal.
//!
//! See [`garrison_agent::daemon`] for the lifecycle rules and exit codes.
//!
//! # The sandbox re-exec
//!
//! acton-ai's `ProcessSandbox` re-execs this binary as its own sandbox child.
//! That check has to happen before anything else in `main`, so the child
//! dispatches its tool call and exits without ever parsing a command line.

use clap::{Parser, Subcommand};
use garrison_agent::audit;
use garrison_agent::client::{update_text, AgentClient, Interactions, Quiet};
use garrison_agent::config::{GarrisonConfig, ServerConfig};
use garrison_agent::daemon;
use garrison_agent::error::GarrisonError;
use garrison_agent::launch;
use garrison_agent::protocol::acp;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

/// A governed agentic coding engine.
#[derive(Debug, Parser)]
#[command(name = "garrison-agent", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Relays ACP between stdin/stdout and the daemon. The mode editors spawn.
    ///
    /// Connects to the per-user daemon's socket and starts the daemon first
    /// when none is running and `[server].autostart` allows. The daemon's
    /// configuration is the one in force; the flags here only tell the relay
    /// where the socket is.
    Acp {
        /// The daemon's socket. Overrides the config file.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Garrison's own config file, read for `[server]` only.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Accepted for compatibility and ignored: the relay runs no engine.
        #[arg(long)]
        acton_config: Option<PathBuf>,
    },
    /// Runs the engine: one daemon per user, serving ACP on a Unix socket.
    ///
    /// Exits 2 when it refuses to start (a locked or broken audit trail, a
    /// configuration it will not accept, a control plane that turned this
    /// install away), 3 on a rejection, 1 on a malfunction.
    Serve {
        /// The Unix socket to listen on. Overrides the config file.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Garrison's own config file. Defaults to the usual search path.
        #[arg(long)]
        config: Option<PathBuf>,
        /// acton-ai's config file. Defaults to the usual search path.
        #[arg(long)]
        acton_config: Option<PathBuf>,
    },
    /// Performs the handshake against a running daemon and prints the result.
    Ping {
        /// The socket to connect to.
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Signs in to a model provider and stores its API key.
    ///
    /// `openai` runs an OAuth sign-in in the browser with the OpenAI
    /// account and mints a platform API key; `anthropic` walks through
    /// pasting a Console key, because Anthropic reserves subscription
    /// OAuth for Claude Code itself. Either way the key is validated
    /// against the live API and stored under ~/.config/garrison/ with
    /// mode 0600.
    Login {
        /// Which provider to sign in to.
        #[arg(value_enum)]
        provider: ProviderArg,
        /// Read an API key from standard input instead of the normal flow.
        /// Made for `rbw get openai | garrison-agent login openai --key-stdin`.
        #[arg(long)]
        key_stdin: bool,
    },
    /// Removes a provider's stored API key.
    Logout {
        /// Which provider's key to remove.
        #[arg(value_enum)]
        provider: ProviderArg,
    },
    /// Inspects the audit trail this install writes.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Talks to a running daemon.
    Chat {
        /// The socket to connect to.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Say one thing, print the answer, and exit.
        ///
        /// Without it the chat is interactive. With it there is no terminal to
        /// approve anything at, so a session that would need a permission
        /// wants `--approve-all` as well.
        #[arg(long)]
        message: Option<String>,
        /// Approve every tool call without asking at the terminal.
        #[arg(long)]
        approve_all: bool,
    },
    /// Reviews a Bitbucket pull request and reports what it found.
    ///
    /// The unattended mode: no terminal, no approvals, no writes. Exits 0 when
    /// the review ran (whatever it found), 3 when `--enforce` is set and a
    /// blocker was found, 1 when the review did not happen. That last one is
    /// not excused by advisory mode: a run that could not read its own answer
    /// must not report a pass.
    ///
    /// The Bitbucket credential is read from `GARRISON_BITBUCKET_TOKEN` and is
    /// deliberately not a flag. A token in argv is readable by every process
    /// on the runner and lands in the pipeline log.
    Review {
        /// The socket to connect to.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// The Bitbucket Data Center base URL, e.g. `https://bitbucket.agency.gov`.
        #[arg(long)]
        bitbucket: String,
        /// Which pull request, as `PROJECT/REPO/ID`.
        #[arg(long)]
        pull_request: String,
        /// Post findings to the pull request instead of only printing them.
        ///
        /// Without it the run is a dry run: it reviews, prints, and touches
        /// nothing. That is the right default for the first time anyone points
        /// this at a repository they care about.
        #[arg(long)]
        post: bool,
        /// Let a blocker-severity finding fail the build.
        ///
        /// Off by default. Failing a build on a model's opinion is a strong
        /// claim, and a team should watch the reviewer for a while before
        /// letting it make one.
        #[arg(long)]
        enforce: bool,
        /// The commit to record a build status against.
        ///
        /// Without it no status is posted. The pull request still gets the
        /// comments; it just does not get a pass/fail mark.
        #[arg(long)]
        commit: Option<String>,
        /// Where a human goes to read this run, recorded on the build status.
        #[arg(long)]
        run_url: Option<String>,
        /// How many unchanged lines to show either side of each change.
        #[arg(long, default_value_t = 10)]
        context: u32,
        /// How long to wait for the audit trail to reach the control plane.
        ///
        /// A CI runner is deleted minutes after the review ends, so an entry
        /// still in its buffer is destroyed evidence rather than delayed
        /// evidence. The run waits for the plane to accept the trail before
        /// exiting, and says so when it could not.
        #[arg(long, default_value_t = 30)]
        audit_timeout: u64,
        /// Exit successfully even when the trail did not reach the plane.
        ///
        /// For running this from a workstation, where the trail file survives
        /// and ships later. On an ephemeral runner it turns "no evidence this
        /// review happened" into a green check, which is the failure the
        /// default exists to prevent.
        #[arg(long)]
        allow_unshipped_audit: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Walks the chain, then measures it against the anchor.
    ///
    /// Two questions with two answers. Exit 3 means the chain does not hang
    /// together: an entry was rewritten or one was inserted. Exit 4 means it
    /// hangs together perfectly and no longer ends where the anchor says it
    /// ended, which is what deleting the tail of a trail looks like and is
    /// the one thing the chain cannot notice about itself. Exit 0 means
    /// neither. Reads files only: it never talks to the daemon, so it works
    /// on a trail copied off the machine.
    Verify {
        /// The trail to read. Defaults to the one acton-ai.toml arms.
        #[arg(long)]
        file: Option<PathBuf>,
        /// The anchor to measure against. Defaults to `[audit] anchor_path`.
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// Garrison's own config file, read for `[audit]`.
        #[arg(long)]
        config: Option<PathBuf>,
        /// acton-ai's config file, read for the trail's path.
        #[arg(long)]
        acton_config: Option<PathBuf>,
        /// Print the finding as JSON rather than as lines.
        #[arg(long)]
        json: bool,
    },
}

/// Which cloud provider a login or logout addresses.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ProviderArg {
    /// Anthropic (Claude models): paste a Console API key.
    Anthropic,
    /// OpenAI (GPT models): OAuth sign-in in the browser.
    Openai,
    /// Groq (OpenAI‑compatible models): paste a Console API key.
    Groq,
}

impl From<ProviderArg> for garrison_agent::auth::Provider {
    fn from(arg: ProviderArg) -> Self {
        match arg {
            ProviderArg::Anthropic => Self::Anthropic,
            ProviderArg::Openai => Self::OpenAI,
            ProviderArg::Groq => Self::Groq,
        }
    }
}

/// Where this invocation's log lines go.
enum Logs {
    /// The usual place. Never stdout: stdout is the protocol in `acp` mode.
    Stderr,
    /// A file, because something else owns the screen.
    File(std::sync::Arc<std::fs::File>),
    /// Nowhere, because something else owns the screen and no file opened.
    Nowhere,
}

/// Decides where logs may be written without wrecking anything.
///
/// The interactive chat paints a pinned viewport with escape sequences and
/// tracks where the cursor is. A log line arriving on stderr in the middle of
/// that does not merely look untidy: it scrolls the screen out from under the
/// viewport. So while the chat owns the terminal, logs go to a file, and if no
/// file can be opened they go nowhere at all.
fn destination(cli: &Cli) -> Logs {
    if !matches!(cli.command, Command::Chat { message: None, .. }) {
        return Logs::Stderr;
    }

    match daemon::log_path("chat.log").and_then(|path| {
        std::fs::create_dir_all(path.parent()?).ok()?;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
    }) {
        Some(file) => Logs::File(std::sync::Arc::new(file)),
        None => Logs::Nowhere,
    }
}

/// The process entry point, which is deliberately not `#[tokio::main]`.
///
/// acton-ai's sandbox child re-execs this binary and dispatches its tool call
/// on a current-thread runtime it builds itself. Building a runtime inside a
/// runtime panics, so the check has to run before any runtime exists — which
/// means before the attribute macro would have started one.
fn main() -> ExitCode {
    // A build that claims FIPS-validated cryptography puts the validated
    // module in place as the process-wide rustls provider before anything can
    // open a connection, and refuses to start if the module reports it is not
    // operating in FIPS mode. This runs ahead of the sandbox re-exec check so
    // the sandbox child gets the same provider the parent does. On a non-FIPS
    // build the call is a no-op, so the call site needs no `cfg` of its own.
    //
    // It is not the only caller. Every place this crate builds a `reqwest`
    // client installs the provider too, because a FIPS build asks reqwest not
    // to install one of its own and `build()` panics rather than erroring when
    // it finds none. See [`garrison_agent::crypto`]. This one stays because it
    // is the earliest point at which the refusal can still be an exit code.
    if let Err(error) = garrison_agent::crypto::ensure_provider() {
        eprintln!("garrison-agent: {error}");
        return ExitCode::from(daemon::exit_code(&error));
    }
    acton_ai::tools::sandbox::process::runner::run_if_sandbox_child();
    serve_command_line()
}

/// Everything the agent does when it was not re-exec'd as a sandbox child.
#[tokio::main]
async fn serve_command_line() -> ExitCode {
    let cli = Cli::parse();
    let logs = destination(&cli);
    let builder = tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    );

    match logs {
        Logs::Stderr => builder.with_writer(std::io::stderr).init(),
        Logs::File(file) => builder.with_ansi(false).with_writer(file).init(),
        Logs::Nowhere => builder.with_writer(std::io::sink).init(),
    }

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("garrison-agent: {error}");
            // A refusal to start (2) and a deliberate rejection (3) are not
            // malfunctions (1): a supervisor must not retry the first two,
            // and a caller scripting against this can tell them apart.
            ExitCode::from(daemon::exit_code(&error))
        }
    }
}

/// Dispatches one invocation.
async fn run(cli: Cli) -> Result<(), GarrisonError> {
    match cli.command {
        Command::Acp {
            socket,
            config,
            acton_config,
        } => acp_relay(socket, config, acton_config.is_some()).await,
        Command::Serve {
            socket,
            config,
            acton_config,
        } => serve(socket, config, acton_config).await,
        Command::Ping { socket } => ping(socket).await,
        Command::Login {
            provider,
            key_stdin,
        } => garrison_agent::auth::login(provider.into(), key_stdin).await,
        Command::Logout { provider } => garrison_agent::auth::logout(provider.into()),
        Command::Audit {
            command:
                AuditCommand::Verify {
                    file,
                    anchor,
                    config,
                    acton_config,
                    json,
                },
        } => audit_verify(file, anchor, config, acton_config, json),
        Command::Chat {
            socket,
            message,
            approve_all,
        } => chat(socket, message, approve_all).await,
        Command::Review {
            socket,
            bitbucket,
            pull_request,
            post,
            enforce,
            commit,
            run_url,
            context,
            audit_timeout,
            allow_unshipped_audit,
        } => {
            review(ReviewRun {
                socket,
                bitbucket,
                pull_request,
                post,
                enforce,
                commit,
                run_url,
                context,
                audit_timeout,
                allow_unshipped_audit,
            })
            .await
        }
    }
}

/// `audit verify`: read the trail, read the anchor, report both.
///
/// The finding is printed either way — an operator triaging a truncation
/// needs the numbers, not just an exit status — and only then does the
/// non-zero outcome become an error, so the report always reaches the screen
/// before the process ends.
fn audit_verify(
    file: Option<PathBuf>,
    anchor: Option<PathBuf>,
    config: Option<PathBuf>,
    acton_config: Option<PathBuf>,
    json: bool,
) -> Result<(), GarrisonError> {
    let garrison = load_config(config)?;
    let trail = match file {
        Some(path) => path,
        None => audit::verify::configured_trail(acton_config.as_deref()).ok_or_else(|| {
            GarrisonError::configuration(
                "audit",
                "no audit trail is armed: acton-ai.toml has no [audit] section, so there is \
                 nothing to verify. Name one with --file",
            )
        })?,
    };
    let anchor_path = anchor.unwrap_or_else(|| garrison.audit.anchor_path());

    let report = audit::verify::run(&trail, &anchor_path)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| GarrisonError::runtime(error.to_string()))?
        );
    } else {
        println!("{}", audit::verify::render(&report));
    }

    audit::verify::refusal(&report).map_or(Ok(()), Err)
}

/// Loads Garrison's config from the named file, or the search path.
fn load_config(path: Option<PathBuf>) -> Result<GarrisonConfig, GarrisonError> {
    match path {
        Some(path) => GarrisonConfig::from_file(&path),
        None => GarrisonConfig::load(),
    }
}

/// Resolves where a client talks to: the argument, else the configured
/// socket, together with the `[server]` rules for a daemon that is not there.
fn client_target(
    socket: Option<PathBuf>,
    config: Option<PathBuf>,
) -> Result<(ServerConfig, PathBuf), GarrisonError> {
    let server = load_config(config)?.server;
    let path = socket.unwrap_or_else(|| server.socket.clone());
    Ok((server, path))
}

/// `acp`: a relay between this process's pipes and the daemon's socket.
///
/// No `ActonAI` is ever built here. The daemon's configuration governs the
/// session; `--config` is read only for `[server]`, and `--acton-config` is
/// accepted so existing hosts keep working, then ignored with a warning.
async fn acp_relay(
    socket: Option<PathBuf>,
    config: Option<PathBuf>,
    acton_config_given: bool,
) -> Result<(), GarrisonError> {
    if acton_config_given {
        tracing::warn!(
            "--acton-config is ignored by `acp`: the relay runs no engine, and the daemon's \
             configuration is in force"
        );
    }
    let (server, path) = client_target(socket, config)?;
    let stream = daemon::connect_or_start(&server, &path).await?;

    tracing::info!(socket = %path.display(), "relaying ACP between stdio and the daemon");
    daemon::relay(stream, tokio::io::stdin(), tokio::io::stdout())
        .await
        .map_err(|error| {
            GarrisonError::transport(path.display().to_string(), format!("relay failed: {error}"))
        })
}

/// `serve`: run until interrupted or asked to stop.
///
/// Tells systemd when it is ready and when it begins stopping, both no-ops
/// without `$NOTIFY_SOCKET`, so `Type=notify` in the unit means "the socket
/// is accepting" rather than "the process exists".
async fn serve(
    socket: Option<PathBuf>,
    config: Option<PathBuf>,
    acton_config: Option<PathBuf>,
) -> Result<(), GarrisonError> {
    let config = load_config(config)?;
    let garrison = launch::launch(&config, socket, acton_config.as_deref()).await?;

    println!("garrison-agent listening on {}", garrison.endpoint);
    acton_ai::introspection::sd_notify::notify_ready();

    wait_for_stop().await?;

    println!("shutting down");
    acton_ai::introspection::sd_notify::notify_stopping();
    garrison.shutdown().await
}

/// Resolves on `SIGINT` or `SIGTERM`, whichever comes first.
///
/// `SIGTERM` is what systemd sends on `stop`; without listening for it the
/// daemon would be killed after `TimeoutStopSec` instead of shutting its
/// actors down and unlinking its socket.
async fn wait_for_stop() -> Result<(), GarrisonError> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| {
        GarrisonError::runtime(format!("could not listen for SIGTERM: {error}"))
    })?;

    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map_err(|error| {
            GarrisonError::runtime(format!("could not wait for a signal: {error}"))
        }),
        _ = terminate.recv() => Ok(()),
    }
}

/// `ping`: handshake, then ask Garrison what it is enforcing.
///
/// Never starts a daemon. A probe that brought the thing it was probing into
/// existence would have nothing truthful to report.
async fn ping(socket: Option<PathBuf>) -> Result<(), GarrisonError> {
    let (_server, path) = client_target(socket, None)?;
    let mut client = AgentClient::from_stream(daemon::connect(&path).await?);
    let handshake = client.initialize("garrison-agent ping").await?;

    let agent = handshake.agent_info.as_ref().map_or_else(
        || "unnamed".to_string(),
        |info| format!("{} {}", info.name, info.version),
    );

    println!("connected to {}", path.display());
    println!("  agent:      {agent}");
    println!("  acp:        {}", handshake.protocol_version.as_u16());
    println!(
        "  sessions:   load={} list={}",
        handshake.agent_capabilities.load_session,
        handshake
            .agent_capabilities
            .session_capabilities
            .list
            .is_some(),
    );

    let status: acp::GarrisonStatus = client
        .request(acp::ext::STATUS, &serde_json::json!({}), &mut Quiet)
        .await?;

    println!(
        "  policy:     timeout={}s auto-approve=[{}]",
        status.policy.approval_timeout_secs,
        status.policy.auto_approve.join(", "),
    );
    if let Some(entitlement) = status.entitlement.as_ref() {
        println!("  seat:       {}", seat_line(entitlement));
    }
    for line in governance_lines(status.policy.governance.as_ref()) {
        println!("{line}");
    }
    println!("  audit:      {}", audit_line(&status.audit));
    println!(
        "  sandbox:    {}",
        if status.sandbox.enabled {
            status
                .sandbox
                .hardening
                .as_deref()
                .map_or_else(|| "on".to_string(), |mode| format!("on ({mode})"))
        } else {
            "off (tools run in-process)".to_string()
        },
    );

    Ok(())
}

/// The seat summary `ping` prints, in one line. Pure.
///
/// The state comes first because it is the word an operator triages on, and
/// the reason comes last because it is the sentence they act on. A refusal
/// prints its whole explanation: `ping` is where somebody looks when every
/// prompt is failing, and truncating the answer there would send them to the
/// logs for no reason.
fn seat_line(status: &acp::EntitlementStatus) -> String {
    let mut line = status.state.clone();

    if let Some(tier) = status.tier.as_deref() {
        line.push_str(&format!(" ({tier})"));
    }
    if let Some(checked) = status.checked_at.as_deref() {
        line.push_str(&format!(" checked={checked}"));
    }
    if let Some(until) = status.grace_until.as_deref() {
        line.push_str(&format!(" grace_until={until}"));
    }
    line.push_str(&format!(" every={}s", status.check_interval_secs));
    if let Some(error) = status.last_error.as_deref() {
        line.push_str(&format!(" last_error={error}"));
    }
    if let Some(reason) = status.reason.as_deref() {
        line.push_str(&format!("\n              {reason}"));
    }

    line
}

/// What `ping` prints about the policy in force. Pure.
///
/// Three things an operator needs and one they are owed. The state, so they
/// know whether this machine is governed at all; the bundle's identity and
/// checksum, so they can say which policy it is running; and the reason, when
/// there is none, because "refused" without a reason is what makes people
/// disable governance. The one they are owed is the "not enforced" line: those
/// bundle fields are part of the published policy and part of its checksum,
/// and this release does not act on them. Saying nothing would let an author
/// believe otherwise.
fn governance_lines(status: Option<&acp::GovernanceStatus>) -> Vec<String> {
    let Some(status) = status else {
        return vec!["  governance: not reported (the policy agent did not answer)".to_string()];
    };

    let mut lines = vec![format!("  governance: {}", status.state)];

    if let Some(bundle) = status.bundle.as_ref() {
        let checksum = &bundle.checksum[..bundle.checksum.len().min(12)];
        lines.push(format!(
            "  bundle:     {} v{} {} (from {}, fetched {})",
            bundle.name, bundle.version, checksum, bundle.source, bundle.fetched_at,
        ));
    }
    if let Some(reason) = status.reason.as_deref() {
        lines.push(format!("  reason:     {reason}"));
    }
    if !status.approved_providers.is_empty() {
        lines.push(format!(
            "  providers:  approved=[{}] default={}",
            status.approved_providers.join(", "),
            status.default_provider.as_deref().unwrap_or("none"),
        ));
    }
    if status.local_auto_approve_ignored {
        lines.push(
            "  note:       [approval].auto_approve in garrison.toml is ignored while this \
             install is governed"
                .to_string(),
        );
    }
    if !status.not_enforced.is_empty() {
        lines.push(format!(
            "  note:       recorded in the bundle and NOT enforced by this release: {}",
            status.not_enforced.join(", "),
        ));
    }

    lines
}

/// The audit summary `ping` prints, in one line. Pure.
///
/// The state comes first because it is the word an operator triages on, and
/// the anchor's sequence comes last because a head that has run away from its
/// anchor is the thing worth noticing once the state itself looks fine.
fn audit_line(status: &acp::AuditStatus) -> String {
    let mut line = status.state.to_string();

    if let Some(durability) = status.durability.as_deref() {
        line.push_str(&format!(" ({durability})"));
    }
    if let (Some(sequence), Some(hash)) = (status.sequence, status.chain_head.as_deref()) {
        line.push_str(&format!(" head={sequence}/{}", &hash[..hash.len().min(8)]));
    }
    if status.failures > 0 {
        line.push_str(&format!(" failures={}", status.failures));
        if let Some(error) = status.last_error.as_deref() {
            line.push_str(&format!(" last_error={error}"));
        }
    }
    if let Some(anchor) = status.anchor.as_ref() {
        match anchor.sequence {
            Some(sequence) => line.push_str(&format!(" anchor={sequence}")),
            None => line.push_str(" anchor=none"),
        }
        if let Some(error) = anchor.last_error.as_deref() {
            line.push_str(&format!(" anchor_error={error}"));
        }
    }

    line
}

/// The smoke client's reactions: print what arrives, ask before every tool.
struct Terminal {
    approve_all: bool,
    tool_titles: std::collections::HashMap<String, String>,
}

impl Interactions for Terminal {
    fn update(&mut self, notification: &acp::SessionNotification) {
        match &notification.update {
            acp::SessionUpdate::ToolCall(call) => {
                self.tool_titles
                    .insert(call.tool_call_id.to_string(), call.title.clone());
                println!("\n  [tool {} started]", call.title);
            }
            acp::SessionUpdate::ToolCallUpdate(update) => {
                if let Some(status) = update.fields.status {
                    let id = update.tool_call_id.to_string();
                    let name = self.tool_titles.get(&id).cloned().unwrap_or(id);
                    println!("  [tool {name}: {status:?}]");
                }
            }
            _ => {
                if let Some(text) = update_text(notification) {
                    print!("{text}");
                    let _ = std::io::stdout().flush();
                }
            }
        }
    }

    fn permission(
        &mut self,
        request: &acp::RequestPermissionRequest,
    ) -> acp::RequestPermissionOutcome {
        let option = if self.approve_all {
            acp::OPTION_ALLOW_ONCE
        } else {
            ask_terminal(request)
        };

        acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(option))
    }
}

/// Reads a decision from the terminal.
///
/// Anything other than an explicit yes refuses. A prompt whose default is
/// "allow" is not a gate.
fn ask_terminal(request: &acp::RequestPermissionRequest) -> &'static str {
    let tool = request
        .tool_call
        .fields
        .title
        .as_deref()
        .unwrap_or("a tool");
    let arguments = request
        .tool_call
        .fields
        .raw_input
        .clone()
        .unwrap_or(serde_json::Value::Null);

    println!("\n  approve {tool} with {arguments}? [y/N] ");
    let _ = std::io::stdout().flush();

    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return acp::OPTION_REJECT;
    }

    if answer.trim().eq_ignore_ascii_case("y") {
        acp::OPTION_ALLOW_ONCE
    } else {
        acp::OPTION_REJECT
    }
}

/// `chat`: one session, one turn, rendered as it happens.
async fn chat(
    socket: Option<PathBuf>,
    message: Option<String>,
    approve_all: bool,
) -> Result<(), GarrisonError> {
    let (server, path) = client_target(socket, None)?;
    let stream = daemon::connect_or_start(&server, &path).await?;
    let Some(message) = message else {
        let cwd = std::env::current_dir()
            .map_err(|error| GarrisonError::runtime(format!("no working directory: {error}")))?;
        return garrison_agent::tui::run(stream, cwd, approve_all).await;
    };

    let mut client = AgentClient::from_stream(stream);
    client.initialize("garrison-agent chat").await?;

    let cwd = std::env::current_dir()
        .map_err(|error| GarrisonError::runtime(format!("no working directory: {error}")))?;
    let session = client.new_session(cwd).await?;
    println!("session {}", session.session_id);

    let mut terminal = Terminal {
        approve_all,
        tool_titles: std::collections::HashMap::new(),
    };
    let response = client
        .prompt(session.session_id, &message, &mut terminal)
        .await?;

    println!("\n[{:?}]", response.stop_reason);
    Ok(())
}

/// Everything one `review` invocation was told.
///
/// A struct rather than eight positional arguments, because a call site that
/// reads `review(socket, url, pr, true, false, commit, None, 10)` is one
/// transposition away from enforcing when it meant to post.
struct ReviewRun {
    socket: Option<PathBuf>,
    bitbucket: String,
    pull_request: String,
    post: bool,
    enforce: bool,
    commit: Option<String>,
    run_url: Option<String>,
    context: u32,
    audit_timeout: u64,
    allow_unshipped_audit: bool,
}

/// The environment variable carrying the Bitbucket credential.
///
/// Not a flag, and not read from the config file. A flag lands in `ps` output
/// and in the pipeline's own log of the command it ran; a config file is a
/// standing secret on a runner that should not keep one.
const TOKEN_VAR: &str = "GARRISON_BITBUCKET_TOKEN";

/// The identity a build status is recorded under.
///
/// Bitbucket dedupes on this, so re-running a pipeline replaces the previous
/// status rather than stacking another one beside it.
const STATUS_KEY: &str = "garrison-review";

/// `review`: read a pull request, say what is wrong with it, exit accordingly.
///
/// The order matters and is not arbitrary. The diff is fetched before the
/// daemon is contacted, so a bad pull request reference or a rejected token
/// fails in a second rather than after a model has been paid to read nothing.
async fn review(run: ReviewRun) -> Result<(), GarrisonError> {
    use garrison_agent::review::{self, Blocking};

    gate_experimental()?;

    let target = garrison_bitbucket::PullRequest::parse(&run.pull_request)
        .map_err(|reason| GarrisonError::configuration("--pull-request", reason))?;

    let token = std::env::var(TOKEN_VAR).map_err(|_| {
        GarrisonError::configuration(
            TOKEN_VAR,
            "no Bitbucket credential in the environment; review mode reads one \
             from this variable rather than a flag, so it cannot leak into the \
             pipeline log",
        )
    })?;

    let bitbucket = garrison_bitbucket::Client::new(
        &run.bitbucket,
        garrison_bitbucket::Credentials::Bearer(token),
    )
    .map_err(|error| GarrisonError::configuration("--bitbucket", error.to_string()))?;

    let blocking = if run.enforce {
        Blocking::Enforcing
    } else {
        Blocking::Advisory
    };

    let files = bitbucket
        .pull_request_diff(&target, run.context)
        .await
        .map_err(|error| GarrisonError::runtime(format!("could not read the diff: {error}")))?;

    let withheld = files.iter().filter(|file| file.truncated).count();
    println!(
        "reviewing {} ({} file(s){})",
        run.pull_request,
        files.len(),
        if withheld == 0 {
            String::new()
        } else {
            // Said up front, because a run that reviewed nine of ten files
            // must not be read as having reviewed the pull request.
            format!(", {withheld} withheld by the server and not reviewed")
        }
    );

    let outcome = if files.is_empty() {
        // Nothing to look at is not the same as nothing wrong, but it is not a
        // failure either: a pull request can legitimately change no files.
        println!("the diff is empty; there is nothing to review");
        review::Outcome::Clean
    } else {
        let answer = ask(&run, &files).await?;
        let parsed = review::parse_findings(&answer);
        let outcome = review::decide(&parsed, blocking);

        report(&parsed, &files, blocking, run.post);
        if run.post {
            publish(&bitbucket, &target, parsed.findings(), &files, blocking).await;
        }
        outcome
    };

    // Drain before the status is posted, so the status can report on the
    // evidence as well as the findings. A pull request marked green by a run
    // whose trail died with the container would be the exact claim Garrison
    // exists not to make.
    let evidence = drain_audit(&run).await;
    let audit_failure = match &evidence {
        Evidence::Shipped(through) => {
            println!("the audit trail reached the plane through entry {through}");
            None
        }
        Evidence::NotShipping => {
            // Not an error here. A standalone install legitimately ships
            // nothing, and this binary cannot tell that apart from a
            // misconfigured runner. Said out loud so the difference is the
            // operator's to notice rather than nobody's.
            println!(
                "this install ships no audit trail, so this review left evidence \
                 only on the machine that ran it"
            );
            None
        }
        Evidence::Missing(reason) => Some(reason.clone()),
    };

    if let Some(reason) = &audit_failure {
        eprintln!("the audit trail did not leave this machine: {reason}");
    }

    if let (Some(commit), true) = (run.commit.as_ref(), run.post) {
        // A status is only posted when posting is on. A dry run that marked
        // the pull request would not be a dry run.
        let status = garrison_bitbucket::BuildStatus {
            key: STATUS_KEY.to_string(),
            state: if audit_failure.is_some() {
                garrison_bitbucket::BuildState::Failed
            } else {
                outcome.build_state()
            },
            url: run
                .run_url
                .clone()
                .unwrap_or_else(|| "https://garrison.local/review".to_string()),
            name: "Garrison review".to_string(),
            description: audit_failure.as_ref().map_or_else(
                || outcome.description(),
                |reason| format!("{} (audit not shipped: {reason})", outcome.description()),
            ),
        };
        if let Err(error) = bitbucket.set_build_status(commit, &status).await {
            // Not fatal on its own: the comments already landed, and losing
            // the status should not turn a completed review into a failed run.
            eprintln!("the build status could not be recorded: {error}");
        }
    }

    println!("\n{}", outcome.description());

    // Order matters. A blocked review is reported ahead of a missing trail,
    // because a developer with a blocker to fix should be sent to the blocker
    // first; the shipping failure is still printed above either way.
    match outcome {
        review::Outcome::Blocked { .. } => {
            Err(GarrisonError::review_blocked(outcome.description()))
        }
        review::Outcome::Failed { reason } => Err(GarrisonError::turn_failed(reason)),
        review::Outcome::Clean | review::Outcome::Advised { .. } => match audit_failure {
            // The default. A review nobody can prove happened is not a review
            // that passed, and on a runner that is about to be deleted there
            // is no later attempt that fixes it.
            Some(reason) if !run.allow_unshipped_audit => {
                Err(GarrisonError::audit_unshipped(reason))
            }
            Some(reason) => {
                println!("continuing anyway, because --allow-unshipped-audit was given: {reason}");
                Ok(())
            }
            None => Ok(()),
        },
    }
}

/// Runs the one turn that does the reviewing.
///
/// Uses the default [`Interactions`] implementation, which refuses every
/// permission request. That is review mode's whole posture and it is inherited
/// rather than configured: there is no flag here that could turn it off.
async fn ask(
    run: &ReviewRun,
    files: &[garrison_bitbucket::ChangedFile],
) -> Result<String, GarrisonError> {
    use garrison_agent::review::ReviewFile;

    let reviewable: Vec<ReviewFile> = files
        .iter()
        .map(|file| ReviewFile {
            path: file.path.clone(),
            text: file.destination_text(),
            truncated: file.truncated,
        })
        .collect();

    let prompt = garrison_agent::review::build_prompt(&reviewable);

    let (server, path) = client_target(run.socket.clone(), None)?;
    let stream = daemon::connect_or_start(&server, &path).await?;
    let mut client = AgentClient::from_stream(stream);
    client.initialize("garrison-agent review").await?;

    let cwd = std::env::current_dir()
        .map_err(|error| GarrisonError::runtime(format!("no working directory: {error}")))?;
    let session = client.new_session(cwd).await?;

    let mut collected = Answer::default();
    client
        .prompt(session.session_id, &prompt, &mut collected)
        .await?;
    Ok(collected.text)
}

/// Accumulates the model's answer, and refuses everything else.
///
/// The refusal is not implemented here: it is [`Interactions`]'s default, and
/// inheriting it rather than writing one is deliberate. A hand-written
/// `permission` in review mode would be a place where someone could later add
/// an exception.
#[derive(Default)]
struct Answer {
    text: String,
}

impl Interactions for Answer {
    fn update(&mut self, notification: &acp::SessionNotification) {
        if let Some(chunk) = update_text(notification) {
            self.text.push_str(chunk);
        }
    }
}

/// Prints what was found, whether or not it is being posted.
///
/// A pipeline log is the only place some of this is ever read, so it carries
/// the same information the comments would.
fn report(
    review: &garrison_agent::review::Review,
    files: &[garrison_bitbucket::ChangedFile],
    blocking: garrison_agent::review::Blocking,
    posting: bool,
) {
    let placed = garrison_agent::review::place(review.findings(), files, blocking);

    for (finding, placement) in review.findings().iter().zip(&placed) {
        let where_ = if placement.anchored {
            format!("{}:{}", finding.file, finding.line)
        } else {
            format!("{} (could not be anchored)", finding.file)
        };
        println!(
            "  [{}] {where_} — {}",
            finding.severity.as_str(),
            finding.message
        );
    }

    let unanchored = placed.iter().filter(|entry| !entry.anchored).count();
    if unanchored > 0 {
        // Worth saying out loud: a review where several findings would not
        // anchor is one whose line numbers should be distrusted.
        println!(
            "\n{unanchored} finding(s) named a line not present in the diff and \
             will appear on the pull request rather than inline"
        );
    }

    if !posting && !review.findings().is_empty() {
        println!("\n(dry run: nothing was posted; pass --post to send these)");
    }
}

/// Sends the comments, one at a time, surviving individual refusals.
async fn publish(
    bitbucket: &garrison_bitbucket::Client,
    target: &garrison_bitbucket::PullRequest,
    findings: &[garrison_agent::review::Finding],
    files: &[garrison_bitbucket::ChangedFile],
    blocking: garrison_agent::review::Blocking,
) {
    let placed = garrison_agent::review::place(findings, files, blocking);
    let mut posted = 0_usize;
    let mut refused = 0_usize;

    for entry in &placed {
        match bitbucket.post_comment(target, &entry.comment).await {
            Ok(()) => posted += 1,
            Err(error) if error.is_fatal() => {
                // The credential died mid-run. Every later call uses it too,
                // so continuing would post nothing and take a minute doing so.
                eprintln!("posting stopped: {error}");
                break;
            }
            Err(error) => {
                refused += 1;
                eprintln!("one comment was refused and the rest continue: {error}");
            }
        }
    }

    println!("\nposted {posted} comment(s)");
    if refused > 0 {
        println!("{refused} were refused by Bitbucket and are above in this log");
    }
}

/// What the drain came to, once the polling stopped.
enum Evidence {
    /// The plane accepted the trail through this sequence.
    Shipped(u64),
    /// It did not, and this is why.
    Missing(String),
    /// This install does not ship at all.
    NotShipping,
}

/// Waits for the audit trail to reach the control plane before the machine
/// that wrote it stops existing.
///
/// This is the whole reason a CI review differs from a workstation one. The
/// shipping policy elsewhere in this binary is built on the trail file being a
/// durable buffer, which is true of a laptop and false of a container that is
/// deleted when the pipeline step ends. Waiting here is what turns "the entry
/// is queued" into "the entry is evidence".
async fn drain_audit(run: &ReviewRun) -> Evidence {
    use garrison_agent::shipping::drain::{self, Progress, Step};

    let deadline = std::time::Duration::from_secs(run.audit_timeout);
    let started = std::time::Instant::now();

    let (_server, path) = match client_target(run.socket.clone(), None) {
        Ok(target) => target,
        Err(error) => {
            return Evidence::Missing(format!("the daemon could not be located: {error}"))
        }
    };

    let stream = match daemon::connect(&path).await {
        Ok(stream) => stream,
        // Not fatal to reach for: the daemon may have exited with the runner.
        // But it does mean nobody can say whether the trail left, which is
        // exactly the thing this function exists to establish.
        Err(error) => {
            return Evidence::Missing(format!(
                "the daemon could not be reached to confirm shipping: {error}"
            ))
        }
    };

    let mut client = AgentClient::from_stream(stream);
    if let Err(error) = client.initialize("garrison-agent review drain").await {
        return Evidence::Missing(format!("the daemon would not answer: {error}"));
    }

    let mut progress = Progress::default();

    loop {
        let status: acp::GarrisonStatus = match client
            .request(acp::ext::STATUS, &serde_json::json!({}), &mut Quiet)
            .await
        {
            Ok(status) => status,
            Err(error) => {
                return Evidence::Missing(format!("the status could not be read: {error}"))
            }
        };

        let Some(shipping) = status.shipping else {
            // No shipping section at all. Reported as "not shipping" rather
            // than as a failure, because the caller is the one that knows
            // whether that is a configuration choice or a governance hole.
            return Evidence::NotShipping;
        };

        match drain::step(&shipping, progress, started.elapsed(), deadline) {
            Step::Complete { shipped_through } => return Evidence::Shipped(shipped_through),
            Step::NotShipping => return Evidence::NotShipping,
            Step::Halted { reason } => {
                return Evidence::Missing(format!("shipping has halted: {reason}"))
            }
            Step::Expired { backlog } => {
                return Evidence::Missing(format!(
                    "{backlog} entr(ies) were still unshipped after {}s",
                    run.audit_timeout
                ))
            }
            Step::Waiting { next_poll, .. } => {
                progress = Progress::observing(shipping.local_head);
                tokio::time::sleep(next_poll).await;
            }
        }
    }
}

/// Refuses unless review mode has been switched on deliberately.
///
/// Checked before the pull request reference, the credential, or anything
/// else, so that "this is experimental" is the first thing an operator learns
/// rather than the fourth. The config file is read directly rather than asked
/// of the daemon: the gate has to answer even when no daemon is running, and a
/// feature that could be enabled by whichever daemon happened to be up would
/// not be a decision anyone made.
fn gate_experimental() -> Result<(), GarrisonError> {
    use garrison_agent::experimental::{self, Feature};

    let config = GarrisonConfig::load()
        .map(|config| config.experimental)
        .unwrap_or_default();

    let env = std::env::var(experimental::ENV_VAR).ok();

    if experimental::enabled(config, env.as_deref(), Feature::Review) {
        eprintln!("{}", experimental::notice(Feature::Review));
        return Ok(());
    }

    // A refusal to start rather than a malfunction: nothing is broken, and a
    // supervisor must not retry it.
    Err(GarrisonError::configuration(
        "experimental.review",
        experimental::refusal(Feature::Review),
    ))
}
