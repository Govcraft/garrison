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
