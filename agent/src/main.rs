//! The `garrison-agent` command.
//!
//! Four subcommands, and the first two are the product:
//!
//! - `acp` speaks the Agent Client Protocol over stdin and stdout. This is the
//!   mode ACP hosts expect: the editor spawns the agent as a child process and
//!   talks to it over its pipes. It is the default for a reason — a JetBrains,
//!   Zed, or Neovim ACP client needs no configuration beyond a path to this
//!   binary.
//! - `serve` runs the same protocol as a daemon on a Unix socket, for clients
//!   that want one long-lived agent shared across editors, and as the seam a
//!   Windows named-pipe transport will slot into.
//! - `ping` performs the handshake against a running daemon and prints what
//!   came back, including Garrison's own `_garrison/status`.
//! - `chat` drives one session end to end over the socket, rendering updates as
//!   they arrive and answering permission requests at the terminal.
//!
//! # The sandbox re-exec
//!
//! acton-ai's `ProcessSandbox` re-execs this binary as its own sandbox child.
//! That check has to happen before anything else in `main`, so the child
//! dispatches its tool call and exits without ever parsing a command line.

use clap::{Parser, Subcommand};
use garrison_agent::client::{update_text, AgentClient, Interactions, Quiet};
use garrison_agent::config::GarrisonConfig;
use garrison_agent::error::GarrisonError;
use garrison_agent::launch;
use garrison_agent::protocol::acp;
use garrison_agent::protocol::server;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use tokio_util::sync::CancellationToken;

/// A governed agentic coding engine.
#[derive(Debug, Parser)]
#[command(name = "garrison-agent", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Speaks ACP over stdin and stdout. The mode editors spawn.
    Acp {
        /// Garrison's own config file. Defaults to the usual search path.
        #[arg(long)]
        config: Option<PathBuf>,
        /// acton-ai's config file. Defaults to the usual search path.
        #[arg(long)]
        acton_config: Option<PathBuf>,
    },
    /// Runs the agent as a daemon serving ACP on a Unix socket.
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
    /// Runs one session against a running daemon.
    Chat {
        /// The socket to connect to.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// What to say. Required; this is a smoke client, not a REPL.
        #[arg(long)]
        message: String,
        /// Approve every tool call without asking at the terminal.
        #[arg(long)]
        approve_all: bool,
    },
}

/// Which cloud provider a login or logout addresses.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ProviderArg {
    /// Anthropic (Claude models): paste a Console API key.
    Anthropic,
    /// OpenAI (GPT models): OAuth sign-in in the browser.
    Openai,
}

impl From<ProviderArg> for garrison_agent::auth::Provider {
    fn from(arg: ProviderArg) -> Self {
        match arg {
            ProviderArg::Anthropic => Self::Anthropic,
            ProviderArg::Openai => Self::OpenAI,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    // stderr, always: stdout is the protocol in `acp` mode, and a log line
    // written into it would be a malformed frame.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("garrison-agent: {error}");
            // A deliberate refusal is not a malfunction, and a caller
            // scripting against this should be able to tell them apart.
            if error.is_rejection() {
                ExitCode::from(3)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

/// Dispatches one invocation.
async fn run(cli: Cli) -> Result<(), GarrisonError> {
    match cli.command {
        Command::Acp {
            config,
            acton_config,
        } => acp_stdio(config, acton_config).await,
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
        Command::Chat {
            socket,
            message,
            approve_all,
        } => chat(socket, message, approve_all).await,
    }
}

/// Loads Garrison's config from the named file, or the search path.
fn load_config(path: Option<PathBuf>) -> Result<GarrisonConfig, GarrisonError> {
    match path {
        Some(path) => GarrisonConfig::from_file(&path),
        None => GarrisonConfig::load(),
    }
}

/// Resolves the socket to talk to: the argument, else the configured one.
fn client_socket(socket: Option<PathBuf>) -> Result<PathBuf, GarrisonError> {
    match socket {
        Some(path) => Ok(path),
        None => Ok(GarrisonConfig::load()?.server.socket),
    }
}

/// `acp`: one client, on this process's own pipes, until it hangs up.
async fn acp_stdio(
    config: Option<PathBuf>,
    acton_config: Option<PathBuf>,
) -> Result<(), GarrisonError> {
    let config = load_config(config)?;
    let ai = launch::build_ai(acton_config.as_deref()).await?;
    let setup = launch::build_setup(&ai, &config).await?;
    let mut runtime = ai.runtime().clone();

    tracing::info!("garrison agent speaking ACP on stdio");
    server::serve_connection(
        &mut runtime,
        tokio::io::stdin(),
        tokio::io::stdout(),
        setup,
        CancellationToken::new(),
    )
    .await;

    runtime
        .shutdown_all()
        .await
        .map_err(|error| GarrisonError::runtime(format!("shutdown failed: {error}")))
}

/// `serve`: run until interrupted.
async fn serve(
    socket: Option<PathBuf>,
    config: Option<PathBuf>,
    acton_config: Option<PathBuf>,
) -> Result<(), GarrisonError> {
    let config = load_config(config)?;
    let garrison = launch::launch(&config, socket, acton_config.as_deref()).await?;

    println!("garrison-agent listening on {}", garrison.endpoint);

    tokio::signal::ctrl_c()
        .await
        .map_err(|error| GarrisonError::runtime(format!("could not wait for a signal: {error}")))?;

    println!("shutting down");
    garrison.shutdown().await
}

/// `ping`: handshake, then ask Garrison what it is enforcing.
async fn ping(socket: Option<PathBuf>) -> Result<(), GarrisonError> {
    let path = client_socket(socket)?;
    let mut client = AgentClient::connect(&path).await?;
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
    println!("  audit:      {}", status.audit.enabled);

    Ok(())
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
    message: String,
    approve_all: bool,
) -> Result<(), GarrisonError> {
    let path = client_socket(socket)?;
    let mut client = AgentClient::connect(&path).await?;
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
