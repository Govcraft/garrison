//! One daemon per user per machine, and how a client reaches it.
//!
//! The process that owns an `ActonAI` runtime owns the audit trail, the
//! policy, the sandbox host and the socket, and there is exactly one of it
//! per user on a machine: `garrison-agent serve`. Everything else is a
//! client of that socket. An editor that spawns `garrison-agent acp` gets a
//! relay, not an engine, so a spawned child can never become a second
//! writer of the hash chain.
//!
//! # Lifecycle rules
//!
//! 1. A client connects to the socket. If something answers, that is the
//!    daemon, and its configuration is the one in force.
//! 2. If nothing answers and `[server].autostart` is on, the client starts
//!    the daemon: through the user's systemd unit when one is loaded,
//!    otherwise as a detached child of this binary rooted at `$HOME`. An
//!    autostarted daemon reads only the XDG configuration files; the flags
//!    the relay was given are never handed to it, because a first editor's
//!    workspace-local file must not become every later editor's policy.
//! 3. If nothing answers and autostart is off, the client reports that and
//!    starts nothing. `ping` never starts anything regardless: it is a probe,
//!    and "not running" is one of its valid answers.
//!
//! # Exit codes
//!
//! `serve` exits 2 when it refused to start (a locked trail, a broken chain,
//! a configuration it will not accept, a plane that turned the install away)
//! and 3 for a rejection; 1 is a malfunction. Only 1 is worth retrying, and
//! the packaged systemd unit is written that way.

use crate::config::ServerConfig;
use crate::error::GarrisonError;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::UnixStream;

/// The user unit that owns the daemon when systemd manages it.
pub const SYSTEMD_UNIT: &str = "garrison-agent.service";

/// How often a client re-probes the socket while the daemon comes up.
const START_POLL: Duration = Duration::from_millis(100);

/// Exit status for "the daemon refused to start".
pub const EXIT_REFUSED_TO_START: u8 = 2;

/// Exit status for "the system refused on purpose" (a rejection).
pub const EXIT_REJECTED: u8 = 3;

/// The process exit status an error maps to.
///
/// Pure, because the mapping is a contract: `RestartPreventExitStatus=2 3`
/// in the systemd unit relies on exactly this table.
#[must_use]
pub const fn exit_code(error: &GarrisonError) -> u8 {
    if error.is_refusal_to_start() {
        EXIT_REFUSED_TO_START
    } else if error.is_rejection() {
        EXIT_REJECTED
    } else {
        1
    }
}

/// Where a spawned daemon runs and what it may read. Pure data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnPlan {
    /// The binary to run: this one.
    pub exe: PathBuf,
    /// The working directory, which is also the default session root.
    pub home: PathBuf,
    /// Where the child's stdout and stderr go.
    pub log: PathBuf,
    /// Garrison's XDG config file, when it exists.
    pub config: Option<PathBuf>,
    /// acton-ai's XDG config file, when it exists.
    pub acton_config: Option<PathBuf>,
}

/// How a missing daemon gets started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Starter {
    /// `systemctl --user start <unit>`.
    Systemd {
        /// The unit name.
        unit: &'static str,
    },
    /// A detached `garrison-agent serve` child.
    Spawn(SpawnPlan),
    /// Nothing: autostart is off.
    Never,
}

/// Decides how a missing daemon is started. Pure.
///
/// systemd wins when the unit is loaded, because two relays racing to start
/// the daemon then serialize inside systemd instead of both spawning. Without
/// a unit the relay spawns the daemon itself, and if two relays race, the
/// loser exits at the socket probe or the trail lock and both relays connect
/// to the survivor.
#[must_use]
pub fn choose_starter(autostart: bool, unit_loaded: bool, plan: SpawnPlan) -> Starter {
    if !autostart {
        return Starter::Never;
    }
    if unit_loaded {
        return Starter::Systemd { unit: SYSTEMD_UNIT };
    }
    Starter::Spawn(plan)
}

/// Whether a connect failure means "no daemon" rather than "something broke".
///
/// A missing file is the common case; a stale file left by `SIGKILL` gives
/// `ConnectionRefused`. Anything else (permissions, a path that is not a
/// socket) is a real error and is reported as one.
#[must_use]
pub const fn is_no_daemon(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
}

/// Connects to the daemon at `socket`, starting nothing.
///
/// # Errors
///
/// [`GarrisonErrorKind::Transport`](crate::error::GarrisonErrorKind::Transport)
/// when nothing is listening or the socket cannot be reached.
pub async fn connect(socket: &Path) -> Result<UnixStream, GarrisonError> {
    UnixStream::connect(socket).await.map_err(|error| {
        let hint = if is_no_daemon(error.kind()) {
            "; no garrison-agent daemon is listening (start it with `systemctl --user start \
             garrison-agent` or `garrison-agent serve`)"
        } else {
            ""
        };
        GarrisonError::transport(socket.display().to_string(), format!("{error}{hint}"))
    })
}

/// Connects to the daemon, starting it first if it is not running and the
/// configuration allows.
///
/// # Errors
///
/// [`GarrisonErrorKind::Transport`](crate::error::GarrisonErrorKind::Transport)
/// when the daemon is not running and may not be started, when it could not
/// be started, or when it did not answer within `server.start_timeout_secs`.
pub async fn connect_or_start(
    server: &ServerConfig,
    socket: &Path,
) -> Result<UnixStream, GarrisonError> {
    let endpoint = socket.display().to_string();

    match UnixStream::connect(socket).await {
        Ok(stream) => return Ok(stream),
        Err(error) if is_no_daemon(error.kind()) => {}
        Err(error) => return Err(GarrisonError::transport(endpoint, error.to_string())),
    }

    if !server.autostart {
        return Err(GarrisonError::transport(
            endpoint,
            "no garrison-agent daemon is listening and [server].autostart is off; start it \
             with `systemctl --user start garrison-agent` or `garrison-agent serve`",
        ));
    }

    let where_to_look =
        match choose_starter(server.autostart, systemd_unit_loaded().await, spawn_plan()?) {
            Starter::Never => unreachable!("autostart was checked above"),
            Starter::Systemd { unit } => {
                tracing::info!(unit, "no daemon is listening; starting it through systemd");
                start_unit(unit).await?;
                format!("`journalctl --user -u {unit}`")
            }
            Starter::Spawn(plan) => {
                tracing::info!(
                    log = %plan.log.display(),
                    "no daemon is listening and no systemd unit is loaded; spawning it detached"
                );
                spawn_detached(&plan)?;
                plan.log.display().to_string()
            }
        };

    wait_for(socket, server.start_timeout())
        .await
        .map_err(|error| {
            GarrisonError::transport(
                endpoint,
                format!(
                    "the daemon did not come up within {}s ({error}); see {where_to_look}",
                    server.start_timeout_secs
                ),
            )
        })
}

/// Everything a detached spawn needs, gathered from this process's environment.
fn spawn_plan() -> Result<SpawnPlan, GarrisonError> {
    Ok(SpawnPlan {
        exe: std::env::current_exe().map_err(|error| {
            GarrisonError::runtime(format!("cannot locate this executable: {error}"))
        })?,
        home: home_dir()?,
        log: log_path("agent.log")
            .ok_or_else(|| GarrisonError::runtime("neither XDG_STATE_HOME nor HOME is set"))?,
        config: xdg_file("garrison", "garrison.toml"),
        acton_config: xdg_file("acton-ai", "config.toml"),
    })
}

/// Polls the socket until it answers or the deadline passes.
async fn wait_for(socket: &Path, timeout: Duration) -> io::Result<UnixStream> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match UnixStream::connect(socket).await {
            Ok(stream) => return Ok(stream),
            Err(error) if is_no_daemon(error.kind()) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(error);
                }
                tokio::time::sleep(START_POLL).await;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Whether the user's systemd knows a `garrison-agent.service`.
///
/// Absent `systemctl`, or a systemd that is not running a user instance, is
/// simply `false`: the relay then spawns the daemon itself.
async fn systemd_unit_loaded() -> bool {
    let output = tokio::process::Command::new("systemctl")
        .args(["--user", "show", "-p", "LoadState", "--value", SYSTEMD_UNIT])
        .output()
        .await;
    match output {
        Ok(output) => {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "loaded"
        }
        Err(_) => false,
    }
}

/// `systemctl --user start <unit>`, which is idempotent.
async fn start_unit(unit: &str) -> Result<(), GarrisonError> {
    let status = tokio::process::Command::new("systemctl")
        .args(["--user", "start", unit])
        .status()
        .await
        .map_err(|error| GarrisonError::runtime(format!("could not run systemctl: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(GarrisonError::runtime(format!(
            "`systemctl --user start {unit}` failed ({status}); see `journalctl --user -u {unit}`"
        )))
    }
}

/// Spawns `garrison-agent serve` detached from this process.
///
/// Its own process group, so an editor killing the relay's group does not
/// take the daemon with it; stdin closed; both output streams appended to the
/// log file. It is given only the XDG configuration files, never the flags
/// this relay was started with.
fn spawn_detached(plan: &SpawnPlan) -> Result<(), GarrisonError> {
    use std::os::unix::process::CommandExt as _;

    if let Some(parent) = plan.log.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            GarrisonError::runtime(format!("could not create {}: {error}", parent.display()))
        })?;
    }
    let open_log = || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&plan.log)
            .map_err(|error| {
                GarrisonError::runtime(format!("could not open {}: {error}", plan.log.display()))
            })
    };

    let mut command = std::process::Command::new(&plan.exe);
    command.arg("serve");
    if let Some(path) = &plan.config {
        command.arg("--config").arg(path);
    }
    if let Some(path) = &plan.acton_config {
        command.arg("--acton-config").arg(path);
    }
    command
        .current_dir(&plan.home)
        .stdin(std::process::Stdio::null())
        .stdout(open_log()?)
        .stderr(open_log()?)
        .process_group(0);

    command.spawn().map(drop).map_err(|error| {
        GarrisonError::runtime(format!(
            "could not spawn `{} serve`: {error}",
            plan.exe.display()
        ))
    })
}

/// Pumps bytes between a client's pipes and the daemon's socket.
///
/// Not an actor, on purpose: it owns no state. ACP frames are newline-delimited
/// JSON and pass through untouched; the daemon's connection actor is the
/// protocol endpoint. When `input` reaches EOF the socket's write half is shut
/// down, so the daemon sees the hang-up exactly as it would from any other
/// client and every parked approval resolves as unanswered. When the daemon
/// closes, the relay returns and the host sees its child exit.
///
/// # Errors
///
/// Any I/O failure on either side, once the other has been drained as far as
/// it could be.
pub async fn relay<I, O>(stream: UnixStream, mut input: I, mut output: O) -> io::Result<()>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let (mut from_daemon, mut to_daemon) = stream.into_split();

    let upstream = async {
        let copied = tokio::io::copy(&mut input, &mut to_daemon).await;
        let _ = to_daemon.shutdown().await;
        copied
    };
    let downstream = async {
        let copied = tokio::io::copy(&mut from_daemon, &mut output).await?;
        output.flush().await?;
        Ok::<u64, io::Error>(copied)
    };
    tokio::pin!(upstream);
    tokio::pin!(downstream);

    tokio::select! {
        up = &mut upstream => {
            // The client hung up. Let the daemon's last frames land before
            // leaving; it closes once it has processed the shutdown.
            up?;
            downstream.await.map(drop)
        }
        down = &mut downstream => down.map(drop),
    }
}

/// `$XDG_STATE_HOME/garrison`, or `~/.local/state/garrison`.
#[must_use]
pub fn state_dir() -> Option<PathBuf> {
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("state"))
        })?;
    Some(state.join("garrison"))
}

/// A log file under the state directory, e.g. `agent.log` or `chat.log`.
#[must_use]
pub fn log_path(name: &str) -> Option<PathBuf> {
    state_dir().map(|dir| dir.join(name))
}

/// `$XDG_CONFIG_HOME/<app>/<file>`, or `~/.config/<app>/<file>`, when it exists.
///
/// These are the only configuration files an autostarted daemon is handed.
#[must_use]
pub fn xdg_file(app: &str, file: &str) -> Option<PathBuf> {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    let path = config_home.join(app).join(file);
    path.is_file().then_some(path)
}

/// The daemon's working directory when a relay starts it: `$HOME`.
fn home_dir() -> Result<PathBuf, GarrisonError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| GarrisonError::runtime("HOME is not set; cannot root the daemon"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt as _;

    fn plan() -> SpawnPlan {
        SpawnPlan {
            exe: PathBuf::from("/usr/bin/garrison-agent"),
            home: PathBuf::from("/home/dev"),
            log: PathBuf::from("/home/dev/.local/state/garrison/agent.log"),
            config: Some(PathBuf::from("/home/dev/.config/garrison/garrison.toml")),
            acton_config: None,
        }
    }

    #[test]
    fn autostart_off_starts_nothing() {
        assert_eq!(
            choose_starter(false, true, plan()),
            Starter::Never,
            "a loaded unit must not override an operator's autostart = false"
        );
    }

    #[test]
    fn a_loaded_unit_is_preferred_over_a_bare_spawn() {
        assert_eq!(
            choose_starter(true, true, plan()),
            Starter::Systemd {
                unit: "garrison-agent.service"
            }
        );
    }

    #[test]
    fn without_a_unit_the_relay_spawns_the_daemon_at_home_with_xdg_files_only() {
        assert_eq!(choose_starter(true, false, plan()), Starter::Spawn(plan()));
    }

    #[test]
    fn only_a_missing_or_dead_socket_means_no_daemon() {
        assert!(is_no_daemon(io::ErrorKind::NotFound));
        assert!(is_no_daemon(io::ErrorKind::ConnectionRefused));
        assert!(!is_no_daemon(io::ErrorKind::PermissionDenied));
        assert!(!is_no_daemon(io::ErrorKind::Other));
    }

    #[test]
    fn exit_codes_separate_refusals_from_crashes() {
        assert_eq!(
            exit_code(&GarrisonError::configuration("audit.path", "locked")),
            2
        );
        assert_eq!(exit_code(&GarrisonError::enrollment("refused")), 2);
        assert_eq!(exit_code(&GarrisonError::patch_rejected("outside root")), 3);
        assert_eq!(exit_code(&GarrisonError::runtime("boom")), 1);
        assert_eq!(
            exit_code(&GarrisonError::transport("/x.sock", "refused")),
            1
        );
    }

    #[tokio::test]
    async fn the_relay_carries_bytes_both_ways_and_propagates_the_hang_up() {
        let (client_end, daemon_end) = UnixStream::pair().expect("pairs");

        // A stand-in daemon: read everything the client sends, then answer
        // once and hang up, the way a connection actor does on `Closed`.
        let daemon = tokio::spawn(async move {
            let mut daemon_end = daemon_end;
            let mut received = Vec::new();
            daemon_end
                .read_to_end(&mut received)
                .await
                .expect("reads until the relay shuts its write half");
            daemon_end
                .write_all(b"{\"id\":1,\"result\":{}}\n")
                .await
                .expect("writes");
            received
        });

        let input: &[u8] = b"{\"id\":1,\"method\":\"initialize\"}\n";
        let mut output = Vec::new();
        relay(client_end, input, &mut output).await.expect("relays");

        assert_eq!(
            daemon.await.expect("daemon task"),
            b"{\"id\":1,\"method\":\"initialize\"}\n"
        );
        assert_eq!(output, b"{\"id\":1,\"result\":{}}\n");
    }

    #[tokio::test]
    async fn the_relay_ends_when_the_daemon_hangs_up_first() {
        let (client_end, daemon_end) = UnixStream::pair().expect("pairs");
        drop(daemon_end);

        // An input that never reaches EOF on its own: the relay must return
        // because the daemon side closed, not because stdin did.
        let (never_eof, _keep_open) = tokio::io::duplex(16);
        let mut output = Vec::new();
        relay(client_end, never_eof, &mut output)
            .await
            .expect("returns");
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn connecting_to_a_missing_socket_names_the_fix() {
        let error = connect(Path::new("/nonexistent/garrison-agent.sock"))
            .await
            .expect_err("nothing listens there");
        assert!(error
            .to_string()
            .contains("no garrison-agent daemon is listening"));
    }

    #[tokio::test]
    async fn a_missing_daemon_is_refused_when_autostart_is_off() {
        let server = ServerConfig {
            socket: PathBuf::from("/nonexistent/garrison-agent.sock"),
            autostart: false,
            start_timeout_secs: 1,
        };
        let error = connect_or_start(&server, &server.socket)
            .await
            .expect_err("must refuse");
        assert!(error.to_string().contains("autostart is off"));
    }
}
