//! Garrison's own configuration, alongside acton-ai's.
//!
//! Deliberately a separate file from `acton-ai.toml`: acton-ai's config
//! describes providers, budgets, and tools, and belongs to the framework.
//! This one describes the *server* — where it listens, what a new thread
//! inherits, and how approvals behave. Keeping them apart means an operator
//! can hand acton-ai's file to a different consumer unchanged, and that
//! Garrison's settings do not have to be accepted upstream to exist.

use crate::error::GarrisonError;
use acton_ai::audit::AuditDurability;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The file name looked for in the working directory and in XDG config.
pub const CONFIG_FILE: &str = "garrison.toml";

/// Everything the agent server reads from disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GarrisonConfig {
    /// Where the server listens.
    pub server: ServerConfig,
    /// What a newly created thread inherits.
    pub threads: ThreadConfig,
    /// How tool approvals behave.
    pub approval: ApprovalConfig,
    /// The control plane this install answers to, if any.
    ///
    /// `None` — no `[plane]` section — is a standalone agent: it starts, it
    /// works, and it reports to nobody. That has to stay the default, because
    /// the editor integration a developer tries first cannot depend on an
    /// agency having stood a plane up. Adding the section is what turns this
    /// daemon into a member of a fleet.
    pub plane: Option<PlaneConfig>,
    /// What this install requires of its audit trail.
    ///
    /// Absent — no `[audit]` section — follows acton-ai: the trail is armed
    /// if `acton-ai.toml` arms one, it promises whatever that file says, and
    /// the anchor lives in the default place. The section exists for the
    /// deployment that wants to say more than acton-ai's file can.
    pub audit: AuditConfig,
    /// Language servers to run, keyed by a name of the operator's choosing.
    pub lsp_servers: std::collections::HashMap<String, LspServerConfig>,
}

/// What Garrison requires of the audit trail acton-ai writes.
///
/// acton-ai owns the trail: where it is, what an append promises, who holds
/// it. This section owns the three questions acton-ai has no opinion about —
/// whether a trail is required at all, where the chain head is anchored
/// outside the trail, and what to do when the two disagree at startup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// What an append must promise before a turn may run.
    ///
    /// `None` — the key omitted — follows the trail: whatever
    /// `acton-ai.toml`'s `[audit] durability` resolved to. Naming it here is
    /// how a deployment states the requirement in its own file, and it is
    /// what [`Self::durability_for`] answers with.
    ///
    /// `strict` is what arms the turn gate: with a strict trail, a writer
    /// that has failed an append refuses further turns rather than running
    /// them unrecorded. `best_effort` records what it can and never refuses.
    pub durability: Option<AuditDurability>,

    /// Where the last verified chain head is written, outside the trail.
    ///
    /// The anchor is what makes a tail truncation detectable: the trail alone
    /// still verifies after its last entries are deleted, because a prefix of
    /// a valid chain is a valid chain. `None` resolves to
    /// `$XDG_STATE_HOME/garrison/audit-anchor.json`, falling back to
    /// `$HOME/.local/state/garrison/audit-anchor.json`.
    pub anchor_path: Option<PathBuf>,

    /// What startup does when the trail and the anchor disagree.
    pub on_anchor_mismatch: AnchorMismatchAction,

    /// Whether the daemon may start without an armed trail.
    ///
    /// `None` means "required when a `[plane]` section is present": a member
    /// of a fleet has an agency expecting its record, a standalone developer
    /// install does not. See [`GarrisonConfig::audit_required`], which is the
    /// only place this rule is decided.
    pub required: Option<bool>,
}

/// What to do when the trail's head is not the head the anchor remembers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorMismatchAction {
    /// Refuse to start (exit 2). The default: a trail that lost entries is
    /// evidence, and starting over it appends to a record already known to be
    /// incomplete.
    #[default]
    Refuse,
    /// Log the disagreement and start anyway, for a deployment that would
    /// rather have a running agent than a stopped one.
    Warn,
}

impl AuditConfig {
    /// The durability the turn gate enforces: what this file declares, else
    /// what the trail itself promises.
    ///
    /// Pure, so the precedence is testable without a runtime.
    #[must_use]
    pub fn durability_for(&self, trail: Option<AuditDurability>) -> AuditDurability {
        self.durability
            .or(trail)
            .unwrap_or(AuditDurability::BestEffort)
    }

    /// Where the anchor file lives.
    ///
    /// State rather than config: it is written by the daemon, changes on
    /// every turn, and must not be checked into whatever backs the config
    /// directory up.
    #[must_use]
    pub fn anchor_path(&self) -> PathBuf {
        self.anchor_path.clone().unwrap_or_else(default_anchor_path)
    }
}

/// The default anchor location: `$XDG_STATE_HOME/garrison/audit-anchor.json`.
///
/// `$HOME/.local/state` is the XDG fallback, and the temp directory is the
/// last resort so a process with no home still writes an anchor somewhere
/// rather than silently anchoring nothing.
fn default_anchor_path() -> PathBuf {
    let state_home = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("state"))
        })
        .unwrap_or_else(std::env::temp_dir);

    state_home.join("garrison").join("audit-anchor.json")
}

/// Where the control plane is, and how this machine first proves itself to it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlaneConfig {
    /// Origin of the control plane, e.g. `https://plane.agency.gov`. The
    /// versioned API path is the framework's convention and is appended for
    /// you, so this is an origin and not a route.
    pub url: String,

    /// Origin of the service that runs the install-token exchange.
    ///
    /// `None` means "the same origin as [`url`](Self::url)", which is the
    /// deployment the shipped `config.toml` describes: `garrison-hooks` sits
    /// behind the same name as the plane. It is an option rather than a
    /// defaulted string because the two are genuinely one setting in the
    /// common case, and a second copy of a hostname is a second thing to get
    /// wrong when a plane moves. Set it when the exchange is reverse-proxied
    /// somewhere else, or when a developer runs the hook service on its own
    /// port.
    pub hooks_url: Option<String>,

    /// The enrollment packet placed on this machine by whoever provisioned it.
    ///
    /// A path rather than the values themselves, for the reason every
    /// credential here is a path: a secret in `garrison.toml` is a secret in
    /// whatever backs that file up. See [`crate::enrollment`] for the packet's
    /// two fields and why it needs both.
    pub enrollment_packet: Option<PathBuf>,

    /// Which operator this install belongs to, as an Entra userPrincipalName.
    ///
    /// Only consulted for a grant that does not already name a person. An
    /// operator-scoped enrollment token carries the answer, and the plane
    /// prefers its own record over anything a machine claims, so leaving this
    /// unset is correct whenever the grant was issued to an individual.
    pub operator_upn: Option<String>,

    /// How the audit trail reaches the plane, and when failing to reach it
    /// stops the work.
    ///
    /// Present by default: a governed install that recorded everything
    /// locally and shipped none of it would satisfy the letter of an audit
    /// requirement and none of its purpose, since the machine that wrote the
    /// record is the machine that could edit it.
    pub shipping: ShippingConfig,
}

/// `[plane.shipping]`: the terms the audit trail leaves the box under.
///
/// Everything here is a duration or a bound; the *rule* they feed lives in
/// [`crate::shipping::policy`] as pure functions, so the numbers can be read
/// here and the behaviour tested there.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShippingConfig {
    /// Whether the trail is shipped at all.
    ///
    /// `false` leaves a governed install recording locally and telling the
    /// plane nothing, which is a decision an agency may make for an
    /// air-gapped machine and should have to make explicitly. The status says
    /// so plainly either way.
    pub enabled: bool,
    /// How often the trail is checked for entries to send.
    pub poll_interval_secs: u64,
    /// How often the daemon files its own account of the trail, even when
    /// nothing moved. This is what the plane's silence detection measures
    /// against, so it is a heartbeat as much as a report.
    pub report_interval_secs: u64,
    /// The most entries one batch may carry.
    pub batch: usize,
    /// How old the oldest unshipped entry may get before turns are refused.
    ///
    /// A day by default: generous enough that an outage, a flight, or a
    /// weekend offline costs nobody a turn, and short enough that an install
    /// which has kept evidence to itself for longer is the case an auditor
    /// asks about.
    pub max_unshipped_age_secs: u64,
    /// How many entries may go unshipped before turns are refused.
    pub max_unshipped_entries: u64,
    /// Whether a backlog past its bound refuses turns.
    ///
    /// A halt refuses either way. This governs only the backlog bound, and
    /// setting it false is a deployment saying it would rather keep working
    /// than keep the evidence moving. Default true, because that is the
    /// posture the README claims.
    pub fail_closed: bool,
    /// The first delay after a failed batch, doubling to the ceiling.
    pub backoff_base_secs: u64,
    /// The longest that delay grows to.
    pub backoff_ceiling_secs: u64,
}

impl Default for ShippingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_secs: 5,
            report_interval_secs: 60,
            batch: 50,
            max_unshipped_age_secs: 86_400,
            max_unshipped_entries: 10_000,
            fail_closed: true,
            backoff_base_secs: 1,
            backoff_ceiling_secs: 300,
        }
    }
}

impl ShippingConfig {
    /// The terms as the shipper reads them.
    ///
    /// Pure. A zero interval would spin, and a zero batch would ship nothing
    /// forever, so both floor at one rather than being rejected: a typo in a
    /// tuning knob must not stop a daemon that would otherwise be governed.
    #[must_use]
    pub fn policy(&self) -> crate::shipping::ShippingPolicy {
        crate::shipping::ShippingPolicy {
            poll_interval: Duration::from_secs(self.poll_interval_secs.max(1)),
            report_interval: Duration::from_secs(self.report_interval_secs.max(1)),
            batch: self.batch.max(1),
            max_unshipped_age: Duration::from_secs(self.max_unshipped_age_secs),
            max_unshipped_entries: self.max_unshipped_entries,
            fail_closed: self.fail_closed,
            backoff_base: Duration::from_secs(self.backoff_base_secs.max(1)),
            backoff_ceiling: Duration::from_secs(self.backoff_ceiling_secs.max(1)),
        }
    }
}

impl PlaneConfig {
    /// Where the install-token exchange lives.
    ///
    /// Pure, and the only place the fallback is spelled, so a caller cannot
    /// forget it and end up posting an assertion at the plane, which would
    /// answer 404 and look like a missing route rather than a missing
    /// setting.
    #[must_use]
    pub fn hooks_url(&self) -> &str {
        match self.hooks_url.as_deref() {
            Some(url) if !url.trim().is_empty() => url,
            _ => &self.url,
        }
    }
}

/// Listener settings, and how a client behaves when nothing is listening.
///
/// There is one daemon per user per machine; `acp` and `chat` are clients of
/// it. Whether a client may bring the daemon up when it finds the socket dead
/// is a decision this section owns, because it decides who may start an
/// engine on this machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// The Unix socket path. A `--socket` argument overrides it.
    pub socket: PathBuf,
    /// Whether a client that finds no daemon may start one.
    ///
    /// `true` (the default) lets an editor's `garrison-agent acp` relay bring
    /// the daemon up: through the user's systemd unit when one is loaded,
    /// otherwise as a detached child rooted at `$HOME` that reads only the
    /// XDG configuration files. `false` means a missing daemon is an error
    /// the relay reports and nothing more, for hosts where only an operator
    /// or systemd may start the engine.
    pub autostart: bool,
    /// How long a client waits for an autostarted daemon to answer.
    pub start_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            socket: default_socket(),
            autostart: true,
            start_timeout_secs: 10,
        }
    }
}

impl ServerConfig {
    /// How long a client waits for an autostarted daemon.
    #[must_use]
    pub const fn start_timeout(&self) -> Duration {
        Duration::from_secs(self.start_timeout_secs)
    }
}

/// Per-thread defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ThreadConfig {
    /// The root a thread is confined to when the client names none.
    ///
    /// `None` means the server's working directory, resolved at launch rather
    /// than baked into the file, so the same config works from any checkout.
    pub project_root: Option<PathBuf>,
    /// Further directories a client may root a session at.
    ///
    /// A session's `cwd` must equal, or lie under, `project_root` or one of
    /// these; anything else is refused. Listing a workspace here is how an
    /// administrator grants access to it, which is why the default is empty:
    /// one server, one tree, unless someone says otherwise.
    pub workspace_roots: Vec<PathBuf>,
    /// A system prompt prepended to every turn.
    pub system_prompt: Option<String>,
}

/// Approval settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalConfig {
    /// How long a client has to answer before the call is denied.
    pub timeout_secs: u64,
    /// Tool-name patterns that never require a round-trip.
    ///
    /// Matched with acton-ai's own pattern syntax, so `mcp__*` and the like
    /// mean here what they mean in a `[tool_policy]` block. Everything not
    /// listed goes to the client.
    ///
    /// This is Garrison's stand-in until the prefix-rule policy engine lands;
    /// it is a *name* allowlist and knows nothing about arguments, so it holds
    /// only tools that cannot change anything.
    pub auto_approve: Vec<String>,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 300,
            auto_approve: default_auto_approve(),
        }
    }
}

/// One language server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LspServerConfig {
    /// The binary to run, resolved on `PATH`.
    pub command: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// File extensions (without dots) routed to this server.
    pub extensions: Vec<String>,
    /// The `languageId` sent when opening a document.
    ///
    /// `None` uses the config key's name, which is right whenever the key is
    /// the language ("rust", "python") — the common case.
    pub language_id: Option<String>,
    /// How long a tool call waits on this server, in seconds.
    ///
    /// The default is generous because the first diagnostics request lands
    /// while the server is still indexing, and a truthful slow answer beats
    /// a fast timeout.
    pub request_timeout_secs: u64,
}

impl Default for LspServerConfig {
    fn default() -> Self {
        Self {
            command: String::new(),
            args: Vec::new(),
            extensions: Vec::new(),
            language_id: None,
            request_timeout_secs: 60,
        }
    }
}

impl LspServerConfig {
    /// The ask timeout as a [`Duration`].
    #[must_use]
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }
}

/// The builtins that never need a human.
///
/// Every one of them only observes or restates the turn's own state. `bash`,
/// `write_file`, `edit_file` and `apply_patch` are deliberately absent: they
/// change the world, so they are exactly what a governed agent asks about.
///
/// `update_plan` is here because it is how the model narrates itself: it
/// touches no file, no socket and no process, it only replaces the plan the
/// turn already owns, and without it every step of every plan would raise a
/// permission dialog in the editor. It is still recorded in the audit chain
/// with its arguments, like any other call.
///
/// This list stays short on purpose. It is a *name* allowlist that knows
/// nothing about arguments, and the policy engine that replaces it reads
/// acton-ai's own `idempotent` declaration instead — which is upstream and
/// cannot be widened by a local file.
fn default_auto_approve() -> Vec<String> {
    [
        "read_file",
        "glob",
        "grep",
        "list_files",
        "calculate",
        "update_plan",
    ]
    .iter()
    .map(|name| (*name).to_string())
    .collect()
}

/// The default socket path: under `$XDG_RUNTIME_DIR` when there is one.
///
/// A runtime directory is per-user, mode 0700, and cleaned on logout, which is
/// what a socket carrying an agent's approval decisions wants. `/tmp` is the
/// fallback and is world-readable, so the socket's own permissions are what
/// protect it there.
fn default_socket() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) => PathBuf::from(dir).join("garrison-agent.sock"),
        None => std::env::temp_dir().join("garrison-agent.sock"),
    }
}

impl GarrisonConfig {
    /// Loads the first config file found, or the defaults when there is none.
    ///
    /// Order: `./garrison.toml`, then `$XDG_CONFIG_HOME/garrison/garrison.toml`
    /// (or `~/.config/...`). A missing file is not an error; an unparseable one
    /// is.
    ///
    /// # Errors
    ///
    /// [`GarrisonErrorKind::Configuration`](crate::error::GarrisonErrorKind::Configuration)
    /// when a file exists but cannot be read or parsed.
    pub fn load() -> Result<Self, GarrisonError> {
        for candidate in Self::search_path() {
            if candidate.is_file() {
                return Self::from_file(&candidate);
            }
        }
        Ok(Self::default())
    }

    /// Reads one specific file.
    ///
    /// # Errors
    ///
    /// As [`Self::load`], and additionally when the named file is absent —
    /// a path given explicitly and not found is a mistake worth reporting.
    pub fn from_file(path: &Path) -> Result<Self, GarrisonError> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            GarrisonError::configuration(
                path.display().to_string(),
                format!("could not be read: {error}"),
            )
        })?;
        Self::from_toml(&text).map_err(|error| {
            GarrisonError::configuration(path.display().to_string(), error.to_string())
        })
    }

    /// Parses configuration from TOML text.
    ///
    /// Pure, so every rule about defaults and rejected keys is testable
    /// without touching a filesystem.
    ///
    /// # Errors
    ///
    /// The `toml` parse error, unchanged, so the message keeps its line and
    /// column.
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// The files [`Self::load`] looks for, in order.
    fn search_path() -> Vec<PathBuf> {
        let mut candidates = vec![PathBuf::from(CONFIG_FILE)];

        let config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));

        if let Some(home) = config_home {
            candidates.push(home.join("garrison").join(CONFIG_FILE));
        }

        candidates
    }

    /// How long a client has to answer an approval.
    #[must_use]
    pub const fn approval_timeout(&self) -> Duration {
        Duration::from_secs(self.approval.timeout_secs)
    }

    /// Whether this daemon may start without an armed audit trail.
    ///
    /// The single home of one rule: **a `[plane]` section present while
    /// acton-ai arms no trail is a refusal to start.** An install that
    /// answers to an agency was configured to be accountable to it, and an
    /// accountable agent that records nothing is the exact failure an audit
    /// exists to prevent — so it fails closed, loudly, at launch, rather than
    /// running unrecorded turns nobody notices until someone asks for the
    /// trail. `[audit] required` overrides the inference in either direction.
    ///
    /// Pure, and deliberately the only place this is decided: #8's shipping
    /// path asks the same question and must get the same answer.
    #[must_use]
    pub fn audit_required(&self) -> bool {
        self.audit.required.unwrap_or(self.plane.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_file_yields_the_defaults() {
        let config = GarrisonConfig::from_toml("").unwrap();

        assert_eq!(config.approval.timeout_secs, 300);
        assert!(config.approval.auto_approve.contains(&"grep".to_string()));
        assert!(config
            .approval
            .auto_approve
            .contains(&"update_plan".to_string()));
        assert!(config.threads.project_root.is_none());
    }

    #[test]
    fn nothing_that_writes_is_auto_approved_by_default() {
        let approve = GarrisonConfig::default().approval.auto_approve;

        for dangerous in ["bash", "write_file", "edit_file", "apply_patch"] {
            assert!(
                !approve.iter().any(|name| name == dangerous),
                "{dangerous} must not be auto-approved",
            );
        }
    }

    #[test]
    fn settings_override_the_defaults() {
        let config = GarrisonConfig::from_toml(
            r#"
            [server]
            socket = "/run/garrison.sock"

            [approval]
            timeout_secs = 30
            auto_approve = ["read_file"]
            "#,
        )
        .unwrap();

        assert_eq!(config.server.socket, PathBuf::from("/run/garrison.sock"));
        assert_eq!(config.approval_timeout(), Duration::from_secs(30));
        assert_eq!(config.approval.auto_approve, vec!["read_file".to_string()]);
    }

    #[test]
    fn a_client_may_start_the_daemon_by_default() {
        let server = GarrisonConfig::from_toml("").unwrap().server;

        assert!(server.autostart);
        assert_eq!(server.start_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn autostart_can_be_switched_off() {
        let config = GarrisonConfig::from_toml(
            r#"
            [server]
            autostart = false
            start_timeout_secs = 3
            "#,
        )
        .unwrap();

        assert!(!config.server.autostart);
        assert_eq!(config.server.start_timeout(), Duration::from_secs(3));
    }

    #[test]
    fn a_misspelled_server_key_is_refused_rather_than_ignored() {
        let error = GarrisonConfig::from_toml(
            "[server]
auto_start = false
",
        )
        .unwrap_err();

        assert!(error.to_string().contains("auto_start"));
    }

    #[test]
    fn no_plane_section_is_a_standalone_agent() {
        let config = GarrisonConfig::from_toml("[approval]\ntimeout_secs = 30\n").unwrap();
        assert!(
            config.plane.is_none(),
            "an agent must not need a control plane to start"
        );
    }

    #[test]
    fn a_plane_section_names_where_to_enroll() {
        let config = GarrisonConfig::from_toml(
            r#"
            [plane]
            url = "https://plane.agency.gov"
            enrollment_packet = "/etc/garrison/enrollment.toml"
            operator_upn = "dev@agency.gov"
            "#,
        )
        .unwrap();

        let plane = config.plane.expect("the section was declared");
        assert_eq!(plane.url, "https://plane.agency.gov");
        assert_eq!(
            plane.enrollment_packet,
            Some(PathBuf::from("/etc/garrison/enrollment.toml"))
        );
        assert_eq!(plane.operator_upn.as_deref(), Some("dev@agency.gov"));
    }

    #[test]
    fn a_plane_section_needs_only_a_url() {
        let plane = GarrisonConfig::from_toml("[plane]\nurl = \"https://plane.agency.gov\"\n")
            .unwrap()
            .plane
            .expect("the section was declared");

        assert!(plane.enrollment_packet.is_none());
        assert!(plane.operator_upn.is_none());
    }

    #[test]
    fn an_unstated_exchange_is_the_plane_itself() {
        let plane = GarrisonConfig::from_toml("[plane]\nurl = \"https://plane.agency.gov\"\n")
            .unwrap()
            .plane
            .expect("the section was declared");

        assert_eq!(
            plane.hooks_url(),
            "https://plane.agency.gov",
            "one name for one deployment; a second copy is a second thing to get wrong"
        );
    }

    #[test]
    fn a_reverse_proxied_exchange_is_named_separately() {
        let plane = GarrisonConfig::from_toml(
            r#"
            [plane]
            url = "https://plane.agency.gov"
            hooks_url = "https://hooks.agency.gov"
            "#,
        )
        .unwrap()
        .plane
        .expect("the section was declared");

        assert_eq!(plane.hooks_url(), "https://hooks.agency.gov");
    }

    #[test]
    fn a_blank_exchange_url_falls_back_rather_than_posting_at_nothing() {
        let plane = GarrisonConfig::from_toml(
            "[plane]\nurl = \"https://plane.agency.gov\"\nhooks_url = \"   \"\n",
        )
        .unwrap()
        .plane
        .expect("the section was declared");

        assert_eq!(plane.hooks_url(), "https://plane.agency.gov");
    }

    #[test]
    fn a_misspelled_plane_key_is_refused_rather_than_ignored() {
        let error = GarrisonConfig::from_toml(
            r#"
            [plane]
            url = "https://plane.agency.gov"
            enrollment_token = "/etc/garrison/token"
            "#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("enrollment_token"));
    }

    #[test]
    fn a_misspelled_key_is_refused_rather_than_ignored() {
        let error = GarrisonConfig::from_toml(
            r#"
            [approval]
            timeout_seconds = 30
            "#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("timeout_seconds"));
    }

    #[test]
    fn no_audit_section_follows_acton_ai() {
        let config = GarrisonConfig::from_toml("").unwrap();

        assert!(config.audit.durability.is_none());
        assert_eq!(
            config.audit.on_anchor_mismatch,
            AnchorMismatchAction::Refuse
        );
        assert!(config.audit.required.is_none());
    }

    #[test]
    fn the_declared_durability_wins_over_the_trails() {
        let config = GarrisonConfig::from_toml("[audit]\ndurability = \"strict\"\n").unwrap();

        assert_eq!(
            config
                .audit
                .durability_for(Some(AuditDurability::BestEffort)),
            AuditDurability::Strict
        );
    }

    #[test]
    fn an_undeclared_durability_follows_the_trail() {
        let audit = GarrisonConfig::default().audit;

        assert_eq!(
            audit.durability_for(Some(AuditDurability::Strict)),
            AuditDurability::Strict
        );
        assert_eq!(audit.durability_for(None), AuditDurability::BestEffort);
    }

    #[test]
    fn a_plane_makes_the_audit_trail_required() {
        let with_plane =
            GarrisonConfig::from_toml("[plane]\nurl = \"https://plane.agency.gov\"\n").unwrap();
        let standalone = GarrisonConfig::from_toml("").unwrap();

        assert!(
            with_plane.audit_required(),
            "an install answering to an agency must record what it does"
        );
        assert!(
            !standalone.audit_required(),
            "a developer install must start with no plane and no trail"
        );
    }

    #[test]
    fn the_required_key_overrides_the_inference_in_both_directions() {
        let plane_without_audit = GarrisonConfig::from_toml(
            "[plane]\nurl = \"https://plane.agency.gov\"\n\n[audit]\nrequired = false\n",
        )
        .unwrap();
        let standalone_with_audit =
            GarrisonConfig::from_toml("[audit]\nrequired = true\n").unwrap();

        assert!(!plane_without_audit.audit_required());
        assert!(standalone_with_audit.audit_required());
    }

    #[test]
    fn the_anchor_path_can_be_named_outright() {
        let config =
            GarrisonConfig::from_toml("[audit]\nanchor_path = \"/var/lib/g/anchor.json\"\n")
                .unwrap();

        assert_eq!(
            config.audit.anchor_path(),
            PathBuf::from("/var/lib/g/anchor.json")
        );
    }

    #[test]
    fn the_mismatch_action_can_be_relaxed_to_a_warning() {
        let config = GarrisonConfig::from_toml("[audit]\non_anchor_mismatch = \"warn\"\n").unwrap();

        assert_eq!(config.audit.on_anchor_mismatch, AnchorMismatchAction::Warn);
    }

    #[test]
    fn a_misspelled_audit_key_is_refused_rather_than_ignored() {
        let error = GarrisonConfig::from_toml("[audit]\ndurabilty = \"strict\"\n").unwrap_err();

        assert!(error.to_string().contains("durabilty"));
    }

    #[test]
    fn a_missing_file_is_reported_with_its_path() {
        let error = GarrisonConfig::from_file(Path::new("/nonexistent/garrison.toml")).unwrap_err();

        assert!(error.is_configuration());
        assert!(error.to_string().contains("/nonexistent/garrison.toml"));
    }
}
