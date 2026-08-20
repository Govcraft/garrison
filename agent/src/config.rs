//! Garrison's own configuration, alongside acton-ai's.
//!
//! Deliberately a separate file from `acton-ai.toml`: acton-ai's config
//! describes providers, budgets, and tools, and belongs to the framework.
//! This one describes the *server* — where it listens, what a new thread
//! inherits, and how approvals behave. Keeping them apart means an operator
//! can hand acton-ai's file to a different consumer unchanged, and that
//! Garrison's settings do not have to be accepted upstream to exist.

use crate::error::GarrisonError;
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
    /// Language servers to run, keyed by a name of the operator's choosing.
    pub lsp_servers: std::collections::HashMap<String, LspServerConfig>,
}

/// Listener settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// The Unix socket path. A `--socket` argument overrides it.
    pub socket: PathBuf,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            socket: default_socket(),
        }
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

/// The read-only builtins that never need a human.
///
/// Every one of them only observes. `bash`, `write_file`, `edit_file` and
/// `apply_patch` are deliberately absent: they change the world, so they are
/// exactly what a governed agent asks about.
fn default_auto_approve() -> Vec<String> {
    ["read_file", "glob", "grep", "list_files", "calculate"]
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_file_yields_the_defaults() {
        let config = GarrisonConfig::from_toml("").unwrap();

        assert_eq!(config.approval.timeout_secs, 300);
        assert!(config.approval.auto_approve.contains(&"grep".to_string()));
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
    fn a_missing_file_is_reported_with_its_path() {
        let error = GarrisonConfig::from_file(Path::new("/nonexistent/garrison.toml")).unwrap_err();

        assert!(error.is_configuration());
        assert!(error.to_string().contains("/nonexistent/garrison.toml"));
    }
}
