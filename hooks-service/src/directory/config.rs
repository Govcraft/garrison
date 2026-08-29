//! The `[directory]` section of `config.toml`.
//!
//! Kept beside the directory code rather than in `config.rs` so the shared
//! file only gains one field. The same rule applies here as there: every key
//! is one word, because the framework's env provider splits `ACTON_*` names
//! on `_`, and `ACTON_DIRECTORY_TOKEN` must land on `directory.token`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Where the directory listing comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DirectoryMode {
    /// No directory. Enrollment admits any registered, active operator.
    #[default]
    Off,
    /// A JSON snapshot on disk. The acceptance path and nothing else.
    File,
    /// Microsoft Graph with a client-credentials app registration.
    Graph,
}

/// The reconciler's settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryConfig {
    /// Which source, if any.
    #[serde(default)]
    pub mode: DirectoryMode,

    /// Bearer for the `directory_service` role. `ACTON_DIRECTORY_TOKEN`.
    #[serde(default)]
    pub token: String,

    /// The `Organization` row this reconciler serves, by id.
    ///
    /// Named rather than discovered: the bearer is tenant-scoped, and the
    /// plane hides tenant-root rows from a tenant-scoped listing (they carry
    /// no tenant of their own), so the sync fetches the one row it was told
    /// about and nothing wider. One reconciler, one organization.
    #[serde(default)]
    pub organization: String,

    /// Seconds between reconciliations.
    #[serde(default = "default_interval")]
    pub interval: u64,

    /// Seconds after which an organization's directory view is stale and
    /// enrollment is refused until the next successful sync. Must be at
    /// least `interval`, or every enrollment between ticks would be refused.
    #[serde(default = "default_staleness")]
    pub staleness: u64,

    /// The largest share of an organization's active operators one
    /// reconciliation may suspend or offboard. A listing that would exceed it
    /// is refused whole, so a wrong group id cannot empty a fleet.
    #[serde(default = "default_fraction")]
    pub fraction: f64,

    /// File mode: the JSON snapshot, an array of directory members.
    #[serde(default)]
    pub path: PathBuf,

    /// Graph mode: the app registration's client id.
    #[serde(default)]
    pub client: String,

    /// Graph mode: the app registration's client secret.
    /// `ACTON_DIRECTORY_SECRET`.
    #[serde(default)]
    pub secret: String,

    /// Graph mode: the token authority.
    #[serde(default = "default_authority")]
    pub authority: String,

    /// Graph mode: the Graph API origin and version.
    #[serde(default = "default_graph")]
    pub graph: String,
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        Self {
            mode: DirectoryMode::Off,
            token: String::new(),
            organization: String::new(),
            interval: default_interval(),
            staleness: default_staleness(),
            fraction: default_fraction(),
            path: PathBuf::new(),
            client: String::new(),
            secret: String::new(),
            authority: default_authority(),
            graph: default_graph(),
        }
    }
}

fn default_interval() -> u64 {
    300
}

fn default_staleness() -> u64 {
    900
}

fn default_fraction() -> f64 {
    0.5
}

fn default_authority() -> String {
    "https://login.microsoftonline.com".to_string()
}

fn default_graph() -> String {
    "https://graph.microsoft.com/v1.0".to_string()
}

impl DirectoryConfig {
    /// Whether a directory is configured at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.mode != DirectoryMode::Off
    }

    /// The names of every setting the chosen mode needs and does not have.
    ///
    /// Returns all of them, so one restart shows the whole gap. `off` needs
    /// nothing and reports nothing, whatever else is set.
    #[must_use]
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        match self.mode {
            DirectoryMode::Off => return missing,
            DirectoryMode::File => {
                if self.path.as_os_str().is_empty() {
                    missing.push("directory.path");
                }
            }
            DirectoryMode::Graph => {
                if self.client.trim().is_empty() {
                    missing.push("directory.client");
                }
                if self.secret.trim().is_empty() {
                    missing.push("directory.secret");
                }
                if self.authority.trim().is_empty() {
                    missing.push("directory.authority");
                }
                if self.graph.trim().is_empty() {
                    missing.push("directory.graph");
                }
            }
        }
        if self.token.trim().is_empty() {
            missing.push("directory.token");
        }
        if self.organization.trim().is_empty() {
            missing.push("directory.organization");
        }
        missing
    }

    /// Every setting whose value is present but cannot be right.
    ///
    /// Separate from `missing` because the fix is different: a missing value
    /// needs supplying, an invalid one needs understanding.
    #[must_use]
    pub fn invalid(&self) -> Vec<String> {
        let mut invalid = Vec::new();
        if !self.enabled() {
            return invalid;
        }
        if self.interval == 0 {
            invalid.push("directory.interval must be greater than zero".to_string());
        }
        if self.staleness < self.interval {
            invalid.push(format!(
                "directory.staleness ({}) must be at least directory.interval ({})",
                self.staleness, self.interval
            ));
        }
        if !(self.fraction > 0.0 && self.fraction <= 1.0) {
            invalid.push(format!(
                "directory.fraction ({}) must be in (0, 1]",
                self.fraction
            ));
        }
        invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_needs_nothing_and_validates_nothing() {
        let config = DirectoryConfig::default();
        assert!(config.missing().is_empty());
        assert!(config.invalid().is_empty());
        assert!(!config.enabled());
    }

    #[test]
    fn file_mode_needs_a_path_and_a_token() {
        let config = DirectoryConfig {
            mode: DirectoryMode::File,
            ..Default::default()
        };
        assert_eq!(
            config.missing(),
            vec!["directory.path", "directory.token", "directory.organization"]
        );
    }

    #[test]
    fn graph_mode_needs_the_app_registration_and_a_token() {
        let config = DirectoryConfig {
            mode: DirectoryMode::Graph,
            ..Default::default()
        };
        assert_eq!(
            config.missing(),
            vec![
                "directory.client",
                "directory.secret",
                "directory.token",
                "directory.organization"
            ]
        );
    }

    #[test]
    fn a_staleness_shorter_than_the_interval_is_invalid() {
        let config = DirectoryConfig {
            mode: DirectoryMode::File,
            interval: 600,
            staleness: 300,
            ..Default::default()
        };
        let invalid = config.invalid();
        assert_eq!(invalid.len(), 1);
        assert!(invalid[0].contains("staleness"));
    }

    #[test]
    fn a_zero_interval_and_a_bad_fraction_are_both_reported() {
        let config = DirectoryConfig {
            mode: DirectoryMode::Graph,
            interval: 0,
            staleness: 0,
            fraction: 1.5,
            ..Default::default()
        };
        assert_eq!(config.invalid().len(), 2);
    }

    #[test]
    fn the_section_deserializes_with_lowercase_modes() {
        let toml = r#"
            mode = "file"
            path = "/tmp/directory.json"
            token = "v4.local.x"
            organization = "organization_01example"
            interval = 10
            staleness = 60
        "#;
        let parsed: DirectoryConfig = toml::from_str(toml).expect("parses");
        assert_eq!(parsed.mode, DirectoryMode::File);
        assert_eq!(parsed.path, PathBuf::from("/tmp/directory.json"));
        assert_eq!(parsed.fraction, 0.5);
        assert!(parsed.missing().is_empty());
        assert!(parsed.invalid().is_empty());
    }
}
