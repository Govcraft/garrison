//! The settings this service needs beyond the framework's own.
//!
//! These arrive through `acton_service::Config<HooksConfig>`, which means the
//! same file, the same XDG search order, and the same `ACTON_*` environment
//! override the framework already implements. `ACTON_GARRISON_TOKEN` is
//! therefore the way to supply the bearer in a deployment that keeps secrets
//! out of files, with no code here to make that work.
//!
//! Every field is one word for that reason. The framework's env provider is
//! `Env::prefixed("ACTON_").split("_")`, so a `service_token` field would only
//! be reachable as `garrison.service.token`, which is not where it lives, so
//! the variable would be ignored and the file value would quietly win. A
//! single-word name is the difference between an override that works and one
//! that only appears to.
//!
//! Every value is validated at startup rather than at first use. A hook that
//! discovers a missing plane URL on the night of the first enrollment has
//! turned a typo into an outage; refusing to boot turns it into a deploy that
//! fails loudly with the field named.

use serde::{Deserialize, Serialize};

pub use crate::directory::config::{DirectoryConfig, DirectoryMode};

/// The `[garrison]` and `[directory]` sections of `config.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HooksConfig {
    #[serde(default)]
    pub garrison: GarrisonConfig,
    #[serde(default)]
    pub directory: DirectoryConfig,
}

/// Where the control plane is, and what this service presents to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GarrisonConfig {
    /// Origin of the control plane, e.g. `https://plane.agency.gov`. The
    /// `/api/v1` prefix is the framework's and is appended by the client.
    #[serde(default)]
    pub url: String,

    /// Bearer for the `enrollment_service` role. Not a human's token: it is
    /// authorized for four operations and nothing else.
    #[serde(default)]
    pub token: String,

    /// The `iss` an enrollment artifact must carry. A token minted for any
    /// other purpose against the same key is refused on this alone.
    #[serde(default = "default_issuer")]
    pub issuer: String,

    /// How long an install bearer lives, in seconds.
    ///
    /// One word, like every other field here, so `ACTON_GARRISON_LIFETIME`
    /// reaches it. Short on purpose: a daemon re-signs an assertion whenever
    /// its bearer is nearly spent, which costs one round trip a quarter hour
    /// and means a leaked bearer is worth almost nothing. Anything longer is
    /// a standing credential on a workstation, which is the thing the install
    /// key exists to avoid.
    #[serde(default = "default_lifetime")]
    pub lifetime: u64,
}

impl Default for GarrisonConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            token: String::new(),
            issuer: default_issuer(),
            lifetime: default_lifetime(),
        }
    }
}

fn default_issuer() -> String {
    "garrison-enrollment".to_string()
}

const fn default_lifetime() -> u64 {
    900
}

impl GarrisonConfig {
    /// The names of every setting that is missing or blank.
    ///
    /// Returns all of them rather than the first, so one restart reveals the
    /// whole gap instead of one field per attempt.
    #[must_use]
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.url.trim().is_empty() {
            missing.push("garrison.url");
        }
        if self.token.trim().is_empty() {
            missing.push("garrison.token");
        }
        if self.issuer.trim().is_empty() {
            missing.push("garrison.issuer");
        }
        missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured() -> GarrisonConfig {
        GarrisonConfig {
            url: "https://plane.gov".into(),
            token: "v4.local.abc".into(),
            issuer: "garrison-enrollment".into(),
            lifetime: default_lifetime(),
        }
    }

    #[test]
    fn a_fully_configured_section_is_missing_nothing() {
        assert!(configured().missing().is_empty());
    }

    #[test]
    fn the_issuer_has_a_default_so_only_the_two_secrets_must_be_supplied() {
        assert_eq!(
            GarrisonConfig::default().missing(),
            vec!["garrison.url", "garrison.token"]
        );
    }

    #[test]
    fn a_whitespace_only_setting_counts_as_missing() {
        let mut config = configured();
        config.token = "   ".into();
        assert_eq!(config.missing(), vec!["garrison.token"]);
    }

    #[test]
    fn every_gap_is_reported_at_once_not_one_per_restart() {
        let config = GarrisonConfig {
            url: String::new(),
            token: String::new(),
            issuer: String::new(),
            lifetime: default_lifetime(),
        };
        assert_eq!(config.missing().len(), 3);
    }

    #[test]
    fn the_section_deserializes_from_the_flattened_table() {
        let toml = r#"
            [garrison]
            url = "https://plane.gov"
            token = "v4.local.abc"
        "#;
        let parsed: HooksConfig = toml::from_str(toml).expect("section parses");
        assert_eq!(parsed.garrison.url, "https://plane.gov");
        assert_eq!(parsed.garrison.issuer, "garrison-enrollment");
        assert_eq!(
            parsed.garrison.lifetime, 900,
            "an unstated bearer lifetime is fifteen minutes"
        );
        assert_eq!(parsed.directory.mode, DirectoryMode::Off);
    }

    #[test]
    fn the_directory_table_sits_beside_the_garrison_one() {
        let toml = r#"
            [garrison]
            url = "https://plane.gov"
            token = "v4.local.abc"

            [directory]
            mode = "file"
            path = "/etc/garrison/directory.json"
            token = "v4.local.dir"
            organization = "organization_01example"
        "#;
        let parsed: HooksConfig = toml::from_str(toml).expect("section parses");
        assert_eq!(parsed.directory.mode, DirectoryMode::File);
        assert!(parsed.directory.missing().is_empty());
    }
}
