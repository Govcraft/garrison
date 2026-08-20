//! Logging Garrison into its cloud model providers.
//!
//! Both vendors end in the same place — a per-provider key file under
//! `~/.config/garrison/`, mode `0600`, that `acton-ai.toml` names through
//! `api_key_file` — but they get there differently, each by the most
//! account-shaped path its vendor sanctions:
//!
//! - **Anthropic** ([`anthropic`]): consumer OAuth is reserved for Claude
//!   Code and Claude.ai, so login walks the operator to the Claude Console
//!   to mint a key and paste it once.
//! - **OpenAI** ([`openai`]): a real OAuth sign-in. The browser opens
//!   `auth.openai.com`, the operator signs in with their OpenAI account,
//!   and the flow's token exchange mints a platform API key for their own
//!   organization — the key lands here without ever being seen or pasted.
//!
//! The key never appears in Garrison's config files, environment, or logs —
//! the config names a *path*, and the file behind it is owner-only.

pub mod anthropic;
pub mod groq;
pub mod openai;

use crate::error::GarrisonError;
use std::path::PathBuf;

/// The providers Garrison can hold credentials for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// Anthropic (Claude models), keyed by a Console API key.
    Anthropic,
    /// OpenAI (GPT models), keyed via OAuth or a pasted platform key.
    OpenAI,
    /// Groq (LLM provider), keyed by a Console API key.
    Groq,
}

impl Provider {
    /// The key file's name under the Garrison config directory.
    const fn key_file_name(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic-key",
            Self::OpenAI => "openai-key",
            Self::Groq => "groq-key",
        }
    }

    /// The name used in messages to the operator.
    const fn display_name(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::OpenAI => "OpenAI",
            Self::Groq => "Groq",
        }
    }
}

/// Where a provider's key is stored, mirroring `garrison.toml`'s own home.
#[must_use]
pub fn key_file_path(provider: Provider) -> PathBuf {
    config_dir(
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
    .join(provider.key_file_name())
}

/// The `~/.config/garrison` directory, from explicit inputs so it tests.
fn config_dir(xdg_config_home: Option<PathBuf>, home: Option<PathBuf>) -> PathBuf {
    match (xdg_config_home, home) {
        (Some(xdg), _) if !xdg.as_os_str().is_empty() => xdg.join("garrison"),
        (_, Some(home)) => home.join(".config").join("garrison"),
        _ => PathBuf::from(".config").join("garrison"),
    }
}

/// Signs in to one provider and stores the resulting key.
///
/// # Errors
///
/// [`GarrisonErrorKind::Configuration`](crate::error::GarrisonErrorKind::Configuration)
/// when the key cannot be obtained, fails validation, or cannot be stored.
pub async fn login(provider: Provider, key_stdin: bool) -> Result<(), GarrisonError> {
    match provider {
        Provider::Anthropic => anthropic::login(key_stdin).await,
        Provider::OpenAI => openai::login(key_stdin).await,
        Provider::Groq => groq::login(key_stdin).await,
    }
}

/// Removes a provider's stored key.
///
/// # Errors
///
/// [`GarrisonErrorKind::Configuration`](crate::error::GarrisonErrorKind::Configuration)
/// when the file exists but cannot be removed.
pub fn logout(provider: Provider) -> Result<(), GarrisonError> {
    let path = key_file_path(provider);
    match std::fs::remove_file(&path) {
        Ok(()) => {
            println!("Removed {}.", path.display());
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("No stored key at {}; nothing to do.", path.display());
            Ok(())
        }
        Err(error) => Err(GarrisonError::configuration(
            path.display().to_string(),
            format!("could not be removed: {error}"),
        )),
    }
}

/// Reads a key from standard input, for piping out of a password manager.
fn key_from_stdin() -> Result<String, GarrisonError> {
    use std::io::Read;
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|error| {
            GarrisonError::configuration("login", format!("could not read stdin: {error}"))
        })?;
    Ok(buffer.trim().to_string())
}

/// Writes a key with owner-only permissions, creating the directory.
fn store_key(provider: Provider, key: &str) -> Result<PathBuf, GarrisonError> {
    let path = key_file_path(provider);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            GarrisonError::configuration(
                parent.display().to_string(),
                format!("could not be created: {error}"),
            )
        })?;
    }
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(key.as_bytes())?;
        file.write_all(b"\n")?;
        // `mode` only applies at creation; an existing file keeps its old
        // permissions unless corrected.
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
    };
    write().map_err(|error| {
        GarrisonError::configuration(
            path.display().to_string(),
            format!("could not be written: {error}"),
        )
    })?;
    Ok(path)
}

/// Announces a stored, validated key and what it can reach.
fn report_success(provider: Provider, path: &std::path::Path, models: &[String]) {
    println!(
        "{} login verified. The account can use, among others:",
        provider.display_name()
    );
    for model in models.iter().take(4) {
        println!("  - {model}");
    }
    println!("Key stored at {} (mode 0600).", path.display());
    println!("Restart the daemon to start using it: garrison-agent serve");
}

/// Pulls the model IDs out of a `/v1/models` response; both vendors use
/// the same `data: [{id}]` shape.
fn model_ids(body: &serde_json::Value) -> Vec<String> {
    body.get("data")
        .and_then(serde_json::Value::as_array)
        .map(|models| {
            models
                .iter()
                .filter_map(|model| model.get("id").and_then(serde_json::Value::as_str))
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Best-effort browser launch; failure is silent because the URL is printed.
fn open_browser(url: &str) {
    drop(
        std::process::Command::new("xdg-open")
            .arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_key_lands_under_xdg_config_home_when_set() {
        let dir = config_dir(Some(PathBuf::from("/xdg")), Some(PathBuf::from("/home/u")));
        assert_eq!(dir, PathBuf::from("/xdg/garrison"));
    }

    #[test]
    fn the_key_falls_back_to_dot_config_under_home() {
        let dir = config_dir(None, Some(PathBuf::from("/home/u")));
        assert_eq!(dir, PathBuf::from("/home/u/.config/garrison"));

        let empty_xdg = config_dir(Some(PathBuf::new()), Some(PathBuf::from("/home/u")));
        assert_eq!(empty_xdg, PathBuf::from("/home/u/.config/garrison"));
    }

    #[test]
    fn each_provider_keeps_its_own_key_file() {
        assert_ne!(
            Provider::Anthropic.key_file_name(),
            Provider::OpenAI.key_file_name()
        );
    }

    #[test]
    fn model_ids_come_out_of_a_models_response() {
        let body = json!({
            "data": [
                { "id": "claude-sonnet-5", "display_name": "Claude Sonnet 5" },
                { "id": "gpt-5.6-terra" },
            ],
            "has_more": false,
        });
        assert_eq!(model_ids(&body), vec!["claude-sonnet-5", "gpt-5.6-terra"]);
        assert!(model_ids(&json!({})).is_empty());
    }
}
