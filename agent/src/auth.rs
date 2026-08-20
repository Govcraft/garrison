//! Logging Garrison into Anthropic.
//!
//! Anthropic's terms reserve consumer OAuth (the Claude.ai account login
//! Claude Code uses) for Claude Code and Claude.ai themselves; third-party
//! tools authenticate with a Console API key. So "login" here means: sign in
//! to the Claude Console in a browser, create a key there, and hand it to
//! Garrison once. Garrison validates the key against the live API, stores it
//! at [`key_file_path`] with owner-only permissions, and the `claude`
//! provider in `acton-ai.toml` reads it from that file on every launch via
//! acton-ai's `api_key_file`.
//!
//! The key never appears in Garrison's config files, environment, or logs —
//! the config names a *path*, and the file behind it is `0600`.

use crate::error::GarrisonError;
use std::io::Read;
use std::path::PathBuf;

/// Where to create a key: sign in with the Anthropic account, mint a key.
pub const CONSOLE_KEYS_URL: &str = "https://console.anthropic.com/settings/keys";

/// The cheapest authenticated endpoint: lists models, bills nothing.
const MODELS_URL: &str = "https://api.anthropic.com/v1/models";

/// The API version header every Anthropic request must carry.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Where the key is stored, mirroring `garrison.toml`'s own search home.
#[must_use]
pub fn key_file_path() -> PathBuf {
    config_dir(
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
    .join("anthropic-key")
}

/// The `~/.config/garrison` directory, from explicit inputs so it tests.
fn config_dir(xdg_config_home: Option<PathBuf>, home: Option<PathBuf>) -> PathBuf {
    match (xdg_config_home, home) {
        (Some(xdg), _) if !xdg.as_os_str().is_empty() => xdg.join("garrison"),
        (_, Some(home)) => home.join(".config").join("garrison"),
        _ => PathBuf::from(".config").join("garrison"),
    }
}

/// True for anything shaped like an Anthropic API key.
///
/// Console keys start with `sk-ant-`; a paste that does not is almost always
/// a stray clipboard (a URL, an OAuth token, a password), so the prompt
/// rejects it before bothering the API.
fn looks_like_api_key(key: &str) -> bool {
    key.starts_with("sk-ant-") && !key.contains(char::is_whitespace) && key.len() > 20
}

/// Interactive (or piped) login: obtain, validate, and store an API key.
///
/// With `key_stdin`, the key is read from standard input — made for
/// `rbw get anthropic | garrison-agent login --key-stdin`. Otherwise the
/// terminal prompts with echo off.
///
/// # Errors
///
/// [`GarrisonErrorKind::Configuration`](crate::error::GarrisonErrorKind::Configuration)
/// when the key is malformed, the API rejects it, or the file cannot be
/// written.
pub async fn login(key_stdin: bool) -> Result<(), GarrisonError> {
    let key = if key_stdin {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|error| {
                GarrisonError::configuration("login", format!("could not read stdin: {error}"))
            })?;
        buffer.trim().to_string()
    } else {
        println!("Garrison authenticates to Anthropic with a Console API key.");
        println!("(Anthropic reserves Claude.ai subscription login for Claude Code itself.)");
        println!();
        println!("  1. Sign in with your Anthropic account:");
        println!("     {CONSOLE_KEYS_URL}");
        println!("  2. Create a key and paste it below.");
        println!();
        open_browser(CONSOLE_KEYS_URL);
        rpassword::prompt_password("Anthropic API key (input hidden): ").map_err(|error| {
            GarrisonError::configuration("login", format!("could not read the key: {error}"))
        })?
    };
    let key = key.trim();

    if !looks_like_api_key(key) {
        return Err(GarrisonError::configuration(
            "login",
            "that does not look like an Anthropic API key; Console keys start with 'sk-ant-'",
        ));
    }

    let models = validate_key(key).await?;
    store_key(key)?;

    println!("Login verified. The account can use, among others:");
    for model in models.iter().take(4) {
        println!("  - {model}");
    }
    println!("Key stored at {} (mode 0600).", key_file_path().display());
    println!("Restart the daemon to start using it: garrison-agent serve");
    Ok(())
}

/// Removes the stored key.
///
/// # Errors
///
/// [`GarrisonErrorKind::Configuration`](crate::error::GarrisonErrorKind::Configuration)
/// when the file exists but cannot be removed.
pub fn logout() -> Result<(), GarrisonError> {
    let path = key_file_path();
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

/// Proves the key works by listing models; returns the Claude model IDs.
async fn validate_key(key: &str) -> Result<Vec<String>, GarrisonError> {
    let client = reqwest::Client::new();
    let response = client
        .get(MODELS_URL)
        .header("x-api-key", key)
        .header("anthropic-version", ANTHROPIC_VERSION)
        .send()
        .await
        .map_err(|error| {
            GarrisonError::configuration("login", format!("could not reach the API: {error}"))
        })?;

    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(GarrisonError::configuration(
            "login",
            "the API rejected the key; check it was copied whole and is not disabled",
        ));
    }
    if !status.is_success() {
        return Err(GarrisonError::configuration(
            "login",
            format!("the API answered {status} while validating the key"),
        ));
    }

    let body: serde_json::Value = response.json().await.map_err(|error| {
        GarrisonError::configuration("login", format!("unreadable models response: {error}"))
    })?;
    Ok(model_ids(&body))
}

/// Pulls the model IDs out of a `/v1/models` response.
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

/// Writes the key with owner-only permissions, creating the directory.
fn store_key(key: &str) -> Result<(), GarrisonError> {
    let path = key_file_path();
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
    })
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
    fn only_console_shaped_keys_pass_the_paste_check() {
        assert!(looks_like_api_key(
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        ));
        assert!(!looks_like_api_key("sk-ant-short"));
        assert!(!looks_like_api_key("hunter2"));
        assert!(!looks_like_api_key("sk-ant-api03-with whitespace inside"));
        assert!(!looks_like_api_key(
            "https://console.anthropic.com/settings/keys"
        ));
    }

    #[test]
    fn model_ids_come_out_of_a_models_response() {
        let body = json!({
            "data": [
                { "id": "claude-sonnet-5", "display_name": "Claude Sonnet 5" },
                { "id": "claude-opus-5" },
            ],
            "has_more": false,
        });
        assert_eq!(model_ids(&body), vec!["claude-sonnet-5", "claude-opus-5"]);
        assert!(model_ids(&json!({})).is_empty());
    }
}
