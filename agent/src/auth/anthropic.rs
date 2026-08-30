//! Anthropic login: a Console API key, validated and stored.
//!
//! Anthropic's terms reserve consumer OAuth (the Claude.ai account login
//! Claude Code uses) for Claude Code and Claude.ai themselves; third-party
//! tools authenticate with a Console API key. So "login" here means: sign in
//! to the Claude Console in a browser, create a key there, and hand it to
//! Garrison once.

use super::Provider;
use crate::error::GarrisonError;

/// Where to create a key: sign in with the Anthropic account, mint a key.
pub const CONSOLE_KEYS_URL: &str = "https://console.anthropic.com/settings/keys";

/// The cheapest authenticated endpoint: lists models, bills nothing.
const MODELS_URL: &str = "https://api.anthropic.com/v1/models";

/// The API version header every Anthropic request must carry.
const ANTHROPIC_VERSION: &str = "2023-06-01";

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
/// `rbw get anthropic | garrison-agent login anthropic --key-stdin`.
/// Otherwise the terminal prompts with echo off.
///
/// # Errors
///
/// [`GarrisonErrorKind::Configuration`](crate::error::GarrisonErrorKind::Configuration)
/// when the key is malformed, the API rejects it, or the file cannot be
/// written.
pub async fn login(key_stdin: bool) -> Result<(), GarrisonError> {
    let key = if key_stdin {
        super::key_from_stdin()?
    } else {
        println!("Garrison authenticates to Anthropic with a Console API key.");
        println!("(Anthropic reserves Claude.ai subscription login for Claude Code itself.)");
        println!();
        println!("  1. Sign in with your Anthropic account:");
        println!("     {CONSOLE_KEYS_URL}");
        println!("  2. Create a key and paste it below.");
        println!();
        super::open_browser(CONSOLE_KEYS_URL);
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
    let path = super::store_key(Provider::Anthropic, key)?;
    super::report_success(Provider::Anthropic, &path, &models);
    Ok(())
}

/// Proves the key works by listing models; returns the model IDs.
async fn validate_key(key: &str) -> Result<Vec<String>, GarrisonError> {
    crate::crypto::ensure_provider()?;
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
    Ok(super::model_ids(&body))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
