//! Groq login: a Console API key, validated and stored.
//!
//! Groq, like OpenAI, offers an OpenAI‑compatible API. The login flow mirrors
//! Anthropic's: the operator creates a Console key at https://console.groq.com/keys
//! and pastes it when prompted. The key is then validated by a cheap request to
//! `/v1/models` and stored under `~/.config/garrison/groq-key` with mode 0600.

use super::Provider;
use crate::error::GarrisonError;

/// Where to create a key: sign in with the Groq account, mint a key.
pub const CONSOLE_KEYS_URL: &str = "https://console.groq.com/keys";

/// The cheapest authenticated endpoint: lists models, bills nothing.
const MODELS_URL: &str = "https://api.groq.com/openai/v1/models";

/// True for anything shaped like a Groq API key.
fn looks_like_api_key(key: &str) -> bool {
    // Groq keys start with `gsk_` and are longer than a trivial prefix.
    key.starts_with("gsk_") && !key.contains(char::is_whitespace) && key.len() > 20
}

/// Interactive (or piped) login: obtain, validate, and store an API key.
///
/// With `key_stdin`, the key is read from standard input — made for
/// `rbw get groq | garrison-agent login groq --key-stdin`.
/// Otherwise the terminal prompts with echo off.
pub async fn login(key_stdin: bool) -> Result<(), GarrisonError> {
    let key = if key_stdin {
        super::key_from_stdin()?
    } else {
        println!("Garrison authenticates to Groq with a Console API key.");
        println!("(Groq provides OpenAI‑compatible keys; no OAuth flow.)");
        println!();
        println!("  1. Sign in with your Groq account:");
        println!("     {CONSOLE_KEYS_URL}");
        println!("  2. Create a key and paste it below.");
        println!();
        super::open_browser(CONSOLE_KEYS_URL);
        rpassword::prompt_password("Groq API key (input hidden): ").map_err(|error| {
            GarrisonError::configuration("login", format!("could not read the key: {error}"))
        })?
    };
    let key = key.trim();

    if !looks_like_api_key(key) {
        return Err(GarrisonError::configuration(
            "login",
            "that does not look like a Groq API key; Console keys start with 'gsk_'",
        ));
    }

    let models = validate_key(key).await?;
    let path = super::store_key(Provider::Groq, key)?;
    super::report_success(Provider::Groq, &path, &models);
    Ok(())
}

/// Proves the key works by listing models; returns the model IDs.
async fn validate_key(key: &str) -> Result<Vec<String>, GarrisonError> {
    crate::crypto::ensure_provider()?;
    let client = reqwest::Client::new();
    let response = client
        .get(MODELS_URL)
        .bearer_auth(key)
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
        assert!(looks_like_api_key("gsk_abcdefghijklmnopqrstuvwxyz"));
        assert!(!looks_like_api_key("gsk_short"));
        assert!(!looks_like_api_key("hunter2"));
        assert!(!looks_like_api_key("gsk_ with space"));
        assert!(!looks_like_api_key("https://console.groq.com/keys"));
    }
}
