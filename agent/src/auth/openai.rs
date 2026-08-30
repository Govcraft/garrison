//! OpenAI login: OAuth in the browser, an API key out the other end.
//!
//! This is a genuine "sign in with your OpenAI account" flow — the same
//! authorization-code-plus-PKCE dance the Codex CLI performs against
//! `auth.openai.com`, using OpenAI's published public client. The browser
//! opens, the operator signs in, and the local callback server on port 1455
//! receives the code. Two token exchanges later Garrison holds not a
//! session token but a **platform API key** minted for the operator's own
//! organization: OpenAI's token endpoint supports an RFC 8693 token
//! exchange whose `requested_token` is literally `openai-api-key`.
//!
//! The distinction matters. ChatGPT subscription tokens work only against
//! the private Codex backend and are not sanctioned for third-party tools;
//! an org API key is the front door, billed per use, and speaks the same
//! Chat Completions dialect acton-ai's `openai` provider already does. The
//! OAuth here is a convenience — nobody copies a key out of a dashboard —
//! not a billing bypass.
//!
//! `--key-stdin` skips the browser entirely and accepts a pasted platform
//! key, for headless machines and password managers.

use super::Provider;
use crate::error::GarrisonError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::Digest;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// OpenAI's published public client for CLI sign-in (from the open-source
/// Codex CLI). Public in the OAuth sense: there is no secret, PKCE carries
/// the proof.
const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

/// The authorization endpoint the browser is sent to.
const AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";

/// The token endpoint both exchanges POST to.
const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";

/// The registered callback: the port is part of the client registration.
const CALLBACK_PORT: u16 = 1455;
const REDIRECT_URI: &str = "http://localhost:1455/auth/callback";

/// Where a key can be made by hand, for the `--key-stdin` path.
pub const PLATFORM_KEYS_URL: &str = "https://platform.openai.com/api-keys";

/// The cheapest authenticated endpoint: lists models, bills nothing.
const MODELS_URL: &str = "https://api.openai.com/v1/models";

/// How long the browser gets before the login gives up.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// True for anything shaped like an OpenAI platform key.
fn looks_like_api_key(key: &str) -> bool {
    key.starts_with("sk-") && !key.contains(char::is_whitespace) && key.len() > 20
}

/// OAuth (or piped) login: obtain, validate, and store an API key.
///
/// # Errors
///
/// [`GarrisonErrorKind::Configuration`](crate::error::GarrisonErrorKind::Configuration)
/// when the flow is refused, times out, the exchange fails, or the key
/// cannot be validated or stored.
pub async fn login(key_stdin: bool) -> Result<(), GarrisonError> {
    let key = if key_stdin {
        let key = super::key_from_stdin()?;
        if !looks_like_api_key(&key) {
            return Err(GarrisonError::configuration(
                "login",
                format!(
                    "that does not look like an OpenAI API key; \
                     platform keys start with 'sk-' (create one at {PLATFORM_KEYS_URL})"
                ),
            ));
        }
        key
    } else {
        oauth_for_api_key().await?
    };

    let models = validate_key(&key).await?;
    let path = super::store_key(Provider::OpenAI, &key)?;
    super::report_success(Provider::OpenAI, &path, &models);
    Ok(())
}

/// Runs the browser flow end to end and returns the minted API key.
async fn oauth_for_api_key() -> Result<String, GarrisonError> {
    // Bind before opening the browser: if the port is taken there is no
    // point sending the operator through a sign-in that cannot land.
    let listener = TcpListener::bind(("127.0.0.1", CALLBACK_PORT))
        .await
        .map_err(|error| {
            GarrisonError::configuration(
                "login",
                format!(
                    "cannot listen on 127.0.0.1:{CALLBACK_PORT} for the OAuth callback \
                     ({error}); close whatever holds it (another login? Codex?) and retry"
                ),
            )
        })?;

    let verifier = random_token(64)?;
    let state = random_token(32)?;
    let url = authorize_url(&challenge_of(&verifier), &state);

    println!("Sign in with your OpenAI account. If the browser does not open:");
    println!("  {url}");
    println!();
    super::open_browser(&url);

    let code = tokio::time::timeout(CALLBACK_TIMEOUT, wait_for_code(&listener, &state))
        .await
        .map_err(|_| {
            GarrisonError::configuration(
                "login",
                "no sign-in arrived within five minutes; run login again",
            )
        })??;

    crate::crypto::ensure_provider()?;
    let client = reqwest::Client::new();
    let id_token = exchange_code(&client, &code, &verifier).await?;
    exchange_for_api_key(&client, &id_token).await
}

/// A URL-safe random token of `bytes` entropy bytes.
fn random_token(bytes: usize) -> Result<String, GarrisonError> {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).map_err(|error| {
        GarrisonError::configuration("login", format!("no OS randomness for OAuth: {error}"))
    })?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

/// The S256 PKCE challenge for a verifier.
fn challenge_of(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()))
}

/// The full authorization URL the browser visits.
fn authorize_url(challenge: &str, state: &str) -> String {
    let url = url::Url::parse_with_params(
        AUTHORIZE_URL,
        &[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid profile email offline_access"),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("state", state),
            // OpenAI-specific: put the org memberships in the id_token (the
            // API-key exchange needs them) and use the streamlined CLI pages.
            ("id_token_add_organizations", "true"),
            ("codex_cli_simplified_flow", "true"),
            ("originator", "garrison"),
        ],
    )
    .expect("a constant base URL with encoded params must parse");
    url.into()
}

/// Accepts connections until the OAuth callback arrives, answering the
/// browser as it goes; returns the authorization code.
async fn wait_for_code(listener: &TcpListener, state: &str) -> Result<String, GarrisonError> {
    loop {
        let (stream, _) = listener.accept().await.map_err(|error| {
            GarrisonError::configuration("login", format!("callback listener failed: {error}"))
        })?;
        let mut stream = BufReader::new(stream);
        let mut request_line = String::new();
        if stream.read_line(&mut request_line).await.is_err() {
            continue;
        }

        let Some(params) = callback_params(&request_line) else {
            // Favicon probes and stray hits: answer and keep waiting.
            respond(stream.into_inner(), 404, "Not the OAuth callback.").await;
            continue;
        };

        match code_from_params(&params, state) {
            Ok(code) => {
                respond(
                    stream.into_inner(),
                    200,
                    "Signed in. You can close this tab and return to the terminal.",
                )
                .await;
                return Ok(code);
            }
            Err(reason) => {
                respond(stream.into_inner(), 400, &reason).await;
                return Err(GarrisonError::configuration("login", reason));
            }
        }
    }
}

/// Parses an HTTP request line into the callback's query parameters, when
/// it is the callback path at all.
fn callback_params(request_line: &str) -> Option<HashMap<String, String>> {
    let target = request_line.split_whitespace().nth(1)?;
    let url = url::Url::parse("http://localhost")
        .ok()?
        .join(target)
        .ok()?;
    if url.path() != "/auth/callback" {
        return None;
    }
    Some(
        url.query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
    )
}

/// Judges a callback: the code comes out only from a clean, state-matching
/// success.
fn code_from_params(params: &HashMap<String, String>, state: &str) -> Result<String, String> {
    if let Some(error) = params.get("error") {
        let detail = params
            .get("error_description")
            .map(|description| format!(": {description}"))
            .unwrap_or_default();
        return Err(format!("OpenAI refused the sign-in ({error}{detail})"));
    }
    if params.get("state").map(String::as_str) != Some(state) {
        return Err("the callback's state did not match; refusing the code".to_string());
    }
    params
        .get("code")
        .cloned()
        .ok_or_else(|| "the callback carried no authorization code".to_string())
}

/// Writes a minimal HTTP response and closes the connection.
async fn respond(mut stream: TcpStream, status: u16, message: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Garrison</title>\
         <body style=\"font-family: system-ui; margin: 3rem\">\
         <h1>Garrison</h1><p>{message}</p></body>"
    );
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/html; charset=utf-8\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    drop(stream.write_all(response.as_bytes()).await);
    drop(stream.shutdown().await);
}

/// Exchanges the authorization code for tokens; returns the id_token.
async fn exchange_code(
    client: &reqwest::Client,
    code: &str,
    verifier: &str,
) -> Result<String, GarrisonError> {
    let body = post_form(
        client,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", CLIENT_ID),
            ("code_verifier", verifier),
        ],
        "exchanging the sign-in code",
    )
    .await?;
    body.get("id_token")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            GarrisonError::configuration("login", "the token response carried no id_token")
        })
}

/// Exchanges the id_token for a freshly minted platform API key.
async fn exchange_for_api_key(
    client: &reqwest::Client,
    id_token: &str,
) -> Result<String, GarrisonError> {
    let body = post_form(
        client,
        &[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("client_id", CLIENT_ID),
            ("requested_token", "openai-api-key"),
            ("subject_token", id_token),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:id_token",
            ),
        ],
        "minting the API key",
    )
    .await?;
    api_key_from_exchange(&body).ok_or_else(|| {
        GarrisonError::configuration(
            "login",
            format!(
                "the sign-in succeeded but no API key came back — the account may have \
                 no platform organization; create a key at {PLATFORM_KEYS_URL} and use \
                 `garrison-agent login openai --key-stdin`"
            ),
        )
    })
}

/// The minted key out of a token-exchange response.
fn api_key_from_exchange(body: &serde_json::Value) -> Option<String> {
    let key = body.get("access_token")?.as_str()?;
    looks_like_api_key(key).then(|| key.to_string())
}

/// One form POST to the token endpoint, with uniform error wrapping.
async fn post_form(
    client: &reqwest::Client,
    fields: &[(&str, &str)],
    doing: &str,
) -> Result<serde_json::Value, GarrisonError> {
    let response = client
        .post(TOKEN_URL)
        .form(fields)
        .send()
        .await
        .map_err(|error| {
            GarrisonError::configuration("login", format!("{doing} failed: {error}"))
        })?;
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    if !status.is_success() {
        let detail = body
            .get("error_description")
            .or_else(|| body.get("error"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("no detail");
        return Err(GarrisonError::configuration(
            "login",
            format!("{doing} failed: {status} ({detail})"),
        ));
    }
    Ok(body)
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
    use serde_json::json;

    #[test]
    fn the_pkce_challenge_matches_the_rfc_7636_vector() {
        // RFC 7636 appendix B.
        assert_eq!(
            challenge_of("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_authorize_url_carries_the_whole_contract() {
        let url = authorize_url("chal123", "state456");
        for needle in [
            "https://auth.openai.com/oauth/authorize?",
            "response_type=code",
            "client_id=app_EMoamEEZ73f0CkXaXp7hrann",
            "code_challenge=chal123",
            "code_challenge_method=S256",
            "state=state456",
            "id_token_add_organizations=true",
            "originator=garrison",
        ] {
            assert!(url.contains(needle), "missing {needle} in {url}");
        }
    }

    #[test]
    fn only_the_callback_path_yields_parameters() {
        let params = callback_params("GET /auth/callback?code=abc&state=s HTTP/1.1\r\n")
            .expect("the callback must parse");
        assert_eq!(params.get("code").map(String::as_str), Some("abc"));

        assert!(callback_params("GET /favicon.ico HTTP/1.1\r\n").is_none());
        assert!(callback_params("garbage").is_none());
    }

    #[test]
    fn the_code_comes_out_only_from_a_clean_matching_callback() {
        let good: HashMap<String, String> = [("code", "abc"), ("state", "s")]
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .into();
        assert_eq!(code_from_params(&good, "s").expect("must pass"), "abc");

        let wrong_state = code_from_params(&good, "other").expect_err("must refuse");
        assert!(wrong_state.contains("state"));

        let denied: HashMap<String, String> = [
            ("error", "access_denied"),
            ("error_description", "the user said no"),
        ]
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .into();
        let refusal = code_from_params(&denied, "s").expect_err("must refuse");
        assert!(refusal.contains("access_denied"));
        assert!(refusal.contains("the user said no"));

        let empty = HashMap::new();
        assert!(code_from_params(&empty, "s").is_err());
    }

    #[test]
    fn the_api_key_comes_out_of_the_exchange_only_when_key_shaped() {
        let minted = json!({ "access_token": "sk-proj-abcdefghijklmnopqrstuvwxyz" });
        assert_eq!(
            api_key_from_exchange(&minted).expect("must extract"),
            "sk-proj-abcdefghijklmnopqrstuvwxyz"
        );

        // A session JWT is not an API key and must not be stored as one.
        let jwt = json!({ "access_token": "eyJhbGciOiJSUzI1NiIs.payload.sig" });
        assert!(api_key_from_exchange(&jwt).is_none());
        assert!(api_key_from_exchange(&json!({})).is_none());
    }

    #[test]
    fn only_platform_shaped_keys_pass_the_paste_check() {
        assert!(looks_like_api_key("sk-proj-abcdefghijklmnopqrstuvwxyz"));
        assert!(!looks_like_api_key("hunter2"));
        assert!(!looks_like_api_key("sk-short"));
        assert!(!looks_like_api_key("sk-proj-with space inside"));
    }
}
