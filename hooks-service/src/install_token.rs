//! `POST /api/v1/install/token` — the one authenticated path from a daemon
//! to the control plane.
//!
//! A `garrison-agent` daemon holds a private key and nothing else. It cannot
//! present a console bearer (there is no human at 03:00), and it must not hold
//! a long-lived one (a file on a workstation is a file an attacker copies).
//! So it signs a 120-second assertion, this route verifies the signature
//! against the public half the plane recorded at enrollment, and answers with
//! a 15-minute bearer scoped to that install's organization. Every other
//! Garrison subsystem — policy pull, seat check, audit shipping — spends that
//! bearer and never mints one.
//!
//! # Why the route is public and still authenticated
//!
//! `[token] public_paths` exempts exactly this path from the framework's
//! bearer middleware, because a daemon arriving here has no bearer by
//! definition. The exemption is a *prefix* match, so the path is deliberately
//! one no other route shares. Authentication is not skipped; it is moved into
//! [`adjudicate_assertion`], which is stricter than a bearer check: a replayed
//! request fails, an expired one fails, and a revoked credential fails on the
//! plane's own row rather than on a token that is still cryptographically
//! valid.
//!
//! # Where the decision lives
//!
//! [`adjudicate_assertion`] is pure: a clock reading, the request body, and
//! the two rows in, a [`Grant`] or a [`Refusal`] out. It performs no I/O, so
//! every branch below has a test that needs neither a database nor a socket.
//! The handler around it does three things the adjudicator cannot: it fetches
//! the rows, it consumes the nonce, and it mints. Replay is the one check that
//! is not in the pure function, because "have I seen this before" is by
//! construction a fact about state; it lives in [`NonceLedger`], an actor, so
//! there is no lock in a request path.
//!
//! # What a refusal says
//!
//! 401 for anything about the assertion: a bad signature, a stale or
//! future-dated window, a replayed nonce, a credential id nobody has heard
//! of. 403 for a credential or install the plane knows and has taken out of
//! service. The distinction is the daemon's: a 401 is worth one retry with a
//! fresh assertion, a 403 never is, and a daemon that treated them alike
//! would hammer the plane for a machine somebody deliberately quarantined.
//! 400 is reserved for a body that is not a request at all, which no daemon
//! sends.

use std::collections::HashMap;
use std::sync::Arc;

use acton_reactive::prelude::{
    acton_actor, acton_message, ActorHandleInterface, Idle, ManagedActor, Reply, Request,
};
use acton_service::auth::config::{PasetoGenerationConfig, TokenGenerationConfig};
use acton_service::auth::tokens::ClaimsBuilder;
use acton_service::auth::{PasetoGenerator, TokenGenerator};
use acton_service::error::Error;
use acton_service::extensions::ActorExtension;
use acton_service::prelude::{
    post, AppState, Extension, HeaderMap, IntoResponse as _, Json, Response, Router, State,
    StatusCode,
};
use chrono::{DateTime, SecondsFormat, TimeZone as _, Utc};
use garrison_wire::{
    verify_assertion, InstallAssertion, TokenGrant, TokenRequest, MAX_ASSERTION_WINDOW_SECS,
    MIN_NONCE_LEN,
};
use serde_json::json;

use crate::plane::{AgentInstallRow, InstallCredentialRow, Plane};

/// The path the route mounts at, and the one `public_paths` must exempt.
///
/// Named as a constant because it appears in three places that must agree:
/// the router, the shipped `config.toml`, and the test that asserts the
/// exemption is exact.
pub const ROUTE: &str = "/install/token";

/// The full path as a client sees it, base path and version included.
pub const PUBLIC_PATH: &str = "/api/v1/install/token";

/// How far the clocks at the two ends may disagree, in seconds.
const SKEW_SECS: i64 = 30;

/// The credential kind this exchange can verify.
const ED25519: &str = "ed25519";

/// Install states that end a credential's usefulness.
const DEAD_INSTALL: [&str; 2] = ["quarantined", "retired"];

/// What the adjudicator concluded when it said yes.
///
/// Everything the minting step needs, and nothing it does not: no row, no
/// public key, no clock. A `Grant` cannot be turned back into an assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The `AgentInstall` row the bearer will speak for.
    pub install: String,
    /// The `Organization` that install belongs to, which becomes the bearer's
    /// tenant chain.
    pub organization: String,
    /// The `InstallCredential` row that proved it.
    pub credential: String,
    /// The nonce to consume, so this assertion cannot be replayed.
    pub nonce: String,
    /// When the assertion expires, which is when its nonce may be forgotten.
    pub nonce_expires_at: i64,
}

/// Why an exchange did not happen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The HTTP status this maps to.
    pub status: u16,
    /// A stable machine-readable reason.
    pub code: &'static str,
    /// What an operator reading a log needs to know.
    pub message: String,
}

impl Refusal {
    /// The assertion did not prove anything. Worth one retry.
    fn unauthenticated(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: 401,
            code,
            message: message.into(),
        }
    }

    /// The plane knows this identity and has withdrawn it. Never retry.
    fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: 403,
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.status, self.code, self.message)
    }
}

/// Decides whether an assertion earns a bearer.
///
/// Pure. `now` is Unix seconds, `credential` and `install` are what the plane
/// answered for the ids in `body` — `None` meaning no such row, or none this
/// service may see, which are the same refusal.
///
/// The order of the checks is the order of increasing disclosure: a caller
/// gets "unknown credential" before it can learn anything about a real one,
/// and every negative answer costs the same lookups.
///
/// Replay is *not* checked here; see [`NonceLedger`] and the module docs.
///
/// # Errors
///
/// A [`Refusal`] carrying the status the handler will return.
pub fn adjudicate_assertion(
    now: i64,
    body: &TokenRequest,
    credential: Option<&InstallCredentialRow>,
    install: Option<&AgentInstallRow>,
) -> Result<Grant, Refusal> {
    let Some(credential) = credential else {
        return Err(Refusal::unauthenticated(
            "unknown_credential",
            "no such install credential",
        ));
    };

    if credential.credential_kind != ED25519 {
        return Err(Refusal::forbidden(
            "unsupported_credential_kind",
            format!(
                "credential {} is '{}'; this exchange verifies '{ED25519}' only",
                credential.credential_id, credential.credential_kind
            ),
        ));
    }
    if credential.status != "active" {
        return Err(Refusal::forbidden(
            "credential_rejected",
            format!(
                "credential {} is '{}', not 'active'",
                credential.credential_id, credential.status
            ),
        ));
    }

    let Some(install) = install else {
        // The credential names an install the plane will not show us. Not the
        // caller's fault to fix, and not a fact worth confirming either.
        return Err(Refusal::unauthenticated(
            "unknown_credential",
            "no such install credential",
        ));
    };
    if DEAD_INSTALL.contains(&install.status.as_str()) {
        return Err(Refusal::forbidden(
            "install_not_active",
            format!("install {} is '{}'", install.install_id, install.status),
        ));
    }

    let assertion = verify_assertion(&credential.public_key, body).map_err(|error| {
        Refusal::unauthenticated("assertion_rejected", format!("assertion rejected: {error}"))
    })?;

    if assertion.install_id != credential.install {
        return Err(Refusal::unauthenticated(
            "assertion_rejected",
            "the assertion names an install the credential does not belong to",
        ));
    }
    check_window(now, &assertion)?;

    Ok(Grant {
        install: install.id.clone(),
        organization: install.organization.clone(),
        credential: credential.id.clone(),
        nonce: assertion.nonce,
        nonce_expires_at: assertion.exp,
    })
}

/// The freshness rules, separated so each has a name in a failure message.
fn check_window(now: i64, assertion: &InstallAssertion) -> Result<(), Refusal> {
    if assertion.exp <= assertion.iat {
        return Err(Refusal::unauthenticated(
            "assertion_expired",
            "the assertion expires no later than it was issued",
        ));
    }
    if assertion.exp - assertion.iat > MAX_ASSERTION_WINDOW_SECS {
        return Err(Refusal::unauthenticated(
            "assertion_window",
            format!(
                "an assertion may be valid for at most {MAX_ASSERTION_WINDOW_SECS}s, this one claims {}s",
                assertion.exp - assertion.iat
            ),
        ));
    }
    if now < assertion.iat - SKEW_SECS {
        return Err(Refusal::unauthenticated(
            "assertion_future",
            "the assertion is dated further in the future than clock skew allows",
        ));
    }
    if now > assertion.exp + SKEW_SECS {
        return Err(Refusal::unauthenticated(
            "assertion_expired",
            "the assertion has expired",
        ));
    }
    if assertion.nonce.chars().count() < MIN_NONCE_LEN {
        return Err(Refusal::unauthenticated(
            "assertion_nonce",
            format!("a nonce must be at least {MIN_NONCE_LEN} characters"),
        ));
    }
    Ok(())
}

// =============================================================================
// Replay
// =============================================================================

/// Offers a nonce to the ledger; the reply is whether it was new.
#[acton_message]
pub struct Consume {
    /// The nonce the assertion carried.
    pub nonce: String,
    /// Its assertion's `exp`, after which it can be forgotten.
    pub expires_at: i64,
    /// The adjudicator's clock reading, so the ledger needs none of its own.
    pub now: i64,
}

/// `true` when the nonce had not been seen.
#[acton_message]
#[derive(PartialEq, Eq)]
pub struct Consumed(pub bool);

impl Request for Consume {
    type Response = Consumed;
}

/// Every nonce still inside its assertion's window.
///
/// An actor rather than a mutex because the alternative in a request handler
/// is a lock held across a decision, and because this is exactly the shape
/// acton-service's `with_actor` exists for. Entries are dropped as they
/// expire, on the way through [`Consume`], so the ledger never holds more
/// than one assertion window's worth of traffic and needs no timer.
///
/// A supervised restart empties it. That is a bounded exposure rather than a
/// hole: an assertion outside its 120-second window is refused by
/// [`check_window`] whether or not its nonce is remembered, so the worst a
/// restart permits is one replay of an assertion made in the last two
/// minutes, by somebody who already has it.
#[acton_actor]
pub struct NonceLedger {
    seen: HashMap<String, i64>,
}

impl ActorExtension for NonceLedger {
    fn configure(actor: &mut ManagedActor<Idle, Self>) {
        actor.mutate_on::<Consume>(|actor, envelope| {
            let message = envelope.message().clone();
            let fresh = consume(&mut actor.model.seen, &message);
            let reply = envelope.reply_envelope();
            Reply::pending(async move { reply.send(Consumed(fresh)).await })
        });
    }
}

/// Records a nonce and drops the expired ones. Pure over its map.
///
/// Returns `false` if the nonce was already there, which is a replay.
fn consume(seen: &mut HashMap<String, i64>, message: &Consume) -> bool {
    seen.retain(|_, expires_at| *expires_at > message.now);
    seen.insert(message.nonce.clone(), message.expires_at)
        .is_none()
}

// =============================================================================
// The route
// =============================================================================

/// Everything the handler needs that does not change between requests.
///
/// Built once at startup so a request never reads a file or parses a key.
pub struct Exchange {
    plane: Plane,
    generator: PasetoGenerator,
    lifetime: i64,
}

impl std::fmt::Debug for Exchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exchange")
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

impl Exchange {
    /// Builds the exchange against the plane's own signing key.
    ///
    /// `key_path` is the `[token] key_path` this service already validates
    /// inbound hook credentials with: minting and verifying against the same
    /// key is what makes the bearer indistinguishable from one
    /// `schemaforge token generate` produced.
    ///
    /// # Errors
    ///
    /// [`Error::ValidationError`] when the key cannot be read or is not a
    /// 32-byte v4.local key, which is a deployment fault and must stop the
    /// service rather than surface as a 500 on the first enrollment.
    pub fn new(
        plane: Plane,
        key_path: std::path::PathBuf,
        issuer: String,
        lifetime: u64,
    ) -> Result<Self, Error> {
        let lifetime = i64::try_from(lifetime).unwrap_or(i64::MAX);
        let generator = PasetoGenerator::new(
            &PasetoGenerationConfig {
                version: "v4".to_string(),
                purpose: "local".to_string(),
                key_path,
                issuer: Some(issuer),
                audience: None,
            },
            &TokenGenerationConfig {
                access_token_lifetime_secs: lifetime,
                issuer: None,
                audience: None,
                include_jti: true,
            },
        )
        .map_err(|error| Error::ValidationError(format!("install token key: {error}")))?;
        Ok(Self {
            plane,
            generator,
            lifetime,
        })
    }

    /// Mints the bearer a grant earned.
    ///
    /// `sub` is `install:{id}` rather than the bare id so a log line says what
    /// kind of principal acted without a lookup, and so an install can never
    /// collide with a console user's subject.
    fn mint(&self, grant: &Grant, now: i64) -> Result<TokenGrant, Error> {
        let claims = ClaimsBuilder::new()
            .subject(format!("install:{}", grant.install))
            .roles(["operator"])
            .custom_claim(
                "tenant_chain",
                json!([{ "schema": "Organization", "entity_id": grant.organization }]),
            )
            .custom_claim("install", json!(grant.install))
            .custom_claim("credential_id", json!(grant.credential))
            .build()
            .map_err(|error| Error::Internal(format!("claims: {error}")))?;
        let token = self
            .generator
            .generate_token(&claims)
            .map_err(|error| Error::Internal(format!("mint: {error}")))?;
        Ok(TokenGrant {
            token,
            expires_at: rfc3339(now + self.lifetime),
            install: grant.install.clone(),
            organization: grant.organization.clone(),
        })
    }
}

/// Mounts the exchange on a versioned router.
///
/// One route, and the base path is the caller's: see
/// [`PUBLIC_PATH`] for the string `public_paths` must carry.
pub fn routes(exchange: Arc<Exchange>) -> Router<AppState> {
    Router::new()
        .route(ROUTE, post(exchange_token))
        .layer(Extension(exchange))
}

/// The handler: fetch, adjudicate, consume, mint.
///
/// `headers` is read for one thing only, the forwarded client address, and it
/// is taken before the body so axum's extractor ordering holds: `Json` must
/// come last because it consumes the request.
async fn exchange_token(
    State(state): State<AppState>,
    Extension(exchange): Extension<Arc<Exchange>>,
    headers: HeaderMap,
    Json(body): Json<TokenRequest>,
) -> Response {
    let now = Utc::now().timestamp();
    let from = client_address(&headers);

    let credential = match looked_up(
        exchange.plane.install_credential(&body.credential_id).await,
        "credential",
    ) {
        Ok(row) => row,
        Err(refusal) => return refused(&refusal),
    };
    let install = match credential.as_ref() {
        Some(credential) => {
            match looked_up(
                exchange.plane.agent_install(&credential.install).await,
                "install",
            ) {
                Ok(row) => row,
                Err(refusal) => return refused(&refusal),
            }
        }
        None => None,
    };

    let grant = match adjudicate_assertion(now, &body, credential.as_ref(), install.as_ref()) {
        Ok(grant) => grant,
        Err(refusal) => {
            tracing::info!(credential = %body.credential_id, %refusal, "install token refused");
            return refused(&refusal);
        }
    };

    match consume_nonce(&state, &grant, now).await {
        Ok(true) => {}
        Ok(false) => {
            let refusal =
                Refusal::unauthenticated("assertion_replayed", "this assertion has been used");
            tracing::warn!(install = %grant.install, %refusal, "install token refused");
            return refused(&refusal);
        }
        Err(refusal) => return refused(&refusal),
    }

    let minted = match exchange.mint(&grant, now) {
        Ok(minted) => minted,
        Err(error) => {
            tracing::error!(%error, "the install bearer could not be minted");
            return refused(&Refusal {
                status: 500,
                code: "mint_failed",
                message: "the bearer could not be minted".to_string(),
            });
        }
    };

    record_use(&exchange.plane, credential.as_ref(), now, from.as_deref()).await;

    tracing::info!(
        install = %grant.install,
        organization = %grant.organization,
        expires_at = %minted.expires_at,
        "issued an install bearer"
    );
    (StatusCode::OK, Json(minted)).into_response()
}

/// Sorts a row lookup into "there is no such row" and "the plane is not
/// answering".
///
/// The distinction is not cosmetic. A daemon can put anything at all in
/// `credential_id`, and the plane rejects a row id that is not even
/// well-formed with a 400 or a 422 before it looks anything up. Reporting
/// that as `plane_unavailable` would tell an operator their control plane is
/// down because somebody typed a credential id wrong, and would tell the
/// daemon to keep retrying something that will never succeed. Anything the
/// caller's own input can provoke is an absent row; a transport failure, a
/// 5xx, or a refusal of *this service's* bearer is the plane not answering,
/// and is a 503 that says so.
fn looked_up<T>(
    result: Result<Option<T>, crate::plane::PlaneError>,
    what: &'static str,
) -> Result<Option<T>, Refusal> {
    match result {
        Ok(row) => Ok(row),
        Err(error) if caller_provoked(&error) => {
            tracing::debug!(%error, "the plane would not look up a {what} the caller named");
            Ok(None)
        }
        Err(error) => {
            tracing::warn!(%error, "the plane did not answer a {what} lookup");
            Err(Refusal {
                status: 503,
                code: "plane_unavailable",
                message: "the control plane could not be reached".to_string(),
            })
        }
    }
}

/// Whether a failed lookup is explained entirely by what the caller sent.
fn caller_provoked(error: &crate::plane::PlaneError) -> bool {
    let crate::plane::PlaneError::Client(client) = error else {
        return false;
    };
    client
        .as_api()
        .is_some_and(|api| matches!(api.status().as_u16(), 400 | 404 | 422))
}

/// Asks the ledger whether this nonce is new, failing closed if it cannot.
async fn consume_nonce(state: &AppState, grant: &Grant, now: i64) -> Result<bool, Refusal> {
    let Some(ledger) = state.actor::<NonceLedger>() else {
        tracing::error!("the nonce ledger is not registered; refusing every exchange");
        return Err(Refusal {
            status: 503,
            code: "replay_guard_unavailable",
            message: "the replay guard is unavailable".to_string(),
        });
    };
    match ledger
        .ask(Consume {
            nonce: grant.nonce.clone(),
            expires_at: grant.nonce_expires_at,
            now,
        })
        .await
    {
        Ok(Consumed(fresh)) => Ok(fresh),
        Err(error) => {
            // A guard that cannot answer has not said this nonce is new.
            tracing::error!(?error, "the nonce ledger did not answer");
            Err(Refusal {
                status: 503,
                code: "replay_guard_unavailable",
                message: "the replay guard is unavailable".to_string(),
            })
        }
    }
}

/// The address the exchange was reached from, when a proxy said so.
///
/// Pure over the headers. There is no socket peer to fall back on: the
/// service is built by `ServiceBuilder`, which does not install axum's
/// `ConnectInfo`, and in every deployment worth recording an address for the
/// daemon reaches this route through a reverse proxy anyway. `None` means the
/// column is left alone rather than filled with the proxy's own address or a
/// placeholder, because an investigator reading `last_used_from` must be able
/// to trust it.
///
/// The first entry of `x-forwarded-for` is the client; the rest are proxies.
/// Truncated to what the column holds so a forged header cannot make the
/// PATCH fail and cost the daemon nothing but a log line.
fn client_address(headers: &HeaderMap) -> Option<String> {
    /// `InstallCredential.last_used_from` is `text(max: 45)`, the textual
    /// maximum for an IPv6 address.
    const MAX: usize = 45;

    let value = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
        })?
        .trim();

    (!value.is_empty()).then(|| value.chars().take(MAX).collect())
}

/// Notes that a credential was spent. Best effort by design.
///
/// A failure here costs an audit detail, and refusing a daemon that already
/// proved itself because a bookkeeping PATCH lost a race would cost it a turn.
/// The counter is written from the row this request read, so a concurrent
/// exchange can lose an increment; the timestamp, which is what an
/// investigator actually reads, cannot.
async fn record_use(
    plane: &Plane,
    credential: Option<&InstallCredentialRow>,
    now: i64,
    from: Option<&str>,
) {
    let Some(credential) = credential else {
        return;
    };
    let mut fields: std::collections::BTreeMap<String, serde_json::Value> = [
        ("last_used_at".to_string(), json!(rfc3339(now))),
        ("use_count".to_string(), json!(credential.use_count + 1)),
    ]
    .into_iter()
    .collect();
    if let Some(from) = from {
        fields.insert("last_used_from".to_string(), json!(from));
    }
    if let Err(error) = plane
        .patch("InstallCredential", &credential.id, fields)
        .await
    {
        tracing::warn!(
            credential = %credential.credential_id,
            %error,
            "the credential's last use was not recorded"
        );
    }
}

/// A refusal as the framework's own error body shape.
fn refused(refusal: &Refusal) -> Response {
    let status = StatusCode::from_u16(refusal.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        Json(json!({
            "error": refusal.code,
            "message": refusal.message,
            "status": refusal.status
        })),
    )
        .into_response()
}

/// Unix seconds as the RFC 3339 the plane's datetime columns accept.
fn rfc3339(seconds: i64) -> String {
    Utc.timestamp_opt(seconds, 0)
        .single()
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp_nanos(0))
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use garrison_wire::{signing_bytes, token_request, vector};

    const NOW: i64 = 1_780_000_030;

    fn credential() -> InstallCredentialRow {
        InstallCredentialRow {
            id: "installcredential_01k9garrisonvector0001".to_string(),
            credential_id: "cred-1".to_string(),
            install: "agentinstall_01k9garrisonvector0001".to_string(),
            organization: "organization_01".to_string(),
            credential_kind: ED25519.to_string(),
            public_key: vector::PUBLIC_KEY_SPKI.to_string(),
            status: "active".to_string(),
            use_count: 3,
        }
    }

    fn install() -> AgentInstallRow {
        AgentInstallRow {
            id: "agentinstall_01k9garrisonvector0001".to_string(),
            install_id: "inst_01".to_string(),
            organization: "organization_01".to_string(),
            status: "active".to_string(),
        }
    }

    fn request() -> TokenRequest {
        TokenRequest {
            credential_id: credential().id,
            assertion: vector_request().assertion,
            signature: vector::SIGNATURE.to_string(),
        }
    }

    fn vector_request() -> TokenRequest {
        let assertion = vector::assertion();
        let bytes = signing_bytes(&assertion).expect("serializes");
        token_request(&bytes, &[0u8; 64], &assertion.credential_id)
    }

    /// Signs a modified assertion with the vector's own key, so a test can
    /// move the window without inventing a second keypair.
    fn signed(mutate: impl FnOnce(&mut InstallAssertion)) -> TokenRequest {
        let mut assertion = vector::assertion();
        mutate(&mut assertion);
        vector::sign(&assertion)
    }

    #[test]
    fn a_valid_assertion_earns_a_grant_naming_the_install_and_its_tenant() {
        let grant = adjudicate_assertion(NOW, &request(), Some(&credential()), Some(&install()))
            .expect("the pinned vector must adjudicate");

        assert_eq!(grant.install, install().id);
        assert_eq!(grant.organization, "organization_01");
        assert_eq!(grant.credential, credential().id);
        assert_eq!(grant.nonce, vector::assertion().nonce);
        assert_eq!(grant.nonce_expires_at, vector::assertion().exp);
    }

    #[test]
    fn an_unknown_credential_is_a_401_that_confirms_nothing() {
        let refusal = adjudicate_assertion(NOW, &request(), None, None).unwrap_err();

        assert_eq!(refusal.status, 401);
        assert_eq!(refusal.code, "unknown_credential");
    }

    #[test]
    fn a_credential_of_the_wrong_kind_is_a_403() {
        let mut credential = credential();
        credential.credential_kind = "x509_mtls".to_string();

        let refusal =
            adjudicate_assertion(NOW, &request(), Some(&credential), Some(&install())).unwrap_err();

        assert_eq!(refusal.status, 403);
        assert_eq!(refusal.code, "unsupported_credential_kind");
    }

    #[test]
    fn every_credential_state_but_active_is_a_403() {
        for status in ["pending", "rotating", "revoked", "expired"] {
            let mut credential = credential();
            credential.status = status.to_string();

            let refusal =
                adjudicate_assertion(NOW, &request(), Some(&credential), Some(&install()))
                    .unwrap_err();

            assert_eq!(refusal.status, 403, "{status}");
            assert_eq!(refusal.code, "credential_rejected", "{status}");
        }
    }

    #[test]
    fn a_quarantined_or_retired_install_is_a_403() {
        for status in DEAD_INSTALL {
            let mut install = install();
            install.status = status.to_string();

            let refusal =
                adjudicate_assertion(NOW, &request(), Some(&credential()), Some(&install))
                    .unwrap_err();

            assert_eq!(refusal.status, 403, "{status}");
            assert_eq!(refusal.code, "install_not_active", "{status}");
        }
    }

    #[test]
    fn an_enrolled_or_active_install_is_admitted() {
        for status in ["enrolled", "active"] {
            let mut install = install();
            install.status = status.to_string();

            assert!(
                adjudicate_assertion(NOW, &request(), Some(&credential()), Some(&install)).is_ok(),
                "{status}"
            );
        }
    }

    #[test]
    fn a_credential_whose_install_is_invisible_is_the_unknown_credential_answer() {
        let refusal = adjudicate_assertion(NOW, &request(), Some(&credential()), None).unwrap_err();

        assert_eq!(refusal.status, 401);
        assert_eq!(refusal.code, "unknown_credential");
    }

    #[test]
    fn a_bad_signature_is_a_401() {
        let refusal = adjudicate_assertion(
            NOW,
            &vector_request(),
            Some(&credential()),
            Some(&install()),
        )
        .unwrap_err();

        assert_eq!(refusal.status, 401);
        assert_eq!(refusal.code, "assertion_rejected");
    }

    #[test]
    fn an_assertion_for_another_installs_credential_is_a_401() {
        let mut credential = credential();
        credential.install = "agentinstall_somebody_else".to_string();

        let refusal =
            adjudicate_assertion(NOW, &request(), Some(&credential), Some(&install())).unwrap_err();

        assert_eq!(refusal.status, 401);
        assert_eq!(refusal.code, "assertion_rejected");
    }

    #[test]
    fn an_expired_assertion_is_a_401_once_it_is_past_the_skew() {
        let body = signed(|_| {});
        let expired = vector::assertion().exp + SKEW_SECS + 1;

        let refusal = adjudicate_assertion(expired, &body, Some(&credential()), Some(&install()))
            .unwrap_err();

        assert_eq!(refusal.code, "assertion_expired");
        assert_eq!(refusal.status, 401);
    }

    #[test]
    fn an_assertion_inside_the_skew_is_still_accepted() {
        let body = signed(|_| {});
        let just_expired = vector::assertion().exp + SKEW_SECS;

        assert!(
            adjudicate_assertion(just_expired, &body, Some(&credential()), Some(&install()))
                .is_ok()
        );
    }

    #[test]
    fn an_assertion_dated_too_far_ahead_is_a_401() {
        let body = signed(|_| {});
        let too_early = vector::assertion().iat - SKEW_SECS - 1;

        let refusal = adjudicate_assertion(too_early, &body, Some(&credential()), Some(&install()))
            .unwrap_err();

        assert_eq!(refusal.code, "assertion_future");
    }

    #[test]
    fn an_assertion_claiming_more_than_two_minutes_is_a_401() {
        let body = signed(|assertion| assertion.exp = assertion.iat + 121);

        let refusal = adjudicate_assertion(
            vector::assertion().iat,
            &body,
            Some(&credential()),
            Some(&install()),
        )
        .unwrap_err();

        assert_eq!(refusal.code, "assertion_window");
        assert_eq!(refusal.status, 401);
    }

    #[test]
    fn an_assertion_claiming_exactly_two_minutes_is_accepted() {
        let body = signed(|assertion| assertion.exp = assertion.iat + 120);

        assert!(adjudicate_assertion(
            vector::assertion().iat,
            &body,
            Some(&credential()),
            Some(&install())
        )
        .is_ok());
    }

    #[test]
    fn an_assertion_that_expires_before_it_was_issued_is_a_401() {
        let body = signed(|assertion| assertion.exp = assertion.iat - 1);

        let refusal = adjudicate_assertion(
            vector::assertion().iat,
            &body,
            Some(&credential()),
            Some(&install()),
        )
        .unwrap_err();

        assert_eq!(refusal.code, "assertion_expired");
    }

    #[test]
    fn a_short_nonce_is_a_401() {
        let body = signed(|assertion| assertion.nonce = "too-short".to_string());

        let refusal =
            adjudicate_assertion(NOW, &body, Some(&credential()), Some(&install())).unwrap_err();

        assert_eq!(refusal.code, "assertion_nonce");
        assert_eq!(refusal.status, 401);
    }

    #[test]
    fn a_nonce_of_exactly_the_minimum_length_is_accepted() {
        let body = signed(|assertion| assertion.nonce = "a".repeat(MIN_NONCE_LEN));

        assert!(adjudicate_assertion(NOW, &body, Some(&credential()), Some(&install())).is_ok());
    }

    #[test]
    fn a_nonce_is_new_once_and_never_again() {
        let mut seen = HashMap::new();
        let message = Consume {
            nonce: "n".to_string(),
            expires_at: NOW + 60,
            now: NOW,
        };

        assert!(consume(&mut seen, &message));
        assert!(!consume(&mut seen, &message));
    }

    #[test]
    fn a_nonce_is_forgotten_once_its_assertion_has_expired() {
        let mut seen = HashMap::new();
        assert!(consume(
            &mut seen,
            &Consume {
                nonce: "n".to_string(),
                expires_at: NOW + 60,
                now: NOW,
            }
        ));

        // Well past that assertion's expiry: the entry is dropped, so the
        // ledger cannot grow without bound. Replaying it would still fail the
        // window check, which is why forgetting is safe.
        assert!(consume(
            &mut seen,
            &Consume {
                nonce: "n".to_string(),
                expires_at: NOW + 3600,
                now: NOW + 3600,
            }
        ));
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn two_different_nonces_do_not_collide() {
        let mut seen = HashMap::new();
        for nonce in ["a", "b"] {
            assert!(consume(
                &mut seen,
                &Consume {
                    nonce: nonce.to_string(),
                    expires_at: NOW + 60,
                    now: NOW,
                }
            ));
        }
        assert_eq!(seen.len(), 2);
    }

    fn plane_error(status: u16) -> crate::plane::PlaneError {
        use acton_service_client::reqwest::header::HeaderMap as ClientHeaders;

        crate::plane::PlaneError::Client(acton_service_client::ClientError::Api(Box::new(
            acton_service_client::error::build_api_error(
                acton_service_client::StatusCode::from_u16(status).unwrap(),
                &ClientHeaders::new(),
                r#"{"error":"nope","status":0}"#,
            ),
        )))
    }

    #[test]
    fn a_row_id_the_plane_will_not_even_parse_is_an_absent_row() {
        for status in [400, 404, 422] {
            assert_eq!(
                looked_up::<()>(Err(plane_error(status)), "credential").unwrap(),
                None,
                "{status}"
            );
        }
    }

    #[test]
    fn a_plane_that_cannot_answer_is_a_503_and_never_an_absent_row() {
        for status in [401, 403, 429, 500, 503] {
            let refusal = looked_up::<()>(Err(plane_error(status)), "credential")
                .expect_err("{status} is not the caller's fault");

            assert_eq!(refusal.status, 503, "{status}");
            assert_eq!(refusal.code, "plane_unavailable", "{status}");
        }
    }

    #[test]
    fn a_row_that_was_found_passes_straight_through() {
        assert_eq!(looked_up(Ok(Some(7)), "credential").unwrap(), Some(7));
        assert_eq!(looked_up::<i32>(Ok(None), "credential").unwrap(), None);
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                acton_service::prelude::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        headers
    }

    #[test]
    fn the_client_address_is_the_first_hop_of_the_forwarded_chain() {
        let seen = client_address(&headers(&[(
            "x-forwarded-for",
            "203.0.113.7, 10.0.0.1, 10.0.0.2",
        )]));

        assert_eq!(seen.as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn a_real_ip_header_is_used_when_nothing_forwarded_a_chain() {
        assert_eq!(
            client_address(&headers(&[("x-real-ip", "2001:db8::1")])).as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn no_proxy_header_leaves_the_column_alone_rather_than_inventing_an_address() {
        assert_eq!(client_address(&HeaderMap::new()), None);
        assert_eq!(client_address(&headers(&[("x-forwarded-for", " ")])), None);
    }

    #[test]
    fn a_forged_address_cannot_overflow_the_column_it_is_written_to() {
        let long = "1".repeat(300);

        let seen = client_address(&headers(&[("x-forwarded-for", &long)])).unwrap();

        assert_eq!(seen.chars().count(), 45);
    }

    #[test]
    fn the_exempted_path_is_the_route_the_router_mounts() {
        assert_eq!(PUBLIC_PATH, format!("/api/v1{ROUTE}"));
    }

    #[test]
    fn a_timestamp_crosses_the_wire_as_rfc_3339_in_utc() {
        assert_eq!(rfc3339(1_780_000_000), "2026-05-28T20:26:40Z");
    }
}
