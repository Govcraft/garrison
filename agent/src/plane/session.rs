//! The actor that holds the daemon's bearer, and the only thing that mints one.
//!
//! # Why an actor and not a cached value
//!
//! Four subsystems want the plane at once, the bearer expires, and obtaining
//! a new one is a network round trip. The obvious shapes — a `Mutex<Option<
//! Bearer>>`, a `watch` channel, a `OnceCell` refreshed on a timer — all put
//! the renewal outside the thing that owns the credential, which is how a
//! fleet ends up making four simultaneous exchanges every fifteen minutes and
//! how a 401 gets handled three different ways.
//!
//! Here there is one mailbox. A caller asks [`Authenticate`] and either gets
//! the current bearer immediately or is parked; the first ask that finds no
//! usable bearer starts exactly one exchange, and every asker that arrives
//! while it is in flight is answered from its result. Serialization is a
//! property of the mailbox, not of a lock somebody remembered to take.
//!
//! # Fail closed
//!
//! A refusal is not retried here. A 401 or 403 from the exchange clears the
//! bearer and is returned as [`PlaneError::Rejected`], which the calling
//! subsystem turns into a turn refusal; an unreachable plane is returned as
//! [`PlaneError::Unreachable`], which is what the grace policies are for. The
//! actor never decides on its own that a rejection was temporary.

use crate::enrollment::key::InstallKey;
use crate::enrollment::Record;
use crate::plane::api::{Api, PlaneError};
use crate::plane::assertion::{fresh_nonce, new_assertion, sign_request};
use crate::protocol::acp::PlaneStatus;
use crate::protocol::conn::{Describe, StatusPart};
use acton_reactive::prelude::*;
use garrison_wire::{TokenGrant, TokenRequest};
use std::sync::Arc;
use std::time::Duration;

/// How much life a bearer must have left to be handed out.
///
/// A caller that receives a bearer is about to spend it on a call with its
/// own five-second budget; handing out one that expires mid-flight would turn
/// a renewal into a spurious 401 and, worse, into a rejection the caller
/// reports as a governance decision.
pub const MIN_REMAINING: Duration = Duration::from_secs(60);

/// How long the exchange itself may take.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// A bearer and when it stops being one.
#[derive(Clone, Debug)]
struct Bearer {
    token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    install: String,
    organization: String,
}

impl Bearer {
    /// Whether this is worth handing to a caller right now.
    fn usable_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.expires_at
            .signed_duration_since(now)
            .to_std()
            .is_ok_and(|left| left >= MIN_REMAINING)
    }
}

/// Everything the actor is given at spawn and never changes.
///
/// Held behind an `Arc` so a pending future can carry it out of the handler
/// without cloning a key.
#[derive(Debug)]
pub struct Identity {
    /// What enrollment recorded about this install.
    pub record: Record,
    /// The private half, for signing assertions and nothing else.
    pub key: Arc<InstallKey>,
    /// Origin of the plane's REST API.
    pub plane_url: String,
    /// Origin of the service that runs the exchange.
    pub hooks_url: String,
}

impl std::fmt::Debug for InstallKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The type deliberately has no derived Debug; this exists only so
        // `Identity` can have one, and prints nothing.
        f.write_str("InstallKey")
    }
}

/// Asks for an authenticated view of the plane.
#[acton_message]
pub struct Authenticate;

/// An authenticated view of the plane, good for a little while.
///
/// Carries the identity alongside the client so a caller never has to consult
/// the enrollment record separately, and so the tenant a call is about is the
/// tenant the bearer carries — by construction, not by agreement.
#[derive(Clone, Debug)]
pub struct Session {
    /// The authenticated client.
    pub api: Api,
    /// The `AgentInstall` row this daemon is.
    pub install: String,
    /// The `Organization` it belongs to.
    pub organization: String,
    /// When the bearer behind `api` stops being accepted.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl Request for Authenticate {
    type Response = Result<Session, PlaneError>;
}

/// Tells the session its bearer is no longer accepted.
///
/// Sent by any caller that saw a 401 on a call it made with a `Session`. A
/// send rather than an ask: the caller has already failed and has nothing to
/// wait for, and the next [`Authenticate`] exchanges a fresh assertion.
#[acton_message]
pub struct RevokeBearer;

/// An exchange finished; delivered by the pending future to its own mailbox.
#[acton_message]
struct Exchanged(Result<Bearer, PlaneError>);

/// The daemon's credential holder.
///
/// `identity` is `None` only in a `Default`-constructed model that was never
/// spawned through [`PlaneSession::spawn`]; every handler treats that as an
/// unreachable plane rather than panicking, which is the fail-closed answer.
#[acton_actor]
pub struct PlaneSession {
    identity: Option<Arc<Identity>>,
    bearer: Option<Bearer>,
    exchanging: bool,
    parked: Vec<OutboundEnvelope>,
    reachable: bool,
    last_exchange_at: Option<chrono::DateTime<chrono::Utc>>,
    last_error: Option<String>,
}

impl PlaneSession {
    /// Starts the session for an enrolled install.
    ///
    /// No exchange happens here: the daemon must start whether or not the
    /// plane is answering, so the first bearer is fetched on the first
    /// [`Authenticate`]. A plane that is down at boot costs the first turn a
    /// grace decision, not the whole process.
    pub async fn spawn(runtime: &mut ActorRuntime, identity: Identity) -> ActorHandle {
        let mut builder = runtime.new_actor_with_name::<Self>("plane_session".to_string());
        builder.model.identity = Some(Arc::new(identity));
        configure(&mut builder);
        builder.start().await
    }
}

/// Wires the handlers.
fn configure(builder: &mut ManagedActor<Idle, PlaneSession>) {
    builder.mutate_on::<Authenticate>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let now = chrono::Utc::now();

        let Some(identity) = actor.model.identity.clone() else {
            let error = PlaneError::Unreachable(
                "this daemon has no install identity; it is not enrolled".to_string(),
            );
            return Reply::pending(async move {
                reply.send(Err::<Session, PlaneError>(error)).await;
            });
        };

        // The common case: a bearer with life left in it.
        if let Some(session) = actor.model.ready_session(now) {
            return Reply::pending(async move {
                reply.send(Ok::<Session, PlaneError>(session)).await;
            });
        }

        // Park first, so an asker that arrives while an exchange is in flight
        // is answered by that exchange rather than starting a second one.
        actor.model.parked.push(reply);
        if actor.model.exchanging {
            return Reply::ready();
        }
        actor.model.exchanging = true;

        let self_envelope = actor.new_envelope();
        Reply::pending(async move {
            let result = exchange(&identity, now.timestamp()).await;
            if let Some(envelope) = self_envelope {
                envelope.send(Exchanged(result)).await;
            }
        })
    });

    builder.mutate_on::<Exchanged>(|actor, envelope| {
        let now = chrono::Utc::now();
        let outcome = envelope.message().0.clone();
        actor.model.exchanging = false;

        let answer = match outcome {
            Ok(bearer) => {
                actor.model.reachable = true;
                actor.model.last_exchange_at = Some(now);
                actor.model.last_error = None;
                actor.model.bearer = Some(bearer);
                actor.model.ready_session(now).ok_or_else(|| {
                    PlaneError::Unreachable(
                        "the new bearer is already spent; check this machine's clock".to_string(),
                    )
                })
            }
            Err(error) => {
                actor.model.reachable = !error.is_unreachable();
                actor.model.last_error = Some(error.to_string());
                actor.model.bearer = None;
                Err(error)
            }
        };

        let waiting = std::mem::take(&mut actor.model.parked);
        Reply::pending(async move {
            for reply in waiting {
                reply.send(answer.clone()).await;
            }
        })
    });

    builder.mutate_on::<RevokeBearer>(|actor, _| {
        if actor.model.bearer.take().is_some() {
            tracing::info!("the install bearer was refused; the next call re-exchanges");
        }
        Reply::ready()
    });

    builder.mutate_on::<Describe>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let part = StatusPart::Plane(PlaneStatus {
            reachable: actor.model.reachable,
            last_exchange_at: actor
                .model
                .last_exchange_at
                .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            expires_at: actor.model.bearer.as_ref().map(|bearer| {
                bearer
                    .expires_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            }),
            last_error: actor.model.last_error.clone(),
        });
        Reply::pending(async move {
            reply.send(part).await;
        })
    });
}

impl PlaneSession {
    /// A session built from the current bearer, if it is still worth having.
    fn ready_session(&self, now: chrono::DateTime<chrono::Utc>) -> Option<Session> {
        let identity = self.identity.as_ref()?;
        let bearer = self
            .bearer
            .as_ref()
            .filter(|bearer| bearer.usable_at(now))?;
        let api = Api::new(&identity.plane_url, &bearer.token).ok()?;
        Some(Session {
            api,
            install: bearer.install.clone(),
            organization: bearer.organization.clone(),
            expires_at: bearer.expires_at,
        })
    }
}

/// Signs an assertion and trades it for a bearer.
///
/// Free of the actor so it can be read as what it is: one HTTP call with a
/// signature on it.
async fn exchange(identity: &Identity, now: i64) -> Result<Bearer, PlaneError> {
    let assertion = new_assertion(
        &identity.record.credential,
        &identity.record.install,
        now,
        fresh_nonce(),
    );
    let request = sign_request(&identity.key, &assertion)
        .map_err(|error| PlaneError::Malformed(error.to_string()))?;

    let grant = post_assertion(&identity.hooks_url, &request).await?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(&grant.expires_at)
        .map_err(|error| {
            PlaneError::Malformed(format!(
                "the grant's expires_at is not a timestamp: {error}"
            ))
        })?
        .with_timezone(&chrono::Utc);

    Ok(Bearer {
        token: grant.token,
        expires_at,
        install: grant.install,
        organization: grant.organization,
    })
}

/// The one unauthenticated call this daemon ever makes.
///
/// `reqwest` rather than `acton-service-client`, because the client's whole
/// value here is bearer handling and this is the request that has no bearer.
async fn post_assertion(hooks_url: &str, request: &TokenRequest) -> Result<TokenGrant, PlaneError> {
    let url = format!("{}/api/v1/install/token", hooks_url.trim_end_matches('/'));
    let http = reqwest::Client::builder()
        .timeout(EXCHANGE_TIMEOUT)
        .build()
        .map_err(|error| PlaneError::Unreachable(error.to_string()))?;

    let response = http
        .post(&url)
        .json(request)
        .send()
        .await
        .map_err(|error| PlaneError::Unreachable(error.to_string()))?;

    let status = response.status().as_u16();
    let body = response
        .text()
        .await
        .map_err(|error| PlaneError::Unreachable(error.to_string()))?;

    if status == 200 {
        return serde_json::from_str(&body)
            .map_err(|error| PlaneError::Malformed(format!("the grant did not decode: {error}")));
    }
    Err(refusal(status, &body))
}

/// Turns a non-200 from the exchange into the error a caller acts on.
///
/// Pure. 429 and 5xx are the service being unavailable; everything else is a
/// decision, and a decision is never retried.
fn refusal(status: u16, body: &str) -> PlaneError {
    let message = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| body.chars().take(200).collect());

    match status {
        429 | 500..=599 => PlaneError::Unreachable(format!("{status}: {message}")),
        _ => PlaneError::Rejected { status, message },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(seconds, 0).expect("a valid instant")
    }

    fn bearer(expires_at: i64) -> Bearer {
        Bearer {
            token: "v4.local.abc".to_string(),
            expires_at: at(expires_at),
            install: "agentinstall_01".to_string(),
            organization: "organization_01".to_string(),
        }
    }

    fn record() -> Record {
        Record {
            install_id: "inst_01".into(),
            install: "agentinstall_01".into(),
            credential: "installcredential_01".into(),
            organization: "organization_01".into(),
            hostname: "ws-01".into(),
            enrolled_at: "2026-08-29T04:50:23.579Z".into(),
        }
    }

    fn identity(dir: &std::path::Path) -> Identity {
        Identity {
            record: record(),
            key: Arc::new(
                InstallKey::load_or_create(&crate::enrollment::key::key_path(dir)).unwrap(),
            ),
            plane_url: "http://127.0.0.1:1".to_string(),
            hooks_url: "http://127.0.0.1:1".to_string(),
        }
    }

    #[test]
    fn a_bearer_with_more_than_a_minute_left_is_handed_out() {
        assert!(bearer(1_000_000).usable_at(at(1_000_000 - 61)));
    }

    #[test]
    fn a_bearer_with_exactly_the_margin_left_is_still_handed_out() {
        assert!(bearer(1_000_000).usable_at(at(1_000_000 - 60)));
    }

    #[test]
    fn a_bearer_about_to_expire_is_not_handed_out() {
        assert!(!bearer(1_000_000).usable_at(at(1_000_000 - 59)));
    }

    #[test]
    fn an_expired_bearer_is_not_handed_out() {
        assert!(!bearer(1_000_000).usable_at(at(1_000_001)));
    }

    #[test]
    fn a_refusal_from_the_exchange_is_a_decision_not_an_outage() {
        for status in [400, 401, 403] {
            let error = refusal(
                status,
                r#"{"error":"credential_rejected","message":"revoked"}"#,
            );
            assert!(!error.is_unreachable(), "{status}");
            assert_eq!(
                error,
                PlaneError::Rejected {
                    status,
                    message: "revoked".to_string()
                }
            );
        }
    }

    #[test]
    fn a_service_that_is_down_or_throttling_is_an_outage() {
        for status in [429, 500, 502, 503] {
            assert!(
                refusal(status, r#"{"message":"later"}"#).is_unreachable(),
                "{status}"
            );
        }
    }

    #[test]
    fn a_refusal_with_no_json_body_still_carries_what_was_said() {
        let error = refusal(403, "plain text refusal");

        assert_eq!(
            error,
            PlaneError::Rejected {
                status: 403,
                message: "plain text refusal".to_string()
            }
        );
    }

    #[tokio::test]
    async fn an_unenrolled_session_reports_an_unreachable_plane_rather_than_panicking() {
        let mut runtime = ActonApp::launch_async().await;
        let mut builder = runtime.new_actor::<PlaneSession>();
        configure(&mut builder);
        let handle = builder.start().await;

        let answer = handle.ask(Authenticate).await.expect("the actor answers");

        assert!(answer.unwrap_err().is_unreachable());
        runtime.shutdown_all().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn a_session_with_no_reachable_exchange_reports_the_outage_to_every_asker() {
        let dir = tempfile::tempdir().unwrap();
        let mut runtime = ActonApp::launch_async().await;
        let handle = PlaneSession::spawn(&mut runtime, identity(dir.path())).await;

        // Two asks at once: both must be answered, and the second must not
        // start its own exchange.
        let (first, second) = tokio::join!(handle.ask(Authenticate), handle.ask(Authenticate));

        assert!(first.expect("answered").unwrap_err().is_unreachable());
        assert!(second.expect("answered").unwrap_err().is_unreachable());
        runtime.shutdown_all().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn the_status_reports_an_unreachable_plane_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let mut runtime = ActonApp::launch_async().await;
        let handle = PlaneSession::spawn(&mut runtime, identity(dir.path())).await;

        let before = handle.ask(Describe).await.expect("describes");
        let StatusPart::Plane(before) = before else {
            panic!("the plane session describes itself as the plane");
        };
        assert!(!before.reachable);
        assert!(before.last_exchange_at.is_none());
        assert!(before.last_error.is_none(), "nothing has been tried yet");

        let _ = handle.ask(Authenticate).await.expect("answered");

        let after = handle.ask(Describe).await.expect("describes");
        let StatusPart::Plane(after) = after else {
            panic!("the plane session describes itself as the plane");
        };
        assert!(!after.reachable);
        assert!(
            after.last_error.is_some(),
            "an operator asking why turns are refused must see the reason"
        );
        assert!(after.expires_at.is_none());
        runtime.shutdown_all().await.expect("clean shutdown");
    }

    #[tokio::test]
    async fn revoking_a_bearer_is_accepted_even_when_there_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let mut runtime = ActonApp::launch_async().await;
        let handle = PlaneSession::spawn(&mut runtime, identity(dir.path())).await;

        handle.send(RevokeBearer).await;

        // Still answering afterwards: a revoke is not a way to wedge the
        // credential holder.
        assert!(handle.ask(Describe).await.is_ok());
        runtime.shutdown_all().await.expect("clean shutdown");
    }
}
