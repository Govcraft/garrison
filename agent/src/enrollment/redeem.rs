//! Spending the grant: one POST, and what to make of the answer.
//!
//! Redemption is an ordinary entity create against the control plane, because
//! on the plane's side `Redemption` is an ordinary schema. There is no special
//! enrollment route to call and no bespoke protocol to get wrong; the daemon
//! posts a row and reads what came back.
//!
//! Two things about the answer are worth knowing before reading the code. A
//! refusal arrives as **201 with `outcome = "refused"`**, not as an error
//! status: the plane persists the refusal so a security officer can see that
//! an unknown machine presented a revoked grant at 03:00, and the created row
//! is what it hands back. And the response is the only channel through which
//! this daemon ever learns its own identity, because the `enrollee` role holds
//! no read grant on the schema. Whatever is not in this body is not knowable
//! from here.

use crate::error::GarrisonError;
use acton_service_client::{ApiVersion, ServiceClient};
use serde_json::{json, Value};

/// What the plane needs to know about this machine.
///
/// Assembled by the caller from what the process actually observed, not from
/// configuration. `sandbox_hardening` in particular is the difference between
/// "we require landlock and seccomp" as a policy statement and as a fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallFacts {
    /// The stable identifier this daemon minted for itself.
    pub install_id: String,
    /// This machine's hostname.
    pub hostname: String,
    /// `linux`, `macos`, or `windows`.
    pub platform: &'static str,
    /// The `garrison-agent` version running.
    pub agent_version: String,
    /// `enforce`, `best_effort`, or `unavailable`, as the kernel granted it.
    pub sandbox_hardening: &'static str,
    /// Whether writing tools run in a sandbox child at all.
    pub isolation_active: bool,
    /// The operator this install belongs to, when the grant does not say.
    pub operator_upn: Option<String>,
}

/// What the plane decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The install is in the fleet. Carries the identity it was given.
    Accepted {
        /// The plane's row id for this install.
        install: String,
        /// The plane's row id for the credential just registered.
        credential: String,
        /// The tenant the plane resolved.
        organization: String,
        /// When the plane decided.
        decided_at: String,
    },
    /// The install was turned away, with the reason recorded on the plane.
    Refused {
        /// Why, in the plane's words.
        reason: String,
    },
}

/// Builds the redemption body.
///
/// Pure, so every field the plane will see can be asserted without a server.
/// Note what is absent: neither `organization` nor `token_id` is sent. The
/// daemon cannot read its own grant, so it has nothing truthful to say about
/// which tenant it belongs to or which token it is spending; the hook resolves
/// both, the second from the artifact this request is bearing. A field the
/// client cannot set is a field the client cannot forge.
#[must_use]
pub fn body(facts: &InstallFacts, public_key: &str) -> Value {
    let mut fields = serde_json::Map::new();
    fields.insert("install_id".into(), json!(facts.install_id));
    fields.insert("hostname".into(), json!(facts.hostname));
    fields.insert("platform".into(), json!(facts.platform));
    fields.insert("agent_version".into(), json!(facts.agent_version));
    fields.insert("sandbox_hardening".into(), json!(facts.sandbox_hardening));
    fields.insert("isolation_active".into(), json!(facts.isolation_active));
    fields.insert("credential_kind".into(), json!("ed25519"));
    fields.insert("public_key".into(), json!(public_key));
    if let Some(upn) = facts
        .operator_upn
        .as_deref()
        .filter(|u| !u.trim().is_empty())
    {
        fields.insert("operator_upn".into(), json!(upn.trim()));
    }
    json!({ "fields": fields })
}

/// Reads the plane's verdict out of a create response.
///
/// Fails closed. An `outcome` this daemon does not recognize, or an acceptance
/// missing any part of the identity it was supposed to carry, is treated as a
/// refusal rather than as success: a daemon that decided it had enrolled on
/// the strength of a half-filled response would be a daemon whose local record
/// disagrees with the fleet.
#[must_use]
pub fn outcome(response: &Value) -> Outcome {
    let fields = response.get("fields").unwrap_or(response);
    let text = |key: &str| {
        fields
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .filter(|value| !value.is_empty())
    };

    match fields.get("outcome").and_then(Value::as_str) {
        Some("accepted") => match (text("install"), text("credential"), text("organization")) {
            (Some(install), Some(credential), Some(organization)) => Outcome::Accepted {
                install,
                credential,
                organization,
                decided_at: text("decided_at").unwrap_or_default(),
            },
            _ => Outcome::Refused {
                reason: "the plane accepted the enrollment but returned no identity for it".into(),
            },
        },
        Some("refused") => Outcome::Refused {
            reason: text("refusal_reason")
                .unwrap_or_else(|| "the plane refused without recording a reason".into()),
        },
        Some(other) => Outcome::Refused {
            reason: format!("the plane returned an unrecognized outcome '{other}'"),
        },
        None => Outcome::Refused {
            reason: "the plane returned no outcome".into(),
        },
    }
}

/// Posts the redemption, authenticating with the enrollment artifact itself.
///
/// The artifact is the only credential this machine has: it is not enrolled
/// yet, so it holds no install credential, and no human is present to supply
/// one. That is exactly what the `enrollee` role exists for, and it is scoped
/// to this single action.
///
/// # Errors
///
/// [`GarrisonErrorKind::Enrollment`](crate::error::GarrisonErrorKind::Enrollment)
/// when the plane cannot be reached or answers with an error status. Note that
/// a *refusal* is not an error here; it comes back as [`Outcome::Refused`].
pub async fn redeem(
    plane_url: &str,
    artifact: &str,
    facts: &InstallFacts,
    public_key: &str,
) -> Result<Outcome, GarrisonError> {
    let client = ServiceClient::builder(plane_url)
        .api_version(ApiVersion::V1)
        .bearer_token(artifact)
        .build()
        .map_err(|error| {
            GarrisonError::enrollment(format!("control plane '{plane_url}' is unusable: {error}"))
        })?;

    let response: Value = client
        .post(
            "forge/schemas/Redemption/entities",
            &body(facts, public_key),
        )
        .await
        .map_err(|error| {
            GarrisonError::enrollment(format!("the control plane refused the request: {error}"))
        })?;

    Ok(outcome(&response))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> InstallFacts {
        InstallFacts {
            install_id: "inst_01h455vb4pex5vsknk084sn02q".into(),
            hostname: "ws-01".into(),
            platform: "linux",
            agent_version: "0.1.0".into(),
            sandbox_hardening: "enforce",
            isolation_active: true,
            operator_upn: Some("dev@agency.gov".into()),
        }
    }

    #[test]
    fn the_body_reports_what_the_process_observed() {
        let body = body(&facts(), "BASE64SPKI");
        let fields = &body["fields"];

        assert_eq!(fields["sandbox_hardening"], json!("enforce"));
        assert_eq!(fields["isolation_active"], json!(true));
        assert_eq!(fields["public_key"], json!("BASE64SPKI"));
        assert_eq!(fields["credential_kind"], json!("ed25519"));
    }

    #[test]
    fn the_daemon_never_asserts_its_own_tenant_or_its_own_grant() {
        let body = body(&facts(), "k");
        assert!(
            body["fields"].get("organization").is_none(),
            "organization is the plane's to decide, never the daemon's to claim"
        );
        assert!(
            body["fields"].get("token_id").is_none(),
            "which grant is being spent comes from the artifact, not the body"
        );
    }

    #[test]
    fn no_private_material_reaches_the_body() {
        let rendered = body(&facts(), "BASE64SPKI").to_string();
        for secret in ["PRIVATE", "private", "secret", "v4.local"] {
            assert!(
                !rendered.contains(secret),
                "the body must not carry {secret}"
            );
        }
    }

    #[test]
    fn an_absent_operator_upn_is_omitted_rather_than_sent_blank() {
        let mut facts = facts();
        facts.operator_upn = None;
        assert!(body(&facts, "k")["fields"].get("operator_upn").is_none());

        facts.operator_upn = Some("   ".into());
        assert!(body(&facts, "k")["fields"].get("operator_upn").is_none());
    }

    #[test]
    fn a_reported_upn_is_trimmed() {
        let mut facts = facts();
        facts.operator_upn = Some("  dev@agency.gov \n".into());
        assert_eq!(
            body(&facts, "k")["fields"]["operator_upn"],
            json!("dev@agency.gov")
        );
    }

    #[test]
    fn an_acceptance_yields_the_identity_the_plane_assigned() {
        let response = json!({
            "id": "redemption_01",
            "fields": {
                "outcome": "accepted",
                "install": "agentinstall_01",
                "credential": "installcredential_01",
                "organization": "organization_01",
                "decided_at": "2026-08-29T04:50:23.579Z",
                "refusal_reason": ""
            }
        });
        assert_eq!(
            outcome(&response),
            Outcome::Accepted {
                install: "agentinstall_01".into(),
                credential: "installcredential_01".into(),
                organization: "organization_01".into(),
                decided_at: "2026-08-29T04:50:23.579Z".into(),
            }
        );
    }

    #[test]
    fn a_refusal_carries_the_planes_reason() {
        let response = json!({
            "fields": {
                "outcome": "refused",
                "refusal_reason": "token has already been fully redeemed",
                "install": null
            }
        });
        assert_eq!(
            outcome(&response),
            Outcome::Refused {
                reason: "token has already been fully redeemed".into()
            }
        );
    }

    #[test]
    fn an_acceptance_without_an_identity_is_treated_as_a_refusal() {
        let response = json!({ "fields": { "outcome": "accepted", "install": "agentinstall_01" } });
        let Outcome::Refused { reason } = outcome(&response) else {
            panic!("a half-filled acceptance must not enroll this daemon");
        };
        assert!(reason.contains("no identity"));
    }

    #[test]
    fn an_unknown_or_missing_outcome_fails_closed() {
        let unknown = outcome(&json!({ "fields": { "outcome": "pending" } }));
        assert!(matches!(unknown, Outcome::Refused { .. }));

        let missing = outcome(&json!({ "fields": {} }));
        assert_eq!(
            missing,
            Outcome::Refused {
                reason: "the plane returned no outcome".into()
            }
        );
    }

    #[test]
    fn a_refusal_with_no_recorded_reason_still_says_something() {
        let response = json!({ "fields": { "outcome": "refused", "refusal_reason": "" } });
        let Outcome::Refused { reason } = outcome(&response) else {
            panic!("expected a refusal");
        };
        assert!(reason.contains("without recording a reason"));
    }

    #[test]
    fn a_flat_response_is_read_as_readily_as_an_enveloped_one() {
        let flat = json!({
            "outcome": "refused",
            "refusal_reason": "token expired"
        });
        assert_eq!(
            outcome(&flat),
            Outcome::Refused {
                reason: "token expired".into()
            }
        );
    }
}
