//! `Redemption.before_validate`: admit a daemon to the fleet, or refuse it.
//!
//! SchemaForge has already done two things before this runs: Cedar checked
//! that the caller holds `enrollee`, and the write-time rules filled the
//! defaults. What is left is everything that needs to look at other rows,
//! which is what a hook is for.
//!
//! Which token is being spent is settled here rather than by the client. The
//! daemon does not send `token_id`; the hook takes it from `user_id`, the
//! subject claim of the artifact the caller authenticated with. That is a
//! stronger anti-replay binding than the `@require` it replaces, which could
//! only refuse a mismatch: a caller that cannot express the field cannot
//! attempt one.
//!
//! It runs at `before_validate` rather than `before_change` for one reason:
//! that phase is the last point at which a field the client never sent can
//! still be added. `organization` is such a field. A v4.local artifact is
//! encrypted with the plane's own key, so a daemon cannot read its own claims
//! and has nothing truthful to say about which tenant it belongs to. Resolving
//! it here means the daemon never asserts it, and a field the client cannot
//! set is a field the client cannot forge.
//!
//! A refusal is persisted, not aborted. `abort_reason` would return an error
//! and leave no trace, and the record that an unknown machine presented a
//! revoked token at 03:00 is precisely the record a security officer wants.
//! The daemon is told `outcome = refused` and nothing else; it holds no read
//! grant on this schema, so the create response is all it ever sees.
//!
//! The token names a person; the second half of the decision is whether that
//! person may hold a machine today (R4). The install binds to the operator's
//! row id, never to the UPN, so a directory rename after enrollment changes
//! nothing here. The reported UPN is consulted exactly once, now.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::Utc;
use serde_json::{json, Value};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::adjudicate::{
    adjudicate, directory_fresh, operator_admissible, operator_source, spend, OperatorSource,
    Verdict,
};
use crate::pb::redemption::redemption_hooks_server::RedemptionHooks;
use crate::pb::redemption::*;
use crate::plane::{OperatorRow, Plane, PlaneError};

/// Whether the directory is the authority for operators, and how recent its
/// view must be for an enrollment to trust it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryGate {
    pub enabled: bool,
    pub staleness: Duration,
}

impl Default for DirectoryGate {
    /// No directory: hand-typed operators are admitted on status alone.
    fn default() -> Self {
        Self {
            enabled: false,
            staleness: Duration::from_secs(900),
        }
    }
}

/// How this service reaches the plane and what it expects to see there.
pub struct Service {
    plane: Plane,
    /// The `iss` an enrollment artifact must have been minted under.
    expected_issuer: String,
    gate: DirectoryGate,
}

impl Service {
    /// Build the service from a plane client and the issuer it trusts.
    #[must_use]
    pub fn new(plane: Plane, expected_issuer: impl Into<String>) -> Self {
        Self {
            plane,
            expected_issuer: expected_issuer.into(),
            gate: DirectoryGate::default(),
        }
    }

    /// Make the directory the authority for who may enrol.
    #[must_use]
    pub fn with_directory(mut self, gate: DirectoryGate) -> Self {
        self.gate = gate;
        self
    }
}

#[tonic::async_trait]
impl RedemptionHooks for Service {
    async fn before_validate(
        &self,
        request: Request<RedemptionBeforeValidateRequest>,
    ) -> Result<Response<RedemptionBeforeValidateResponse>, Status> {
        let req = request.into_inner();

        // Only a create provisions. An update to a decided redemption must not
        // mint a second credential for the same install. `Redemption` is also
        // forbidden to update outright; see policies/custom/credential-lifecycle.cedar.
        if req.operation != "create" {
            return Ok(Response::new(RedemptionBeforeValidateResponse::default()));
        }

        // The token being spent is the subject of the artifact that
        // authenticated this call, and nothing else. An absent subject is not
        // a refusal to record: there is no grant to record it against, and
        // persisting a verdict with no subject would write a row no auditor
        // could join to anything.
        let Some(token_id) = req.user_id.clone().filter(|sub| !sub.is_empty()) else {
            warn!(
                install_id = %req.install_id,
                "a redemption arrived with no subject claim; refusing to adjudicate it"
            );
            return Ok(Response::new(RedemptionBeforeValidateResponse {
                abort_reason: Some("the presented credential carries no subject claim".to_string()),
                ..Default::default()
            }));
        };

        match self.provision(&req, &token_id).await {
            Ok(response) => Ok(Response::new(response)),
            // The plane being unreachable is not a refusal. Refusing would
            // write a permanent verdict on a transient fault. Abort instead,
            // so the daemon retries and nothing is recorded.
            Err(error) => {
                warn!(
                    %token_id,
                    install_id = %req.install_id,
                    "enrollment could not be adjudicated: {error}"
                );
                Ok(Response::new(RedemptionBeforeValidateResponse {
                    abort_reason: Some(format!("enrollment temporarily unavailable: {error}")),
                    ..Default::default()
                }))
            }
        }
    }
}

impl Service {
    async fn provision(
        &self,
        req: &RedemptionBeforeValidateRequest,
        token_id: &str,
    ) -> Result<RedemptionBeforeValidateResponse, PlaneError> {
        let now = Utc::now();

        let Some(token) = self.plane.enrollment_token(token_id).await? else {
            // No such token. The caller authenticated with an artifact whose
            // `sub` is this value, so a missing row means the row was deleted,
            // never created, or is invisible to this bearer's tenant: worth
            // recording, not worth detail.
            return Ok(refused(
                &now,
                token_id,
                "no enrollment token matches this artifact",
            ));
        };

        let organization = match adjudicate(&token, &self.expected_issuer, now) {
            Verdict::Accept { organization } => organization,
            Verdict::Refuse(reason) => {
                info!(%token_id, %reason, "enrollment refused");
                return Ok(refused_within(
                    &now,
                    token_id,
                    &organization_of(&token),
                    &token.id,
                    &reason,
                ));
            }
        };
        let within = Some(organization.clone());

        let operator = match self.resolve_operator(&token, req).await? {
            Ok(row) => row,
            Err(reason) => {
                info!(%token_id, %reason, "enrollment refused");
                return Ok(refused_within(&now, token_id, &within, &token.id, &reason));
            }
        };

        if let Err(reason) = operator_admissible(&operator, self.gate.enabled) {
            info!(%token_id, operator = %operator.id, %reason, "enrollment refused");
            return Ok(refused_within(&now, token_id, &within, &token.id, &reason));
        }

        if self.gate.enabled {
            let fresh = match self.plane.organization_by_id(&organization).await? {
                Some(org) => directory_fresh(&org, now, self.gate.staleness),
                None => Err("organization is not visible to the enrollment service".into()),
            };
            if let Err(reason) = fresh {
                info!(%token_id, %organization, %reason, "enrollment refused");
                return Ok(refused_within(&now, token_id, &within, &token.id, &reason));
            }
        }

        let install = self
            .plane
            .create(
                "AgentInstall",
                install_fields(req, &organization, &operator.id, &token.id),
            )
            .await?;

        let credential = self
            .plane
            .create(
                "InstallCredential",
                credential_fields(req, &organization, &install, token_id),
            )
            .await?;

        let (uses, status) = spend(&token);
        let mut patch = BTreeMap::new();
        patch.insert("uses".into(), json!(uses));
        patch.insert("status".into(), json!(status));
        patch.insert("last_redeemed_at".into(), json!(rfc3339(&now)));
        if token.first_redeemed_at.is_none() {
            patch.insert("first_redeemed_at".into(), json!(rfc3339(&now)));
        }
        self.plane
            .patch("EnrollmentToken", &token.id, patch)
            .await?;

        info!(
            %token_id,
            install_id = %req.install_id,
            %install,
            %credential,
            "enrollment accepted"
        );

        Ok(RedemptionBeforeValidateResponse {
            token_id: Some(token_id.to_string()),
            organization: Some(organization),
            enrollment_token: Some(token.id),
            install: Some(install),
            credential: Some(credential),
            outcome: Some("accepted".into()),
            refusal_reason: Some(String::new()),
            decided_at: Some(rfc3339(&now)),
            ..Default::default()
        })
    }

    /// The operator row the token or the daemon points at, or the refusal.
    ///
    /// The outer `Result` is the plane failing (abort, retry); the inner one
    /// is a decision (persist).
    async fn resolve_operator(
        &self,
        token: &crate::plane::EnrollmentTokenRow,
        req: &RedemptionBeforeValidateRequest,
    ) -> Result<Result<OperatorRow, String>, PlaneError> {
        let source = operator_source(token, req.operator_upn.as_deref().unwrap_or_default());
        Ok(match source {
            OperatorSource::Bound(id) => match self.plane.operator_by_id(&id).await? {
                Some(row) => Ok(row),
                None => Err(format!(
                    "the operator this token names ({id}) no longer exists"
                )),
            },
            OperatorSource::ReportedUpn(upn) => match self.plane.operator_by_upn(&upn).await? {
                Some(row) => Ok(row),
                None => Err(format!("no operator is registered as '{upn}'")),
            },
            OperatorSource::Unknown => {
                Err("the request identifies no operator and the token names none".into())
            }
        })
    }
}

/// The install this daemon is asking to become.
///
/// `status` is `enrolled`, not `active`: joining the fleet and being cleared
/// to prompt a model are different decisions, and the second one belongs to a
/// Seat.
fn install_fields(
    req: &RedemptionBeforeValidateRequest,
    organization: &str,
    operator: &str,
    enrollment_token: &str,
) -> BTreeMap<String, Value> {
    let mut fields = BTreeMap::new();
    fields.insert("install_id".into(), json!(req.install_id));
    fields.insert("hostname".into(), json!(req.hostname));
    fields.insert("operator".into(), json!(operator));
    fields.insert("organization".into(), json!(organization));
    fields.insert("platform".into(), json!(req.platform));
    fields.insert("agent_version".into(), json!(req.agent_version));
    fields.insert("sandbox_hardening".into(), json!(req.sandbox_hardening));
    fields.insert(
        "isolation_active".into(),
        json!(req.isolation_active.unwrap_or(false)),
    );
    fields.insert("status".into(), json!("enrolled"));
    fields.insert("enrolled_via".into(), json!(enrollment_token));
    if let Some(version) = req.acton_ai_version.as_deref().filter(|v| !v.is_empty()) {
        fields.insert("acton_ai_version".into(), json!(version));
    }
    fields
}

/// The credential the daemon will sign with from now on.
///
/// `status` is `active` because an install that just proved it holds a
/// spendable token has proved everything this credential is for. Public
/// material only: the private half never left the machine.
fn credential_fields(
    req: &RedemptionBeforeValidateRequest,
    organization: &str,
    install: &str,
    token_id: &str,
) -> BTreeMap<String, Value> {
    let mut fields = BTreeMap::new();
    fields.insert("credential_id".into(), json!(credential_id(req, token_id)));
    fields.insert("install".into(), json!(install));
    fields.insert("organization".into(), json!(organization));
    fields.insert("credential_kind".into(), json!(req.credential_kind));
    fields.insert("public_key".into(), json!(req.public_key));
    fields.insert("status".into(), json!("active"));
    if let Some(fingerprint) = req.cert_fingerprint.as_deref().filter(|f| !f.is_empty()) {
        fields.insert("cert_fingerprint".into(), json!(fingerprint));
    }
    fields
}

/// A stable, non-secret key id for the credential.
///
/// Derived from the install and the token being spent rather than randomly
/// generated, so a retried redemption of the same token by the same install
/// collides on `credential_id`'s unique index instead of silently minting a
/// second live credential.
fn credential_id(req: &RedemptionBeforeValidateRequest, token_id: &str) -> String {
    format!("{}.{}", req.install_id, token_id)
}

/// A persisted refusal.
///
/// `token_id` is stamped here rather than left to the client, which can no
/// longer send it at all. Without it the row would record that *something* was
/// refused without naming the grant it was refused against, which is the one
/// fact the record exists to carry.
fn refused(
    now: &chrono::DateTime<Utc>,
    token_id: &str,
    reason: &str,
) -> RedemptionBeforeValidateResponse {
    RedemptionBeforeValidateResponse {
        token_id: Some(token_id.to_string()),
        outcome: Some("refused".into()),
        refusal_reason: Some(reason.to_string()),
        decided_at: Some(rfc3339(now)),
        ..Default::default()
    }
}

/// A refusal that still knows which tenant it belongs to.
///
/// Worth the extra arguments: a refused row outside every tenant is a row the
/// organization it concerns cannot read.
fn refused_within(
    now: &chrono::DateTime<Utc>,
    token_id: &str,
    organization: &Option<String>,
    enrollment_token: &str,
    reason: &str,
) -> RedemptionBeforeValidateResponse {
    RedemptionBeforeValidateResponse {
        organization: organization.clone(),
        enrollment_token: Some(enrollment_token.to_string()),
        ..refused(now, token_id, reason)
    }
}

fn organization_of(token: &crate::plane::EnrollmentTokenRow) -> Option<String> {
    token.organization.clone().filter(|o| !o.is_empty())
}

fn rfc3339(instant: &chrono::DateTime<Utc>) -> String {
    instant.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `sub` of the artifact a caller authenticated with, which is what
    /// the hook uses in place of the field the client used to send.
    const SUBJECT: &str = "tok_7f3a";

    /// A request as the hook actually receives one: no `token_id`, because the
    /// daemon has no field to put it in, and a `user_id` because the gateway
    /// resolved the bearer's subject claim.
    fn request() -> RedemptionBeforeValidateRequest {
        RedemptionBeforeValidateRequest {
            operation: "create".into(),
            user_id: Some(SUBJECT.into()),
            install_id: "inst-a".into(),
            hostname: "ws-01".into(),
            platform: "linux".into(),
            agent_version: "0.1.0".into(),
            sandbox_hardening: "best_effort".into(),
            credential_kind: "ed25519".into(),
            public_key: "BASE64SPKI".into(),
            ..Default::default()
        }
    }

    #[test]
    fn an_install_joins_as_enrolled_not_active() {
        let fields = install_fields(&request(), "org_1", "operator_1", "tok_row");
        assert_eq!(fields["status"], json!("enrolled"));
        assert_eq!(fields["enrolled_via"], json!("tok_row"));
        assert_eq!(fields["operator"], json!("operator_1"));
    }

    #[test]
    fn an_absent_acton_version_is_omitted_rather_than_sent_empty() {
        let mut req = request();
        req.acton_ai_version = Some(String::new());
        assert!(!install_fields(&req, "o", "p", "t").contains_key("acton_ai_version"));
        req.acton_ai_version = Some("0.34.0".into());
        assert_eq!(
            install_fields(&req, "o", "p", "t")["acton_ai_version"],
            json!("0.34.0")
        );
    }

    #[test]
    fn isolation_defaults_to_false_when_the_daemon_says_nothing() {
        assert_eq!(
            install_fields(&request(), "o", "p", "t")["isolation_active"],
            json!(false)
        );
    }

    #[test]
    fn a_credential_carries_only_public_material() {
        let fields = credential_fields(&request(), "org_1", "install_1", SUBJECT);
        assert_eq!(fields["public_key"], json!("BASE64SPKI"));
        assert_eq!(fields["status"], json!("active"));
        assert!(!fields.contains_key("cert_fingerprint"));
        for key in fields.keys() {
            assert!(
                !key.contains("secret") && !key.contains("private"),
                "credential field {key} looks secret-bearing"
            );
        }
    }

    #[test]
    fn an_mtls_enrollment_carries_its_fingerprint_through() {
        let mut req = request();
        req.credential_kind = "x509_mtls".into();
        req.cert_fingerprint = Some("a".repeat(64));
        assert_eq!(
            credential_fields(&req, "o", "i", SUBJECT)["cert_fingerprint"],
            json!("a".repeat(64))
        );
    }

    #[test]
    fn the_credential_id_is_stable_so_a_retry_collides_instead_of_duplicating() {
        assert_eq!(
            credential_id(&request(), SUBJECT),
            credential_id(&request(), SUBJECT)
        );
        assert_eq!(credential_id(&request(), SUBJECT), "inst-a.tok_7f3a");
    }

    #[test]
    fn a_refusal_records_the_reason_and_no_identity() {
        let response = refused(&Utc::now(), SUBJECT, "token expired");
        assert_eq!(response.outcome, Some("refused".into()));
        assert_eq!(response.refusal_reason, Some("token expired".into()));
        assert!(response.install.is_none());
        assert!(response.credential.is_none());
        assert!(response.abort_reason.is_none());
    }

    #[test]
    fn a_refusal_still_names_the_grant_that_was_presented() {
        // The client cannot send `token_id`, so if the hook does not stamp it
        // the persisted row records that something was refused without saying
        // which grant, which is the one fact the row exists to carry.
        assert_eq!(
            refused(&Utc::now(), SUBJECT, "token expired").token_id,
            Some(SUBJECT.into())
        );
        assert_eq!(
            refused_within(
                &Utc::now(),
                SUBJECT,
                &Some("org_1".into()),
                "tok_row",
                "token has been revoked"
            )
            .token_id,
            Some(SUBJECT.into())
        );
    }

    #[test]
    fn a_tenant_scoped_refusal_keeps_the_organization() {
        let response = refused_within(
            &Utc::now(),
            SUBJECT,
            &Some("org_1".into()),
            "tok_row",
            "token has been revoked",
        );
        assert_eq!(response.organization, Some("org_1".into()));
        assert_eq!(response.enrollment_token, Some("tok_row".into()));
        assert_eq!(response.outcome, Some("refused".into()));
    }

    #[test]
    fn the_gate_is_off_by_default_and_can_be_turned_on() {
        let plane = Plane::new("https://plane.gov", "tok").unwrap();
        let service = Service::new(plane, "garrison-enrollment");
        assert!(!service.gate.enabled);
        let gate = DirectoryGate {
            enabled: true,
            staleness: Duration::from_secs(60),
        };
        assert_eq!(service.with_directory(gate).gate, gate);
    }
}
