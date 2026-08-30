//! `PolicyBundle.before_validate` — the publish gate.
//!
//! # What publishing means
//!
//! A bundle in `draft` is somebody's work in progress. A bundle in
//! `published` is a thing every install in the organization will pull and put
//! in force, and the moment it flips is the last moment anyone can check it.
//! So this hook does the checking, and it does it here rather than in a
//! console or a CLI, because a check the submitter runs is a check the
//! submitter can skip.
//!
//! Three things happen, in this order:
//!
//! 1. **The rules are assembled.** The bundle's `CommandRule` and `ToolRule`
//!    rows and the `ModelEndpoint` rows it cites are read back from the plane
//!    with this service's own bearer, so what is checksummed is what an
//!    install will actually pull, not what the submitter says it will.
//! 2. **Every rule is run against its own examples.** A rule whose
//!    `match_examples` it does not match, or whose `not_match_examples` it
//!    does, refuses the publish and names the rule and the example. A rule
//!    nobody can check is a rule nobody should distribute.
//! 3. **The checksum is stamped**, along with `published_at` and
//!    `published_by`. Nothing else in the system writes that field: the plane
//!    evaluates `@require` rules ahead of `before_validate`, so a rule
//!    demanding 64 hex characters on the row would be one this gate runs too
//!    late to satisfy. What makes the field trustworthy is the binding, which
//!    is `required = true`, so a publish this gate cannot answer fails.
//!
//! # Why the hook is the producer
//!
//! Because the alternative is trusting the submitter's arithmetic. The
//! checksum is what lets an install say "the policy I am running is the
//! policy you published"; if the console computed it, a console that computed
//! it wrongly — or a caller that skipped the console — would produce a bundle
//! that verifies against nothing and grounds every machine that pulls it.
//! Running `garrison_policy::checksum` here, in the same crate version the
//! daemon verifies with, is what makes the two answers the same answer.
//!
//! # Fail closed
//!
//! Every path that cannot complete the check refuses the publish: an
//! unreachable plane, a bundle with no row id, a rule that fails its own
//! test. Drafting and retiring pass through untouched, so an author keeps
//! working on a bundle that is not yet in force and an org_admin can always
//! withdraw one.

use std::sync::Arc;

use garrison_policy::{AgentsMdDiscovery, Bundle, BundleHeader};
use tonic::{Request, Response, Status};

use crate::pb::policy_bundle::policy_bundle_hooks_server::PolicyBundleHooks;
use crate::pb::policy_bundle::*;
use crate::plane::Plane;

/// Told to the console when a bundle is published by creating it.
///
/// The schema defaults `status` to `draft`, so a bundle is published by
/// updating one that already exists — and it has to be, because the rules
/// this gate checks point at the bundle by id, and a row being created does
/// not have one yet.
pub const CREATE_REFUSAL: &str =
    "a policy bundle is published by updating a draft, not by creating one already published: \
     its rules refer to it by id, and a bundle being created has none yet";

/// The publish gate. Holds the bearer it reads the bundle's rules back with.
pub struct Service {
    plane: Arc<Plane>,
}

impl Service {
    /// Builds the gate over a plane client carrying the `enrollment_service`
    /// role, which the policy schemas grant read and nothing else.
    #[must_use]
    pub fn new(plane: Plane) -> Self {
        Self {
            plane: Arc::new(plane),
        }
    }
}

#[tonic::async_trait]
impl PolicyBundleHooks for Service {
    /// Stamp the checksum and self-test the rules when a bundle is published.
    async fn before_validate(
        &self,
        request: Request<PolicyBundleBeforeValidateRequest>,
    ) -> Result<Response<PolicyBundleBeforeValidateResponse>, Status> {
        let request = request.into_inner();

        if !is_publish(request.status.as_deref()) {
            return Ok(Response::new(PolicyBundleBeforeValidateResponse::default()));
        }

        let Some(id) = request.entity_id.as_deref().filter(|id| !id.is_empty()) else {
            return Ok(Response::new(abort(CREATE_REFUSAL)));
        };

        let bundle = match self.assemble(id, &request).await {
            Ok(bundle) => bundle,
            Err(reason) => return Ok(Response::new(abort(&reason))),
        };

        Ok(Response::new(stamp(
            &bundle,
            request.user_id.as_deref(),
            &now(),
        )))
    }
}

impl Service {
    /// Reads the bundle's rules and endpoints back from the plane.
    ///
    /// The scalar fields come from the request, because those are the values
    /// about to be written; everything else comes from the plane, because
    /// those are the values an install will pull.
    async fn assemble(
        &self,
        id: &str,
        request: &PolicyBundleBeforeValidateRequest,
    ) -> Result<Bundle, String> {
        let command_rules = self
            .plane
            .command_rules_of(id)
            .await
            .map_err(|error| unreachable("its command rules", &error.to_string()))?;
        let tool_rules = self
            .plane
            .tool_rules_of(id)
            .await
            .map_err(|error| unreachable("its tool rules", &error.to_string()))?;
        let endpoints = self
            .plane
            .model_endpoints(&request.allowed_endpoints)
            .await
            .map_err(|error| unreachable("its approved endpoints", &error.to_string()))?;

        let bundle = Bundle {
            header: header_of(id, request),
            command_rules,
            tool_rules,
            endpoints,
        };

        garrison_policy::validate(&bundle).map_err(|failures| refusal(&failures))?;
        Ok(bundle)
    }
}

/// The incoming row's own fields, as a bundle header.
///
/// Pure. `checksum` is left empty: what is being computed is the checksum of
/// everything else, so including whatever the submitter put there would make
/// the answer depend on the guess.
fn header_of(id: &str, request: &PolicyBundleBeforeValidateRequest) -> BundleHeader {
    BundleHeader {
        id: id.to_string(),
        name: request.name.clone(),
        version: request.version.max(0).unsigned_abs(),
        organization: request.organization.clone(),
        status: request.status.clone().unwrap_or_default(),
        default_approval_mode: parse_enum(request.default_approval_mode.as_deref()),
        network_egress: parse_enum(request.network_egress.as_deref()),
        allow_unsandboxed_escalation: request.allow_unsandboxed_escalation.unwrap_or(false),
        agents_md_discovery: parse_agents_md_discovery(request.agents_md_discovery.as_deref()),
        agents_md_allowed_paths: request.agents_md_allowed_paths.clone().unwrap_or_default(),
        checksum: String::new(),
        allowed_endpoints: request.allowed_endpoints.clone(),
    }
}

/// The response that stamps a verified bundle. Pure.
///
/// `published_by` is the subject claim of whoever made the request, which is
/// the plane's word rather than the submitter's: the whole point of recording
/// it is that an auditor can ask who put this policy in force.
fn stamp(bundle: &Bundle, user_id: Option<&str>, now: &str) -> PolicyBundleBeforeValidateResponse {
    PolicyBundleBeforeValidateResponse {
        checksum: Some(garrison_policy::checksum(bundle)),
        published_at: Some(now.to_string()),
        published_by: Some(user_id.unwrap_or("unknown").to_string()),
        ..Default::default()
    }
}

/// A response that refuses the write, and nothing else. Pure.
fn abort(reason: &str) -> PolicyBundleBeforeValidateResponse {
    PolicyBundleBeforeValidateResponse {
        abort_reason: Some(reason.to_string()),
        ..Default::default()
    }
}

/// Whether the incoming row is trying to be `published`. Pure.
fn is_publish(status: Option<&str>) -> bool {
    status == Some("published")
}

/// The sentence a console shows when a rule disagrees with its author. Pure.
///
/// Every failure, not the first: an author fixing one rule per attempt is an
/// author who gives up and asks for the gate to be turned off.
fn refusal(failures: &[garrison_policy::SelfTestFailure]) -> String {
    let listed: Vec<String> = failures.iter().map(ToString::to_string).collect();
    format!(
        "this bundle cannot be published because {} of its rules do not agree with their own \
         examples: {}",
        failures.len(),
        listed.join("; ")
    )
}

/// The sentence a console shows when the gate could not read the bundle. Pure.
fn unreachable(what: &str, error: &str) -> String {
    format!(
        "this bundle cannot be published because {what} could not be read back from the control \
         plane, so there is nothing to checksum: {error}"
    )
}

/// Parses one of the schema's snake_case enums, falling back to its default.
///
/// A value this service does not recognize is a schema that moved ahead of
/// this binary; the default is the stricter reading in both enums, and the
/// value is part of the checksum either way, so a fleet would see the change.
fn parse_enum<T: serde::de::DeserializeOwned + Default>(value: Option<&str>) -> T {
    value
        .and_then(|value| serde_json::from_value(serde_json::Value::String(value.to_string())).ok())
        .unwrap_or_default()
}

/// `agents_md_discovery` cannot use [`parse_enum`]'s generic fallback.
///
/// For every other enum in this hook, "the submitter left it unset" and "the
/// submitter sent a value this binary predates" collapse to the same safe
/// answer, because their `Default` derive already sits at the strict end
/// (`NetworkEgress::Deny`, `ApprovalMode::OnRequest`). `AgentsMdDiscovery`'s
/// schema default is `Enabled`, chosen so a bundle nobody has touched keeps
/// today's behavior — which makes it the *permissive* extreme, not the safe
/// one. Collapsing both cases onto it would mean a future discovery mode this
/// binary does not recognize silently decodes as unrestricted `AGENTS.md`
/// loading. So the two cases are told apart: absent still means `Enabled`
/// (backward compatible), but an unrecognized string fails closed to
/// `Disabled` rather than guessing it means the permissive default.
fn parse_agents_md_discovery(value: Option<&str>) -> AgentsMdDiscovery {
    match value {
        None => AgentsMdDiscovery::Enabled,
        Some(value) => {
            serde_json::from_value(serde_json::Value::String(value.to_string()))
                .unwrap_or(AgentsMdDiscovery::Disabled)
        }
    }
}

/// Now, in the format the plane's `datetime` columns take.
fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use garrison_policy::{
        ApprovalMode, CommandDecision, CommandRule, NetworkEgress, ToolDecision, ToolRule,
    };

    fn request(status: &str) -> PolicyBundleBeforeValidateRequest {
        PolicyBundleBeforeValidateRequest {
            operation: "update".into(),
            user_id: Some("user_security_officer".into()),
            entity_id: Some("policybundle_01".into()),
            name: "Baseline".into(),
            version: 3,
            organization: "organization_01".into(),
            status: Some(status.into()),
            default_approval_mode: Some("on_request".into()),
            network_egress: Some("approved_hosts".into()),
            allow_unsandboxed_escalation: Some(false),
            ..Default::default()
        }
    }

    fn rule(name: &str, program: &str, matches: &[&str], not: &[&str]) -> CommandRule {
        CommandRule {
            name: name.into(),
            program: program.into(),
            decision: CommandDecision::Forbid,
            justification: "because".into(),
            match_examples: matches.iter().map(|s| (*s).to_string()).collect(),
            not_match_examples: not.iter().map(|s| (*s).to_string()).collect(),
            enabled: true,
            priority: 100,
            ..CommandRule::default()
        }
    }

    fn bundle(rules: Vec<CommandRule>) -> Bundle {
        Bundle {
            header: header_of("policybundle_01", &request("published")),
            command_rules: rules,
            tool_rules: vec![ToolRule {
                tool_name: "read_file".into(),
                decision: ToolDecision::AutoApprove,
                justification: "reading is not a change".into(),
                sandbox_required: false,
                enabled: true,
                ..ToolRule::default()
            }],
            endpoints: Vec::new(),
        }
    }

    #[test]
    fn drafting_and_retiring_pass_through_untouched() {
        for status in [Some("draft"), Some("retired"), None] {
            assert!(!is_publish(status), "{status:?}");
        }
    }

    #[test]
    fn the_incoming_rows_own_fields_become_the_header_that_is_hashed() {
        let header = header_of("policybundle_01", &request("published"));

        assert_eq!(header.id, "policybundle_01");
        assert_eq!(header.name, "Baseline");
        assert_eq!(header.version, 3);
        assert_eq!(header.default_approval_mode, ApprovalMode::OnRequest);
        assert_eq!(header.network_egress, NetworkEgress::ApprovedHosts);
        assert!(header.is_published());
    }

    #[test]
    fn agents_md_fields_default_to_enabled_and_no_restriction_when_absent() {
        let header = header_of("policybundle_01", &request("published"));

        assert_eq!(header.agents_md_discovery, AgentsMdDiscovery::Enabled);
        assert_eq!(header.agents_md_allowed_paths, "");
    }

    #[test]
    fn agents_md_fields_carry_through_when_the_submitter_sets_them() {
        let mut submitted = request("published");
        submitted.agents_md_discovery = Some("restricted".into());
        submitted.agents_md_allowed_paths = Some("docs\ntools".into());

        let header = header_of("policybundle_01", &submitted);

        assert_eq!(header.agents_md_discovery, AgentsMdDiscovery::Restricted);
        assert_eq!(header.agents_md_allowed_paths, "docs\ntools");
    }

    #[test]
    fn whatever_checksum_the_submitter_sent_is_not_part_of_the_answer() {
        let mut submitted = request("published");
        submitted.checksum = Some("f".repeat(64));

        assert!(
            header_of("policybundle_01", &submitted).checksum.is_empty(),
            "the gate computes the checksum; it does not confirm a guess"
        );
    }

    #[test]
    fn an_enum_this_binary_does_not_know_reads_as_the_stricter_default() {
        let mut ahead = request("published");
        ahead.default_approval_mode = Some("telepathic".into());
        ahead.network_egress = Some("telepathic".into());

        let header = header_of("policybundle_01", &ahead);

        assert_eq!(header.default_approval_mode, ApprovalMode::OnRequest);
        assert_eq!(header.network_egress, NetworkEgress::Deny);
    }

    #[test]
    fn an_agents_md_mode_this_binary_does_not_know_fails_closed_to_disabled() {
        let mut ahead = request("published");
        ahead.agents_md_discovery = Some("telepathic".into());

        let header = header_of("policybundle_01", &ahead);

        assert_eq!(
            header.agents_md_discovery,
            AgentsMdDiscovery::Disabled,
            "unlike the other enums, this field's schema default is the \
             permissive extreme, so an unrecognized value must not fall back \
             to it"
        );
    }

    #[test]
    fn a_verified_bundle_is_stamped_with_a_checksum_a_publish_can_satisfy() {
        let bundle = bundle(vec![rule("no rm", "rm", &["rm -rf /tmp/x"], &["ls"])]);

        let response = stamp(
            &bundle,
            Some("user_security_officer"),
            "2026-08-29T00:00:00Z",
        );

        let checksum = response.checksum.expect("a published bundle is stamped");
        assert_eq!(checksum.len(), 64, "BLAKE3 in lowercase hex");
        assert!(checksum.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            checksum,
            garrison_policy::checksum(&bundle),
            "the gate stamps what the daemon will compute"
        );
        assert_eq!(
            response.published_by.as_deref(),
            Some("user_security_officer")
        );
        assert_eq!(
            response.published_at.as_deref(),
            Some("2026-08-29T00:00:00Z")
        );
        assert!(response.abort_reason.is_none());
    }

    #[test]
    fn a_publish_by_an_unauthenticated_caller_still_records_who_it_was_not() {
        let response = stamp(&bundle(Vec::new()), None, "2026-08-29T00:00:00Z");

        assert_eq!(response.published_by.as_deref(), Some("unknown"));
    }

    #[test]
    fn a_rule_that_does_not_match_its_own_example_refuses_the_publish_by_name() {
        let failures =
            garrison_policy::validate(&bundle(vec![rule("no rm", "rm", &["ls /tmp"], &[])]))
                .expect_err("the rule disagrees with its author");

        let reason = refusal(&failures);

        assert!(reason.contains("no rm"), "{reason}");
        assert!(reason.contains("ls /tmp"), "{reason}");
        assert!(reason.contains("cannot be published"), "{reason}");
    }

    #[test]
    fn every_failing_rule_is_named_so_one_attempt_reveals_the_whole_problem() {
        let failures = garrison_policy::validate(&bundle(vec![
            rule("first", "rm", &["ls"], &[]),
            rule("second", "curl", &["wget x"], &[]),
        ]))
        .expect_err("both rules disagree");

        let reason = refusal(&failures);

        assert!(reason.contains("first"), "{reason}");
        assert!(reason.contains("second"), "{reason}");
        assert!(reason.starts_with("this bundle cannot be published because 2 "));
    }

    #[test]
    fn a_bundle_whose_rules_cannot_be_read_is_refused_rather_than_checksummed_empty() {
        let reason = unreachable("its command rules", "connection refused");

        assert!(reason.contains("nothing to checksum"), "{reason}");
        assert!(reason.contains("connection refused"), "{reason}");
    }

    #[test]
    fn creating_a_bundle_already_published_is_refused_with_the_reason() {
        let response = abort(CREATE_REFUSAL);

        assert_eq!(response.abort_reason.as_deref(), Some(CREATE_REFUSAL));
        assert!(response.checksum.is_none());
    }

    #[test]
    fn a_refusal_stamps_nothing() {
        let response = abort("no");

        assert!(response.checksum.is_none());
        assert!(response.published_at.is_none());
        assert!(response.published_by.is_none());
    }
}
