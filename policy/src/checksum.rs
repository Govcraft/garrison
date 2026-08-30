//! The one canonical form a bundle hashes to.
//!
//! # What the checksum is for
//!
//! An auditor's question is "is the machine running the policy we published".
//! The plane records a checksum when a bundle is published; the daemon hashes
//! what it pulled and compares. A mismatch means the content and the record
//! disagree, and the daemon refuses turns rather than guessing which one is
//! right. That only works if both ends hash the same bytes, which is why the
//! canonical form is defined here, in a crate both compile, rather than twice.
//!
//! # What is in it, and what deliberately is not
//!
//! In: everything that changes a decision — the bundle's name and version,
//! the default approval mode, the two recorded-but-unenforced fields (an
//! author who changes them has changed the published policy, whether or not
//! this release acts on them), and every **enabled** rule's matching terms
//! and verdict.
//!
//! Out: row ids, timestamps, the organization, the checksum itself, and
//! justifications. Ids and timestamps differ between a bundle and its copy in
//! another environment without the policy differing. Justifications are
//! display text: rewording "because it deletes files" must not invalidate
//! every install's cache mid-shift.
//!
//! Rules are sorted, so the order two queries happened to return them in is
//! not part of the answer.

use crate::bundle::{
    ApprovalMode, Bundle, CommandDecision, CommandRule, ModelEndpoint, NetworkEgress, ToolDecision,
    ToolRule,
};
use serde::Serialize;

/// The plane and the daemon disagree about what a bundle contains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChecksumMismatch {
    /// What the `PolicyBundle` row records.
    pub expected: String,
    /// What the content actually hashes to.
    pub found: String,
}

impl std::fmt::Display for ChecksumMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the bundle's checksum does not match its content: the control plane recorded \
             {}, the rules pulled with it hash to {}",
            self.expected, self.found
        )
    }
}

impl std::error::Error for ChecksumMismatch {}

/// The exact bytes a bundle's checksum is taken over.
///
/// Pure. Serde emits struct fields in declaration order, so the order below
/// *is* the canonical order; changing it changes every checksum in a fleet,
/// which is why a fixture test pins the answer.
#[must_use]
pub fn canonical_bytes(bundle: &Bundle) -> Vec<u8> {
    let mut commands: Vec<CanonicalCommand<'_>> = bundle
        .enabled_command_rules()
        .map(canonical_command)
        .collect();
    commands.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.name.cmp(b.name)));

    let mut tools: Vec<CanonicalTool<'_>> =
        bundle.enabled_tool_rules().map(canonical_tool).collect();
    tools.sort_by(|a, b| a.tool_name.cmp(b.tool_name));

    let mut endpoints: Vec<CanonicalEndpoint<'_>> =
        bundle.endpoints.iter().map(canonical_endpoint).collect();
    endpoints.sort_by(|a, b| a.name.cmp(b.name));

    let canonical = Canonical {
        name: &bundle.header.name,
        version: bundle.header.version,
        default_approval_mode: bundle.header.default_approval_mode,
        network_egress: bundle.header.network_egress,
        allow_unsandboxed_escalation: bundle.header.allow_unsandboxed_escalation,
        command_rules: commands,
        tool_rules: tools,
        endpoints,
    };

    // A struct of owned primitives and borrowed strings cannot fail to
    // serialize; the fallback keeps the signature infallible rather than
    // pushing an impossible error onto every caller.
    serde_json::to_vec(&canonical).unwrap_or_default()
}

/// The BLAKE3 of a bundle's canonical form, lowercase hex.
#[must_use]
pub fn checksum(bundle: &Bundle) -> String {
    blake3::hash(&canonical_bytes(bundle)).to_hex().to_string()
}

/// Whether the content agrees with the checksum the plane recorded.
///
/// # Errors
///
/// [`ChecksumMismatch`] naming both values, so the refusal an operator reads
/// says which side to look at.
pub fn verify(bundle: &Bundle) -> Result<(), ChecksumMismatch> {
    let found = checksum(bundle);
    if found == bundle.header.checksum {
        return Ok(());
    }
    Err(ChecksumMismatch {
        expected: bundle.header.checksum.clone(),
        found,
    })
}

/// Strips a base URL down to the form two spellings of one endpoint share.
///
/// A trailing slash is not a different endpoint, and an empty string is not a
/// URL. Used by the canonical form and by endpoint matching, so the two agree
/// about when two endpoints are the same one.
#[must_use]
pub fn normalize_base_url(url: Option<&str>) -> Option<&str> {
    let url = url?.trim().trim_end_matches('/');
    (!url.is_empty()).then_some(url)
}

#[derive(Serialize)]
struct Canonical<'a> {
    name: &'a str,
    version: u64,
    default_approval_mode: ApprovalMode,
    network_egress: NetworkEgress,
    allow_unsandboxed_escalation: bool,
    command_rules: Vec<CanonicalCommand<'a>>,
    tool_rules: Vec<CanonicalTool<'a>>,
    endpoints: Vec<CanonicalEndpoint<'a>>,
}

#[derive(Serialize)]
struct CanonicalCommand<'a> {
    name: &'a str,
    program: &'a str,
    argv_pattern: &'a [String],
    decision: CommandDecision,
    priority: u64,
}

#[derive(Serialize)]
struct CanonicalTool<'a> {
    tool_name: &'a str,
    decision: ToolDecision,
    sandbox_required: bool,
}

#[derive(Serialize)]
struct CanonicalEndpoint<'a> {
    name: &'a str,
    provider_type: &'a str,
    model: &'a str,
    base_url: Option<&'a str>,
    authorization: &'a str,
    status: &'a str,
}

const fn canonical_command(rule: &CommandRule) -> CanonicalCommand<'_> {
    CanonicalCommand {
        name: rule.name.as_str(),
        program: rule.program.as_str(),
        argv_pattern: rule.argv_pattern.as_slice(),
        decision: rule.decision,
        priority: rule.priority,
    }
}

const fn canonical_tool(rule: &ToolRule) -> CanonicalTool<'_> {
    CanonicalTool {
        tool_name: rule.tool_name.as_str(),
        decision: rule.decision,
        sandbox_required: rule.sandbox_required,
    }
}

fn canonical_endpoint(endpoint: &ModelEndpoint) -> CanonicalEndpoint<'_> {
    CanonicalEndpoint {
        name: endpoint.name.as_str(),
        provider_type: endpoint.provider_type.as_str(),
        model: endpoint.model.as_str(),
        base_url: normalize_base_url(endpoint.base_url.as_deref()),
        authorization: endpoint.authorization.as_str(),
        status: endpoint.status.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::BundleHeader;

    /// The bundle the fixture checksum below is taken over. Any change to it
    /// changes the expected hash, which is the point: both must move together
    /// and in one commit.
    fn fixture() -> Bundle {
        Bundle {
            header: BundleHeader {
                id: "policybundle_01".into(),
                name: "Baseline".into(),
                version: 3,
                organization: "organization_01".into(),
                status: "published".into(),
                default_approval_mode: ApprovalMode::OnRequest,
                network_egress: NetworkEgress::Deny,
                allow_unsandboxed_escalation: false,
                checksum: String::new(),
                allowed_endpoints: vec!["modelendpoint_01".into()],
            },
            command_rules: vec![
                CommandRule {
                    id: "commandrule_02".into(),
                    name: "no rm".into(),
                    program: "rm".into(),
                    argv_pattern: Vec::new(),
                    decision: CommandDecision::Forbid,
                    justification: "deleting files is not reviewable after the fact".into(),
                    priority: 10,
                    enabled: true,
                    ..CommandRule::default()
                },
                CommandRule {
                    id: "commandrule_01".into(),
                    name: "git status".into(),
                    program: "git".into(),
                    argv_pattern: vec!["status".into()],
                    decision: CommandDecision::Allow,
                    justification: "reading the working tree changes nothing".into(),
                    priority: 100,
                    enabled: true,
                    ..CommandRule::default()
                },
            ],
            tool_rules: vec![ToolRule {
                id: "toolrule_01".into(),
                tool_name: "read_file".into(),
                decision: ToolDecision::AutoApprove,
                justification: "reading is not a change".into(),
                sandbox_required: false,
                enabled: true,
            }],
            endpoints: vec![ModelEndpoint {
                id: "modelendpoint_01".into(),
                name: "on-prem ollama".into(),
                provider_type: "ollama".into(),
                model: "qwen3.8".into(),
                base_url: Some("http://127.0.0.1:11434/v1".into()),
                authorization: "ato".into(),
                status: "approved".into(),
            }],
        }
    }

    /// Pinned deliberately. A change to the canonical form is a fleet-wide
    /// cache invalidation and a checksum every published bundle has to be
    /// republished for, so it must never happen by accident.
    const FIXTURE_CHECKSUM: &str =
        "24b9266bb79ccf964fdb2d4d00ae3cffb5a858f015b69615731d1dfe7ec9c731";

    #[test]
    fn the_canonical_form_is_pinned_so_a_drift_is_a_deliberate_break() {
        assert_eq!(checksum(&fixture()), FIXTURE_CHECKSUM);
    }

    #[test]
    fn rule_order_from_the_plane_does_not_change_the_answer() {
        let mut shuffled = fixture();
        shuffled.command_rules.reverse();
        shuffled.tool_rules.reverse();
        shuffled.endpoints.reverse();

        assert_eq!(checksum(&shuffled), checksum(&fixture()));
    }

    #[test]
    fn row_ids_and_justifications_are_display_text_and_not_hashed() {
        let mut reworded = fixture();
        reworded.header.id = "policybundle_99".into();
        reworded.header.organization = "organization_99".into();
        reworded.command_rules[0].id = "commandrule_99".into();
        reworded.command_rules[0].justification = "a longer explanation entirely".into();
        reworded.command_rules[0].match_examples = vec!["rm -rf /".into()];

        assert_eq!(checksum(&reworded), checksum(&fixture()));
    }

    #[test]
    fn changing_a_rules_verdict_changes_the_checksum() {
        let mut widened = fixture();
        widened.command_rules[0].decision = CommandDecision::Allow;

        assert_ne!(checksum(&widened), checksum(&fixture()));
    }

    #[test]
    fn switching_a_rule_off_changes_the_checksum() {
        let mut disabled = fixture();
        disabled.command_rules[0].enabled = false;

        assert_ne!(
            checksum(&disabled),
            checksum(&fixture()),
            "removing a forbid rule must be visible to the fleet"
        );
    }

    #[test]
    fn a_recorded_but_unenforced_field_is_still_part_of_the_published_policy() {
        let mut widened = fixture();
        widened.header.allow_unsandboxed_escalation = true;

        assert_ne!(checksum(&widened), checksum(&fixture()));
    }

    #[test]
    fn a_bundle_whose_content_matches_its_recorded_checksum_verifies() {
        let mut bundle = fixture();
        bundle.header.checksum = checksum(&bundle);

        verify(&bundle).expect("the content agrees with the record");
    }

    #[test]
    fn a_mismatch_names_both_sides_so_the_refusal_says_where_to_look() {
        let mut bundle = fixture();
        bundle.header.checksum = "0".repeat(64);

        let mismatch = verify(&bundle).expect_err("the record disagrees");

        assert_eq!(mismatch.expected, "0".repeat(64));
        assert_eq!(mismatch.found, FIXTURE_CHECKSUM);
        assert!(mismatch.to_string().contains(FIXTURE_CHECKSUM));
    }

    #[test]
    fn a_checksum_is_sixty_four_lowercase_hex_characters() {
        let hash = checksum(&fixture());

        assert_eq!(hash.len(), 64);
        assert!(hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn a_trailing_slash_is_not_a_different_endpoint() {
        assert_eq!(
            normalize_base_url(Some("http://x/v1/")),
            normalize_base_url(Some("http://x/v1"))
        );
        assert_eq!(normalize_base_url(Some("  ")), None);
        assert_eq!(normalize_base_url(None), None);
    }
}
