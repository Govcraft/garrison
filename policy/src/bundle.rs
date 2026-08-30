//! What a policy bundle is, in the shape both ends of the wire see it.
//!
//! These types deserialize directly from a flattened SchemaForge row — `{id,
//! …fields}` — because that is what both consumers actually hold: the hook
//! service reads the rows it is about to checksum, and the daemon reads the
//! rows it pulled. Writing the struct to match the schema means the two ends
//! cannot disagree about what a field is called, which is the whole reason
//! this crate exists rather than two copies of the same serde attributes.
//!
//! # Defaults are the schema's defaults
//!
//! Every optional field carries the default the `.schema` file declares, so a
//! row the plane returned with a column omitted reads the same way the plane
//! would have read it. Silently defaulting `enabled` to `false`, say, would
//! turn a transport quirk into a policy change.

use serde::{Deserialize, Serialize};

/// A whole bundle: the row, its rules, and the endpoints it cites.
///
/// Assembled rather than deserialized in one piece, because the plane stores
/// it in four tables and the relation columns on the row are ids rather than
/// the rows themselves.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    /// The `PolicyBundle` row's own fields.
    pub header: BundleHeader,
    /// Its `CommandRule` rows, in whatever order they arrived.
    #[serde(default)]
    pub command_rules: Vec<CommandRule>,
    /// Its `ToolRule` rows.
    #[serde(default)]
    pub tool_rules: Vec<ToolRule>,
    /// The `ModelEndpoint` rows named by `allowed_endpoints`.
    #[serde(default)]
    pub endpoints: Vec<ModelEndpoint>,
}

impl Bundle {
    /// The bundle's row id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.header.id
    }

    /// Its name, as an operator wrote it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.header.name
    }

    /// Its version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.header.version
    }

    /// The checksum the plane recorded, which may or may not be the one the
    /// content hashes to; see [`crate::checksum::verify`].
    #[must_use]
    pub fn checksum(&self) -> &str {
        &self.header.checksum
    }

    /// Only the rules an author left switched on.
    ///
    /// Disabled rules are excluded from every decision and from the canonical
    /// form, so switching one off changes the checksum — which is what makes
    /// "somebody disabled the rule that stopped this" visible in the fleet.
    pub fn enabled_command_rules(&self) -> impl Iterator<Item = &CommandRule> {
        self.command_rules.iter().filter(|rule| rule.enabled)
    }

    /// Only the tool rules an author left switched on.
    pub fn enabled_tool_rules(&self) -> impl Iterator<Item = &ToolRule> {
        self.tool_rules.iter().filter(|rule| rule.enabled)
    }

    /// The two fields this release records but does not enforce.
    ///
    /// `network_egress` and `allow_unsandboxed_escalation` are pulled,
    /// checksummed, and reported, and nothing in the daemon acts on them: the
    /// agent has no egress control and no escalation path to withhold. They
    /// are named here so `_garrison/status` can say so out loud, because a
    /// bundle author who sets `network_egress = "deny"` and is not told
    /// otherwise will believe it is in force.
    #[must_use]
    pub fn not_enforced() -> &'static [&'static str] {
        &["network_egress", "allow_unsandboxed_escalation"]
    }
}

/// The scalar half of a `PolicyBundle` row.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleHeader {
    /// The row id.
    #[serde(default)]
    pub id: String,
    /// The name an operator gave it.
    #[serde(default)]
    pub name: String,
    /// Its version, which an author bumps rather than editing in place.
    #[serde(default = "one")]
    pub version: u64,
    /// The `Organization` it belongs to, by row id.
    #[serde(default)]
    pub organization: String,
    /// `draft`, `published`, or `retired`.
    #[serde(default)]
    pub status: String,
    /// What happens to a tool no rule names.
    #[serde(default)]
    pub default_approval_mode: ApprovalMode,
    /// Recorded, not enforced; see [`Bundle::not_enforced`].
    #[serde(default)]
    pub network_egress: NetworkEgress,
    /// Recorded, not enforced; see [`Bundle::not_enforced`].
    #[serde(default)]
    pub allow_unsandboxed_escalation: bool,
    /// The BLAKE3 the plane recorded when the bundle was published.
    #[serde(default)]
    pub checksum: String,
    /// The `ModelEndpoint` rows this bundle approves, by row id.
    ///
    /// The ids rather than the rows, because that is what the relation column
    /// holds. They are not part of the canonical form: what is hashed is the
    /// endpoints themselves, so a bundle citing a row that was since deleted
    /// hashes differently from one citing a row that still exists, which is
    /// the outcome worth detecting.
    #[serde(default)]
    pub allowed_endpoints: Vec<String>,
}

impl BundleHeader {
    /// Whether the plane considers this bundle distributable.
    #[must_use]
    pub fn is_published(&self) -> bool {
        self.status == "published"
    }
}

/// What a tool no rule names is subject to.
///
/// Codex's vocabulary, kept because the escalation flow it describes is the
/// one `garrison-agent` implements. Only `never` — never ask — is a decision
/// this release can act on without a rule; the rest collapse to a prompt,
/// which is the reading that cannot let a call through unseen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Ask about everything; treat the workspace as untrusted.
    Untrusted,
    /// Ask once something has failed.
    OnFailure,
    /// Ask when the model asks. The schema's default.
    #[default]
    OnRequest,
    /// Never ask.
    Never,
    /// Ask per category.
    Granular,
}

impl ApprovalMode {
    /// Whether an unmatched tool runs without asking anybody.
    #[must_use]
    pub const fn admits_unmatched(self) -> bool {
        matches!(self, Self::Never)
    }
}

/// What the bundle says about reaching the network.
///
/// Recorded and checksummed; see [`Bundle::not_enforced`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkEgress {
    /// No egress.
    #[default]
    Deny,
    /// Only hosts the organization approved.
    ApprovedHosts,
    /// Any host.
    Allow,
}

/// A rule about one program's canonicalized argv.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRule {
    /// The row id.
    #[serde(default)]
    pub id: String,
    /// The name an author gave the rule; it appears in refusals.
    #[serde(default)]
    pub name: String,
    /// Canonicalized `argv[0]`, e.g. `git`. Compared by basename, so
    /// `/usr/bin/git` and `git` are the same program.
    #[serde(default)]
    pub program: String,
    /// The argv pattern after the program.
    ///
    /// Empty matches **any** argv, because a rule that names only a program
    /// is a rule about that program. `*` matches exactly one token and a
    /// trailing `**` matches the rest; see [`crate::decide::pattern_matches`].
    #[serde(default)]
    pub argv_pattern: Vec<String>,
    /// What to do when it matches.
    #[serde(default)]
    pub decision: CommandDecision,
    /// Why, in the author's words. Surfaces verbatim in a refusal and in the
    /// approval dialog, which is the point of requiring it.
    #[serde(default)]
    pub justification: String,
    /// Shell commands this rule must match. Checked on publish and again
    /// before the bundle is put in force.
    #[serde(default)]
    pub match_examples: Vec<String>,
    /// Shell commands this rule must not match.
    #[serde(default)]
    pub not_match_examples: Vec<String>,
    /// Lower numbers win. The schema's default is 100.
    #[serde(default = "hundred")]
    pub priority: u64,
    /// Whether the rule is in force at all.
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// What a matching command rule decides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandDecision {
    /// Run it without asking.
    Allow,
    /// Ask the operator. The reading a missing value gets, because a rule
    /// whose decision did not survive the wire must not silently allow.
    #[default]
    Prompt,
    /// Refuse it, with the rule's justification as the reason.
    Forbid,
}

/// A rule about one of the agent's tools by name.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRule {
    /// The row id.
    #[serde(default)]
    pub id: String,
    /// The tool's name, or a trailing-`*` prefix pattern such as `mcp__*`.
    #[serde(default)]
    pub tool_name: String,
    /// What to do when it matches.
    #[serde(default)]
    pub decision: ToolDecision,
    /// Why, in the author's words.
    #[serde(default)]
    pub justification: String,
    /// Whether this tool may run at all without an active sandbox. The
    /// schema's default is `true`.
    #[serde(default = "yes")]
    pub sandbox_required: bool,
    /// Whether the rule is in force.
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// What a matching tool rule decides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolDecision {
    /// Run it without asking.
    AutoApprove,
    /// Ask the operator. The default, for the same reason as
    /// [`CommandDecision::Prompt`].
    #[default]
    Prompt,
    /// Refuse it.
    Deny,
}

/// A model endpoint the organization has taken a position on.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelEndpoint {
    /// The row id.
    #[serde(default)]
    pub id: String,
    /// The name an operator gave it.
    #[serde(default)]
    pub name: String,
    /// `anthropic`, `openai`, `kimi`, `ollama`, or `openai_compatible`.
    #[serde(default)]
    pub provider_type: String,
    /// The model identifier this endpoint serves.
    #[serde(default)]
    pub model: String,
    /// Its base URL, when it has one.
    #[serde(default)]
    pub base_url: Option<String>,
    /// `pilot`, `interim_ato`, `ato`, or `denied`.
    #[serde(default)]
    pub authorization: String,
    /// `approved`, `suspended`, or `retired`.
    #[serde(default)]
    pub status: String,
}

impl ModelEndpoint {
    /// Whether code may be sent here at all.
    ///
    /// Both halves must agree: an endpoint the organization suspended is not
    /// usable however it was authorized, and one whose authorization was
    /// withdrawn is not usable however its status reads.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.status == "approved" && self.authorization != "denied"
    }
}

const fn one() -> u64 {
    1
}

const fn hundred() -> u64 {
    100
}

const fn yes() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_command_rule_reads_from_a_flattened_row_with_the_schemas_defaults() {
        let rule: CommandRule = serde_json::from_value(json!({
            "id": "commandrule_01",
            "name": "git status",
            "program": "git",
            "argv_pattern": ["status"],
            "decision": "allow",
            "justification": "reading the working tree changes nothing"
        }))
        .expect("a row parses");

        assert_eq!(rule.decision, CommandDecision::Allow);
        assert_eq!(rule.priority, 100, "the schema's default priority");
        assert!(rule.enabled, "the schema's default is enabled");
        assert!(rule.match_examples.is_empty());
    }

    #[test]
    fn a_tool_rule_keeps_the_schemas_sandbox_default() {
        let rule: ToolRule = serde_json::from_value(json!({
            "tool_name": "write_file",
            "decision": "prompt",
            "justification": "writing is reviewed"
        }))
        .expect("a row parses");

        assert!(
            rule.sandbox_required,
            "the schema defaults sandbox_required to true"
        );
        assert!(rule.enabled);
    }

    #[test]
    fn a_decision_that_did_not_survive_the_wire_prompts_rather_than_allows() {
        assert_eq!(CommandDecision::default(), CommandDecision::Prompt);
        assert_eq!(ToolDecision::default(), ToolDecision::Prompt);
    }

    #[test]
    fn only_never_admits_a_tool_no_rule_names() {
        assert!(ApprovalMode::Never.admits_unmatched());
        for mode in [
            ApprovalMode::Untrusted,
            ApprovalMode::OnFailure,
            ApprovalMode::OnRequest,
            ApprovalMode::Granular,
        ] {
            assert!(!mode.admits_unmatched(), "{mode:?}");
        }
    }

    #[test]
    fn an_endpoint_needs_both_an_approved_status_and_a_standing_authorization() {
        let usable = ModelEndpoint {
            status: "approved".into(),
            authorization: "ato".into(),
            ..ModelEndpoint::default()
        };
        assert!(usable.is_usable());

        let suspended = ModelEndpoint {
            status: "suspended".into(),
            ..usable.clone()
        };
        assert!(!suspended.is_usable());

        let denied = ModelEndpoint {
            authorization: "denied".into(),
            ..usable
        };
        assert!(!denied.is_usable());
    }

    #[test]
    fn a_disabled_rule_is_not_part_of_the_bundle_in_force() {
        let bundle = Bundle {
            command_rules: vec![
                CommandRule {
                    name: "on".into(),
                    enabled: true,
                    ..CommandRule::default()
                },
                CommandRule {
                    name: "off".into(),
                    enabled: false,
                    ..CommandRule::default()
                },
            ],
            tool_rules: vec![ToolRule {
                tool_name: "off".into(),
                enabled: false,
                ..ToolRule::default()
            }],
            ..Bundle::default()
        };

        let names: Vec<&str> = bundle
            .enabled_command_rules()
            .map(|rule| rule.name.as_str())
            .collect();
        assert_eq!(names, ["on"]);
        assert_eq!(bundle.enabled_tool_rules().count(), 0);
    }

    #[test]
    fn the_two_recorded_but_unenforced_fields_are_named_so_status_can_say_so() {
        assert_eq!(
            Bundle::not_enforced(),
            ["network_egress", "allow_unsandboxed_escalation"]
        );
    }

    #[test]
    fn a_bundle_row_defaults_to_version_one_and_a_prompting_mode() {
        let header: BundleHeader =
            serde_json::from_value(json!({ "id": "policybundle_01", "name": "Baseline" }))
                .expect("a row parses");

        assert_eq!(header.version, 1);
        assert_eq!(header.default_approval_mode, ApprovalMode::OnRequest);
        assert_eq!(header.network_egress, NetworkEgress::Deny);
        assert!(!header.is_published());
    }
}
