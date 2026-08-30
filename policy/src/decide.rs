//! Turning a bundle and one tool call into one of three answers.
//!
//! Pure, and deliberately so: this is the function an auditor is entitled to
//! read and an operator is entitled to reason about, and neither should have
//! to hold an actor, a network, or a clock in their head to do it.
//!
//! # The order, and why it is that order
//!
//! 1. **The tool rule.** A bundle names tools by name. A `deny` here ends it:
//!    nothing further can widen it.
//! 2. **The sandbox requirement.** A rule that says a tool needs isolation and
//!    finds none is a refusal, not a prompt. Asking an operator to approve a
//!    call the policy already said needs a sandbox would let a dialog
//!    overrule the bundle.
//! 3. **The command rules, for `bash` only.** The shell is decided by what it
//!    will actually run ([`crate::argv`]), one program at a time, and the
//!    strictest verdict across the chain wins. A tool rule that *auto-approves*
//!    `bash` is ignored on purpose — see below.
//! 4. **The fallback.** A tool nothing named is auto-approved when acton-ai
//!    declared it idempotent, and otherwise follows the bundle's
//!    `default_approval_mode`.
//!
//! # Why `bash` ignores a tool-level auto-approve
//!
//! One `ToolRule { tool_name: "bash", decision: auto_approve }` would silently
//! grant every command rule's worst case, which is exactly the laundering the
//! argv canonicalization exists to stop. A tool rule on `bash` may therefore
//! only deny it or require a sandbox for it; allowing shell commands is what
//! command rules are for.
//!
//! # Why idempotent tools are exempt from the fallback
//!
//! `read_file`, `grep`, `glob`, `list_directory`, `calculate`,
//! `get_context_remaining`, and `update_plan` are declared `idempotent: true`
//! upstream in acton-ai. That flag is not local configuration — no
//! `garrison.toml` can add to it — so honouring it cannot widen a bundle, and
//! not honouring it would make a governed install ask permission before every
//! plan update. A bundle that disagrees writes a `ToolRule`, which is checked
//! first and wins.

use crate::argv::{commands_of, ArgvError, Command};
use crate::bundle::{Bundle, CommandDecision, CommandRule, ToolDecision, ToolRule};
use serde_json::Value;

/// What the bundle says about one tool call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Run it without asking anybody.
    AutoApprove {
        /// The rule that said so, when one did.
        rule: Option<String>,
    },
    /// Ask the operator.
    Prompt {
        /// The rule that said so, when one did.
        rule: Option<String>,
        /// The rule's reason, to show in the dialog.
        justification: Option<String>,
    },
    /// Refuse it, and tell the model why.
    Deny {
        /// The rule that refused, when one did.
        rule: Option<String>,
        /// Words a human can act on.
        reason: String,
    },
}

impl Disposition {
    /// A prompt with no rule behind it.
    #[must_use]
    pub const fn ask() -> Self {
        Self::Prompt {
            rule: None,
            justification: None,
        }
    }

    /// Whether this call reaches a human.
    #[must_use]
    pub const fn is_prompt(&self) -> bool {
        matches!(self, Self::Prompt { .. })
    }
}

/// What the caller knows about the call that the bundle does not.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// The tool the model asked for.
    pub tool_name: &'a str,
    /// The arguments it proposed. Only `bash`'s `command` is read.
    pub arguments: &'a Value,
    /// Whether the runtime's writing tools are actually confined right now.
    pub sandbox_active: bool,
    /// Whether acton-ai declares this tool idempotent. Upstream-declared; see
    /// the module docs.
    pub idempotent: bool,
}

/// The decision, for one call, under one bundle.
#[must_use]
pub fn decide(bundle: &Bundle, context: &Context<'_>) -> Disposition {
    let tool = best_tool_rule(bundle, context.tool_name);

    if let Some(rule) = tool {
        if rule.decision == ToolDecision::Deny {
            return Disposition::Deny {
                rule: Some(rule.tool_name.clone()),
                reason: refusal_reason(rule, context.tool_name),
            };
        }
        if rule.sandbox_required && !context.sandbox_active {
            return Disposition::Deny {
                rule: Some(rule.tool_name.clone()),
                reason: format!(
                    "policy requires a sandbox for '{}' and none is active; \
                     turn the sandbox on in acton-ai.toml or ask for a bundle that does not \
                     require one",
                    context.tool_name
                ),
            };
        }
    }

    if context.tool_name == "bash" {
        return decide_shell(bundle, context.arguments);
    }

    match tool.map(|rule| rule.decision) {
        Some(ToolDecision::AutoApprove) => Disposition::AutoApprove {
            rule: tool.map(|rule| rule.tool_name.clone()),
        },
        Some(ToolDecision::Prompt) => Disposition::Prompt {
            rule: tool.map(|rule| rule.tool_name.clone()),
            justification: tool.and_then(justification_of),
        },
        Some(ToolDecision::Deny) | None => unmatched(bundle, context),
    }
}

/// What happens to a tool no enabled rule names.
fn unmatched(bundle: &Bundle, context: &Context<'_>) -> Disposition {
    if context.idempotent || bundle.header.default_approval_mode.admits_unmatched() {
        return Disposition::AutoApprove { rule: None };
    }
    Disposition::ask()
}

/// The shell, decided by what it will actually run.
fn decide_shell(bundle: &Bundle, arguments: &Value) -> Disposition {
    let Some(script) = arguments.get("command").and_then(Value::as_str) else {
        return Disposition::Prompt {
            rule: None,
            justification: Some(
                "the shell call carries no readable command, so policy cannot decide it"
                    .to_string(),
            ),
        };
    };

    let commands = match commands_of(script) {
        Ok(commands) => commands,
        Err(error) => return unreadable(&error),
    };
    if commands.is_empty() {
        return Disposition::ask();
    }

    let verdicts: Vec<(&Command, Option<&CommandRule>)> = commands
        .iter()
        .map(|command| (command, best_command_rule(bundle, command)))
        .collect();

    // The strictest verdict across the chain wins: one forbidden program in a
    // `&&` chain forbids the whole call, because the shell would have run it.
    if let Some((command, rule)) = verdicts
        .iter()
        .find(|(_, rule)| rule.is_some_and(|rule| rule.decision == CommandDecision::Forbid))
    {
        let rule = rule.expect("the find matched a rule");
        return Disposition::Deny {
            rule: Some(rule.name.clone()),
            reason: format!(
                "policy rule '{}' forbids `{}`: {}",
                rule.name,
                command.display(),
                display_justification(&rule.justification)
            ),
        };
    }

    if let Some((command, rule)) = verdicts
        .iter()
        .find(|(_, rule)| rule.is_none_or(|rule| rule.decision == CommandDecision::Prompt))
    {
        return Disposition::Prompt {
            rule: rule.map(|rule| rule.name.clone()),
            justification: Some(match rule {
                Some(rule) => format!(
                    "policy rule '{}' asks about `{}`: {}",
                    rule.name,
                    command.display(),
                    display_justification(&rule.justification)
                ),
                None => format!(
                    "no policy rule covers `{}`, so it needs an operator's decision",
                    command.display()
                ),
            }),
        };
    }

    Disposition::AutoApprove {
        rule: verdicts
            .first()
            .and_then(|(_, rule)| rule.map(|rule| rule.name.clone())),
    }
}

/// A shell command policy could not read is asked about, never approved.
fn unreadable(error: &ArgvError) -> Disposition {
    Disposition::Prompt {
        rule: None,
        justification: Some(format!(
            "policy could not read this shell command, so it cannot approve it: {error}"
        )),
    }
}

/// The enabled tool rule that governs this tool, if any.
///
/// An exact name beats a pattern, and among patterns the longest prefix wins,
/// so `mcp__docs__*` governs over `mcp__*` however the rows were ordered.
#[must_use]
pub fn best_tool_rule<'a>(bundle: &'a Bundle, tool_name: &str) -> Option<&'a ToolRule> {
    bundle
        .enabled_tool_rules()
        .filter(|rule| name_matches(&rule.tool_name, tool_name))
        .max_by_key(|rule| {
            (
                usize::from(rule.tool_name == tool_name),
                rule.tool_name.len(),
            )
        })
}

/// The enabled command rule that governs one program, if any.
///
/// Lowest `priority` wins; ties break by name so two rules that an author
/// gave the same priority still resolve the same way on every install.
#[must_use]
pub fn best_command_rule<'a>(bundle: &'a Bundle, command: &Command) -> Option<&'a CommandRule> {
    bundle
        .enabled_command_rules()
        .filter(|rule| {
            rule.program == command.program && pattern_matches(&rule.argv_pattern, &command.argv)
        })
        .min_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.name.cmp(&b.name))
        })
}

/// Whether an argv pattern covers an argv.
///
/// - An **empty** pattern matches any argv: a rule that names only a program
///   is a rule about that program, which is what an author writing
///   `program = "rm"` and nothing else means.
/// - `*` matches exactly one token.
/// - A trailing `**` matches everything left, including nothing.
/// - Anything else must be equal, and a non-empty pattern must consume the
///   whole argv, so `["status"]` does not match `git status --short`.
#[must_use]
pub fn pattern_matches(pattern: &[String], argv: &[String]) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let mut rest = argv;
    for (index, element) in pattern.iter().enumerate() {
        match element.as_str() {
            "**" => return index + 1 == pattern.len(),
            "*" => match rest.split_first() {
                Some((_, tail)) => rest = tail,
                None => return false,
            },
            literal => match rest.split_first() {
                Some((head, tail)) if head == literal => rest = tail,
                _ => return false,
            },
        }
    }
    rest.is_empty()
}

/// Whether a tool-name pattern covers a tool name.
///
/// The same two rules acton-ai's own `name_matches` applies — an exact name,
/// or a trailing `*` as a prefix — restated here because this crate is pure
/// and the hook service that also runs it has no business depending on an
/// inference runtime. The agent's ungoverned path calls acton-ai's function
/// directly rather than this one, so there is exactly one place each set of
/// semantics is applied.
#[must_use]
pub fn name_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

/// A tool rule's justification, when the author wrote one.
fn justification_of(rule: &ToolRule) -> Option<String> {
    (!rule.justification.trim().is_empty()).then(|| rule.justification.clone())
}

/// The sentence the model is told when a tool rule denies.
fn refusal_reason(rule: &ToolRule, tool_name: &str) -> String {
    format!(
        "policy denies '{tool_name}' (rule '{}'): {}",
        rule.tool_name,
        display_justification(&rule.justification)
    )
}

/// A justification, or a stand-in that does not read as an empty sentence.
fn display_justification(justification: &str) -> &str {
    let trimmed = justification.trim();
    if trimmed.is_empty() {
        "the bundle records no reason"
    } else {
        trimmed
    }
}

// =============================================================================
// Self-tests: a rule that does not match its own examples does not load
// =============================================================================

/// A rule's own examples disagree with the rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfTestFailure {
    /// The rule, by name.
    pub rule: String,
    /// The example that disagreed.
    pub example: String,
    /// What was expected of it.
    pub expected: Expectation,
    /// Why, when the example could not even be read.
    pub detail: Option<String>,
}

/// Which list an example came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expectation {
    /// It is in `match_examples` and the rule did not match it.
    Match,
    /// It is in `not_match_examples` and the rule matched it anyway.
    NotMatch,
}

impl std::fmt::Display for SelfTestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let verb = match self.expected {
            Expectation::Match => "does not match its own match_example",
            Expectation::NotMatch => "matches its own not_match_example",
        };
        write!(
            f,
            "command rule '{}' {} `{}`",
            self.rule, verb, self.example
        )?;
        if let Some(detail) = &self.detail {
            write!(f, " ({detail})")?;
        }
        Ok(())
    }
}

impl std::error::Error for SelfTestFailure {}

/// Runs one rule against the examples its author wrote.
///
/// This is what makes a bundle reviewable: an author states what a rule is
/// meant to catch and what it must not, and the publish gate refuses the
/// bundle if the pattern disagrees. A rule nobody can check is a rule nobody
/// should distribute.
///
/// # Errors
///
/// One [`SelfTestFailure`] per disagreeing example, in the order the author
/// wrote them.
pub fn self_test(rule: &CommandRule) -> Result<(), Vec<SelfTestFailure>> {
    let mut failures = Vec::new();

    for example in &rule.match_examples {
        match matches_example(rule, example) {
            Ok(true) => {}
            Ok(false) => failures.push(SelfTestFailure {
                rule: rule.name.clone(),
                example: example.clone(),
                expected: Expectation::Match,
                detail: None,
            }),
            Err(error) => failures.push(SelfTestFailure {
                rule: rule.name.clone(),
                example: example.clone(),
                expected: Expectation::Match,
                detail: Some(error.to_string()),
            }),
        }
    }

    for example in &rule.not_match_examples {
        // An unreadable not-match example is not a failure: policy would
        // prompt on it, which is the outcome the author wanted.
        if matches_example(rule, example).unwrap_or(false) {
            failures.push(SelfTestFailure {
                rule: rule.name.clone(),
                example: example.clone(),
                expected: Expectation::NotMatch,
                detail: None,
            });
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

/// Whether this rule matches any program in a shell command.
fn matches_example(rule: &CommandRule, example: &str) -> Result<bool, ArgvError> {
    Ok(commands_of(example)?.iter().any(|command| {
        rule.program == command.program && pattern_matches(&rule.argv_pattern, &command.argv)
    }))
}

/// Runs every enabled rule's self-test.
///
/// Called twice on purpose: by the publish gate, so a bad rule never reaches
/// a fleet, and by each daemon before it puts a bundle in force, so a bundle
/// that reached it some other way is still checked.
///
/// # Errors
///
/// Every failure, so one publish attempt reveals the whole problem.
pub fn validate(bundle: &Bundle) -> Result<(), Vec<SelfTestFailure>> {
    let failures: Vec<SelfTestFailure> = bundle
        .enabled_command_rules()
        .filter_map(|rule| self_test(rule).err())
        .flatten()
        .collect();

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{ApprovalMode, BundleHeader};
    use serde_json::json;

    fn command_rule(
        name: &str,
        program: &str,
        pattern: &[&str],
        decision: CommandDecision,
    ) -> CommandRule {
        CommandRule {
            name: name.into(),
            program: program.into(),
            argv_pattern: pattern.iter().map(|s| (*s).to_string()).collect(),
            decision,
            justification: format!("because of {name}"),
            enabled: true,
            priority: 100,
            ..CommandRule::default()
        }
    }

    fn tool_rule(tool_name: &str, decision: ToolDecision) -> ToolRule {
        ToolRule {
            tool_name: tool_name.into(),
            decision,
            justification: format!("because of {tool_name}"),
            sandbox_required: false,
            enabled: true,
            ..ToolRule::default()
        }
    }

    fn bundle(command_rules: Vec<CommandRule>, tool_rules: Vec<ToolRule>) -> Bundle {
        Bundle {
            header: BundleHeader {
                name: "Baseline".into(),
                default_approval_mode: ApprovalMode::OnRequest,
                ..BundleHeader::default()
            },
            command_rules,
            tool_rules,
            ..Bundle::default()
        }
    }

    fn call<'a>(tool_name: &'a str, arguments: &'a Value) -> Context<'a> {
        Context {
            tool_name,
            arguments,
            sandbox_active: true,
            idempotent: false,
        }
    }

    fn shell(command: &str) -> Value {
        json!({ "command": command })
    }

    #[test]
    fn a_tool_rule_that_denies_ends_the_decision() {
        let bundle = bundle(
            Vec::new(),
            vec![tool_rule("write_file", ToolDecision::Deny)],
        );

        let decision = decide(&bundle, &call("write_file", &json!({})));

        assert!(
            matches!(&decision, Disposition::Deny { reason, .. } if reason.contains("because of write_file")),
            "{decision:?}"
        );
    }

    #[test]
    fn a_tool_that_needs_a_sandbox_and_has_none_is_refused_not_asked_about() {
        let mut rule = tool_rule("write_file", ToolDecision::AutoApprove);
        rule.sandbox_required = true;
        let bundle = bundle(Vec::new(), vec![rule]);

        let arguments = json!({});
        let context = Context {
            sandbox_active: false,
            ..call("write_file", &arguments)
        };

        assert!(
            matches!(decide(&bundle, &context), Disposition::Deny { .. }),
            "an approval dialog must not be able to overrule the bundle"
        );
    }

    #[test]
    fn an_exact_tool_name_beats_a_pattern_and_the_longest_pattern_wins() {
        let bundle = bundle(
            Vec::new(),
            vec![
                tool_rule("mcp__*", ToolDecision::Deny),
                tool_rule("mcp__docs__*", ToolDecision::AutoApprove),
                tool_rule("mcp__docs__search", ToolDecision::Prompt),
            ],
        );

        assert!(matches!(
            decide(&bundle, &call("mcp__docs__search", &json!({}))),
            Disposition::Prompt { .. }
        ));
        assert!(matches!(
            decide(&bundle, &call("mcp__docs__list", &json!({}))),
            Disposition::AutoApprove { .. }
        ));
        assert!(matches!(
            decide(&bundle, &call("mcp__shell__run", &json!({}))),
            Disposition::Deny { .. }
        ));
    }

    #[test]
    fn an_unmatched_tool_follows_the_bundles_default_mode() {
        let asking = bundle(Vec::new(), Vec::new());
        assert!(decide(&asking, &call("write_file", &json!({}))).is_prompt());

        let mut never = asking.clone();
        never.header.default_approval_mode = ApprovalMode::Never;
        assert!(matches!(
            decide(&never, &call("write_file", &json!({}))),
            Disposition::AutoApprove { rule: None }
        ));
    }

    #[test]
    fn an_upstream_idempotent_tool_does_not_prompt_just_because_no_rule_names_it() {
        let bundle = bundle(Vec::new(), Vec::new());
        let arguments = json!({});
        let context = Context {
            idempotent: true,
            ..call("update_plan", &arguments)
        };

        assert!(matches!(
            decide(&bundle, &context),
            Disposition::AutoApprove { rule: None }
        ));
    }

    #[test]
    fn a_tool_rule_still_wins_over_the_idempotent_exemption() {
        let bundle = bundle(
            Vec::new(),
            vec![tool_rule("read_file", ToolDecision::Prompt)],
        );
        let arguments = json!({});
        let context = Context {
            idempotent: true,
            ..call("read_file", &arguments)
        };

        assert!(decide(&bundle, &context).is_prompt());
    }

    #[test]
    fn a_shell_command_is_decided_by_the_program_it_runs() {
        let bundle = bundle(
            vec![command_rule(
                "git status",
                "git",
                &["status"],
                CommandDecision::Allow,
            )],
            Vec::new(),
        );

        assert!(matches!(
            decide(&bundle, &call("bash", &shell("git status"))),
            Disposition::AutoApprove { .. }
        ));
    }

    #[test]
    fn wrapping_a_forbidden_command_in_a_shell_does_not_launder_it() {
        let bundle = bundle(
            vec![command_rule("no rm", "rm", &[], CommandDecision::Forbid)],
            Vec::new(),
        );

        for script in [
            "rm -rf /tmp/x",
            "bash -lc \"rm -rf /tmp/x\"",
            "true && rm x",
        ] {
            let decision = decide(&bundle, &call("bash", &shell(script)));
            assert!(
                matches!(&decision, Disposition::Deny { reason, .. } if reason.contains("no rm")),
                "{script}: {decision:?}"
            );
        }
    }

    #[test]
    fn the_strictest_verdict_in_a_chain_is_the_verdict() {
        let bundle = bundle(
            vec![
                command_rule("git status", "git", &["status"], CommandDecision::Allow),
                command_rule("no rm", "rm", &[], CommandDecision::Forbid),
            ],
            Vec::new(),
        );

        assert!(matches!(
            decide(
                &bundle,
                &call("bash", &shell("git status && rm -rf /tmp/x"))
            ),
            Disposition::Deny { .. }
        ));
        assert!(
            decide(&bundle, &call("bash", &shell("git status && ls"))).is_prompt(),
            "an uncovered program in the chain still needs a decision"
        );
    }

    #[test]
    fn a_tool_rule_auto_approving_bash_does_not_grant_every_command() {
        let bundle = bundle(
            vec![command_rule("no rm", "rm", &[], CommandDecision::Forbid)],
            vec![tool_rule("bash", ToolDecision::AutoApprove)],
        );

        assert!(matches!(
            decide(&bundle, &call("bash", &shell("rm x"))),
            Disposition::Deny { .. }
        ));
        assert!(
            decide(&bundle, &call("bash", &shell("curl example.gov"))).is_prompt(),
            "the shell is decided by command rules, never by one tool rule"
        );
    }

    #[test]
    fn a_tool_rule_may_still_deny_the_shell_outright() {
        let bundle = bundle(
            vec![command_rule(
                "git status",
                "git",
                &["status"],
                CommandDecision::Allow,
            )],
            vec![tool_rule("bash", ToolDecision::Deny)],
        );

        assert!(matches!(
            decide(&bundle, &call("bash", &shell("git status"))),
            Disposition::Deny { .. }
        ));
    }

    #[test]
    fn a_shell_command_policy_cannot_read_is_asked_about_and_never_approved() {
        let bundle = bundle(
            vec![command_rule(
                "git anything",
                "git",
                &[],
                CommandDecision::Allow,
            )],
            Vec::new(),
        );

        let decision = decide(&bundle, &call("bash", &shell("git $(cat /tmp/evil)")));

        assert!(decision.is_prompt(), "{decision:?}");
        assert!(
            matches!(&decision, Disposition::Prompt { justification: Some(why), .. }
                if why.contains("could not read")),
            "{decision:?}"
        );
    }

    #[test]
    fn a_shell_call_with_no_command_argument_is_asked_about() {
        let bundle = bundle(Vec::new(), Vec::new());

        assert!(decide(&bundle, &call("bash", &json!({}))).is_prompt());
    }

    #[test]
    fn the_lowest_priority_number_wins_and_ties_break_by_name() {
        let mut forbid = command_rule("aaa forbid", "git", &[], CommandDecision::Forbid);
        forbid.priority = 10;
        let mut allow = command_rule("zzz allow", "git", &[], CommandDecision::Allow);
        allow.priority = 100;
        let bundle = bundle(vec![allow, forbid], Vec::new());

        assert!(matches!(
            decide(&bundle, &call("bash", &shell("git push"))),
            Disposition::Deny { .. }
        ));
    }

    #[test]
    fn a_disabled_rule_decides_nothing() {
        let mut rule = command_rule("no rm", "rm", &[], CommandDecision::Forbid);
        rule.enabled = false;
        let bundle = bundle(vec![rule], Vec::new());

        assert!(decide(&bundle, &call("bash", &shell("rm x"))).is_prompt());
    }

    #[test]
    fn an_empty_pattern_is_a_rule_about_the_program_itself() {
        assert!(pattern_matches(&[], &["-rf".to_string(), "/".to_string()]));
        assert!(pattern_matches(&[], &[]));
    }

    #[test]
    fn a_named_pattern_must_consume_the_whole_argv() {
        let pattern = vec!["status".to_string()];

        assert!(pattern_matches(&pattern, &["status".to_string()]));
        assert!(!pattern_matches(
            &pattern,
            &["status".to_string(), "--short".to_string()]
        ));
        assert!(!pattern_matches(&pattern, &[]));
    }

    #[test]
    fn a_star_matches_exactly_one_token_and_a_double_star_matches_the_rest() {
        let one = vec!["log".to_string(), "*".to_string()];
        assert!(pattern_matches(
            &one,
            &["log".to_string(), "-5".to_string()]
        ));
        assert!(!pattern_matches(&one, &["log".to_string()]));
        assert!(!pattern_matches(
            &one,
            &["log".to_string(), "-5".to_string(), "--oneline".to_string()]
        ));

        let rest = vec!["log".to_string(), "**".to_string()];
        assert!(pattern_matches(&rest, &["log".to_string()]));
        assert!(pattern_matches(
            &rest,
            &["log".to_string(), "-5".to_string(), "--oneline".to_string()]
        ));
        assert!(!pattern_matches(&rest, &["status".to_string()]));
    }

    #[test]
    fn a_double_star_before_the_end_of_a_pattern_matches_nothing() {
        let pattern = vec!["**".to_string(), "status".to_string()];

        assert!(!pattern_matches(&pattern, &["status".to_string()]));
    }

    #[test]
    fn a_rule_that_matches_its_own_examples_passes_its_self_test() {
        let mut rule = command_rule("git status", "git", &["status"], CommandDecision::Allow);
        rule.match_examples = vec!["git status".into(), "bash -lc 'git status'".into()];
        rule.not_match_examples = vec!["git push".into(), "rm -rf /".into()];

        self_test(&rule).expect("the rule agrees with its author");
    }

    #[test]
    fn a_rule_that_does_not_match_its_own_example_names_the_example() {
        let mut rule = command_rule("git status", "git", &["status"], CommandDecision::Allow);
        rule.match_examples = vec!["git log".into()];

        let failures = self_test(&rule).expect_err("the rule disagrees with its author");

        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].expected, Expectation::Match);
        assert!(failures[0].to_string().contains("git log"));
        assert!(failures[0].to_string().contains("git status"));
    }

    #[test]
    fn a_rule_that_matches_what_it_promised_not_to_is_a_failure_too() {
        let mut rule = command_rule("git", "git", &[], CommandDecision::Allow);
        rule.not_match_examples = vec!["git push --force".into()];

        let failures = self_test(&rule).expect_err("the pattern is wider than the author thought");

        assert_eq!(failures[0].expected, Expectation::NotMatch);
        assert!(failures[0].to_string().contains("not_match_example"));
    }

    #[test]
    fn an_unreadable_match_example_is_a_failure_that_says_why() {
        let mut rule = command_rule("git status", "git", &["status"], CommandDecision::Allow);
        rule.match_examples = vec!["git status \"".into()];

        let failures = self_test(&rule).expect_err("an example nobody can read is not a test");

        assert!(failures[0].detail.is_some());
        assert!(failures[0].to_string().contains("quoting"));
    }

    #[test]
    fn an_unreadable_not_match_example_is_not_a_failure_because_policy_would_prompt() {
        let mut rule = command_rule("git status", "git", &["status"], CommandDecision::Allow);
        rule.not_match_examples = vec!["git status \"".into()];

        self_test(&rule).expect("a command policy cannot read is already asked about");
    }

    #[test]
    fn validating_a_bundle_reports_every_failure_not_just_the_first() {
        let mut first = command_rule("a", "git", &["status"], CommandDecision::Allow);
        first.match_examples = vec!["git log".into()];
        let mut second = command_rule("b", "rm", &["x"], CommandDecision::Forbid);
        second.match_examples = vec!["rm y".into()];

        let failures = validate(&bundle(vec![first, second], Vec::new()))
            .expect_err("both rules disagree with their authors");

        assert_eq!(failures.len(), 2);
    }

    #[test]
    fn a_disabled_rules_examples_are_not_checked() {
        let mut rule = command_rule("a", "git", &["status"], CommandDecision::Allow);
        rule.match_examples = vec!["git log".into()];
        rule.enabled = false;

        validate(&bundle(vec![rule], Vec::new())).expect("a rule not in force is not tested");
    }

    #[test]
    fn a_tool_name_pattern_is_an_exact_name_or_a_trailing_star() {
        assert!(name_matches("read_file", "read_file"));
        assert!(!name_matches("read_file", "read_files"));
        assert!(name_matches("mcp__*", "mcp__docs__search"));
        assert!(!name_matches("mcp__*", "bash"));
        assert!(name_matches("*", "anything"));
    }
}
