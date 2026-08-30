//! Features that ship in the binary but are not on.
//!
//! # Why a gate rather than a warning
//!
//! An experimental feature in a governance tool is an awkward object. It has
//! to be reachable, or nobody evaluates it and it never stops being
//! experimental. It must not be reachable by accident, because the whole
//! value of this binary is that what it did is what it said it would do, and
//! a subcommand whose exit codes may change is not something a pipeline should
//! come to depend on without somebody having decided to.
//!
//! A printed warning does not achieve the second. Warnings are read once and
//! then filtered out of CI logs. A refusal is read every time until somebody
//! makes a decision, and the decision leaves a trace: an environment variable
//! in a pipeline definition, or a line in `garrison.toml` that an auditor can
//! find.
//!
//! # What is being promised, and what is not
//!
//! Enabling one of these says: this may change, including its exit codes and
//! its output, without a major version bump. Everything else this binary does
//! keeps its usual contract. That distinction is the point of the gate, and it
//! is stated in the refusal so nobody has to read this file to learn it.

use serde::{Deserialize, Serialize};

/// The environment variable that turns features on for one invocation.
///
/// Comma-separated, so a runner enabling two features does not need two
/// variables and a future feature does not need a new one.
pub const ENV_VAR: &str = "GARRISON_EXPERIMENTAL";

/// An experimental feature's name, as written in config and the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Unattended pull request review. See `docs/review-mode.md`.
    Review,
}

impl Feature {
    /// The name used in `GARRISON_EXPERIMENTAL` and in `[experimental]`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Review => "review",
        }
    }
}

impl std::fmt::Display for Feature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `[experimental]` section of `garrison.toml`.
///
/// Absent means every feature is off, which is the only sane default: a
/// deployment that has not heard of a feature has not opted into it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExperimentalConfig {
    /// Whether unattended pull request review may run.
    pub review: bool,
}

impl ExperimentalConfig {
    /// Whether this config enables `feature`.
    #[must_use]
    pub const fn enables(self, feature: Feature) -> bool {
        match feature {
            Feature::Review => self.review,
        }
    }
}

/// Whether `value`, as read from [`ENV_VAR`], names `feature`.
///
/// Split out and pure because the parsing is where this would go wrong
/// quietly: a trailing space or a capital letter turning an intended opt-in
/// into a refusal an operator then debugs for twenty minutes.
#[must_use]
pub fn env_enables(value: &str, feature: Feature) -> bool {
    value.split(',').any(|entry| {
        let entry = entry.trim();
        // Case-insensitive on purpose. Nobody should lose an afternoon to
        // having typed `Review`, and there is no second feature named `REVIEW`
        // that this could confuse it with.
        entry.eq_ignore_ascii_case(feature.as_str())
    })
}

/// Whether `feature` may run, given the config and the environment.
///
/// Either source is enough. The environment suits a pipeline, where the opt-in
/// belongs beside the invocation and is visible in the job definition; the
/// config file suits a workstation, where it should not have to be retyped.
/// Neither can turn a feature *off* that the other turned on, because a gate
/// with two switches that disagree is a gate nobody can reason about.
#[must_use]
pub fn enabled(config: ExperimentalConfig, env: Option<&str>, feature: Feature) -> bool {
    config.enables(feature) || env.is_some_and(|value| env_enables(value, feature))
}

/// What to print when a feature is asked for and is not on.
///
/// Names both ways to enable it, because the right one depends on where this
/// is running and the binary does not know.
#[must_use]
pub fn refusal(feature: Feature) -> String {
    format!(
        "{feature} mode is experimental and not enabled.\n  \
         Set {ENV_VAR}={feature}, or `[experimental] {feature} = true` in \
         garrison.toml.\n  \
         Its behaviour and exit codes may change without a major version bump."
    )
}

/// What to print when a feature is on, once, before it runs.
///
/// Short by design. It goes to stderr on every invocation, and a paragraph
/// there would be scrolled past or filtered out.
#[must_use]
pub fn notice(feature: Feature) -> String {
    format!("warning: {feature} mode is experimental; exit codes may change")
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFF: ExperimentalConfig = ExperimentalConfig { review: false };
    const ON: ExperimentalConfig = ExperimentalConfig { review: true };

    #[test]
    fn nothing_is_experimental_by_default() {
        // The only safe default. A deployment that has not heard of a feature
        // has not opted into it.
        assert!(!enabled(
            ExperimentalConfig::default(),
            None,
            Feature::Review
        ));
    }

    #[test]
    fn the_config_file_can_turn_a_feature_on() {
        assert!(enabled(ON, None, Feature::Review));
    }

    #[test]
    fn the_environment_can_turn_a_feature_on() {
        assert!(enabled(OFF, Some("review"), Feature::Review));
    }

    #[test]
    fn an_unrelated_environment_value_does_not() {
        assert!(!enabled(OFF, Some("something-else"), Feature::Review));
        assert!(!enabled(OFF, Some(""), Feature::Review));
    }

    #[test]
    fn a_list_enables_the_feature_it_names() {
        // The variable is comma-separated so a second feature never needs a
        // second variable.
        assert!(enabled(OFF, Some("other,review"), Feature::Review));
        assert!(enabled(OFF, Some("review,other"), Feature::Review));
    }

    #[test]
    fn spacing_and_case_do_not_cost_an_operator_an_afternoon() {
        for value in [" review ", "REVIEW", "Review", "other, review"] {
            assert!(
                env_enables(value, Feature::Review),
                "{value:?} should have enabled review"
            );
        }
    }

    #[test]
    fn a_name_that_merely_contains_the_feature_does_not_enable_it() {
        // Substring matching would let `reviewer` or `no-review` switch this
        // on, which is the kind of gate that is worse than none.
        for value in ["reviewing", "no-review", "previewer"] {
            assert!(
                !env_enables(value, Feature::Review),
                "{value:?} should not have enabled review"
            );
        }
    }

    #[test]
    fn either_source_alone_is_enough_and_neither_vetoes_the_other() {
        // A gate whose two switches can disagree is a gate nobody can reason
        // about, so the rule is plain: on wins.
        assert!(enabled(ON, Some("nothing"), Feature::Review));
        assert!(enabled(OFF, Some("review"), Feature::Review));
        assert!(enabled(ON, None, Feature::Review));
    }

    #[test]
    fn the_refusal_names_both_ways_to_enable_it() {
        // The right one depends on whether this is a pipeline or a laptop,
        // and the binary does not know which.
        let text = refusal(Feature::Review);
        assert!(text.contains(ENV_VAR), "{text}");
        assert!(text.contains("garrison.toml"), "{text}");
        assert!(text.contains("review"), "{text}");
    }

    #[test]
    fn the_refusal_says_what_the_instability_actually_is() {
        // "Experimental" alone tells a reader nothing actionable. Naming the
        // exit codes tells a pipeline author exactly what may break.
        let text = refusal(Feature::Review);
        assert!(text.contains("exit codes"), "{text}");
    }

    #[test]
    fn the_notice_is_one_line_because_it_prints_every_run() {
        let text = notice(Feature::Review);
        assert!(!text.contains('\n'), "{text}");
        assert!(text.contains("experimental"), "{text}");
    }

    #[test]
    fn the_config_section_round_trips_through_toml() {
        let parsed: ExperimentalConfig = toml::from_str("review = true").expect("parses");
        assert!(parsed.review);
        let empty: ExperimentalConfig = toml::from_str("").expect("an empty section parses");
        assert!(!empty.review, "an absent key is off, not on");
    }
}
