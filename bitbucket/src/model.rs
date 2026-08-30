//! The values the three calls exchange.

use serde::{Deserialize, Serialize};

/// Which pull request, on which repository.
///
/// Bitbucket DC addresses everything as `projects/{key}/repos/{slug}`, and the
/// project key is uppercase by convention but not by rule, so it is carried
/// verbatim rather than normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequest {
    /// The project key, e.g. `AGENCY`.
    pub project: String,
    /// The repository slug, e.g. `benefits-portal`.
    pub repository: String,
    /// The pull request's number within that repository.
    pub id: u64,
}

impl PullRequest {
    /// The REST path prefix every call on this pull request shares.
    #[must_use]
    pub fn path(&self) -> String {
        format!(
            "projects/{}/repos/{}/pull-requests/{}",
            self.project, self.repository, self.id
        )
    }
}

/// How seriously a reviewer means a finding.
///
/// Bitbucket has exactly two comment severities and no more, so this maps
/// one-to-one rather than inventing a scale the API cannot carry. A reviewer
/// with five levels of concern has to decide which of them are blockers, and
/// making that decision here rather than in the API is the honest place for
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// An observation. Does not block the merge check.
    Normal,
    /// A blocker. Bitbucket surfaces it as an unresolved task.
    Blocker,
}

/// One finding, ready to post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    /// The comment body, as Bitbucket-flavoured markdown.
    pub text: String,
    /// Where to attach it, or `None` for a comment on the pull request itself.
    pub anchor: Option<crate::Anchor>,
    /// Whether this blocks.
    pub severity: Severity,
}

/// What a build status says happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BuildState {
    /// The review ran and found nothing that blocks.
    Successful,
    /// The review ran and found something that blocks.
    Failed,
    /// The review is running.
    InProgress,
}

/// The status posted against the commit under review.
///
/// `key` is the identity Bitbucket dedupes on: posting twice with the same key
/// replaces rather than appends, which is what makes a re-run of a pipeline
/// leave one status rather than a pile of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildStatus {
    /// The dedupe identity, e.g. `garrison-review`.
    pub key: String,
    /// What happened.
    pub state: BuildState,
    /// Where a human goes to read the run.
    pub url: String,
    /// A short human-facing name.
    pub name: String,
    /// One line of detail, shown under the name.
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pull_request_addresses_itself_the_way_data_center_does() {
        let pr = PullRequest {
            project: "AGENCY".into(),
            repository: "benefits-portal".into(),
            id: 42,
        };
        assert_eq!(
            pr.path(),
            "projects/AGENCY/repos/benefits-portal/pull-requests/42"
        );
    }

    #[test]
    fn a_lowercase_project_key_is_carried_verbatim() {
        // Uppercase is a convention, not a rule, and normalizing here would
        // produce a 404 that names a project the caller never typed.
        let pr = PullRequest {
            project: "agency".into(),
            repository: "r".into(),
            id: 1,
        };
        assert!(pr.path().starts_with("projects/agency/"));
    }

    #[test]
    fn severities_serialize_as_the_two_names_bitbucket_knows() {
        assert_eq!(
            serde_json::to_string(&Severity::Blocker).unwrap(),
            "\"BLOCKER\""
        );
        assert_eq!(
            serde_json::to_string(&Severity::Normal).unwrap(),
            "\"NORMAL\""
        );
    }

    #[test]
    fn build_states_serialize_as_the_names_the_rest_api_expects() {
        assert_eq!(
            serde_json::to_string(&BuildState::Successful).unwrap(),
            "\"SUCCESSFUL\""
        );
        assert_eq!(
            serde_json::to_string(&BuildState::InProgress).unwrap(),
            "\"INPROGRESS\""
        );
    }
}
