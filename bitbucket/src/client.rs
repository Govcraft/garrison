//! The three calls, and nothing else.
//!
//! This module is deliberately thin. It builds a URL, attaches a credential,
//! sends, and hands the body to a parser in [`crate::diff`] or
//! [`crate::error`]. Every decision worth testing lives in those parsers, so
//! that a test can exercise the decision without standing up a server.

use crate::{
    parse_diff, parse_error, Anchor, BitbucketError, BuildStatus, ChangedFile, Comment,
    PullRequest, Severity,
};
use serde_json::json;

/// How the daemon proves who it is to Bitbucket.
///
/// Both variants end up as an `Authorization` header, so this is not an
/// abstraction over auth so much as a refusal to let a caller assemble that
/// header by hand and get the encoding wrong.
#[derive(Clone)]
pub enum Credentials {
    /// A Bitbucket HTTP access token, personal or repository-scoped.
    ///
    /// The one to prefer: DC lets an admin scope it to a single repository
    /// and to `REPO_WRITE` rather than admin, which is the narrowest thing
    /// that can still post a comment.
    Bearer(String),

    /// A username and password or app password, sent as HTTP Basic.
    ///
    /// Present because plenty of DC instances predate access tokens, not
    /// because it is a good idea. A password here is a whole user account,
    /// not a scoped grant.
    Basic {
        /// The Bitbucket username.
        username: String,
        /// The password or app password.
        password: String,
    },
}

impl Credentials {
    /// The `Authorization` header value this credential produces.
    fn header(&self) -> String {
        match self {
            Self::Bearer(token) => format!("Bearer {token}"),
            Self::Basic { username, password } => {
                use base64::Engine as _;
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                format!("Basic {encoded}")
            }
        }
    }
}

// A credential that renders itself into a log is a credential that leaks, so
// the debug output names the kind and nothing else.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer(_) => f.write_str("Credentials::Bearer(<redacted>)"),
            Self::Basic { username, .. } => {
                write!(f, "Credentials::Basic {{ username: {username:?}, .. }}")
            }
        }
    }
}

/// A handle on one Bitbucket Data Center instance.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    /// The REST root, always ending in a slash so joining a path is total.
    root: String,
    credentials: Credentials,
}

impl Client {
    /// Points a client at `base_url`, e.g. `https://bitbucket.agency.gov`.
    ///
    /// A trailing slash on `base_url` is tolerated rather than required: the
    /// difference between a URL that has one and one that does not is not a
    /// thing an operator should have to get right in a config file, and
    /// getting it wrong would produce a 404 that names a doubled slash.
    ///
    /// # Errors
    ///
    /// [`BitbucketError::Transport`] if a TLS-capable HTTP client cannot be
    /// built, which in practice means the platform has no usable root store.
    pub fn new(base_url: &str, credentials: Credentials) -> Result<Self, BitbucketError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("garrison/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| BitbucketError::Transport(error.to_string()))?;

        Ok(Self {
            http,
            root: format!("{}/rest/api/1.0/", base_url.trim_end_matches('/')),
            credentials,
        })
    }

    /// Sends one request and reads the body, turning a failing status into the
    /// error it means.
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<String, BitbucketError> {
        let response = request
            .header(reqwest::header::AUTHORIZATION, self.credentials.header())
            .send()
            .await
            .map_err(|error| BitbucketError::Transport(error.to_string()))?;

        let status = response.status().as_u16();
        // The body is read either way: on failure it carries the message, and
        // discarding it would leave an operator with a bare status code.
        let body = response
            .text()
            .await
            .map_err(|error| BitbucketError::Transport(error.to_string()))?;

        if (200..300).contains(&status) {
            Ok(body)
        } else {
            Err(parse_error(status, &body))
        }
    }

    /// The files a pull request changes, with the hunks needed to anchor a
    /// comment on any line of them.
    ///
    /// `context` is how many unchanged lines Bitbucket includes either side of
    /// each change. It is not cosmetic: a reviewer given only the added lines
    /// is reviewing them without the code they sit in, which is how a model
    /// ends up flagging a null check that is three lines above the window.
    ///
    /// # Errors
    ///
    /// [`BitbucketError`] if the request fails or the diff does not parse.
    pub async fn pull_request_diff(
        &self,
        pull_request: &PullRequest,
        context: u32,
    ) -> Result<Vec<ChangedFile>, BitbucketError> {
        let url = format!("{}{}/diff", self.root, pull_request.path());
        let body = self
            .send(
                self.http
                    .get(&url)
                    .query(&[("contextLines", context.to_string())]),
            )
            .await?;
        parse_diff(&body)
    }

    /// Posts one comment, inline if it carries an anchor.
    ///
    /// # Errors
    ///
    /// [`BitbucketError`] if the request fails. A [`Rejected`] error here is
    /// the expected outcome for an anchor Bitbucket will not accept, and a
    /// caller should drop that one comment rather than end the review.
    ///
    /// [`Rejected`]: BitbucketError::Rejected
    pub async fn post_comment(
        &self,
        pull_request: &PullRequest,
        comment: &Comment,
    ) -> Result<(), BitbucketError> {
        let url = format!("{}{}/comments", self.root, pull_request.path());

        let mut payload = json!({
            "text": comment.text,
            "severity": comment.severity,
        });

        // Bitbucket rejects a BLOCKER comment that does not also declare a
        // state, and the pairing is not obvious from the field names: a
        // blocker is modelled as an open task, so it must say it is OPEN.
        if comment.severity == Severity::Blocker {
            payload["state"] = json!("OPEN");
        }

        if let Some(anchor) = &comment.anchor {
            payload["anchor"] = anchor_payload(anchor);
        }

        self.send(self.http.post(&url).json(&payload)).await?;
        Ok(())
    }

    /// Records the run's outcome against a commit.
    ///
    /// Note the path: build status lives under `/rest/build-status/1.0`, not
    /// under the core API, and it is keyed by commit rather than by pull
    /// request. That is why this takes a `commit` and the other two calls
    /// take a [`PullRequest`].
    ///
    /// # Errors
    ///
    /// [`BitbucketError`] if the request fails.
    pub async fn set_build_status(
        &self,
        commit: &str,
        status: &BuildStatus,
    ) -> Result<(), BitbucketError> {
        let url = format!(
            "{}build-status/1.0/commits/{commit}",
            self.root.trim_end_matches("api/1.0/")
        );
        self.send(self.http.post(&url).json(status)).await?;
        Ok(())
    }
}

/// The anchor object Bitbucket wants alongside an inline comment.
///
/// Split out as a pure function so the field names, which are the part that
/// silently misplaces a comment when wrong, are testable without a server.
fn anchor_payload(anchor: &Anchor) -> serde_json::Value {
    json!({
        "line": anchor.line,
        "lineType": if anchor.file_type == "FROM" { "REMOVED" } else { "ADDED" },
        "fileType": anchor.file_type,
        "path": anchor.path,
        "diffType": anchor.diff_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_base_url_with_a_trailing_slash_does_not_double_it() {
        let client = Client::new("https://bb.gov/", Credentials::Bearer("t".into())).unwrap();
        assert_eq!(client.root, "https://bb.gov/rest/api/1.0/");
    }

    #[test]
    fn a_base_url_without_one_gets_the_same_root() {
        let client = Client::new("https://bb.gov", Credentials::Bearer("t".into())).unwrap();
        assert_eq!(client.root, "https://bb.gov/rest/api/1.0/");
    }

    #[test]
    fn a_bearer_credential_becomes_the_header_bitbucket_expects() {
        assert_eq!(
            Credentials::Bearer("abc123".into()).header(),
            "Bearer abc123"
        );
    }

    #[test]
    fn a_basic_credential_is_encoded_rather_than_concatenated() {
        // "alice:hunter2" base64-encoded. Hand-assembling this header is the
        // mistake the enum exists to prevent.
        assert_eq!(
            Credentials::Basic {
                username: "alice".into(),
                password: "hunter2".into(),
            }
            .header(),
            "Basic YWxpY2U6aHVudGVyMg=="
        );
    }

    #[test]
    fn a_credential_does_not_print_itself_into_a_log() {
        let rendered = format!("{:?}", Credentials::Bearer("secret-token".into()));
        assert!(!rendered.contains("secret-token"), "{rendered}");

        let basic = format!(
            "{:?}",
            Credentials::Basic {
                username: "alice".into(),
                password: "hunter2".into(),
            }
        );
        assert!(!basic.contains("hunter2"), "{basic}");
        // The username is not a secret, and knowing which account failed is
        // most of what an operator needs from the log.
        assert!(basic.contains("alice"), "{basic}");
    }

    #[test]
    fn an_added_line_anchors_as_added_on_the_destination_side() {
        let payload = anchor_payload(&Anchor {
            path: "src/lib.rs".into(),
            line: 11,
            file_type: "TO",
            diff_type: "COMMIT",
        });
        assert_eq!(payload["lineType"], "ADDED");
        assert_eq!(payload["fileType"], "TO");
        assert_eq!(payload["line"], 11);
        assert_eq!(payload["path"], "src/lib.rs");
    }

    #[test]
    fn a_removed_line_anchors_as_removed_on_the_source_side() {
        // The pairing matters: FROM with lineType ADDED is accepted by
        // Bitbucket and lands the comment on the wrong line.
        let payload = anchor_payload(&Anchor {
            path: "src/lib.rs".into(),
            line: 10,
            file_type: "FROM",
            diff_type: "COMMIT",
        });
        assert_eq!(payload["lineType"], "REMOVED");
        assert_eq!(payload["fileType"], "FROM");
    }

    #[test]
    fn the_build_status_path_leaves_the_core_api_behind() {
        let client = Client::new("https://bb.gov", Credentials::Bearer("t".into())).unwrap();
        let url = format!(
            "{}build-status/1.0/commits/{}",
            client.root.trim_end_matches("api/1.0/"),
            "deadbeef"
        );
        assert_eq!(url, "https://bb.gov/rest/build-status/1.0/commits/deadbeef");
    }
}
