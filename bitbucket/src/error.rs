//! What went wrong, in terms a review run can act on.
//!
//! Bitbucket returns errors as a JSON envelope: `{"errors": [{"message":
//! ..., "exceptionName": ...}]}`, and it uses that same envelope for a bad
//! credential, a missing pull request, and a comment anchored to a line the
//! diff does not contain. The status code is what separates them, so
//! [`parse_error`] pairs the status with the envelope's message rather than
//! surfacing either alone.
//!
//! The distinction earns its keep in one specific place: a run that cannot
//! authenticate must stop, and a run whose comment would not anchor should
//! drop that comment and keep going. Collapsing both into "the request
//! failed" would either abandon a whole review over one bad line number, or
//! post forty comments into the void with an expired token.

use std::fmt;

/// A failure from Bitbucket, or from getting to it.
#[derive(Debug)]
pub enum BitbucketError {
    /// The credential was rejected, or carries no rights here.
    ///
    /// Fatal for a run: retrying will fail the same way, and every later
    /// call in the run uses the same credential.
    Unauthorized(String),

    /// The pull request, repository, or project does not exist.
    ///
    /// Also what Bitbucket returns when the credential cannot *see* the
    /// repository, which is deliberate on its part: a 404 does not disclose
    /// that a private repository exists. So this is not always the caller's
    /// typo.
    NotFound(String),

    /// Bitbucket refused the request on its merits.
    ///
    /// The common cause in a review run is an anchor Bitbucket does not
    /// accept for this diff. Survivable: drop the comment, keep the run.
    Rejected {
        /// The HTTP status Bitbucket answered with.
        status: u16,
        /// The first message from the error envelope.
        message: String,
    },

    /// Bitbucket failed, or is not answering yet.
    ///
    /// Worth a retry in a way the others are not: DC restarts, and a `503`
    /// during one is not a statement about the request.
    Unavailable {
        /// The HTTP status Bitbucket answered with.
        status: u16,
        /// The first message from the error envelope.
        message: String,
    },

    /// The request never reached Bitbucket.
    Transport(String),

    /// Bitbucket answered, but not in a shape this client understands.
    ///
    /// Distinct from [`Rejected`](Self::Rejected) on purpose: a rejection is
    /// Bitbucket working correctly and saying no, and this is the client's
    /// model of Bitbucket being wrong. The second is a bug here, and
    /// labelling it as the first would hide it.
    Malformed(String),
}

impl BitbucketError {
    /// Whether a run holding this error should stop rather than continue.
    ///
    /// Only the credential failing is fatal. Everything else is about one
    /// call, and one call failing should not cost a reviewer the other
    /// thirty-nine comments it had to make.
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        matches!(self, Self::Unauthorized(_))
    }

    /// Whether the same request is worth sending again.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable { .. } | Self::Transport(_))
    }
}

impl fmt::Display for BitbucketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized(message) => {
                write!(f, "bitbucket rejected the credential: {message}")
            }
            Self::NotFound(message) => write!(f, "bitbucket has no such thing: {message}"),
            Self::Rejected { status, message } => {
                write!(f, "bitbucket refused the request ({status}): {message}")
            }
            Self::Unavailable { status, message } => {
                write!(f, "bitbucket is not answering ({status}): {message}")
            }
            Self::Transport(message) => write!(f, "could not reach bitbucket: {message}"),
            Self::Malformed(message) => write!(
                f,
                "bitbucket answered in a shape this client does not know: {message}"
            ),
        }
    }
}

impl std::error::Error for BitbucketError {}

/// The error envelope Bitbucket wraps every failure in.
#[derive(serde::Deserialize)]
struct ErrorEnvelope {
    #[serde(default)]
    errors: Vec<ErrorDetail>,
}

#[derive(serde::Deserialize)]
struct ErrorDetail {
    #[serde(default)]
    message: String,
}

/// Reads a failed response into the error it means.
///
/// `body` may be anything: Bitbucket serves an HTML error page when a reverse
/// proxy answers instead of the application, and a run that reports a wall of
/// HTML as its failure reason has told the operator nothing. So a body that is
/// not the envelope yields a short stand-in naming the status, and the status
/// still selects the variant.
#[must_use]
pub fn parse_error(status: u16, body: &str) -> BitbucketError {
    let message = serde_json::from_str::<ErrorEnvelope>(body)
        .ok()
        .and_then(|envelope| envelope.errors.into_iter().next())
        .map(|detail| detail.message)
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| format!("no message; bitbucket answered {status}"));

    match status {
        401 | 403 => BitbucketError::Unauthorized(message),
        404 => BitbucketError::NotFound(message),
        // 5xx and 429 are the ones that mean "ask again later". A 429 is not
        // Bitbucket disagreeing with the request, it is Bitbucket asking for
        // less of it at once.
        429 | 500..=599 => BitbucketError::Unavailable { status, message },
        _ => BitbucketError::Rejected { status, message },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded verbatim from Bitbucket DC 10.4.2 at
    /// `GET /rest/api/1.0/projects` with no credential.
    const UNAUTHORIZED: &str = r#"{"errors":[{"context":null,"message":"You are not permitted to access this resource","exceptionName":"com.atlassian.plugins.rest.api.security.exception.AuthenticationRequiredException"}]}"#;

    #[test]
    fn a_401_is_a_credential_problem_and_is_fatal() {
        let error = parse_error(401, UNAUTHORIZED);
        assert!(matches!(error, BitbucketError::Unauthorized(_)));
        assert!(
            error.is_fatal(),
            "every later call uses the same credential, so the run cannot go on"
        );
        assert!(!error.is_retryable());
        assert!(error.to_string().contains("not permitted"), "{error}");
    }

    #[test]
    fn a_403_is_treated_as_a_credential_problem_too() {
        // Authenticated but unauthorized is still "this token cannot do the
        // job", and a review run has no second token to try.
        assert!(matches!(
            parse_error(403, r#"{"errors":[{"message":"no write access"}]}"#),
            BitbucketError::Unauthorized(_)
        ));
    }

    #[test]
    fn a_404_is_not_fatal_because_it_may_be_one_missing_pull_request() {
        let error = parse_error(404, r#"{"errors":[{"message":"PR 7 does not exist"}]}"#);
        assert!(matches!(error, BitbucketError::NotFound(_)));
        assert!(!error.is_fatal());
    }

    #[test]
    fn a_400_is_survivable_so_one_bad_anchor_does_not_end_a_review() {
        let error = parse_error(400, r#"{"errors":[{"message":"invalid anchor line"}]}"#);
        assert!(matches!(
            error,
            BitbucketError::Rejected { status: 400, .. }
        ));
        assert!(!error.is_fatal());
        assert!(!error.is_retryable());
    }

    #[test]
    fn a_503_is_retryable_because_data_center_restarts() {
        let error = parse_error(503, "");
        assert!(matches!(error, BitbucketError::Unavailable { .. }));
        assert!(error.is_retryable());
    }

    #[test]
    fn a_429_is_retryable_rather_than_a_disagreement() {
        assert!(parse_error(429, "").is_retryable());
    }

    #[test]
    fn an_html_error_page_still_names_the_status_rather_than_quoting_the_page() {
        // A proxy answering instead of Bitbucket is the realistic case, and
        // pasting its HTML into a log tells an operator nothing.
        let error = parse_error(
            502,
            "<html><head><title>502 Bad Gateway</title></head></html>",
        );
        let rendered = error.to_string();
        assert!(rendered.contains("502"), "{rendered}");
        assert!(!rendered.contains("<html>"), "{rendered}");
    }

    #[test]
    fn an_envelope_with_an_empty_message_falls_back_rather_than_saying_nothing() {
        let error = parse_error(400, r#"{"errors":[{"message":""}]}"#);
        assert!(error.to_string().contains("400"), "{error}");
    }

    #[test]
    fn a_malformed_answer_is_not_dressed_up_as_a_refusal() {
        // This variant exists so a bug in this client's model of Bitbucket
        // does not get logged as Bitbucket saying no.
        let error = BitbucketError::Malformed("diff response: expected value".into());
        assert!(!error.is_fatal());
        assert!(error.to_string().contains("does not know"), "{error}");
    }
}
