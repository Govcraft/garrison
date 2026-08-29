//! `PolicyBundle.before_validate` — the publish gate, not yet stamping.
//!
//! The real hook assembles the bundle's rules and endpoints, runs every
//! rule's own match examples, and stamps the BLAKE3 checksum when the bundle
//! moves to `published`. Until that lands, a publish is refused: a bundle
//! that reached `published` with an empty checksum would fail its own
//! `@require`, and one that somehow carried a checksum nobody computed would
//! be worse. Drafting and retiring are untouched, so the console keeps
//! working on bundles that are not yet in force.

use tonic::{Request, Response, Status};

use crate::pb::policy_bundle::policy_bundle_hooks_server::PolicyBundleHooks;
use crate::pb::policy_bundle::*;

/// The reason a publish is refused until the gate exists.
pub const NOT_IMPLEMENTED: &str =
    "policy bundle publishing is not implemented on this hook service";

/// The publish gate. Stateless until it stamps.
pub struct Service;

#[tonic::async_trait]
impl PolicyBundleHooks for Service {
    /// Stamp the checksum and self-test the rules when a bundle is published.
    async fn before_validate(
        &self,
        request: Request<PolicyBundleBeforeValidateRequest>,
    ) -> Result<Response<PolicyBundleBeforeValidateResponse>, Status> {
        let req = request.into_inner();
        Ok(Response::new(decide(req.status.as_deref())))
    }
}

/// Refuse a publish, pass everything else through unchanged.
fn decide(status: Option<&str>) -> PolicyBundleBeforeValidateResponse {
    let abort_reason = is_publish(status).then(|| NOT_IMPLEMENTED.to_string());
    PolicyBundleBeforeValidateResponse {
        abort_reason,
        ..Default::default()
    }
}

/// Whether the incoming row is trying to be `published`.
fn is_publish(status: Option<&str>) -> bool {
    status == Some("published")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_publish_is_refused() {
        let response = decide(Some("published"));
        assert_eq!(response.abort_reason.as_deref(), Some(NOT_IMPLEMENTED));
    }

    #[test]
    fn drafting_and_retiring_pass_through() {
        for status in [Some("draft"), Some("retired"), None] {
            let response = decide(status);
            assert!(response.abort_reason.is_none(), "{status:?} was refused");
            assert!(response.checksum.is_none());
        }
    }
}
