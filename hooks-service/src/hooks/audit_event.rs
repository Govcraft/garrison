//! `AuditEvent.before_validate` — the verifying ingest, not yet verifying.
//!
//! The real hook re-links a shipped entry against its trail's `AuditChain`,
//! refuses forks and edits, and records gaps. Until that lands, this stub
//! refuses every write. A stub that accepted would persist entries nobody
//! verified while the plane's `required = true` binding reported success, and
//! the daemon would take the 201 as an acknowledgement and drop the entry from
//! its backlog. Aborting is a 422 the daemon treats as a halt, which is the
//! honest state of an ingest that does not exist yet.

use tonic::{Request, Response, Status};

use crate::pb::audit_event::audit_event_hooks_server::AuditEventHooks;
use crate::pb::audit_event::*;

/// The reason every write is refused until the verifying ingest exists.
pub const NOT_IMPLEMENTED: &str = "audit ingest is not implemented on this hook service";

/// The verifying ingest. Stateless until it verifies.
pub struct Service;

#[tonic::async_trait]
impl AuditEventHooks for Service {
    /// Verify the shipped entry against the trail's chain state; refuse forks
    /// and edits, record gaps.
    async fn before_validate(
        &self,
        request: Request<AuditEventBeforeValidateRequest>,
    ) -> Result<Response<AuditEventBeforeValidateResponse>, Status> {
        let req = request.into_inner();
        Ok(Response::new(refuse(&req.operation)))
    }
}

/// The response for any operation while the ingest is unimplemented.
fn refuse(operation: &str) -> AuditEventBeforeValidateResponse {
    AuditEventBeforeValidateResponse {
        abort_reason: Some(format!("{NOT_IMPLEMENTED} (operation: {operation})")),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_is_refused_with_the_reason() {
        for operation in ["create", "update"] {
            let response = refuse(operation);
            let reason = response.abort_reason.expect("an abort reason");
            assert!(reason.starts_with(NOT_IMPLEMENTED));
            assert!(reason.contains(operation));
        }
    }

    #[test]
    fn a_refusal_sets_no_fields() {
        let response = refuse("create");
        assert!(response.entry.is_none());
        assert!(response.entry_hash.is_none());
        assert!(response.operator.is_none());
    }
}
