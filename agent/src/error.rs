//! Garrison's error type.
//!
//! Mirrors acton-ai's convention exactly, and for the same reasons: one outer
//! struct carrying a `#[non_exhaustive]` kind enum, named struct variants
//! only, one constructor per variant, a hand-written `Display`, and no
//! dependency on `anyhow`, `thiserror`, or `eyre`. Foreign errors are
//! flattened to strings at the boundary rather than chained, so that an error
//! crossing the protocol never carries a type the client cannot name.

use std::fmt;

/// An error raised by garrison-agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarrisonError {
    /// What went wrong.
    pub kind: GarrisonErrorKind,
}

/// The specific failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GarrisonErrorKind {
    /// A configuration value was missing or unusable.
    Configuration {
        /// The setting at fault.
        field: String,
        /// Why it could not be used.
        reason: String,
    },
    /// The protocol socket could not be bound, or could not be served.
    Transport {
        /// The endpoint being served, rendered for a human.
        endpoint: String,
        /// Why it failed.
        reason: String,
    },
    /// The embedded acton-ai runtime failed.
    Runtime {
        /// Why it failed.
        reason: String,
    },
    /// A thread was named that this client cannot address.
    UnknownThread {
        /// The identifier the client sent.
        thread_id: String,
    },
    /// This install could not join, or could not confirm it had joined, the
    /// control plane it is configured to answer to.
    Enrollment {
        /// What the plane said, or what stopped it being asked.
        reason: String,
    },
    /// The session store could not answer.
    ///
    /// Its own kind because a store that cannot be reached is not a
    /// configuration mistake and not a failed turn: it is the persistence a
    /// session's survival depends on being unavailable right now, and every
    /// caller of it has to fail closed rather than carry on unrecorded.
    Store {
        /// What was being attempted, e.g. `resolve` or `append`.
        operation: String,
        /// Why it could not be done.
        reason: String,
    },
    /// A turn could not be run to completion.
    TurnFailed {
        /// Why it failed.
        reason: String,
    },
    /// A patch could not be parsed.
    PatchParse {
        /// One-based line number within the patch text.
        line: usize,
        /// What was wrong with it.
        reason: String,
    },
    /// A patch parsed but could not be applied to the tree.
    PatchApply {
        /// Zero-based index of the hunk that failed.
        hunk: usize,
        /// The file the hunk addressed.
        path: String,
        /// What went wrong, including any near-miss diagnostics.
        reason: String,
    },
    /// A write was refused before any bytes moved.
    PatchRejected {
        /// Why the safety assessment refused it.
        reason: String,
    },
    /// An audit trail did not verify as a hash chain.
    AuditChainBroken {
        /// Where the walk stopped, and why.
        reason: String,
    },
    /// An audit trail verifies but no longer ends where its anchor says it
    /// ended: history was removed or rewritten.
    ///
    /// Its own kind, and its own exit code, because it is the one finding a
    /// chain cannot make about itself — a prefix of a valid chain is a valid
    /// chain — and a caller scripting `audit verify` needs to tell it apart
    /// from a chain that simply does not hang together.
    AuditAnchorMismatch {
        /// What the comparison found.
        reason: String,
    },
    /// A review ran, found something blocking, and was enforcing.
    ///
    /// A rejection rather than a malfunction: the reviewer worked exactly as
    /// configured. A pipeline must be able to tell this from a crash, because
    /// one means "fix the code" and the other means "fix the reviewer".
    ReviewBlocked {
        /// What it found.
        reason: String,
    },
}

impl GarrisonError {
    /// Wraps a kind.
    #[must_use]
    pub const fn new(kind: GarrisonErrorKind) -> Self {
        Self { kind }
    }

    /// The kind of failure.
    #[must_use]
    pub const fn kind(&self) -> &GarrisonErrorKind {
        &self.kind
    }

    /// A configuration value was missing or unusable.
    #[must_use]
    pub fn configuration(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::Configuration {
            field: field.into(),
            reason: reason.into(),
        })
    }

    /// The protocol socket could not be bound or served.
    #[must_use]
    pub fn transport(endpoint: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::Transport {
            endpoint: endpoint.into(),
            reason: reason.into(),
        })
    }

    /// The embedded runtime failed.
    #[must_use]
    pub fn runtime(reason: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::Runtime {
            reason: reason.into(),
        })
    }

    /// A thread was named that this client cannot address.
    #[must_use]
    pub fn unknown_thread(thread_id: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::UnknownThread {
            thread_id: thread_id.into(),
        })
    }

    /// This install could not join the control plane.
    #[must_use]
    pub fn enrollment(reason: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::Enrollment {
            reason: reason.into(),
        })
    }

    /// The session store could not answer.
    #[must_use]
    pub fn store(operation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::Store {
            operation: operation.into(),
            reason: reason.into(),
        })
    }

    /// A turn could not be run to completion.
    #[must_use]
    pub fn turn_failed(reason: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::TurnFailed {
            reason: reason.into(),
        })
    }

    /// A patch could not be parsed.
    #[must_use]
    pub fn patch_parse(line: usize, reason: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::PatchParse {
            line,
            reason: reason.into(),
        })
    }

    /// A patch parsed but would not apply.
    #[must_use]
    pub fn patch_apply(hunk: usize, path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::PatchApply {
            hunk,
            path: path.into(),
            reason: reason.into(),
        })
    }

    /// A write was refused before any bytes moved.
    #[must_use]
    pub fn patch_rejected(reason: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::PatchRejected {
            reason: reason.into(),
        })
    }

    /// A review found something blocking while enforcing.
    #[must_use]
    pub fn review_blocked(reason: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::ReviewBlocked {
            reason: reason.into(),
        })
    }

    /// An audit trail did not verify as a hash chain.
    #[must_use]
    pub fn audit_chain_broken(reason: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::AuditChainBroken {
            reason: reason.into(),
        })
    }

    /// An audit trail no longer ends where its anchor says it ended.
    #[must_use]
    pub fn audit_anchor_mismatch(reason: impl Into<String>) -> Self {
        Self::new(GarrisonErrorKind::AuditAnchorMismatch {
            reason: reason.into(),
        })
    }

    /// Whether this is a configuration failure.
    #[must_use]
    pub const fn is_configuration(&self) -> bool {
        matches!(self.kind, GarrisonErrorKind::Configuration { .. })
    }

    /// Whether a trail disagrees with the anchor that vouched for it.
    #[must_use]
    pub const fn is_audit_anchor_mismatch(&self) -> bool {
        matches!(self.kind, GarrisonErrorKind::AuditAnchorMismatch { .. })
    }

    /// Whether this is an enrollment failure.
    #[must_use]
    pub const fn is_enrollment(&self) -> bool {
        matches!(self.kind, GarrisonErrorKind::Enrollment { .. })
    }

    /// Whether the daemon refused to start, as opposed to failing while it ran.
    ///
    /// A configuration the daemon will not accept, or a control plane that
    /// turned the install away, are decisions and not malfunctions: nothing
    /// about restarting the process changes the answer. A supervisor that
    /// sees this must stop and let an operator look, which is why `serve`
    /// maps it to its own exit code and the systemd unit refuses to retry it.
    #[must_use]
    pub const fn is_refusal_to_start(&self) -> bool {
        self.is_configuration() || self.is_enrollment()
    }

    /// Whether this is a refusal rather than a malfunction.
    ///
    /// A rejected patch and a trail that does not verify are both decisions
    /// the system made on purpose. Callers that report failures to an
    /// operator should say so differently from the ones that mean something
    /// broke.
    #[must_use]
    pub const fn is_rejection(&self) -> bool {
        matches!(
            self.kind,
            GarrisonErrorKind::PatchRejected { .. }
                | GarrisonErrorKind::AuditChainBroken { .. }
                | GarrisonErrorKind::ReviewBlocked { .. }
        )
    }
}

impl fmt::Display for GarrisonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            GarrisonErrorKind::Configuration { field, reason } => {
                write!(f, "configuration error in '{field}': {reason}")
            }
            GarrisonErrorKind::Transport { endpoint, reason } => {
                write!(f, "transport error on {endpoint}: {reason}")
            }
            GarrisonErrorKind::Runtime { reason } => write!(f, "runtime error: {reason}"),
            GarrisonErrorKind::Enrollment { reason } => {
                write!(f, "enrollment error: {reason}")
            }
            GarrisonErrorKind::UnknownThread { thread_id } => {
                write!(f, "no such thread: {thread_id}")
            }
            GarrisonErrorKind::Store { operation, reason } => {
                write!(f, "the session store could not {operation}: {reason}")
            }
            GarrisonErrorKind::TurnFailed { reason } => write!(f, "turn failed: {reason}"),
            GarrisonErrorKind::PatchParse { line, reason } => {
                write!(f, "invalid patch at line {line}: {reason}")
            }
            GarrisonErrorKind::PatchApply { hunk, path, reason } => {
                write!(f, "hunk {hunk} does not apply to {path}: {reason}")
            }
            GarrisonErrorKind::PatchRejected { reason } => {
                write!(f, "patch rejected: {reason}")
            }
            GarrisonErrorKind::AuditChainBroken { reason } => {
                write!(f, "the audit trail does not verify: {reason}")
            }
            GarrisonErrorKind::AuditAnchorMismatch { reason } => {
                write!(f, "the audit trail disagrees with its anchor: {reason}")
            }
            GarrisonErrorKind::ReviewBlocked { reason } => {
                write!(f, "the review blocked this change: {reason}")
            }
        }
    }
}

impl std::error::Error for GarrisonError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rejection_reads_differently_from_a_malfunction() {
        // An operator triaging a failure needs to know instantly whether the
        // system broke or whether it refused on purpose.
        assert!(GarrisonError::patch_rejected("outside the project root").is_rejection());
        assert!(!GarrisonError::runtime("provider unreachable").is_rejection());
    }

    #[test]
    fn a_refusal_to_start_is_a_decision_not_a_crash() {
        // Restarting cannot fix either of these; a supervisor must not try.
        assert!(GarrisonError::configuration("audit.path", "locked").is_refusal_to_start());
        assert!(GarrisonError::enrollment("token already spent").is_refusal_to_start());
        assert!(GarrisonError::enrollment("token already spent").is_enrollment());
        assert!(!GarrisonError::transport("/run/x.sock", "refused").is_refusal_to_start());
        assert!(!GarrisonError::runtime("provider unreachable").is_refusal_to_start());
    }

    #[test]
    fn a_failing_hunk_names_itself_and_its_file() {
        let error = GarrisonError::patch_apply(2, "src/lib.rs", "no match found");
        assert_eq!(
            error.to_string(),
            "hunk 2 does not apply to src/lib.rs: no match found"
        );
    }

    #[test]
    fn a_parse_failure_carries_the_line_the_model_got_wrong() {
        let error = GarrisonError::patch_parse(7, "expected a hunk header");
        assert_eq!(
            error.to_string(),
            "invalid patch at line 7: expected a hunk header"
        );
    }
}
