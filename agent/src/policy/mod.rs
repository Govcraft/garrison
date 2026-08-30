//! Policy that is managed centrally and enforced locally.
//!
//! # The claim this module has to survive
//!
//! "Our agent policy is managed centrally" is a sentence an auditor will ask
//! to see. What they are entitled to see is: a policy authored in one place,
//! distributed to every install, verifiable as the same policy on both ends,
//! and enforced on the machine whether or not the person at the keyboard
//! wants it enforced. A configuration file copied around by hand is none of
//! those things.
//!
//! So the bundle is authored in the control plane, checksummed by the hook
//! that publishes it, pulled by this daemon, re-verified against that
//! checksum from the rows actually received, and put in force before any turn
//! runs. The install writes back the checksum it is running, which is what
//! turns "we published a policy" into "these machines are running it".
//!
//! # Where the parts live
//!
//! - [`cache`] — the last verified bundle on disk, and the freshness rule.
//! - [`pull`] — the walk from this install to its bundle, and the two kinds
//!   of failure that walk can have.
//! - [`agent`] — the actor: the three states, the gate, the tool decision,
//!   and the status.
//!
//! Adjudication itself is not here. It is `garrison-policy`, a crate with no
//! IO that both this daemon and the hook service compile, which is what makes
//! the checksum the two ends compare the same number.

pub mod agent;
pub mod cache;
pub mod pull;

pub use agent::{PolicyAgent, PolicyState, Settings, Source};
pub use pull::PullFailure;
