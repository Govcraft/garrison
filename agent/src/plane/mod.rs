//! The daemon's one authenticated way to reach the control plane.
//!
//! # The invariant
//!
//! Nothing outside this module builds a `ServiceClient` with a bearer. Every
//! subsystem that needs the plane — the policy pull, the seat check, the
//! audit shipper, the health probe — asks [`session::PlaneSession`] for an
//! [`Authenticate`](session::Authenticate) and receives an [`api::Api`] that
//! is already authenticated, already scoped to this install's organization,
//! and already about to expire. That is worth stating as a rule rather than a
//! convention, because the alternative is four subsystems each holding a
//! bearer, each renewing it on its own schedule, and each with its own
//! opinion about what a 401 means.
//!
//! # How the bearer is obtained
//!
//! The daemon has a private key and nothing else. It signs a 120-second
//! assertion ([`assertion`]), posts it to `garrison-hooks`, and gets back a
//! 15-minute bearer for the plane's REST API. The wire form of that exchange
//! is [`garrison_wire`], shared with the service that verifies it, so neither
//! end can drift.
//!
//! # What a failure means
//!
//! [`api::PlaneError`] separates "the plane could not be reached" from "the
//! plane answered and said no", because the two lead to opposite behaviour.
//! An unreachable plane is a condition to ride out under whatever grace the
//! organization allows; a rejection is a decision somebody made, and retrying
//! it is how a quarantined machine turns into a denial of service against its
//! own control plane.

pub mod api;
pub mod assertion;
pub mod session;

pub use api::{Api, PlaneError};
pub use assertion::{new_assertion, sign_request};
pub use session::{Authenticate, PlaneSession, RevokeBearer, Session};
