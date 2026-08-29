//! The directory the organization's operators are read from.
//!
//! Entra ID is the authority on who is an operator. This module is the
//! boundary between that authority and the reconciler: one trait, one row
//! shape, one error type. Two implementations sit behind it. `graph` speaks
//! Microsoft Graph over HTTPS and is the production path; `file` reads a JSON
//! snapshot in exactly the shape `graph` produces and is what every plane-side
//! test drives, because no tenant is available to a test and a fake that
//! produces the same `Vec<DirectoryUser>` exercises every line after this
//! boundary byte for byte.
//!
//! What the boundary refuses to express is as important as what it does. A
//! listing is `Ok(Vec)` or `Err`; there is no "empty because unreachable".
//! The reconciler treats an empty `Ok` as a failure too (rule R5), but the
//! implementations are held to producing an `Err` for anything that is not a
//! successful read, so the two guards never rely on each other.

pub mod config;
pub mod file;
pub mod graph;

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

/// One directory member, in the attributes the reconciler owns.
///
/// `object_id` is Entra's stable objectId and the only join key. `upn`,
/// `display_name`, and `mail` are directory-owned attributes that the sync
/// overwrites on every reconciliation. `enabled` is `accountEnabled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryUser {
    pub object_id: String,
    pub upn: String,
    pub display_name: String,
    #[serde(default)]
    pub mail: Option<String>,
    pub enabled: bool,
}

/// Which slice of which directory to list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryQuery {
    /// The Entra tenant (directory) id.
    pub tenant_id: String,
    /// The group whose members are the operators. `None` lists every user in
    /// the tenant, which is only right for a tenant that is nothing but the
    /// organization.
    pub group_id: Option<String>,
}

/// Everything that can go wrong between here and the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    /// The directory refused our credentials.
    Auth(String),
    /// The directory could not be reached, or answered with a status that
    /// says "not now" (throttling, server error).
    Transport(String),
    /// The directory answered with a shape this client does not understand.
    Malformed(String),
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(what) => write!(f, "directory refused the credential: {what}"),
            Self::Transport(what) => write!(f, "directory unreachable: {what}"),
            Self::Malformed(what) => write!(f, "directory response not understood: {what}"),
        }
    }
}

impl std::error::Error for DirectoryError {}

/// The future a listing returns. Boxed so the trait stays object-safe.
pub type MembersFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<DirectoryUser>, DirectoryError>> + Send + Sync + 'a>>;

/// A source of directory members.
pub trait Directory: Send + Sync {
    /// List every member the query names.
    ///
    /// An implementation must return `Err` for anything that is not a
    /// complete, successful read. An empty `Ok` means the directory really
    /// answered "nobody", and the reconciler refuses to act on it anyway.
    fn members<'a>(&'a self, query: &'a DirectoryQuery) -> MembersFuture<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_round_trips_through_json_with_mail_optional() {
        let text = r#"{"object_id":"a1","upn":"a@x.gov","display_name":"A","enabled":true}"#;
        let user: DirectoryUser = serde_json::from_str(text).expect("parses");
        assert_eq!(user.mail, None);
        assert!(user.enabled);
        let back = serde_json::to_string(&user).expect("serializes");
        let again: DirectoryUser = serde_json::from_str(&back).expect("parses again");
        assert_eq!(again, user);
    }

    #[test]
    fn each_error_names_its_kind() {
        assert!(DirectoryError::Auth("x".into())
            .to_string()
            .contains("credential"));
        assert!(DirectoryError::Transport("x".into())
            .to_string()
            .contains("unreachable"));
        assert!(DirectoryError::Malformed("x".into())
            .to_string()
            .contains("not understood"));
    }
}
