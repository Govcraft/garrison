//! A directory read from a JSON file.
//!
//! The file is a JSON array of `DirectoryUser`, the same shape the Graph
//! parser produces, so a test that edits this file exercises the reconciler,
//! the plane client, the enrollment hook, and every rule between them with
//! nothing faked past this line.
//!
//! It is read on every call rather than cached. The point of the file is to
//! be edited between ticks.

use tokio::fs;

use super::{Directory, DirectoryError, DirectoryQuery, DirectoryUser, MembersFuture};

/// A directory whose members are whatever the file says right now.
#[derive(Debug, Clone)]
pub struct FileDirectory {
    path: std::path::PathBuf,
}

impl FileDirectory {
    /// A directory backed by the JSON array at `path`.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

/// Parse a snapshot. Anything that is not a JSON array of members is an
/// error, never an empty list: a truncated file must not read as "everyone
/// left".
pub fn parse_snapshot(text: &str) -> Result<Vec<DirectoryUser>, DirectoryError> {
    serde_json::from_str(text).map_err(|e| DirectoryError::Malformed(format!("snapshot: {e}")))
}

impl Directory for FileDirectory {
    fn members<'a>(&'a self, _query: &'a DirectoryQuery) -> MembersFuture<'a> {
        Box::pin(async move {
            let text = fs::read_to_string(&self.path).await.map_err(|e| {
                DirectoryError::Transport(format!("{}: {e}", self.path.display()))
            })?;
            parse_snapshot(&text)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> DirectoryQuery {
        DirectoryQuery {
            tenant_id: "t".into(),
            group_id: None,
        }
    }

    #[test]
    fn a_snapshot_is_an_array_of_members() {
        let users = parse_snapshot(
            r#"[{"object_id":"a1","upn":"a@x.gov","display_name":"A","enabled":true}]"#,
        )
        .expect("parses");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].object_id, "a1");
    }

    #[test]
    fn a_truncated_snapshot_is_an_error_not_an_empty_directory() {
        let err = parse_snapshot(r#"[{"object_id":"a1","#).unwrap_err();
        assert!(matches!(err, DirectoryError::Malformed(_)));
    }

    #[test]
    fn an_object_where_an_array_belongs_is_an_error() {
        assert!(parse_snapshot(r#"{"object_id":"a1"}"#).is_err());
    }

    #[tokio::test]
    async fn a_missing_file_is_a_transport_error() {
        let directory = FileDirectory::new("/nonexistent/garrison-directory.json");
        let err = directory.members(&query()).await.unwrap_err();
        assert!(matches!(err, DirectoryError::Transport(_)));
        assert!(err.to_string().contains("garrison-directory.json"));
    }

    #[tokio::test]
    async fn a_readable_file_lists_its_members() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("directory.json");
        std::fs::write(
            &path,
            r#"[{"object_id":"a1","upn":"a@x.gov","display_name":"A","enabled":false}]"#,
        )
        .expect("write");
        let users = FileDirectory::new(&path)
            .members(&query())
            .await
            .expect("lists");
        assert_eq!(users.len(), 1);
        assert!(!users[0].enabled);
    }
}
