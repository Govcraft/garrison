//! Microsoft Graph as a directory.
//!
//! Two calls: a client-credentials token from the tenant's authority, then a
//! paged listing of the group's user members (or of every user when the
//! organization names no group), following `@odata.nextLink` until Graph
//! stops sending one.
//!
//! Everything that interprets bytes is a pure function with a fixture test:
//! `parse_token_response`, `parse_members_page`, `classify`. The HTTP client
//! only moves them. That split is what makes this module honest about what
//! it has proved: the parsers are tested against recorded Graph shapes, the
//! transport has never been run against a real tenant, and the docs say so.
//!
//! A token is fetched per listing rather than cached. The listing runs once
//! per `interval` (five minutes by default) and a client-credentials token is
//! one round trip, so a cache would buy nothing and cost a mutable field on a
//! value that is otherwise read-only.

use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use tracing::debug;

use super::{Directory, DirectoryError, DirectoryQuery, DirectoryUser, MembersFuture};

/// The projection every listing asks for. Nothing wider: the reconciler owns
/// exactly these attributes and Graph bills by field.
pub const SELECT: &str = "id,userPrincipalName,displayName,mail,accountEnabled";

/// Graph's maximum page size for users.
pub const PAGE_SIZE: u32 = 999;

/// The scope a client-credentials grant asks for.
pub const SCOPE: &str = "https://graph.microsoft.com/.default";

/// An upper bound on pages followed, so a `nextLink` loop cannot spin.
const MAX_PAGES: usize = 1000;

/// A directory read from Microsoft Graph with an app registration.
#[derive(Debug, Clone)]
pub struct GraphDirectory {
    http: Client,
    authority: String,
    graph: String,
    client_id: String,
    secret: String,
}

impl GraphDirectory {
    /// A client for `graph`, authenticating against `authority` as the app
    /// registration `client_id` with `secret`.
    pub fn new(
        authority: impl Into<String>,
        graph: impl Into<String>,
        client_id: impl Into<String>,
        secret: impl Into<String>,
    ) -> Result<Self, DirectoryError> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| DirectoryError::Transport(format!("http client: {e}")))?;
        Ok(Self {
            http,
            authority: authority.into(),
            graph: graph.into(),
            client_id: client_id.into(),
            secret: secret.into(),
        })
    }

    async fn token(&self, tenant_id: &str) -> Result<String, DirectoryError> {
        let form = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.secret.as_str()),
            ("scope", SCOPE),
            ("grant_type", "client_credentials"),
        ];
        let response = self
            .http
            .post(token_url(&self.authority, tenant_id))
            .form(&form)
            .send()
            .await
            .map_err(|e| DirectoryError::Transport(format!("token request: {e}")))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| DirectoryError::Transport(format!("token response: {e}")))?;
        classify(status, &body)?;
        parse_token_response(&body).map(|t| t.access_token)
    }

    async fn page(
        &self,
        token: &str,
        url: &str,
    ) -> Result<(Vec<DirectoryUser>, Option<String>), DirectoryError> {
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| DirectoryError::Transport(format!("listing request: {e}")))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| DirectoryError::Transport(format!("listing response: {e}")))?;
        classify(status, &body)?;
        parse_members_page(&body)
    }
}

impl Directory for GraphDirectory {
    fn members<'a>(&'a self, query: &'a DirectoryQuery) -> MembersFuture<'a> {
        Box::pin(async move {
            let token = self.token(&query.tenant_id).await?;
            let mut url = members_url(&self.graph, query.group_id.as_deref());
            let mut members = Vec::new();
            for page in 0..MAX_PAGES {
                let (mut batch, next) = self.page(&token, &url).await?;
                debug!(page, count = batch.len(), more = next.is_some(), "graph page");
                members.append(&mut batch);
                match next {
                    Some(next) => url = next,
                    None => return Ok(members),
                }
            }
            Err(DirectoryError::Malformed(format!(
                "listing did not end after {MAX_PAGES} pages"
            )))
        })
    }
}

/// The client-credentials endpoint for one tenant.
#[must_use]
pub fn token_url(authority: &str, tenant_id: &str) -> String {
    format!(
        "{}/{tenant_id}/oauth2/v2.0/token",
        authority.trim_end_matches('/')
    )
}

/// The first page of the listing: the group's user members, or every user.
#[must_use]
pub fn members_url(graph: &str, group_id: Option<&str>) -> String {
    let base = graph.trim_end_matches('/');
    match group_id {
        Some(group) => {
            format!("{base}/groups/{group}/members/microsoft.graph.user?$select={SELECT}&$top={PAGE_SIZE}")
        }
        None => format!("{base}/users?$select={SELECT}&$top={PAGE_SIZE}"),
    }
}

/// Sort an HTTP status into the directory's error taxonomy.
///
/// Throttling (429) and server errors are `Transport`, so a tick that hits
/// them fails and is retried next interval rather than reading as an empty
/// directory. 401 and 403 are `Auth`. Anything else non-2xx is `Transport`
/// with the body, which is where Graph puts its explanation.
pub fn classify(status: StatusCode, body: &str) -> Result<(), DirectoryError> {
    if status.is_success() {
        return Ok(());
    }
    let detail = graph_error_message(body).unwrap_or_else(|| body.chars().take(200).collect());
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            Err(DirectoryError::Auth(format!("{status}: {detail}")))
        }
        _ => Err(DirectoryError::Transport(format!("{status}: {detail}"))),
    }
}

/// The `error.message` or `error_description` Graph and the token endpoint
/// put in a failure body, if the body is one of theirs.
fn graph_error_message(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    if let Some(message) = value.pointer("/error/message").and_then(Value::as_str) {
        let code = value
            .pointer("/error/code")
            .and_then(Value::as_str)
            .unwrap_or("error");
        return Some(format!("{code}: {message}"));
    }
    if let Some(description) = value.get("error_description").and_then(Value::as_str) {
        return Some(description.to_string());
    }
    value.get("error").and_then(Value::as_str).map(str::to_owned)
}

/// A successful token response, in the fields used here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccessToken {
    pub access_token: String,
    #[serde(default)]
    pub expires_in: u64,
}

/// Read a token endpoint body. A body carrying `error` is an `Auth` failure
/// even under a 200, because the token endpoint has been known to say so.
pub fn parse_token_response(text: &str) -> Result<AccessToken, DirectoryError> {
    let value: Value =
        serde_json::from_str(text).map_err(|e| DirectoryError::Malformed(format!("token: {e}")))?;
    if value.get("error").is_some() {
        return Err(DirectoryError::Auth(
            graph_error_message(text).unwrap_or_else(|| "token endpoint returned an error".into()),
        ));
    }
    let token: AccessToken = serde_json::from_value(value)
        .map_err(|e| DirectoryError::Malformed(format!("token: {e}")))?;
    if token.access_token.is_empty() {
        return Err(DirectoryError::Malformed("token: empty access_token".into()));
    }
    Ok(token)
}

#[derive(Debug, Deserialize)]
struct MembersPage {
    #[serde(rename = "@odata.nextLink", default)]
    next_link: Option<String>,
    #[serde(default)]
    value: Vec<GraphUser>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphUser {
    id: String,
    #[serde(default)]
    user_principal_name: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    mail: Option<String>,
    #[serde(default)]
    account_enabled: Option<bool>,
}

/// Read one page of a members listing: the members and the next link.
///
/// A user without `accountEnabled` or without `userPrincipalName` is a
/// `Malformed` error rather than a guess. Guessing `enabled = false` would
/// suspend a person on a projection quirk; guessing `true` would keep a
/// disabled one active. Either is worse than a failed tick that names the
/// object id.
pub fn parse_members_page(
    text: &str,
) -> Result<(Vec<DirectoryUser>, Option<String>), DirectoryError> {
    let page: MembersPage = serde_json::from_str(text)
        .map_err(|e| DirectoryError::Malformed(format!("members page: {e}")))?;
    let mut members = Vec::with_capacity(page.value.len());
    for user in page.value {
        let upn = user
            .user_principal_name
            .filter(|u| !u.is_empty())
            .ok_or_else(|| {
                DirectoryError::Malformed(format!("user {} has no userPrincipalName", user.id))
            })?;
        let enabled = user.account_enabled.ok_or_else(|| {
            DirectoryError::Malformed(format!("user {} has no accountEnabled", user.id))
        })?;
        members.push(DirectoryUser {
            object_id: user.id,
            display_name: user.display_name.unwrap_or_else(|| upn.clone()),
            upn,
            mail: user.mail.filter(|m| !m.is_empty()),
            enabled,
        });
    }
    Ok((members, page.next_link))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = include_str!("../../tests/fixtures/graph/token.json");
    const TOKEN_ERROR: &str = include_str!("../../tests/fixtures/graph/token_error.json");
    const PAGE1: &str = include_str!("../../tests/fixtures/graph/members_page1.json");
    const PAGE2: &str = include_str!("../../tests/fixtures/graph/members_page2.json");
    const NO_ENABLED: &str = include_str!("../../tests/fixtures/graph/members_no_enabled.json");
    const THROTTLED: &str = include_str!("../../tests/fixtures/graph/members_throttled.json");

    #[test]
    fn a_token_response_yields_the_bearer() {
        let token = parse_token_response(TOKEN).expect("parses");
        assert!(token.access_token.starts_with("eyJ"));
        assert_eq!(token.expires_in, 3599);
    }

    #[test]
    fn a_token_error_body_is_an_auth_failure_with_the_description() {
        let err = parse_token_response(TOKEN_ERROR).unwrap_err();
        assert!(matches!(err, DirectoryError::Auth(_)));
        assert!(err.to_string().contains("AADSTS7000215"));
    }

    #[test]
    fn an_empty_access_token_is_malformed() {
        let err = parse_token_response(r#"{"access_token":""}"#).unwrap_err();
        assert!(matches!(err, DirectoryError::Malformed(_)));
    }

    #[test]
    fn the_first_page_carries_its_members_and_the_next_link() {
        let (members, next) = parse_members_page(PAGE1).expect("parses");
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].object_id, "aaaaaaaa-1111-1111-1111-111111111111");
        assert_eq!(members[0].upn, "alice@example-agency.gov");
        assert!(members[0].enabled);
        assert_eq!(members[0].mail.as_deref(), Some("alice@example-agency.gov"));
        assert!(next.expect("next link").contains("$skiptoken"));
    }

    #[test]
    fn a_guest_without_mail_is_kept_with_mail_absent() {
        let (members, _) = parse_members_page(PAGE1).expect("parses");
        assert_eq!(members[1].mail, None);
        assert!(members[1].upn.contains("#EXT#"));
    }

    #[test]
    fn the_last_page_has_no_next_link_and_carries_the_disabled_flag() {
        let (members, next) = parse_members_page(PAGE2).expect("parses");
        assert_eq!(next, None);
        assert_eq!(members.len(), 1);
        assert!(!members[0].enabled);
    }

    #[test]
    fn a_user_without_account_enabled_fails_the_page_rather_than_guessing() {
        let err = parse_members_page(NO_ENABLED).unwrap_err();
        assert!(matches!(err, DirectoryError::Malformed(_)));
        assert!(err.to_string().contains("dddddddd-4444"));
    }

    #[test]
    fn an_empty_page_is_an_empty_list_not_an_error() {
        let (members, next) = parse_members_page(r#"{"value":[]}"#).expect("parses");
        assert!(members.is_empty());
        assert!(next.is_none());
    }

    #[test]
    fn throttling_is_a_transport_error_with_graphs_message() {
        let err = classify(StatusCode::TOO_MANY_REQUESTS, THROTTLED).unwrap_err();
        assert!(matches!(err, DirectoryError::Transport(_)));
        assert!(err.to_string().contains("TooManyRequests"));
    }

    #[test]
    fn forbidden_is_an_auth_error() {
        let err = classify(StatusCode::FORBIDDEN, "{}").unwrap_err();
        assert!(matches!(err, DirectoryError::Auth(_)));
    }

    #[test]
    fn a_server_error_with_a_non_json_body_quotes_the_body() {
        let err = classify(StatusCode::BAD_GATEWAY, "<html>bad gateway</html>").unwrap_err();
        assert!(err.to_string().contains("bad gateway"));
    }

    #[test]
    fn success_classifies_as_ok() {
        assert!(classify(StatusCode::OK, "").is_ok());
    }

    #[test]
    fn urls_are_built_for_a_group_and_for_the_whole_tenant() {
        assert_eq!(
            token_url("https://login.microsoftonline.com/", "tenant-1"),
            "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
        );
        let group = members_url("https://graph.microsoft.com/v1.0", Some("g1"));
        assert!(group.starts_with("https://graph.microsoft.com/v1.0/groups/g1/members/microsoft.graph.user?"));
        assert!(group.contains("$top=999"));
        let all = members_url("https://graph.microsoft.com/v1.0/", None);
        assert!(all.starts_with("https://graph.microsoft.com/v1.0/users?"));
    }

    #[test]
    fn a_client_can_be_built() {
        assert!(GraphDirectory::new("https://a", "https://g", "c", "s").is_ok());
    }
}
