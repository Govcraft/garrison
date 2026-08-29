//! A narrow client for the control plane's own REST API.
//!
//! The hook provisions by calling the plane rather than by writing to its
//! database. That costs a network hop and buys the thing worth having: every
//! row this service creates goes through the same Cedar decision, the same
//! `@require` rules, and the same audit as a row created by a human. A hook
//! that reached for the connection pool would be a second write path with its
//! own bugs, and the first place a policy change would fail to apply.
//!
//! The transport underneath is `acton-service-client`, the consumer-side
//! counterpart to the framework the plane is built on. It already knows the
//! wire conventions every acton-service speaks: the `{error, code, status}`
//! body shape, the versioned `{base}/{v1}` route layout, bearer auth, the
//! request-tracking headers, and which statuses are worth retrying. What is
//! left here is the part that is genuinely SchemaForge's: the `forge/schemas`
//! route shape, the `{"fields": …}` envelope, and the row types this service
//! reads.
//!
//! Two bearers use this client. The enrollment hook holds one scoped by the
//! `enrollment_service` role, and the directory sync holds one scoped by
//! `directory_service`. Each `Plane` value carries exactly one, so the sync
//! cannot spend the enrollment grant and the hook cannot spend the sync's.

use std::collections::BTreeMap;

use acton_service_client::{ApiVersion, ClientError, ServiceClient};
use serde::Deserialize;
use serde_json::{json, Value};

/// Rows fetched per page when listing. The plane caps a query at a few
/// hundred; this stays under it and pages until a short page arrives.
const PAGE: usize = 200;

/// Everything that can go wrong between here and the plane.
#[derive(Debug)]
pub enum PlaneError {
    /// Transport, status, or decode: the framework client's own taxonomy.
    Client(ClientError),
    /// The plane answered with a shape this client does not understand.
    ///
    /// Distinct from `ClientError::Decode` on purpose: that means the JSON did
    /// not fit the struct, this means it fit and still made no sense, such as
    /// two rows behind a unique index.
    Malformed(String),
}

impl std::fmt::Display for PlaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Client(e) => write!(f, "control plane call failed: {e}"),
            Self::Malformed(what) => write!(f, "control plane response not understood: {what}"),
        }
    }
}

impl std::error::Error for PlaneError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Client(e) => Some(e),
            Self::Malformed(_) => None,
        }
    }
}

impl From<ClientError> for PlaneError {
    fn from(e: ClientError) -> Self {
        Self::Client(e)
    }
}

/// One `EnrollmentToken` row, in the fields this service actually reads.
///
/// Deliberately not the whole entity: a struct that names only what it needs
/// cannot accidentally start depending on a field somebody meant to remove.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollmentTokenRow {
    pub id: String,
    pub issuer: String,
    pub organization: Option<String>,
    pub scope: String,
    pub operator: Option<String>,
    pub max_uses: i64,
    pub uses: i64,
    pub status: String,
    pub expires_at: Option<String>,
    pub first_redeemed_at: Option<String>,
}

/// The subset of an `Operator` row the hook and the sync both read.
///
/// `organization` is read for the freshness check at enrollment and nothing
/// else: the tenant an install joins still comes from the token, which the
/// plane issued, not from the row, which a UPN lookup reached.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OperatorRow {
    pub id: String,
    pub upn: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub entra_object_id: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub organization: Option<String>,
}

/// The subset of an `Organization` row the sync drives and the hook checks.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OrganizationRow {
    pub id: String,
    pub slug: String,
    #[serde(default)]
    pub entra_tenant_id: Option<String>,
    #[serde(default)]
    pub entra_group_id: Option<String>,
    #[serde(default)]
    pub directory_synced_at: Option<String>,
    #[serde(default)]
    pub directory_sync_status: Option<String>,
    #[serde(default = "yes")]
    pub active: bool,
}

/// A console login, in the fields the sync follows.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UserRow {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default = "yes")]
    pub active: bool,
    #[serde(default)]
    pub entra_object_id: Option<String>,
    #[serde(default)]
    pub org_slug: Option<String>,
}

/// A seat, in the fields needed to revoke it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SeatRow {
    pub id: String,
    pub operator: String,
    #[serde(default)]
    pub status: String,
}

/// The standing identity a daemon presents, in the fields the install-token
/// exchange reads.
///
/// `install` and `organization` are relation columns and arrive as the
/// related row's id, which is exactly what the exchange needs: the identity
/// it is about to mint a bearer for.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InstallCredentialRow {
    pub id: String,
    pub credential_id: String,
    pub install: String,
    pub organization: String,
    pub credential_kind: String,
    pub public_key: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub use_count: i64,
}

/// One daemon in the fleet, in the fields that decide whether it may still
/// authenticate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AgentInstallRow {
    pub id: String,
    pub install_id: String,
    pub organization: String,
    #[serde(default)]
    pub status: String,
    /// The `Operator` row this machine belongs to.
    ///
    /// Read by the audit ingest, which attributes every shipped entry from
    /// here rather than from anything the daemon sent. Optional in the struct
    /// and required in the schema: a row this bearer can see but not fully
    /// read should narrow what the hook may conclude, not crash it.
    #[serde(default)]
    pub operator: Option<String>,
}

fn yes() -> bool {
    true
}

/// A bearer-authenticated client for one control plane.
#[derive(Clone)]
pub struct Plane {
    http: ServiceClient,
}

impl std::fmt::Debug for Plane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plane").finish_non_exhaustive()
    }
}

impl Plane {
    /// Build a client for the plane at `base_url`, authenticating with `token`.
    ///
    /// `base_url` is the origin, e.g. `https://plane.agency.gov`; the `/api/v1`
    /// prefix is the framework's convention and the client appends it, so no
    /// caller here spells a version.
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self, PlaneError> {
        let http = ServiceClient::builder(base_url)
            .api_version(ApiVersion::V1)
            .bearer_token(token)
            .build()?;
        Ok(Self { http })
    }

    /// Find the single enrollment token with this public id.
    ///
    /// `token_id` is `unique`, so zero or one row can match; more than one is
    /// a database that has lost a constraint, and this refuses rather than
    /// picking a winner.
    pub async fn enrollment_token(
        &self,
        token_id: &str,
    ) -> Result<Option<EnrollmentTokenRow>, PlaneError> {
        let value: Value = self
            .http
            .post(
                "forge/schemas/EnrollmentToken/entities/query",
                &equals("token_id", token_id),
            )
            .await?;
        let mut rows = entities_of(&value)?;
        match rows.len() {
            0 => Ok(None),
            1 => one_row(rows.remove(0), "EnrollmentToken"),
            n => Err(PlaneError::Malformed(format!(
                "token_id {token_id} matched {n} rows; it is declared unique"
            ))),
        }
    }

    /// Resolve an operator by `upn`.
    ///
    /// The bearer's own tenant scope is applied by the plane, so this cannot
    /// reach an operator in another organization even if the UPN collides.
    pub async fn operator_by_upn(&self, upn: &str) -> Result<Option<OperatorRow>, PlaneError> {
        self.first("Operator", &equals("upn", upn)).await
    }

    /// Fetch one operator by row id.
    pub async fn operator_by_id(&self, id: &str) -> Result<Option<OperatorRow>, PlaneError> {
        self.get("Operator", id).await
    }

    /// Fetch one organization by row id.
    pub async fn organization_by_id(
        &self,
        id: &str,
    ) -> Result<Option<OrganizationRow>, PlaneError> {
        self.get("Organization", id).await
    }

    /// Every operator of one organization.
    pub async fn operators_of(&self, organization: &str) -> Result<Vec<OperatorRow>, PlaneError> {
        self.list_all("Operator", Some(("organization", organization)))
            .await
    }

    /// Every console login the bearer can see.
    pub async fn users(&self) -> Result<Vec<UserRow>, PlaneError> {
        self.list_all("User", None).await
    }

    /// Every seat held by one operator.
    pub async fn seats_of(&self, operator: &str) -> Result<Vec<SeatRow>, PlaneError> {
        self.list_all("Seat", Some(("operator", operator))).await
    }

    /// Fetch one install credential by row id.
    ///
    /// `None` covers both "no such row" and "this bearer may not see it",
    /// which for the exchange are the same refusal: an unknown credential.
    pub async fn install_credential(
        &self,
        id: &str,
    ) -> Result<Option<InstallCredentialRow>, PlaneError> {
        self.get("InstallCredential", id).await
    }

    /// Fetch one install by row id.
    pub async fn agent_install(&self, id: &str) -> Result<Option<AgentInstallRow>, PlaneError> {
        self.get("AgentInstall", id).await
    }

    /// Create an entity and return its new id.
    pub async fn create(
        &self,
        schema: &str,
        fields: BTreeMap<String, Value>,
    ) -> Result<String, PlaneError> {
        let value: Value = self
            .http
            .post(
                format!("forge/schemas/{schema}/entities"),
                &json!({ "fields": fields }),
            )
            .await?;
        value
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| PlaneError::Malformed(format!("{schema} create returned no id")))
    }

    /// Patch an entity in place.
    pub async fn patch(
        &self,
        schema: &str,
        id: &str,
        fields: BTreeMap<String, Value>,
    ) -> Result<(), PlaneError> {
        let _: Value = self
            .http
            .patch(
                format!("forge/schemas/{schema}/entities/{id}"),
                &json!({ "fields": fields }),
            )
            .await?;
        Ok(())
    }

    async fn first<T: serde::de::DeserializeOwned>(
        &self,
        schema: &str,
        query: &Value,
    ) -> Result<Option<T>, PlaneError> {
        let value: Value = self
            .http
            .post(format!("forge/schemas/{schema}/entities/query"), query)
            .await?;
        let mut rows = entities_of(&value)?;
        if rows.is_empty() {
            return Ok(None);
        }
        one_row(rows.remove(0), schema)
    }

    /// A single entity by id; `None` when the plane says it does not exist or
    /// the bearer may not see it, which from here are the same thing.
    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        schema: &str,
        id: &str,
    ) -> Result<Option<T>, PlaneError> {
        let result: Result<Value, ClientError> = self
            .http
            .get(format!("forge/schemas/{schema}/entities/{id}"))
            .await;
        match result {
            Ok(value) => one_row(value, schema),
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Every row matching `filter`, paged until a short page.
    async fn list_all<T: serde::de::DeserializeOwned>(
        &self,
        schema: &str,
        filter: Option<(&str, &str)>,
    ) -> Result<Vec<T>, PlaneError> {
        let mut rows = Vec::new();
        let mut offset = 0;
        loop {
            let value: Value = self
                .http
                .post(
                    format!("forge/schemas/{schema}/entities/query"),
                    &page_query(filter, PAGE, offset),
                )
                .await?;
            let page = entities_of(&value)?;
            let got = page.len();
            for row in page {
                if let Some(parsed) = one_row(row, schema)? {
                    rows.push(parsed);
                }
            }
            if got < PAGE {
                return Ok(rows);
            }
            offset += got;
        }
    }
}

fn is_not_found(error: &ClientError) -> bool {
    error
        .as_api()
        .is_some_and(|api| api.status().as_u16() == 404)
}

/// A single-field equality query body.
///
/// `limit: 2` rather than `1` on purpose: asking for one row can never reveal
/// that a unique index has two, and the caller's job is to notice.
fn equals(field: &str, value: &str) -> Value {
    json!({
        "filter": { "field": field, "op": "eq", "value": value },
        "limit": 2
    })
}

/// One page of a listing, optionally narrowed by one equality.
fn page_query(filter: Option<(&str, &str)>, limit: usize, offset: usize) -> Value {
    match filter {
        Some((field, value)) => json!({
            "filter": { "field": field, "op": "eq", "value": value },
            "limit": limit,
            "offset": offset
        }),
        None => json!({ "limit": limit, "offset": offset }),
    }
}

/// Deserialize one row, naming the schema in any failure.
fn one_row<T: serde::de::DeserializeOwned>(
    row: Value,
    schema: &str,
) -> Result<Option<T>, PlaneError> {
    serde_json::from_value(flatten(row))
        .map(Some)
        .map_err(|e| PlaneError::Malformed(format!("{schema}: {e}")))
}

/// Fold an entity envelope down to the flat object the row types expect.
///
/// The plane returns `{id, schema, fields: {…}, permissions: {…}}`, which puts
/// the identity and the data at different depths. Merging `id` into the field
/// map means a row struct reads the way the schema does: one field per line,
/// no envelope in the middle. Anything already flat passes through, so this
/// works against a single-entity GET as well as a query.
fn flatten(row: Value) -> Value {
    let Some(Value::Object(fields)) = row.get("fields") else {
        return row;
    };
    let mut flat = fields.clone();
    if let Some(id) = row.get("id") {
        flat.insert("id".to_string(), id.clone());
    }
    Value::Object(flat)
}

/// Pull the row array out of a list/query response.
///
/// The plane wraps results under `entities`; a bare array is accepted too so
/// this does not break on a response-shape change it could tolerate.
fn entities_of(value: &Value) -> Result<Vec<Value>, PlaneError> {
    match value.get("entities").unwrap_or(value) {
        Value::Array(rows) => Ok(rows.clone()),
        other => Err(PlaneError::Malformed(format!(
            "expected an array of entities, got {}",
            kind_of(other)
        ))),
    }
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

// ---------------------------------------------------------------------------
// Audit shipping. Additive: the row types and lookups the verifying ingest and
// the liveness sweep read, in their own `impl` block so this file stays easy
// to merge.
// ---------------------------------------------------------------------------

/// The daemon's own claim about one trail.
///
/// Written by the install's operator bearer, so nothing on it is evidence.
/// The ingest reads `install` from here rather than from the row the client
/// sent, which is what makes shipping into somebody else's trail detectable.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuditTrailRow {
    pub id: String,
    pub trail_id: String,
    pub install: String,
    pub organization: String,
    #[serde(default)]
    pub local_head_seq: i64,
    #[serde(default)]
    pub local_head_hash: Option<String>,
    #[serde(default)]
    pub shipped_through: i64,
    #[serde(default)]
    pub reported_at: Option<String>,
    #[serde(default)]
    pub halted_reason: Option<String>,
}

/// What the plane has verified about one trail.
///
/// The install cannot write this row at all. Its disagreement with the
/// matching [`AuditTrailRow`] over time is the whole liveness signal.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuditChainRow {
    pub id: String,
    pub trail_id: String,
    pub trail: String,
    pub organization: String,
    pub install: String,
    #[serde(default)]
    pub head_hash: String,
    #[serde(default)]
    pub head_seq: i64,
    #[serde(default)]
    pub verified_through: i64,
    #[serde(default)]
    pub integrity: String,
    #[serde(default)]
    pub finding: Option<String>,
    #[serde(default)]
    pub last_entry_at: Option<String>,
}

/// One already-ingested entry, in the fields that resolve a re-send.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuditEventRow {
    pub id: String,
    pub trail: String,
    pub chain_seq: i64,
    pub entry_hash: String,
    #[serde(default)]
    pub prev_hash: String,
}

impl Plane {
    /// Fetch one trail by row id.
    ///
    /// The hook is handed `trail` as a row id, already resolved by the forge
    /// from the relation the client set, so this is a `get` rather than a
    /// lookup by `trail_id`.
    pub async fn audit_trail(&self, id: &str) -> Result<Option<AuditTrailRow>, PlaneError> {
        self.get("AuditTrail", id).await
    }

    /// Find the chain for a trail by the trail's own identity.
    ///
    /// Keyed on `trail_id` rather than the relation because `trail_id` is the
    /// unique column: one chain per trail is a constraint the database holds,
    /// not a convention the hook maintains.
    pub async fn audit_chain(&self, trail_id: &str) -> Result<Option<AuditChainRow>, PlaneError> {
        self.first("AuditChain", &equals("trail_id", trail_id))
            .await
    }

    /// Find an already-ingested entry by its hash.
    ///
    /// `entry_hash` is unique, so this answers the one question a re-sent
    /// entry raises: is this the same entry arriving twice, or a different
    /// entry claiming a position the chain has already passed?
    pub async fn audit_event_by_hash(
        &self,
        entry_hash: &str,
    ) -> Result<Option<AuditEventRow>, PlaneError> {
        self.first("AuditEvent", &equals("entry_hash", entry_hash))
            .await
    }

    /// Every trail this bearer can see.
    pub async fn audit_trails(&self) -> Result<Vec<AuditTrailRow>, PlaneError> {
        self.list_all("AuditTrail", None).await
    }

    /// Every chain this bearer can see.
    pub async fn audit_chains(&self) -> Result<Vec<AuditChainRow>, PlaneError> {
        self.list_all("AuditChain", None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entities_are_read_from_the_wrapper() {
        let value = json!({ "entities": [{ "id": "a" }], "count": 1 });
        assert_eq!(entities_of(&value).unwrap().len(), 1);
    }

    #[test]
    fn a_bare_array_is_also_accepted() {
        let value = json!([{ "id": "a" }, { "id": "b" }]);
        assert_eq!(entities_of(&value).unwrap().len(), 2);
    }

    #[test]
    fn a_response_that_is_not_a_list_is_a_malformed_error() {
        let value = json!({ "entities": 7 });
        let err = entities_of(&value).unwrap_err();
        assert!(matches!(err, PlaneError::Malformed(_)));
        assert!(err.to_string().contains("a number"));
    }

    #[test]
    fn a_lookup_asks_for_two_rows_so_a_lost_unique_index_is_visible() {
        assert_eq!(equals("token_id", "tok_1")["limit"], json!(2));
        assert_eq!(
            equals("token_id", "tok_1")["filter"]["value"],
            json!("tok_1")
        );
    }

    #[test]
    fn a_page_query_carries_its_offset_and_optional_filter() {
        let narrowed = page_query(Some(("operator", "op_1")), 200, 400);
        assert_eq!(narrowed["offset"], json!(400));
        assert_eq!(narrowed["filter"]["field"], json!("operator"));
        let whole = page_query(None, 200, 0);
        assert!(whole.get("filter").is_none());
    }

    #[test]
    fn an_envelope_is_folded_flat_with_its_id_alongside_the_fields() {
        let row = json!({
            "id": "operator_01",
            "schema": "Operator",
            "fields": { "upn": "dev@agency.gov", "display_name": "Dev", "status": "active" },
            "permissions": { "update": true }
        });
        let parsed: OperatorRow = one_row(row, "Operator").unwrap().unwrap();
        assert_eq!(parsed.id, "operator_01");
        assert_eq!(parsed.upn, "dev@agency.gov");
        assert_eq!(parsed.entra_object_id, None);
    }

    #[test]
    fn a_hand_typed_operator_reads_with_its_optional_fields_absent() {
        let row = json!({ "id": "operator_01", "upn": "dev@agency.gov" });
        let parsed: OperatorRow = one_row(row, "Operator").unwrap().unwrap();
        assert_eq!(parsed.status, "");
        assert_eq!(parsed.organization, None);
    }

    #[test]
    fn a_user_row_defaults_to_active_with_no_roles() {
        let row = json!({ "id": "user_01", "email": "a@x.gov" });
        let parsed: UserRow = one_row(row, "User").unwrap().unwrap();
        assert!(parsed.active);
        assert!(parsed.roles.is_empty());
    }

    #[test]
    fn an_already_flat_row_passes_through_untouched() {
        let row = json!({ "id": "operator_01", "upn": "dev@agency.gov" });
        assert_eq!(flatten(row.clone()), row);
    }

    #[test]
    fn a_row_that_does_not_fit_names_its_schema() {
        let err = one_row::<OperatorRow>(json!({ "nope": true }), "Operator").unwrap_err();
        assert!(err.to_string().contains("Operator"));
    }

    #[test]
    fn a_plane_can_be_built_from_an_origin() {
        assert!(Plane::new("https://plane.gov", "tok").is_ok());
    }

    #[test]
    fn a_base_url_that_is_not_a_url_is_rejected_at_build_time() {
        assert!(Plane::new("not a url", "tok").is_err());
    }
}
