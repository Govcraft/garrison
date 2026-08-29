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
//! left here is the part that is genuinely SchemaForge's — the `forge/schemas`
//! route shape, the `{"fields": …}` envelope, and the two row types this
//! service reads.
//!
//! The credential it holds is scoped by the `enrollment_service` role, which
//! appears in exactly four `@access` lists: AgentInstall and InstallCredential
//! writes, EnrollmentToken reads and writes, Operator reads.

use std::collections::BTreeMap;

use acton_service_client::{ApiVersion, ClientError, ServiceClient};
use serde::Deserialize;
use serde_json::{json, Value};

/// Everything that can go wrong between here and the plane.
#[derive(Debug)]
pub enum PlaneError {
    /// Transport, status, or decode — the framework client's own taxonomy.
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

/// The subset of an `Operator` row needed to bind an install to a person.
///
/// The organization is deliberately absent: it comes from the token, which the
/// plane issued, not from the row, which a UPN lookup reached.
#[derive(Debug, Clone, Deserialize)]
pub struct OperatorRow {
    pub id: String,
}

/// A bearer-authenticated client for one control plane.
pub struct Plane {
    http: ServiceClient,
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
        let value: Value = self
            .http
            .post("forge/schemas/Operator/entities/query", &equals("upn", upn))
            .await?;
        let mut rows = entities_of(&value)?;
        if rows.is_empty() {
            return Ok(None);
        }
        one_row(rows.remove(0), "Operator")
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
    fn an_envelope_is_folded_flat_with_its_id_alongside_the_fields() {
        let row = json!({
            "id": "operator_01",
            "schema": "Operator",
            "fields": { "upn": "dev@agency.gov" },
            "permissions": { "update": true }
        });
        let parsed: OperatorRow = one_row(row, "Operator").unwrap().unwrap();
        assert_eq!(parsed.id, "operator_01");
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
