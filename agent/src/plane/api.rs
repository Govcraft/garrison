//! An authenticated, short-lived view of the plane's REST API.
//!
//! The transport is `acton-service-client`, which already knows the wire
//! conventions every acton-service speaks: the `{error, code, status}` body
//! shape, the versioned route layout, bearer auth, and request tracking. What
//! is here is the part that is SchemaForge's — the `forge/schemas` route
//! shape and the `{"fields": …}` envelope — plus the one thing the daemon
//! needs that the hook service does not: a failure taxonomy that separates
//! *unreachable* from *refused*.
//!
//! # Why no retries
//!
//! The client is built with a single attempt and a five-second timeout. A
//! subsystem that calls the plane is already inside an actor with its own
//! cadence: the seat monitor will ask again on its next tick, the shipper on
//! its next batch. Retrying underneath them would multiply one outage by
//! three and hide the latency from the status surface, which is where an
//! operator looks to find out whether the plane is answering.
//!
//! An `Api` is not kept. It carries a bearer that expires, so it is obtained
//! per operation from [`super::session::PlaneSession`] and dropped.

use acton_service_client::{ApiVersion, ClientError, RetryPolicy, ServiceClient};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::time::Duration;

/// How long any single plane call may take.
///
/// Bounded well under the five-second gate deadline in
/// [`crate::admission`], so a slow plane surfaces as a refusal with a reason
/// rather than as a gate that timed out.
pub const TIMEOUT: Duration = Duration::from_secs(5);

/// Everything that can go wrong between the daemon and the plane.
///
/// The split that matters is [`is_unreachable`](PlaneError::is_unreachable).
/// Every governance subsystem has a grace policy for an unreachable plane and
/// no grace at all for a refusal, so collapsing the two would either ground a
/// fleet during a network blip or keep a revoked install running.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlaneError {
    /// The plane could not be asked, or could not answer: connection, TLS,
    /// timeout, 5xx, 429, or a body that did not decode.
    Unreachable(String),
    /// The plane answered, and the answer was no.
    Rejected {
        /// The HTTP status it refused with.
        status: u16,
        /// What it said.
        message: String,
    },
    /// The row is not there, or this bearer may not see it, which from here
    /// are the same fact.
    NotFound(String),
    /// The plane answered with a shape this client does not understand.
    ///
    /// Distinct from a decode failure: that means the JSON did not fit the
    /// struct, this means it fit and still made no sense.
    Malformed(String),
}

impl PlaneError {
    /// Whether this is the plane being unavailable rather than unwilling.
    ///
    /// A decode failure counts as unreachable: a proxy returning an HTML
    /// error page is an outage wearing a 200, and treating it as a refusal
    /// would make a load balancer look like a policy decision.
    #[must_use]
    pub const fn is_unreachable(&self) -> bool {
        matches!(self, Self::Unreachable(_))
    }
}

impl std::fmt::Display for PlaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(why) => write!(f, "the control plane is unreachable: {why}"),
            Self::Rejected { status, message } => {
                write!(f, "the control plane refused ({status}): {message}")
            }
            Self::NotFound(what) => write!(f, "the control plane has no {what}"),
            Self::Malformed(what) => write!(f, "the control plane's answer made no sense: {what}"),
        }
    }
}

impl std::error::Error for PlaneError {}

impl From<ClientError> for PlaneError {
    fn from(error: ClientError) -> Self {
        classify(&error)
    }
}

/// Sorts a transport failure into the two buckets that drive behaviour.
///
/// Pure over the error, so the table below is a test rather than a claim.
fn classify(error: &ClientError) -> PlaneError {
    let Some(api) = error.as_api() else {
        // Transport, decode, or a bad base URL: nothing the plane said.
        return PlaneError::Unreachable(error.to_string());
    };
    let status = api.status().as_u16();
    match status {
        404 => PlaneError::NotFound(api.message().to_string()),
        429 | 500..=599 => PlaneError::Unreachable(format!("{status}: {}", api.message())),
        _ => PlaneError::Rejected {
            status,
            message: api.message().to_string(),
        },
    }
}

/// A bearer-authenticated client for one control plane.
///
/// Cloneable and cheap: the underlying `ServiceClient` shares one connection
/// pool. Not `Debug`-derivable, because the one thing it holds is a bearer.
#[derive(Clone)]
pub struct Api {
    http: ServiceClient,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api").finish_non_exhaustive()
    }
}

impl Api {
    /// Builds a client for the plane at `base_url` holding `bearer`.
    ///
    /// `base_url` is the origin; the `/api/v1` prefix is the framework's
    /// convention and the client appends it, so no caller here spells a
    /// version.
    ///
    /// # Errors
    ///
    /// [`PlaneError::Unreachable`] when `base_url` is not a URL, which is a
    /// configuration fault the caller reports as a plane it cannot reach.
    pub fn new(base_url: &str, bearer: &str) -> Result<Self, PlaneError> {
        let http = ServiceClient::builder(base_url)
            .api_version(ApiVersion::V1)
            .bearer_token(bearer)
            .timeout(TIMEOUT)
            // One attempt: how "no retry" is spelled in this client.
            .retry(RetryPolicy::with_max_attempts(1))
            .build()?;
        Ok(Self { http })
    }

    /// One row by id.
    ///
    /// # Errors
    ///
    /// [`PlaneError::NotFound`] when the plane will not show it; otherwise as
    /// [`PlaneError`].
    pub async fn get<T: DeserializeOwned>(&self, schema: &str, id: &str) -> Result<T, PlaneError> {
        let value: Value = self
            .http
            .get(format!("forge/schemas/{schema}/entities/{id}"))
            .await
            .map_err(|error| match classify(&error) {
                PlaneError::NotFound(_) => PlaneError::NotFound(format!("{schema} {id}")),
                other => other,
            })?;
        one_row(value, schema)
    }

    /// Every row matching a filter body.
    ///
    /// The body is built by [`eq`] and friends rather than assembled here, so
    /// the shape the plane accepts is stated once and tested without a
    /// socket.
    ///
    /// # Errors
    ///
    /// As [`PlaneError`].
    pub async fn query<T: DeserializeOwned>(
        &self,
        schema: &str,
        query: &Value,
    ) -> Result<Vec<T>, PlaneError> {
        let value: Value = self
            .http
            .post(format!("forge/schemas/{schema}/entities/query"), query)
            .await?;
        entities_of(&value)?
            .into_iter()
            .map(|row| one_row(row, schema))
            .collect()
    }

    /// Updates a row in place.
    ///
    /// # Errors
    ///
    /// As [`PlaneError`].
    pub async fn patch(&self, schema: &str, id: &str, fields: &Value) -> Result<(), PlaneError> {
        let _: Value = self
            .http
            .patch(
                format!("forge/schemas/{schema}/entities/{id}"),
                &json!({ "fields": fields }),
            )
            .await?;
        Ok(())
    }

    /// Creates a row and returns its new id.
    ///
    /// # Errors
    ///
    /// As [`PlaneError`], plus [`PlaneError::Malformed`] when the plane
    /// answers a create with no id.
    pub async fn create(&self, schema: &str, fields: &Value) -> Result<String, PlaneError> {
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
}

// =============================================================================
// Query bodies and response shapes — pure, and shared by every consumer
// =============================================================================

/// Rows fetched per page. The plane caps a query at a few hundred.
pub const PAGE: usize = 200;

/// A single-field equality query.
///
/// A relation column compares by the related row's id, which is what the
/// plane stores and what a Q3 probe against a live plane confirmed. `limit`
/// is the caller's, because "find the one row behind a unique index" and
/// "list everything for this organization" want different answers when the
/// count is wrong.
#[must_use]
pub fn eq(field: &str, value: &str, limit: usize) -> Value {
    json!({
        "filter": { "field": field, "op": "eq", "value": value },
        "limit": limit
    })
}

/// A membership query: this field is any of these values.
#[must_use]
pub fn in_(field: &str, values: &[&str], limit: usize) -> Value {
    json!({
        "filter": { "field": field, "op": "in", "value": values },
        "limit": limit
    })
}

/// One page of a listing, optionally narrowed by one equality.
///
/// There is deliberately no compound `and` helper. The plane's query grammar
/// takes exactly one `{field, op, value}` per request — a probe of
/// `{"and": [...]}` against a live plane came back
/// `400 invalid_query: filter must have an 'op' field` — so a caller that
/// needs two conditions issues the selective one and filters the rest in
/// Rust. Shipping a combinator the plane rejects would move that discovery
/// from here to production.
#[must_use]
pub fn page(filter: Option<(&str, &str)>, limit: usize, offset: usize) -> Value {
    match filter {
        Some((field, value)) => json!({
            "filter": { "field": field, "op": "eq", "value": value },
            "limit": limit,
            "offset": offset
        }),
        None => json!({ "limit": limit, "offset": offset }),
    }
}

/// Folds an entity envelope down to the flat object a row type expects.
///
/// The plane returns `{id, schema, fields: {…}, permissions: {…}}`, which puts
/// the identity and the data at different depths. Merging `id` into the field
/// map lets a row struct read the way the schema does. Anything already flat
/// passes through, so this works for a single-entity GET as well as a query.
#[must_use]
pub fn flatten(row: Value) -> Value {
    let Some(Value::Object(fields)) = row.get("fields") else {
        return row;
    };
    let mut flat = fields.clone();
    if let Some(id) = row.get("id") {
        flat.insert("id".to_string(), id.clone());
    }
    Value::Object(flat)
}

/// Pulls the row array out of a list or query response.
///
/// The plane wraps results under `entities`; a bare array is accepted too, so
/// a response-shape change this client could tolerate does not break it.
///
/// # Errors
///
/// [`PlaneError::Malformed`] when the answer is neither.
pub fn entities_of(value: &Value) -> Result<Vec<Value>, PlaneError> {
    match value.get("entities").unwrap_or(value) {
        Value::Array(rows) => Ok(rows.clone()),
        other => Err(PlaneError::Malformed(format!(
            "expected an array of entities, got {}",
            kind_of(other)
        ))),
    }
}

/// Deserializes one row, naming the schema in any failure.
fn one_row<T: DeserializeOwned>(row: Value, schema: &str) -> Result<T, PlaneError> {
    serde_json::from_value(flatten(row))
        .map_err(|error| PlaneError::Malformed(format!("{schema}: {error}")))
}

const fn kind_of(value: &Value) -> &'static str {
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
    use acton_service_client::reqwest::header::HeaderMap;
    use acton_service_client::StatusCode;

    /// A refusal as it arrives from an acton-service, built through the
    /// client's own parser so this table tests the real mapping rather than a
    /// hand-assembled error value.
    fn api_error(status: u16) -> ClientError {
        ClientError::Api(Box::new(acton_service_client::error::build_api_error(
            StatusCode::from_u16(status).unwrap(),
            &HeaderMap::new(),
            r#"{"error":"nope","status":0}"#,
        )))
    }

    #[test]
    fn a_five_hundred_is_the_plane_being_unavailable_not_unwilling() {
        for status in [500, 502, 503, 504] {
            let error = classify(&api_error(status));
            assert!(error.is_unreachable(), "{status}: {error}");
        }
    }

    #[test]
    fn a_rate_limit_is_unreachable_so_callers_back_off_instead_of_refusing() {
        assert!(classify(&api_error(429)).is_unreachable());
    }

    #[test]
    fn a_four_oh_one_and_a_four_oh_three_are_decisions_not_outages() {
        for status in [401, 403] {
            let error = classify(&api_error(status));
            assert!(!error.is_unreachable(), "{status}");
            assert!(
                matches!(error, PlaneError::Rejected { status: s, .. } if s == status),
                "{error}"
            );
        }
    }

    #[test]
    fn a_four_oh_four_is_its_own_answer() {
        assert!(matches!(classify(&api_error(404)), PlaneError::NotFound(_)));
    }

    #[test]
    fn a_body_that_does_not_decode_reads_as_an_outage() {
        let error = ClientError::Decode {
            status: StatusCode::OK,
            snippet: "<html>502 Bad Gateway</html>".to_string(),
            source: serde_json::from_str::<Value>("<").unwrap_err(),
        };

        assert!(
            classify(&error).is_unreachable(),
            "a proxy error page is an outage wearing a 200"
        );
    }

    #[test]
    fn a_bad_base_url_is_reported_as_an_unreachable_plane() {
        let error = Api::new("not a url", "tok").unwrap_err();

        assert!(error.is_unreachable(), "{error}");
    }

    #[test]
    fn a_client_is_built_from_an_origin_with_no_version_spelled() {
        assert!(Api::new("https://plane.gov", "v4.local.abc").is_ok());
    }

    #[test]
    fn an_equality_filter_names_the_field_the_op_and_the_value() {
        let body = eq("install", "agentinstall_01", 2);

        assert_eq!(body["filter"]["field"], json!("install"));
        assert_eq!(body["filter"]["op"], json!("eq"));
        assert_eq!(body["filter"]["value"], json!("agentinstall_01"));
        assert_eq!(body["limit"], json!(2));
    }

    #[test]
    fn a_membership_filter_carries_every_value() {
        let body = in_("status", &["active", "rotating"], 50);

        assert_eq!(body["filter"]["op"], json!("in"));
        assert_eq!(body["filter"]["value"], json!(["active", "rotating"]));
    }

    #[test]
    fn a_page_query_carries_its_offset_and_optional_filter() {
        let narrowed = page(Some(("organization", "organization_01")), PAGE, 400);
        assert_eq!(narrowed["offset"], json!(400));
        assert_eq!(narrowed["filter"]["field"], json!("organization"));

        let whole = page(None, PAGE, 0);
        assert!(whole.get("filter").is_none());
    }

    #[test]
    fn an_envelope_is_folded_flat_with_its_id_alongside_the_fields() {
        #[derive(serde::Deserialize)]
        struct Row {
            id: String,
            hostname: String,
        }

        let row: Row = one_row(
            json!({
                "id": "agentinstall_01",
                "schema": "AgentInstall",
                "fields": { "hostname": "ws-01" },
                "permissions": { "update": true }
            }),
            "AgentInstall",
        )
        .unwrap();

        assert_eq!(row.id, "agentinstall_01");
        assert_eq!(row.hostname, "ws-01");
    }

    #[test]
    fn an_already_flat_row_passes_through_untouched() {
        let row = json!({ "id": "a", "hostname": "ws-01" });
        assert_eq!(flatten(row.clone()), row);
    }

    #[test]
    fn entities_are_read_from_the_wrapper_or_from_a_bare_array() {
        assert_eq!(
            entities_of(&json!({ "entities": [{ "id": "a" }], "count": 1 }))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            entities_of(&json!([{ "id": "a" }, { "id": "b" }]))
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn a_response_that_is_not_a_list_is_malformed_and_says_what_it_was() {
        let error = entities_of(&json!({ "entities": 7 })).unwrap_err();

        assert!(matches!(error, PlaneError::Malformed(_)));
        assert!(error.to_string().contains("a number"));
    }

    #[test]
    fn a_row_that_does_not_fit_names_its_schema() {
        #[derive(Debug, serde::Deserialize)]
        struct Row {
            hostname: String,
        }

        let good: Row = one_row(json!({ "hostname": "ws-01" }), "AgentInstall").unwrap();
        assert_eq!(good.hostname, "ws-01");

        let error = one_row::<Row>(json!({ "nope": true }), "AgentInstall").unwrap_err();

        assert!(error.to_string().contains("AgentInstall"));
    }
}
