//! JSON-RPC 2.0 envelopes, newline-delimited.
//!
//! This module knows nothing about ACP. It is the transport grammar and
//! nothing else: what a request, a notification, a response, and an error
//! object look like on the wire, and how to tell them apart when one arrives.
//! The vocabulary carried inside lives in [`super::acp`].
//!
//! Keeping the two apart is what makes the connection actor readable. A peer
//! that speaks JSON-RPC but not ACP must still receive a well-formed error
//! rather than a parse failure, and that is only possible if the envelope
//! parses independently of the payload.
//!
//! # Why both directions carry requests
//!
//! ACP is bidirectional. The client calls `session/prompt`; the agent calls
//! `session/request_permission` back down the same socket while that prompt is
//! still running. So a frame arriving here may be a request, a notification,
//! *or* a response to something this agent asked — and [`classify`] is where
//! those three are told apart.
//!
//! The identifier and error types come from the ACP schema crate rather than
//! being redefined, so an error code Garrison emits is the same value an ACP
//! client already knows how to interpret.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use agent_client_protocol_schema::v1::{Error as ErrorObject, ErrorCode, RequestId};

/// The only JSON-RPC version this agent speaks.
pub const JSONRPC_VERSION: &str = "2.0";

/// Renders one error object as a line a person can act on.
///
/// JSON-RPC splits an error into a code, a short `message` that is fixed by
/// the code, and a `data` field carrying the part that is specific to this
/// failure. "Invalid params" tells a reader nothing on its own: `data` is
/// where the agent says *which* param and what was wrong with it, so dropping
/// it leaves somebody holding a number.
///
/// Pure, and the single place either client path formats a refusal, so the
/// two cannot drift into saying different amounts about the same error.
#[must_use]
pub fn describe(error: &ErrorObject) -> String {
    let code = i32::from(error.code);
    match error.data.as_ref().and_then(detail) {
        Some(detail) => format!("{} (code {code}): {detail}", error.message),
        None => format!("{} (code {code})", error.message),
    }
}

/// The human-readable part of a `data` field.
///
/// A string is the common case and is taken as-is. Anything else — an object
/// an agent chose to structure — is rendered as JSON rather than discarded,
/// because a reader confronted with `{"root": "/srv"}` still learns more than
/// one shown nothing at all.
fn detail(data: &Value) -> Option<String> {
    match data {
        Value::Null => None,
        Value::String(text) if text.is_empty() => None,
        Value::String(text) => Some(text.clone()),
        other => Some(other.to_string()),
    }
}

/// Error codes Garrison defines on top of ACP's.
///
/// JSON-RPC reserves -32000 to -32099 for implementation-defined server
/// errors. ACP already occupies -32000 (`auth_required`) and -32002
/// (`resource_not_found`) in that range, so Garrison's start at -32010 and
/// leave room between the two.
pub mod error_code {
    /// A method arrived before `initialize` completed.
    pub const NOT_INITIALIZED: i32 = -32010;
    /// The client asked for a protocol version this agent cannot speak.
    pub const UNSUPPORTED_VERSION: i32 = -32011;
    /// The turn could not be run to completion.
    pub const TURN_FAILED: i32 = -32012;
    /// The session already has a turn in flight.
    pub const SESSION_BUSY: i32 = -32013;
}

/// One frame arriving over the socket, classified.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Inbound {
    /// A call expecting exactly one answer.
    Request {
        /// What the answer must be tagged with.
        id: RequestId,
        /// The method being called.
        method: String,
        /// Its parameters, if any.
        params: Option<Value>,
    },
    /// A call expecting no answer.
    Notification {
        /// The method being called.
        method: String,
        /// Its parameters, if any.
        params: Option<Value>,
    },
    /// An answer to something this agent asked the client.
    Response {
        /// The identifier this agent sent the request under.
        id: RequestId,
        /// The result, or the error the client answered with.
        outcome: Result<Value, ErrorObject>,
    },
}

/// A frame that could not be classified, and what to answer with.
///
/// Returned boxed from [`classify`]: an ACP error object carries a code, a
/// message, and an arbitrary JSON payload, which is several times the size of
/// the success value. Paying for that on every well-formed frame — the
/// overwhelming majority — to save an allocation on the rare bad one is the
/// wrong trade.
#[derive(Clone, Debug)]
pub struct Malformed {
    /// The identifier to answer against, if one could be recovered.
    pub id: Option<RequestId>,
    /// The error to send.
    pub error: ErrorObject,
}

/// Sorts one frame into a request, a notification, or a response.
///
/// Pure: no IO, no state, so every branch is testable from a string literal.
///
/// # Errors
///
/// [`Malformed`] with the recovered id when the text is not JSON, is not an
/// object, declares the wrong JSON-RPC version, or is none of the three shapes
/// the specification defines.
pub fn classify(line: &str) -> Result<Inbound, Box<Malformed>> {
    let value: Value = serde_json::from_str(line).map_err(|error| {
        Box::new(Malformed {
            id: None,
            error: ErrorObject::parse_error().data(Value::String(error.to_string())),
        })
    })?;

    let Value::Object(object) = value else {
        return Err(Box::new(Malformed {
            id: None,
            error: ErrorObject::invalid_request().data(Value::String(
                "a JSON-RPC frame must be an object".to_string(),
            )),
        }));
    };

    // Recovered before the version check so a mismatched version is still
    // answered against the client's own identifier.
    let id = object
        .get("id")
        .and_then(|value| serde_json::from_value::<RequestId>(value.clone()).ok());

    if object.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_VERSION) {
        return Err(Box::new(Malformed {
            id,
            error: ErrorObject::invalid_request()
                .data(Value::String(format!("jsonrpc must be {JSONRPC_VERSION}"))),
        }));
    }

    let params = object
        .get("params")
        .cloned()
        .filter(|value| !value.is_null());

    if let Some(method) = object.get("method").and_then(Value::as_str) {
        let method = method.to_string();
        return Ok(match id {
            Some(id) => Inbound::Request { id, method, params },
            None => Inbound::Notification { method, params },
        });
    }

    // `contains_key` rather than a value check: a successful response whose
    // result is literally `null` is well-formed, and reading it as "no result"
    // would strand the caller waiting forever.
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");

    if !has_result && !has_error {
        return Err(Box::new(Malformed {
            id,
            error: ErrorObject::invalid_request().data(Value::String(
                "frame is neither a request, a notification, nor a response".to_string(),
            )),
        }));
    }

    let Some(id) = id else {
        return Err(Box::new(Malformed {
            id: None,
            error: ErrorObject::invalid_request()
                .data(Value::String("a response must carry an id".to_string())),
        }));
    };

    let outcome = if has_error {
        let raw = object.get("error").cloned().unwrap_or(Value::Null);
        match serde_json::from_value::<ErrorObject>(raw) {
            Ok(error) => Err(error),
            Err(error) => Err(ErrorObject::internal_error().data(Value::String(format!(
                "client sent an unreadable error object: {error}"
            )))),
        }
    } else {
        Ok(object.get("result").cloned().unwrap_or(Value::Null))
    };

    Ok(Inbound::Response { id, outcome })
}

/// A successful response to a request.
#[derive(Debug, Clone, Serialize)]
pub struct SuccessResponse {
    /// Always `"2.0"`.
    pub jsonrpc: &'static str,
    /// Echoed from the request.
    pub id: RequestId,
    /// The method's return value.
    pub result: Value,
}

/// A failed response to a request.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    /// Always `"2.0"`.
    pub jsonrpc: &'static str,
    /// Echoed from the request, or null when none could be recovered.
    pub id: Option<RequestId>,
    /// What went wrong.
    pub error: ErrorObject,
}

/// A notification this agent sends: every `session/update` is one.
#[derive(Debug, Clone, Serialize)]
pub struct OutgoingNotification {
    /// Always `"2.0"`.
    pub jsonrpc: &'static str,
    /// The method name.
    pub method: String,
    /// The payload.
    pub params: Value,
}

/// A request this agent sends to the client, expecting an answer.
///
/// `session/request_permission` is the one Garrison uses.
#[derive(Debug, Clone, Serialize)]
pub struct OutgoingRequest {
    /// Always `"2.0"`.
    pub jsonrpc: &'static str,
    /// What the client must tag its answer with.
    pub id: RequestId,
    /// The method name.
    pub method: String,
    /// The payload.
    pub params: Value,
}

impl SuccessResponse {
    /// Builds a success response for `id`.
    #[must_use]
    pub const fn new(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            id,
            result,
        }
    }
}

impl ErrorResponse {
    /// Builds an error response for `id`, which is `None` when the request was
    /// too malformed to recover one.
    #[must_use]
    pub const fn new(id: Option<RequestId>, error: ErrorObject) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            id,
            error,
        }
    }
}

impl OutgoingNotification {
    /// Builds an agent-initiated notification.
    #[must_use]
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            method: method.into(),
            params,
        }
    }
}

impl OutgoingRequest {
    /// Builds an agent-initiated request.
    #[must_use]
    pub fn new(id: RequestId, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            id,
            method: method.into(),
            params,
        }
    }
}

/// Serializes a frame and appends the newline that delimits it.
///
/// Every frame leaving the agent goes through here, so the delimiter is
/// applied in exactly one place.
///
/// # Errors
///
/// Returns the underlying serialization error if `frame` cannot be rendered
/// as JSON.
pub fn to_line<T: Serialize>(frame: &T) -> Result<String, serde_json::Error> {
    let mut line = serde_json::to_string(frame)?;
    line.push('\n');
    Ok(line)
}

/// Reads a typed value out of a method's parameters.
///
/// # Errors
///
/// [`ErrorCode::InvalidParams`] naming what serde objected to.
pub fn params<T>(raw: Option<Value>) -> Result<T, ErrorObject>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(raw.unwrap_or(Value::Null))
        .map_err(|error| ErrorObject::invalid_params().data(Value::String(error.to_string())))
}

/// Renders a method's result, turning a serde failure into a JSON-RPC one.
///
/// # Errors
///
/// [`ErrorCode::InternalError`] when the value will not serialize.
pub fn encode<T: Serialize>(value: &T) -> Result<Value, ErrorObject> {
    serde_json::to_value(value).map_err(|error| {
        ErrorObject::internal_error().data(Value::String(format!("unserializable result: {error}")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_description_carries_the_reason_the_agent_gave() {
        // The refusal a client actually has to act on: "Invalid params"
        // alone names nothing, so the boundary it fell outside must survive.
        let error = ErrorObject::invalid_params().data(Value::String(
            "cannot open a session there: '/srv/other' is outside the approved roots".to_string(),
        ));

        let described = describe(&error);
        assert!(
            described.contains("outside the approved roots"),
            "the reason must survive: {described}"
        );
        assert!(
            described.contains("-32602"),
            "and so must the code: {described}"
        );
    }

    #[test]
    fn a_description_without_data_is_still_readable() {
        let described = describe(&ErrorObject::invalid_params());
        assert!(described.contains("-32602"), "got: {described}");
        assert!(
            !described.ends_with(": "),
            "no empty detail clause: {described}"
        );
    }

    #[test]
    fn a_structured_data_field_is_rendered_rather_than_dropped() {
        // An agent that answers with an object still tells the reader more
        // than one that answers with nothing.
        let error = ErrorObject::invalid_params().data(json!({"root": "/srv"}));
        assert!(describe(&error).contains("/srv"), "{}", describe(&error));
    }

    #[test]
    fn an_empty_data_string_adds_no_clause() {
        let error = ErrorObject::invalid_params().data(Value::String(String::new()));
        assert_eq!(describe(&error), describe(&ErrorObject::invalid_params()));
    }

    #[test]
    fn a_call_with_an_id_is_a_request() {
        let frame = classify(r#"{"jsonrpc":"2.0","id":1,"method":"session/new"}"#).unwrap();

        match frame {
            Inbound::Request { id, method, params } => {
                assert_eq!(id, RequestId::Number(1));
                assert_eq!(method, "session/new");
                assert!(params.is_none());
            }
            other => panic!("expected a request, got {other:?}"),
        }
    }

    #[test]
    fn a_call_without_an_id_is_a_notification() {
        let frame = classify(r#"{"jsonrpc":"2.0","method":"session/cancel"}"#).unwrap();

        assert!(matches!(frame, Inbound::Notification { .. }));
    }

    #[test]
    fn a_frame_with_a_result_is_a_response() {
        let frame =
            classify(r#"{"jsonrpc":"2.0","id":"a","result":{"outcome":{"outcome":"cancelled"}}}"#)
                .unwrap();

        match frame {
            Inbound::Response { id, outcome } => {
                assert_eq!(id, RequestId::Str("a".to_string()));
                assert_eq!(outcome.unwrap()["outcome"]["outcome"], "cancelled");
            }
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn a_null_result_is_still_a_response() {
        // Not "no result": a client answering a request that returns nothing
        // sends exactly this, and reading it as unclassifiable would strand
        // whatever is waiting on the answer.
        let frame = classify(r#"{"jsonrpc":"2.0","id":2,"result":null}"#).unwrap();

        match frame {
            Inbound::Response { outcome, .. } => assert_eq!(outcome.unwrap(), Value::Null),
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn an_error_response_carries_the_error() {
        let frame =
            classify(r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"nope"}}"#)
                .unwrap();

        match frame {
            Inbound::Response { outcome, .. } => {
                let error = outcome.unwrap_err();
                assert_eq!(error.code, ErrorCode::MethodNotFound);
                assert_eq!(error.message, "nope");
            }
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn a_version_mismatch_is_answered_against_the_clients_own_id() {
        let malformed = classify(r#"{"jsonrpc":"1.0","id":7,"method":"initialize"}"#).unwrap_err();

        assert_eq!(malformed.id, Some(RequestId::Number(7)));
        assert_eq!(malformed.error.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn unparseable_text_has_no_id_to_answer_against() {
        let malformed = classify("{not json").unwrap_err();

        assert!(malformed.id.is_none());
        assert_eq!(malformed.error.code, ErrorCode::ParseError);
    }

    #[test]
    fn a_frame_that_is_none_of_the_three_shapes_is_refused() {
        let malformed = classify(r#"{"jsonrpc":"2.0","id":1}"#).unwrap_err();

        assert_eq!(malformed.error.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn a_response_without_an_id_is_refused() {
        let malformed = classify(r#"{"jsonrpc":"2.0","result":{}}"#).unwrap_err();

        assert_eq!(malformed.error.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn a_non_object_frame_is_refused() {
        let malformed = classify("[1,2,3]").unwrap_err();

        assert_eq!(malformed.error.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn a_string_id_survives_the_round_trip_as_a_string() {
        let frame = classify(r#"{"jsonrpc":"2.0","id":"abc","method":"initialize"}"#).unwrap();
        let Inbound::Request { id, .. } = frame else {
            panic!("expected a request");
        };

        let rendered = serde_json::to_string(&SuccessResponse::new(id, json!({}))).unwrap();

        assert!(rendered.contains(r#""id":"abc""#), "{rendered}");
    }

    #[test]
    fn every_frame_leaves_with_exactly_one_trailing_newline() {
        let line = to_line(&OutgoingNotification::new(
            "session/update",
            json!({"text": "hi\nthere"}),
        ))
        .unwrap();

        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1, "{line:?}");
    }

    #[test]
    fn an_outgoing_request_carries_its_id_and_method() {
        let rendered = serde_json::to_string(&OutgoingRequest::new(
            RequestId::Number(4),
            "session/request_permission",
            json!({}),
        ))
        .unwrap();

        assert!(rendered.contains(r#""id":4"#), "{rendered}");
        assert!(
            rendered.contains(r#""method":"session/request_permission""#),
            "{rendered}"
        );
    }

    #[test]
    fn an_unparseable_frame_reports_a_null_id() {
        let rendered =
            serde_json::to_string(&ErrorResponse::new(None, ErrorObject::parse_error())).unwrap();

        assert!(rendered.contains(r#""id":null"#), "{rendered}");
    }

    #[test]
    fn missing_parameters_are_reported_as_invalid_params() {
        #[derive(Debug, Deserialize)]
        struct Needed {
            _wanted: String,
        }

        let error = params::<Needed>(None).unwrap_err();

        assert_eq!(error.code, ErrorCode::InvalidParams);
    }

    #[test]
    fn garrisons_codes_avoid_the_ones_acp_already_uses() {
        for code in [
            error_code::NOT_INITIALIZED,
            error_code::UNSUPPORTED_VERSION,
            error_code::TURN_FAILED,
            error_code::SESSION_BUSY,
        ] {
            assert!((-32099..=-32000).contains(&code), "{code} is out of range");
            assert!(
                matches!(ErrorCode::from(code), ErrorCode::Other(_)),
                "{code} collides with an ACP code",
            );
        }
    }
}
