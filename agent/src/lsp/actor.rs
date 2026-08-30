//! One language server, one owning actor.
//!
//! The actor owns everything about a connection that changes: the writer, the
//! request-id counter, the map of in-flight requests to the callers waiting
//! on them, which documents are open at which version, and the diagnostics
//! the server has volunteered. A reader task ([`super::connection::pump`])
//! turns the server's stdout into [`ServerMessage`]s; nothing else touches
//! the transport.
//!
//! # Split-phase initialization
//!
//! LSP opens with an `initialize` request the client must not follow with
//! anything else until the response arrives. That response arrives as a
//! [`ServerMessage`] on this actor's own mailbox — so no handler may await
//! it inline, or the actor would wait forever on a message behind it in the
//! queue. Instead the phase lives in the model: requests that arrive while
//! [`Phase::Starting`] are parked and drained the moment the handshake
//! completes, and [`WaitReady`] askers are answered the same way.
//!
//! # Writes
//!
//! Frames are written inside `mutate_on` pending futures, which acton-reactive
//! awaits inline, one at a time — so the mutex around the writer is
//! uncontended by construction and exists only because a future cannot borrow
//! the model it was built from.

use super::framing;
// The type every handler returns. acton-reactive names it FutureBox internally
// but does not export it; `Reply::ready()` / `Reply::pending()` both coerce.
type FutureBox = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync + 'static>>;
use acton_reactive::prelude::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWrite;

/// The writer half of a connection, shareable into pending futures.
#[derive(Clone)]
pub struct SharedWriter(Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Sync + Unpin>>>);

impl SharedWriter {
    /// Wraps a transport's write half.
    pub fn new(writer: Box<dyn AsyncWrite + Send + Sync + Unpin>) -> Self {
        Self(Arc::new(tokio::sync::Mutex::new(writer)))
    }

    /// Writes one framed message, reporting only whether it landed.
    async fn write(&self, body: Vec<u8>) -> Result<(), String> {
        let mut writer = self.0.lock().await;
        framing::write_frame(&mut *writer, &body)
            .await
            .map_err(|error| format!("write to language server failed: {error}"))
    }
}

impl std::fmt::Debug for SharedWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedWriter")
    }
}

/// Where the connection is in its life.
#[derive(Debug, Default)]
enum Phase {
    /// `initialize` is in flight; work is parked.
    #[default]
    Starting,
    /// The handshake completed; requests flow.
    Ready,
    /// The transport died or the handshake failed. Terminal.
    Failed(String),
}

/// Tells the actor to open the LSP handshake.
#[acton_message]
pub struct Initialize {
    /// The workspace root, as a `file://` URI.
    pub root_uri: String,
}

/// A parsed frame from the server, delivered by the reader task.
#[acton_message]
pub struct ServerMessage(pub Value);

/// The reader task saw the transport end.
#[acton_message]
pub struct ServerGone {
    /// What ended it, for the error shown to callers.
    pub reason: String,
}

/// Asks whether the server finished its handshake, parking until it has.
#[acton_message]
pub struct WaitReady;

/// The answer to [`WaitReady`].
#[acton_message]
pub struct ReadyState {
    /// Handshake done and transport alive.
    pub ready: bool,
    /// Why not, when it never will be.
    pub failed: Option<String>,
    /// Whether the server negotiated UTF-8 position encoding.
    pub utf8_positions: bool,
}

impl Request for WaitReady {
    type Response = ReadyState;
}

/// A raw LSP request on the caller's behalf.
#[acton_message]
pub struct SendRequest {
    /// The LSP method, e.g. `textDocument/hover`.
    pub method: String,
    /// Its params, already in LSP shape.
    pub params: Value,
}

/// The result of any ask that reaches the server.
#[acton_message]
pub struct LspOutcome {
    /// The server's `result`, or what went wrong.
    pub result: Result<Value, String>,
}

impl Request for SendRequest {
    type Response = LspOutcome;
}

/// Pushes a document's current content to the server.
///
/// `didOpen` the first time, `didChange` with full text after; the version
/// counter lives here so callers cannot misnumber it. Answered once the
/// notification is written, which is what lets a caller `ask` this as a
/// barrier before requesting diagnostics.
#[acton_message]
pub struct SyncDocument {
    /// The document, as a `file://` URI.
    pub uri: String,
    /// A language identifier the server recognizes, e.g. `rust`.
    pub language_id: String,
    /// The document's entire current text.
    pub content: String,
}

impl Request for SyncDocument {
    type Response = LspOutcome;
}

/// Asks for a document's diagnostics.
///
/// Pull (`textDocument/diagnostic`) when the server advertised it; otherwise
/// parks until the server's next `publishDiagnostics` for the document. A
/// server that never publishes leaves the caller to its ask timeout — parking
/// cannot be told apart from a slow computation from in here.
#[acton_message]
pub struct AwaitDiagnostics {
    /// The document, as a `file://` URI.
    pub uri: String,
}

impl Request for AwaitDiagnostics {
    type Response = LspOutcome;
}

/// One language server connection.
#[acton_actor]
pub struct LspServer {
    /// The connection's write half; `None` until wired, gone after failure.
    writer: Option<SharedWriter>,
    /// The child process, held so it lives exactly as long as its actor.
    child: Option<tokio::process::Child>,
    phase: Phase,
    /// The id `initialize` went out under.
    init_id: Option<i64>,
    next_id: i64,
    /// In-flight requests, by id, each holding its caller's envelope.
    pending: HashMap<i64, OutboundEnvelope>,
    /// Requests that arrived during the handshake.
    parked: Vec<(SendRequest, OutboundEnvelope)>,
    /// [`WaitReady`] askers parked during the handshake.
    ready_waiters: Vec<OutboundEnvelope>,
    /// Open documents and their version counters.
    open_docs: HashMap<String, i32>,
    /// Callers waiting on the next `publishDiagnostics` per URI.
    diagnostic_waiters: HashMap<String, Vec<OutboundEnvelope>>,
    /// Whether the server advertised pull diagnostics.
    pull_diagnostics: bool,
    /// Whether the server negotiated UTF-8 positions.
    utf8_positions: bool,
    /// The configured name, for log lines.
    name: String,
}

impl LspServer {
    /// Creates the actor, wired to a transport but not yet started.
    ///
    /// The caller starts it, hands the read half to
    /// [`super::connection::pump`], and sends [`Initialize`].
    pub async fn spawn(
        runtime: &mut ActorRuntime,
        name: String,
        writer: SharedWriter,
        child: Option<tokio::process::Child>,
    ) -> ActorHandle {
        let mut builder = runtime.new_actor_with_name::<Self>(format!("lsp_{name}"));
        builder.model.name = name;
        builder.model.writer = Some(writer);
        builder.model.child = child;
        configure_handlers(&mut builder);
        builder.start().await
    }

    fn allocate(&mut self) -> i64 {
        self.next_id += 1;
        self.next_id
    }
}

/// Wires every handler.
fn configure_handlers(builder: &mut ManagedActor<Idle, LspServer>) {
    builder.mutate_on::<Initialize>(|actor, envelope| {
        let id = actor.model.allocate();
        actor.model.init_id = Some(id);
        let body = request(
            id,
            "initialize",
            initialize_params(&envelope.message().root_uri),
        );
        write_or_fail(actor, body)
    });

    builder.mutate_on::<ServerMessage>(|actor, envelope| {
        dispatch_server_message(actor, envelope.message().0.clone())
    });

    builder.mutate_on::<WaitReady>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let state = match &actor.model.phase {
            Phase::Starting => {
                actor.model.ready_waiters.push(reply);
                return Reply::ready();
            }
            Phase::Ready => ReadyState {
                ready: true,
                failed: None,
                utf8_positions: actor.model.utf8_positions,
            },
            Phase::Failed(reason) => ReadyState {
                ready: false,
                failed: Some(reason.clone()),
                utf8_positions: false,
            },
        };
        Reply::pending(async move {
            reply.send(state).await;
        })
    });

    builder.mutate_on::<SendRequest>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let message = envelope.message().clone();
        match &actor.model.phase {
            Phase::Starting => {
                actor.model.parked.push((message, reply));
                Reply::ready()
            }
            Phase::Failed(reason) => answer_failure(reply, reason.clone()),
            Phase::Ready => {
                let id = actor.model.allocate();
                actor.model.pending.insert(id, reply);
                let body = request(id, &message.method, message.params);
                write_or_fail(actor, body)
            }
        }
    });

    builder.mutate_on::<SyncDocument>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let message = envelope.message().clone();
        if let Phase::Failed(reason) = &actor.model.phase {
            return answer_failure(reply, reason.clone());
        }
        let body = match actor.model.open_docs.get_mut(&message.uri) {
            Some(version) => {
                *version += 1;
                notification(
                    "textDocument/didChange",
                    json!({
                        "textDocument": { "uri": message.uri, "version": *version },
                        "contentChanges": [{ "text": message.content }],
                    }),
                )
            }
            None => {
                actor.model.open_docs.insert(message.uri.clone(), 1);
                notification(
                    "textDocument/didOpen",
                    json!({
                        "textDocument": {
                            "uri": message.uri,
                            "languageId": message.language_id,
                            "version": 1,
                            "text": message.content,
                        },
                    }),
                )
            }
        };
        let Some(writer) = actor.model.writer.clone() else {
            return answer_failure(reply, "language server has no transport".to_string());
        };
        Reply::pending(async move {
            let result = writer.write(body).await.map(|()| Value::Null);
            reply.send(LspOutcome { result }).await;
        })
    });

    builder.mutate_on::<AwaitDiagnostics>(|actor, envelope| {
        let reply = envelope.reply_envelope();
        let uri = envelope.message().uri.clone();
        match &actor.model.phase {
            Phase::Failed(reason) => answer_failure(reply, reason.clone()),
            _ if actor.model.pull_diagnostics => {
                let id = actor.model.allocate();
                actor.model.pending.insert(id, reply);
                let body = request(
                    id,
                    "textDocument/diagnostic",
                    json!({ "textDocument": { "uri": uri } }),
                );
                write_or_fail(actor, body)
            }
            _ => {
                actor
                    .model
                    .diagnostic_waiters
                    .entry(uri)
                    .or_default()
                    .push(reply);
                Reply::ready()
            }
        }
    });

    builder.mutate_on::<ServerGone>(|actor, envelope| {
        let reason = envelope.message().reason.clone();
        tracing::warn!(server = %actor.model.name, %reason, "language server connection ended");
        actor.model.phase = Phase::Failed(reason.clone());
        actor.model.writer = None;

        let mut owed: Vec<OutboundEnvelope> = Vec::new();
        owed.extend(actor.model.pending.drain().map(|(_, envelope)| envelope));
        owed.extend(actor.model.parked.drain(..).map(|(_, envelope)| envelope));
        owed.extend(
            actor
                .model
                .diagnostic_waiters
                .drain()
                .flat_map(|(_, waiters)| waiters),
        );
        let ready_waiters: Vec<OutboundEnvelope> = std::mem::take(&mut actor.model.ready_waiters);

        Reply::pending(async move {
            for envelope in owed {
                envelope
                    .send(LspOutcome {
                        result: Err(format!("language server exited: {reason}")),
                    })
                    .await;
            }
            for envelope in ready_waiters {
                envelope
                    .send(ReadyState {
                        ready: false,
                        failed: Some(reason.clone()),
                        utf8_positions: false,
                    })
                    .await;
            }
        })
    });
}

/// Routes one frame from the server to whatever is waiting on it.
fn dispatch_server_message(
    actor: &mut ManagedActor<Started, LspServer>,
    message: Value,
) -> FutureBox {
    match classify(&message) {
        Incoming::Response { id, result } => {
            if actor.model.init_id == Some(id) {
                return complete_handshake(actor, result);
            }
            let Some(reply) = actor.model.pending.remove(&id) else {
                return Reply::ready();
            };
            Reply::pending(async move {
                reply.send(LspOutcome { result }).await;
            })
        }
        Incoming::Request { id, method, params } => {
            let body = match answer_server_request(&method, &params) {
                Ok(result) => response(id, result),
                Err((code, text)) => error_response(id, code, &text),
            };
            write_only(actor, body)
        }
        Incoming::Notification { method, params } => {
            if method == "textDocument/publishDiagnostics" {
                return deliver_published_diagnostics(actor, params);
            }
            Reply::ready()
        }
        Incoming::Unintelligible => Reply::ready(),
    }
}

/// Finishes `initialize`: reads capabilities, confirms, drains parked work.
fn complete_handshake(
    actor: &mut ManagedActor<Started, LspServer>,
    result: Result<Value, String>,
) -> FutureBox {
    let capabilities = match result {
        Ok(value) => value,
        Err(reason) => {
            let reason = format!("initialize failed: {reason}");
            actor.model.phase = Phase::Failed(reason.clone());
            let waiters: Vec<OutboundEnvelope> = std::mem::take(&mut actor.model.ready_waiters);
            return Reply::pending(async move {
                for envelope in waiters {
                    envelope
                        .send(ReadyState {
                            ready: false,
                            failed: Some(reason.clone()),
                            utf8_positions: false,
                        })
                        .await;
                }
            });
        }
    };

    let server = &capabilities["capabilities"];
    actor.model.pull_diagnostics = !server["diagnosticProvider"].is_null();
    actor.model.utf8_positions = server["positionEncoding"] == json!("utf-8");
    actor.model.phase = Phase::Ready;
    tracing::info!(
        server = %actor.model.name,
        pull_diagnostics = actor.model.pull_diagnostics,
        utf8_positions = actor.model.utf8_positions,
        "language server ready"
    );

    let utf8_positions = actor.model.utf8_positions;
    let waiters: Vec<OutboundEnvelope> = std::mem::take(&mut actor.model.ready_waiters);
    let parked: Vec<(SendRequest, OutboundEnvelope)> = std::mem::take(&mut actor.model.parked);
    let mut frames = vec![notification("initialized", json!({}))];
    for (message, reply) in parked {
        let id = actor.model.allocate();
        actor.model.pending.insert(id, reply);
        frames.push(request(id, &message.method, message.params));
    }

    let Some(writer) = actor.model.writer.clone() else {
        return Reply::ready();
    };
    Reply::pending(async move {
        for envelope in waiters {
            envelope
                .send(ReadyState {
                    ready: true,
                    failed: None,
                    utf8_positions,
                })
                .await;
        }
        for frame in frames {
            if writer.write(frame).await.is_err() {
                // The reader task will see the same death and report it;
                // nothing useful to add from here.
                return;
            }
        }
    })
}

/// Answers everyone parked on a document's diagnostics.
fn deliver_published_diagnostics(
    actor: &mut ManagedActor<Started, LspServer>,
    params: Value,
) -> FutureBox {
    let Some(uri) = params["uri"].as_str() else {
        return Reply::ready();
    };
    let Some(waiters) = actor.model.diagnostic_waiters.remove(uri) else {
        return Reply::ready();
    };
    Reply::pending(async move {
        for envelope in waiters {
            envelope
                .send(LspOutcome {
                    result: Ok(params.clone()),
                })
                .await;
        }
    })
}

/// What one frame from the server turned out to be.
#[derive(Debug, PartialEq)]
enum Incoming {
    /// An answer to something this client asked.
    Response {
        id: i64,
        result: Result<Value, String>,
    },
    /// The server asking the client for something.
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    /// The server volunteering something.
    Notification { method: String, params: Value },
    /// Not JSON-RPC as this client knows it.
    Unintelligible,
}

/// Tells responses, requests, and notifications apart. Pure.
fn classify(message: &Value) -> Incoming {
    let method = message.get("method").and_then(Value::as_str);
    let id = message.get("id");
    match (method, id) {
        (Some(method), Some(id)) => Incoming::Request {
            id: id.clone(),
            method: method.to_string(),
            params: message.get("params").cloned().unwrap_or(Value::Null),
        },
        (Some(method), None) => Incoming::Notification {
            method: method.to_string(),
            params: message.get("params").cloned().unwrap_or(Value::Null),
        },
        (None, Some(id)) => {
            let Some(id) = id.as_i64() else {
                return Incoming::Unintelligible;
            };
            let result = if let Some(error) = message.get("error") {
                let text = error["message"].as_str().unwrap_or("unspecified error");
                let code = error["code"].as_i64().unwrap_or(0);
                Err(format!("{text} (code {code})"))
            } else {
                Ok(message.get("result").cloned().unwrap_or(Value::Null))
            };
            Incoming::Response { id, result }
        }
        (None, None) => Incoming::Unintelligible,
    }
}

/// The client's answer to a server-to-client request. Pure.
///
/// A server stalls politely when a request goes unanswered, so everything
/// gets *an* answer: the two requests that need a specific shape get it, and
/// the rest get method-not-found, which every server treats as "the client
/// doesn't do that" rather than a failure.
fn answer_server_request(method: &str, params: &Value) -> Result<Value, (i64, String)> {
    match method {
        "workspace/configuration" => {
            let count = params["items"].as_array().map_or(0, Vec::len);
            Ok(Value::Array(vec![Value::Null; count]))
        }
        "window/workDoneProgress/create" => Ok(Value::Null),
        "client/registerCapability" | "client/unregisterCapability" => Ok(Value::Null),
        other => Err((-32601, format!("client does not implement {other}"))),
    }
}

/// The capabilities this client claims at `initialize`. Pure.
///
/// Deliberately narrow: only what the four tools use, plus UTF-8 position
/// encoding first in the preference list so servers that can count bytes do.
fn initialize_params(root_uri: &str) -> Value {
    json!({
        "processId": std::process::id(),
        "rootUri": root_uri,
        "workspaceFolders": [{ "uri": root_uri, "name": "workspace" }],
        "capabilities": {
            "general": { "positionEncodings": ["utf-8", "utf-16"] },
            "textDocument": {
                "synchronization": { "didSave": false },
                "publishDiagnostics": {},
                "diagnostic": {},
                "hover": { "contentFormat": ["markdown", "plaintext"] },
                "definition": {},
                "references": {},
            },
        },
    })
}

/// Frames a request. Pure.
fn request(id: i64, method: &str, params: Value) -> Vec<u8> {
    body(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
}

/// Frames a notification. Pure.
fn notification(method: &str, params: Value) -> Vec<u8> {
    body(json!({ "jsonrpc": "2.0", "method": method, "params": params }))
}

/// Frames a successful response to a server-to-client request. Pure.
fn response(id: Value, result: Value) -> Vec<u8> {
    body(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

/// Frames an error response to a server-to-client request. Pure.
fn error_response(id: Value, code: i64, message: &str) -> Vec<u8> {
    body(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }))
}

fn body(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap_or_default()
}

/// A write with a caller waiting on the eventual response — the write's own
/// failure is not reported here because the reader task will observe the
/// death and [`ServerGone`] fails every pending caller at once.
fn write_or_fail(actor: &mut ManagedActor<Started, LspServer>, body: Vec<u8>) -> FutureBox {
    write_only(actor, body)
}

/// A write nobody is waiting on directly.
fn write_only(actor: &mut ManagedActor<Started, LspServer>, body: Vec<u8>) -> FutureBox {
    let Some(writer) = actor.model.writer.clone() else {
        return Reply::ready();
    };
    Reply::pending(async move {
        let _ = writer.write(body).await;
    })
}

/// Answers a caller whose request can never reach the server.
fn answer_failure(reply: OutboundEnvelope, reason: String) -> FutureBox {
    Reply::pending(async move {
        reply
            .send(LspOutcome {
                result: Err(format!("language server unavailable: {reason}")),
            })
            .await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_response_is_classified_with_its_result() {
        let classified = classify(&json!({ "jsonrpc": "2.0", "id": 3, "result": { "x": 1 } }));
        assert_eq!(
            classified,
            Incoming::Response {
                id: 3,
                result: Ok(json!({ "x": 1 })),
            }
        );
    }

    #[test]
    fn an_error_response_carries_the_message_and_code() {
        let classified = classify(
            &json!({ "jsonrpc": "2.0", "id": 7, "error": { "code": -32601, "message": "nope" } }),
        );
        let Incoming::Response { id, result } = classified else {
            panic!("must classify as a response");
        };
        assert_eq!(id, 7);
        assert_eq!(result, Err("nope (code -32601)".to_string()));
    }

    #[test]
    fn a_server_request_and_a_notification_are_told_apart() {
        assert!(matches!(
            classify(&json!({ "jsonrpc": "2.0", "id": 1, "method": "workspace/configuration" })),
            Incoming::Request { .. }
        ));
        assert!(matches!(
            classify(&json!({ "jsonrpc": "2.0", "method": "$/progress", "params": {} })),
            Incoming::Notification { .. }
        ));
    }

    #[test]
    fn workspace_configuration_is_answered_with_one_null_per_item() {
        let answer =
            answer_server_request("workspace/configuration", &json!({ "items": [{}, {}, {}] }))
                .expect("must answer");
        assert_eq!(answer, json!([null, null, null]));
    }

    #[test]
    fn unknown_server_requests_get_method_not_found() {
        let (code, _) = answer_server_request("window/showMessageRequest", &Value::Null)
            .expect_err("must refuse");
        assert_eq!(code, -32601);
    }

    #[test]
    fn initialize_prefers_utf8_positions() {
        let params = initialize_params("file:///tmp/x");
        assert_eq!(
            params["capabilities"]["general"]["positionEncodings"][0],
            json!("utf-8")
        );
    }
}
