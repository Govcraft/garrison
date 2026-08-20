//! The LSP actor against a scripted language server.
//!
//! Every test drives the real actor, the real framing, and the real reader
//! task over an in-memory duplex; only the language server on the far end is
//! scripted. Synchronization is entirely by `ask` — a reply proves the
//! request cycle completed — with no sleeps anywhere.

use acton_reactive::prelude::*;
use garrison_agent::lsp::actor::{
    AwaitDiagnostics, Initialize, LspOutcome, LspServer, ReadyState, SendRequest, SharedWriter,
    SyncDocument, WaitReady,
};
use garrison_agent::lsp::connection::pump;
use garrison_agent::lsp::framing;
use serde_json::{json, Value};
use tokio::io::{ReadHalf, WriteHalf};

/// The scripted server's end of the wire.
struct Script {
    reader: ReadHalf<tokio::io::DuplexStream>,
    writer: WriteHalf<tokio::io::DuplexStream>,
}

impl Script {
    /// Reads one frame the client sent.
    async fn recv(&mut self) -> Value {
        let body = framing::read_frame(&mut self.reader)
            .await
            .expect("the scripted server must read")
            .expect("the client must not close first");
        serde_json::from_slice(&body).expect("the client must write JSON")
    }

    /// Sends one frame to the client.
    async fn send(&mut self, message: Value) {
        let body = serde_json::to_vec(&message).expect("must serialize");
        framing::write_frame(&mut self.writer, &body)
            .await
            .expect("the scripted server must write");
    }

    /// Plays the `initialize` exchange, advertising the given capabilities.
    async fn handshake(&mut self, capabilities: Value) {
        let initialize = self.recv().await;
        assert_eq!(initialize["method"], "initialize");
        assert_eq!(
            initialize["params"]["capabilities"]["general"]["positionEncodings"][0], "utf-8",
            "the client must prefer utf-8 positions",
        );
        self.send(json!({
            "jsonrpc": "2.0",
            "id": initialize["id"],
            "result": { "capabilities": capabilities },
        }))
        .await;
        let initialized = self.recv().await;
        assert_eq!(initialized["method"], "initialized");
    }
}

/// Brings up the actor and its pump over a duplex, returning both ends.
async fn connect(runtime: &mut ActorRuntime) -> (ActorHandle, Script) {
    let (agent_side, server_side) = tokio::io::duplex(64 * 1024);
    let (agent_read, agent_write) = tokio::io::split(agent_side);
    let (server_read, server_write) = tokio::io::split(server_side);

    let handle = LspServer::spawn(
        runtime,
        "scripted".to_string(),
        SharedWriter::new(Box::new(agent_write)),
        None,
    )
    .await;
    pump(Box::new(agent_read), handle.clone());
    handle
        .send(Initialize {
            root_uri: "file:///work".to_string(),
        })
        .await;

    (
        handle,
        Script {
            reader: server_read,
            writer: server_write,
        },
    )
}

#[tokio::test]
async fn the_handshake_completes_and_hover_round_trips() {
    let mut runtime = ActonApp::launch_async().await;
    let (handle, mut script) = connect(&mut runtime).await;

    let server = tokio::spawn(async move {
        script
            .handshake(json!({ "positionEncoding": "utf-8", "hoverProvider": true }))
            .await;
        let open = script.recv().await;
        assert_eq!(open["method"], "textDocument/didOpen");
        assert_eq!(open["params"]["textDocument"]["version"], 1);
        let hover = script.recv().await;
        assert_eq!(hover["method"], "textDocument/hover");
        script
            .send(json!({
                "jsonrpc": "2.0",
                "id": hover["id"],
                "result": { "contents": { "kind": "markdown", "value": "fn main()" } },
            }))
            .await;
        script
    });

    let ready: ReadyState = handle.ask(WaitReady).await.expect("must become ready");
    assert!(ready.ready);
    assert!(ready.utf8_positions);

    let synced: LspOutcome = handle
        .ask(SyncDocument {
            uri: "file:///work/src/main.rs".to_string(),
            language_id: "rust".to_string(),
            content: "fn main() {}\n".to_string(),
        })
        .await
        .expect("sync must be answered");
    synced.result.expect("sync must succeed");

    let outcome: LspOutcome = handle
        .ask(SendRequest {
            method: "textDocument/hover".to_string(),
            params: json!({
                "textDocument": { "uri": "file:///work/src/main.rs" },
                "position": { "line": 0, "character": 3 },
            }),
        })
        .await
        .expect("hover must be answered");
    let answer = outcome.result.expect("hover must succeed");
    assert_eq!(answer["contents"]["value"], "fn main()");

    server.await.expect("the scripted server must finish");
    runtime.shutdown_all().await.expect("shutdown");
}

#[tokio::test]
async fn requests_sent_during_the_handshake_are_parked_then_served() {
    let mut runtime = ActonApp::launch_async().await;
    let (handle, mut script) = connect(&mut runtime).await;

    // Ask before the server has answered `initialize`. The reply can only
    // arrive if the actor parks it and drains it after the handshake.
    let early = {
        let handle = handle.clone();
        tokio::spawn(async move {
            handle
                .ask(SendRequest {
                    method: "textDocument/definition".to_string(),
                    params: json!({}),
                })
                .await
        })
    };

    script.handshake(json!({})).await;
    let definition = script.recv().await;
    assert_eq!(definition["method"], "textDocument/definition");
    script
        .send(json!({ "jsonrpc": "2.0", "id": definition["id"], "result": [] }))
        .await;

    let outcome: LspOutcome = early
        .await
        .expect("the early ask task must finish")
        .expect("the early ask must be answered");
    assert_eq!(outcome.result.expect("must succeed"), json!([]));
    runtime.shutdown_all().await.expect("shutdown");
}

#[tokio::test]
async fn diagnostics_pull_when_the_server_advertises_it() {
    let mut runtime = ActonApp::launch_async().await;
    let (handle, mut script) = connect(&mut runtime).await;

    let server = tokio::spawn(async move {
        script.handshake(json!({ "diagnosticProvider": {} })).await;
        let pull = script.recv().await;
        assert_eq!(pull["method"], "textDocument/diagnostic");
        script
            .send(json!({
                "jsonrpc": "2.0",
                "id": pull["id"],
                "result": { "kind": "full", "items": [{ "message": "boom",
                    "range": { "start": { "line": 0, "character": 0 },
                                "end": { "line": 0, "character": 1 } } }] },
            }))
            .await;
    });

    let ready: ReadyState = handle.ask(WaitReady).await.expect("must become ready");
    assert!(ready.ready);
    let outcome: LspOutcome = handle
        .ask(AwaitDiagnostics {
            uri: "file:///work/src/main.rs".to_string(),
        })
        .await
        .expect("diagnostics must be answered");
    let answer = outcome.result.expect("must succeed");
    assert_eq!(answer["items"][0]["message"], "boom");

    server.await.expect("the scripted server must finish");
    runtime.shutdown_all().await.expect("shutdown");
}

#[tokio::test]
async fn diagnostics_fall_back_to_publish_when_pull_is_absent() {
    let mut runtime = ActonApp::launch_async().await;
    let (handle, mut script) = connect(&mut runtime).await;

    script.handshake(json!({})).await;
    let ready: ReadyState = handle.ask(WaitReady).await.expect("must become ready");
    assert!(ready.ready);

    let waiting = {
        let handle = handle.clone();
        tokio::spawn(async move {
            handle
                .ask(AwaitDiagnostics {
                    uri: "file:///work/src/lib.rs".to_string(),
                })
                .await
        })
    };

    // A publish for a different document must not answer the waiter; the
    // right one must.
    script
        .send(json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": { "uri": "file:///work/other.rs", "diagnostics": [] },
        }))
        .await;
    script
        .send(json!({
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": { "uri": "file:///work/src/lib.rs",
                        "diagnostics": [{ "message": "unused import",
                            "range": { "start": { "line": 2, "character": 0 },
                                        "end": { "line": 2, "character": 5 } } }] },
        }))
        .await;

    let outcome: LspOutcome = waiting
        .await
        .expect("the waiting task must finish")
        .expect("diagnostics must be answered");
    let answer = outcome.result.expect("must succeed");
    assert_eq!(answer["diagnostics"][0]["message"], "unused import");
    runtime.shutdown_all().await.expect("shutdown");
}

#[tokio::test]
async fn a_server_to_client_request_is_answered() {
    let mut runtime = ActonApp::launch_async().await;
    let (handle, mut script) = connect(&mut runtime).await;

    script.handshake(json!({})).await;
    let ready: ReadyState = handle.ask(WaitReady).await.expect("must become ready");
    assert!(ready.ready);

    script
        .send(json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "workspace/configuration",
            "params": { "items": [{}, {}] },
        }))
        .await;
    let answer = script.recv().await;
    assert_eq!(answer["id"], 99);
    assert_eq!(answer["result"], json!([null, null]));
    runtime.shutdown_all().await.expect("shutdown");
}

#[tokio::test]
async fn a_dead_server_fails_pending_and_future_callers() {
    let mut runtime = ActonApp::launch_async().await;
    let (handle, mut script) = connect(&mut runtime).await;

    script.handshake(json!({})).await;
    let ready: ReadyState = handle.ask(WaitReady).await.expect("must become ready");
    assert!(ready.ready);

    let in_flight = {
        let handle = handle.clone();
        tokio::spawn(async move {
            handle
                .ask(SendRequest {
                    method: "textDocument/hover".to_string(),
                    params: json!({}),
                })
                .await
        })
    };
    // The request must be on the wire before the death, or it would be
    // parked nowhere.
    let hover = script.recv().await;
    assert_eq!(hover["method"], "textDocument/hover");
    drop(script);

    let outcome: LspOutcome = in_flight
        .await
        .expect("the in-flight task must finish")
        .expect("the in-flight ask must be answered");
    assert!(
        outcome.result.is_err(),
        "the pending caller must see the death"
    );

    let late: LspOutcome = handle
        .ask(SendRequest {
            method: "textDocument/hover".to_string(),
            params: json!({}),
        })
        .await
        .expect("a late ask must still be answered");
    assert!(late.result.is_err(), "a late caller must see the death");

    let ready: ReadyState = handle.ask(WaitReady).await.expect("must be answered");
    assert!(!ready.ready);
    assert!(ready.failed.is_some());
    runtime.shutdown_all().await.expect("shutdown");
}
