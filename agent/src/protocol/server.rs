//! The listener, and the actor that owns it.
//!
//! # Why the accept loop is a task, not a hook
//!
//! acton-reactive's `after_start` hook is awaited to completion *before* the
//! actor's message loop begins. An accept loop installed there would therefore
//! never return, and the server actor would never process a single message —
//! including the one telling it to stop.
//!
//! So the loop runs as a plain `tokio::spawn`ed task, owned by the actor
//! through a [`CancellationToken`] that `before_stop` cancels. That is not a
//! detached spawn: the task has an owner, a lifetime bounded by the actor's,
//! and a shutdown path.
//!
//! # What accepting a connection does
//!
//! Three things, in this order, and the order matters:
//!
//! 1. Split the socket and start the **writer** task, so an event has
//!    somewhere to go before anything can produce one.
//! 2. Spawn the [`ClientConn`] actor around that sink.
//! 3. Start the **reader** task, which is the only thing that can put a frame
//!    into the actor.
//!
//! When the reader ends — the client hung up, the socket failed, a frame was
//! oversized — it stops the connection actor. Stopping drops the actor's
//! model, which drops every suspended approval envelope it held, which
//! releases every tool call parked on this client as `NoReply`. A disconnected
//! client cannot leave a thread waiting.

use crate::error::GarrisonError;
use crate::protocol::acp::{self, AgentCapabilities};
use crate::protocol::codec::{self, EventSink, FrameError};
use crate::protocol::conn::{ClientConn, ConnSetup, Incoming, ThreadDefaults};
use crate::protocol::jsonrpc;
use crate::protocol::transport::{Connection, Listener};
use crate::types::ClientId;
use acton_ai::facade::ActonAI;
use acton_reactive::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Everything the server hands to each connection it accepts.
#[derive(Clone, Debug)]
pub struct ServerSetup {
    /// The session supervisor.
    pub supervisor: ActorHandle,
    /// The acton-ai runtime turns run on.
    pub runtime: ActonAI,
    /// The turn router.
    pub router: ActorHandle,
    /// What new sessions inherit.
    pub defaults: ThreadDefaults,
    /// What this agent advertises at `initialize`.
    pub capabilities: AgentCapabilities,
    /// Whether the runtime is recording tool calls.
    pub audited: bool,
    /// What isolation the runtime's writing tools run under.
    pub sandbox: acp::SandboxStatus,
    /// Every actor that contributes a part to `_garrison/status`.
    pub describers: Vec<ActorHandle>,
}

/// Owns the listener and the accept loop.
#[acton_actor]
pub struct ProtocolServer {
    endpoint: String,
    accepting: Option<CancellationToken>,
}

impl ProtocolServer {
    /// The address the server is listening on, for logs and smoke clients.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

/// Starts the server: binds nothing, but takes ownership of a bound listener.
///
/// Taking the listener rather than a path keeps this testable over a pair of
/// in-memory sockets, and keeps the choice of transport — Unix socket today,
/// a named pipe on Windows tomorrow — out of the server entirely.
pub async fn serve(
    runtime: &mut ActorRuntime,
    listener: Box<dyn Listener>,
    setup: ServerSetup,
) -> Result<ActorHandle, GarrisonError> {
    let endpoint = listener.endpoint();
    let cancel = CancellationToken::new();

    let mut builder = runtime.new_actor_with_name::<ProtocolServer>("protocol_server".to_string());
    builder.model.endpoint = endpoint.clone();
    builder.model.accepting = Some(cancel.clone());

    builder.before_stop(|actor| {
        let cancel = actor.model.accepting.clone();
        async move {
            if let Some(cancel) = cancel {
                cancel.cancel();
            }
        }
    });

    let handle = builder.start().await;

    // Spawned *after* `start`, so the actor exists to be stopped if the loop
    // fails immediately.
    let accept_runtime = runtime.clone();
    tokio::spawn(accept_loop(accept_runtime, listener, setup, cancel));

    tracing::info!(%endpoint, "garrison agent protocol listening");
    Ok(handle)
}

/// Accepts connections until cancelled.
async fn accept_loop(
    mut runtime: ActorRuntime,
    mut listener: Box<dyn Listener>,
    setup: ServerSetup,
    cancel: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            () = cancel.cancelled() => return,
            accepted = listener.accept() => accepted,
        };

        match accepted {
            Ok(connection) => {
                accept(&mut runtime, connection, setup.clone(), cancel.clone()).await;
            }
            Err(error) => {
                // One failed accept is not a reason to stop serving everybody
                // else; a listener that fails permanently will simply fail
                // again on the next pass, which the log makes visible.
                tracing::warn!(%error, "accept failed");
            }
        }
    }
}

/// Wires up one accepted connection.
pub async fn accept(
    runtime: &mut ActorRuntime,
    connection: Connection,
    setup: ServerSetup,
    cancel: CancellationToken,
) -> ActorHandle {
    let (read_half, write_half) = tokio::io::split(connection);
    accept_split(runtime, read_half, write_half, setup, cancel).await
}

/// Wires up one connection from an already-split pair of halves.
///
/// The split form is what stdio needs — a process's stdin and stdout are two
/// unrelated handles that were never one socket to begin with — and it is what
/// tests use to drive a real connection actor over
/// [`tokio::net::UnixStream::pair`] with no listener at all. The daemon and the
/// stdio agent therefore run the same protocol state machine over two different
/// byte pipes, which is the point.
pub async fn accept_split<R, W>(
    runtime: &mut ActorRuntime,
    read_half: R,
    write_half: W,
    setup: ServerSetup,
    cancel: CancellationToken,
) -> ActorHandle
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let (conn, sink, client_id) = attach(runtime, write_half, setup).await;

    tokio::spawn(read_loop(
        BufReader::new(read_half),
        sink,
        conn.clone(),
        client_id,
        cancel,
    ));

    conn
}

/// Serves one connection to completion on the caller's task.
///
/// This is the stdio mode: there is exactly one client, it is the process that
/// spawned this one, and when its pipe closes the agent has nothing left to do.
/// Returning rather than spawning is what makes that a normal exit instead of a
/// process waiting for a signal nobody will send.
pub async fn serve_connection<R, W>(
    runtime: &mut ActorRuntime,
    read_half: R,
    write_half: W,
    setup: ServerSetup,
    cancel: CancellationToken,
) where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let (conn, sink, client_id) = attach(runtime, write_half, setup).await;

    read_loop(BufReader::new(read_half), sink, conn, client_id, cancel).await;
}

/// Starts the writer task and the connection actor behind it.
///
/// Split out because the order matters and both entry points need it: the sink
/// must exist before the actor can be handed one, and the actor must exist
/// before a reader can put a frame into it.
async fn attach<W>(
    runtime: &mut ActorRuntime,
    write_half: W,
    setup: ServerSetup,
) -> (ActorHandle, EventSink, ClientId)
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    let client_id = ClientId::new();

    let (tx, rx) = mpsc::unbounded_channel();
    let sink = EventSink::new(tx);
    tokio::spawn(codec::write_loop(write_half, rx));

    let conn = ClientConn::spawn(
        runtime,
        ConnSetup {
            client_id: client_id.clone(),
            sink: sink.clone(),
            supervisor: setup.supervisor,
            runtime: setup.runtime,
            router: setup.router,
            defaults: setup.defaults,
            capabilities: setup.capabilities,
            audited: setup.audited,
            sandbox: setup.sandbox,
            describers: setup.describers,
        },
    )
    .await;

    (conn, sink, client_id)
}

/// Pulls frames off one socket until it ends, then stops the connection actor.
async fn read_loop<R>(
    mut reader: R,
    sink: EventSink,
    conn: ActorHandle,
    client_id: ClientId,
    cancel: CancellationToken,
) where
    R: tokio::io::AsyncBufRead + Unpin,
{
    loop {
        let frame = tokio::select! {
            () = cancel.cancelled() => break,
            frame = codec::read_frame(&mut reader) => frame,
        };

        match frame {
            Ok(line) if line.trim().is_empty() => {}
            Ok(line) => match jsonrpc::classify(&line) {
                Ok(frame) => conn.send(Incoming { frame }).await,
                // A frame that will not classify may still have carried an id,
                // and answering against it is what lets a client match the
                // complaint to the call that caused it.
                Err(malformed) => {
                    sink.fail(malformed.id, malformed.error);
                }
            },
            Err(FrameError::Closed) => break,
            Err(error) => {
                tracing::debug!(%client_id, %error, "closing connection");
                sink.fail(
                    None,
                    jsonrpc::ErrorObject::invalid_request()
                        .data(serde_json::Value::String(error.to_string())),
                );
                break;
            }
        }
    }

    tracing::debug!(%client_id, "client disconnected");

    // Stopping drops the model, and with it every suspended approval envelope.
    // Each parked `ask` resolves as `NoReply`, so the tool calls this client
    // was asked about are denied rather than left waiting on a socket that is
    // no longer there.
    if let Err(error) = conn.stop().await {
        tracing::debug!(%client_id, %error, "connection actor did not stop cleanly");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_server_reports_no_endpoint() {
        assert_eq!(ProtocolServer::default().endpoint(), "");
    }
}
