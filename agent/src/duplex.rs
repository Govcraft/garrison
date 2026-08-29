//! A full-duplex ACP client, for user interfaces.
//!
//! [`AgentClient`](crate::client::AgentClient) is sequential by design: it
//! writes one request and then blocks reading frames until that request's own
//! answer arrives. That is the right shape for a smoke test and the wrong shape
//! for a terminal, because a person watching a turn scroll past wants to press
//! Esc and have `session/cancel` go out *while* `session/prompt` is still open.
//!
//! So this splits the socket. A reader task owns the read half and classifies
//! every frame onto a channel; the caller owns the write half outright and can
//! send at any moment. Nothing is shared, so nothing needs a lock: the two
//! halves of a `UnixStream` are genuinely independent.
//!
//! What the caller gives up is correlation. [`DuplexClient::send`] hands back
//! the [`RequestId`] the answer will carry and then forgets about it; matching
//! [`AgentEvent::Response`] to the request that earned it is the caller's job,
//! because only the caller knows what to do with an answer that arrives after
//! the user has moved on.

use crate::client::{notification_line, request_line, response_line};
use crate::error::GarrisonError;
use crate::protocol::acp;
use crate::protocol::codec::{self, FrameError};
use crate::protocol::jsonrpc::{self, ErrorObject, Inbound, RequestId};
use serde::Serialize;
use std::path::Path;
use tokio::io::{AsyncWriteExt, BufReader, WriteHalf};
use tokio::net::UnixStream;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

/// Something the agent said, on its own schedule.
#[derive(Debug)]
pub enum AgentEvent {
    /// A `session/update` notification.
    Update(Box<acp::SessionNotification>),
    /// A `session/request_permission` the agent is blocked on.
    ///
    /// The turn does not advance until this is answered, so a caller that drops
    /// one stalls the agent until it times out.
    Permission {
        /// The id to answer under.
        id: RequestId,
        /// What the agent wants to do.
        request: Box<acp::RequestPermissionRequest>,
    },
    /// A request this client does not implement, or could not read.
    ///
    /// The agent is blocked on it exactly as it would be on a permission, so
    /// it must be refused; [`DuplexClient::refuse`] is how.
    Unsupported {
        /// The id to refuse under.
        id: RequestId,
        /// The method the agent asked for.
        method: String,
    },
    /// An answer to something this client sent.
    Response {
        /// The id the request was sent under.
        id: RequestId,
        /// The result, or the agent's refusal.
        outcome: Result<serde_json::Value, ErrorObject>,
    },
    /// The connection ended. No further events will arrive.
    Closed {
        /// Why, in words fit to show a person.
        reason: String,
    },
}

/// One connection to a running agent, readable and writable at once.
#[derive(Debug)]
pub struct DuplexClient {
    writer: WriteHalf<UnixStream>,
    next_id: i64,
    events: Option<UnboundedReceiver<AgentEvent>>,
}

impl DuplexClient {
    /// Connects to an agent listening on a Unix socket.
    ///
    /// # Errors
    ///
    /// [`GarrisonErrorKind::Transport`](crate::error::GarrisonErrorKind::Transport)
    /// when the socket cannot be reached, which most often means no agent is
    /// running there.
    pub async fn connect(path: &Path) -> Result<Self, GarrisonError> {
        let stream = UnixStream::connect(path).await.map_err(|error| {
            GarrisonError::transport(
                path.display().to_string(),
                format!("connect failed: {error}"),
            )
        })?;
        Ok(Self::from_stream(stream))
    }

    /// Wraps an already-connected stream, spawning the reader task.
    ///
    /// The seam that lets tests drive a real agent over
    /// [`UnixStream::pair`](tokio::net::UnixStream::pair).
    #[must_use]
    pub fn from_stream(stream: UnixStream) -> Self {
        let (read_half, writer) = tokio::io::split(stream);
        let (sender, events) = mpsc::unbounded_channel();
        tokio::spawn(read_frames(BufReader::new(read_half), sender));

        Self {
            writer,
            next_id: 1,
            events: Some(events),
        }
    }

    /// Waits for the next thing the agent says.
    ///
    /// Returns `None` once the connection has ended, and immediately after
    /// [`Self::split`] has handed the stream to somebody else.
    pub async fn next_event(&mut self) -> Option<AgentEvent> {
        match self.events.as_mut() {
            Some(events) => events.recv().await,
            None => None,
        }
    }

    /// Sends a request and waits for its answer, for use before the interface
    /// exists.
    ///
    /// Only correct while nothing else is reading the stream and no turn is
    /// open — the handshake, in other words. It drops updates rather than
    /// delivering them, and refuses nothing, so an agent that asked a question
    /// here would be left waiting.
    ///
    /// # Errors
    ///
    /// Transport failures, an agent-side refusal, a closed connection, and a
    /// result that does not deserialize into `R`.
    pub async fn request<P, R>(&mut self, method: &str, params: &P) -> Result<R, GarrisonError>
    where
        P: Serialize,
        R: serde::de::DeserializeOwned,
    {
        let expected = self.send(method, params).await?;

        loop {
            match self.next_event().await {
                Some(AgentEvent::Response { id, outcome }) if id == expected => {
                    return match outcome {
                        Ok(result) => serde_json::from_value(result).map_err(|error| {
                            GarrisonError::transport(method, format!("unexpected result: {error}"))
                        }),
                        // `data` is where the agent says *why*. The TUI is
                        // the path with no second chance to ask, so it must
                        // carry the same detail the one-shot client does.
                        Err(error) => {
                            Err(GarrisonError::transport(method, jsonrpc::describe(&error)))
                        }
                    };
                }
                Some(AgentEvent::Closed { reason }) => {
                    return Err(GarrisonError::transport(method, reason))
                }
                Some(other) => tracing::debug!(?other, "ignoring an event during the handshake"),
                None => {
                    return Err(GarrisonError::transport(
                        method,
                        "the agent stopped answering",
                    ))
                }
            }
        }
    }

    /// Hands the write half to a task and the read stream to the caller.
    ///
    /// After this the socket has two independent owners and neither needs a
    /// lock: one task does every write, in the order the channel delivers
    /// them, and whoever holds the receiver does every read. The returned
    /// [`WireWriter`] is synchronous, so an actor can send on the wire from
    /// inside a handler without awaiting anything.
    ///
    /// # Panics
    ///
    /// If the stream was already taken.
    #[must_use]
    pub fn split(mut self) -> (WireWriter, UnboundedReceiver<AgentEvent>) {
        let events = self
            .events
            .take()
            .expect("a DuplexClient's stream can only be taken once");
        let (lines, outbound) = mpsc::unbounded_channel();
        tokio::spawn(write_lines(self.writer, outbound));

        (
            WireWriter {
                lines,
                next_id: self.next_id,
            },
            events,
        )
    }

    /// Writes one already-framed line.
    async fn write_line(&mut self, context: &str, line: String) -> Result<(), GarrisonError> {
        self.writer
            .write_all(line.as_bytes())
            .await
            .map_err(|error| GarrisonError::transport(context, format!("write failed: {error}")))?;
        self.writer
            .flush()
            .await
            .map_err(|error| GarrisonError::transport(context, format!("flush failed: {error}")))
    }

    /// Sends a request and returns the id its answer will carry.
    ///
    /// # Errors
    ///
    /// Transport failures, and a `params` value that will not serialize.
    pub async fn send<P: Serialize>(
        &mut self,
        method: &str,
        params: &P,
    ) -> Result<RequestId, GarrisonError> {
        let id = RequestId::Number(self.next_id);
        self.next_id += 1;

        let line = request_line(id.clone(), method, params)?;
        self.write_line(method, line).await?;
        Ok(id)
    }

    /// Sends a notification, which is never answered.
    ///
    /// # Errors
    ///
    /// Transport failures, and a `params` value that will not serialize.
    pub async fn notify<P: Serialize>(
        &mut self,
        method: &str,
        params: &P,
    ) -> Result<(), GarrisonError> {
        let line = notification_line(method, params)?;
        self.write_line(method, line).await
    }

    /// Answers one `session/request_permission`.
    ///
    /// # Errors
    ///
    /// Transport failures, and an outcome that will not serialize.
    pub async fn answer_permission(
        &mut self,
        id: RequestId,
        outcome: acp::RequestPermissionOutcome,
    ) -> Result<(), GarrisonError> {
        let method = acp::method::SESSION_REQUEST_PERMISSION;
        let response = serde_json::to_value(acp::RequestPermissionResponse::new(outcome))
            .map_err(|error| GarrisonError::transport(method, error.to_string()))?;
        let line = response_line(method, id, Ok(response))?;

        self.write_line(method, line).await
    }

    /// Refuses one request this client cannot serve.
    ///
    /// # Errors
    ///
    /// Transport failures.
    pub async fn refuse(&mut self, id: RequestId, method: &str) -> Result<(), GarrisonError> {
        let line = response_line(
            method,
            id,
            Err(ErrorObject::method_not_found().data(serde_json::Value::String(method.to_string()))),
        )?;

        self.write_line(method, line).await
    }

    /// Begins the ACP handshake.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    pub async fn begin_initialize(
        &mut self,
        client_name: &str,
    ) -> Result<RequestId, GarrisonError> {
        let request = acp::InitializeRequest::new(acp::PROTOCOL_VERSION).client_info(
            acp::Implementation::new(client_name, env!("CARGO_PKG_VERSION")),
        );

        self.send(acp::method::INITIALIZE, &request).await
    }

    /// Asks for a new session rooted at `cwd`.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    pub async fn begin_new_session(
        &mut self,
        cwd: impl Into<std::path::PathBuf>,
    ) -> Result<RequestId, GarrisonError> {
        self.send(acp::method::SESSION_NEW, &acp::NewSessionRequest::new(cwd))
            .await
    }

    /// Starts one turn. The answer arrives as an [`AgentEvent::Response`] once
    /// the turn ends, however it ends.
    ///
    /// # Errors
    ///
    /// As [`Self::send`].
    pub async fn begin_prompt(
        &mut self,
        session_id: acp::SessionId,
        text: &str,
    ) -> Result<RequestId, GarrisonError> {
        let request = acp::PromptRequest::new(session_id, vec![acp::ContentBlock::from(text)]);

        self.send(acp::method::SESSION_PROMPT, &request).await
    }

    /// Asks the agent to stop the session's running turn.
    ///
    /// # Errors
    ///
    /// Transport failures. A cancellation is a notification, so a successful
    /// send says only that the agent was told.
    pub async fn cancel(&mut self, session_id: acp::SessionId) -> Result<(), GarrisonError> {
        self.notify(
            acp::method::SESSION_CANCEL,
            &acp::CancelNotification::new(session_id),
        )
        .await
    }
}

/// Reads frames until the connection ends, classifying each onto `events`.
///
/// The task owns no writer, so it never answers anything itself. Every frame
/// the agent is blocked on leaves here as an event the caller must reply to.
async fn read_frames<R>(mut reader: R, events: UnboundedSender<AgentEvent>)
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let reason = loop {
        let line = match codec::read_frame(&mut reader).await {
            Ok(line) => line,
            Err(FrameError::Closed) => break "the agent closed the connection".to_string(),
            Err(error) => break error.to_string(),
        };

        if line.trim().is_empty() {
            continue;
        }

        let event = match jsonrpc::classify(&line) {
            Ok(inbound) => inbound,
            Err(malformed) => break malformed.error.message.clone(),
        };

        let delivered = match event {
            Inbound::Notification { method, params } => {
                forward_notification(&events, &method, params)
            }
            Inbound::Request { id, method, params } => {
                forward_request(&events, id, &method, params)
            }
            Inbound::Response { id, outcome } => {
                events.send(AgentEvent::Response { id, outcome }).is_ok()
            }
        };

        if !delivered {
            return;
        }
    };

    let _ = events.send(AgentEvent::Closed { reason });
}

/// Forwards one notification, dropping the ones this client does not model.
///
/// An unknown or unreadable notification is logged and dropped rather than
/// ending the connection, because a client that died every time ACP grew a new
/// event would need a release to match every agent release.
fn forward_notification(
    events: &UnboundedSender<AgentEvent>,
    method: &str,
    params: Option<serde_json::Value>,
) -> bool {
    if method != acp::method::SESSION_UPDATE {
        tracing::debug!(method, "dropping an unmodelled notification");
        return true;
    }

    match serde_json::from_value::<acp::SessionNotification>(
        params.unwrap_or(serde_json::Value::Null),
    ) {
        Ok(notification) => events
            .send(AgentEvent::Update(Box::new(notification)))
            .is_ok(),
        Err(error) => {
            tracing::debug!(%error, "dropping an unreadable session update");
            true
        }
    }
}

/// Forwards one agent-initiated request, or reports that it was refused.
fn forward_request(
    events: &UnboundedSender<AgentEvent>,
    id: RequestId,
    method: &str,
    params: Option<serde_json::Value>,
) -> bool {
    if method != acp::method::SESSION_REQUEST_PERMISSION {
        return events
            .send(AgentEvent::Unsupported {
                id,
                method: method.to_string(),
            })
            .is_ok();
    }

    match serde_json::from_value::<acp::RequestPermissionRequest>(
        params.unwrap_or(serde_json::Value::Null),
    ) {
        Ok(request) => events
            .send(AgentEvent::Permission {
                id,
                request: Box::new(request),
            })
            .is_ok(),
        Err(error) => {
            tracing::debug!(%error, "refusing an unreadable permission request");
            events
                .send(AgentEvent::Unsupported {
                    id,
                    method: method.to_string(),
                })
                .is_ok()
        }
    }
}

/// The write half of a connection, as something an actor can hold.
///
/// Every method is synchronous: it builds the wire line and hands it to the
/// writing task. That is what lets a message handler answer a permission or
/// cancel a turn without an `.await`, and therefore without the writer needing
/// to be shared, locked, or cloned.
#[derive(Debug)]
pub struct WireWriter {
    lines: UnboundedSender<String>,
    next_id: i64,
}

impl WireWriter {
    /// Sends a request and returns the id its answer will carry.
    ///
    /// # Errors
    ///
    /// A `params` value that will not serialize, and a connection whose
    /// writing task has stopped.
    pub fn request<P: Serialize>(
        &mut self,
        method: &str,
        params: &P,
    ) -> Result<RequestId, GarrisonError> {
        let id = RequestId::Number(self.next_id);
        self.next_id += 1;

        self.write(method, request_line(id.clone(), method, params)?)?;
        Ok(id)
    }

    /// Sends a notification, which is never answered.
    ///
    /// # Errors
    ///
    /// As [`Self::request`].
    pub fn notify<P: Serialize>(&self, method: &str, params: &P) -> Result<(), GarrisonError> {
        self.write(method, notification_line(method, params)?)
    }

    /// Answers one `session/request_permission`.
    ///
    /// # Errors
    ///
    /// As [`Self::request`].
    pub fn answer_permission(
        &self,
        id: RequestId,
        outcome: acp::RequestPermissionOutcome,
    ) -> Result<(), GarrisonError> {
        let method = acp::method::SESSION_REQUEST_PERMISSION;
        let response = serde_json::to_value(acp::RequestPermissionResponse::new(outcome))
            .map_err(|error| GarrisonError::transport(method, error.to_string()))?;

        self.write(method, response_line(method, id, Ok(response))?)
    }

    /// Refuses one request this client cannot serve.
    ///
    /// # Errors
    ///
    /// As [`Self::request`].
    pub fn refuse(&self, id: RequestId, method: &str) -> Result<(), GarrisonError> {
        let line = response_line(
            method,
            id,
            Err(ErrorObject::method_not_found().data(serde_json::Value::String(method.to_string()))),
        )?;

        self.write(method, line)
    }

    /// Asks the agent to stop the session's running turn.
    ///
    /// # Errors
    ///
    /// As [`Self::request`].
    pub fn cancel(&self, session_id: acp::SessionId) -> Result<(), GarrisonError> {
        self.notify(
            acp::method::SESSION_CANCEL,
            &acp::CancelNotification::new(session_id),
        )
    }

    /// Starts one turn.
    ///
    /// # Errors
    ///
    /// As [`Self::request`].
    pub fn prompt(
        &mut self,
        session_id: acp::SessionId,
        text: &str,
    ) -> Result<RequestId, GarrisonError> {
        let request = acp::PromptRequest::new(session_id, vec![acp::ContentBlock::from(text)]);

        self.request(acp::method::SESSION_PROMPT, &request)
    }

    /// Queues one already-framed line for the writing task.
    fn write(&self, context: &str, line: String) -> Result<(), GarrisonError> {
        self.lines
            .send(line)
            .map_err(|_| GarrisonError::transport(context, "the connection has closed"))
    }
}

/// Writes queued lines until the channel closes or the socket fails.
async fn write_lines(mut writer: WriteHalf<UnixStream>, mut lines: UnboundedReceiver<String>) {
    while let Some(line) = lines.recv().await {
        if let Err(error) = writer.write_all(line.as_bytes()).await {
            tracing::warn!(%error, "the connection stopped accepting writes");
            return;
        }
        if let Err(error) = writer.flush().await {
            tracing::warn!(%error, "the connection stopped accepting writes");
            return;
        }
    }
}
