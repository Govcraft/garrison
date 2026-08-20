//! A minimal ACP client, for making the agent testable and demonstrable.
//!
//! `ping` proves the handshake, `chat` drives a whole session. It is
//! deliberately small and sequential in shape — one connection, one outstanding
//! request at a time — because that is what a smoke client should be. A real
//! editor multiplexes; this does not pretend to.
//!
//! # It is a client, so it answers too
//!
//! ACP is bidirectional. While a `session/prompt` is open the agent may send
//! `session/request_permission` back down the same socket, and a client that
//! only ever read responses would deadlock the moment a tool needed approval.
//! So the read loop classifies every frame and hands the agent's questions to
//! an [`Interactions`] implementation, whose default answer is a refusal:
//! a smoke client that silently approved everything would be a worse thing to
//! hand somebody than one that does nothing at all.

use crate::error::GarrisonError;
use crate::protocol::acp;
use crate::protocol::codec::{self, FrameError};
use crate::protocol::jsonrpc::{
    self, to_line, ErrorObject, Inbound, OutgoingRequest, RequestId, SuccessResponse,
    JSONRPC_VERSION,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;
use tokio::io::{AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::UnixStream;

/// Builds the wire line for one outgoing request.
///
/// Pure: the caller decides when it reaches the socket.
///
/// # Errors
///
/// A `params` value that will not serialize.
pub(crate) fn request_line(
    id: RequestId,
    method: &str,
    params: &impl Serialize,
) -> Result<String, GarrisonError> {
    let params = serde_json::to_value(params).map_err(|error| {
        GarrisonError::transport(method, format!("unserializable params: {error}"))
    })?;
    to_line(&OutgoingRequest::new(id, method, params))
        .map_err(|error| GarrisonError::transport(method, format!("unserializable: {error}")))
}

/// Builds the wire line for one outgoing notification.
///
/// # Errors
///
/// A `params` value that will not serialize.
pub(crate) fn notification_line(
    method: &str,
    params: &impl Serialize,
) -> Result<String, GarrisonError> {
    let params = serde_json::to_value(params).map_err(|error| {
        GarrisonError::transport(method, format!("unserializable params: {error}"))
    })?;
    to_line(&jsonrpc::OutgoingNotification::new(method, params))
        .map_err(|error| GarrisonError::transport(method, format!("unserializable: {error}")))
}

/// Builds the wire line answering one agent-initiated request.
///
/// # Errors
///
/// A `result` value that will not serialize.
pub(crate) fn response_line(
    context: &str,
    id: RequestId,
    outcome: Result<serde_json::Value, ErrorObject>,
) -> Result<String, GarrisonError> {
    match outcome {
        Ok(result) => to_line(&SuccessResponse::new(id, result)),
        Err(error) => to_line(&jsonrpc::ErrorResponse::new(Some(id), error)),
    }
    .map_err(|error| GarrisonError::transport(context, error.to_string()))
}

/// How a client reacts to what the agent sends it unprompted.
pub trait Interactions {
    /// Called for every `session/update` notification.
    fn update(&mut self, _notification: &acp::SessionNotification) {}

    /// Called for every `session/request_permission` request.
    ///
    /// The default refuses. Approving is a decision a caller must make
    /// explicitly, in code somebody read.
    fn permission(
        &mut self,
        _request: &acp::RequestPermissionRequest,
    ) -> acp::RequestPermissionOutcome {
        acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(
            acp::OPTION_REJECT,
        ))
    }
}

/// An [`Interactions`] that watches nothing and refuses everything.
#[derive(Clone, Copy, Debug, Default)]
pub struct Quiet;

impl Interactions for Quiet {}

/// One connection to a running agent.
#[derive(Debug)]
pub struct AgentClient {
    reader: BufReader<ReadHalf<UnixStream>>,
    writer: WriteHalf<UnixStream>,
    next_id: i64,
}

impl AgentClient {
    /// Connects to an agent listening on a Unix socket.
    ///
    /// # Errors
    ///
    /// [`GarrisonErrorKind::Transport`](crate::error::GarrisonErrorKind::Transport)
    /// when the socket cannot be reached — which most often means no agent is
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

    /// Wraps an already-connected stream.
    ///
    /// The seam that lets tests drive a real agent over
    /// [`UnixStream::pair`](tokio::net::UnixStream::pair) — no listener, no
    /// socket file, no cleanup.
    #[must_use]
    pub fn from_stream(stream: UnixStream) -> Self {
        let (read_half, writer) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(read_half),
            writer,
            next_id: 1,
        }
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

    /// Sends a request and returns the id it will be answered under.
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

    /// Reads and classifies the next frame the agent sends.
    ///
    /// # Errors
    ///
    /// Transport failures, including the agent closing the connection, and a
    /// frame that is not well-formed JSON-RPC.
    pub async fn next_frame(&mut self) -> Result<Inbound, GarrisonError> {
        loop {
            let line = match codec::read_frame(&mut self.reader).await {
                Ok(line) => line,
                Err(FrameError::Closed) => {
                    return Err(GarrisonError::transport(
                        "agent",
                        "the agent closed the connection",
                    ))
                }
                Err(error) => return Err(GarrisonError::transport("agent", error.to_string())),
            };

            if line.trim().is_empty() {
                continue;
            }

            return jsonrpc::classify(&line).map_err(|malformed| {
                GarrisonError::transport("agent", malformed.error.message.clone())
            });
        }
    }

    /// Sends a request and waits for its answer, servicing whatever the agent
    /// asks in the meantime.
    ///
    /// # Errors
    ///
    /// Transport failures, an agent-side refusal, or a result that does not
    /// deserialize into `R`.
    pub async fn request<P, R>(
        &mut self,
        method: &str,
        params: &P,
        interactions: &mut impl Interactions,
    ) -> Result<R, GarrisonError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let expected = self.send(method, params).await?;

        loop {
            match self.next_frame().await? {
                Inbound::Notification {
                    method: name,
                    params,
                } => {
                    deliver_update(interactions, &name, params.as_ref());
                }
                Inbound::Request { id, method, params } => {
                    self.answer(interactions, id, &method, params).await?;
                }
                Inbound::Response { id, outcome } if id == expected => {
                    return match outcome {
                        Ok(result) => serde_json::from_value(result).map_err(|error| {
                            GarrisonError::transport(method, format!("unexpected result: {error}"))
                        }),
                        Err(error) => Err(GarrisonError::transport(
                            method,
                            format!("{} (code {})", error.message, i32::from(error.code)),
                        )),
                    }
                }
                other => tracing::debug!(?other, "ignoring an answer to an older request"),
            }
        }
    }

    /// Answers one agent-initiated request.
    async fn answer(
        &mut self,
        interactions: &mut impl Interactions,
        id: RequestId,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<(), GarrisonError> {
        if method != acp::method::SESSION_REQUEST_PERMISSION {
            let line = response_line(
                method,
                id,
                Err(ErrorObject::method_not_found()
                    .data(serde_json::Value::String(method.to_string()))),
            )?;
            return self.write_line(method, line).await;
        }

        let request: acp::RequestPermissionRequest =
            serde_json::from_value(params.unwrap_or(serde_json::Value::Null)).map_err(|error| {
                GarrisonError::transport(method, format!("unreadable permission request: {error}"))
            })?;

        let outcome = interactions.permission(&request);
        let response = serde_json::to_value(acp::RequestPermissionResponse::new(outcome))
            .map_err(|error| GarrisonError::transport(method, error.to_string()))?;
        let line = response_line(method, id, Ok(response))?;

        self.write_line(method, line).await
    }

    /// Performs the ACP handshake.
    ///
    /// # Errors
    ///
    /// As [`Self::request`].
    pub async fn initialize(
        &mut self,
        client_name: &str,
    ) -> Result<acp::InitializeResponse, GarrisonError> {
        let request = acp::InitializeRequest::new(acp::PROTOCOL_VERSION).client_info(
            acp::Implementation::new(client_name, env!("CARGO_PKG_VERSION")),
        );

        self.request(acp::method::INITIALIZE, &request, &mut Quiet)
            .await
    }

    /// Opens a session rooted at `cwd`.
    ///
    /// # Errors
    ///
    /// As [`Self::request`].
    pub async fn new_session(
        &mut self,
        cwd: impl Into<std::path::PathBuf>,
    ) -> Result<acp::NewSessionResponse, GarrisonError> {
        self.request(
            acp::method::SESSION_NEW,
            &acp::NewSessionRequest::new(cwd),
            &mut Quiet,
        )
        .await
    }

    /// Runs one turn and waits for it to end.
    ///
    /// # Errors
    ///
    /// As [`Self::request`].
    pub async fn prompt(
        &mut self,
        session_id: acp::SessionId,
        text: &str,
        interactions: &mut impl Interactions,
    ) -> Result<acp::PromptResponse, GarrisonError> {
        let request = acp::PromptRequest::new(session_id, vec![acp::ContentBlock::from(text)]);

        self.request(acp::method::SESSION_PROMPT, &request, interactions)
            .await
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

/// Hands one notification to the caller's reactions, if it is one we model.
///
/// Pure but for the callback: an unreadable or unknown notification is logged
/// and dropped, because a client that failed the whole turn over an event it
/// did not recognize would break every time ACP grew a new one.
fn deliver_update(
    interactions: &mut impl Interactions,
    method: &str,
    params: Option<&serde_json::Value>,
) {
    if method != acp::method::SESSION_UPDATE {
        tracing::debug!(method, "ignoring an unknown notification");
        return;
    }

    let raw = params.cloned().unwrap_or(serde_json::Value::Null);
    match serde_json::from_value::<acp::SessionNotification>(raw) {
        Ok(notification) => interactions.update(&notification),
        Err(error) => tracing::debug!(%error, "ignoring an unreadable session update"),
    }
}

/// The JSON-RPC version string this client sends, for callers that log it.
#[must_use]
pub const fn jsonrpc_version() -> &'static str {
    JSONRPC_VERSION
}

/// Pulls the plain text out of a `session/update`, if it carries any.
///
/// Pure, and useful to every consumer of this client: a CLI printing a reply
/// and a test asserting on one want exactly the same thing.
#[must_use]
pub fn update_text(notification: &acp::SessionNotification) -> Option<&str> {
    match &notification.update {
        acp::SessionUpdate::AgentMessageChunk(chunk)
        | acp::SessionUpdate::UserMessageChunk(chunk) => match &chunk.content {
            acp::ContentBlock::Text(text) => Some(text.text.as_str()),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ThreadId;

    /// Records what it was shown and approves everything.
    #[derive(Default)]
    struct Recorder {
        text: String,
        asked: Vec<String>,
    }

    impl Interactions for Recorder {
        fn update(&mut self, notification: &acp::SessionNotification) {
            if let Some(text) = update_text(notification) {
                self.text.push_str(text);
            }
        }

        fn permission(
            &mut self,
            request: &acp::RequestPermissionRequest,
        ) -> acp::RequestPermissionOutcome {
            self.asked
                .push(request.tool_call.tool_call_id.0.to_string());
            acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(
                acp::OPTION_ALLOW_ONCE,
            ))
        }
    }

    #[test]
    fn the_default_answer_to_a_permission_request_is_no() {
        let request = acp::RequestPermissionRequest::new(
            acp::SessionId::new("s"),
            acp::ToolCallUpdate::new("call-1", acp::ToolCallUpdateFields::new()),
            acp::permission_options(),
        );

        let outcome = Quiet.permission(&request);

        assert_eq!(acp::permission_for(&outcome), Some(acp::Permission::Reject));
    }

    #[test]
    fn agent_chunks_accumulate_into_the_reply() {
        let thread_id = ThreadId::new();
        let mut recorder = Recorder::default();

        for text in ["hel", "lo"] {
            let notification = acp::agent_chunk(&thread_id, text);
            let params = serde_json::to_value(&notification).unwrap();
            deliver_update(&mut recorder, acp::method::SESSION_UPDATE, Some(&params));
        }

        assert_eq!(recorder.text, "hello");
    }

    #[test]
    fn an_unknown_notification_is_dropped_rather_than_failing() {
        let mut recorder = Recorder::default();

        deliver_update(&mut recorder, "session/somethingNew", None);

        assert!(recorder.text.is_empty());
    }

    #[test]
    fn an_unreadable_session_update_is_dropped_rather_than_failing() {
        let mut recorder = Recorder::default();
        let params = serde_json::json!({"nonsense": true});

        deliver_update(&mut recorder, acp::method::SESSION_UPDATE, Some(&params));

        assert!(recorder.text.is_empty());
    }

    #[test]
    fn a_tool_call_update_carries_no_message_text() {
        let notification = acp::tool_call_finished(&ThreadId::new(), "call-1", true, "ok");

        assert_eq!(update_text(&notification), None);
    }
}
