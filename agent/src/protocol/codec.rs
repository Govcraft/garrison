//! Framing: newline-delimited JSON in, newline-delimited JSON out.
//!
//! The protocol's grammar lives in [`jsonrpc`](crate::protocol::jsonrpc); this
//! module is only about getting whole lines off a socket and whole lines back
//! onto it.
//!
//! # Shape
//!
//! Each connection gets two plain tokio tasks and no actor of its own:
//!
//! - a **reader** task that pulls frames off the socket and `send`s them to
//!   the connection's actor, and
//! - a **writer** task that drains an unbounded channel of already-serialized
//!   lines onto the socket.
//!
//! Splitting the write half behind a channel is what lets several producers —
//! the connection actor answering a request, a thread actor streaming tokens,
//! the router announcing a tool result — all emit to one socket without any of
//! them sharing a lock. A channel sender is a handoff, not shared state.
//!
//! # Why the reader is bounded
//!
//! A line-oriented protocol has an obvious denial of service in it: a client
//! that sends bytes and never a newline. `read_until` would happily grow a
//! buffer until the process dies, so [`read_frame`] scans incrementally and
//! gives up the moment the frame in progress exceeds [`MAX_FRAME_BYTES`],
//! having allocated no more than that.

use crate::protocol::jsonrpc::{
    to_line, ErrorObject, ErrorResponse, OutgoingNotification, OutgoingRequest, RequestId,
    SuccessResponse,
};
use serde::Serialize;
use std::io;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// The largest single frame the server will accept, in bytes.
///
/// Generous enough for a patch of a few thousand lines travelling as a JSON
/// string, small enough that a hostile client cannot exhaust memory one
/// connection at a time.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// A write handle onto one client connection.
///
/// Cloneable and cheap: every clone feeds the same writer task, which is the
/// single owner of the socket's write half.
///
/// # The default sink
///
/// [`Default`] yields a sink whose receiver is already dropped, so every send
/// fails and [`is_closed`](Self::is_closed) is true. It exists because actor
/// models must be `Default`, and a null object that visibly discards is safer
/// than an `Option` every call site has to unwrap.
#[derive(Clone, Debug)]
pub struct EventSink {
    tx: mpsc::UnboundedSender<String>,
}

impl Default for EventSink {
    fn default() -> Self {
        let (tx, _rx) = mpsc::unbounded_channel();
        Self { tx }
    }
}

impl EventSink {
    /// Wraps a sender that a [`spawn_writer`] task is draining.
    #[must_use]
    pub fn new(tx: mpsc::UnboundedSender<String>) -> Self {
        Self { tx }
    }

    /// True once the writer task has gone, i.e. the connection is finished.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }

    /// Queues an already-framed line. Returns false if the connection is gone.
    pub fn send_line(&self, line: String) -> bool {
        self.tx.send(line).is_ok()
    }

    /// Queues a server-to-client notification.
    ///
    /// Returns false if the line could not be serialized or the connection is
    /// gone. Both are conditions a caller may reasonably ignore — an event for
    /// a client that has hung up is not an error — so this reports rather than
    /// fails.
    pub fn notify<T: Serialize>(&self, method: &str, params: &T) -> bool {
        let params = match serde_json::to_value(params) {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, method, "dropping unserializable event");
                return false;
            }
        };
        self.frame(&OutgoingNotification::new(method, params))
    }

    /// Queues an agent-to-client request.
    ///
    /// The answer arrives back through the reader as an
    /// [`Inbound::Response`](crate::protocol::jsonrpc::Inbound::Response); it
    /// is the connection actor, not this sink, that remembers who is waiting
    /// for it.
    pub fn request<T: Serialize>(&self, id: RequestId, method: &str, params: &T) -> bool {
        let params = match serde_json::to_value(params) {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, method, "dropping unserializable request");
                return false;
            }
        };
        self.frame(&OutgoingRequest::new(id, method, params))
    }

    /// Queues a successful response to a request.
    pub fn respond<T: Serialize>(&self, id: RequestId, result: &T) -> bool {
        let result = match serde_json::to_value(result) {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "dropping unserializable result");
                return self.fail(Some(id), ErrorObject::internal_error());
            }
        };
        self.frame(&SuccessResponse::new(id, result))
    }

    /// Queues an error response.
    pub fn fail(&self, id: Option<RequestId>, error: ErrorObject) -> bool {
        self.frame(&ErrorResponse::new(id, error))
    }

    fn frame<T: Serialize>(&self, frame: &T) -> bool {
        match to_line(frame) {
            Ok(line) => self.send_line(line),
            Err(error) => {
                tracing::error!(%error, "dropping unserializable frame");
                false
            }
        }
    }
}

/// Why a frame could not be read.
#[derive(Debug)]
#[non_exhaustive]
pub enum FrameError {
    /// The peer closed the connection cleanly, mid-frame or between frames.
    Closed,
    /// The frame exceeded [`MAX_FRAME_BYTES`] before a newline arrived.
    TooLarge {
        /// How many bytes had accumulated when the limit was hit.
        bytes: usize,
    },
    /// The socket itself failed.
    Io {
        /// The underlying error.
        source: io::Error,
    },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "connection closed"),
            Self::TooLarge { bytes } => write!(
                f,
                "frame exceeded {MAX_FRAME_BYTES} bytes (had {bytes} with no newline)"
            ),
            Self::Io { source } => write!(f, "connection failed: {source}"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source } => Some(source),
            _ => None,
        }
    }
}

/// Reads one newline-terminated frame, never buffering past [`MAX_FRAME_BYTES`].
///
/// The returned `String` excludes the newline and any trailing carriage
/// return. Blank lines are returned as empty strings; the caller decides
/// whether to ignore them (the server does).
///
/// # Errors
///
/// [`FrameError::Closed`] at end of stream, [`FrameError::TooLarge`] when the
/// limit is reached with no newline in sight, [`FrameError::Io`] otherwise.
/// Invalid UTF-8 is reported as [`FrameError::Io`] with
/// [`io::ErrorKind::InvalidData`], since a JSON-RPC frame that is not text is
/// a transport-level fault rather than a protocol one.
pub async fn read_frame<R>(reader: &mut R) -> Result<String, FrameError>
where
    R: AsyncBufRead + Unpin,
{
    let mut frame = Vec::new();

    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|source| FrameError::Io { source })?;

        if available.is_empty() {
            return Err(FrameError::Closed);
        }

        match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                frame.extend_from_slice(&available[..index]);
                reader.consume(index + 1);
                return finish_frame(frame);
            }
            None => {
                let taken = available.len();
                if frame.len() + taken > MAX_FRAME_BYTES {
                    reader.consume(taken);
                    return Err(FrameError::TooLarge {
                        bytes: frame.len() + taken,
                    });
                }
                frame.extend_from_slice(available);
                reader.consume(taken);
            }
        }
    }
}

/// Turns an accumulated frame into text, enforcing the size cap once more.
///
/// Split out so the length check covers the terminating read too: a frame can
/// only exceed the cap on the read that also carries its newline.
fn finish_frame(mut frame: Vec<u8>) -> Result<String, FrameError> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { bytes: frame.len() });
    }
    if frame.last() == Some(&b'\r') {
        frame.pop();
    }
    String::from_utf8(frame).map_err(|error| FrameError::Io {
        source: io::Error::new(io::ErrorKind::InvalidData, error),
    })
}

/// Drains `rx` onto `writer` until the channel closes or the socket fails.
///
/// Runs as a plain task rather than an actor because it owns no decisions:
/// there is exactly one of it per socket, it has no state beyond the write
/// half, and nothing ever needs to ask it a question.
pub async fn write_loop<W>(mut writer: W, mut rx: mpsc::UnboundedReceiver<String>)
where
    W: AsyncWrite + Unpin,
{
    while let Some(line) = rx.recv().await {
        if let Err(error) = writer.write_all(line.as_bytes()).await {
            tracing::debug!(%error, "client write failed; closing");
            return;
        }
        if let Err(error) = writer.flush().await {
            tracing::debug!(%error, "client flush failed; closing");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn reads_successive_frames() {
        let mut reader = BufReader::new(&b"one\ntwo\n"[..]);

        assert_eq!(read_frame(&mut reader).await.unwrap(), "one");
        assert_eq!(read_frame(&mut reader).await.unwrap(), "two");
        assert!(matches!(
            read_frame(&mut reader).await,
            Err(FrameError::Closed)
        ));
    }

    #[tokio::test]
    async fn strips_a_carriage_return() {
        let mut reader = BufReader::new(&b"windows\r\n"[..]);

        assert_eq!(read_frame(&mut reader).await.unwrap(), "windows");
    }

    #[tokio::test]
    async fn a_blank_line_is_an_empty_frame() {
        let mut reader = BufReader::new(&b"\nafter\n"[..]);

        assert_eq!(read_frame(&mut reader).await.unwrap(), "");
        assert_eq!(read_frame(&mut reader).await.unwrap(), "after");
    }

    #[tokio::test]
    async fn an_unterminated_frame_is_not_returned() {
        let mut reader = BufReader::new(&b"no newline here"[..]);

        assert!(matches!(
            read_frame(&mut reader).await,
            Err(FrameError::Closed)
        ));
    }

    #[tokio::test]
    async fn an_oversized_frame_is_refused_before_it_is_buffered() {
        let flood = vec![b'x'; MAX_FRAME_BYTES + 1024];
        let mut reader = BufReader::new(&flood[..]);

        match read_frame(&mut reader).await {
            Err(FrameError::TooLarge { bytes }) => assert!(bytes > MAX_FRAME_BYTES),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_utf8_is_an_io_error() {
        let mut reader = BufReader::new(&b"\xff\xfe\n"[..]);

        assert!(matches!(
            read_frame(&mut reader).await,
            Err(FrameError::Io { .. })
        ));
    }

    #[tokio::test]
    async fn the_default_sink_discards() {
        let sink = EventSink::default();

        assert!(sink.is_closed());
        assert!(!sink.send_line("dropped\n".to_string()));
    }

    #[tokio::test]
    async fn a_notification_is_written_as_one_line() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sink = EventSink::new(tx);

        assert!(sink.notify("token", &serde_json::json!({"text": "hi"})));

        let line = rx.recv().await.unwrap();
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["method"], "token");
        assert_eq!(parsed["params"]["text"], "hi");
        assert!(parsed.get("id").is_none());
    }

    #[tokio::test]
    async fn a_response_carries_the_request_id() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sink = EventSink::new(tx);

        assert!(sink.respond(RequestId::Number(7), &serde_json::json!({"ok": true})));

        let parsed: serde_json::Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
        assert_eq!(parsed["id"], 7);
        assert_eq!(parsed["result"]["ok"], true);
    }

    #[tokio::test]
    async fn a_request_is_written_with_an_id_and_a_method() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sink = EventSink::new(tx);

        assert!(sink.request(
            RequestId::Number(9),
            "session/request_permission",
            &serde_json::json!({"sessionId": "s"}),
        ));

        let parsed: serde_json::Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
        assert_eq!(parsed["id"], 9);
        assert_eq!(parsed["method"], "session/request_permission");
        assert_eq!(parsed["params"]["sessionId"], "s");
    }

    #[tokio::test]
    async fn the_write_loop_drains_in_order_then_stops() {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut sink_bytes = Vec::new();

        tx.send("a\n".to_string()).unwrap();
        tx.send("b\n".to_string()).unwrap();
        drop(tx);

        write_loop(&mut sink_bytes, rx).await;

        assert_eq!(sink_bytes, b"a\nb\n");
    }
}
