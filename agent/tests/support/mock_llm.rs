//! A scripted OpenAI-compatible server, in plain tokio.
//!
//! The protocol tests need a provider that answers deterministically, and they
//! need one without dragging a web framework into a crate that has no HTTP
//! server of its own. acton-ai's mock is axum-based and lives in its own test
//! tree, so this is a deliberate second implementation rather than a shared
//! one: forty lines of hand-written HTTP against a fixed client is cheaper to
//! own than a dependency, and it can never drift into being a real server.
//!
//! # Wire shape
//!
//! What `acton_ai`'s OpenAI client parses: `data: {…}` lines carrying a chunk
//! with a non-empty `id` and a `choices` array whose entries have `index`,
//! `delta`, and an optional `finish_reason`, terminated by `data: [DONE]`.
//! Tool calls arrive as `delta.tool_calls` entries with `index`, `id`,
//! `function.name`, and `function.arguments` — the arguments a **JSON-encoded
//! string** — and the client only emits accumulated calls once it sees a
//! `finish_reason`, so every scripted round ends with a finish chunk.
//!
//! # Determinism
//!
//! Nothing sleeps. Rounds are handed out in order, and asking for one that was
//! never scripted is a 500 rather than a hang.

use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// One tool call a round should emit.
#[derive(Clone)]
struct ScriptedToolCall {
    id: String,
    name: String,
    arguments: Value,
}

/// One complete scripted response: some text, some tool calls, then a finish.
#[derive(Clone, Default)]
pub struct Round {
    text: Option<String>,
    tool_calls: Vec<ScriptedToolCall>,
    usage: Option<(u64, u64)>,
}

impl Round {
    /// A prose answer that ends the turn.
    #[must_use]
    pub fn text(text: &str) -> Self {
        Self {
            text: Some(text.to_string()),
            ..Self::default()
        }
    }

    /// A round whose only content is one tool call.
    #[must_use]
    pub fn tool_call(id: &str, name: &str, arguments: Value) -> Self {
        Self {
            tool_calls: vec![ScriptedToolCall {
                id: id.to_string(),
                name: name.to_string(),
                arguments,
            }],
            ..Self::default()
        }
    }

    /// Makes this round report token usage in a trailing chunk.
    #[must_use]
    pub fn with_usage(mut self, prompt_tokens: u64, completion_tokens: u64) -> Self {
        self.usage = Some((prompt_tokens, completion_tokens));
        self
    }

    /// Renders the round as an SSE body.
    fn to_sse(&self) -> String {
        let mut body = String::new();
        let mut push = |chunk: &Value| {
            body.push_str("data: ");
            body.push_str(&serde_json::to_string(chunk).expect("a chunk must serialize"));
            body.push_str("\n\n");
        };

        if let Some(text) = &self.text {
            push(&json!({
                "id": "chatcmpl-mock",
                "choices": [{"index": 0, "delta": {"content": text}}],
            }));
        }

        for (index, call) in self.tool_calls.iter().enumerate() {
            push(&json!({
                "id": "chatcmpl-mock",
                "choices": [{
                    "index": 0,
                    "delta": {"tool_calls": [{
                        "index": index,
                        "id": call.id,
                        "function": {
                            "name": call.name,
                            "arguments": call.arguments.to_string(),
                        },
                    }]},
                }],
            }));
        }

        let finish_reason = if self.tool_calls.is_empty() {
            "stop"
        } else {
            "tool_calls"
        };
        push(&json!({
            "id": "chatcmpl-mock",
            "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
        }));

        if let Some((prompt_tokens, completion_tokens)) = self.usage {
            push(&json!({
                "id": "chatcmpl-mock",
                "choices": [],
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                },
            }));
        }

        body.push_str("data: [DONE]\n\n");
        body
    }
}

/// A running scripted server.
pub struct MockServer {
    base_url: String,
    served: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<Value>>>,
    rounds: Option<mpsc::UnboundedReceiver<usize>>,
}

impl MockServer {
    /// Binds an ephemeral port and serves `script`, one round per request.
    pub async fn start(script: Vec<Round>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding an ephemeral port must succeed");
        let addr = listener
            .local_addr()
            .expect("a bound listener must have an address");

        let served = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(script);
        let (tx, rounds) = mpsc::unbounded_channel();

        let accept_served = Arc::clone(&served);
        let accept_received = Arc::clone(&received);
        tokio::spawn(async move {
            // Ends when the test's runtime is dropped.
            while let Ok((stream, _)) = listener.accept().await {
                let script = Arc::clone(&script);
                let served = Arc::clone(&accept_served);
                let received = Arc::clone(&accept_received);
                let tx = tx.clone();
                tokio::spawn(async move {
                    serve(stream, script, served, received, tx).await;
                });
            }
        });

        Self {
            base_url: format!("http://{addr}/v1"),
            served,
            received,
            rounds: Some(rounds),
        }
    }

    /// Takes the channel that reports each round as it is served.
    ///
    /// This is how a test waits for the prompt loop to reach a particular
    /// round without sleeping: the model answering is the only observable
    /// event that says the turn got that far.
    ///
    /// # Panics
    ///
    /// If called more than once. There is one receiver.
    pub fn rounds(&mut self) -> mpsc::UnboundedReceiver<usize> {
        self.rounds
            .take()
            .expect("the rounds channel is taken once")
    }

    /// The `/v1` base URL this server is listening on.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// How many requests the server has answered.
    #[must_use]
    pub fn request_count(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }

    /// Every request body received so far, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<Value> {
        self.received
            .lock()
            .expect("the request log must not be poisoned")
            .clone()
    }
}

/// Answers requests on one connection until the client hangs up.
async fn serve(
    mut stream: TcpStream,
    script: Arc<Vec<Round>>,
    served: Arc<AtomicUsize>,
    received: Arc<Mutex<Vec<Value>>>,
    rounds: mpsc::UnboundedSender<usize>,
) {
    let mut buffer = Vec::new();

    loop {
        let Some(request) = read_request(&mut stream, &mut buffer).await else {
            return;
        };

        if let Ok(body) = serde_json::from_str::<Value>(&request) {
            received
                .lock()
                .expect("the request log must not be poisoned")
                .push(body);
        }

        let index = served.fetch_add(1, Ordering::SeqCst);
        let response = match script.get(index) {
            Some(round) => http_ok(&round.to_sse()),
            // Asking for a round nobody scripted is a bug in the test, and a
            // 500 says so in a way that ends the turn instead of hanging it.
            None => http_error(index),
        };

        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }

        let _ = rounds.send(index);
    }
}

/// Reads one HTTP request and returns its body.
///
/// Deliberately minimal: the only client is `acton_ai`'s OpenAI client, which
/// always sends `content-length` and never chunks.
async fn read_request(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(request) = take_request(buffer) {
            return Some(request);
        }

        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Splits one complete request off the front of `buffer`, if there is one.
fn take_request(buffer: &mut Vec<u8>) -> Option<String> {
    let text = String::from_utf8_lossy(buffer).to_string();
    let header_end = text.find("\r\n\r\n")? + 4;
    let length = content_length(&text[..header_end])?;

    if buffer.len() < header_end + length {
        return None;
    }

    let body = text[header_end..header_end + length].to_string();
    buffer.drain(..header_end + length);
    Some(body)
}

/// Reads `content-length` out of a header block, case-insensitively.
fn content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("content-length") {
            return None;
        }
        value.trim().parse().ok()
    })
}

/// A 200 carrying an SSE body.
fn http_ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n\
         content-type: text/event-stream\r\n\
         cache-control: no-cache\r\n\
         content-length: {}\r\n\
         \r\n\
         {body}",
        body.len(),
    )
}

/// A 500 naming the round that was asked for and never scripted.
fn http_error(index: usize) -> String {
    let body = format!("mock server has no scripted round #{index}");
    format!(
        "HTTP/1.1 500 Internal Server Error\r\n\
         content-type: text/plain\r\n\
         content-length: {}\r\n\
         \r\n\
         {body}",
        body.len(),
    )
}
