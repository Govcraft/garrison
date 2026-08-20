//! The Garrison Agent Protocol, end to end over a real socket.
//!
//! Every test here drives the actual actors: a `ClientConn` reading a real
//! `UnixStream`, a `Thread` running a real acton-ai turn, a real policy gate
//! calling Garrison's approval hook. The only thing faked is the model, and it
//! is faked at the wire (a scripted OpenAI-compatible server) rather than by
//! substituting a trait, so the prompt loop, the tool round-tripping, and the
//! streaming callbacks are all the production ones.
//!
//! # No sleeps
//!
//! Nothing here waits on a duration. Every synchronization point is an
//! observable event: a frame arriving on the socket, a request answered, or
//! the mock server reporting that it served a round. A test that needed a
//! sleep would be a test that could not say what it was waiting for.

mod support;

use garrison_agent::approval;
use garrison_agent::client::{update_text, AgentClient, Interactions, Quiet};
use garrison_agent::config::GarrisonConfig;
use garrison_agent::launch;
use garrison_agent::protocol::acp;
use garrison_agent::protocol::jsonrpc::{self, Inbound, RequestId};
use garrison_agent::protocol::server;
use garrison_agent::thread::{DescribeThread, FindThread, ThreadLookup, ThreadSummary};
use garrison_agent::types::ThreadId;
use serde_json::json;
use support::mock_llm::{MockServer, Round};

use acton_ai::facade::ActonAI;
use acton_ai::policy::ToolPolicy;
use acton_reactive::prelude::*;
use std::path::PathBuf;
use tokio::net::UnixStream;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_util::sync::CancellationToken;

// =============================================================================
// Harness
// =============================================================================

/// The agent side of a connected pair, with the handles a test needs to look
/// behind the protocol.
struct Agent {
    runtime: ActorRuntime,
    supervisor: ActorHandle,
    _conn: ActorHandle,
}

impl Agent {
    /// Asks the supervisor for a session's actor.
    async fn find(&self, thread_id: &ThreadId) -> Option<ActorHandle> {
        self.supervisor
            .ask(FindThread {
                thread_id: thread_id.clone(),
            })
            .await
            .map(|lookup: ThreadLookup| lookup.handle)
            .unwrap_or_default()
    }

    /// Stops everything. Called explicitly so a test failure does not leave a
    /// runtime running under the harness.
    async fn shutdown(mut self) {
        let _ = self.runtime.shutdown_all().await;
    }
}

/// A config with the defaults a test wants: no auto-approval, so every tool
/// call is visible as a protocol round-trip.
fn strict_config(timeout_secs: u64) -> GarrisonConfig {
    rooted_config(timeout_secs, project_root())
}

/// The same, confined to a directory of the test's choosing.
fn rooted_config(timeout_secs: u64, root: PathBuf) -> GarrisonConfig {
    let mut config = GarrisonConfig::default();
    config.approval.timeout_secs = timeout_secs;
    config.approval.auto_approve.clear();
    config.threads.project_root = Some(root);
    config
}

/// A throwaway project root, removed when the test ends.
struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("garrison-protocol-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the test root must be creatable");
        Self {
            path: path.canonicalize().expect("the test root must resolve"),
        }
    }

    fn write(&self, name: &str, contents: &str) {
        std::fs::write(self.path.join(name), contents).expect("the fixture must be writable");
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.path.join(name)).expect("the file must be readable")
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A round in which the model calls `apply_patch` with this text.
fn patch_call(id: &str, patch: &str) -> Round {
    Round::tool_call(id, "apply_patch", json!({ "patch": patch }))
}

/// An absolute directory every test can name as a session root.
fn project_root() -> PathBuf {
    std::env::current_dir().expect("a test process must have a working directory")
}

/// Brings up the whole agent over a socket pair and returns a connected
/// client.
async fn connect(base_url: &str, config: &GarrisonConfig) -> (Agent, AgentClient) {
    let ai = ActonAI::builder()
        .app_name("garrison-agent-test")
        .with_builtin_tools(&["calculate"])
        .ollama_at(base_url, "test-model")
        .tool_policy(ToolPolicy::new().on_approval(approval::approval_hook))
        .launch()
        .await
        .expect("the test runtime must launch");

    // One runtime, acton-ai's own: the router lives on its broker.
    let setup = launch::build_setup(&ai, config)
        .await
        .expect("the test setup must build");
    let supervisor = setup.supervisor.clone();
    let mut runtime = ai.runtime().clone();

    let (agent_side, client_side) = UnixStream::pair().expect("a socket pair must be creatable");
    let (read_half, write_half) = tokio::io::split(agent_side);
    let conn = server::accept_split(
        &mut runtime,
        read_half,
        write_half,
        setup,
        CancellationToken::new(),
    )
    .await;

    (
        Agent {
            runtime,
            supervisor,
            _conn: conn,
        },
        AgentClient::from_stream(client_side),
    )
}

/// Handshakes and opens a session, which every test past the first one needs.
async fn open_session(client: &mut AgentClient) -> acp::SessionId {
    open_session_at(client, project_root()).await
}

/// The same, rooted somewhere the test chose.
async fn open_session_at(client: &mut AgentClient, cwd: PathBuf) -> acp::SessionId {
    client
        .initialize("integration-test")
        .await
        .expect("the handshake must succeed");
    client
        .new_session(cwd)
        .await
        .expect("a session must open")
        .session_id
}

/// An [`Interactions`] that records what it saw and answers with a fixed
/// option id.
#[derive(Debug)]
struct Scripted {
    answer: &'static str,
    text: String,
    asked: Vec<String>,
    tool_calls: Vec<(String, acp::ToolCallStatus)>,
}

impl Scripted {
    fn answering(answer: &'static str) -> Self {
        Self {
            answer,
            text: String::new(),
            asked: Vec::new(),
            tool_calls: Vec::new(),
        }
    }
}

impl Interactions for Scripted {
    fn update(&mut self, notification: &acp::SessionNotification) {
        if let Some(text) = update_text(notification) {
            self.text.push_str(text);
        }
        match &notification.update {
            acp::SessionUpdate::ToolCall(call) => self
                .tool_calls
                .push((call.tool_call_id.0.to_string(), call.status)),
            acp::SessionUpdate::ToolCallUpdate(update) => {
                if let Some(status) = update.fields.status {
                    self.tool_calls
                        .push((update.tool_call_id.0.to_string(), status));
                }
            }
            _ => {}
        }
    }

    fn permission(
        &mut self,
        request: &acp::RequestPermissionRequest,
    ) -> acp::RequestPermissionOutcome {
        self.asked.push(
            request
                .tool_call
                .fields
                .title
                .clone()
                .unwrap_or_else(|| request.tool_call.tool_call_id.0.to_string()),
        );
        acp::RequestPermissionOutcome::Selected(acp::SelectedPermissionOutcome::new(self.answer))
    }
}

/// One round that asks for a calculation, then one that answers in prose.
fn calculate_then_answer() -> Vec<Round> {
    vec![
        Round::tool_call("call-1", "calculate", json!({"expression": "2 + 2"})),
        Round::text("The answer is 4.").with_usage(11, 7),
    ]
}

/// Reads frames until the agent asks for permission, returning the request id
/// and leaving it deliberately unanswered.
async fn wait_for_permission(client: &mut AgentClient) -> RequestId {
    loop {
        match client
            .next_frame()
            .await
            .expect("the agent must keep talking")
        {
            Inbound::Request { id, method, .. }
                if method == acp::method::SESSION_REQUEST_PERMISSION =>
            {
                return id
            }
            other => {
                assert!(
                    !matches!(other, Inbound::Response { .. }),
                    "the turn answered before it asked for permission: {other:?}"
                );
            }
        }
    }
}

/// Waits for the mock server to report that it served round `index`.
async fn wait_for_round(rounds: &mut UnboundedReceiver<usize>, index: usize) {
    while let Some(served) = rounds.recv().await {
        if served == index {
            return;
        }
    }
    panic!("the mock server closed before serving round {index}");
}

// =============================================================================
// Handshake
// =============================================================================

#[tokio::test]
async fn the_handshake_agrees_a_version_and_states_capabilities() {
    let server = MockServer::start(Vec::new()).await;
    let (agent, mut client) = connect(server.base_url(), &strict_config(300)).await;

    let response = client
        .initialize("integration-test")
        .await
        .expect("the handshake must succeed");

    assert_eq!(response.protocol_version, acp::PROTOCOL_VERSION);
    assert!(response.agent_capabilities.load_session);
    assert!(!response.agent_capabilities.prompt_capabilities.image);
    assert_eq!(jsonrpc::JSONRPC_VERSION, "2.0");

    agent.shutdown().await;
}

#[tokio::test]
async fn a_session_cannot_be_opened_before_the_handshake() {
    let server = MockServer::start(Vec::new()).await;
    let (agent, mut client) = connect(server.base_url(), &strict_config(300)).await;

    let refusal = client
        .request::<_, acp::NewSessionResponse>(
            acp::method::SESSION_NEW,
            &acp::NewSessionRequest::new(project_root()),
            &mut Quiet,
        )
        .await
        .expect_err("an uninitialized connection must be refused");

    assert!(
        refusal.to_string().contains("-32010"),
        "expected the not-initialized code, got: {refusal}"
    );

    agent.shutdown().await;
}

// =============================================================================
// The session boundary
// =============================================================================

#[tokio::test]
async fn a_session_rooted_outside_the_approved_tree_is_refused() {
    // The whole point of a configured root: a client cannot pick the host's
    // filesystem and get a session pointed at it.
    let approved = TempRoot::new("boundary-approved");
    let elsewhere = TempRoot::new("boundary-elsewhere");
    let server = MockServer::start(Vec::new()).await;
    let (agent, mut client) = connect(
        server.base_url(),
        &rooted_config(300, approved.path.clone()),
    )
    .await;

    client
        .initialize("integration-test")
        .await
        .expect("the handshake must succeed");

    let refusal = client
        .new_session(elsewhere.path.clone())
        .await
        .expect_err("a root outside the approved tree must be refused");

    assert!(
        refusal.to_string().contains("outside the approved roots"),
        "the refusal should name the boundary, got: {refusal}"
    );

    agent.shutdown().await;
}

#[tokio::test]
async fn a_session_rooted_under_the_approved_root_is_accepted() {
    let approved = TempRoot::new("boundary-nested");
    let nested = approved.path.join("workspace");
    std::fs::create_dir_all(&nested).expect("the nested root must be creatable");
    let server = MockServer::start(Vec::new()).await;
    let (agent, mut client) = connect(
        server.base_url(),
        &rooted_config(300, approved.path.clone()),
    )
    .await;

    let session_id = open_session_at(&mut client, nested).await;
    assert!(!session_id.to_string().is_empty());

    agent.shutdown().await;
}

#[tokio::test]
async fn traversal_out_of_the_approved_root_is_refused() {
    let approved = TempRoot::new("boundary-traversal");
    let nested = approved.path.join("workspace");
    std::fs::create_dir_all(&nested).expect("the nested root must be creatable");
    let server = MockServer::start(Vec::new()).await;
    let (agent, mut client) = connect(
        server.base_url(),
        &rooted_config(300, approved.path.clone()),
    )
    .await;

    client
        .initialize("integration-test")
        .await
        .expect("the handshake must succeed");

    let refusal = client
        .new_session(nested.join("..").join(".."))
        .await
        .expect_err("`..` must be resolved before the boundary is checked");

    assert!(
        refusal.to_string().contains("outside the approved roots"),
        "got: {refusal}"
    );

    agent.shutdown().await;
}

#[tokio::test]
async fn a_second_workspace_is_reachable_only_once_an_administrator_approves_it() {
    let approved = TempRoot::new("boundary-primary");
    let second = TempRoot::new("boundary-second");
    let server = MockServer::start(Vec::new()).await;

    let mut config = rooted_config(300, approved.path.clone());
    config.threads.workspace_roots = vec![second.path.clone()];
    let (agent, mut client) = connect(server.base_url(), &config).await;

    let session_id = open_session_at(&mut client, second.path.clone()).await;
    assert!(!session_id.to_string().is_empty());

    agent.shutdown().await;
}

// =============================================================================
// A plain turn
// =============================================================================

#[tokio::test]
async fn a_prompt_streams_its_answer_and_reports_usage() {
    let server = MockServer::start(vec![Round::text("Hello back.").with_usage(3, 5)]).await;
    let (agent, mut client) = connect(server.base_url(), &strict_config(300)).await;
    let session_id = open_session(&mut client).await;

    let mut watcher = Scripted::answering(acp::OPTION_REJECT);
    let response = client
        .prompt(session_id, "hello", &mut watcher)
        .await
        .expect("the turn must complete");

    assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
    assert_eq!(watcher.text, "Hello back.");
    assert!(watcher.asked.is_empty(), "no tool, so nothing to approve");

    let meta = response.meta.expect("the turn must report its usage");
    let usage = meta
        .get(acp::ext::META_KEY)
        .expect("usage travels under the garrison key");
    assert_eq!(
        usage
            .get("promptTokens")
            .and_then(serde_json::Value::as_u64),
        Some(3)
    );
    assert_eq!(
        usage
            .get("completionTokens")
            .and_then(serde_json::Value::as_u64),
        Some(5)
    );
    assert!(usage
        .get("turnId")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|id| !id.is_empty()));

    agent.shutdown().await;
}

// =============================================================================
// Approval round-trip
// =============================================================================

#[tokio::test]
async fn an_approved_tool_call_runs_and_the_turn_finishes() {
    let server = MockServer::start(calculate_then_answer()).await;
    let (agent, mut client) = connect(server.base_url(), &strict_config(300)).await;
    let session_id = open_session(&mut client).await;

    let mut watcher = Scripted::answering(acp::OPTION_ALLOW_ONCE);
    let response = client
        .prompt(session_id, "what is 2 + 2?", &mut watcher)
        .await
        .expect("the turn must complete");

    assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
    assert_eq!(watcher.asked.len(), 1, "the one tool call was asked about");
    assert_eq!(watcher.text, "The answer is 4.");
    assert!(
        watcher
            .tool_calls
            .contains(&("call-1".to_string(), acp::ToolCallStatus::Completed)),
        "an approved call must report success: {:?}",
        watcher.tool_calls
    );
    assert_eq!(
        server.request_count(),
        2,
        "the tool result went back to the model"
    );

    agent.shutdown().await;
}

#[tokio::test]
async fn a_rejected_tool_call_is_refused_and_the_model_is_told() {
    let server = MockServer::start(calculate_then_answer()).await;
    let (agent, mut client) = connect(server.base_url(), &strict_config(300)).await;
    let session_id = open_session(&mut client).await;

    let mut watcher = Scripted::answering(acp::OPTION_REJECT);
    let response = client
        .prompt(session_id, "what is 2 + 2?", &mut watcher)
        .await
        .expect("a refusal ends the turn normally, not with an error");

    assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
    assert_eq!(watcher.asked.len(), 1);
    assert!(
        watcher
            .tool_calls
            .contains(&("call-1".to_string(), acp::ToolCallStatus::Failed)),
        "a refused call must report failure: {:?}",
        watcher.tool_calls
    );

    // The refusal is fed back as a tool result, so the model gets another
    // round to react to it rather than the turn dying.
    assert_eq!(server.request_count(), 2);
    let last = server.requests().pop().expect("two requests were made");
    let transcript = last.to_string();
    assert!(
        transcript.contains(approval::REJECTED_REASON),
        "the refusal reason must reach the model: {transcript}"
    );

    agent.shutdown().await;
}

#[tokio::test]
async fn allow_always_answers_the_second_call_without_asking_again() {
    let server = MockServer::start(vec![
        Round::tool_call("call-1", "calculate", json!({"expression": "2 + 2"})),
        Round::tool_call("call-2", "calculate", json!({"expression": "3 + 3"})),
        Round::text("Four, then six."),
    ])
    .await;
    let (agent, mut client) = connect(server.base_url(), &strict_config(300)).await;
    let session_id = open_session(&mut client).await;

    let mut watcher = Scripted::answering(acp::OPTION_ALLOW_ALWAYS);
    let response = client
        .prompt(session_id, "two sums please", &mut watcher)
        .await
        .expect("the turn must complete");

    assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
    assert_eq!(
        watcher.asked.len(),
        1,
        "the second call is answered from the session's cache"
    );
    assert_eq!(server.request_count(), 3);

    agent.shutdown().await;
}

// =============================================================================
// Cancellation
// =============================================================================

#[tokio::test]
async fn cancelling_while_an_approval_is_open_ends_the_turn() {
    // A timeout long enough that only cancellation can end this turn.
    let server = MockServer::start(calculate_then_answer()).await;
    let (agent, mut client) = connect(server.base_url(), &strict_config(3_600)).await;
    let session_id = open_session(&mut client).await;

    let prompt_id = client
        .send(
            acp::method::SESSION_PROMPT,
            &acp::PromptRequest::new(session_id.clone(), vec![acp::ContentBlock::from("stall")]),
        )
        .await
        .expect("the prompt must send");

    // The permission request arriving is the barrier: it proves the turn is in
    // flight and parked on a human.
    let _unanswered = wait_for_permission(&mut client).await;

    client
        .cancel(session_id)
        .await
        .expect("the cancellation must send");

    let response = loop {
        if let Inbound::Response { id, outcome } =
            client.next_frame().await.expect("the agent must answer")
        {
            if id == prompt_id {
                break outcome.expect("a cancelled turn answers with a result, not an error");
            }
        }
    };

    let response: acp::PromptResponse =
        serde_json::from_value(response).expect("the answer must be a prompt response");
    assert_eq!(response.stop_reason, acp::StopReason::Cancelled);

    agent.shutdown().await;
}

// =============================================================================
// Disconnection
// =============================================================================

#[tokio::test]
async fn a_client_that_vanishes_mid_turn_does_not_wedge_the_session() {
    // An hour-long approval timeout: if the turn continues, it is because the
    // disconnection released the approval, not because anything expired.
    let mut server = MockServer::start(calculate_then_answer()).await;
    let mut rounds = server.rounds();
    let (agent, mut client) = connect(server.base_url(), &strict_config(3_600)).await;
    let session_id = open_session(&mut client).await;
    let thread_id = acp::thread_id(&session_id).expect("the session id must parse");

    client
        .send(
            acp::method::SESSION_PROMPT,
            &acp::PromptRequest::new(session_id, vec![acp::ContentBlock::from("stall")]),
        )
        .await
        .expect("the prompt must send");

    wait_for_permission(&mut client).await;

    // Hang up with the approval still open.
    drop(client);

    // The model being asked a second time is the proof: the parked call was
    // released, denied, and its result fed back into the loop.
    wait_for_round(&mut rounds, 1).await;

    let handle = agent
        .find(&thread_id)
        .await
        .expect("the session must outlive the connection that made it");
    let summary: ThreadSummary = handle
        .ask(DescribeThread)
        .await
        .expect("the session actor must still answer");
    assert_eq!(summary.thread_id, thread_id);

    agent.shutdown().await;
}

// =============================================================================
// Resuming
// =============================================================================

#[tokio::test]
async fn loading_a_session_replays_what_was_said() {
    let server = MockServer::start(vec![Round::text("Noted.")]).await;
    let (agent, mut client) = connect(server.base_url(), &strict_config(300)).await;
    let session_id = open_session(&mut client).await;

    client
        .prompt(session_id.clone(), "remember this", &mut Quiet)
        .await
        .expect("the turn must complete");

    let mut replay = Scripted::answering(acp::OPTION_REJECT);
    let _: acp::LoadSessionResponse = client
        .request(
            acp::method::SESSION_LOAD,
            &acp::LoadSessionRequest::new(session_id, project_root()),
            &mut replay,
        )
        .await
        .expect("the session must load");

    assert!(
        replay.text.contains("remember this") && replay.text.contains("Noted."),
        "the replay must carry both sides: {:?}",
        replay.text
    );

    agent.shutdown().await;
}

// =============================================================================
// apply_patch, end to end
// =============================================================================

#[tokio::test]
async fn a_patch_that_only_creates_files_is_applied_without_asking() {
    let root = TempRoot::new("creates");
    let server = MockServer::start(vec![
        patch_call(
            "call-1",
            "*** Begin Patch\n*** Add File: notes/new.txt\n+one\n+two\n*** End Patch\n",
        ),
        Round::text("Created notes/new.txt."),
    ])
    .await;
    let config = rooted_config(300, root.path.clone());
    let (agent, mut client) = connect(server.base_url(), &config).await;
    let session_id = open_session_at(&mut client, root.path.clone()).await;

    let mut watcher = Scripted::answering(acp::OPTION_REJECT);
    let response = client
        .prompt(session_id, "add a notes file", &mut watcher)
        .await
        .expect("the turn must complete");

    assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
    assert!(
        watcher.asked.is_empty(),
        "creating a new file destroys nothing, so nobody should have been asked",
    );
    assert_eq!(root.read("notes/new.txt"), "one\ntwo\n");

    agent.shutdown().await;
}

#[tokio::test]
async fn a_destructive_patch_is_applied_only_after_the_operator_agrees() {
    let root = TempRoot::new("approved");
    root.write("a.txt", "one\ntwo\nthree\n");
    let server = MockServer::start(vec![
        patch_call(
            "call-1",
            "*** Begin Patch\n\
             *** Update File: a.txt\n\
             @@\n\
             -two\n\
             +TWO\n\
             *** End Patch\n",
        ),
        Round::text("Updated a.txt."),
    ])
    .await;
    let config = rooted_config(300, root.path.clone());
    let (agent, mut client) = connect(server.base_url(), &config).await;
    let session_id = open_session_at(&mut client, root.path.clone()).await;

    let mut watcher = Scripted::answering(acp::OPTION_ALLOW_ONCE);
    let response = client
        .prompt(session_id, "shout the second line", &mut watcher)
        .await
        .expect("the turn must complete");

    assert_eq!(response.stop_reason, acp::StopReason::EndTurn);
    assert_eq!(
        watcher.asked.len(),
        1,
        "an in-place edit must reach a human"
    );
    assert_eq!(root.read("a.txt"), "one\nTWO\nthree\n");

    agent.shutdown().await;
}

#[tokio::test]
async fn a_refused_patch_leaves_the_file_exactly_as_it_was() {
    let root = TempRoot::new("refused");
    root.write("a.txt", "one\ntwo\nthree\n");
    let server = MockServer::start(vec![
        patch_call(
            "call-1",
            "*** Begin Patch\n\
             *** Delete File: a.txt\n\
             *** End Patch\n",
        ),
        Round::text("I was not allowed to delete it."),
    ])
    .await;
    let config = rooted_config(300, root.path.clone());
    let (agent, mut client) = connect(server.base_url(), &config).await;
    let session_id = open_session_at(&mut client, root.path.clone()).await;

    let mut watcher = Scripted::answering(acp::OPTION_REJECT);
    client
        .prompt(session_id, "delete a.txt", &mut watcher)
        .await
        .expect("a refusal ends the turn normally");

    assert_eq!(watcher.asked.len(), 1);
    assert_eq!(
        root.read("a.txt"),
        "one\ntwo\nthree\n",
        "a refused delete must not have run",
    );

    agent.shutdown().await;
}

#[tokio::test]
async fn a_patch_reaching_outside_the_root_is_refused_without_asking_anybody() {
    let root = TempRoot::new("escape");
    let server = MockServer::start(vec![
        patch_call(
            "call-1",
            "*** Begin Patch\n*** Add File: ../escaped.txt\n+hi\n*** End Patch\n",
        ),
        Round::text("That path is outside the project."),
    ])
    .await;
    let config = rooted_config(300, root.path.clone());
    let (agent, mut client) = connect(server.base_url(), &config).await;
    let session_id = open_session_at(&mut client, root.path.clone()).await;

    let mut watcher = Scripted::answering(acp::OPTION_ALLOW_ALWAYS);
    client
        .prompt(session_id, "write outside the project", &mut watcher)
        .await
        .expect("the turn must complete");

    assert!(
        watcher.asked.is_empty(),
        "no operator may authorize a write outside the root, so none is asked",
    );
    assert!(
        !root.path.join("../escaped.txt").exists(),
        "nothing may have been written outside the root",
    );
    assert!(
        watcher
            .tool_calls
            .contains(&("call-1".to_string(), acp::ToolCallStatus::Failed)),
        "the refusal must reach the client as a failed tool call: {:?}",
        watcher.tool_calls,
    );

    agent.shutdown().await;
}
