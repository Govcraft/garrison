//! A session outlives the process that opened it.
//!
//! This is the only test in the tree that starts the real binary. Every other
//! integration test builds the stack in-process and tears it down by shutting
//! actors off, which proves a great deal but cannot prove the one claim this
//! file exists for: that a conversation survives a daemon that is *gone*. So
//! the daemon here is a child process, it is stopped with a signal, and the
//! second daemon is a different process reading the first one's database.
//!
//! `env!("CARGO_BIN_EXE_garrison-agent")` is what makes that cheap: cargo has
//! already built the binary before this test binary runs, so starting it costs
//! a fork rather than a build.
//!
//! # What is faked, and what is not
//!
//! Only the model, and only at the wire. The provider is [`MockServer`],
//! listening on an ephemeral TCP port in *this* process, which both daemons
//! reach over the loopback. Everything else is production: the real socket,
//! the real protocol, the real session store on disk, the real hash-chained
//! audit trail.
//!
//! # Synchronization
//!
//! Startup is read off the daemon's own stdout — it prints its endpoint once
//! the socket is accepting — rather than slept on. Shutdown is awaited on the
//! child's exit status. The one place a duration appears is the poll for the
//! socket file after the banner, and even that is bounded and asserted on.

mod support;

use garrison_agent::client::{AgentClient, Interactions};
use garrison_agent::protocol::acp;
use serde_json::Value;
use std::io::BufRead;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::mock_llm::{MockServer, Round};

// =============================================================================
// Fixture
// =============================================================================

/// A throwaway directory holding both daemons' entire world.
///
/// Config, database, trail, anchor, socket and workspace all live here, so the
/// second daemon inherits the first one's state by reading the same paths and
/// nothing leaks into the developer's own `~/.config/garrison`.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "garrison-sessions-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_nanos())
                .unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("workspace")).expect("the fixture must be creatable");
        std::fs::create_dir_all(root.join("config")).expect("the config dir must be creatable");

        Self {
            root: root.canonicalize().expect("the fixture must resolve"),
        }
    }

    fn workspace(&self) -> PathBuf {
        self.root.join("workspace")
    }

    fn socket(&self) -> PathBuf {
        self.root.join("agent.sock")
    }

    fn database(&self) -> PathBuf {
        self.root.join("sessions.db")
    }

    fn trail(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }

    /// Writes both config files and returns the path to Garrison's.
    ///
    /// The provider is written as an `ollama` type because that is acton-ai's
    /// name for "OpenAI-compatible at a base URL with no key", which is
    /// exactly what the mock is.
    fn write_config(&self, provider_url: &str) -> PathBuf {
        let garrison = self.root.join("garrison.toml");
        std::fs::write(
            &garrison,
            format!(
                "[server]\n\
                 autostart = false\n\
                 \n\
                 [threads]\n\
                 project_root = {workspace:?}\n\
                 \n\
                 [approval]\n\
                 timeout_secs = 120\n\
                 auto_approve = [\"read_file\"]\n\
                 \n\
                 [audit]\n\
                 anchor_path = {anchor:?}\n\
                 \n\
                 [sessions]\n\
                 required = true\n\
                 retain_days = 30\n\
                 sweep_interval_hours = 24\n",
                workspace = self.workspace(),
                anchor = self.root.join("audit-anchor.json"),
            ),
        )
        .expect("garrison.toml must be writable");

        std::fs::write(
            self.root.join("acton-ai.toml"),
            format!(
                "default_provider = \"mock\"\n\
                 \n\
                 [providers.mock]\n\
                 type = \"ollama\"\n\
                 model = \"test-model\"\n\
                 base_url = \"{provider_url}\"\n\
                 timeout_secs = 30\n\
                 context_window_tokens = 32768\n\
                 \n\
                 [audit]\n\
                 path = {trail:?}\n\
                 durability = \"strict\"\n\
                 \n\
                 [checkpoint]\n\
                 db_path = {database:?}\n\
                 policy = \"resume_on_request\"\n\
                 max_resume_attempts = 3\n",
                trail = self.trail(),
                database = self.database().display().to_string(),
            ),
        )
        .expect("acton-ai.toml must be writable");

        garrison
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// =============================================================================
// The daemon, as a process
// =============================================================================

/// A running `garrison-agent serve`, and the means to stop it.
struct Daemon {
    child: Child,
}

impl Daemon {
    /// Starts the binary and returns once its socket is accepting.
    ///
    /// Readiness is the daemon's own "listening on" line, which it prints
    /// after the listener is bound. Waiting on a duration instead would be
    /// both slower and a source of flakes.
    fn start(fixture: &Fixture) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_garrison-agent"))
            .arg("serve")
            .arg("--socket")
            .arg(fixture.socket())
            .arg("--config")
            .arg(fixture.root.join("garrison.toml"))
            .arg("--acton-config")
            .arg(fixture.root.join("acton-ai.toml"))
            // The agent identity and any install record land here rather than
            // in the developer's real config directory.
            .env("XDG_CONFIG_HOME", fixture.root.join("config"))
            .env("XDG_STATE_HOME", fixture.root.join("state"))
            .env("XDG_DATA_HOME", fixture.root.join("data"))
            .env("HOME", &fixture.root)
            .current_dir(&fixture.root)
            .stdout(Stdio::piped())
            // Inherited rather than piped: nextest captures it, so a daemon
            // that refuses to start explains itself in the failure output,
            // and no pipe this test forgets to drain can ever block it.
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the daemon binary must start");

        let stdout = child.stdout.take().expect("stdout was piped");
        let mut reader = std::io::BufReader::new(stdout);
        let mut banner = String::new();
        loop {
            let mut line = String::new();
            let read = reader
                .read_line(&mut line)
                .expect("the daemon's output must be readable");
            assert!(
                read > 0,
                "the daemon exited before it listened; its stderr is above",
            );
            banner.push_str(&line);
            if line.contains("listening on") {
                break;
            }
        }

        // Drained for the rest of the daemon's life, in a thread. Dropping the
        // reader here would close the pipe's read end, and the daemon's own
        // "shutting down" line would then kill it with a broken pipe on the
        // way out — turning every clean stop into a failure.
        std::thread::spawn(move || {
            let mut sink = String::new();
            while reader.read_line(&mut sink).unwrap_or(0) > 0 {
                sink.clear();
            }
        });

        // The banner is printed from the same task that bound the listener, so
        // the socket file is already there; this only guards against a
        // filesystem that has not caught up.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !fixture.socket().exists() {
            assert!(
                Instant::now() < deadline,
                "the daemon announced {banner} but no socket appeared",
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        Self { child }
    }

    /// Stops it the way systemd would, and waits for it to be gone.
    fn stop(mut self) {
        signal(&self.child, "TERM");
        let status = self.child.wait().expect("the daemon must be reapable");
        assert!(
            status.success(),
            "a daemon asked to stop must exit cleanly, got {status}; its stderr is above",
        );
    }

    /// Kills it outright, the way a power cut would.
    ///
    /// This is what leaves a turn interrupted: there is no shutdown, so
    /// nothing clears the open turn from the session's record.
    fn kill(mut self) {
        signal(&self.child, "KILL");
        let _ = self.child.wait();
    }
}

/// Sends one signal to a child process.
///
/// Through `kill(1)` rather than through `libc`, deliberately: this is the
/// only place in the tree that needs to signal anything, and one spawned
/// process in one test is cheaper than a dependency every build pays for.
fn signal(child: &Child, name: &str) {
    let sent = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(child.id().to_string())
        .status()
        .expect("kill(1) must be runnable");
    assert!(sent.success(), "could not send SIG{name} to the daemon");
}

// =============================================================================
// A client that answers nothing
// =============================================================================

/// Records the session updates a turn produced and refuses every permission.
///
/// Every script here auto-approves what it calls, so reaching the operator is
/// a bug in the test rather than a case to handle.
#[derive(Debug, Default)]
struct Watched {
    text: String,
}

impl Interactions for Watched {
    fn update(&mut self, notification: &acp::SessionNotification) {
        if let acp::SessionUpdate::AgentMessageChunk(chunk) = &notification.update {
            if let acp::ContentBlock::Text(text) = &chunk.content {
                self.text.push_str(&text.text);
            }
        }
    }

    fn permission(
        &mut self,
        request: &acp::RequestPermissionRequest,
    ) -> acp::RequestPermissionOutcome {
        panic!(
            "nothing in these scripts should reach the operator: {}",
            request.tool_call.tool_call_id.0
        );
    }
}

/// Connects, handshakes, and hands back a client ready to be prompted.
async fn client_for(fixture: &Fixture) -> AgentClient {
    let mut client = AgentClient::connect(&fixture.socket())
        .await
        .expect("the daemon's socket must accept a client");
    client
        .initialize("session-persistence-test")
        .await
        .expect("the handshake must succeed");
    client
}

/// Everything the daemon says about itself.
async fn status(client: &mut AgentClient) -> acp::GarrisonStatus {
    let value: Value = client
        .request(
            acp::ext::STATUS,
            &serde_json::Value::Object(serde_json::Map::new()),
            &mut Watched::default(),
        )
        .await
        .expect("the status must be answerable");
    serde_json::from_value(value).expect("the status must be Garrison's own shape")
}

// =============================================================================
// The claim
// =============================================================================

/// The whole of issue #3, as one uninterrupted narrative.
///
/// Deliberately one test rather than five. Each step's premise is the previous
/// step's outcome — there is no session to reload until one has been written,
/// and no history to compare until a turn has produced one — and the expensive
/// part is starting two real daemons, not asserting.
#[tokio::test(flavor = "multi_thread")]
async fn a_conversation_survives_the_daemon_that_opened_it() {
    let fixture = Fixture::new("survives");
    // Each turn reads a file before answering. The tool call is not
    // incidental: the audit trail records invocations, so a turn that calls
    // nothing leaves the chain where it was, and this test's claim is that
    // the *record* survives the restart as well as the conversation.
    let notes = fixture.workspace().join("notes.txt");
    std::fs::write(&notes, "41\n").expect("the workspace file must be writable");
    let read = serde_json::json!({ "path": notes.display().to_string() });

    let mock = MockServer::start(vec![
        Round::tool_call("call-1", "read_file", read.clone()),
        Round::text("Noted: the number is 41.").with_usage(120, 8),
        Round::tool_call("call-2", "read_file", read),
        Round::text("You told me 41.").with_usage(180, 6),
    ])
    .await;
    fixture.write_config(mock.base_url());

    // --- The first daemon ------------------------------------------------
    let first = Daemon::start(&fixture);
    let mut client = client_for(&fixture).await;

    let session_id = client
        .new_session(fixture.workspace())
        .await
        .expect("a session must open")
        .session_id;

    let mut watched = Watched::default();
    client
        .prompt(session_id.clone(), "Remember the number 41.", &mut watched)
        .await
        .expect("the first turn must complete");
    assert!(
        watched.text.contains("41"),
        "the model's answer must reach the client, got {:?}",
        watched.text,
    );

    let before = status(&mut client).await;
    let store = before
        .session_store
        .as_ref()
        .expect("a daemon with [checkpoint] armed must report its session store");
    assert!(store.healthy, "the store must be answering");
    assert_eq!(store.sessions, 1, "the session must have been written down");
    assert_eq!(store.interrupted, 0, "nothing was interrupted yet");
    let chain_head = before
        .audit
        .chain_head
        .clone()
        .expect("a strict trail must have a head after a turn");

    drop(client);
    first.stop();

    // The process is gone. Everything below is a different daemon.
    assert!(
        !fixture.socket().exists(),
        "a daemon that shut down must unlink its socket",
    );

    // --- The second daemon -----------------------------------------------
    let second = Daemon::start(&fixture);
    let mut client = client_for(&fixture).await;

    let listed = client
        .request::<_, acp::ListSessionsResponse>(
            acp::method::SESSION_LIST,
            &acp::ListSessionsRequest::new().cwd(fixture.workspace()),
            &mut Watched::default(),
        )
        .await
        .expect("sessions must be listable");
    assert!(
        listed
            .sessions
            .iter()
            .any(|info| info.session_id == session_id),
        "the stored session must be offered back: {listed:?}",
    );

    client
        .load_session(
            session_id.clone(),
            fixture.workspace(),
            &mut Watched::default(),
        )
        .await
        .expect("the stored session must load into a daemon that never opened it");

    // The proof that the *history* came back, not merely the identity: the
    // provider is shown the earlier exchange on the very next turn.
    let mut watched = Watched::default();
    client
        .prompt(
            session_id.clone(),
            "What number did I give you?",
            &mut watched,
        )
        .await
        .expect("a restored session must be promptable");

    let last = mock
        .requests()
        .last()
        .cloned()
        .expect("the second daemon must have called the provider");
    let sent = last.to_string();
    assert!(
        sent.contains("Remember the number 41."),
        "the restored turn must carry the history the first daemon wrote: {sent}",
    );
    assert!(
        sent.contains("Noted: the number is 41."),
        "including the model's own earlier answer: {sent}",
    );

    // And the record is one record, not two. The second daemon started over
    // the first one's trail without refusing — which it would have done, with
    // exit 2, had the anchor disagreed — and then extended it rather than
    // beginning a new chain.
    let after = status(&mut client).await;
    let extended = after
        .audit
        .chain_head
        .clone()
        .expect("the restarted daemon must report a head too");
    assert_ne!(
        extended, chain_head,
        "the second daemon's tool call must have advanced the chain",
    );
    let trail = std::fs::read_to_string(fixture.trail()).expect("the trail must be readable");
    assert!(
        trail.contains(&chain_head),
        "the first daemon's head must still be in the chain the second extended",
    );
    assert_eq!(
        trail.lines().count(),
        2,
        "one entry per tool call, across both daemons: {trail}",
    );

    drop(client);
    second.stop();
}

/// A turn the daemon died in the middle of is never silently restarted.
///
/// The kill is what makes this honest: `SIGKILL` gives the daemon no chance to
/// clear the open turn from the session's record, which is exactly the state a
/// crash or a power cut leaves and exactly the state the resume path exists
/// for.
#[tokio::test(flavor = "multi_thread")]
async fn a_turn_the_daemon_died_in_blocks_the_session_until_it_is_settled() {
    let fixture = Fixture::new("interrupted");
    // A tool call the config does not auto-approve. The daemon runs the turn,
    // asks the operator, and parks — and this test's client never answers, so
    // the turn is genuinely mid-flight and stays there until it is killed.
    // That is what makes the kill deterministic rather than a race with an
    // answer already on its way back.
    let mut mock = MockServer::start(vec![Round::tool_call(
        "call-1",
        "write_file",
        serde_json::json!({
            "path": fixture.workspace().join("out.txt").display().to_string(),
            "content": "never written",
        }),
    )])
    .await;
    let mut rounds = mock.rounds();
    fixture.write_config(mock.base_url());

    let first = Daemon::start(&fixture);
    let mut client = client_for(&fixture).await;
    let session_id = client
        .new_session(fixture.workspace())
        .await
        .expect("a session must open")
        .session_id;

    // Sent raw, and never awaited. Awaiting the prompt would mean this task
    // reading frames, and the point is to abandon the turn mid-flight.
    client
        .send(
            acp::method::SESSION_PROMPT,
            &acp::PromptRequest::new(
                session_id.clone(),
                vec![acp::ContentBlock::from("Start something long.")],
            ),
        )
        .await
        .expect("the prompt must reach the daemon");

    // The provider having been called proves the turn passed admission, which
    // is where the open turn is written to the store.
    rounds
        .recv()
        .await
        .expect("the daemon must have reached the provider");

    // Killed with the client still connected and still silent: the daemon is
    // parked on a permission request nobody is going to answer, so the turn
    // cannot have finished, and `SIGKILL` gives it no chance to tidy up.
    first.kill();
    drop(client);

    // --- The daemon that finds the wreckage -------------------------------
    let second = Daemon::start(&fixture);
    let mut client = client_for(&fixture).await;

    let loaded = client
        .load_session(
            session_id.clone(),
            fixture.workspace(),
            &mut Watched::default(),
        )
        .await
        .expect("the session must still load");
    let interrupted = loaded
        .meta
        .as_ref()
        .and_then(|meta| meta.get(acp::ext::META_KEY))
        .cloned()
        .expect("a session holding an interrupted turn must say so on load");
    let interrupted: acp::LoadMeta =
        serde_json::from_value(interrupted).expect("the metadata must be Garrison's own shape");
    assert_eq!(
        interrupted.interrupted_turn.prompt, "Start something long.",
        "the operator must be told what was cut short",
    );

    let reported = status(&mut client).await;
    assert_eq!(
        reported
            .session_store
            .as_ref()
            .expect("the store must be reported")
            .interrupted,
        1,
        "the status must count the blocked session",
    );

    // Fail closed: a new prompt does not quietly start over the top of it.
    let refused = client
        .prompt(
            session_id.clone(),
            "never mind, do this instead",
            &mut Watched::default(),
        )
        .await
        .expect_err("a session with an interrupted turn must refuse a new prompt");
    assert!(
        refused.to_string().contains("(code -32019)"),
        "the refusal must be TURN_INTERRUPTED, got {refused}",
    );

    // And the escape hatch: the operator says the work is not wanted, and the
    // session is promptable again.
    let abandoned = client
        .abandon(session_id.clone())
        .await
        .expect("an interrupted turn must be abandonable");
    assert_eq!(
        abandoned.turn_id, interrupted.interrupted_turn.turn_id,
        "the turn abandoned must be the turn reported",
    );

    let again = client
        .abandon(session_id.clone())
        .await
        .expect_err("there is nothing left to abandon");
    assert!(
        again.to_string().contains("(code -32021)"),
        "a second abandon must be refused with NO_INTERRUPTED_TURN, got {again}",
    );

    drop(client);
    second.stop();
}
