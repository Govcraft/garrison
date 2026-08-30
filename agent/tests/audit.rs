//! Durability, degradation and anchoring, end to end over a real socket.
//!
//! Every test here brings up the production stack — a real `ClientConn`, a
//! real `Thread`, a real acton-ai turn over a real hash-chained trail on disk
//! — and then breaks the trail underneath it. Only the model is faked, and it
//! is faked at the wire.
//!
//! # Breaking a trail without root
//!
//! The writer holds the trail's lock on an open descriptor and appends *by
//! path*, so replacing the file with a directory of the same name is exactly
//! what a disk yanked out mid-session looks like: the next open fails and the
//! lock is untouched. This is the technique acton-ai's own `audit_trail.rs`
//! uses, and unlike `chattr +i` or filling a tmpfs it needs no privileges, so
//! it runs in an ordinary `cargo nextest` on any machine.
//!
//! # No sleeps
//!
//! Nothing waits on a duration. The anchor is taken by asking the keeper
//! [`AnchorNow`] rather than by waiting for the turn-end broadcast to land,
//! so a test never races the broker.

mod support;

use garrison_agent::admission::{Admission, AdmitTurn};
use garrison_agent::approval;
use garrison_agent::audit::{AnchorNow, AnchorOutcome, AuditState, VerifyOutcome};
use garrison_agent::client::{AgentClient, Interactions};
use garrison_agent::config::{AnchorMismatchAction, GarrisonConfig};
use garrison_agent::launch;
use garrison_agent::protocol::acp;
use garrison_agent::protocol::server;
use garrison_agent::types::{ThreadId, TurnId};
use serde_json::json;
use support::mock_llm::{MockServer, Round};

use acton_ai::audit::{AuditConfig, AuditDurability};
use acton_ai::facade::ActonAI;
use acton_ai::policy::ToolPolicy;
use acton_reactive::prelude::*;
use std::path::{Path, PathBuf};
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;

// =============================================================================
// Harness
// =============================================================================

/// A throwaway directory holding a session root, a trail and an anchor.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "garrison-audit-{name}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_nanos())
                .unwrap_or_default()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("workspace")).expect("the fixture must be creatable");
        Self {
            root: root.canonicalize().expect("the fixture must resolve"),
        }
    }

    /// Where sessions are rooted, and where the model's `write_file` lands.
    fn workspace(&self) -> PathBuf {
        self.root.join("workspace")
    }

    fn trail(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }

    fn anchor(&self) -> PathBuf {
        self.root.join("audit-anchor.json")
    }

    fn wrote(&self, name: &str) -> bool {
        self.workspace().join(name).exists()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Makes the trail unappendable from under a running writer.
///
/// See the module docs: a directory in the file's place fails the next open
/// and leaves the lock alone, which is what a failed disk does.
fn make_unappendable(path: &Path) {
    if path.is_file() {
        std::fs::remove_file(path).expect("the trail can be removed");
        std::fs::create_dir(path).expect("a directory can take its place");
    }
}

/// Puts a writable trail back where an unappendable one was.
fn make_appendable_again(path: &Path) {
    if path.is_dir() {
        std::fs::remove_dir_all(path).expect("the directory can be removed");
    }
}

/// Garrison's config for these tests: rooted at the workspace, anchored in the
/// fixture, and auto-approving the two tools the scripts call so a refusal is
/// never confused with an unanswered permission request.
fn config_for(fixture: &Fixture, durability: Option<AuditDurability>) -> GarrisonConfig {
    let mut config = GarrisonConfig::default();
    config.threads.project_root = Some(fixture.workspace());
    config.approval.auto_approve = vec!["write_file".to_string(), "read_file".to_string()];
    config.audit.durability = durability;
    config.audit.anchor_path = Some(fixture.anchor());
    config
}

/// An acton-ai runtime auditing to the fixture's trail.
async fn audited_runtime(
    base_url: &str,
    fixture: &Fixture,
    durability: AuditDurability,
) -> ActonAI {
    ActonAI::builder()
        .app_name("garrison-audit-test")
        .with_builtin_tools(&["write_file", "read_file"])
        .ollama_at(base_url, "test-model")
        .tool_policy(ToolPolicy::new().on_approval(approval::approval_hook))
        .audit(AuditConfig::new(fixture.trail()).with_durability(durability))
        .launch()
        .await
        .expect("the audited runtime must launch")
}

/// The agent side, plus the handles a test needs to look behind the protocol.
struct Agent {
    runtime: ActorRuntime,
    keeper: ActorHandle,
    _conn: ActorHandle,
}

impl Agent {
    /// Writes the anchor now and returns what it vouches for.
    async fn anchor_now(&self) -> AnchorOutcome {
        self.keeper
            .ask(AnchorNow)
            .await
            .expect("the anchor keeper must answer")
    }

    async fn shutdown(mut self) {
        let _ = self.runtime.shutdown_all().await;
    }
}

/// Brings the whole audited stack up over a socket pair.
async fn connect(ai: &ActonAI, config: &GarrisonConfig) -> (Agent, AgentClient) {
    let setup = launch::build_setup(ai, config, None)
        .await
        .expect("the audited setup must build");
    // The keeper is both a gate and a describer; the gate list is where a
    // subsystem that can refuse a turn lands, so that is where it is found.
    let keeper = setup
        .defaults
        .gates
        .first()
        .cloned()
        .expect("an armed trail must install its keeper as a gate");
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
            keeper,
            _conn: conn,
        },
        AgentClient::from_stream(client_side),
    )
}

/// Handshakes and opens a session rooted at the fixture's workspace.
async fn open_session(client: &mut AgentClient, fixture: &Fixture) -> acp::SessionId {
    client
        .initialize("audit-test")
        .await
        .expect("the handshake must succeed");
    client
        .new_session(fixture.workspace())
        .await
        .expect("a session must open")
        .session_id
}

/// Records every tool call's final status and the text that closed it.
#[derive(Debug, Default)]
struct Watched {
    finished: Vec<(String, acp::ToolCallStatus, String)>,
}

impl Watched {
    /// What closed the call with this id.
    fn outcome(&self, tool_call_id: &str) -> (acp::ToolCallStatus, String) {
        self.finished
            .iter()
            .find(|(id, ..)| id == tool_call_id)
            .map(|(_, status, text)| (*status, text.clone()))
            .unwrap_or_else(|| panic!("no tool call {tool_call_id} finished: {:?}", self.finished))
    }
}

impl Interactions for Watched {
    fn update(&mut self, notification: &acp::SessionNotification) {
        let acp::SessionUpdate::ToolCallUpdate(update) = &notification.update else {
            return;
        };
        let Some(status) = update.fields.status else {
            return;
        };
        let text = update
            .fields
            .content
            .as_ref()
            .map(|blocks| format!("{blocks:?}"))
            .unwrap_or_default();
        self.finished
            .push((update.tool_call_id.0.to_string(), status, text));
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

/// Two writes and a read: the first write breaks nothing, the second is the
/// one a strict trail must refuse, and the read proves the refusal is about
/// mutation rather than about tools in general.
///
/// The paths are absolute because the builtins insist on it, and they are
/// under the session root because the session boundary insists on that.
fn write_write_read(fixture: &Fixture) -> Vec<Round> {
    let first = fixture.workspace().join("first.txt");
    let second = fixture.workspace().join("second.txt");

    vec![
        Round::tool_call(
            "call-1",
            "write_file",
            json!({"path": first, "content": "one"}),
        ),
        Round::tool_call(
            "call-2",
            "write_file",
            json!({"path": second, "content": "two"}),
        ),
        Round::tool_call("call-3", "read_file", json!({"path": first})),
        Round::text("done"),
    ]
}

/// Asks `_garrison/status` and returns the audit block.
async fn audit_status(client: &mut AgentClient) -> acp::AuditStatus {
    let status: acp::GarrisonStatus = client
        .request(acp::ext::STATUS, &json!({}), &mut Watched::default())
        .await
        .expect("status must answer");
    status.audit
}

// =============================================================================
// Strict mode refuses; the default records what it can
// =============================================================================

#[tokio::test]
async fn a_strict_trail_refuses_a_mutating_call_once_the_writer_has_failed() {
    let fixture = Fixture::new("strict");
    let server = MockServer::start(write_write_read(&fixture)).await;
    let ai = audited_runtime(server.base_url(), &fixture, AuditDurability::Strict).await;
    let (agent, mut client) =
        connect(&ai, &config_for(&fixture, Some(AuditDurability::Strict))).await;
    let session = open_session(&mut client, &fixture).await;

    // The disk goes away between opening the session and running the turn.
    make_unappendable(&fixture.trail());

    let mut watched = Watched::default();
    client
        .prompt(
            session.clone(),
            "write two files and read one",
            &mut watched,
        )
        .await
        .expect("the turn itself completes; it is the calls inside it that are refused");

    // The first call ran: its record is what failed, and the tool had already
    // done its work by then.
    let (first, first_text) = watched.outcome("call-1");
    assert_eq!(first, acp::ToolCallStatus::Completed, "{first_text}");
    assert!(fixture.wrote("first.txt"), "the first write landed");

    // The second is refused, before it runs, because it cannot be recorded.
    let (second, reason) = watched.outcome("call-2");
    assert_eq!(
        second,
        acp::ToolCallStatus::Failed,
        "a mutating call over a degraded strict writer must be refused"
    );
    assert!(
        reason.contains("audit trail is degraded"),
        "the refusal must say why: {reason}"
    );
    assert!(
        !fixture.wrote("second.txt"),
        "a refused write must not have written anything"
    );

    // A read is not refused: refusing it protects no record that matters.
    let (third, _) = watched.outcome("call-3");
    assert_eq!(third, acp::ToolCallStatus::Completed);

    // And the operator can see all of it in one place.
    let status = audit_status(&mut client).await;
    assert_eq!(status.state, AuditState::Degraded);
    assert_eq!(status.durability.as_deref(), Some("strict"));
    assert!(status.failures >= 1, "{status:?}");
    assert_eq!(status.first_failed_sequence, Some(1));
    assert!(status.last_error.is_some());
    assert!(status.degraded_since.is_some());

    make_appendable_again(&fixture.trail());
    agent.shutdown().await;
}

#[tokio::test]
async fn a_degraded_strict_writer_refuses_the_next_turn_outright() {
    let fixture = Fixture::new("strict-gate");
    let mut rounds = write_write_read(&fixture);
    rounds.extend(write_write_read(&fixture));
    let server = MockServer::start(rounds).await;
    let ai = audited_runtime(server.base_url(), &fixture, AuditDurability::Strict).await;
    let (agent, mut client) =
        connect(&ai, &config_for(&fixture, Some(AuditDurability::Strict))).await;
    let session = open_session(&mut client, &fixture).await;

    make_unappendable(&fixture.trail());

    // The first turn is admitted: nothing had failed yet when the gate was
    // asked. It is inside the turn that the writer breaks.
    client
        .prompt(session.clone(), "first", &mut Watched::default())
        .await
        .expect("the first turn is admitted");

    // The second is not admitted at all. The gate answers before a single
    // tool runs, which is the difference between refusing a call and refusing
    // a turn.
    let refusal = client
        .prompt(session, "second", &mut Watched::default())
        .await
        .expect_err("a degraded strict writer must refuse the whole turn");
    let text = refusal.to_string();

    assert!(
        text.contains("-32017"),
        "the refusal must carry the frozen audit code: {text}"
    );
    assert_eq!(
        server.request_count(),
        4,
        "a refused turn must never reach the model",
    );

    make_appendable_again(&fixture.trail());
    agent.shutdown().await;
}

#[tokio::test]
async fn the_default_durability_records_what_it_can_and_refuses_nothing() {
    let fixture = Fixture::new("best-effort");
    let mut rounds = write_write_read(&fixture);
    rounds.extend(write_write_read(&fixture));
    let server = MockServer::start(rounds).await;
    let ai = audited_runtime(server.base_url(), &fixture, AuditDurability::BestEffort).await;
    let (agent, mut client) = connect(
        &ai,
        &config_for(&fixture, Some(AuditDurability::BestEffort)),
    )
    .await;
    let session = open_session(&mut client, &fixture).await;

    make_unappendable(&fixture.trail());

    let mut watched = Watched::default();
    client
        .prompt(
            session.clone(),
            "write two files and read one",
            &mut watched,
        )
        .await
        .expect("the turn completes");

    // The same failure, the same trail, the opposite behaviour: this is what
    // proves the refusal above comes from `durability = "strict"` and not
    // merely from the disk having failed.
    assert_eq!(watched.outcome("call-1").0, acp::ToolCallStatus::Completed);
    assert_eq!(
        watched.outcome("call-2").0,
        acp::ToolCallStatus::Completed,
        "best effort must not refuse a mutating call"
    );
    assert!(fixture.wrote("first.txt") && fixture.wrote("second.txt"));

    // A second turn still runs: the gate admits everything under best effort.
    client
        .prompt(session, "again", &mut Watched::default())
        .await
        .expect("best effort admits the next turn too");

    // The failure is still reported. Not refusing is not the same as not
    // noticing, and an operator must still be told the record is incomplete.
    let status = audit_status(&mut client).await;
    assert_eq!(status.state, AuditState::Degraded);
    assert_eq!(status.durability.as_deref(), Some("best_effort"));
    assert!(status.failures >= 1);

    make_appendable_again(&fixture.trail());
    agent.shutdown().await;
}

// =============================================================================
// The anchor: what a hash chain cannot notice about itself
// =============================================================================

#[tokio::test]
async fn a_finished_turn_re_anchors_the_head_without_being_told_to() {
    // The keeper learns a turn ended by subscribing to acton-ai's turn
    // lifecycle, not by a message the session sends it. Nothing on the turn
    // path knows the keeper exists, which is what lets a second subsystem
    // want the same moment without editing the turn path again.
    let fixture = Fixture::new("subscribed");
    let server = MockServer::start(write_write_read(&fixture)).await;
    let ai = audited_runtime(server.base_url(), &fixture, AuditDurability::Strict).await;
    let (agent, mut client) =
        connect(&ai, &config_for(&fixture, Some(AuditDurability::Strict))).await;
    let session = open_session(&mut client, &fixture).await;

    // Launch anchored an empty trail, so anything above zero came from the
    // broadcast rather than from the startup anchor.
    let launched = garrison_agent::audit::anchor::read(&fixture.anchor())
        .expect("the startup anchor is readable")
        .expect("launch anchors before the first turn");
    assert_eq!(launched.sequence, 0, "a fresh trail starts at genesis");

    client
        .prompt(
            session,
            "write two files and read one",
            &mut Watched::default(),
        )
        .await
        .expect("the turn completes");

    // The one place a test waits: a broadcast has no reply to await, so the
    // only honest synchronization is to watch for its effect. The deadline is
    // an upper bound on a failure, never a delay in the passing case.
    let anchored = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let anchor = garrison_agent::audit::anchor::read(&fixture.anchor())
                .expect("the anchor stays readable");
            if let Some(anchor) = anchor.filter(|anchor| anchor.sequence > 0) {
                return anchor;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a finished turn must re-anchor the head");

    assert!(
        anchored.sequence >= 3,
        "the anchor follows the head the turn left: {anchored:?}"
    );
    assert_eq!(anchored.trail_path, fixture.trail());

    agent.shutdown().await;
}

#[tokio::test]
async fn truncating_the_tail_of_a_trail_is_caught_only_by_the_anchor() {
    let fixture = Fixture::new("truncation");
    let server = MockServer::start(write_write_read(&fixture)).await;
    let ai = audited_runtime(server.base_url(), &fixture, AuditDurability::Strict).await;
    let (agent, mut client) =
        connect(&ai, &config_for(&fixture, Some(AuditDurability::Strict))).await;
    let session = open_session(&mut client, &fixture).await;

    client
        .prompt(
            session,
            "write two files and read one",
            &mut Watched::default(),
        )
        .await
        .expect("the turn completes over a healthy trail");

    let AnchorOutcome::Anchored(anchor) = agent.anchor_now().await else {
        panic!("a healthy trail must anchor");
    };
    assert!(
        anchor.sequence >= 3,
        "three tool calls were recorded: {anchor:?}"
    );
    agent.shutdown().await;

    // A whole trail agrees with its anchor.
    let clean = garrison_agent::audit::verify::run(&fixture.trail(), &fixture.anchor())
        .expect("both files read");
    assert_eq!(VerifyOutcome::of(&clean), VerifyOutcome::Clean);

    // Now delete the last entry, which is what tampering with a trail looks
    // like when the tamperer knows a chain is checked forwards.
    let text = std::fs::read_to_string(fixture.trail()).expect("the trail is readable");
    let kept: Vec<&str> = text.lines().collect();
    let truncated = kept[..kept.len() - 1].join("\n");
    std::fs::write(fixture.trail(), format!("{truncated}\n")).expect("the trail is writable");

    let report = garrison_agent::audit::verify::run(&fixture.trail(), &fixture.anchor())
        .expect("both files still read");

    // The chain itself still verifies. A prefix of a valid chain is a valid
    // chain, so nothing inside the file can object.
    assert_eq!(
        report.chain,
        garrison_agent::audit::verify::ChainVerdict::Intact,
        "the chain alone cannot notice its own truncation",
    );
    // The anchor can, and it is the only thing that can.
    assert_eq!(VerifyOutcome::of(&report), VerifyOutcome::AnchorMismatch);
    let error = garrison_agent::audit::verify::refusal(&report).expect("a mismatch is reported");
    assert_eq!(
        garrison_agent::daemon::exit_code(&error),
        4,
        "an anchor mismatch is exit 4 and nothing else in this binary is",
    );
    assert!(error.to_string().contains("truncated"), "{error}");
}

#[tokio::test]
async fn a_daemon_refuses_to_start_over_a_trail_that_lost_its_tail() {
    let fixture = Fixture::new("startup-refusal");
    let server = MockServer::start(write_write_read(&fixture)).await;
    let ai = audited_runtime(server.base_url(), &fixture, AuditDurability::Strict).await;
    let (agent, mut client) =
        connect(&ai, &config_for(&fixture, Some(AuditDurability::Strict))).await;
    let session = open_session(&mut client, &fixture).await;

    client
        .prompt(
            session,
            "write two files and read one",
            &mut Watched::default(),
        )
        .await
        .expect("the turn completes");
    let AnchorOutcome::Anchored(_) = agent.anchor_now().await else {
        panic!("a healthy trail must anchor");
    };
    agent.shutdown().await;
    ai.shutdown().await.expect("the runtime releases the trail");

    // Someone removes the last entry between one start and the next.
    let text = std::fs::read_to_string(fixture.trail()).expect("readable");
    let kept: Vec<&str> = text.lines().collect();
    std::fs::write(
        fixture.trail(),
        format!("{}\n", kept[..kept.len() - 1].join("\n")),
    )
    .expect("writable");

    // Refuse by default...
    let server = MockServer::start(Vec::new()).await;
    let ai = audited_runtime(server.base_url(), &fixture, AuditDurability::Strict).await;
    let error = launch::build_setup(
        &ai,
        &config_for(&fixture, Some(AuditDurability::Strict)),
        None,
    )
    .await
    .expect_err("a truncated trail must refuse to start");

    assert!(error.is_configuration(), "{error}");
    assert_eq!(
        garrison_agent::daemon::exit_code(&error),
        2,
        "a refusal to start is exit 2, which systemd does not retry",
    );
    assert!(error.to_string().contains("truncated"), "{error}");

    // ...and start anyway when the deployment asked for a warning instead.
    let mut relaxed = config_for(&fixture, Some(AuditDurability::Strict));
    relaxed.audit.on_anchor_mismatch = AnchorMismatchAction::Warn;
    launch::build_setup(&ai, &relaxed, None)
        .await
        .expect("warn mode must start over a trail it has said is incomplete");

    ai.shutdown().await.expect("clean shutdown");
}

#[tokio::test]
async fn a_plane_without_a_trail_refuses_to_start() {
    // The single rule, exercised where it actually stops a daemon: an install
    // that answers to an agency and records nothing does not run.
    let server = MockServer::start(Vec::new()).await;
    let ai = ActonAI::builder()
        .app_name("garrison-audit-unarmed")
        .ollama_at(server.base_url(), "test-model")
        .launch()
        .await
        .expect("an unaudited runtime launches");

    let fixture = Fixture::new("required");
    let mut config = config_for(&fixture, None);
    config.audit.required = Some(true);

    let error = launch::build_setup(&ai, &config, None)
        .await
        .expect_err("a required trail that is not armed must refuse to start");

    assert!(error.is_configuration(), "{error}");
    assert_eq!(garrison_agent::daemon::exit_code(&error), 2);
    assert!(
        error.to_string().contains("audit trail is required"),
        "{error}"
    );

    // Without the requirement the same runtime starts, with no keeper: the
    // standalone developer install. The policy gate is still in the list,
    // because a standalone install is still governed, by `garrison.toml`
    // rather than by a bundle, and it admits the turn.
    config.audit.required = Some(false);
    let setup = launch::build_setup(&ai, &config, None)
        .await
        .expect("a standalone install starts unrecorded");
    let gates = &setup.defaults.gates;
    assert_eq!(
        gates.len(),
        1,
        "nothing gates a turn for the trail when nothing is being recorded",
    );
    let admission = gates[0]
        .ask(AdmitTurn {
            thread_id: ThreadId::new(),
            turn_id: TurnId::new(),
        })
        .await
        .expect("the remaining gate must answer");
    assert_eq!(
        admission,
        Admission::Admit,
        "an unenrolled install is not refused by the policy gate"
    );

    ai.shutdown().await.expect("clean shutdown");
}
