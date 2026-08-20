//! The sandbox re-exec contract, driven against the real `garrison-agent`
//! binary.
//!
//! acton-ai's process sandbox runs a tool by re-exec'ing whatever binary is
//! hosting it and speaking a length-prefixed JSON protocol over the child's
//! pipes. That only works if the binary checks for the sandbox environment
//! before it does anything else: parse a command line and the child exits with
//! a usage error; start a tokio runtime and the child panics building its own.
//!
//! Neither failure is visible from a unit test, because both live in `main`.
//! So these tests spawn the actual binary the way the sandbox does.

#![cfg(unix)]

use acton_ai::tools::sandbox::{HardeningMode, ProcessSandboxConfig, SandboxedExecution};
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;

/// The binary a deployment installs, which is the one that must hold up its
/// end of the contract.
fn garrison_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_garrison-agent"))
}

/// Hardening off: landlock would confine the child away from the test's own
/// tempdirs, and the hardened path is acton-ai's to cover, not Garrison's.
/// What is under test here is the entry point, not the kernel.
fn config() -> ProcessSandboxConfig {
    ProcessSandboxConfig::new()
        .with_timeout(Duration::from_secs(15))
        .with_hardening(HardeningMode::Off)
}

#[tokio::test]
async fn the_agent_binary_dispatches_a_sandboxed_tool_instead_of_booting_itself() {
    let sandbox = SandboxedExecution::process_with_exe(garrison_binary(), config())
        .expect("the agent binary must canonicalize");

    let result = sandbox
        .execute("bash", json!({"command": "echo governed"}))
        .await
        .expect("the re-exec'd agent must answer the sandbox protocol");

    assert_eq!(
        result
            .get("stdout")
            .and_then(serde_json::Value::as_str)
            .expect("bash results carry stdout")
            .trim_end(),
        "governed",
        "a usage error or a nested-runtime panic would surface here instead"
    );
}

#[tokio::test]
async fn the_child_works_in_its_own_directory_rather_than_the_agents() {
    let sandbox = SandboxedExecution::process_with_exe(garrison_binary(), config())
        .expect("the agent binary must canonicalize");

    let result = sandbox
        .execute("bash", json!({"command": "pwd"}))
        .await
        .expect("the sandboxed command must succeed");

    let cwd = result
        .get("stdout")
        .and_then(serde_json::Value::as_str)
        .expect("bash results carry stdout")
        .trim_end()
        .to_string();
    let here = std::env::current_dir().expect("a working directory");

    assert_ne!(
        PathBuf::from(&cwd),
        here,
        "a sandboxed command that starts in the daemon's directory is not confined"
    );
}

#[tokio::test]
async fn a_sandboxed_write_outside_the_childs_root_is_refused() {
    // The child allows its own per-invocation directory and nothing else, so
    // a write aimed anywhere on the host comes back as a refusal rather than
    // a file. That is also why sandboxed `write_file` cannot yet touch a
    // project: the session's root is not carried across the process boundary
    // (Govcraft/garrison#5).
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("should-never-exist.txt");

    let sandbox = SandboxedExecution::process_with_exe(garrison_binary(), config())
        .expect("the agent binary must canonicalize");

    let error = sandbox
        .execute(
            "write_file",
            json!({"path": path.to_str().unwrap(), "content": "escaped\n"}),
        )
        .await
        .expect_err("the child must refuse a path outside its own root");

    assert!(
        error.to_string().contains("outside allowed directories"),
        "the refusal should name the boundary, got: {error}"
    );
    assert!(
        !path.exists(),
        "a refused write must not have happened anyway"
    );
}
