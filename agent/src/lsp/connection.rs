//! Getting bytes to and from a language server.
//!
//! A transport is just a write half and a read half. Production builds one
//! around a child process's pipes; tests build one around an in-memory
//! duplex and drive the real actor with a scripted server. The actor cannot
//! tell the difference, which is the point.
//!
//! # The reader task
//!
//! [`pump`] is the one place a task exists outside an actor, and it earns it:
//! a child's stdout is a genuine process boundary, and something must sit on
//! the blocking read and turn what arrives into messages. It owns no state —
//! every frame goes straight to the actor, and the actor's mailbox is what
//! serializes it against everything else.

use super::actor::{ServerGone, ServerMessage, SharedWriter};
use acton_reactive::prelude::*;
use std::io;
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncRead;
use tokio::process::{Child, Command};

/// A language server's two pipe ends, plus the process they belong to.
pub struct Transport {
    /// The write half, ready for the actor's model.
    pub writer: SharedWriter,
    /// The read half, ready for [`pump`].
    pub reader: Box<dyn AsyncRead + Send + Unpin>,
    /// The child, when there is one to hold onto.
    pub child: Option<Child>,
}

impl Transport {
    /// Spawns a language server process and takes its pipes.
    ///
    /// stderr is discarded: rust-analyzer alone writes megabytes of progress
    /// there, and a pipe nobody drains would eventually block the server.
    ///
    /// # Errors
    ///
    /// Whatever spawning reports — most usefully [`io::ErrorKind::NotFound`]
    /// when the binary is not installed, which the caller downgrades to a
    /// warning rather than a failed launch.
    pub fn spawn(command: &str, args: &[String], root: &Path) -> io::Result<Self> {
        let mut child = Command::new(command)
            .args(args)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;

        let stdin = child.stdin.take().ok_or_else(|| {
            io::Error::other("language server child came up without a stdin pipe")
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            io::Error::other("language server child came up without a stdout pipe")
        })?;

        Ok(Self {
            writer: SharedWriter::new(Box::new(stdin)),
            reader: Box::new(stdout),
            child: Some(child),
        })
    }
}

/// Reads frames until the transport dies, delivering each to the actor.
///
/// Returns the task's handle only so a test can await quiescence; production
/// lets it run until EOF, which arrives no later than the actor dropping the
/// child.
pub fn pump(
    mut reader: Box<dyn AsyncRead + Send + Unpin>,
    handle: ActorHandle,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match super::framing::read_frame(&mut reader).await {
                Ok(Some(body)) => match serde_json::from_slice(&body) {
                    Ok(value) => handle.send(ServerMessage(value)).await,
                    Err(error) => {
                        tracing::debug!(%error, "language server sent unparseable JSON; skipping");
                    }
                },
                Ok(None) => {
                    handle
                        .send(ServerGone {
                            reason: "the server closed its output".to_string(),
                        })
                        .await;
                    return;
                }
                Err(error) => {
                    handle
                        .send(ServerGone {
                            reason: error.to_string(),
                        })
                        .await;
                    return;
                }
            }
        }
    })
}
