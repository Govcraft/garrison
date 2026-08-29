//! Language Server Protocol support: real code intelligence for the agent.
//!
//! A coding agent that can only grep guesses; one with a language server
//! checks. This module gives the model four read-only tools —
//! `lsp_diagnostics`, `lsp_hover`, `lsp_definition`, `lsp_references` —
//! backed by whatever servers `[lsp_servers]` in garrison.toml configures,
//! routed by file extension.
//!
//! # Shape
//!
//! One [`actor::LspServer`] actor per configured server owns that
//! connection's entire mutable state; a reader task
//! ([`connection::pump`]) is the only other party, and it holds nothing.
//! Servers are spawned at launch — eagerly, so rust-analyzer indexes while
//! the first prompt is still being typed — and a server that fails to spawn
//! is a logged warning, not a failed launch: the agent still works, it just
//! answers from grep like it used to.
//!
//! # Roots
//!
//! Servers are rooted at the daemon's project root, once, at launch. With one
//! daemon per user rooted at `$HOME`, that root is not any workspace, and a
//! server asked about a file under some other session's `cwd` answers with
//! whatever it can see, which is usually nothing. The shipped `garrison.toml`
//! therefore leaves `[lsp_servers]` empty and says why; an operator running
//! the daemon with `threads.project_root` set to one tree may enable them.
//! Spawning servers per session root is the fix and is a tracked follow-up.

pub mod actor;
pub mod connection;
pub mod framing;
pub mod tools;

pub use tools::install;

use crate::config::LspServerConfig;
use acton_reactive::prelude::*;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// One running language server, as the tools see it.
#[derive(Clone, Debug)]
pub struct LspServerEntry {
    /// The configured name, for error messages.
    pub name: String,
    /// File extensions this server owns, without dots.
    pub extensions: Vec<String>,
    /// The `languageId` sent in `didOpen`.
    pub language_id: String,
    /// The owning actor.
    pub handle: ActorHandle,
    /// How long a tool call waits on this server.
    pub timeout: Duration,
}

/// Every running language server, routable by file extension.
#[derive(Clone, Debug, Default)]
pub struct LspRegistry {
    servers: Vec<LspServerEntry>,
}

impl LspRegistry {
    /// True when no server came up.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// The server owning a path's extension, if any.
    #[must_use]
    pub fn for_path(&self, path: &Path) -> Option<&LspServerEntry> {
        let extension = path.extension()?.to_str()?;
        self.servers
            .iter()
            .find(|server| server.extensions.iter().any(|known| known == extension))
    }

    /// Every extension any server claims, for the "no server" error.
    #[must_use]
    pub fn known_extensions(&self) -> Vec<String> {
        let mut extensions: Vec<String> = self
            .servers
            .iter()
            .flat_map(|server| server.extensions.iter().cloned())
            .collect();
        extensions.sort();
        extensions.dedup();
        extensions
    }
}

/// Spawns every configured language server.
///
/// Infallible by design: a server whose binary is missing or whose spawn
/// fails is logged and skipped, because an agent without code intelligence
/// beats no agent at all.
pub async fn spawn_servers(
    runtime: &mut ActorRuntime,
    configs: &HashMap<String, LspServerConfig>,
    root: &Path,
) -> LspRegistry {
    let mut servers = Vec::new();
    for (name, config) in configs {
        let transport = match connection::Transport::spawn(&config.command, &config.args, root) {
            Ok(transport) => transport,
            Err(error) => {
                tracing::warn!(
                    server = %name,
                    command = %config.command,
                    %error,
                    "language server did not start; its tools will be unavailable"
                );
                continue;
            }
        };

        let root_uri = match url::Url::from_file_path(root) {
            Ok(url) => url.to_string(),
            Err(()) => {
                tracing::warn!(server = %name, root = %root.display(),
                    "project root cannot be a file URI; skipping language server");
                continue;
            }
        };

        let handle =
            actor::LspServer::spawn(runtime, name.clone(), transport.writer, transport.child).await;
        connection::pump(transport.reader, handle.clone());
        handle.send(actor::Initialize { root_uri }).await;

        tracing::info!(server = %name, command = %config.command, "language server starting");
        servers.push(LspServerEntry {
            name: name.clone(),
            extensions: config.extensions.clone(),
            language_id: config.language_id.clone().unwrap_or_else(|| name.clone()),
            handle,
            timeout: config.timeout(),
        });
    }
    LspRegistry { servers }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, extensions: &[&str]) -> LspServerEntry {
        LspServerEntry {
            name: name.to_string(),
            extensions: extensions.iter().map(ToString::to_string).collect(),
            language_id: name.to_string(),
            handle: ActorHandle::default(),
            timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn routing_is_by_extension() {
        let registry = LspRegistry {
            servers: vec![entry("rust", &["rs"]), entry("web", &["ts", "tsx"])],
        };
        assert_eq!(
            registry
                .for_path(Path::new("/p/src/main.rs"))
                .expect("must route")
                .name,
            "rust"
        );
        assert_eq!(
            registry
                .for_path(Path::new("/p/app.tsx"))
                .expect("must route")
                .name,
            "web"
        );
        assert!(registry.for_path(Path::new("/p/README.md")).is_none());
        assert!(registry.for_path(Path::new("/p/Makefile")).is_none());
        assert_eq!(registry.known_extensions(), vec!["rs", "ts", "tsx"]);
    }
}
