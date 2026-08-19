//! Where the protocol is served, and how bytes get to it.
//!
//! The rest of the protocol code never names a Unix socket. It works in terms
//! of [`Connection`] — anything that reads and writes bytes — and [`Listener`],
//! anything that produces connections. Two things follow.
//!
//! First, a Windows named-pipe listener slots in by implementing [`Listener`]
//! and nothing else changes. That transport is not built yet, deliberately:
//! Linux is the target now, and an abstraction with one implementation is a
//! guess. But the seam is at the only place a second transport would differ,
//! so the guess is cheap to be wrong about.
//!
//! Second, and more immediately useful: tests serve a connection from
//! [`tokio::net::UnixStream::pair`] with no path, no listener, and no cleanup.
//! A protocol test that needed a temporary directory would be testing the
//! filesystem as much as the protocol.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// One client connection: a bidirectional byte stream.
pub trait ConnectionStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T> ConnectionStream for T where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// A boxed client connection.
pub type Connection = Box<dyn ConnectionStream>;

/// A bound endpoint that produces connections.
///
/// `accept` is spelled as a boxed future rather than an `async fn` in the
/// trait so that [`Listener`] stays object-safe. The server holds one as
/// `Box<dyn Listener>` precisely so the transport can be swapped, and an
/// `async fn` in a trait would take that away.
pub trait Listener: Send + 'static {
    /// Waits for the next connection.
    fn accept(&mut self) -> Pin<Box<dyn Future<Output = io::Result<Connection>> + Send + '_>>;

    /// How this endpoint should be described to a human — in a log line, an
    /// error message, or the `serve` banner.
    fn endpoint(&self) -> String;
}

/// A Unix domain socket listener.
#[derive(Debug)]
pub struct UnixListener {
    inner: tokio::net::UnixListener,
    path: PathBuf,
}

impl UnixListener {
    /// Binds a Unix domain socket at `path`.
    ///
    /// A socket file left behind by a previous process is removed first. This
    /// is a deliberate choice and not an entirely safe one: if another agent
    /// really is listening, this steals its endpoint. The alternative — refuse
    /// to start when the file exists — is worse in practice, because the file
    /// outlives any process killed with `SIGKILL` and the common case by far
    /// is a stale socket rather than a live rival. A connect probe would
    /// distinguish them; that is worth adding when the daemon grows a
    /// supervisor that might genuinely race itself.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created, or if the
    /// socket cannot be bound.
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, crate::error::GarrisonError> {
        let path = path.as_ref().to_path_buf();
        let endpoint = path.display().to_string();

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    crate::error::GarrisonError::transport(
                        &endpoint,
                        format!("could not create {}: {e}", parent.display()),
                    )
                })?;
            }
        }

        match std::fs::remove_file(&path) {
            Ok(()) => {
                tracing::warn!(path = %endpoint, "removed a stale socket file before binding");
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(crate::error::GarrisonError::transport(
                    &endpoint,
                    format!("could not remove the existing socket file: {e}"),
                ));
            }
        }

        let inner = tokio::net::UnixListener::bind(&path)
            .map_err(|e| crate::error::GarrisonError::transport(&endpoint, e.to_string()))?;

        Ok(Self { inner, path })
    }

    /// The path this listener is bound to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Listener for UnixListener {
    fn accept(&mut self) -> Pin<Box<dyn Future<Output = io::Result<Connection>> + Send + '_>> {
        Box::pin(async move {
            let (stream, _addr) = self.inner.accept().await?;
            let connection: Connection = Box::new(stream);
            Ok(connection)
        })
    }

    fn endpoint(&self) -> String {
        self.path.display().to_string()
    }
}

impl Drop for UnixListener {
    /// Removes the socket file.
    ///
    /// Binding does not unlink on close by itself, so without this every run
    /// leaves a file behind that the next run has to decide whether to trust.
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "could not remove the socket file on shutdown",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn a_socket_pair_is_a_connection_with_no_filesystem_involved() {
        // This is the shape every protocol test uses: two ends of a stream,
        // no path to bind, nothing to clean up, nothing to race.
        let (client, server) = tokio::net::UnixStream::pair().expect("pairs");
        let mut client: Connection = Box::new(client);
        let server: Connection = Box::new(server);

        client.write_all(b"{\"hello\":1}\n").await.expect("writes");

        let mut lines = BufReader::new(server).lines();
        let line = lines.next_line().await.expect("reads").expect("one line");
        assert_eq!(line, r#"{"hello":1}"#);
    }

    #[tokio::test]
    async fn binding_reports_the_path_it_serves() {
        let dir = std::env::temp_dir().join(format!("garrison-bind-{}", std::process::id()));
        let path = dir.join("agent.sock");
        let listener = UnixListener::bind(&path).expect("binds");

        assert_eq!(listener.endpoint(), path.display().to_string());
        assert!(path.exists(), "binding creates the socket file");

        drop(listener);
        assert!(!path.exists(), "dropping removes it again");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn binding_over_a_stale_socket_file_succeeds() {
        // A daemon killed with SIGKILL leaves its socket file behind. Refusing
        // to start until someone deletes it by hand is the wrong default.
        let dir = std::env::temp_dir().join(format!("garrison-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("creates the directory");
        let path = dir.join("agent.sock");

        let first = UnixListener::bind(&path).expect("binds once");
        std::mem::forget(first); // Skip the Drop unlink, imitating SIGKILL.
        assert!(path.exists(), "the stale file is present");

        let second = UnixListener::bind(&path).expect("binds over the stale file");
        assert_eq!(second.endpoint(), path.display().to_string());

        drop(second);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_accepted_connection_carries_bytes_both_ways() {
        let dir = std::env::temp_dir().join(format!("garrison-accept-{}", std::process::id()));
        let path = dir.join("agent.sock");
        let mut listener = UnixListener::bind(&path).expect("binds");

        let connect_path = path.clone();
        let client = tokio::spawn(async move {
            let mut stream = tokio::net::UnixStream::connect(&connect_path)
                .await
                .expect("connects");
            stream.write_all(b"ping\n").await.expect("writes");
            let mut lines = BufReader::new(stream).lines();
            lines.next_line().await.expect("reads").expect("one line")
        });

        let server = listener.accept().await.expect("accepts");
        let mut lines = BufReader::new(server).lines();
        let request = lines.next_line().await.expect("reads").expect("one line");
        assert_eq!(request, "ping");
        let mut server = lines.into_inner();
        server.write_all(b"pong\n").await.expect("writes");

        assert_eq!(client.await.expect("client finishes"), "pong");

        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
