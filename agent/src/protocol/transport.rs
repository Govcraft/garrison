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
    /// A socket file already at `path` is probed before anything is done to
    /// it. If something answers, another daemon owns this endpoint and this
    /// process refuses to start: there is one engine per user, and stealing
    /// its socket would leave two of them holding one audit trail. If nothing
    /// answers, the file is what a process killed with `SIGKILL` leaves
    /// behind, and it is removed with a warning. The probe is what makes the
    /// two cases distinguishable; refusing on the mere presence of the file
    /// would make every crash a manual clean-up.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created, if a live
    /// daemon already answers at `path`, or if the socket cannot be bound.
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

        match probe(&path) {
            Probe::Absent => {}
            Probe::Live => {
                return Err(crate::error::GarrisonError::transport(
                    &endpoint,
                    "another garrison-agent is already listening here; this process will not \
                     start a second engine (stop it with `systemctl --user stop garrison-agent`, \
                     or point this one at a different --socket)",
                ));
            }
            Probe::Stale => {
                std::fs::remove_file(&path).map_err(|e| {
                    crate::error::GarrisonError::transport(
                        &endpoint,
                        format!("could not remove the stale socket file: {e}"),
                    )
                })?;
                tracing::warn!(path = %endpoint, "removed a stale socket file before binding");
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

/// What a connect probe found at a socket path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// No file there.
    Absent,
    /// A file, and a process answering on it.
    Live,
    /// A file nobody answers on.
    Stale,
}

/// Asks whether anyone is listening at `path`, without keeping a connection.
///
/// A blocking connect on purpose: this runs once, before the listener exists,
/// and a Unix-socket connect to a local path either succeeds or is refused
/// immediately.
fn probe(path: &Path) -> Probe {
    if !path.exists() {
        return Probe::Absent;
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_live) => Probe::Live,
        Err(_) => Probe::Stale,
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

        // A std listener closes its descriptor on drop but leaves the file,
        // which is exactly the state SIGKILL leaves behind: a path nobody
        // answers on.
        let dead = std::os::unix::net::UnixListener::bind(&path).expect("binds once");
        drop(dead);
        assert!(path.exists(), "the stale file is present");

        let second = UnixListener::bind(&path).expect("binds over the stale file");
        assert_eq!(second.endpoint(), path.display().to_string());

        drop(second);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn binding_over_a_live_socket_is_refused() {
        // Two engines on one endpoint would be two writers of one trail. The
        // second one must not start, and must say who is in its way.
        let dir = std::env::temp_dir().join(format!("garrison-live-{}", std::process::id()));
        let path = dir.join("agent.sock");

        let first = UnixListener::bind(&path).expect("binds once");
        let error = UnixListener::bind(&path).expect_err("must refuse the second bind");

        assert!(
            error.to_string().contains("already listening"),
            "unexpected message: {error}"
        );
        assert!(path.exists(), "the refusal leaves the live socket alone");

        drop(first);
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
