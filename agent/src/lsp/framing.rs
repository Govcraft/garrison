//! LSP's wire framing: `Content-Length` headers around JSON bodies.
//!
//! The Language Server Protocol does not share ACP's newline-delimited
//! framing ([`crate::protocol::jsonrpc`]); it frames every message the way
//! HTTP frames a body — a `Content-Length: N` header line, an optional
//! `Content-Type`, a blank line, then exactly N bytes of JSON. This module is
//! that grammar and nothing else: it moves bytes, it does not interpret them.
//!
//! Reads are incremental against a growing buffer rather than framed by the
//! transport, because a language server writes whenever it likes — a single
//! read may carry half a message or three of them.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest body this client will accept, in bytes.
///
/// A language server answering a references request on a generated file can
/// legitimately produce megabytes; sixteen of them is past anything a tool
/// result will keep, and a header claiming more is treated as a broken peer
/// rather than an allocation request.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Writes one framed message.
///
/// # Errors
///
/// Whatever the underlying writer reports; a failed write means the
/// connection is gone.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, body: &[u8]) -> io::Result<()> {
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    writer.write_all(header.as_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await
}

/// Reads one framed message, returning `None` on a clean end of stream.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`] for a malformed header or a body length
/// past [`MAX_BODY_BYTES`]; [`io::ErrorKind::UnexpectedEof`] for a stream
/// that ends mid-message; otherwise whatever the reader reports.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut header = Vec::with_capacity(64);
    let mut byte = [0u8; 1];

    // The header section ends at the first blank line. Reading it a byte at a
    // time is fine: headers are tens of bytes, and the body below is read in
    // one call.
    loop {
        match reader.read(&mut byte).await? {
            0 if header.is_empty() => return Ok(None),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "language server stream ended inside a header",
                ))
            }
            _ => header.push(byte[0]),
        }
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let length = content_length(&header).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "language server frame carried no Content-Length header",
        )
    })?;
    if length > MAX_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("language server frame claimed {length} bytes; refusing"),
        ));
    }

    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Extracts the `Content-Length` value from a raw header section.
///
/// Pure, and case-insensitive on the header name because the spec inherits
/// HTTP's rules even though every known server writes it in canonical case.
fn content_length(header: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(header).ok()?;
    text.split("\r\n").find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_frame_round_trips() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        write_frame(&mut client, br#"{"jsonrpc":"2.0"}"#)
            .await
            .expect("write");
        let body = read_frame(&mut server).await.expect("read").expect("some");
        assert_eq!(body, br#"{"jsonrpc":"2.0"}"#);
    }

    #[tokio::test]
    async fn two_frames_in_one_stream_arrive_separately() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        write_frame(&mut client, b"1").await.expect("write");
        write_frame(&mut client, b"22").await.expect("write");
        assert_eq!(
            read_frame(&mut server).await.expect("read").expect("some"),
            b"1"
        );
        assert_eq!(
            read_frame(&mut server).await.expect("read").expect("some"),
            b"22"
        );
    }

    #[tokio::test]
    async fn a_closed_stream_reads_as_none() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);
        assert!(read_frame(&mut server).await.expect("read").is_none());
    }

    #[tokio::test]
    async fn extra_headers_are_tolerated() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        use tokio::io::AsyncWriteExt;
        client
            .write_all(b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\nok")
            .await
            .expect("write");
        assert_eq!(
            read_frame(&mut server).await.expect("read").expect("some"),
            b"ok"
        );
    }

    #[tokio::test]
    async fn a_missing_length_is_invalid_data() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        use tokio::io::AsyncWriteExt;
        client
            .write_all(b"Content-Type: application/json\r\n\r\n")
            .await
            .expect("write");
        let error = read_frame(&mut server).await.expect_err("must refuse");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
