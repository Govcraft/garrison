//! The Garrison Agent Protocol: ACP over newline-delimited JSON-RPC.
//!
//! [`acp`] is the wire vocabulary (Zed's Agent Client Protocol schema, plus
//! Garrison's `_garrison/*` extensions), [`jsonrpc`] the envelope grammar,
//! [`codec`] the framing, [`transport`] the byte pipe, [`server`] the listener,
//! and [`conn`] one connected client.

pub mod acp;
pub mod codec;
pub mod conn;
pub mod jsonrpc;
pub mod server;
pub mod transport;
