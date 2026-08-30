//! The process-wide TLS crypto provider, and the one call that installs it.
//!
//! # Why this module exists
//!
//! `agent/Cargo.toml` asks reqwest for `rustls-tls-webpki-roots-no-provider`,
//! which is what a FIPS build has to ask for: the ordinary `rustls-tls`
//! feature installs ring as the process-wide default the first time a client
//! is built, and a build that claims FIPS-validated cryptography must not race
//! ring for that slot.
//!
//! The cost of turning it off is that nothing installs a provider on reqwest's
//! behalf any more. `reqwest::Client::builder().build()` does not return an
//! error when it finds no provider — it panics with "No provider set". So
//! every place this crate builds a client has to have installed one first.
//!
//! [`ensure_provider`] is that call. It is idempotent and cheap after the
//! first time, so the rule is simply to call it immediately before building a
//! client rather than to reason about whether some earlier caller did. That is
//! the same shape acton-ai uses: `main` installs the provider before it parses
//! a command line, and `ActonAIBuilder::launch` installs it again for
//! embedders who never went through that `main`.
//!
//! # What it refuses
//!
//! Under the `fips` feature acton-ai asks the module whether it is actually
//! operating in FIPS mode and reports an error when it is not, rather than
//! assuming it from the fact that the crate is linked. A non-FIPS provider
//! already sitting in the process-wide slot is also an error, because a build
//! that promises validated cryptography and quietly runs something else is
//! worse than one that makes no promise. Both arrive here as a configuration
//! error naming `fips`.

use crate::error::GarrisonError;

/// Installs the process-wide rustls crypto provider, idempotently.
///
/// Call this before building any `reqwest` client. Calling it twice, or after
/// something else installed the same kind of provider, is fine and cheap.
///
/// # Errors
///
/// [`GarrisonError::configuration`] naming `fips` when a non-FIPS provider is
/// already installed in this process, or when the FIPS module reports that it
/// is not operating in FIPS mode. On a build without the `fips` feature this
/// cannot fail.
pub fn ensure_provider() -> Result<(), GarrisonError> {
    acton_ai::fips::install_crypto_provider()
        .map_err(|error| GarrisonError::configuration("fips", error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installing_the_provider_is_idempotent() {
        ensure_provider().expect("the first install succeeds");
        ensure_provider().expect("a second install is not an error");
    }

    #[test]
    fn a_client_can_be_built_once_the_provider_is_installed() {
        // The regression this module exists for: without the install, this
        // panics with "No provider set" rather than returning an error, so a
        // test that only checked for `Err` would not have caught it.
        ensure_provider().expect("install");
        reqwest::Client::builder()
            .build()
            .expect("a client builds once a provider is installed");
    }
}
