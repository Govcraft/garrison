//! Building the thing a daemon signs.
//!
//! Two pure functions and a nonce. Separated from the actor that spends them
//! so the format can be tested against [`garrison_wire`]'s verifier with no
//! clock, no socket, and no runtime — which is the same test the service runs
//! from the other side.

use crate::enrollment::key::InstallKey;
use garrison_wire::{signing_bytes, token_request, InstallAssertion, TokenRequest, WireError};

/// How long an assertion claims to be good for.
///
/// Sixty seconds, half of what [`garrison_wire::MAX_ASSERTION_WINDOW_SECS`]
/// permits, so a daemon whose clock is a little fast is still inside the
/// service's window rather than exactly on its edge.
pub const LIFETIME_SECS: i64 = 60;

/// How many bytes of randomness a nonce carries.
///
/// 16 bytes is 22 unpadded base64url characters, which is the minimum the
/// exchange accepts. The bound that matters is not the length: it is that
/// this comes from the operating system and is never derived from a counter,
/// a clock, or a hostname, all of which an attacker can predict.
const NONCE_BYTES: usize = 16;

/// The assertion this install would make right now.
///
/// Pure over its inputs: `now` is Unix seconds and `nonce` is supplied, so a
/// test can pin both. [`fresh_nonce`] is what a caller normally passes.
#[must_use]
pub fn new_assertion(
    credential_id: &str,
    install_id: &str,
    now: i64,
    nonce: String,
) -> InstallAssertion {
    InstallAssertion {
        credential_id: credential_id.to_string(),
        install_id: install_id.to_string(),
        iat: now,
        exp: now + LIFETIME_SECS,
        nonce,
    }
}

/// Signs an assertion into the body the exchange accepts.
///
/// # Errors
///
/// [`WireError::Malformed`] if the assertion cannot be serialized, which this
/// struct cannot do.
pub fn sign_request(
    key: &InstallKey,
    assertion: &InstallAssertion,
) -> Result<TokenRequest, WireError> {
    let bytes = signing_bytes(assertion)?;
    let signature = key.sign(&bytes);
    Ok(token_request(&bytes, &signature, &assertion.credential_id))
}

/// A value this install has never used before.
///
/// Falls back to a time-seeded value only if the operating system has no
/// randomness at all, which on a running daemon means something is very
/// wrong. The fallback is deliberately still unique per call rather than
/// constant: a repeated nonce is refused as a replay, and a daemon that
/// cannot get randomness should fail its next exchange loudly rather than
/// silently reuse one.
#[must_use]
pub fn fresh_nonce() -> String {
    use base64::Engine as _;

    let mut bytes = [0u8; NONCE_BYTES];
    if getrandom::fill(&mut bytes).is_err() {
        tracing::error!("no system randomness for an install assertion nonce");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        bytes.copy_from_slice(&now.to_le_bytes());
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use garrison_wire::{verify_assertion, MAX_ASSERTION_WINDOW_SECS, MIN_NONCE_LEN};

    #[test]
    fn an_assertion_names_the_credential_the_install_and_its_window() {
        let assertion = new_assertion("cred_1", "agentinstall_01", 1_780_000_000, "n".into());

        assert_eq!(assertion.credential_id, "cred_1");
        assert_eq!(assertion.install_id, "agentinstall_01");
        assert_eq!(assertion.iat, 1_780_000_000);
        assert_eq!(assertion.exp, 1_780_000_000 + LIFETIME_SECS);
    }

    #[test]
    fn the_window_this_daemon_claims_is_inside_what_the_exchange_allows() {
        const {
            assert!(
                LIFETIME_SECS < MAX_ASSERTION_WINDOW_SECS,
                "a daemon must not sit on the edge of the service's own bound"
            );
        }
    }

    #[test]
    fn a_signed_assertion_verifies_against_the_public_half_the_plane_stored() {
        let dir = tempfile::tempdir().unwrap();
        let key =
            InstallKey::load_or_create(&crate::enrollment::key::key_path(dir.path())).unwrap();
        let assertion = new_assertion("cred_1", "agentinstall_01", 1_780_000_000, fresh_nonce());

        let request = sign_request(&key, &assertion).unwrap();

        assert_eq!(
            verify_assertion(&key.public_spki_base64().unwrap(), &request).unwrap(),
            assertion,
            "the round trip through the wire format must be lossless"
        );
    }

    #[test]
    fn a_request_signed_by_one_install_does_not_verify_for_another() {
        let dir = tempfile::tempdir().unwrap();
        let mine =
            InstallKey::load_or_create(&crate::enrollment::key::key_path(dir.path())).unwrap();
        let theirs = InstallKey::load_or_create(&dir.path().join("other.pem")).unwrap();
        let assertion = new_assertion("cred_1", "agentinstall_01", 1, fresh_nonce());

        let request = sign_request(&mine, &assertion).unwrap();

        assert!(verify_assertion(&theirs.public_spki_base64().unwrap(), &request).is_err());
    }

    #[test]
    fn a_nonce_is_long_enough_for_the_exchange_and_never_repeats() {
        let first = fresh_nonce();
        let second = fresh_nonce();

        assert!(first.chars().count() >= MIN_NONCE_LEN, "{first}");
        assert_ne!(first, second);
    }

    #[test]
    fn a_nonce_is_url_safe_so_it_survives_json_and_logs_unescaped() {
        let nonce = fresh_nonce();

        assert!(
            nonce
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{nonce}"
        );
    }
}
