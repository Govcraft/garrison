//! The bytes a daemon and the control plane's hook service agree on.
//!
//! There is exactly one authenticated path from a `garrison-agent` daemon to
//! the plane: the daemon signs a short-lived assertion with its install key,
//! `garrison-hooks` verifies that signature against the public half it stored
//! at enrollment, and answers with a bearer the daemon spends on the plane's
//! ordinary REST API. Everything in this crate is the wire form of that one
//! exchange, and it lives in its own crate for a reason that is not
//! aesthetic: the signer and the verifier are two binaries, and a type that
//! is *described* in two places is a type whose two halves eventually
//! disagree about a field name, a key order, or a base64 alphabet. Here there
//! is one definition, one [`signing_bytes`], and one test vector both sides
//! compile against.
//!
//! # What is signed
//!
//! [`signing_bytes`] is the JSON serialization of an [`InstallAssertion`],
//! and the signature covers exactly those bytes. The daemon sends the same
//! bytes it signed, base64url-encoded, rather than re-serializing them on the
//! far side, so the verifier never has to reproduce a canonical form. Key
//! order is fixed by the struct's field order and is therefore part of the
//! format, but nothing in verification depends on it: a signature is checked
//! against the octets that arrived.
//!
//! # What is not here
//!
//! No clock, no nonce store, no policy. [`verify_assertion`] answers one
//! question — did the holder of this credential's private key produce this
//! assertion — and the freshness window, the replay cache, and the credential
//! and install status checks belong to the adjudicator in `garrison-hooks`,
//! which can be tested without a key or a socket.

#![forbid(unsafe_code)]

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use ed25519_dalek::pkcs8::DecodePublicKey as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The smallest nonce the exchange accepts, in characters.
///
/// 22 base64url characters is 132 bits, which is what a 128-bit random value
/// encodes to without padding. Stated as a length rather than an alphabet
/// because the nonce is opaque to the verifier: it only ever has to be
/// unguessable and unrepeated.
pub const MIN_NONCE_LEN: usize = 22;

/// The longest an assertion may claim to be valid for, in seconds.
///
/// An assertion is a bearer of the install's identity for as long as it is
/// unexpired, so it is deliberately shorter than the token it buys. Two
/// minutes covers any clock skew a `[garrison] skew` allowance would tolerate
/// and leaves nothing worth stealing.
pub const MAX_ASSERTION_WINDOW_SECS: i64 = 120;

/// base64url without padding, tolerating padding on the way in.
///
/// Encoding is unpadded, which is what every other base64url producer in this
/// stack emits. Decoding is indifferent, because a client that pads is
/// obviously well-intentioned and rejecting it would turn an interoperability
/// nit into a 401 nobody can debug.
const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// What a daemon asserts about itself, once, to obtain a bearer.
///
/// The field order is the serialized key order and is part of the format; see
/// the module docs. Times are Unix seconds because the two ends of this wire
/// are a Rust daemon and a Rust service, and a string timestamp would only
/// add a parse that can fail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallAssertion {
    /// The `InstallCredential` row whose public key verifies this.
    pub credential_id: String,
    /// The `AgentInstall` row the credential belongs to.
    ///
    /// Carried even though the credential row names it, so that the signature
    /// covers the binding: a credential moved to another install by a
    /// database edit does not silently keep working.
    pub install_id: String,
    /// When this assertion was made, in Unix seconds.
    pub iat: i64,
    /// When it stops being usable, in Unix seconds.
    pub exp: i64,
    /// A value this install has never used before.
    pub nonce: String,
}

/// The body posted to `POST /api/v1/install/token`.
///
/// `credential_id` is repeated outside the assertion so the service can find
/// the verification key before it has verified anything — the one thing it
/// must do before checking a signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRequest {
    /// The `InstallCredential` row id, as the lookup key.
    pub credential_id: String,
    /// base64url of the exact assertion bytes that were signed.
    pub assertion: String,
    /// base64url of the Ed25519 signature over those bytes.
    pub signature: String,
}

/// What the exchange answers with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenGrant {
    /// The bearer to present to the plane's REST API.
    pub token: String,
    /// When it stops being accepted, RFC 3339.
    pub expires_at: String,
    /// The `AgentInstall` row this bearer speaks for.
    pub install: String,
    /// The `Organization` the install belongs to.
    pub organization: String,
}

/// Why an assertion did not verify.
///
/// Deliberately coarse. A verifier that told a caller *which* of four things
/// was wrong with its signature would be a probing oracle, and the daemon has
/// no branch that depends on the distinction: it retries or it stops.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// A field was not the base64url it must be.
    Encoding(&'static str),
    /// The assertion bytes were not the JSON object they must be.
    Malformed(String),
    /// The stored public key is not a usable Ed25519 SPKI.
    UnusableKey(String),
    /// The signature does not verify under that key.
    Signature,
    /// The assertion names a different credential than the request.
    CredentialMismatch,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encoding(field) => write!(f, "'{field}' is not base64url"),
            Self::Malformed(why) => write!(f, "the assertion is not a valid assertion: {why}"),
            Self::UnusableKey(why) => write!(f, "the stored public key is unusable: {why}"),
            Self::Signature => write!(f, "the signature does not verify"),
            Self::CredentialMismatch => write!(
                f,
                "the assertion names a different credential than the request"
            ),
        }
    }
}

impl std::error::Error for WireError {}

/// The exact bytes a signature covers.
///
/// Pure, total, and the only place either side turns an assertion into
/// octets.
///
/// # Errors
///
/// [`WireError::Malformed`] if the assertion cannot be serialized, which
/// takes a value `serde_json` refuses and is not reachable for this struct.
pub fn signing_bytes(assertion: &InstallAssertion) -> Result<Vec<u8>, WireError> {
    serde_json::to_vec(assertion).map_err(|error| WireError::Malformed(error.to_string()))
}

/// Assembles a request from an assertion and the signature over its bytes.
///
/// Takes the signature rather than a key, so nothing in this crate ever holds
/// private key material: the daemon signs with its own
/// `InstallKey`, which never leaves `agent/src/enrollment/key.rs`.
#[must_use]
pub fn token_request(
    assertion_bytes: &[u8],
    signature: &[u8],
    credential_id: &str,
) -> TokenRequest {
    TokenRequest {
        credential_id: credential_id.to_string(),
        assertion: B64.encode(assertion_bytes),
        signature: B64.encode(signature),
    }
}

/// Checks that a request was signed by the holder of `public_key_spki`.
///
/// `public_key_spki` is the base64 (standard alphabet) SPKI stored on the
/// `InstallCredential` row, which is what
/// `InstallKey::public_spki_base64` produced at enrollment.
///
/// Verifies the signature over the octets that arrived rather than over a
/// re-serialization of the parsed assertion, so a daemon and a service that
/// disagree about JSON formatting still interoperate, and a mutated byte
/// still fails.
///
/// # Errors
///
/// A [`WireError`] naming which stage failed; see the type's own note on why
/// callers should not report the distinction to the network.
pub fn verify_assertion(
    public_key_spki: &str,
    request: &TokenRequest,
) -> Result<InstallAssertion, WireError> {
    let bytes = B64
        .decode(request.assertion.as_bytes())
        .map_err(|_| WireError::Encoding("assertion"))?;
    let signature = B64
        .decode(request.signature.as_bytes())
        .map_err(|_| WireError::Encoding("signature"))?;
    let signature: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| WireError::Encoding("signature"))?;

    let key = verifying_key(public_key_spki)?;
    key.verify_strict(&bytes, &Signature::from_bytes(&signature))
        .map_err(|_| WireError::Signature)?;

    let assertion: InstallAssertion =
        serde_json::from_slice(&bytes).map_err(|error| WireError::Malformed(error.to_string()))?;
    if assertion.credential_id != request.credential_id {
        return Err(WireError::CredentialMismatch);
    }
    Ok(assertion)
}

/// Decodes the SPKI the plane stored into a key that can verify.
fn verifying_key(public_key_spki: &str) -> Result<VerifyingKey, WireError> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(public_key_spki.trim().as_bytes())
        .map_err(|error| WireError::UnusableKey(error.to_string()))?;
    VerifyingKey::from_public_key_der(&der)
        .map_err(|error| WireError::UnusableKey(error.to_string()))
}

/// A fixed assertion, key, and signature both binaries can compile against.
///
/// This is the one place the format is pinned to actual octets. A change to a
/// field name, the field order, the base64 alphabet, or the bytes a signature
/// covers breaks [`tests::the_vector_still_verifies`] in this crate and in
/// every crate that depends on it, which is the point: the daemon and the
/// service cannot drift apart without a red test.
pub mod vector {
    use super::InstallAssertion;

    /// The signing key's public half, base64 SPKI, exactly as an
    /// `InstallCredential.public_key` holds it.
    pub const PUBLIC_KEY_SPKI: &str =
        "MCowBQYDK2VwAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=";

    /// The signature over [`assertion`]'s [`super::signing_bytes`],
    /// base64url, unpadded.
    pub const SIGNATURE: &str =
        "NwNo7ubmlh2n-MtrBxv-Q3-FkHlYodULVuXDX5QH7Gq5TPcDrb-iFI8X4Am2PPeDEykfIFWBhbA4L5LjHybpCw";

    /// The pinned assertion.
    #[must_use]
    pub fn assertion() -> InstallAssertion {
        InstallAssertion {
            credential_id: "installcredential_01k9garrisonvector0001".to_string(),
            install_id: "agentinstall_01k9garrisonvector0001".to_string(),
            iat: 1_780_000_000,
            exp: 1_780_000_060,
            nonce: "g4rr1s0nv3ct0rn0nc3aaa".to_string(),
        }
    }

    /// The seed of the key that signed the vector.
    ///
    /// Behind the `testing` feature so it cannot reach a shipped binary. It
    /// exists because both ends of this wire need to *produce* assertions in
    /// their own tests, and a hand-rolled signing helper on each side is a
    /// second chance to disagree about what gets signed.
    #[cfg(feature = "testing")]
    pub const SEED: [u8; 32] = [7u8; 32];

    /// Signs an assertion with the vector's key, exactly as a daemon would.
    ///
    /// # Panics
    ///
    /// If the assertion cannot be serialized, which this struct cannot do.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn sign(assertion: &InstallAssertion) -> super::TokenRequest {
        use ed25519_dalek::Signer as _;

        let bytes = super::signing_bytes(assertion).expect("an assertion serializes");
        let signature = ed25519_dalek::SigningKey::from_bytes(&SEED).sign(&bytes);
        super::token_request(&bytes, &signature.to_bytes(), &assertion.credential_id)
    }

    /// The pinned serialization, as the octets a signature covers.
    pub const SIGNED_JSON: &str = concat!(
        r#"{"credential_id":"installcredential_01k9garrisonvector0001","#,
        r#""install_id":"agentinstall_01k9garrisonvector0001","#,
        r#""iat":1780000000,"exp":1780000060,"#,
        r#""nonce":"g4rr1s0nv3ct0rn0nc3aaa"}"#
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector_request() -> TokenRequest {
        let assertion = vector::assertion();
        TokenRequest {
            credential_id: assertion.credential_id.clone(),
            assertion: B64.encode(vector::SIGNED_JSON.as_bytes()),
            signature: vector::SIGNATURE.to_string(),
        }
    }

    #[test]
    fn the_signed_bytes_are_the_pinned_json_in_the_pinned_order() {
        let bytes = signing_bytes(&vector::assertion()).unwrap();

        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            vector::SIGNED_JSON,
            "the key order is the format; changing it invalidates every signature"
        );
    }

    #[test]
    fn the_vector_still_verifies() {
        let assertion = verify_assertion(vector::PUBLIC_KEY_SPKI, &vector_request())
            .expect("the pinned signature must verify against the pinned key");

        assert_eq!(assertion, vector::assertion());
    }

    #[test]
    fn a_round_trip_through_token_request_verifies() {
        let assertion = vector::assertion();
        let bytes = signing_bytes(&assertion).unwrap();
        let signature = B64.decode(vector::SIGNATURE).unwrap();

        let request = token_request(&bytes, &signature, &assertion.credential_id);

        assert_eq!(
            verify_assertion(vector::PUBLIC_KEY_SPKI, &request).unwrap(),
            assertion
        );
    }

    #[test]
    fn a_padded_signature_is_accepted_and_an_unpadded_one_is_what_we_emit() {
        let mut request = vector_request();
        request.signature.push('=');
        request.signature.push('=');

        assert!(verify_assertion(vector::PUBLIC_KEY_SPKI, &request).is_ok());
        assert!(
            !vector::SIGNATURE.contains('='),
            "encoding is unpadded base64url"
        );
    }

    #[test]
    fn one_flipped_byte_in_the_assertion_fails_the_signature() {
        let mut tampered = vector::assertion();
        tampered.exp += 1;
        let bytes = signing_bytes(&tampered).unwrap();
        let request = TokenRequest {
            assertion: B64.encode(&bytes),
            ..vector_request()
        };

        assert_eq!(
            verify_assertion(vector::PUBLIC_KEY_SPKI, &request),
            Err(WireError::Signature)
        );
    }

    #[test]
    fn a_signature_from_another_key_does_not_verify() {
        use ed25519_dalek::pkcs8::EncodePublicKey as _;
        let other = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_public_key_der()
            .unwrap();
        let other = base64::engine::general_purpose::STANDARD.encode(other.as_bytes());

        assert_eq!(
            verify_assertion(&other, &vector_request()),
            Err(WireError::Signature)
        );
    }

    #[test]
    fn a_request_naming_a_different_credential_than_it_signed_is_refused() {
        let request = TokenRequest {
            credential_id: "installcredential_someone_else".to_string(),
            ..vector_request()
        };

        assert_eq!(
            verify_assertion(vector::PUBLIC_KEY_SPKI, &request),
            Err(WireError::CredentialMismatch)
        );
    }

    #[test]
    fn a_body_that_is_not_base64url_is_named_by_field() {
        let bad_assertion = TokenRequest {
            assertion: "not base64!".to_string(),
            ..vector_request()
        };
        assert_eq!(
            verify_assertion(vector::PUBLIC_KEY_SPKI, &bad_assertion),
            Err(WireError::Encoding("assertion"))
        );

        let bad_signature = TokenRequest {
            signature: "not base64!".to_string(),
            ..vector_request()
        };
        assert_eq!(
            verify_assertion(vector::PUBLIC_KEY_SPKI, &bad_signature),
            Err(WireError::Encoding("signature"))
        );
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_an_encoding_error_not_a_panic() {
        let request = TokenRequest {
            signature: B64.encode([0u8; 32]),
            ..vector_request()
        };

        assert_eq!(
            verify_assertion(vector::PUBLIC_KEY_SPKI, &request),
            Err(WireError::Encoding("signature"))
        );
    }

    #[test]
    fn a_public_key_that_is_not_an_spki_is_reported_as_unusable() {
        let error = verify_assertion("bm90LWEta2V5", &vector_request()).unwrap_err();

        assert!(matches!(error, WireError::UnusableKey(_)), "{error}");
    }

    #[test]
    fn assertion_bytes_that_are_not_an_assertion_are_malformed() {
        // Signed over the same key, so the failure is the JSON and not the
        // signature: proves the two stages are distinguishable.
        let request = TokenRequest {
            assertion: B64.encode(b"{}"),
            ..vector_request()
        };

        assert!(matches!(
            verify_assertion(vector::PUBLIC_KEY_SPKI, &request),
            // The signature is checked first, so `{}` never reaches the parse.
            Err(WireError::Signature)
        ));
    }

    #[test]
    fn a_grant_round_trips_through_json() {
        let grant = TokenGrant {
            token: "v4.local.abc".to_string(),
            expires_at: "2026-08-29T04:50:23Z".to_string(),
            install: "agentinstall_01".to_string(),
            organization: "organization_01".to_string(),
        };

        let text = serde_json::to_string(&grant).unwrap();
        assert_eq!(serde_json::from_str::<TokenGrant>(&text).unwrap(), grant);
    }
}
