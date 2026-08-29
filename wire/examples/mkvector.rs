//! Regenerates the pinned test vector in `garrison_wire::vector`.
//!
//! Not shipped behaviour and not a test: it is the tool that produces the
//! constants the tests then hold still. Run it only when the format
//! deliberately changes, and paste its output into `src/lib.rs`:
//!
//! ```text
//! cargo run -p garrison-wire --example mkvector
//! ```
//!
//! The seed is fixed so the vector is reproducible; it is a test key and has
//! never signed anything but this file's output.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use ed25519_dalek::pkcs8::EncodePublicKey as _;
use ed25519_dalek::{Signer as _, SigningKey};

const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn main() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let spki = key
        .verifying_key()
        .to_public_key_der()
        .expect("an Ed25519 key encodes as SPKI");
    let assertion = garrison_wire::vector::assertion();
    let bytes = garrison_wire::signing_bytes(&assertion).expect("the assertion serializes");
    let signature = key.sign(&bytes);

    println!(
        "PUBLIC_KEY_SPKI: {}",
        base64::engine::general_purpose::STANDARD.encode(spki.as_bytes())
    );
    println!("SIGNATURE: {}", B64.encode(signature.to_bytes()));
    println!(
        "SIGNED_JSON: {}",
        String::from_utf8(bytes).expect("JSON is utf8")
    );
}
