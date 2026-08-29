//! The install's own signing key.
//!
//! Generated on this machine, at enrollment, and never transmitted. What
//! reaches the control plane is the public half in SPKI form; the private half
//! is written once to an owner-only PKCS#8 file and read back on every
//! subsequent start.
//!
//! The alternative, a shared bearer secret issued by the plane, was rejected
//! in the schema design for a reason that applies just as much on this side of
//! the wire: it would put a replayable credential in the plane's database, on
//! the wire at every heartbeat, and in a file on every workstation. That is
//! three copies of something that only ever needs to exist in one place, and
//! this file is that place.

use crate::error::GarrisonError;
use base64::Engine as _;
// `LineEnding` is not re-exported at `ed25519_dalek::pkcs8`, only reachable
// through the spki/der chain beneath it. Spelling the path here is preferable
// to taking a direct dependency on `pkcs8`, which would be a second version of
// a crate ed25519-dalek already pins.
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};

/// The keypair this install signs with.
///
/// No `Debug`: the only thing it holds is a private key, and a type that can
/// print itself is a type that will eventually print itself into a log.
pub struct InstallKey {
    signing: SigningKey,
}

impl InstallKey {
    /// Loads the key at `path`, generating and storing one if it is absent.
    ///
    /// Idempotent on purpose. A daemon that regenerated its key whenever it
    /// could not find the file would invalidate the credential the plane holds
    /// for it, silently, at the worst possible moment.
    ///
    /// # Errors
    ///
    /// [`GarrisonErrorKind::Enrollment`](crate::error::GarrisonErrorKind::Enrollment)
    /// when the file exists but cannot be read or parsed, or when a new key
    /// cannot be written.
    pub fn load_or_create(path: &Path) -> Result<Self, GarrisonError> {
        if path.is_file() {
            return Self::load(path);
        }
        let key = Self::generate()?;
        key.store(path)?;
        Ok(key)
    }

    /// Reads an existing PKCS#8 PEM key.
    fn load(path: &Path) -> Result<Self, GarrisonError> {
        let pem = std::fs::read_to_string(path).map_err(|error| {
            GarrisonError::enrollment(format!(
                "install key '{}' could not be read: {error}",
                path.display()
            ))
        })?;
        let signing = SigningKey::from_pkcs8_pem(&pem).map_err(|error| {
            GarrisonError::enrollment(format!(
                "install key '{}' is not a usable Ed25519 key: {error}",
                path.display()
            ))
        })?;
        Ok(Self { signing })
    }

    /// Mints a new keypair from the operating system's randomness.
    ///
    /// `getrandom` rather than a seeded RNG: the seed of a signing key is the
    /// one number in this process that must not be reproducible.
    fn generate() -> Result<Self, GarrisonError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|error| {
            GarrisonError::enrollment(format!(
                "no system randomness for a new install key: {error}"
            ))
        })?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Writes the private half with owner-only permissions.
    fn store(&self, path: &Path) -> Result<(), GarrisonError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                GarrisonError::enrollment(format!(
                    "'{}' could not be created: {error}",
                    parent.display()
                ))
            })?;
        }
        let pem = self.signing.to_pkcs8_pem(LineEnding::LF).map_err(|error| {
            GarrisonError::enrollment(format!("install key could not be encoded: {error}"))
        })?;
        write_private(path, pem.as_bytes()).map_err(|error| {
            GarrisonError::enrollment(format!(
                "install key '{}' could not be written: {error}",
                path.display()
            ))
        })
    }

    /// The public half, base64-encoded SPKI: what the plane stores.
    ///
    /// # Errors
    ///
    /// [`GarrisonErrorKind::Enrollment`](crate::error::GarrisonErrorKind::Enrollment)
    /// if the key cannot be encoded, which would mean a corrupt key in memory.
    pub fn public_spki_base64(&self) -> Result<String, GarrisonError> {
        let der = self
            .signing
            .verifying_key()
            .to_public_key_der()
            .map_err(|error| {
                GarrisonError::enrollment(format!(
                    "install public key could not be encoded: {error}"
                ))
            })?;
        Ok(base64::engine::general_purpose::STANDARD.encode(der.as_bytes()))
    }
}

/// Creates or truncates `path` at mode 0600 and writes `bytes`.
///
/// The explicit `set_permissions` is not redundant: `mode` on `OpenOptions`
/// applies only when the file is created, so a key rewritten over a
/// world-readable file would silently keep the wrong mode.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
}

/// The install key's place under the Garrison config directory.
#[must_use]
pub fn key_path(config_dir: &Path) -> PathBuf {
    config_dir.join("install-key.pem")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(dir.path());

        let first = InstallKey::load_or_create(&path).unwrap();
        let second = InstallKey::load_or_create(&path).unwrap();

        assert_eq!(
            first.public_spki_base64().unwrap(),
            second.public_spki_base64().unwrap(),
            "a restart must not change the install's identity"
        );
    }

    #[test]
    fn the_private_half_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(dir.path());
        InstallKey::load_or_create(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "install key must not be readable by anyone else"
        );
    }

    #[test]
    fn an_existing_world_readable_key_file_is_corrected_on_rewrite() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(dir.path());
        std::fs::write(&path, b"placeholder").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        InstallKey::generate().unwrap().store(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn two_installs_do_not_share_a_key() {
        let a = InstallKey::generate()
            .unwrap()
            .public_spki_base64()
            .unwrap();
        let b = InstallKey::generate()
            .unwrap()
            .public_spki_base64()
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_public_half_is_base64_spki_not_raw_key_material() {
        let key = InstallKey::generate().unwrap();
        let encoded = key.public_spki_base64().unwrap();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .expect("the field is base64");

        // 12-byte SPKI header for Ed25519, then the 32-byte key.
        assert_eq!(der.len(), 44);
        assert_eq!(&der[..2], &[0x30, 0x2a], "a DER SEQUENCE of 42 bytes");
    }

    #[test]
    fn a_file_that_is_not_a_key_is_reported_as_an_enrollment_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(dir.path());
        std::fs::write(&path, b"not a pem file").unwrap();

        let Err(error) = InstallKey::load_or_create(&path) else {
            panic!("a file that is not a key must not load as one");
        };
        assert!(error.to_string().contains("not a usable Ed25519 key"));
    }
}
