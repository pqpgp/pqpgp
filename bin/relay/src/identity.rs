//! Relay identity management.
//!
//! This module handles generation, storage, and loading of the relay's ML-DSA-87
//! signing keypair. The identity is used to sign heads statements for transparency.
//!
//! ## Key Storage
//!
//! The keypair is stored at `{data_dir}/relay_identity.key` in bincode format.
//! On first run, a new keypair is generated automatically.
//!
//! ## Usage
//!
//! ```ignore
//! use crate::identity::RelayIdentity;
//!
//! // Load or generate identity
//! let identity = RelayIdentity::load_or_generate(data_dir)?;
//!
//! // Get fingerprint for logging
//! println!("Relay identity: {}", identity.fingerprint_short());
//!
//! // Sign a heads statement
//! let signed = SignedHeadsStatement::sign(statement, identity.private_key())?;
//! ```

use pqpgp::crypto::{hash_data, KeyPair, PrivateKey, PublicKey};
use std::fs;
use std::path::Path;
use tracing::{info, warn};

/// Filename for storing the relay identity keypair.
const IDENTITY_FILENAME: &str = "relay_identity.key";

/// Relay identity for signing heads statements.
///
/// Contains an ML-DSA-87 keypair and derived fingerprint for identification.
pub struct RelayIdentity {
    /// The signing keypair.
    keypair: KeyPair,
    /// SHA3-512 fingerprint of the public key.
    fingerprint: [u8; 64],
}

impl RelayIdentity {
    /// Loads an existing identity or generates a new one.
    ///
    /// If a keypair exists at `{data_dir}/relay_identity.key`, it is loaded.
    /// Otherwise, a new ML-DSA-87 keypair is generated and saved.
    ///
    /// # Arguments
    /// * `data_dir` - Directory for storing the identity file
    ///
    /// # Returns
    /// The relay identity, or an error if loading/generation fails.
    pub fn load_or_generate(data_dir: &Path) -> Result<Self, String> {
        let identity_path = data_dir.join(IDENTITY_FILENAME);

        if identity_path.exists() {
            Self::load(&identity_path)
        } else {
            Self::generate_and_save(&identity_path)
        }
    }

    /// Loads an identity from a file.
    fn load(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|e| format!("Failed to read identity file: {}", e))?;

        let keypair: KeyPair = bincode::deserialize(&bytes)
            .map_err(|e| format!("Failed to deserialize identity: {}", e))?;

        let fingerprint = Self::compute_fingerprint(&keypair);

        info!(
            "Loaded relay identity from {} (fingerprint: {})",
            path.display(),
            hex::encode(&fingerprint[..8])
        );

        Ok(Self {
            keypair,
            fingerprint,
        })
    }

    /// Generates a new identity and saves it to a file.
    fn generate_and_save(path: &Path) -> Result<Self, String> {
        info!("Generating new relay identity...");

        let keypair = KeyPair::generate_mldsa87()
            .map_err(|e| format!("Failed to generate keypair: {}", e))?;

        let fingerprint = Self::compute_fingerprint(&keypair);

        // Serialize and save
        let bytes = bincode::serialize(&keypair)
            .map_err(|e| format!("Failed to serialize identity: {}", e))?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create identity directory: {}", e))?;
        }

        fs::write(path, &bytes).map_err(|e| format!("Failed to write identity file: {}", e))?;

        info!(
            "Generated new relay identity at {} (fingerprint: {})",
            path.display(),
            hex::encode(&fingerprint[..8])
        );

        // Warn about protecting the key
        warn!(
            "IMPORTANT: Protect {} - it contains your relay's private key",
            path.display()
        );

        Ok(Self {
            keypair,
            fingerprint,
        })
    }

    /// Computes the SHA3-512 fingerprint of the public key.
    fn compute_fingerprint(keypair: &KeyPair) -> [u8; 64] {
        let public_bytes = keypair.public_key().as_bytes();
        let hash = hash_data(&public_bytes);
        let mut fingerprint = [0u8; 64];
        fingerprint.copy_from_slice(&hash);
        fingerprint
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> &PublicKey {
        self.keypair.public_key()
    }

    /// Returns a reference to the private key.
    pub fn private_key(&self) -> &PrivateKey {
        self.keypair.private_key()
    }

    /// Returns the relay's 64-byte fingerprint.
    pub fn fingerprint(&self) -> &[u8; 64] {
        &self.fingerprint
    }

    /// Returns a short hex representation of the fingerprint (first 8 bytes).
    pub fn fingerprint_short(&self) -> String {
        hex::encode(&self.fingerprint[..8])
    }

    /// Returns the full hex representation of the fingerprint.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_and_load_identity() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path();

        // First call should generate
        let identity1 = RelayIdentity::load_or_generate(data_dir).unwrap();
        let fingerprint1 = *identity1.fingerprint();

        // Second call should load the same identity
        let identity2 = RelayIdentity::load_or_generate(data_dir).unwrap();
        let fingerprint2 = *identity2.fingerprint();

        assert_eq!(fingerprint1, fingerprint2);
    }

    #[test]
    fn test_fingerprint_format() {
        let temp_dir = TempDir::new().unwrap();
        let identity = RelayIdentity::load_or_generate(temp_dir.path()).unwrap();

        // Short fingerprint should be 16 hex chars (8 bytes)
        assert_eq!(identity.fingerprint_short().len(), 16);

        // Full fingerprint should be 128 hex chars (64 bytes)
        assert_eq!(identity.fingerprint_hex().len(), 128);
    }

    #[test]
    fn test_keypair_is_signing_capable() {
        let temp_dir = TempDir::new().unwrap();
        let identity = RelayIdentity::load_or_generate(temp_dir.path()).unwrap();

        // Should be able to sign
        assert!(identity.private_key().can_sign());
        assert!(identity.public_key().can_verify());
    }
}
