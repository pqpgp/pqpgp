//! Post-quantum cryptographic primitives for PQPGP.
//!
//! This module provides the core cryptographic operations using NIST-standardized
//! post-quantum algorithms:
//!
//! - **ML-KEM**: Module-Lattice-Based Key-Encapsulation Mechanism for encryption
//! - **ML-DSA**: Module-Lattice-Based Digital Signature Algorithm for signing
//! - **AES-GCM**: Traditional symmetric encryption for message content
//! - **SHA3**: Quantum-resistant hashing

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub mod encryption;
pub mod keys;
pub mod password;
pub mod signature;

pub use encryption::{
    decrypt_data, decrypt_message, decrypt_messages, encrypt_data, encrypt_message,
    encrypt_messages, estimate_encrypted_size, EncryptedMessage,
};
pub use keys::{KeyPair, PrivateKey, PublicKey};
pub use password::{EncryptedPrivateKey, Password};
pub use signature::{
    sign_data, sign_message, sign_messages, verify_data_signature, verify_signature,
    verify_signatures, Signature,
};

/// Supported post-quantum algorithm identifiers for PGP packets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    /// ML-KEM-768 for key encapsulation (NIST standardized)
    Mlkem768 = 100,
    /// ML-DSA-65 for digital signatures (NIST standardized)
    Mldsa65 = 101,
    /// AES-256-GCM for symmetric encryption
    Aes256Gcm = 102,
    /// SHA3-256 for hashing
    Sha3_256 = 103,
}

impl Algorithm {
    /// Returns the algorithm name as a string
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::Mlkem768 => "ML-KEM-768",
            Algorithm::Mldsa65 => "ML-DSA-65",
            Algorithm::Aes256Gcm => "AES-256-GCM",
            Algorithm::Sha3_256 => "SHA3-256",
        }
    }

    /// Returns the key size in bytes for this algorithm
    pub fn key_size(&self) -> usize {
        match self {
            Algorithm::Mlkem768 => 1184, // ML-KEM-768 public key size
            Algorithm::Mldsa65 => 1952,  // ML-DSA-65 public key size
            Algorithm::Aes256Gcm => 32,  // 256 bits
            Algorithm::Sha3_256 => 32,   // 256 bits
        }
    }

    /// Returns true if this is a post-quantum algorithm
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, Algorithm::Mlkem768 | Algorithm::Mldsa65)
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Key usage flags indicating how a key may be used
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUsage {
    /// Key may be used for encryption
    pub encrypt: bool,
    /// Key may be used for digital signatures
    pub sign: bool,
    /// Key may be used to certify other keys
    pub certify: bool,
    /// Key may be used for authentication
    pub authenticate: bool,
}

impl KeyUsage {
    /// Creates a new KeyUsage with all permissions disabled
    pub fn none() -> Self {
        Self {
            encrypt: false,
            sign: false,
            certify: false,
            authenticate: false,
        }
    }

    /// Creates a new KeyUsage for encryption only
    pub fn encrypt_only() -> Self {
        Self {
            encrypt: true,
            sign: false,
            certify: false,
            authenticate: false,
        }
    }

    /// Creates a new KeyUsage for signing only
    pub fn sign_only() -> Self {
        Self {
            encrypt: false,
            sign: true,
            certify: false,
            authenticate: false,
        }
    }

    /// Creates a new KeyUsage for certification only
    pub fn certify_only() -> Self {
        Self {
            encrypt: false,
            sign: false,
            certify: true,
            authenticate: false,
        }
    }

    /// Creates a new KeyUsage with all permissions enabled
    pub fn all() -> Self {
        Self {
            encrypt: true,
            sign: true,
            certify: true,
            authenticate: true,
        }
    }
}

/// Cryptographic hash function using SHA3-256
pub fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Secure random number generation for cryptographic operations
pub fn secure_random_bytes<R: CryptoRng + RngCore>(rng: &mut R, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a deterministic key ID from key material and metadata
/// In PGP, key IDs are derived from the key fingerprint, not randomly generated
pub fn generate_key_id(key_material: &[u8], algorithm: Algorithm, created: u64) -> u64 {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update((algorithm as u8).to_be_bytes());
    hasher.update(created.to_be_bytes());
    hasher.update(key_material);
    let hash = hasher.finalize();

    // Use the last 8 bytes of the hash as the key ID (standard PGP practice)
    let mut key_id_bytes = [0u8; 8];
    key_id_bytes.copy_from_slice(&hash[24..32]);
    u64::from_be_bytes(key_id_bytes)
}

/// Constant-time comparison of key IDs to prevent timing attacks
///
/// This function compares two 64-bit key IDs in constant time to prevent
/// information leakage through timing side channels.
pub fn key_ids_equal(a: u64, b: u64) -> bool {
    a.to_be_bytes().ct_eq(&b.to_be_bytes()).into()
}

/// Key metadata including creation time, expiration, and usage flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key creation time (Unix timestamp)
    pub created: u64,
    /// Key expiration time (Unix timestamp, None for no expiration)
    pub expires: Option<u64>,
    /// Key usage permissions
    pub usage: KeyUsage,
    /// Key algorithm
    pub algorithm: Algorithm,
    /// Unique key identifier
    pub key_id: u64,
}

impl KeyMetadata {
    /// Creates new key metadata with the specified parameters
    pub fn new(algorithm: Algorithm, usage: KeyUsage, key_id: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            created: now,
            expires: None,
            usage,
            algorithm,
            key_id,
        }
    }

    /// Creates new key metadata with expiration time
    pub fn with_expiration(
        algorithm: Algorithm,
        usage: KeyUsage,
        key_id: u64,
        expires_seconds: u64,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            created: now,
            expires: Some(expires_seconds),
            usage,
            algorithm,
            key_id,
        }
    }

    /// Checks if the key is currently valid (not expired)
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.expires.is_none_or(|exp| now < exp)
    }

    /// Returns the key's age in seconds
    pub fn age_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now.saturating_sub(self.created)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_properties() {
        assert_eq!(Algorithm::Mlkem768.name(), "ML-KEM-768");
        assert_eq!(Algorithm::Mldsa65.name(), "ML-DSA-65");
        assert!(Algorithm::Mlkem768.is_post_quantum());
        assert!(Algorithm::Mldsa65.is_post_quantum());
        assert!(!Algorithm::Aes256Gcm.is_post_quantum());
    }

    #[test]
    fn test_key_usage() {
        let usage = KeyUsage::encrypt_only();
        assert!(usage.encrypt);
        assert!(!usage.sign);

        let usage = KeyUsage::all();
        assert!(usage.encrypt && usage.sign && usage.certify && usage.authenticate);
    }

    #[test]
    fn test_hash_data() {
        let data = b"test data";
        let hash1 = hash_data(data);
        let hash2 = hash_data(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_key_metadata() {
        let key_id = 12345;
        let metadata = KeyMetadata::new(Algorithm::Mlkem768, KeyUsage::encrypt_only(), key_id);
        assert_eq!(metadata.key_id, key_id);
        assert_eq!(metadata.algorithm, Algorithm::Mlkem768);
        assert!(metadata.is_valid());
    }
}
