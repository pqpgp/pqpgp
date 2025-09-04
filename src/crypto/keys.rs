//! Post-quantum key generation and management.
//!
//! This module implements key generation for ML-KEM and ML-DSA algorithms,
//! providing both individual keys and combined key pairs for hybrid operations.

use crate::crypto::{
    generate_key_id, hash_data, Algorithm, EncryptedPrivateKey, KeyMetadata, KeyUsage, Password,
};
use crate::error::{PqpgpError, Result};
use pqcrypto_mldsa::mldsa87::{self, PublicKey as Mldsa87PublicKey, SecretKey as Mldsa87SecretKey};
use pqcrypto_mlkem::mlkem1024::{
    self, PublicKey as Mlkem1024PublicKey, SecretKey as Mlkem1024SecretKey,
};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A post-quantum public key that can contain either ML-KEM or ML-DSA keys
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Serialized key bytes for the specific algorithm
    pub(crate) key_bytes: Vec<u8>,
    /// Key metadata including algorithm, usage, and creation time
    pub(crate) metadata: KeyMetadata,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("algorithm", &self.metadata.algorithm)
            .field("key_id", &self.metadata.key_id)
            .field("key_size", &self.key_bytes.len())
            .finish()
    }
}

/// Storage format for private key data
#[derive(Clone, Serialize, Deserialize)]
pub enum PrivateKeyStorage {
    /// Unencrypted private key data
    Unencrypted(Vec<u8>),
    /// Password-encrypted private key data
    Encrypted(EncryptedPrivateKey),
}

/// A post-quantum private key that can contain either ML-KEM or ML-DSA keys
#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    /// Private key storage (encrypted or unencrypted)
    pub(crate) storage: PrivateKeyStorage,
    /// Key metadata including algorithm, usage, and creation time
    pub(crate) metadata: KeyMetadata,
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (is_encrypted, key_size) = match &self.storage {
            PrivateKeyStorage::Unencrypted(bytes) => (false, bytes.len()),
            PrivateKeyStorage::Encrypted(enc) => (true, enc.encrypted_size()),
        };
        f.debug_struct("PrivateKey")
            .field("algorithm", &self.metadata.algorithm)
            .field("key_id", &self.metadata.key_id)
            .field("is_encrypted", &is_encrypted)
            .field("key_size", &key_size)
            .finish()
    }
}

/// A complete key pair containing both public and private keys
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// The public key component
    pub public: PublicKey,
    /// The private key component  
    pub private: PrivateKey,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("algorithm", &self.public.metadata.algorithm)
            .field("key_id", &self.public.metadata.key_id)
            .finish()
    }
}

impl PublicKey {
    /// Creates a new ML-KEM-1024 public key for encryption
    pub fn new_mlkem1024(key: Mlkem1024PublicKey, key_id: u64, usage: KeyUsage) -> Self {
        let metadata = KeyMetadata::new(Algorithm::Mlkem1024, usage, key_id);
        let key_bytes = KemPublicKey::as_bytes(&key).to_vec();
        Self {
            key_bytes,
            metadata,
        }
    }

    /// Creates a new ML-DSA-87 public key for signatures
    pub fn new_mldsa87(key: Mldsa87PublicKey, key_id: u64, usage: KeyUsage) -> Self {
        let metadata = KeyMetadata::new(Algorithm::Mldsa87, usage, key_id);
        let key_bytes = SignPublicKey::as_bytes(&key).to_vec();
        Self {
            key_bytes,
            metadata,
        }
    }

    /// Returns the key's metadata
    pub fn metadata(&self) -> &KeyMetadata {
        &self.metadata
    }

    /// Returns the key's unique identifier
    pub fn key_id(&self) -> u64 {
        self.metadata.key_id
    }

    /// Returns the algorithm used by this key
    pub fn algorithm(&self) -> Algorithm {
        self.metadata.algorithm
    }

    /// Returns the key usage flags
    pub fn usage(&self) -> KeyUsage {
        self.metadata.usage
    }

    /// Checks if this key is valid for encryption
    pub fn can_encrypt(&self) -> bool {
        self.metadata.usage.encrypt && self.metadata.algorithm == Algorithm::Mlkem1024
    }

    /// Checks if this key is valid for signature verification
    pub fn can_verify(&self) -> bool {
        self.metadata.algorithm == Algorithm::Mldsa87
    }

    /// Returns the raw key bytes for serialization
    pub fn as_bytes(&self) -> Vec<u8> {
        self.key_bytes.clone()
    }

    /// Computes the fingerprint of this public key using SHA3-256
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&(self.metadata.algorithm as u8).to_be_bytes());
        data.extend_from_slice(&self.as_bytes());
        hash_data(&data)
    }

    /// Returns the ML-KEM-1024 public key if this key supports encryption
    pub fn as_mlkem1024(&self) -> Result<Mlkem1024PublicKey> {
        if self.metadata.algorithm != Algorithm::Mlkem1024 {
            return Err(PqpgpError::key("Key is not a ML-KEM-1024 key"));
        }

        Mlkem1024PublicKey::from_bytes(&self.key_bytes)
            .map_err(|_| PqpgpError::key("Failed to reconstruct ML-KEM-1024 public key from bytes"))
    }

    /// Returns the ML-DSA-87 public key if this key supports verification
    pub fn as_mldsa87(&self) -> Result<Mldsa87PublicKey> {
        if self.metadata.algorithm != Algorithm::Mldsa87 {
            return Err(PqpgpError::key("Key is not a ML-DSA-87 key"));
        }

        Mldsa87PublicKey::from_bytes(&self.key_bytes)
            .map_err(|_| PqpgpError::key("Failed to reconstruct ML-DSA-87 public key from bytes"))
    }
}

impl PrivateKey {
    /// Creates a new ML-KEM-1024 private key for decryption
    pub fn new_mlkem1024(key: Mlkem1024SecretKey, key_id: u64, usage: KeyUsage) -> Self {
        let metadata = KeyMetadata::new(Algorithm::Mlkem1024, usage, key_id);
        let key_bytes = KemSecretKey::as_bytes(&key).to_vec();
        Self {
            storage: PrivateKeyStorage::Unencrypted(key_bytes),
            metadata,
        }
    }

    /// Creates a new ML-DSA-87 private key for signing
    pub fn new_mldsa87(key: Mldsa87SecretKey, key_id: u64, usage: KeyUsage) -> Self {
        let metadata = KeyMetadata::new(Algorithm::Mldsa87, usage, key_id);
        let key_bytes = SignSecretKey::as_bytes(&key).to_vec();
        Self {
            storage: PrivateKeyStorage::Unencrypted(key_bytes),
            metadata,
        }
    }

    /// Encrypts the private key with a password
    pub fn encrypt_with_password(&mut self, password: &Password) -> Result<()> {
        let key_bytes = match &self.storage {
            PrivateKeyStorage::Unencrypted(bytes) => bytes.clone(),
            PrivateKeyStorage::Encrypted(_) => {
                return Err(PqpgpError::key("Private key is already encrypted"));
            }
        };

        let encrypted = EncryptedPrivateKey::encrypt(&key_bytes, password)?;
        self.storage = PrivateKeyStorage::Encrypted(encrypted);
        Ok(())
    }

    /// Decrypts the private key with a password and returns the raw key bytes
    pub fn decrypt_with_password(&self, password: &Password) -> Result<Vec<u8>> {
        match &self.storage {
            PrivateKeyStorage::Unencrypted(bytes) => Ok(bytes.clone()),
            PrivateKeyStorage::Encrypted(encrypted) => encrypted.decrypt(password),
        }
    }

    /// Returns true if the private key is encrypted
    pub fn is_encrypted(&self) -> bool {
        matches!(self.storage, PrivateKeyStorage::Encrypted(_))
    }

    /// Returns the key's metadata
    pub fn metadata(&self) -> &KeyMetadata {
        &self.metadata
    }

    /// Returns the key's unique identifier
    pub fn key_id(&self) -> u64 {
        self.metadata.key_id
    }

    /// Returns the algorithm used by this key
    pub fn algorithm(&self) -> Algorithm {
        self.metadata.algorithm
    }

    /// Checks if this key is valid for decryption
    pub fn can_decrypt(&self) -> bool {
        self.metadata.usage.encrypt && self.metadata.algorithm == Algorithm::Mlkem1024
    }

    /// Checks if this key is valid for signing
    pub fn can_sign(&self) -> bool {
        self.metadata.usage.sign && self.metadata.algorithm == Algorithm::Mldsa87
    }

    /// Returns the ML-KEM-1024 private key if this key supports decryption
    /// For encrypted keys, a password must be provided
    pub fn as_mlkem1024(&self, password: Option<&Password>) -> Result<Mlkem1024SecretKey> {
        if self.metadata.algorithm != Algorithm::Mlkem1024 {
            return Err(PqpgpError::key("Key is not a ML-KEM-1024 key"));
        }

        let key_bytes = match &self.storage {
            PrivateKeyStorage::Unencrypted(bytes) => bytes.clone(),
            PrivateKeyStorage::Encrypted(encrypted) => {
                let password = password.ok_or_else(|| {
                    PqpgpError::password("Password required for encrypted private key")
                })?;
                encrypted.decrypt(password)?
            }
        };

        Mlkem1024SecretKey::from_bytes(&key_bytes)
            .map_err(|_| PqpgpError::key("Failed to reconstruct ML-KEM-1024 secret key from bytes"))
    }

    /// Returns the ML-DSA-87 private key if this key supports signing
    /// For encrypted keys, a password must be provided
    pub fn as_mldsa87(&self, password: Option<&Password>) -> Result<Mldsa87SecretKey> {
        if self.metadata.algorithm != Algorithm::Mldsa87 {
            return Err(PqpgpError::key("Key is not a ML-DSA-87 key"));
        }

        let key_bytes = match &self.storage {
            PrivateKeyStorage::Unencrypted(bytes) => bytes.clone(),
            PrivateKeyStorage::Encrypted(encrypted) => {
                let password = password.ok_or_else(|| {
                    PqpgpError::password("Password required for encrypted private key")
                })?;
                encrypted.decrypt(password)?
            }
        };

        Mldsa87SecretKey::from_bytes(&key_bytes)
            .map_err(|_| PqpgpError::key("Failed to reconstruct ML-DSA-87 secret key from bytes"))
    }
}

impl KeyPair {
    /// Generates a new ML-KEM-1024 key pair for encryption/decryption
    ///
    /// Note: The `rng` parameter is currently ignored as the pqcrypto-mlkem crate
    /// uses its own internal cryptographically secure RNG for key generation.
    /// This is acceptable as the internal RNG provides sufficient cryptographic security.
    ///
    /// Future versions may support custom RNG if the underlying library adds support.
    pub fn generate_mlkem1024<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self> {
        let usage = KeyUsage::encrypt_only();

        // Note: mlkem1024::keypair() uses internal CSPRNG - this is cryptographically secure
        let (public_key, secret_key) = mlkem1024::keypair();

        // Generate deterministic key ID from public key material and current time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key_material = KemPublicKey::as_bytes(&public_key);
        let key_id = generate_key_id(key_material, Algorithm::Mlkem1024, now);

        let public = PublicKey::new_mlkem1024(public_key, key_id, usage);
        let private = PrivateKey::new_mlkem1024(secret_key, key_id, usage);

        Ok(Self { public, private })
    }

    /// Generates a new ML-DSA-87 key pair for signing/verification
    ///
    /// Note: The `rng` parameter is currently ignored as the pqcrypto-mldsa crate
    /// uses its own internal cryptographically secure RNG for key generation.
    /// This is acceptable as the internal RNG provides sufficient cryptographic security.
    ///
    /// Future versions may support custom RNG if the underlying library adds support.
    pub fn generate_mldsa87<R: CryptoRng + RngCore>(_rng: &mut R) -> Result<Self> {
        let usage = KeyUsage::sign_only();

        // Note: mldsa87::keypair() uses internal CSPRNG - this is cryptographically secure
        let (public_key, secret_key) = mldsa87::keypair();

        // Generate deterministic key ID from public key material and current time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key_material = SignPublicKey::as_bytes(&public_key);
        let key_id = generate_key_id(key_material, Algorithm::Mldsa87, now);

        let public = PublicKey::new_mldsa87(public_key, key_id, usage);
        let private = PrivateKey::new_mldsa87(secret_key, key_id, usage);

        Ok(Self { public, private })
    }

    /// Generates a complete key set with both encryption and signing capabilities
    /// Returns (encryption_keypair, signing_keypair)
    pub fn generate_hybrid<R: CryptoRng + RngCore>(rng: &mut R) -> Result<(Self, Self)> {
        let kem_keypair = Self::generate_mlkem1024(rng)?;
        let dsa_keypair = Self::generate_mldsa87(rng)?;
        Ok((kem_keypair, dsa_keypair))
    }

    /// Returns the public key component
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Returns the private key component
    pub fn private_key(&self) -> &PrivateKey {
        &self.private
    }

    /// Returns a mutable reference to the private key component
    pub fn private_key_mut(&mut self) -> &mut PrivateKey {
        &mut self.private
    }

    /// Returns the key's unique identifier
    pub fn key_id(&self) -> u64 {
        self.public.key_id()
    }

    /// Returns the algorithm used by this key pair
    pub fn algorithm(&self) -> Algorithm {
        self.public.algorithm()
    }

    /// Checks if the public and private keys have matching identifiers
    pub fn is_valid(&self) -> bool {
        crate::crypto::key_ids_equal(self.public.key_id(), self.private.key_id())
            && self.public.algorithm() == self.private.algorithm()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey({}, ID: {:016X})",
            self.algorithm(),
            self.key_id()
        )
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrivateKey({}, ID: {:016X})",
            self.algorithm(),
            self.key_id()
        )
    }
}

impl fmt::Display for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyPair({}, ID: {:016X})",
            self.algorithm(),
            self.key_id()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_mlkem1024_key_generation() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();

        assert!(keypair.is_valid());
        assert_eq!(keypair.algorithm(), Algorithm::Mlkem1024);
        assert!(keypair.public_key().can_encrypt());
        assert!(keypair.private_key().can_decrypt());
    }

    #[test]
    fn test_mldsa87_key_generation() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mldsa87(&mut rng).unwrap();

        assert!(keypair.is_valid());
        assert_eq!(keypair.algorithm(), Algorithm::Mldsa87);
        assert!(keypair.public_key().can_verify());
        assert!(keypair.private_key().can_sign());
    }

    #[test]
    fn test_hybrid_key_generation() {
        let mut rng = OsRng;
        let (kem_keypair, dsa_keypair) = KeyPair::generate_hybrid(&mut rng).unwrap();

        assert!(kem_keypair.is_valid());
        assert!(dsa_keypair.is_valid());
        assert_eq!(kem_keypair.algorithm(), Algorithm::Mlkem1024);
        assert_eq!(dsa_keypair.algorithm(), Algorithm::Mldsa87);
        assert_ne!(kem_keypair.key_id(), dsa_keypair.key_id());
    }

    #[test]
    fn test_key_fingerprints() {
        let mut rng = OsRng;
        let keypair1 = KeyPair::generate_mlkem1024(&mut rng).unwrap();
        let keypair2 = KeyPair::generate_mlkem1024(&mut rng).unwrap();

        let fp1 = keypair1.public_key().fingerprint();
        let fp2 = keypair2.public_key().fingerprint();

        assert_ne!(fp1, fp2);
        assert_eq!(fp1.len(), 32);
        assert_eq!(fp2.len(), 32);
    }

    #[test]
    fn test_key_serialization() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mldsa87(&mut rng).unwrap();

        let bytes = keypair.public_key().as_bytes();
        assert!(!bytes.is_empty());

        // Test that the same key produces the same bytes
        let bytes2 = keypair.public_key().as_bytes();
        assert_eq!(bytes, bytes2);
    }
}
