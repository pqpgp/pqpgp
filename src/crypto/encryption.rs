//! Post-quantum hybrid encryption operations.
//!
//! This module provides secure message encryption and decryption using a hybrid
//! approach: ML-KEM-1024 for key encapsulation and AES-256-GCM for symmetric encryption
//! of the actual message content. This provides both post-quantum security and
//! high performance for large messages.

use crate::crypto::keys::{PrivateKey, PublicKey};
use crate::crypto::{hash_data, secure_random_bytes, Algorithm, Password};
use crate::error::{PqpgpError, Result};
use crate::validation::Validator;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// A hybrid encrypted message containing both the encapsulated key and encrypted content
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedMessage {
    /// The algorithm used for key encapsulation
    pub kem_algorithm: Algorithm,
    /// The algorithm used for symmetric encryption
    pub sym_algorithm: Algorithm,
    /// The recipient's key ID
    pub recipient_key_id: u64,
    /// The encapsulated symmetric key (ML-KEM-1024 ciphertext)
    pub encapsulated_key: Vec<u8>,
    /// The AES-GCM nonce (12 bytes)
    pub nonce: Vec<u8>,
    /// The encrypted message content with authentication tag
    pub encrypted_content: Vec<u8>,
    /// Timestamp when message was encrypted (Unix timestamp)
    pub created: u64,
}

impl std::fmt::Debug for EncryptedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedMessage")
            .field("kem_algorithm", &self.kem_algorithm)
            .field("sym_algorithm", &self.sym_algorithm)
            .field(
                "recipient_key_id",
                &format!("{:016X}", self.recipient_key_id),
            )
            .field("encapsulated_key_size", &self.encapsulated_key.len())
            .field("encrypted_content_size", &self.encrypted_content.len())
            .field("created", &self.created)
            .finish()
    }
}

impl EncryptedMessage {
    /// Creates a new encrypted message
    pub fn new(
        kem_algorithm: Algorithm,
        sym_algorithm: Algorithm,
        recipient_key_id: u64,
        encapsulated_key: Vec<u8>,
        nonce: Vec<u8>,
        encrypted_content: Vec<u8>,
        created: u64,
    ) -> Self {
        Self {
            kem_algorithm,
            sym_algorithm,
            recipient_key_id,
            encapsulated_key,
            nonce,
            encrypted_content,
            created,
        }
    }

    /// Returns the recipient's key ID
    pub fn recipient_key_id(&self) -> u64 {
        self.recipient_key_id
    }

    /// Returns the total size of the encrypted message
    pub fn total_size(&self) -> usize {
        self.encapsulated_key.len() + self.nonce.len() + self.encrypted_content.len()
    }

    /// Returns the creation timestamp
    pub fn created(&self) -> u64 {
        self.created
    }
}

impl fmt::Display for EncryptedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EncryptedMessage(To: {:016X}, Size: {} bytes, {}+{})",
            self.recipient_key_id,
            self.total_size(),
            self.kem_algorithm,
            self.sym_algorithm
        )
    }
}

/// Encrypts a message using post-quantum hybrid encryption
///
/// # Arguments
/// * `recipient_public_key` - The recipient's public key (must be ML-KEM-1024)
/// * `message` - The message to encrypt
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
/// An `EncryptedMessage` containing the hybrid-encrypted message
///
/// # Examples
/// ```rust,no_run
/// use pqpgp::crypto::{KeyPair, encrypt_message};
/// use rand::rngs::OsRng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = OsRng;
/// let recipient_keypair = KeyPair::generate_mlkem1024(&mut rng)?;
/// let message = b"Hello, post-quantum world!";
/// let encrypted = encrypt_message(recipient_keypair.public_key(), message, &mut rng)?;
/// # Ok(())
/// # }
/// ```
pub fn encrypt_message<R: CryptoRng + RngCore>(
    recipient_public_key: &PublicKey,
    message: &[u8],
    rng: &mut R,
) -> Result<EncryptedMessage> {
    // Validate message size first
    Validator::validate_message_size(message)?;

    // Verify this is an encryption key
    if !recipient_public_key.can_encrypt() {
        return Err(PqpgpError::message(
            "Public key cannot be used for encryption",
        ));
    }

    // Only support ML-KEM-1024 for now
    if recipient_public_key.algorithm() != Algorithm::Mlkem1024 {
        return Err(PqpgpError::message(
            "Only ML-KEM-1024 encryption is supported",
        ));
    }

    // Get the reconstructed ML-KEM-1024 public key
    let public_key = recipient_public_key
        .as_mlkem1024()
        .map_err(|e| PqpgpError::message(format!("Failed to get ML-KEM-1024 public key: {}", e)))?;

    // Generate a random symmetric key and encapsulate it
    let (shared_secret, ciphertext) = mlkem1024::encapsulate(&public_key);

    // Derive AES key from the shared secret using a KDF
    let hash = hash_data(shared_secret.as_bytes());
    // Take the first 32 bytes of SHA3-512 for AES-256 key derivation
    let mut aes_key_material = [0u8; 32];
    aes_key_material.copy_from_slice(&hash[..32]);

    // Generate a random nonce for AES-GCM
    let nonce_bytes = secure_random_bytes(rng, 12); // AES-GCM nonce is 12 bytes
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Initialize AES-GCM cipher (copy the key material first)
    let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_material);
    let cipher = Aes256Gcm::new(aes_key);

    // Securely clear the key material after cipher creation
    aes_key_material.zeroize();

    // Encrypt the message
    let encrypted_content = cipher
        .encrypt(nonce, message)
        .map_err(|_| PqpgpError::message("Failed to encrypt message with AES-GCM"))?;

    // Get current timestamp
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Get the ciphertext bytes using safe serialization
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();

    Ok(EncryptedMessage::new(
        Algorithm::Mlkem1024,
        Algorithm::Aes256Gcm,
        recipient_public_key.key_id(),
        ciphertext_bytes,
        nonce_bytes,
        encrypted_content,
        created,
    ))
}

/// Decrypts a message using post-quantum hybrid decryption
///
/// # Arguments
/// * `private_key` - The recipient's private key (must be ML-KEM-1024)
/// * `encrypted_message` - The encrypted message to decrypt
///
/// # Returns
/// The original plaintext message
///
/// # Examples
/// ```rust,no_run
/// use pqpgp::crypto::{KeyPair, encrypt_message, decrypt_message};
/// use rand::rngs::OsRng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = OsRng;
/// let keypair = KeyPair::generate_mlkem1024(&mut rng)?;
/// let message = b"Hello, post-quantum world!";
/// let encrypted = encrypt_message(keypair.public_key(), message, &mut rng)?;
/// let decrypted = decrypt_message(keypair.private_key(), &encrypted, None)?;
/// assert_eq!(message, &decrypted[..]);
/// # Ok(())
/// # }
/// ```
pub fn decrypt_message(
    private_key: &PrivateKey,
    encrypted_message: &EncryptedMessage,
    password: Option<&Password>,
) -> Result<Vec<u8>> {
    // Verify this is a decryption key
    if !private_key.can_decrypt() {
        return Err(PqpgpError::message(
            "Private key cannot be used for decryption",
        ));
    }

    // Verify key ID matches using constant-time comparison
    if !crate::crypto::key_ids_equal(private_key.key_id(), encrypted_message.recipient_key_id) {
        return Err(PqpgpError::message(
            "Key ID doesn't match encrypted message recipient",
        ));
    }

    // Verify algorithms
    if encrypted_message.kem_algorithm != Algorithm::Mlkem1024 {
        return Err(PqpgpError::message(
            "Only ML-KEM-1024 decryption is supported",
        ));
    }
    if encrypted_message.sym_algorithm != Algorithm::Aes256Gcm {
        return Err(PqpgpError::message(
            "Only AES-256-GCM decryption is supported",
        ));
    }

    // Get the reconstructed ML-KEM-1024 secret key
    let secret_key = private_key
        .as_mlkem1024(password)
        .map_err(|e| PqpgpError::message(format!("Failed to get ML-KEM-1024 secret key: {}", e)))?;

    // Reconstruct ciphertext
    let ciphertext = mlkem1024::Ciphertext::from_bytes(&encrypted_message.encapsulated_key)
        .map_err(|_| PqpgpError::message(format!(
            "Failed to reconstruct ML-KEM-1024 ciphertext: expected length based on temporary CT, got {} bytes",
            encrypted_message.encapsulated_key.len()
        )))?;

    // Decapsulate to get the shared secret
    let shared_secret = mlkem1024::decapsulate(&ciphertext, &secret_key);

    // Derive AES key from the shared secret (same as during encryption)
    let hash = hash_data(shared_secret.as_bytes());
    // Take the first 32 bytes of SHA3-512 for AES-256 key derivation
    let mut aes_key_material = [0u8; 32];
    aes_key_material.copy_from_slice(&hash[..32]);

    // Verify nonce length with validation
    Validator::validate_nonce_size(&encrypted_message.nonce, 12)?;
    let nonce = Nonce::from_slice(&encrypted_message.nonce);

    // Initialize AES-GCM cipher (copy the key material first)
    let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_material);
    let cipher = Aes256Gcm::new(aes_key);

    // Securely clear the key material after cipher creation
    aes_key_material.zeroize();

    // Decrypt the message
    let plaintext = cipher
        .decrypt(nonce, encrypted_message.encrypted_content.as_ref())
        .map_err(|_| PqpgpError::message("Failed to decrypt message or authentication failed"))?;

    Ok(plaintext)
}

/// Encrypts multiple messages for the same recipient efficiently
pub fn encrypt_messages<R: CryptoRng + RngCore>(
    recipient_public_key: &PublicKey,
    messages: &[&[u8]],
    rng: &mut R,
) -> Result<Vec<EncryptedMessage>> {
    messages
        .iter()
        .map(|message| encrypt_message(recipient_public_key, message, rng))
        .collect()
}

/// Decrypts multiple messages for the same recipient
pub fn decrypt_messages(
    private_key: &PrivateKey,
    encrypted_messages: &[EncryptedMessage],
    password: Option<&Password>,
) -> Result<Vec<Vec<u8>>> {
    encrypted_messages
        .iter()
        .map(|encrypted_message| decrypt_message(private_key, encrypted_message, password))
        .collect()
}

/// Encrypts structured data (automatically serializes)
pub fn encrypt_data<T: Serialize, R: CryptoRng + RngCore>(
    recipient_public_key: &PublicKey,
    data: &T,
    rng: &mut R,
) -> Result<EncryptedMessage> {
    let serialized = bincode::serialize(data)
        .map_err(|e| PqpgpError::serialization(format!("Failed to serialize data: {}", e)))?;
    encrypt_message(recipient_public_key, &serialized, rng)
}

/// Decrypts structured data
pub fn decrypt_data<T: for<'de> Deserialize<'de>>(
    private_key: &PrivateKey,
    encrypted_message: &EncryptedMessage,
    password: Option<&Password>,
) -> Result<T> {
    let decrypted_bytes = decrypt_message(private_key, encrypted_message, password)?;
    let data = bincode::deserialize(&decrypted_bytes)
        .map_err(|e| PqpgpError::serialization(format!("Failed to deserialize data: {}", e)))?;
    Ok(data)
}

/// Estimates the encrypted message size for a given plaintext size
pub fn estimate_encrypted_size(plaintext_size: usize) -> usize {
    // Get actual ciphertext size - it's always the same for ML-KEM-1024
    let ciphertext_size = std::mem::size_of::<mlkem1024::Ciphertext>();

    ciphertext_size + // Encapsulated key
    12 + // Nonce  
    plaintext_size + // Message content
    16 // AES-GCM authentication tag
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use rand::rngs::OsRng;

    #[test]
    fn test_hybrid_encryption_decryption() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();

        let message = b"Hello, post-quantum hybrid encryption!";

        // Encrypt message
        let encrypted = encrypt_message(keypair.public_key(), message, &mut rng).unwrap();

        // Verify encrypted message properties
        assert_eq!(encrypted.kem_algorithm, Algorithm::Mlkem1024);
        assert_eq!(encrypted.sym_algorithm, Algorithm::Aes256Gcm);
        assert_eq!(encrypted.recipient_key_id, keypair.key_id());
        assert!(!encrypted.encrypted_content.is_empty());

        // Decrypt message
        let decrypted = decrypt_message(keypair.private_key(), &encrypted, None).unwrap();

        // Verify decryption
        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test_encryption_with_wrong_key_type_fails() {
        let mut rng = OsRng;
        let signing_keypair = KeyPair::generate_mldsa87(&mut rng).unwrap();

        let message = b"Test message";

        // ML-DSA-87 key should not be able to encrypt
        assert!(encrypt_message(signing_keypair.public_key(), message, &mut rng).is_err());
    }

    #[test]
    fn test_decryption_with_wrong_key_fails() {
        let mut rng = OsRng;
        let keypair1 = KeyPair::generate_mlkem1024(&mut rng).unwrap();
        let keypair2 = KeyPair::generate_mlkem1024(&mut rng).unwrap();

        let message = b"Test message";
        let encrypted = encrypt_message(keypair1.public_key(), message, &mut rng).unwrap();

        // Wrong key should fail decryption
        assert!(decrypt_message(keypair2.private_key(), &encrypted, None).is_err());
    }

    #[test]
    fn test_message_authentication() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();

        let message = b"Test message";
        let mut encrypted = encrypt_message(keypair.public_key(), message, &mut rng).unwrap();

        // Tamper with encrypted content
        if let Some(byte) = encrypted.encrypted_content.get_mut(0) {
            *byte = byte.wrapping_add(1);
        }

        // Decryption should fail due to authentication
        assert!(decrypt_message(keypair.private_key(), &encrypted, None).is_err());
    }

    #[test]
    fn test_large_message_encryption() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();

        // Create a large message (1MB)
        let large_message = vec![0x42u8; 1024 * 1024];

        let encrypted = encrypt_message(keypair.public_key(), &large_message, &mut rng).unwrap();
        let decrypted = decrypt_message(keypair.private_key(), &encrypted, None).unwrap();

        assert_eq!(large_message, decrypted);
    }

    #[test]
    fn test_batch_encryption_decryption() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();

        let messages = [
            b"First message".as_slice(),
            b"Second message".as_slice(),
            b"Third message".as_slice(),
        ];

        let encrypted_messages =
            encrypt_messages(keypair.public_key(), &messages, &mut rng).unwrap();
        assert_eq!(encrypted_messages.len(), 3);

        let decrypted_messages =
            decrypt_messages(keypair.private_key(), &encrypted_messages, None).unwrap();
        assert_eq!(decrypted_messages.len(), 3);

        for (original, decrypted) in messages.iter().zip(decrypted_messages.iter()) {
            assert_eq!(original, &decrypted.as_slice());
        }
    }

    #[test]
    fn test_structured_data_encryption() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestData {
            name: String,
            value: u64,
            items: Vec<String>,
        }

        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();

        let data = TestData {
            name: "test".to_string(),
            value: 12345,
            items: vec!["item1".to_string(), "item2".to_string()],
        };

        let encrypted = encrypt_data(keypair.public_key(), &data, &mut rng).unwrap();
        let decrypted: TestData = decrypt_data(keypair.private_key(), &encrypted, None).unwrap();

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_encrypted_message_display() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();

        let message = b"Test message";
        let encrypted = encrypt_message(keypair.public_key(), message, &mut rng).unwrap();

        let display_str = format!("{}", encrypted);
        assert!(display_str.contains("EncryptedMessage"));
        assert!(display_str.contains(&format!("{:016X}", keypair.key_id())));
        assert!(display_str.contains("ML-KEM-1024"));
        assert!(display_str.contains("AES-256-GCM"));
    }

    #[test]
    fn test_encryption_size_estimation() {
        let plaintext_size = 1000;
        let estimated_size = estimate_encrypted_size(plaintext_size);

        // Should be plaintext + overhead
        assert!(estimated_size > plaintext_size);
        assert!(estimated_size < plaintext_size + 2000); // Reasonable overhead
    }
}
