//! Post-quantum hybrid encryption operations.
//!
//! This module provides secure message encryption and decryption using a hybrid
//! approach: ML-KEM-1024 for key encapsulation and AES-256-GCM for symmetric encryption
//! of the actual message content. This provides both post-quantum security and
//! high performance for large messages.

use crate::crypto::keys::{PrivateKey, PublicKey};
use crate::crypto::{Algorithm, Password};
use crate::error::{PqpgpError, Result};
use crate::validation::Validator;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey as PqPublicKey, SharedSecret};
use serde::{Deserialize, Serialize};
use sha3::Sha3_512;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Returns appropriate error message based on debug-errors feature flag
#[inline]
fn encryption_error(detail: &str) -> PqpgpError {
    #[cfg(feature = "debug-errors")]
    {
        PqpgpError::message(format!("Encryption failed: {}", detail))
    }
    #[cfg(not(feature = "debug-errors"))]
    {
        let _ = detail; // Suppress unused variable warning
        PqpgpError::message("Encryption failed")
    }
}

/// Returns appropriate error message based on debug-errors feature flag
#[inline]
fn decryption_error(detail: &str) -> PqpgpError {
    #[cfg(feature = "debug-errors")]
    {
        PqpgpError::message(format!("Decryption failed: {}", detail))
    }
    #[cfg(not(feature = "debug-errors"))]
    {
        let _ = detail; // Suppress unused variable warning
        PqpgpError::message("Decryption failed")
    }
}

/// Constructs AEAD metadata for cryptographic binding
///
/// Binds together timestamp, key ID, algorithms, and KEM ciphertext to prevent tampering
/// and substitution attacks. All components are included in AEAD associated data.
fn build_metadata(created: u64, key_id: u64, ciphertext: &[u8]) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&created.to_be_bytes());
    metadata.extend_from_slice(&key_id.to_be_bytes());
    metadata.push(Algorithm::Mlkem1024 as u8);
    metadata.push(Algorithm::Aes256Gcm as u8);
    metadata.extend_from_slice(ciphertext);
    metadata
}

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
        encrypted_content: Vec<u8>,
        created: u64,
    ) -> Self {
        Self {
            kem_algorithm,
            sym_algorithm,
            recipient_key_id,
            encapsulated_key,
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
        self.encapsulated_key.len() + self.encrypted_content.len()
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
/// # Security Properties
/// - Uses ML-KEM-1024 for post-quantum key encapsulation
/// - Uses AES-256-GCM for authenticated symmetric encryption  
/// - KEM ciphertext bound to AEAD metadata (prevents substitution attacks)
/// - Timestamp binding provides temporal context and prevents tampering with creation time
/// - Deterministic nonce derivation eliminates nonce reuse vulnerabilities
///
/// # Message Size Considerations
/// **Memory Usage**: This function loads the entire message into memory for encryption.
/// For very large messages (approaching the 100MB limit), consider:
/// - Using `encrypt_messages()` to split data into smaller chunks
/// - Implementing streaming encryption at the application layer
/// - Monitoring memory usage during encryption operations
///
/// The current limit of 100MB ensures reasonable memory usage while supporting most
/// practical use cases. Messages larger than this should be chunked at the application level.
///
/// # Replay Protection
/// Messages include cryptographically-bound timestamps. Applications requiring stronger
/// replay protection should implement sequence numbers or session IDs at the protocol layer.
///
/// # Clock Synchronization
/// **IMPORTANT**: Since timestamps are AEAD-authenticated, decryption will fail if sender
/// and receiver clocks are not synchronized. For systems with clock drift or unsynchronized
/// time sources, consider using monotonic counters or session IDs instead of timestamps.
///
/// # Arguments
/// * `recipient_public_key` - The recipient's public key (must be ML-KEM-1024)
/// * `message` - The message to encrypt
///
/// # Returns
/// An `EncryptedMessage` containing the hybrid-encrypted message
///
/// # Examples
/// ```rust,no_run
/// use pqpgp::crypto::{KeyPair, encrypt_message};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let recipient_keypair = KeyPair::generate_mlkem1024()?;
/// let message = b"Hello, post-quantum world!";
/// let encrypted = encrypt_message(recipient_keypair.public_key(), message)?;
/// # Ok(())
/// # }
/// ```
pub fn encrypt_message(
    recipient_public_key: &PublicKey,
    message: &[u8],
) -> Result<EncryptedMessage> {
    // Validate message size first
    Validator::validate_message_size(message)?;

    // Get current timestamp for metadata
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

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
        .map_err(|e| encryption_error(&format!("Failed to get ML-KEM-1024 public key: {}", e)))?;

    // Add ML-KEM public key validation
    if PqPublicKey::as_bytes(&public_key).len() != 1568 {
        return Err(PqpgpError::message("Invalid ML-KEM-1024 public key length"));
    }

    // Generate a random symmetric key and encapsulate it
    let (shared_secret, ciphertext) = mlkem1024::encapsulate(&public_key);

    // Create salt by binding KEM ciphertext to prevent mix-and-match attacks
    let mut salt = Vec::with_capacity(b"PQPGP-v1-".len() + ciphertext.as_bytes().len());
    salt.extend_from_slice(b"PQPGP-v1-");
    salt.extend_from_slice(ciphertext.as_bytes());

    // Use HKDF-SHA3-512 for proper key derivation with KEM ciphertext binding
    let hk = Hkdf::<Sha3_512>::new(
        Some(&salt), // Salt includes KEM ciphertext to prevent substitution attacks
        shared_secret.as_bytes(),
    );

    // Create metadata for authentication including KEM ciphertext (defense in depth)
    // Note: Timestamp is included in AEAD metadata to prevent tampering and provide
    // cryptographic binding to creation time. Messages are "locked" to their send-time.
    let metadata = build_metadata(
        created,
        recipient_public_key.key_id(),
        ciphertext.as_bytes(),
    );

    // Derive AES-256 key with context information
    let mut aes_key_material = Zeroizing::new([0u8; 32]);
    hk.expand(b"PQPGP-v1 AES-256-GCM key", aes_key_material.as_mut())
        .map_err(|e| encryption_error(&format!("HKDF key derivation failed: {}", e)))?;

    // Note: shared_secret will be automatically dropped/zeroized by ML-KEM implementation
    // after this scope since we derive directly from the original

    // Generate a deterministic nonce using HKDF for better security
    let mut nonce_bytes = [0u8; 12];
    hk.expand(b"PQPGP-v1 AES-GCM nonce", &mut nonce_bytes)
        .map_err(|e| encryption_error(&format!("HKDF nonce derivation failed: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Initialize AES-GCM cipher (copy the key material first)
    let aes_key = Key::<Aes256Gcm>::from_slice(aes_key_material.as_ref());
    let cipher = Aes256Gcm::new(aes_key);

    // Securely clear the key material after cipher creation
    aes_key_material.zeroize();

    // Encrypt the message with metadata as associated data
    let payload = Payload {
        msg: message,
        aad: &metadata,
    };
    let encrypted_content = cipher
        .encrypt(nonce, payload)
        .map_err(|_| encryption_error("Failed to encrypt message with AES-GCM"))?;

    // Get the ciphertext bytes using safe serialization
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();

    Ok(EncryptedMessage::new(
        Algorithm::Mlkem1024,
        Algorithm::Aes256Gcm,
        recipient_public_key.key_id(),
        ciphertext_bytes,
        encrypted_content,
        created,
    ))
}

/// Decrypts a message using post-quantum hybrid decryption
///
/// # Security Properties  
/// - Verifies cryptographic binding of all metadata (timestamp, key ID, algorithms, KEM ciphertext)
/// - Uses constant-time operations to prevent timing attacks
/// - Automatically zeroizes sensitive cryptographic material
/// - Returns generic error messages to prevent oracle attacks
///
/// # Arguments
/// * `private_key` - The recipient's private key (must be ML-KEM-1024)  
/// * `encrypted_message` - The encrypted message to decrypt
/// * `password` - Optional password if private key is encrypted
///
/// # Returns
/// The original plaintext message
///
/// # Examples
/// ```rust,no_run
/// use pqpgp::crypto::{KeyPair, encrypt_message, decrypt_message};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let keypair = KeyPair::generate_mlkem1024()?;
/// let message = b"Hello, post-quantum world!";
/// let encrypted = encrypt_message(keypair.public_key(), message)?;
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
        // Use timing-safe error to prevent key enumeration attacks
        return crate::crypto::TimingSafeError::delayed_error(PqpgpError::message(
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
        .map_err(|e| decryption_error(&format!("Failed to get ML-KEM-1024 secret key: {}", e)))?;

    // Reconstruct ciphertext
    let ciphertext = mlkem1024::Ciphertext::from_bytes(&encrypted_message.encapsulated_key)
        .map_err(|_| {
            decryption_error(&format!(
                "Failed to reconstruct ML-KEM-1024 ciphertext: expected length, got {} bytes",
                encrypted_message.encapsulated_key.len()
            ))
        })?;

    // Decapsulate to get the shared secret
    let shared_secret = mlkem1024::decapsulate(&ciphertext, &secret_key);

    // Create salt by binding KEM ciphertext (same as encryption)
    let mut salt =
        Vec::with_capacity(b"PQPGP-v1-".len() + encrypted_message.encapsulated_key.len());
    salt.extend_from_slice(b"PQPGP-v1-");
    salt.extend_from_slice(&encrypted_message.encapsulated_key);

    // Use HKDF-SHA3-512 for proper key derivation (same as encryption)
    let hk = Hkdf::<Sha3_512>::new(
        Some(&salt), // Same KEM ciphertext binding as encryption
        shared_secret.as_bytes(),
    );

    // Create metadata for AEAD verification including KEM ciphertext (same as encryption)
    // Note: Timestamp must match exactly due to AEAD authentication binding
    let metadata = build_metadata(
        encrypted_message.created,
        encrypted_message.recipient_key_id,
        &encrypted_message.encapsulated_key,
    );

    // Derive AES-256 key with same context as during encryption
    let mut aes_key_material = Zeroizing::new([0u8; 32]);
    hk.expand(b"PQPGP-v1 AES-256-GCM key", aes_key_material.as_mut())
        .map_err(|e| decryption_error(&format!("HKDF key derivation failed: {}", e)))?;

    // Note: shared_secret will be automatically dropped/zeroized by ML-KEM implementation
    // after this scope since we derive directly from the original

    // Derive the same deterministic nonce using HKDF
    let mut nonce_bytes = [0u8; 12];
    hk.expand(b"PQPGP-v1 AES-GCM nonce", &mut nonce_bytes)
        .map_err(|e| decryption_error(&format!("HKDF nonce derivation failed: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Nonce is deterministically derived - no stored validation needed
    // AEAD authentication will catch any tampering with the ciphertext

    // Initialize AES-GCM cipher (copy the key material first)
    let aes_key = Key::<Aes256Gcm>::from_slice(aes_key_material.as_ref());
    let cipher = Aes256Gcm::new(aes_key);

    // Securely clear the key material after cipher creation
    aes_key_material.zeroize();

    // Decrypt the message with metadata as associated data
    let payload = Payload {
        msg: encrypted_message.encrypted_content.as_ref(),
        aad: &metadata,
    };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| decryption_error("Failed to decrypt message or authentication failed"))?;

    Ok(plaintext)
}

/// Encrypts multiple messages for the same recipient efficiently using batch mode
///
/// This function is optimized for encrypting multiple messages to the same recipient:
/// - Performs single ML-KEM encapsulation (instead of one per message)
/// - Derives per-message AES keys and nonces from the shared secret
/// - Significantly faster than calling encrypt_message() repeatedly
///
/// # Security Properties
/// - Each message gets a unique AES key and nonce (derived from message index)
/// - All security properties of single-message encryption are maintained
/// - Cryptographic binding between all messages in the batch
///
/// # Memory Management for Large Data
/// **Chunking Strategy**: This function is ideal for splitting large data into manageable chunks:
/// ```rust,no_run
/// # use pqpgp::crypto::{KeyPair, encrypt_messages};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let recipient_keypair = KeyPair::generate_mlkem1024()?;
/// # let large_data = vec![0u8; 100 * 1024 * 1024]; // 100MB of data
/// // Example: Encrypt a large file in 50MB chunks
/// let chunk_size = 50 * 1024 * 1024; // 50MB chunks
/// let chunks: Vec<&[u8]> = large_data.chunks(chunk_size).collect();
/// let encrypted_chunks = encrypt_messages(recipient_keypair.public_key(), &chunks)?;
/// # Ok(())
/// # }
/// ```
/// This approach keeps memory usage bounded while maintaining efficiency through batch processing.
///
/// # Arguments
/// * `recipient_public_key` - The recipient's public key (must be ML-KEM-1024)
/// * `messages` - Slice of message byte slices to encrypt
///
/// # Returns
/// Vector of encrypted messages, one per input message
pub fn encrypt_messages(
    recipient_public_key: &PublicKey,
    messages: &[&[u8]],
) -> Result<Vec<EncryptedMessage>> {
    if messages.is_empty() {
        return Ok(Vec::new());
    }

    // Get current timestamp for all messages in batch
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

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
        .map_err(|e| encryption_error(&format!("Failed to get ML-KEM-1024 public key: {}", e)))?;

    // Add ML-KEM public key validation
    if PqPublicKey::as_bytes(&public_key).len() != 1568 {
        return Err(PqpgpError::message("Invalid ML-KEM-1024 public key length"));
    }

    // Single ML-KEM encapsulation for all messages
    let (shared_secret, ciphertext) = mlkem1024::encapsulate(&public_key);

    // Create salt by binding KEM ciphertext to prevent mix-and-match attacks
    let mut salt = Vec::with_capacity(b"PQPGP-v1-".len() + ciphertext.as_bytes().len());
    salt.extend_from_slice(b"PQPGP-v1-");
    salt.extend_from_slice(ciphertext.as_bytes());

    // Use HKDF-SHA3-512 for root key derivation
    let hk = Hkdf::<Sha3_512>::new(
        Some(&salt), // Salt includes KEM ciphertext to prevent substitution attacks
        shared_secret.as_bytes(),
    );

    // Get the ciphertext bytes once
    let ciphertext_bytes = ciphertext.as_bytes().to_vec();

    // Process each message with derived keys
    let mut encrypted_messages = Vec::with_capacity(messages.len());
    for (msg_index, message) in messages.iter().enumerate() {
        // Validate message size
        Validator::validate_message_size(message)?;

        // Create per-message metadata
        let metadata = build_metadata(
            created,
            recipient_public_key.key_id(),
            ciphertext.as_bytes(),
        );

        // Derive per-message AES key using message index for domain separation
        // Use compatible derivation: single message uses standard context, batch uses indexed context
        let mut aes_key_material = Zeroizing::new([0u8; 32]);
        let key_info = if messages.len() == 1 {
            b"PQPGP-v1 AES-256-GCM key".to_vec()
        } else {
            format!("PQPGP-v1 AES-256-GCM key msg:{}", msg_index).into_bytes()
        };
        hk.expand(&key_info, aes_key_material.as_mut())
            .map_err(|e| encryption_error(&format!("HKDF key derivation failed: {}", e)))?;

        // Derive per-message nonce using message index for domain separation
        let mut nonce_bytes = [0u8; 12];
        let nonce_info = if messages.len() == 1 {
            b"PQPGP-v1 AES-GCM nonce".to_vec()
        } else {
            format!("PQPGP-v1 AES-GCM nonce msg:{}", msg_index).into_bytes()
        };
        hk.expand(&nonce_info, &mut nonce_bytes)
            .map_err(|e| encryption_error(&format!("HKDF nonce derivation failed: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Initialize AES-GCM cipher for this message
        let aes_key = Key::<Aes256Gcm>::from_slice(aes_key_material.as_ref());
        let cipher = Aes256Gcm::new(aes_key);

        // Encrypt the message with metadata as associated data
        let payload = Payload {
            msg: message,
            aad: &metadata,
        };
        let encrypted_content = cipher
            .encrypt(nonce, payload)
            .map_err(|_| encryption_error("Failed to encrypt message with AES-GCM"))?;

        // Create encrypted message (reuse same ciphertext for all messages)
        encrypted_messages.push(EncryptedMessage::new(
            Algorithm::Mlkem1024,
            Algorithm::Aes256Gcm,
            recipient_public_key.key_id(),
            ciphertext_bytes.clone(), // Same KEM ciphertext for all messages
            encrypted_content,
            created,
        ));
    }

    Ok(encrypted_messages)
}

/// Decrypts multiple messages for the same recipient
///
/// Automatically detects batch-encrypted messages (same KEM ciphertext + timestamp)
/// and uses optimized batch decryption for efficiency.
pub fn decrypt_messages(
    private_key: &PrivateKey,
    encrypted_messages: &[EncryptedMessage],
    password: Option<&Password>,
) -> Result<Vec<Vec<u8>>> {
    if encrypted_messages.is_empty() {
        return Ok(Vec::new());
    }

    // Check if messages were batch-encrypted (same KEM ciphertext and timestamp)
    let is_batch = encrypted_messages.len() > 1 && {
        let first = &encrypted_messages[0];
        encrypted_messages[1..].iter().all(|msg| {
            msg.encapsulated_key == first.encapsulated_key && msg.created == first.created
        })
    };

    if is_batch {
        decrypt_messages_batch(private_key, encrypted_messages, password)
    } else {
        // Regular per-message decryption
        encrypted_messages
            .iter()
            .map(|encrypted_message| decrypt_message(private_key, encrypted_message, password))
            .collect()
    }
}

/// Optimized batch decryption for messages encrypted with encrypt_messages()
fn decrypt_messages_batch(
    private_key: &PrivateKey,
    encrypted_messages: &[EncryptedMessage],
    password: Option<&Password>,
) -> Result<Vec<Vec<u8>>> {
    if encrypted_messages.is_empty() {
        return Ok(Vec::new());
    }

    // Use first message for shared parameters
    let encrypted_message = &encrypted_messages[0];

    // Verify this is a decryption key
    if !private_key.can_decrypt() {
        return Err(PqpgpError::message(
            "Private key cannot be used for decryption",
        ));
    }

    // Verify key ID matches using constant-time comparison
    if !crate::crypto::key_ids_equal(private_key.key_id(), encrypted_message.recipient_key_id) {
        return crate::crypto::TimingSafeError::delayed_error(PqpgpError::message(
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
        .map_err(|e| decryption_error(&format!("Failed to get ML-KEM-1024 secret key: {}", e)))?;

    // Reconstruct ciphertext
    let ciphertext = mlkem1024::Ciphertext::from_bytes(&encrypted_message.encapsulated_key)
        .map_err(|_| {
            decryption_error(&format!(
                "Failed to reconstruct ML-KEM-1024 ciphertext: expected length, got {} bytes",
                encrypted_message.encapsulated_key.len()
            ))
        })?;

    // Decapsulate to get the shared secret
    let shared_secret = mlkem1024::decapsulate(&ciphertext, &secret_key);

    // Create salt by binding KEM ciphertext (same as encryption)
    let mut salt =
        Vec::with_capacity(b"PQPGP-v1-".len() + encrypted_message.encapsulated_key.len());
    salt.extend_from_slice(b"PQPGP-v1-");
    salt.extend_from_slice(&encrypted_message.encapsulated_key);

    // Use HKDF-SHA3-512 for proper key derivation (same as encryption)
    let hk = Hkdf::<Sha3_512>::new(
        Some(&salt), // Same KEM ciphertext binding as encryption
        shared_secret.as_bytes(),
    );

    // Decrypt each message with its derived key
    let mut decrypted_messages = Vec::with_capacity(encrypted_messages.len());
    for (msg_index, encrypted_message) in encrypted_messages.iter().enumerate() {
        // Create metadata for AEAD verification including KEM ciphertext (same as encryption)
        let metadata = build_metadata(
            encrypted_message.created,
            encrypted_message.recipient_key_id,
            &encrypted_message.encapsulated_key,
        );

        // Derive per-message AES key (same as batch encryption)
        let mut aes_key_material = Zeroizing::new([0u8; 32]);
        let key_info = format!("PQPGP-v1 AES-256-GCM key msg:{}", msg_index);
        hk.expand(key_info.as_bytes(), aes_key_material.as_mut())
            .map_err(|e| decryption_error(&format!("HKDF key derivation failed: {}", e)))?;

        // Derive per-message nonce (same as batch encryption)
        let mut nonce_bytes = [0u8; 12];
        let nonce_info = format!("PQPGP-v1 AES-GCM nonce msg:{}", msg_index);
        hk.expand(nonce_info.as_bytes(), &mut nonce_bytes)
            .map_err(|e| decryption_error(&format!("HKDF nonce derivation failed: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Initialize AES-GCM cipher for this message
        let aes_key = Key::<Aes256Gcm>::from_slice(aes_key_material.as_ref());
        let cipher = Aes256Gcm::new(aes_key);

        // Decrypt the message with metadata as associated data
        let payload = Payload {
            msg: encrypted_message.encrypted_content.as_ref(),
            aad: &metadata,
        };
        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| decryption_error("Failed to decrypt message or authentication failed"))?;

        decrypted_messages.push(plaintext);
    }

    Ok(decrypted_messages)
}

/// Encrypts structured data (automatically serializes)
pub fn encrypt_data<T: Serialize>(
    recipient_public_key: &PublicKey,
    data: &T,
) -> Result<EncryptedMessage> {
    let serialized = bincode::serialize(data)
        .map_err(|e| PqpgpError::serialization(format!("Failed to serialize data: {}", e)))?;
    encrypt_message(recipient_public_key, &serialized)
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

    #[test]
    fn test_hybrid_encryption_decryption() {
        let keypair = KeyPair::generate_mlkem1024().unwrap();

        let message = b"Hello, post-quantum hybrid encryption!";

        // Encrypt message
        let encrypted = encrypt_message(keypair.public_key(), message).unwrap();

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
        let signing_keypair = KeyPair::generate_mldsa87().unwrap();

        let message = b"Test message";

        // ML-DSA-87 key should not be able to encrypt
        assert!(encrypt_message(signing_keypair.public_key(), message).is_err());
    }

    #[test]
    fn test_decryption_with_wrong_key_fails() {
        let keypair1 = KeyPair::generate_mlkem1024().unwrap();
        let keypair2 = KeyPair::generate_mlkem1024().unwrap();

        let message = b"Test message";
        let encrypted = encrypt_message(keypair1.public_key(), message).unwrap();

        // Wrong key should fail decryption
        assert!(decrypt_message(keypair2.private_key(), &encrypted, None).is_err());
    }

    #[test]
    fn test_message_authentication() {
        let keypair = KeyPair::generate_mlkem1024().unwrap();

        let message = b"Test message";
        let mut encrypted = encrypt_message(keypair.public_key(), message).unwrap();

        // Tamper with encrypted content
        if let Some(byte) = encrypted.encrypted_content.get_mut(0) {
            *byte = byte.wrapping_add(1);
        }

        // Decryption should fail due to authentication
        assert!(decrypt_message(keypair.private_key(), &encrypted, None).is_err());
    }

    #[test]
    fn test_large_message_encryption() {
        let keypair = KeyPair::generate_mlkem1024().unwrap();

        // Create a large message (1MB)
        let large_message = vec![0x42u8; 1024 * 1024];

        let encrypted = encrypt_message(keypair.public_key(), &large_message).unwrap();
        let decrypted = decrypt_message(keypair.private_key(), &encrypted, None).unwrap();

        assert_eq!(large_message, decrypted);
    }

    #[test]
    fn test_batch_encryption_decryption() {
        let keypair = KeyPair::generate_mlkem1024().unwrap();

        let messages = [
            b"First message".as_slice(),
            b"Second message".as_slice(),
            b"Third message".as_slice(),
        ];

        let encrypted_messages = encrypt_messages(keypair.public_key(), &messages).unwrap();
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

        let keypair = KeyPair::generate_mlkem1024().unwrap();

        let data = TestData {
            name: "test".to_string(),
            value: 12345,
            items: vec!["item1".to_string(), "item2".to_string()],
        };

        let encrypted = encrypt_data(keypair.public_key(), &data).unwrap();
        let decrypted: TestData = decrypt_data(keypair.private_key(), &encrypted, None).unwrap();

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_encrypted_message_display() {
        let keypair = KeyPair::generate_mlkem1024().unwrap();

        let message = b"Test message";
        let encrypted = encrypt_message(keypair.public_key(), message).unwrap();

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
