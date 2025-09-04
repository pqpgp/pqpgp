//! Post-quantum digital signature operations.
//!
//! This module provides secure digital signing and verification using ML-DSA-65,
//! implementing both detached signatures and signature verification with proper
//! message authentication and integrity checking.

use crate::crypto::keys::{PrivateKey, PublicKey};
use crate::crypto::{hash_data, Algorithm, Password};
use crate::error::{PqpgpError, Result};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::DetachedSignature;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A post-quantum digital signature
#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    /// The signature algorithm used
    pub algorithm: Algorithm,
    /// The key ID that created this signature
    pub key_id: u64,
    /// The actual signature bytes
    pub signature_bytes: Vec<u8>,
    /// Timestamp when signature was created (Unix timestamp)
    pub created: u64,
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("algorithm", &self.algorithm)
            .field("key_id", &format!("{:016X}", self.key_id))
            .field("signature_size", &self.signature_bytes.len())
            .field("created", &self.created)
            .finish()
    }
}

impl Signature {
    /// Creates a new signature with the specified parameters
    pub fn new(algorithm: Algorithm, key_id: u64, signature_bytes: Vec<u8>, created: u64) -> Self {
        Self {
            algorithm,
            key_id,
            signature_bytes,
            created,
        }
    }

    /// Returns the signature algorithm
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the key ID that created this signature
    pub fn key_id(&self) -> u64 {
        self.key_id
    }

    /// Returns the signature bytes
    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature_bytes
    }

    /// Returns the creation timestamp
    pub fn created(&self) -> u64 {
        self.created
    }

    /// Returns the size of the signature in bytes
    pub fn size(&self) -> usize {
        self.signature_bytes.len()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signature({}, Key: {:016X}, {} bytes)",
            self.algorithm,
            self.key_id,
            self.size()
        )
    }
}

/// Signs a message using a post-quantum private key
///
/// # Arguments
/// * `private_key` - The private key to sign with (must be ML-DSA-65)
/// * `message` - The message to sign
///
/// # Returns
/// A `Signature` containing the post-quantum digital signature
///
/// # Examples
/// ```rust,no_run
/// use pqpgp::crypto::{KeyPair, sign_message};
/// use rand::rngs::OsRng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = OsRng;
/// let keypair = KeyPair::generate_mldsa65(&mut rng)?;
/// let message = b"Hello, post-quantum world!";
/// let signature = sign_message(keypair.private_key(), message, None)?;
/// # Ok(())
/// # }
/// ```
pub fn sign_message(
    private_key: &PrivateKey,
    message: &[u8],
    password: Option<&Password>,
) -> Result<Signature> {
    // Verify this is a signing key
    if !private_key.can_sign() {
        return Err(PqpgpError::signature(
            "Private key cannot be used for signing",
        ));
    }

    // Only support ML-DSA-65 for now
    if private_key.algorithm() != Algorithm::Mldsa65 {
        return Err(PqpgpError::signature(
            "Only ML-DSA-65 signatures are supported",
        ));
    }

    // Get the reconstructed ML-DSA-65 secret key
    let secret_key = private_key
        .as_mldsa65(password)
        .map_err(|e| PqpgpError::signature(format!("Failed to get ML-DSA-65 secret key: {}", e)))?;

    // Create message hash for signing (prevents signature malleability)
    let message_hash = hash_data(message);

    // Sign the message hash
    let signature_bytes = mldsa65::detached_sign(&message_hash, &secret_key);

    // Get current timestamp
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Ok(Signature::new(
        Algorithm::Mldsa65,
        private_key.key_id(),
        signature_bytes.as_bytes().to_vec(),
        created,
    ))
}

/// Verifies a post-quantum digital signature
///
/// # Arguments
/// * `public_key` - The public key to verify with (must be ML-DSA-65)
/// * `message` - The original message that was signed
/// * `signature` - The signature to verify
///
/// # Returns
/// `Ok(())` if the signature is valid, `Err` otherwise
///
/// # Examples
/// ```rust,no_run
/// use pqpgp::crypto::{KeyPair, sign_message, verify_signature};
/// use rand::rngs::OsRng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = OsRng;
/// let keypair = KeyPair::generate_mldsa65(&mut rng)?;
/// let message = b"Hello, post-quantum world!";
/// let signature = sign_message(keypair.private_key(), message, None)?;
/// verify_signature(keypair.public_key(), message, &signature)?;
/// # Ok(())
/// # }
/// ```
pub fn verify_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    // Verify this is a verification key
    if !public_key.can_verify() {
        return Err(PqpgpError::signature(
            "Public key cannot be used for verification",
        ));
    }

    // Verify algorithm compatibility
    if public_key.algorithm() != signature.algorithm() {
        return Err(PqpgpError::signature(
            "Key algorithm doesn't match signature algorithm",
        ));
    }

    // Verify key ID matches
    if public_key.key_id() != signature.key_id() {
        return Err(PqpgpError::signature(
            "Key ID doesn't match signature key ID",
        ));
    }

    // Only support ML-DSA-65 for now
    if signature.algorithm() != Algorithm::Mldsa65 {
        return Err(PqpgpError::signature(
            "Only ML-DSA-65 signatures are supported",
        ));
    }

    // Get the reconstructed ML-DSA-65 public key
    let public_key = public_key
        .as_mldsa65()
        .map_err(|e| PqpgpError::signature(format!("Failed to get ML-DSA-65 public key: {}", e)))?;

    // Reconstruct signature
    let detached_signature = mldsa65::DetachedSignature::from_bytes(&signature.signature_bytes)
        .map_err(|_| PqpgpError::signature("Failed to reconstruct ML-DSA-65 signature"))?;

    // Hash the message (same as during signing)
    let message_hash = hash_data(message);

    // Verify the signature
    mldsa65::verify_detached_signature(&detached_signature, &message_hash, &public_key)
        .map_err(|_| PqpgpError::signature("Signature verification failed"))?;

    Ok(())
}

/// Signs multiple messages as a batch for efficiency
pub fn sign_messages(
    private_key: &PrivateKey,
    messages: &[&[u8]],
    password: Option<&Password>,
) -> Result<Vec<Signature>> {
    messages
        .iter()
        .map(|message| sign_message(private_key, message, password))
        .collect()
}

/// Verifies multiple signatures as a batch
pub fn verify_signatures(
    public_key: &PublicKey,
    messages: &[&[u8]],
    signatures: &[Signature],
) -> Result<()> {
    if messages.len() != signatures.len() {
        return Err(PqpgpError::signature(
            "Message count doesn't match signature count",
        ));
    }

    for (message, signature) in messages.iter().zip(signatures.iter()) {
        verify_signature(public_key, message, signature)?;
    }

    Ok(())
}

/// Creates a signature over structured data (automatically serializes and hashes)
pub fn sign_data<T: Serialize>(
    private_key: &PrivateKey,
    data: &T,
    password: Option<&Password>,
) -> Result<Signature> {
    let serialized = bincode::serialize(data)
        .map_err(|e| PqpgpError::serialization(format!("Failed to serialize data: {}", e)))?;
    sign_message(private_key, &serialized, password)
}

/// Verifies a signature over structured data
pub fn verify_data_signature<T: Serialize>(
    public_key: &PublicKey,
    data: &T,
    signature: &Signature,
) -> Result<()> {
    let serialized = bincode::serialize(data)
        .map_err(|e| PqpgpError::serialization(format!("Failed to serialize data: {}", e)))?;
    verify_signature(public_key, &serialized, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use rand::rngs::OsRng;

    #[test]
    fn test_mldsa65_signing() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mldsa65(&mut rng).unwrap();

        let message = b"Test message for post-quantum signing";
        let signature = sign_message(keypair.private_key(), message, None).unwrap();

        assert_eq!(signature.algorithm(), Algorithm::Mldsa65);
        assert_eq!(signature.key_id(), keypair.key_id());
        assert!(!signature.signature_bytes().is_empty());
    }

    #[test]
    fn test_signature_verification() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mldsa65(&mut rng).unwrap();

        let message = b"Test message for signature verification";
        let signature = sign_message(keypair.private_key(), message, None).unwrap();

        // Valid signature should verify
        verify_signature(keypair.public_key(), message, &signature).unwrap();
    }

    #[test]
    fn test_signature_verification_fails_with_wrong_message() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mldsa65(&mut rng).unwrap();

        let message = b"Original message";
        let wrong_message = b"Modified message";
        let signature = sign_message(keypair.private_key(), message, None).unwrap();

        // Wrong message should fail verification
        assert!(verify_signature(keypair.public_key(), wrong_message, &signature).is_err());
    }

    #[test]
    fn test_signature_verification_fails_with_wrong_key() {
        let mut rng = OsRng;
        let keypair1 = KeyPair::generate_mldsa65(&mut rng).unwrap();
        let keypair2 = KeyPair::generate_mldsa65(&mut rng).unwrap();

        let message = b"Test message";
        let signature = sign_message(keypair1.private_key(), message, None).unwrap();

        // Wrong key should fail verification
        assert!(verify_signature(keypair2.public_key(), message, &signature).is_err());
    }

    #[test]
    fn test_batch_signing_and_verification() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mldsa65(&mut rng).unwrap();

        let messages = [
            b"First message".as_slice(),
            b"Second message".as_slice(),
            b"Third message".as_slice(),
        ];

        let signatures = sign_messages(keypair.private_key(), &messages, None).unwrap();
        assert_eq!(signatures.len(), 3);

        // Verify all signatures
        verify_signatures(keypair.public_key(), &messages, &signatures).unwrap();
    }

    #[test]
    fn test_structured_data_signing() {
        use serde::Serialize;

        #[derive(Serialize)]
        struct TestData {
            name: String,
            value: u64,
            active: bool,
        }

        let mut rng = OsRng;
        let keypair = KeyPair::generate_mldsa65(&mut rng).unwrap();

        let data = TestData {
            name: "test".to_string(),
            value: 42,
            active: true,
        };

        let signature = sign_data(keypair.private_key(), &data, None).unwrap();
        verify_data_signature(keypair.public_key(), &data, &signature).unwrap();
    }

    #[test]
    fn test_encryption_key_cannot_sign() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem768(&mut rng).unwrap();

        let message = b"Test message";

        // ML-KEM-768 key should not be able to sign
        assert!(sign_message(keypair.private_key(), message, None).is_err());
    }

    #[test]
    fn test_signature_display() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mldsa65(&mut rng).unwrap();

        let message = b"Test message";
        let signature = sign_message(keypair.private_key(), message, None).unwrap();

        let display_str = format!("{}", signature);
        assert!(display_str.contains("ML-DSA-65"));
        assert!(display_str.contains(&format!("{:016X}", keypair.key_id())));
    }
}
