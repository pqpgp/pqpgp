//! Message header encryption for the chat protocol.
//!
//! This module provides header encryption to protect message metadata.
//! Headers contain ratchet state information that should be encrypted
//! separately from the message body.
//!
//! ## Header Contents
//!
//! - Sender's current ratchet public key
//! - Message number in the current chain
//! - Previous chain length (for handling ratchet transitions)
//! - KEM ciphertext (when ratchet key changes)
//!
//! ## Security Considerations
//!
//! Headers are encrypted with a header key derived from the session.
//! This prevents observers from learning:
//! - How many messages have been exchanged
//! - When ratchet steps occur
//! - The sender's current ratchet key

use crate::chat::kdf_info;
use crate::chat::ratchet::RatchetPublicKey;
use crate::error::{PqpgpError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha3::Sha3_512;
use std::fmt;
use zeroize::ZeroizeOnDrop;

/// Size of a header encryption key in bytes.
pub const HEADER_KEY_SIZE: usize = 32;

/// A key used to encrypt message headers.
#[derive(Clone, ZeroizeOnDrop)]
pub struct HeaderKey {
    key: [u8; HEADER_KEY_SIZE],
}

impl fmt::Debug for HeaderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl HeaderKey {
    /// Creates a header key from bytes.
    pub fn from_bytes(bytes: [u8; HEADER_KEY_SIZE]) -> Self {
        Self { key: bytes }
    }

    /// Derives a header key from a root key and chain key.
    pub fn derive(root_key: &[u8], chain_key: &[u8]) -> Result<Self> {
        let mut input = Vec::with_capacity(root_key.len() + chain_key.len());
        input.extend_from_slice(root_key);
        input.extend_from_slice(chain_key);

        let hk = Hkdf::<Sha3_512>::new(None, &input);

        let mut key = [0u8; HEADER_KEY_SIZE];
        hk.expand(kdf_info::HEADER_KEY, &mut key)
            .map_err(|_| PqpgpError::session("Header key derivation failed"))?;

        Ok(Self { key })
    }

    /// Returns the key bytes.
    pub fn as_bytes(&self) -> &[u8; HEADER_KEY_SIZE] {
        &self.key
    }

    /// Encrypts a header.
    pub fn encrypt(&self, header: &MessageHeader) -> Result<EncryptedHeader> {
        let plaintext = bincode::serialize(header).map_err(|e| {
            PqpgpError::serialization(format!("Header serialization failed: {}", e))
        })?;

        // Use a random nonce for header encryption
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|_| PqpgpError::session("Header encryption failed"))?;

        Ok(EncryptedHeader {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypts a header.
    pub fn decrypt(&self, encrypted: &EncryptedHeader) -> Result<MessageHeader> {
        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_slice())
            .map_err(|_| PqpgpError::session("Header decryption failed"))?;

        bincode::deserialize(&plaintext)
            .map_err(|e| PqpgpError::serialization(format!("Header deserialization failed: {}", e)))
    }
}

/// Unencrypted message header containing ratchet information.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageHeader {
    /// Sender's current ratchet public key
    pub ratchet_key: Vec<u8>,
    /// Message number in the current sending chain
    pub message_number: u32,
    /// Length of the previous sending chain
    pub previous_chain_length: u32,
    /// KEM ciphertext for ratchet step (if ratchet key changed)
    pub kem_ciphertext: Option<Vec<u8>>,
}

impl fmt::Debug for MessageHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageHeader")
            .field("ratchet_key_len", &self.ratchet_key.len())
            .field("message_number", &self.message_number)
            .field("previous_chain_length", &self.previous_chain_length)
            .field("has_kem_ciphertext", &self.kem_ciphertext.is_some())
            .finish()
    }
}

impl MessageHeader {
    /// Creates a new message header.
    pub fn new(
        ratchet_key: &RatchetPublicKey,
        message_number: u32,
        previous_chain_length: u32,
        kem_ciphertext: Option<Vec<u8>>,
    ) -> Self {
        Self {
            ratchet_key: ratchet_key.as_bytes().to_vec(),
            message_number,
            previous_chain_length,
            kem_ciphertext,
        }
    }

    /// Returns the ratchet public key.
    pub fn ratchet_public_key(&self) -> Result<RatchetPublicKey> {
        RatchetPublicKey::from_bytes(self.ratchet_key.clone())
    }

    /// Returns the serialized size of this header.
    pub fn serialized_size(&self) -> usize {
        // Approximate size: ratchet key + numbers + optional ciphertext
        self.ratchet_key.len()
            + 8  // message_number + previous_chain_length
            + self.kem_ciphertext.as_ref().map_or(1, |ct| ct.len() + 5)
    }
}

/// Encrypted message header.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedHeader {
    /// Nonce used for encryption
    pub nonce: [u8; 12],
    /// Encrypted header data
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for EncryptedHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedHeader")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl EncryptedHeader {
    /// Returns the total size of the encrypted header.
    pub fn size(&self) -> usize {
        12 + self.ciphertext.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::ratchet::RatchetKeyPair;

    #[test]
    fn test_header_key_derivation() {
        let root_key = [1u8; 32];
        let chain_key = [2u8; 32];

        let key = HeaderKey::derive(&root_key, &chain_key).unwrap();

        assert!(!key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_header_key_deterministic() {
        let root_key = [1u8; 32];
        let chain_key = [2u8; 32];

        let key1 = HeaderKey::derive(&root_key, &chain_key).unwrap();
        let key2 = HeaderKey::derive(&root_key, &chain_key).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_header_encryption_decryption() {
        let key = HeaderKey::from_bytes([42u8; HEADER_KEY_SIZE]);

        let keypair = RatchetKeyPair::generate();
        let header = MessageHeader::new(&keypair.public, 5, 3, Some(vec![1, 2, 3, 4, 5]));

        let encrypted = key.encrypt(&header).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(header.message_number, decrypted.message_number);
        assert_eq!(
            header.previous_chain_length,
            decrypted.previous_chain_length
        );
        assert_eq!(header.ratchet_key, decrypted.ratchet_key);
        assert_eq!(header.kem_ciphertext, decrypted.kem_ciphertext);
    }

    #[test]
    fn test_header_encryption_different_nonces() {
        let key = HeaderKey::from_bytes([42u8; HEADER_KEY_SIZE]);

        let keypair = RatchetKeyPair::generate();
        let header = MessageHeader::new(&keypair.public, 1, 0, None);

        let encrypted1 = key.encrypt(&header).unwrap();
        let encrypted2 = key.encrypt(&header).unwrap();

        // Same header should produce different ciphertexts (random nonce)
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        assert_ne!(encrypted1.nonce, encrypted2.nonce);

        // But both should decrypt correctly
        let decrypted1 = key.decrypt(&encrypted1).unwrap();
        let decrypted2 = key.decrypt(&encrypted2).unwrap();

        assert_eq!(decrypted1, decrypted2);
    }

    #[test]
    fn test_header_decryption_fails_wrong_key() {
        let key1 = HeaderKey::from_bytes([1u8; HEADER_KEY_SIZE]);
        let key2 = HeaderKey::from_bytes([2u8; HEADER_KEY_SIZE]);

        let keypair = RatchetKeyPair::generate();
        let header = MessageHeader::new(&keypair.public, 1, 0, None);

        let encrypted = key1.encrypt(&header).unwrap();

        // Wrong key should fail
        assert!(key2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_header_decryption_fails_tampered() {
        let key = HeaderKey::from_bytes([42u8; HEADER_KEY_SIZE]);

        let keypair = RatchetKeyPair::generate();
        let header = MessageHeader::new(&keypair.public, 1, 0, None);

        let mut encrypted = key.encrypt(&header).unwrap();

        // Tamper with ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        assert!(key.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_message_header_without_kem() {
        let keypair = RatchetKeyPair::generate();
        let header = MessageHeader::new(&keypair.public, 10, 5, None);

        assert_eq!(header.message_number, 10);
        assert_eq!(header.previous_chain_length, 5);
        assert!(header.kem_ciphertext.is_none());
    }

    #[test]
    fn test_message_header_serialization() {
        let keypair = RatchetKeyPair::generate();
        let header = MessageHeader::new(
            &keypair.public,
            100,
            50,
            Some(vec![0u8; 1568]), // ML-KEM ciphertext size
        );

        let serialized = bincode::serialize(&header).unwrap();
        let deserialized: MessageHeader = bincode::deserialize(&serialized).unwrap();

        assert_eq!(header, deserialized);
    }

    #[test]
    fn test_encrypted_header_size() {
        let key = HeaderKey::from_bytes([42u8; HEADER_KEY_SIZE]);

        let keypair = RatchetKeyPair::generate();
        let header = MessageHeader::new(&keypair.public, 1, 0, None);

        let encrypted = key.encrypt(&header).unwrap();

        assert_eq!(encrypted.size(), 12 + encrypted.ciphertext.len());
    }
}
