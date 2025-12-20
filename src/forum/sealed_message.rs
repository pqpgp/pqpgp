//! Sealed private message node for DAG-based encrypted messaging.
//!
//! A `SealedPrivateMessage` is an end-to-end encrypted message where:
//! - **Content is encrypted**: Only the recipient can read the message
//! - **Sender is hidden**: Sender identity is inside the encrypted payload
//! - **Recipient is hidden**: Only recipient can verify the hint to identify their messages
//!
//! ## Privacy Properties
//!
//! | Property | How Achieved |
//! |----------|--------------|
//! | Content hidden | AES-256-GCM encryption |
//! | Sender hidden | Sealed sender - identity inside encrypted envelope |
//! | Recipient hidden | Encrypted recipient hint (HMAC) |
//! | Forward secrecy | X3DH + Double Ratchet per conversation |
//! | Deniability | No signatures on message content |
//!
//! ## Message Structure
//!
//! ```text
//! SealedPrivateMessage (public in DAG)
//! ├── recipient_hint: HMAC(hint_key, nonce) - only recipient can verify
//! ├── hint_nonce: random per message
//! └── sealed_payload: ML-KEM encrypted envelope
//!     └── SealedEnvelope (encrypted)
//!         ├── sender_identity_hash: ContentHash of sender's EncryptionIdentity
//!         ├── x3dh_keys: Key agreement ciphertexts (for initial messages)
//!         ├── ratchet_header: Double ratchet state
//!         └── encrypted_inner: AES-GCM encrypted InnerMessage
//!             └── InnerMessage
//!                 ├── message_id: UUID
//!                 ├── conversation_id: derived from X3DH
//!                 ├── body: actual message text
//!                 ├── reply_to: optional previous message_id
//!                 └── timestamp
//! ```

use crate::error::{PqpgpError, Result};
use crate::forum::types::{current_timestamp_millis, ContentHash, NodeType};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum size of the sealed payload in bytes (100 KB).
pub const MAX_SEALED_PAYLOAD_SIZE: usize = 100 * 1024;

/// Size of the recipient hint (HMAC-SHA3-256 output).
pub const RECIPIENT_HINT_SIZE: usize = 32;

/// Size of the hint nonce.
pub const HINT_NONCE_SIZE: usize = 16;

/// Domain separation for recipient hint key derivation.
pub const HINT_KEY_DOMAIN: &[u8] = b"PQPGP-PM-hint-v1";

/// The content of a sealed private message node.
///
/// This structure is stored publicly in the DAG. The actual message content
/// is encrypted inside `sealed_payload` and only the recipient can decrypt it.
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedPrivateMessageContent {
    /// Node type discriminator (always SealedPrivateMessage).
    pub node_type: NodeType,
    /// Hash of the forum this message belongs to.
    pub forum_hash: ContentHash,
    /// Recipient hint for efficient filtering.
    /// Computed as HMAC-SHA3(recipient_hint_key, hint_nonce).
    /// Only the recipient can verify this matches their key.
    pub recipient_hint: [u8; RECIPIENT_HINT_SIZE],
    /// Random nonce used to compute the recipient hint.
    /// Different per message to prevent correlation.
    pub hint_nonce: [u8; HINT_NONCE_SIZE],
    /// The sealed (doubly-encrypted) message payload.
    /// Contains: sender identity + X3DH keys + ratchet header + encrypted message.
    pub sealed_payload: Vec<u8>,
    /// Creation timestamp in milliseconds since Unix epoch.
    pub created_at: u64,
}

impl fmt::Debug for SealedPrivateMessageContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedPrivateMessageContent")
            .field("node_type", &self.node_type)
            .field("forum_hash", &self.forum_hash)
            .field("recipient_hint", &hex::encode(&self.recipient_hint[..8]))
            .field("sealed_payload_size", &self.sealed_payload.len())
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl SealedPrivateMessageContent {
    /// Creates new sealed private message content.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this message belongs to
    /// * `recipient_hint` - HMAC hint for the recipient
    /// * `hint_nonce` - Nonce used to compute the hint
    /// * `sealed_payload` - The encrypted message envelope
    ///
    /// # Errors
    /// Returns an error if the sealed payload exceeds size limits.
    pub fn new(
        forum_hash: ContentHash,
        recipient_hint: [u8; RECIPIENT_HINT_SIZE],
        hint_nonce: [u8; HINT_NONCE_SIZE],
        sealed_payload: Vec<u8>,
    ) -> Result<Self> {
        if sealed_payload.len() > MAX_SEALED_PAYLOAD_SIZE {
            return Err(PqpgpError::validation(format!(
                "Sealed payload exceeds maximum size: {} bytes (max {})",
                sealed_payload.len(),
                MAX_SEALED_PAYLOAD_SIZE
            )));
        }

        if sealed_payload.is_empty() {
            return Err(PqpgpError::validation("Sealed payload cannot be empty"));
        }

        Ok(Self {
            node_type: NodeType::SealedPrivateMessage,
            forum_hash,
            recipient_hint,
            hint_nonce,
            sealed_payload,
            created_at: current_timestamp_millis(),
        })
    }

    /// Computes the content hash of this sealed message content.
    pub fn content_hash(&self) -> Result<ContentHash> {
        ContentHash::compute(self)
    }
}

/// A complete sealed private message node with content and hash.
///
/// Note: This node is NOT signed with the sender's key (to hide sender identity).
/// Instead, integrity is provided by the content hash and the AEAD encryption.
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedPrivateMessage {
    /// The content of this node.
    pub content: SealedPrivateMessageContent,
    /// Content hash - the unique identifier of this node.
    pub content_hash: ContentHash,
}

impl fmt::Debug for SealedPrivateMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedPrivateMessage")
            .field("content_hash", &self.content_hash)
            .field("forum_hash", &self.content.forum_hash)
            .field("sealed_payload_size", &self.content.sealed_payload.len())
            .field("created_at", &self.content.created_at)
            .finish()
    }
}

impl SealedPrivateMessage {
    /// Creates a new sealed private message node.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this message belongs to
    /// * `recipient_hint` - HMAC hint for the recipient
    /// * `hint_nonce` - Nonce used to compute the hint
    /// * `sealed_payload` - The encrypted message envelope
    ///
    /// # Errors
    /// Returns an error if validation fails.
    pub fn create(
        forum_hash: ContentHash,
        recipient_hint: [u8; RECIPIENT_HINT_SIZE],
        hint_nonce: [u8; HINT_NONCE_SIZE],
        sealed_payload: Vec<u8>,
    ) -> Result<Self> {
        let content = SealedPrivateMessageContent::new(
            forum_hash,
            recipient_hint,
            hint_nonce,
            sealed_payload,
        )?;
        let content_hash = content.content_hash()?;

        Ok(Self {
            content,
            content_hash,
        })
    }

    /// Verifies the content hash of this node.
    ///
    /// Note: We cannot verify sender identity or decrypt content here.
    /// That requires the recipient's private key.
    pub fn verify_hash(&self) -> Result<()> {
        let computed_hash = self.content.content_hash()?;
        if computed_hash != self.content_hash {
            return Err(PqpgpError::validation(
                "SealedPrivateMessage content hash mismatch",
            ));
        }
        Ok(())
    }

    /// Checks if this message is intended for the given recipient hint key.
    ///
    /// The hint key should be derived as:
    /// `hint_key = HKDF(recipient_encryption_private_key, HINT_KEY_DOMAIN)`
    ///
    /// # Arguments
    /// * `hint_key` - The recipient's hint key (32 bytes)
    ///
    /// # Returns
    /// `true` if the hint matches, indicating this message is likely for this recipient.
    pub fn check_recipient_hint(&self, hint_key: &[u8; 32]) -> bool {
        use hmac::{Hmac, Mac};
        use sha3::Sha3_256;

        type HmacSha3 = Hmac<Sha3_256>;

        let mut mac = match HmacSha3::new_from_slice(hint_key) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(&self.content.hint_nonce);
        let expected = mac.finalize().into_bytes();

        // Constant-time comparison
        crate::crypto::TimingSafe::bytes_equal(&expected, &self.content.recipient_hint)
    }

    /// Returns the forum hash.
    pub fn forum_hash(&self) -> &ContentHash {
        &self.content.forum_hash
    }

    /// Returns the recipient hint.
    pub fn recipient_hint(&self) -> &[u8; RECIPIENT_HINT_SIZE] {
        &self.content.recipient_hint
    }

    /// Returns the hint nonce.
    pub fn hint_nonce(&self) -> &[u8; HINT_NONCE_SIZE] {
        &self.content.hint_nonce
    }

    /// Returns the sealed payload.
    pub fn sealed_payload(&self) -> &[u8] {
        &self.content.sealed_payload
    }

    /// Returns the creation timestamp in milliseconds.
    pub fn created_at(&self) -> u64 {
        self.content.created_at
    }

    /// Returns the content hash (unique identifier).
    pub fn hash(&self) -> &ContentHash {
        &self.content_hash
    }

    /// Returns the node type.
    pub fn node_type(&self) -> NodeType {
        self.content.node_type
    }

    /// Returns a reference to the content.
    pub fn content(&self) -> &SealedPrivateMessageContent {
        &self.content
    }

    /// Creates a SealedPrivateMessage from existing content.
    ///
    /// This recomputes the content hash. Useful for testing tampering detection.
    pub fn from_content(content: SealedPrivateMessageContent) -> Result<Self> {
        let content_hash = content.content_hash()?;
        Ok(Self {
            content,
            content_hash,
        })
    }
}

/// Computes a recipient hint for a message.
///
/// # Arguments
/// * `hint_key` - The recipient's hint key (derived from their encryption private key)
/// * `hint_nonce` - Random nonce for this message
///
/// # Returns
/// The 32-byte HMAC hint.
pub fn compute_recipient_hint(
    hint_key: &[u8; 32],
    hint_nonce: &[u8; HINT_NONCE_SIZE],
) -> [u8; RECIPIENT_HINT_SIZE] {
    use hmac::{Hmac, Mac};
    use sha3::Sha3_256;

    type HmacSha3 = Hmac<Sha3_256>;

    let mut mac = HmacSha3::new_from_slice(hint_key).expect("HMAC key size is always valid");
    mac.update(hint_nonce);
    let result = mac.finalize().into_bytes();

    let mut hint = [0u8; RECIPIENT_HINT_SIZE];
    hint.copy_from_slice(&result);
    hint
}

/// Derives a recipient hint key from an encryption private key.
///
/// This key is used to quickly filter messages intended for a recipient
/// without performing expensive ML-KEM decryption.
///
/// # Arguments
/// * `encryption_private_key_bytes` - The recipient's ML-KEM private key bytes
///
/// # Returns
/// A 32-byte hint key.
pub fn derive_hint_key(encryption_private_key_bytes: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha3::Sha3_256;

    let hkdf = Hkdf::<Sha3_256>::new(Some(HINT_KEY_DOMAIN), encryption_private_key_bytes);
    let mut hint_key = [0u8; 32];
    hkdf.expand(b"hint-key", &mut hint_key)
        .expect("32 bytes is a valid output length for HKDF");
    hint_key
}

/// Padding utilities for message length hiding.
///
/// SECURITY: Message size can leak information about content. These utilities
/// allow padding messages to fixed sizes to hide their true length from the
/// relay server.
pub mod padding {
    use crate::error::{PqpgpError, Result};
    use rand::RngCore;

    /// Standard padding bucket sizes in bytes.
    /// Messages are padded to the next higher bucket size.
    /// Uses exponential sizing for efficient coverage across message sizes.
    pub const PADDING_BUCKETS: &[usize] = &[
        256,    // Tiny messages (acknowledgments, reactions)
        512,    // Short messages (single sentences)
        1024,   // Medium messages (paragraphs)
        2048,   // Longer messages
        4096,   // Large messages
        8192,   // Very large messages
        16384,  // 16 KB
        32768,  // 32 KB
        65536,  // 64 KB
        131072, // 128 KB - maximum bucket size
    ];

    /// Pads data to the specified target size.
    ///
    /// Uses a 4-byte big-endian length prefix to allow for large padding amounts.
    /// Format: [original_data][random_padding][4-byte original_length]
    ///
    /// # Arguments
    /// * `data` - The data to pad
    /// * `target_size` - The target size (must be >= data.len() + 4)
    ///
    /// # Returns
    /// Padded data with random padding and length indicator.
    ///
    /// # Errors
    /// Returns an error if target_size is too small to fit the data + length indicator.
    pub fn pad_to_size(data: &[u8], target_size: usize) -> Result<Vec<u8>> {
        // Need at least 4 bytes for the length prefix
        let min_size = data.len() + 4;
        if target_size < min_size {
            return Err(PqpgpError::validation(format!(
                "Target size {} must be at least {} (data + 4 byte length)",
                target_size, min_size
            )));
        }

        let padding_len = target_size - min_size;

        let mut padded = Vec::with_capacity(target_size);
        padded.extend_from_slice(data);

        // Fill with random bytes for the padding portion
        if padding_len > 0 {
            let mut random_padding = vec![0u8; padding_len];
            rand::rng().fill_bytes(&mut random_padding);
            padded.extend_from_slice(&random_padding);
        }

        // Last 4 bytes are the original data length (big-endian)
        padded.extend_from_slice(&(data.len() as u32).to_be_bytes());

        Ok(padded)
    }

    /// Removes padding from data that was padded with `pad_to_size`.
    ///
    /// # Arguments
    /// * `padded_data` - The padded data
    ///
    /// # Returns
    /// The original unpadded data.
    ///
    /// # Errors
    /// Returns an error if the padding is invalid.
    pub fn unpad(padded_data: &[u8]) -> Result<Vec<u8>> {
        if padded_data.len() < 4 {
            return Err(PqpgpError::validation(
                "Padded data too short - must be at least 4 bytes",
            ));
        }

        // Read the original length from the last 4 bytes
        let len_bytes: [u8; 4] = padded_data[padded_data.len() - 4..]
            .try_into()
            .map_err(|_| PqpgpError::crypto("Failed to read padding length"))?;
        let original_len = u32::from_be_bytes(len_bytes) as usize;

        // Validate the length
        if original_len > padded_data.len() - 4 {
            return Err(PqpgpError::crypto(
                "Invalid padding: original length exceeds padded data",
            ));
        }

        Ok(padded_data[..original_len].to_vec())
    }

    /// Returns the next bucket size for a given data length.
    ///
    /// This allows messages to be padded to fixed sizes, making it harder
    /// for observers to determine message content from size alone.
    ///
    /// # Arguments
    /// * `data_len` - The current data length
    ///
    /// # Returns
    /// The recommended padding target size, or None if data is too large.
    pub fn next_bucket_size(data_len: usize) -> Option<usize> {
        // Need at least 4 bytes for the length indicator
        let min_bucket = data_len + 4;
        PADDING_BUCKETS
            .iter()
            .find(|&&size| size >= min_bucket)
            .copied()
    }

    /// Pads data to the next bucket size.
    ///
    /// Combines `next_bucket_size` and `pad_to_size` for convenience.
    ///
    /// # Arguments
    /// * `data` - The data to pad
    ///
    /// # Returns
    /// Padded data sized to a standard bucket.
    ///
    /// # Errors
    /// Returns an error if the data is too large for any bucket.
    pub fn pad_to_bucket(data: &[u8]) -> Result<Vec<u8>> {
        let target = next_bucket_size(data.len()).ok_or_else(|| {
            PqpgpError::validation(format!(
                "Data size {} exceeds maximum bucket size {}",
                data.len(),
                PADDING_BUCKETS.last().unwrap_or(&0)
            ))
        })?;
        pad_to_size(data, target)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_pad_and_unpad() {
            let data = b"Hello, World!";
            let padded = pad_to_size(data, 256).unwrap();

            assert_eq!(padded.len(), 256);
            let unpadded = unpad(&padded).unwrap();
            assert_eq!(unpadded, data);
        }

        #[test]
        fn test_pad_large_data() {
            // Test with larger data that needs bigger buckets
            let data = vec![0x42u8; 50_000];
            let padded = pad_to_bucket(&data).unwrap();
            assert_eq!(padded.len(), 65536); // 64KB bucket

            let unpadded = unpad(&padded).unwrap();
            assert_eq!(unpadded, data);
        }

        #[test]
        fn test_bucket_sizes() {
            // 0 bytes + 4 length = 4, fits in 256
            assert_eq!(next_bucket_size(0), Some(256));
            // 100 bytes + 4 length = 104, fits in 256
            assert_eq!(next_bucket_size(100), Some(256));
            // 252 bytes + 4 length = 256, fits exactly in 256
            assert_eq!(next_bucket_size(252), Some(256));
            // 253 bytes + 4 length = 257, needs 512
            assert_eq!(next_bucket_size(253), Some(512));
            // Large data needs larger bucket
            assert_eq!(next_bucket_size(100_000), Some(131072)); // 128KB
                                                                 // 131068 bytes + 4 = 131072, fits exactly
            assert_eq!(next_bucket_size(131068), Some(131072));
            // Data too large for any bucket (131069 + 4 = 131073 > 131072)
            assert_eq!(next_bucket_size(131069), None);
        }

        #[test]
        fn test_pad_to_bucket() {
            let data = b"Short message";
            let padded = pad_to_bucket(data).unwrap();
            assert_eq!(padded.len(), 256);

            let unpadded = unpad(&padded).unwrap();
            assert_eq!(unpadded, data);
        }

        #[test]
        fn test_invalid_padding() {
            // Too short for length field
            assert!(unpad(&[]).is_err());
            assert!(unpad(&[1, 2, 3]).is_err());

            // Length exceeds data (claims 1000 bytes but only has a few)
            let bad = [0x00, 0x00, 0x03, 0xE8]; // 1000 in big-endian
            assert!(unpad(&bad).is_err());
        }
    }
}

/// The inner message content that gets encrypted.
///
/// This is what the recipient actually sees after decryption.
#[derive(Clone, Serialize, Deserialize)]
pub struct InnerMessage {
    /// Unique message identifier (UUID).
    pub message_id: [u8; 16],
    /// Conversation identifier (derived from X3DH shared secret).
    /// Links messages in the same conversation.
    pub conversation_id: [u8; 32],
    /// Optional subject line.
    pub subject: Option<String>,
    /// Message body text.
    pub body: String,
    /// Optional reference to a previous message in this conversation.
    pub reply_to: Option<[u8; 16]>,
    /// Timestamp when the message was composed (milliseconds since Unix epoch).
    pub timestamp: u64,
}

impl fmt::Debug for InnerMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InnerMessage")
            .field("message_id", &hex::encode(&self.message_id[..8]))
            .field("conversation_id", &hex::encode(&self.conversation_id[..8]))
            .field("subject", &self.subject)
            .field("body_len", &self.body.len())
            .field("reply_to", &self.reply_to.map(|r| hex::encode(&r[..8])))
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

impl InnerMessage {
    /// Creates a new inner message.
    ///
    /// # Arguments
    /// * `conversation_id` - Conversation identifier from X3DH
    /// * `body` - Message body text
    pub fn new(conversation_id: [u8; 32], body: String) -> Self {
        let mut message_id = [0u8; 16];
        // Generate a random message ID
        use rand::RngCore;
        rand::rng().fill_bytes(&mut message_id);

        Self {
            message_id,
            conversation_id,
            subject: None,
            body,
            reply_to: None,
            timestamp: current_timestamp_millis(),
        }
    }

    /// Sets the subject line.
    pub fn with_subject(mut self, subject: String) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Sets the reply-to reference.
    pub fn with_reply_to(mut self, reply_to: [u8; 16]) -> Self {
        self.reply_to = Some(reply_to);
        self
    }

    /// Serializes the inner message to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            PqpgpError::serialization(format!("Failed to serialize InnerMessage: {}", e))
        })
    }

    /// Deserializes an inner message from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| {
            PqpgpError::serialization(format!("Failed to deserialize InnerMessage: {}", e))
        })
    }
}

/// The sealed envelope that contains sender identity and encrypted message.
///
/// This is encrypted with the recipient's ML-KEM key to form the outer layer.
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedEnvelope {
    /// Hash of the sender's EncryptionIdentity node.
    pub sender_identity_hash: ContentHash,
    /// X3DH key agreement data (for initial messages in a conversation).
    pub x3dh_data: Option<X3DHData>,
    /// Ratchet header for Double Ratchet synchronization.
    pub ratchet_header: Option<RatchetHeader>,
    /// The inner message, encrypted with the conversation key.
    pub encrypted_inner: Vec<u8>,
    /// Nonce used for inner message encryption.
    pub inner_nonce: [u8; 12],
}

impl SealedEnvelope {
    /// Validates the envelope structure.
    ///
    /// SECURITY: Ensures mutual exclusivity of X3DH and ratchet headers
    /// to prevent message type confusion attacks.
    ///
    /// # Errors
    /// Returns an error if both x3dh_data and ratchet_header are present,
    /// or if neither is present.
    pub fn validate(&self) -> crate::error::Result<()> {
        match (&self.x3dh_data, &self.ratchet_header) {
            (Some(_), Some(_)) => Err(crate::error::PqpgpError::crypto(
                "Invalid envelope: cannot contain both X3DH data and ratchet header",
            )),
            (None, None) => {
                // This is allowed for session-based messages (no X3DH, no ratchet)
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl fmt::Debug for SealedEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedEnvelope")
            .field("sender_identity_hash", &self.sender_identity_hash)
            .field("has_x3dh_data", &self.x3dh_data.is_some())
            .field("has_ratchet_header", &self.ratchet_header.is_some())
            .field("encrypted_inner_len", &self.encrypted_inner.len())
            .finish()
    }
}

impl SealedEnvelope {
    /// Serializes the sealed envelope to bytes.
    ///
    /// # Security
    /// Validates the envelope structure before serialization.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        // SECURITY: Validate envelope structure before serializing
        self.validate()?;
        bincode::serialize(self).map_err(|e| {
            PqpgpError::serialization(format!("Failed to serialize SealedEnvelope: {}", e))
        })
    }

    /// Deserializes a sealed envelope from bytes.
    ///
    /// # Security
    /// Validates the envelope structure after deserialization to prevent
    /// message type confusion attacks.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let envelope: Self = bincode::deserialize(bytes).map_err(|e| {
            PqpgpError::serialization(format!("Failed to deserialize SealedEnvelope: {}", e))
        })?;
        // SECURITY: Validate envelope structure after deserialization
        envelope.validate()?;
        Ok(envelope)
    }
}

/// X3DH key agreement data for initial messages.
#[derive(Clone, Serialize, Deserialize)]
pub struct X3DHData {
    /// Ciphertext from encapsulating to the signed prekey.
    pub signed_prekey_ciphertext: Vec<u8>,
    /// ID of the signed prekey used.
    pub signed_prekey_id: u32,
    /// Ciphertext from encapsulating to the one-time prekey (if used).
    pub one_time_prekey_ciphertext: Option<Vec<u8>>,
    /// ID of the one-time prekey used (if any).
    pub one_time_prekey_id: Option<u32>,
}

impl fmt::Debug for X3DHData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X3DHData")
            .field("signed_prekey_id", &self.signed_prekey_id)
            .field("one_time_prekey_id", &self.one_time_prekey_id)
            .finish()
    }
}

/// Double Ratchet header for key synchronization.
#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetHeader {
    /// Current ratchet public key (ML-KEM-1024).
    pub ratchet_public_key: Vec<u8>,
    /// Previous chain message count.
    pub previous_chain_length: u32,
    /// Current message number in the chain.
    pub message_number: u32,
}

impl fmt::Debug for RatchetHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RatchetHeader")
            .field("ratchet_key_len", &self.ratchet_public_key.len())
            .field("prev_chain_len", &self.previous_chain_length)
            .field("msg_num", &self.message_number)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_forum_hash() -> ContentHash {
        ContentHash::from_bytes([0u8; 64])
    }

    #[test]
    fn test_recipient_hint_computation() {
        let hint_key = [42u8; 32];
        let hint_nonce = [1u8; HINT_NONCE_SIZE];

        let hint1 = compute_recipient_hint(&hint_key, &hint_nonce);
        let hint2 = compute_recipient_hint(&hint_key, &hint_nonce);

        // Same inputs should produce same output
        assert_eq!(hint1, hint2);

        // Different nonce should produce different output
        let hint_nonce2 = [2u8; HINT_NONCE_SIZE];
        let hint3 = compute_recipient_hint(&hint_key, &hint_nonce2);
        assert_ne!(hint1, hint3);
    }

    #[test]
    fn test_sealed_private_message_creation() {
        let forum_hash = create_test_forum_hash();
        let recipient_hint = [1u8; RECIPIENT_HINT_SIZE];
        let hint_nonce = [2u8; HINT_NONCE_SIZE];
        let sealed_payload = vec![0u8; 1000]; // Dummy payload

        let message =
            SealedPrivateMessage::create(forum_hash, recipient_hint, hint_nonce, sealed_payload)
                .expect("Failed to create sealed message");

        assert_eq!(message.node_type(), NodeType::SealedPrivateMessage);
        assert_eq!(message.forum_hash(), &forum_hash);
        assert_eq!(message.recipient_hint(), &recipient_hint);
    }

    #[test]
    fn test_sealed_private_message_hash_verification() {
        let forum_hash = create_test_forum_hash();
        let recipient_hint = [1u8; RECIPIENT_HINT_SIZE];
        let hint_nonce = [2u8; HINT_NONCE_SIZE];
        let sealed_payload = vec![0u8; 1000];

        let message =
            SealedPrivateMessage::create(forum_hash, recipient_hint, hint_nonce, sealed_payload)
                .expect("Failed to create sealed message");

        message.verify_hash().expect("Hash verification failed");
    }

    #[test]
    fn test_check_recipient_hint() {
        let hint_key = [42u8; 32];
        let hint_nonce = [1u8; HINT_NONCE_SIZE];
        let recipient_hint = compute_recipient_hint(&hint_key, &hint_nonce);

        let forum_hash = create_test_forum_hash();
        let sealed_payload = vec![0u8; 1000];

        let message =
            SealedPrivateMessage::create(forum_hash, recipient_hint, hint_nonce, sealed_payload)
                .expect("Failed to create sealed message");

        // Should match with correct hint key
        assert!(message.check_recipient_hint(&hint_key));

        // Should not match with wrong hint key
        let wrong_key = [99u8; 32];
        assert!(!message.check_recipient_hint(&wrong_key));
    }

    #[test]
    fn test_derive_hint_key() {
        let private_key_bytes = [42u8; 100]; // Dummy private key bytes

        let hint_key1 = derive_hint_key(&private_key_bytes);
        let hint_key2 = derive_hint_key(&private_key_bytes);

        // Same input should produce same output
        assert_eq!(hint_key1, hint_key2);

        // Different input should produce different output
        let different_key_bytes = [43u8; 100];
        let hint_key3 = derive_hint_key(&different_key_bytes);
        assert_ne!(hint_key1, hint_key3);
    }

    #[test]
    fn test_inner_message_serialization() {
        let conversation_id = [1u8; 32];
        let message = InnerMessage::new(conversation_id, "Hello, World!".to_string())
            .with_subject("Test Subject".to_string());

        let bytes = message.to_bytes().expect("Serialization failed");
        let restored = InnerMessage::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(message.conversation_id, restored.conversation_id);
        assert_eq!(message.body, restored.body);
        assert_eq!(message.subject, restored.subject);
    }

    #[test]
    fn test_sealed_payload_size_limit() {
        let forum_hash = create_test_forum_hash();
        let recipient_hint = [1u8; RECIPIENT_HINT_SIZE];
        let hint_nonce = [2u8; HINT_NONCE_SIZE];
        let oversized_payload = vec![0u8; MAX_SEALED_PAYLOAD_SIZE + 1];

        let result =
            SealedPrivateMessage::create(forum_hash, recipient_hint, hint_nonce, oversized_payload);

        assert!(result.is_err());
    }

    #[test]
    fn test_sealed_message_serialization() {
        let forum_hash = create_test_forum_hash();
        let recipient_hint = [1u8; RECIPIENT_HINT_SIZE];
        let hint_nonce = [2u8; HINT_NONCE_SIZE];
        let sealed_payload = vec![42u8; 500];

        let message =
            SealedPrivateMessage::create(forum_hash, recipient_hint, hint_nonce, sealed_payload)
                .expect("Failed to create sealed message");

        let serialized = bincode::serialize(&message).expect("Serialization failed");
        let restored: SealedPrivateMessage =
            bincode::deserialize(&serialized).expect("Deserialization failed");

        assert_eq!(message.hash(), restored.hash());
        restored
            .verify_hash()
            .expect("Hash verification failed after deserialization");
    }
}
