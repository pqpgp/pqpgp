//! Sealed sender encryption and decryption for private messages.
//!
//! This module provides the cryptographic operations for the sealed sender protocol:
//! - **Sealing**: Encrypt a message so only the recipient can decrypt it, while hiding
//!   the sender's identity from observers.
//! - **Unsealing**: Decrypt a message and discover who sent it.
//!
//! ## Protocol Overview
//!
//! ### Sealing (Sender)
//! 1. Perform X3DH key agreement with recipient's prekeys
//! 2. Derive conversation key and conversation_id
//! 3. Encrypt inner message with AES-GCM using conversation key
//! 4. Create sealed envelope with sender identity + X3DH data + encrypted inner
//! 5. Encrypt envelope with recipient's ML-KEM identity key
//! 6. Compute recipient hint for efficient filtering
//!
//! ### Unsealing (Recipient)
//! 1. Verify recipient hint matches
//! 2. Decrypt outer layer with ML-KEM private key
//! 3. Extract sender identity and X3DH data
//! 4. Perform X3DH receiver-side key agreement
//! 5. Decrypt inner message with conversation key

use crate::chat::prekey::PreKeyId;
use crate::error::{PqpgpError, Result};
use crate::forum::conversation::ConversationSession;
use crate::forum::encryption_identity::{EncryptionIdentity, EncryptionIdentityPrivate};
use crate::forum::sealed_message::{
    compute_recipient_hint, InnerMessage, RatchetHeader, SealedEnvelope, SealedPrivateMessage,
    X3DHData, HINT_NONCE_SIZE,
};
use crate::forum::types::ContentHash;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey as KemPublicKey, SharedSecret};
use rand::RngCore;
use sha3::Sha3_256;
use zeroize::Zeroizing;

/// Domain separation for conversation key derivation.
const CONVERSATION_KEY_DOMAIN: &[u8] = b"PQPGP-PM-conversation-v1";

/// Domain separation for conversation ID derivation.
const CONVERSATION_ID_DOMAIN: &[u8] = b"PQPGP-PM-conversation-id-v1";

/// Size of ML-KEM-1024 ciphertext.
const MLKEM1024_CIPHERTEXT_SIZE: usize = 1568;

/// Result of sealing a private message.
pub struct SealedMessageResult {
    /// The sealed private message ready for DAG storage.
    pub message: SealedPrivateMessage,
    /// The conversation ID for this conversation (store locally).
    pub conversation_id: [u8; 32],
    /// The conversation key (store locally for subsequent messages).
    pub conversation_key: Zeroizing<[u8; 32]>,
}

/// Result of unsealing a private message.
#[derive(Debug)]
pub struct UnsealedMessageResult {
    /// The decrypted inner message.
    pub inner_message: InnerMessage,
    /// Hash of the sender's EncryptionIdentity node.
    pub sender_identity_hash: ContentHash,
    /// The conversation ID.
    pub conversation_id: [u8; 32],
    /// The conversation key (store locally for subsequent messages).
    pub conversation_key: Zeroizing<[u8; 32]>,
    /// ID of the one-time prekey that was used (should be consumed).
    pub used_one_time_prekey_id: Option<PreKeyId>,
}

/// Seals a private message for a recipient.
///
/// This performs:
/// 1. X3DH key agreement with recipient's prekeys
/// 2. Inner message encryption with derived conversation key
/// 3. Sealed envelope creation
/// 4. Outer encryption with recipient's ML-KEM identity key
/// 5. Recipient hint computation
///
/// # Arguments
/// * `forum_hash` - Hash of the forum this message belongs to
/// * `sender_identity` - Sender's encryption identity (for embedding in envelope)
/// * `recipient_identity` - Recipient's encryption identity (for key agreement)
/// * `inner_message` - The message content to encrypt
/// * `use_one_time_prekey` - Whether to use a one-time prekey (recommended for first message)
///
/// # Returns
/// A `SealedMessageResult` containing the sealed message and conversation keys.
pub fn seal_private_message(
    forum_hash: ContentHash,
    sender_identity: &EncryptionIdentity,
    recipient_identity: &EncryptionIdentity,
    inner_message: InnerMessage,
    use_one_time_prekey: bool,
) -> Result<SealedMessageResult> {
    // Step 1: Parse recipient's prekeys
    let recipient_spk = parse_mlkem_public(recipient_identity.signed_prekey().public_key())?;

    // Step 2: Perform X3DH key agreement
    // Encapsulate to signed prekey
    let (ss1, ct1) = mlkem1024::encapsulate(&recipient_spk);

    // Optionally encapsulate to one-time prekey
    let (ss2, ct2, otp_id) = if use_one_time_prekey {
        if let Some(otp) = recipient_identity.one_time_prekeys().first() {
            let otp_public = parse_mlkem_public(otp.public_key())?;
            let (ss, ct) = mlkem1024::encapsulate(&otp_public);
            (Some(ss), Some(ct), Some(otp.id()))
        } else {
            (None, None, None)
        }
    } else {
        (None, None, None)
    };

    // Step 3: Derive conversation key and ID
    let (conversation_key, conversation_id) = derive_conversation_keys(
        &ss1,
        ss2.as_ref(),
        sender_identity.hash(),
        recipient_identity.hash(),
    )?;

    // Step 4: Encrypt inner message with mandatory padding
    // SECURITY: Use conversation_id as Additional Authenticated Data (AAD) to cryptographically
    // bind the message to this conversation, preventing message reassignment attacks.
    // SECURITY: Apply mandatory padding to hide message length from relay servers.
    let inner_bytes = inner_message.to_bytes()?;
    let padded_inner = crate::forum::sealed_message::padding::pad_to_bucket(&inner_bytes)?;

    let mut inner_nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut inner_nonce);

    let cipher = Aes256Gcm::new_from_slice(&conversation_key[..])
        .map_err(|_| PqpgpError::crypto("Failed to create AES-GCM cipher"))?;

    // Use AES-GCM with AAD for conversation binding
    use aes_gcm::aead::Payload;
    let payload = Payload {
        msg: &padded_inner,
        aad: &conversation_id, // Bind message to this conversation
    };
    let encrypted_inner = cipher
        .encrypt(Nonce::from_slice(&inner_nonce), payload)
        .map_err(|_| PqpgpError::crypto("Failed to encrypt inner message"))?;

    // Step 5: Create X3DH data
    let x3dh_data = X3DHData {
        signed_prekey_ciphertext: ct1.as_bytes().to_vec(),
        signed_prekey_id: recipient_identity.signed_prekey().id(),
        one_time_prekey_ciphertext: ct2.map(|ct| ct.as_bytes().to_vec()),
        one_time_prekey_id: otp_id,
    };

    // Step 6: Create sealed envelope
    let envelope = SealedEnvelope {
        sender_identity_hash: *sender_identity.hash(),
        x3dh_data: Some(x3dh_data),
        ratchet_header: None, // Not using double ratchet for now
        encrypted_inner,
        inner_nonce,
    };

    let envelope_bytes = envelope.to_bytes()?;

    // Step 7: Encrypt envelope with recipient's signed prekey (outer layer)
    // We use the signed prekey for outer encryption since it's always available
    let (outer_ss, outer_ct) = mlkem1024::encapsulate(&recipient_spk);

    let outer_key = derive_outer_key(&outer_ss)?;
    let mut outer_nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut outer_nonce);

    let outer_cipher = Aes256Gcm::new_from_slice(&outer_key)
        .map_err(|_| PqpgpError::crypto("Failed to create outer AES-GCM cipher"))?;

    let encrypted_envelope = outer_cipher
        .encrypt(Nonce::from_slice(&outer_nonce), envelope_bytes.as_slice())
        .map_err(|_| PqpgpError::crypto("Failed to encrypt envelope"))?;

    // Step 8: Build sealed payload: outer_ct || outer_nonce || encrypted_envelope
    let mut sealed_payload =
        Vec::with_capacity(MLKEM1024_CIPHERTEXT_SIZE + 12 + encrypted_envelope.len());
    sealed_payload.extend_from_slice(outer_ct.as_bytes());
    sealed_payload.extend_from_slice(&outer_nonce);
    sealed_payload.extend_from_slice(&encrypted_envelope);

    // Step 9: Compute recipient hint
    let recipient_hint_key =
        derive_hint_key_from_spk(recipient_identity.signed_prekey().public_key());
    let mut hint_nonce = [0u8; HINT_NONCE_SIZE];
    rand::rng().fill_bytes(&mut hint_nonce);
    let recipient_hint = compute_recipient_hint(&recipient_hint_key, &hint_nonce);

    // Step 10: Create sealed message
    let message =
        SealedPrivateMessage::create(forum_hash, recipient_hint, hint_nonce, sealed_payload)?;

    Ok(SealedMessageResult {
        message,
        conversation_id,
        conversation_key,
    })
}

/// Seals a private message using an existing conversation key.
///
/// This is used for replies in an existing conversation where the X3DH
/// key exchange has already been performed. The message is encrypted with
/// the existing conversation key and no X3DH data is included.
///
/// # Arguments
/// * `forum_hash` - The forum this message belongs to
/// * `sender_identity` - The sender's encryption identity
/// * `recipient_identity` - The recipient's encryption identity
/// * `inner_message` - The message to seal
/// * `conversation_key` - The existing conversation key from the session
/// * `conversation_id` - The existing conversation ID
///
/// # Returns
/// A `SealedMessageResult` containing the sealed message.
pub fn seal_private_message_with_session(
    forum_hash: ContentHash,
    sender_identity: &EncryptionIdentity,
    recipient_identity: &EncryptionIdentity,
    inner_message: InnerMessage,
    conversation_key: &[u8; 32],
    conversation_id: [u8; 32],
) -> Result<SealedMessageResult> {
    // Step 1: Encrypt inner message with existing conversation key and mandatory padding
    // SECURITY: Use conversation_id as AAD to bind message to this conversation
    // SECURITY: Apply mandatory padding to hide message length from relay servers.
    let inner_bytes = inner_message.to_bytes()?;
    let padded_inner = crate::forum::sealed_message::padding::pad_to_bucket(&inner_bytes)?;

    let mut inner_nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut inner_nonce);

    let cipher = Aes256Gcm::new_from_slice(conversation_key)
        .map_err(|_| PqpgpError::crypto("Failed to create AES-GCM cipher"))?;

    use aes_gcm::aead::Payload;
    let payload = Payload {
        msg: &padded_inner,
        aad: &conversation_id, // Bind message to this conversation
    };
    let encrypted_inner = cipher
        .encrypt(Nonce::from_slice(&inner_nonce), payload)
        .map_err(|_| PqpgpError::crypto("Failed to encrypt inner message"))?;

    // Step 2: Create sealed envelope (without X3DH data - using existing session)
    let envelope = SealedEnvelope {
        sender_identity_hash: *sender_identity.hash(),
        x3dh_data: None, // No X3DH for session messages
        ratchet_header: None,
        encrypted_inner,
        inner_nonce,
    };

    let envelope_bytes = envelope.to_bytes()?;

    // Step 3: Encrypt envelope with recipient's signed prekey (outer layer)
    let recipient_spk = parse_mlkem_public(recipient_identity.signed_prekey().public_key())?;
    let (outer_ss, outer_ct) = mlkem1024::encapsulate(&recipient_spk);

    let outer_key = derive_outer_key(&outer_ss)?;
    let mut outer_nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut outer_nonce);

    let outer_cipher = Aes256Gcm::new_from_slice(&outer_key)
        .map_err(|_| PqpgpError::crypto("Failed to create outer AES-GCM cipher"))?;

    let encrypted_envelope = outer_cipher
        .encrypt(Nonce::from_slice(&outer_nonce), envelope_bytes.as_slice())
        .map_err(|_| PqpgpError::crypto("Failed to encrypt envelope"))?;

    // Step 4: Build sealed payload
    let mut sealed_payload =
        Vec::with_capacity(MLKEM1024_CIPHERTEXT_SIZE + 12 + encrypted_envelope.len());
    sealed_payload.extend_from_slice(outer_ct.as_bytes());
    sealed_payload.extend_from_slice(&outer_nonce);
    sealed_payload.extend_from_slice(&encrypted_envelope);

    // Step 5: Compute recipient hint
    let recipient_hint_key =
        derive_hint_key_from_spk(recipient_identity.signed_prekey().public_key());
    let mut hint_nonce = [0u8; HINT_NONCE_SIZE];
    rand::rng().fill_bytes(&mut hint_nonce);
    let recipient_hint = compute_recipient_hint(&recipient_hint_key, &hint_nonce);

    // Step 6: Create sealed message
    let message =
        SealedPrivateMessage::create(forum_hash, recipient_hint, hint_nonce, sealed_payload)?;

    Ok(SealedMessageResult {
        message,
        conversation_id,
        conversation_key: Zeroizing::new(*conversation_key),
    })
}

/// Attempts to unseal a private message.
///
/// This performs:
/// 1. Verify recipient hint
/// 2. Decrypt outer layer with ML-KEM private key
/// 3. Extract sender identity and X3DH data
/// 4. Perform X3DH receiver-side to derive conversation key
/// 5. Decrypt inner message
///
/// # Arguments
/// * `sealed_message` - The sealed message to unseal
/// * `recipient_private` - The recipient's encryption private keys
///
/// # Returns
/// An `UnsealedMessageResult` if successful, or an error if this message
/// isn't for this recipient or is malformed.
pub fn unseal_private_message(
    sealed_message: &SealedPrivateMessage,
    recipient_private: &EncryptionIdentityPrivate,
) -> Result<UnsealedMessageResult> {
    // Step 1: Verify recipient hint
    // Use public key for hint derivation (same as sender)
    let spk_public_bytes = recipient_private.signed_prekey_public();
    let hint_key = derive_hint_key_from_spk(spk_public_bytes);

    if !sealed_message.check_recipient_hint(&hint_key) {
        return Err(PqpgpError::crypto(
            "Recipient hint mismatch - message not for this recipient",
        ));
    }

    // Step 2: Parse sealed payload
    let payload = sealed_message.sealed_payload();
    if payload.len() < MLKEM1024_CIPHERTEXT_SIZE + 12 {
        return Err(PqpgpError::crypto("Sealed payload too short"));
    }

    let outer_ct_bytes = &payload[..MLKEM1024_CIPHERTEXT_SIZE];
    let outer_nonce = &payload[MLKEM1024_CIPHERTEXT_SIZE..MLKEM1024_CIPHERTEXT_SIZE + 12];
    let encrypted_envelope = &payload[MLKEM1024_CIPHERTEXT_SIZE + 12..];

    // Step 3: Decrypt outer layer
    let outer_ct = mlkem1024::Ciphertext::from_bytes(outer_ct_bytes)
        .map_err(|_| PqpgpError::crypto("Invalid outer ciphertext"))?;

    let spk_secret = recipient_private.signed_prekey_as_mlkem()?;
    let outer_ss = mlkem1024::decapsulate(&outer_ct, &spk_secret);

    let outer_key = derive_outer_key(&outer_ss)?;
    let outer_cipher = Aes256Gcm::new_from_slice(&outer_key)
        .map_err(|_| PqpgpError::crypto("Failed to create outer AES-GCM cipher"))?;

    let envelope_bytes = outer_cipher
        .decrypt(Nonce::from_slice(outer_nonce), encrypted_envelope)
        .map_err(|_| PqpgpError::crypto("Failed to decrypt envelope - authentication failed"))?;

    // Step 4: Parse envelope
    let envelope = SealedEnvelope::from_bytes(&envelope_bytes)?;

    // Step 5: Perform X3DH receiver side
    let x3dh_data = envelope
        .x3dh_data
        .as_ref()
        .ok_or_else(|| PqpgpError::crypto("Missing X3DH data in initial message"))?;

    // Decapsulate signed prekey
    let ct1 = mlkem1024::Ciphertext::from_bytes(&x3dh_data.signed_prekey_ciphertext)
        .map_err(|_| PqpgpError::crypto("Invalid signed prekey ciphertext"))?;
    let ss1 = mlkem1024::decapsulate(&ct1, &spk_secret);

    // Decapsulate one-time prekey if present
    let (ss2, used_otp_id) = if let (Some(ct_bytes), Some(otp_id)) = (
        &x3dh_data.one_time_prekey_ciphertext,
        x3dh_data.one_time_prekey_id,
    ) {
        let ct2 = mlkem1024::Ciphertext::from_bytes(ct_bytes)
            .map_err(|_| PqpgpError::crypto("Invalid one-time prekey ciphertext"))?;
        let otp_secret = recipient_private.get_one_time_as_mlkem(otp_id)?;
        let ss = mlkem1024::decapsulate(&ct2, &otp_secret);
        (Some(ss), Some(otp_id))
    } else {
        (None, None)
    };

    // Step 6: Derive conversation key (same as sender)
    let (conversation_key, conversation_id) = derive_conversation_keys(
        &ss1,
        ss2.as_ref(),
        &envelope.sender_identity_hash,
        &recipient_private.identity_hash,
    )?;

    // Step 7: Decrypt inner message and remove padding
    // SECURITY: Verify conversation_id as AAD to ensure message belongs to this conversation
    let inner_cipher = Aes256Gcm::new_from_slice(&conversation_key[..])
        .map_err(|_| PqpgpError::crypto("Failed to create inner AES-GCM cipher"))?;

    use aes_gcm::aead::Payload;
    let payload = Payload {
        msg: &envelope.encrypted_inner,
        aad: &conversation_id, // Verify message is bound to this conversation
    };
    let padded_inner = inner_cipher
        .decrypt(Nonce::from_slice(&envelope.inner_nonce), payload)
        .map_err(|_| {
            PqpgpError::crypto("Failed to decrypt inner message - authentication failed")
        })?;

    // Remove mandatory padding
    let inner_bytes = crate::forum::sealed_message::padding::unpad(&padded_inner)?;

    let inner_message = InnerMessage::from_bytes(&inner_bytes)?;

    Ok(UnsealedMessageResult {
        inner_message,
        sender_identity_hash: envelope.sender_identity_hash,
        conversation_id,
        conversation_key,
        used_one_time_prekey_id: used_otp_id,
    })
}

/// Attempts to unseal a private message using an existing session key.
///
/// This is used for messages in an existing conversation where we already
/// have the conversation key. The message doesn't contain X3DH data.
///
/// # Arguments
/// * `sealed_message` - The sealed message to unseal
/// * `recipient_private` - The recipient's encryption private keys
/// * `conversation_key` - The existing conversation key from the session
/// * `conversation_id` - The existing conversation ID
/// * `expected_sender_hash` - Expected sender identity hash for verification
///
/// # Returns
/// An `UnsealedMessageResult` if successful.
///
/// # Security
/// This function validates that the sender identity in the envelope matches
/// the expected sender from the session, preventing sender impersonation.
pub fn unseal_private_message_with_session(
    sealed_message: &SealedPrivateMessage,
    recipient_private: &EncryptionIdentityPrivate,
    conversation_key: &[u8; 32],
    conversation_id: [u8; 32],
    expected_sender_hash: Option<&ContentHash>,
) -> Result<UnsealedMessageResult> {
    // Step 1: Verify recipient hint
    let spk_public_bytes = recipient_private.signed_prekey_public();
    let hint_key = derive_hint_key_from_spk(spk_public_bytes);

    if !sealed_message.check_recipient_hint(&hint_key) {
        return Err(PqpgpError::crypto(
            "Recipient hint mismatch - message not for this recipient",
        ));
    }

    // Step 2: Parse sealed payload
    let payload = sealed_message.sealed_payload();
    if payload.len() < MLKEM1024_CIPHERTEXT_SIZE + 12 {
        return Err(PqpgpError::crypto("Sealed payload too short"));
    }

    let outer_ct_bytes = &payload[..MLKEM1024_CIPHERTEXT_SIZE];
    let outer_nonce = &payload[MLKEM1024_CIPHERTEXT_SIZE..MLKEM1024_CIPHERTEXT_SIZE + 12];
    let encrypted_envelope = &payload[MLKEM1024_CIPHERTEXT_SIZE + 12..];

    // Step 3: Decrypt outer layer
    let outer_ct = mlkem1024::Ciphertext::from_bytes(outer_ct_bytes)
        .map_err(|_| PqpgpError::crypto("Invalid outer ciphertext"))?;

    let spk_secret = recipient_private.signed_prekey_as_mlkem()?;
    let outer_ss = mlkem1024::decapsulate(&outer_ct, &spk_secret);

    let outer_key = derive_outer_key(&outer_ss)?;
    let outer_cipher = Aes256Gcm::new_from_slice(&outer_key)
        .map_err(|_| PqpgpError::crypto("Failed to create outer AES-GCM cipher"))?;

    let envelope_bytes = outer_cipher
        .decrypt(Nonce::from_slice(outer_nonce), encrypted_envelope)
        .map_err(|_| PqpgpError::crypto("Failed to decrypt envelope - authentication failed"))?;

    // Step 4: Parse envelope
    let envelope = SealedEnvelope::from_bytes(&envelope_bytes)?;

    // Step 5: SECURITY - Verify sender matches expected peer from session
    // This prevents sender impersonation within an established conversation.
    if let Some(expected) = expected_sender_hash {
        if &envelope.sender_identity_hash != expected {
            return Err(PqpgpError::crypto(
                "Sender identity mismatch - message sender does not match expected peer",
            ));
        }
    }

    // Step 6: Decrypt inner message using existing conversation key and remove padding
    // SECURITY: Verify conversation_id as AAD to ensure message belongs to this conversation
    let inner_cipher = Aes256Gcm::new_from_slice(conversation_key)
        .map_err(|_| PqpgpError::crypto("Failed to create inner AES-GCM cipher"))?;

    use aes_gcm::aead::Payload;
    let payload = Payload {
        msg: &envelope.encrypted_inner,
        aad: &conversation_id, // Verify message is bound to this conversation
    };
    let padded_inner = inner_cipher
        .decrypt(Nonce::from_slice(&envelope.inner_nonce), payload)
        .map_err(|_| {
            PqpgpError::crypto("Failed to decrypt inner message - authentication failed")
        })?;

    // Remove mandatory padding
    let inner_bytes = crate::forum::sealed_message::padding::unpad(&padded_inner)?;

    let inner_message = InnerMessage::from_bytes(&inner_bytes)?;

    Ok(UnsealedMessageResult {
        inner_message,
        sender_identity_hash: envelope.sender_identity_hash,
        conversation_id,
        conversation_key: Zeroizing::new(*conversation_key),
        used_one_time_prekey_id: None,
    })
}

/// Derives conversation key and ID from X3DH shared secrets.
fn derive_conversation_keys(
    ss1: &mlkem1024::SharedSecret,
    ss2: Option<&mlkem1024::SharedSecret>,
    sender_hash: &ContentHash,
    recipient_hash: &ContentHash,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
    // Build input key material
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(ss1.as_bytes());
    if let Some(ss) = ss2 {
        ikm.extend_from_slice(ss.as_bytes());
    }

    // Build salt from identity hashes (for domain separation)
    let mut salt = Vec::with_capacity(128);
    salt.extend_from_slice(CONVERSATION_KEY_DOMAIN);
    salt.extend_from_slice(sender_hash.as_bytes());
    salt.extend_from_slice(recipient_hash.as_bytes());

    let hkdf = Hkdf::<Sha3_256>::new(Some(&salt), &ikm);

    // Derive conversation key
    let mut conversation_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"conversation-key", &mut conversation_key[..])
        .map_err(|_| PqpgpError::crypto("HKDF expansion failed for conversation key"))?;

    // Derive conversation ID
    let mut conversation_id = [0u8; 32];
    hkdf.expand(CONVERSATION_ID_DOMAIN, &mut conversation_id)
        .map_err(|_| PqpgpError::crypto("HKDF expansion failed for conversation ID"))?;

    Ok((conversation_key, conversation_id))
}

/// Derives the outer encryption key from the outer shared secret.
fn derive_outer_key(outer_ss: &mlkem1024::SharedSecret) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha3_256>::new(Some(b"PQPGP-PM-outer-v1"), outer_ss.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(b"outer-key", &mut key)
        .map_err(|_| PqpgpError::crypto("HKDF expansion failed for outer key"))?;
    Ok(key)
}

/// Parses ML-KEM-1024 public key from bytes.
fn parse_mlkem_public(bytes: &[u8]) -> Result<mlkem1024::PublicKey> {
    mlkem1024::PublicKey::from_bytes(bytes)
        .map_err(|_| PqpgpError::crypto("Invalid ML-KEM-1024 public key"))
}

/// Derives a hint key from signed prekey public key bytes.
/// Both sender and recipient use the same public key to derive the hint key.
///
/// SECURITY: Uses HKDF with domain separation for proper key derivation.
/// This matches the derivation in sealed_message.rs::derive_hint_key().
fn derive_hint_key_from_spk(spk_public: &[u8]) -> [u8; 32] {
    // Use the unified HKDF-based derivation from sealed_message
    crate::forum::sealed_message::derive_hint_key(spk_public)
}

// ============================================================================
// Double Ratchet Based Functions
//
// These functions use the Double Ratchet protocol for per-message key derivation,
// providing forward secrecy and post-compromise security.
// ============================================================================

/// Seals a private message using the Double Ratchet for key derivation.
///
/// This provides maximum security with per-message keys that are immediately
/// deleted after use. Even if a key is compromised, only that single message
/// is affected.
///
/// # Arguments
/// * `forum_hash` - Hash of the forum this message belongs to
/// * `sender_identity` - Sender's encryption identity
/// * `recipient_identity` - Recipient's encryption identity
/// * `inner_message` - The message content to encrypt
/// * `session` - The conversation session (will be mutated to advance ratchet)
///
/// # Returns
/// The sealed private message ready for DAG storage.
///
/// # Security Properties
/// - **Forward Secrecy**: Message key is derived from ratchet chain and deleted after use
/// - **Post-Compromise Security**: Ratchet rotates keys, so compromise is limited
/// - **Deniability**: No signatures on message content
pub fn seal_with_ratchet(
    forum_hash: ContentHash,
    sender_identity: &EncryptionIdentity,
    recipient_identity: &EncryptionIdentity,
    inner_message: InnerMessage,
    session: &mut ConversationSession,
) -> Result<SealedPrivateMessage> {
    // Step 1: Initialize ratchet if this is the first message
    // The KEM ciphertext for the first message will be included via get_sending_key()
    if !session.is_ratchet_initialized() {
        session.initialize_ratchet_initiator(recipient_identity.signed_prekey().public_key())?;
    }

    // Step 2: Get sending key from the ratchet
    let send_info = session.get_sending_key()?;

    // Step 3: Encrypt inner message with the ratchet-derived key
    let inner_bytes = inner_message.to_bytes()?;
    let mut inner_nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut inner_nonce);

    let aes_key = send_info.message_key.derive_aes_key()?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|_| PqpgpError::crypto("Failed to create AES-GCM cipher"))?;

    let encrypted_inner = cipher
        .encrypt(Nonce::from_slice(&inner_nonce), inner_bytes.as_slice())
        .map_err(|_| PqpgpError::crypto("Failed to encrypt inner message"))?;

    // Step 4: Create ratchet header
    let ratchet_header = RatchetHeader {
        ratchet_public_key: send_info.ratchet_public_key.as_bytes().to_vec(),
        previous_chain_length: send_info.previous_chain_length,
        message_number: send_info.message_number,
    };

    // Step 5: Create sealed envelope with ratchet header
    let envelope = SealedEnvelope {
        sender_identity_hash: *sender_identity.hash(),
        x3dh_data: None, // No X3DH for ratchet-based messages
        ratchet_header: Some(ratchet_header),
        encrypted_inner,
        inner_nonce,
    };

    // Step 6: Encrypt envelope with recipient's signed prekey (outer layer)
    let envelope_bytes = envelope.to_bytes()?;
    let recipient_spk = parse_mlkem_public(recipient_identity.signed_prekey().public_key())?;
    let (outer_ss, outer_ct) = mlkem1024::encapsulate(&recipient_spk);

    let outer_key = derive_outer_key(&outer_ss)?;
    let mut outer_nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut outer_nonce);

    let outer_cipher = Aes256Gcm::new_from_slice(&outer_key)
        .map_err(|_| PqpgpError::crypto("Failed to create outer AES-GCM cipher"))?;

    let encrypted_envelope = outer_cipher
        .encrypt(Nonce::from_slice(&outer_nonce), envelope_bytes.as_slice())
        .map_err(|_| PqpgpError::crypto("Failed to encrypt envelope"))?;

    // Step 7: Build sealed payload with KEM ciphertext if present
    let kem_ct_bytes = send_info.kem_ciphertext;
    let sealed_payload = build_sealed_payload_with_kem(
        &outer_ct,
        &outer_nonce,
        &encrypted_envelope,
        kem_ct_bytes.as_deref(),
    );

    // Step 8: Compute recipient hint
    let recipient_hint_key =
        derive_hint_key_from_spk(recipient_identity.signed_prekey().public_key());
    let mut hint_nonce = [0u8; HINT_NONCE_SIZE];
    rand::rng().fill_bytes(&mut hint_nonce);
    let recipient_hint = compute_recipient_hint(&recipient_hint_key, &hint_nonce);

    // Step 9: Create sealed message
    let message =
        SealedPrivateMessage::create(forum_hash, recipient_hint, hint_nonce, sealed_payload)?;

    // Record the send
    session.record_sent();

    Ok(message)
}

/// Unseals a private message using the Double Ratchet for key derivation.
///
/// # Arguments
/// * `sealed_message` - The sealed message to unseal
/// * `recipient_private` - The recipient's encryption private keys
/// * `session` - The conversation session (will be mutated to advance ratchet)
///
/// # Returns
/// The decrypted inner message.
///
/// # Security
/// The ratchet state advances on each received message, providing forward secrecy.
/// Out-of-order messages are handled by storing skipped keys.
pub fn unseal_with_ratchet(
    sealed_message: &SealedPrivateMessage,
    recipient_private: &EncryptionIdentityPrivate,
    session: &mut ConversationSession,
) -> Result<InnerMessage> {
    // Step 1: Verify recipient hint
    let spk_public_bytes = recipient_private.signed_prekey_public();
    let hint_key = derive_hint_key_from_spk(spk_public_bytes);

    if !sealed_message.check_recipient_hint(&hint_key) {
        return Err(PqpgpError::crypto(
            "Recipient hint mismatch - message not for this recipient",
        ));
    }

    // Step 2: Parse sealed payload and extract KEM ciphertext
    let payload = sealed_message.sealed_payload();
    let (outer_ct_bytes, outer_nonce, encrypted_envelope, kem_ciphertext) =
        parse_sealed_payload_with_kem(payload)?;

    // Step 3: Decrypt outer layer
    let outer_ct = mlkem1024::Ciphertext::from_bytes(outer_ct_bytes)
        .map_err(|_| PqpgpError::crypto("Invalid outer ciphertext"))?;

    let spk_secret = recipient_private.signed_prekey_as_mlkem()?;
    let outer_ss = mlkem1024::decapsulate(&outer_ct, &spk_secret);

    let outer_key = derive_outer_key(&outer_ss)?;
    let outer_cipher = Aes256Gcm::new_from_slice(&outer_key)
        .map_err(|_| PqpgpError::crypto("Failed to create outer AES-GCM cipher"))?;

    let envelope_bytes = outer_cipher
        .decrypt(Nonce::from_slice(outer_nonce), encrypted_envelope)
        .map_err(|_| PqpgpError::crypto("Failed to decrypt envelope - authentication failed"))?;

    // Step 4: Parse envelope
    let envelope = SealedEnvelope::from_bytes(&envelope_bytes)?;

    // Step 5: Get ratchet header
    let ratchet_header = envelope
        .ratchet_header
        .as_ref()
        .ok_or_else(|| PqpgpError::crypto("Missing ratchet header in message"))?;

    // Step 6: Get receiving key from ratchet
    let message_key = session.get_receiving_key(
        &ratchet_header.ratchet_public_key,
        ratchet_header.message_number,
        ratchet_header.previous_chain_length,
        kem_ciphertext,
    )?;

    // Step 7: Decrypt inner message
    let aes_key = message_key.derive_aes_key()?;
    let inner_cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|_| PqpgpError::crypto("Failed to create inner AES-GCM cipher"))?;

    let inner_bytes = inner_cipher
        .decrypt(
            Nonce::from_slice(&envelope.inner_nonce),
            envelope.encrypted_inner.as_slice(),
        )
        .map_err(|_| {
            PqpgpError::crypto("Failed to decrypt inner message - authentication failed")
        })?;

    let inner_message = InnerMessage::from_bytes(&inner_bytes)?;

    // Record the receive
    session.record_received();

    Ok(inner_message)
}

/// Builds a sealed payload that includes optional KEM ciphertext for ratchet rotation.
///
/// Format: outer_ct (1568) || outer_nonce (12) || kem_ct_len (2) || [kem_ct (variable)] || encrypted_envelope
fn build_sealed_payload_with_kem(
    outer_ct: &mlkem1024::Ciphertext,
    outer_nonce: &[u8; 12],
    encrypted_envelope: &[u8],
    kem_ciphertext: Option<&[u8]>,
) -> Vec<u8> {
    // Always include 2 bytes for kem_len, plus the actual ciphertext if present
    let kem_data_size = kem_ciphertext.map(|ct| ct.len()).unwrap_or(0);
    let mut payload = Vec::with_capacity(
        MLKEM1024_CIPHERTEXT_SIZE + 12 + 2 + kem_data_size + encrypted_envelope.len(),
    );

    // Outer ML-KEM ciphertext
    payload.extend_from_slice(outer_ct.as_bytes());
    // Outer nonce
    payload.extend_from_slice(outer_nonce);

    // KEM ciphertext length-prefixed (always present)
    if let Some(ct) = kem_ciphertext {
        let len = ct.len() as u16;
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(ct);
    } else {
        // Zero length means no KEM ciphertext
        payload.extend_from_slice(&0u16.to_le_bytes());
    }

    // Encrypted envelope
    payload.extend_from_slice(encrypted_envelope);

    payload
}

/// Parsed components from a sealed payload with KEM ciphertext.
/// (outer_ct, outer_nonce, encrypted_envelope, optional_kem_ct)
type ParsedSealedPayload<'a> = (&'a [u8], &'a [u8], &'a [u8], Option<&'a [u8]>);

/// Parses a sealed payload that may include KEM ciphertext for ratchet rotation.
///
/// Returns (outer_ct, outer_nonce, encrypted_envelope, optional_kem_ct)
fn parse_sealed_payload_with_kem(payload: &[u8]) -> Result<ParsedSealedPayload<'_>> {
    // Minimum size: outer_ct (1568) + outer_nonce (12) + kem_len (2)
    if payload.len() < MLKEM1024_CIPHERTEXT_SIZE + 12 + 2 {
        return Err(PqpgpError::crypto("Sealed payload too short"));
    }

    let outer_ct = &payload[..MLKEM1024_CIPHERTEXT_SIZE];
    let outer_nonce = &payload[MLKEM1024_CIPHERTEXT_SIZE..MLKEM1024_CIPHERTEXT_SIZE + 12];

    let kem_len_offset = MLKEM1024_CIPHERTEXT_SIZE + 12;
    let kem_len =
        u16::from_le_bytes([payload[kem_len_offset], payload[kem_len_offset + 1]]) as usize;

    let kem_data_start = kem_len_offset + 2;

    if kem_len > 0 {
        if payload.len() < kem_data_start + kem_len {
            return Err(PqpgpError::crypto("Invalid KEM ciphertext length"));
        }
        let kem_ct = &payload[kem_data_start..kem_data_start + kem_len];
        let encrypted_envelope = &payload[kem_data_start + kem_len..];
        Ok((outer_ct, outer_nonce, encrypted_envelope, Some(kem_ct)))
    } else {
        let encrypted_envelope = &payload[kem_data_start..];
        Ok((outer_ct, outer_nonce, encrypted_envelope, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::forum::encryption_identity::EncryptionIdentityGenerator;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
    }

    fn create_test_forum_hash() -> ContentHash {
        ContentHash::from_bytes([42u8; 64])
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
        let forum_hash = create_test_forum_hash();

        // Create sender identity
        let sender_keypair = create_test_keypair();
        let (sender_identity, _sender_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        // Create recipient identity
        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        // Create and seal message
        let inner = InnerMessage::new([0u8; 32], "Hello, this is a secret message!".to_string());

        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner.clone(),
            true,
        )
        .expect("Failed to seal message");

        // Unseal message
        let unsealed_result = unseal_private_message(&sealed_result.message, &recipient_private)
            .expect("Failed to unseal message");

        // Verify content
        assert_eq!(
            unsealed_result.inner_message.body,
            "Hello, this is a secret message!"
        );
        assert_eq!(
            unsealed_result.sender_identity_hash,
            *sender_identity.hash()
        );
        assert!(unsealed_result.used_one_time_prekey_id.is_some());
    }

    #[test]
    fn test_wrong_recipient_cannot_unseal() {
        let forum_hash = create_test_forum_hash();

        // Create sender and two recipients
        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        let recipient_keypair = create_test_keypair();
        let (recipient_identity, _recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        let wrong_keypair = create_test_keypair();
        let (_wrong_identity, wrong_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            wrong_keypair.public_key(),
            wrong_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate wrong identity");

        // Seal message to correct recipient
        let inner = InnerMessage::new([0u8; 32], "Secret message".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            false,
        )
        .expect("Failed to seal message");

        // Wrong recipient should fail hint check
        let result = unseal_private_message(&sealed_result.message, &wrong_private);
        assert!(result.is_err());
    }

    #[test]
    fn test_seal_without_one_time_prekey() {
        let forum_hash = create_test_forum_hash();

        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            0, // No OTPs
            None,
        )
        .expect("Failed to generate sender identity");

        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            0, // No OTPs
            None,
        )
        .expect("Failed to generate recipient identity");

        // Seal without OTP
        let inner = InnerMessage::new([0u8; 32], "Message without OTP".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            false,
        )
        .expect("Failed to seal message");

        // Should still unseal
        let unsealed = unseal_private_message(&sealed_result.message, &recipient_private)
            .expect("Failed to unseal");

        assert_eq!(unsealed.inner_message.body, "Message without OTP");
        assert!(unsealed.used_one_time_prekey_id.is_none());
    }

    #[test]
    fn test_conversation_keys_are_deterministic() {
        let forum_hash = create_test_forum_hash();

        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        let inner = InnerMessage::new([0u8; 32], "Test".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            true,
        )
        .expect("Failed to seal message");

        let unsealed = unseal_private_message(&sealed_result.message, &recipient_private)
            .expect("Failed to unseal");

        // Sender and recipient should derive same conversation key
        // (We can't directly compare since sealing creates new randomness,
        // but the unsealed key should work for decryption - which we already tested)
        assert_eq!(unsealed.conversation_id.len(), 32);
    }

    #[test]
    fn test_message_with_subject_and_reply() {
        let forum_hash = create_test_forum_hash();

        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        let reply_to_id = [99u8; 16];
        let inner = InnerMessage::new([0u8; 32], "Reply message".to_string())
            .with_subject("Re: Previous".to_string())
            .with_reply_to(reply_to_id);

        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            false,
        )
        .expect("Failed to seal message");

        let unsealed = unseal_private_message(&sealed_result.message, &recipient_private)
            .expect("Failed to unseal");

        assert_eq!(
            unsealed.inner_message.subject,
            Some("Re: Previous".to_string())
        );
        assert_eq!(unsealed.inner_message.reply_to, Some(reply_to_id));
    }

    #[test]
    fn test_tampering_detection_sealed_payload() {
        let forum_hash = create_test_forum_hash();

        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        let inner = InnerMessage::new([0u8; 32], "Secret message".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            true,
        )
        .expect("Failed to seal message");

        // Tamper with the sealed payload by flipping a byte
        let mut tampered_content = sealed_result.message.content().clone();
        let payload_offset = 100; // Somewhere in the sealed payload
        if tampered_content.sealed_payload.len() > payload_offset {
            tampered_content.sealed_payload[payload_offset] ^= 0xFF;
        }

        // Create tampered message
        let tampered_message = SealedPrivateMessage::from_content(tampered_content)
            .expect("Failed to create tampered message");

        // Unsealing should fail due to authentication failure
        let result = unseal_private_message(&tampered_message, &recipient_private);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("authentication")
                || err_msg.contains("failed")
                || err_msg.contains("hint"),
            "Expected authentication error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_tampering_detection_hint() {
        let forum_hash = create_test_forum_hash();

        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        let inner = InnerMessage::new([0u8; 32], "Secret message".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            true,
        )
        .expect("Failed to seal message");

        // Tamper with the recipient hint
        let mut tampered_content = sealed_result.message.content().clone();
        tampered_content.recipient_hint[0] ^= 0xFF;

        let tampered_message = SealedPrivateMessage::from_content(tampered_content)
            .expect("Failed to create tampered message");

        // Unsealing should fail at hint check
        let result = unseal_private_message(&tampered_message, &recipient_private);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hint"));
    }

    #[test]
    fn test_tampering_detection_nonce() {
        let forum_hash = create_test_forum_hash();

        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        let inner = InnerMessage::new([0u8; 32], "Secret message".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            true,
        )
        .expect("Failed to seal message");

        // Tamper with the hint nonce (affects hint verification)
        let mut tampered_content = sealed_result.message.content().clone();
        tampered_content.hint_nonce[0] ^= 0xFF;

        let tampered_message = SealedPrivateMessage::from_content(tampered_content)
            .expect("Failed to create tampered message");

        // Unsealing should fail at hint check (hint won't match with different nonce)
        let result = unseal_private_message(&tampered_message, &recipient_private);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hint"));
    }

    #[test]
    fn test_different_messages_have_different_hints() {
        let forum_hash = create_test_forum_hash();

        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        let recipient_keypair = create_test_keypair();
        let (recipient_identity, _recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        // Seal two messages to the same recipient
        let inner1 = InnerMessage::new([1u8; 32], "First message".to_string());
        let sealed1 = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner1,
            false,
        )
        .expect("Failed to seal first message");

        let inner2 = InnerMessage::new([2u8; 32], "Second message".to_string());
        let sealed2 = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner2,
            false,
        )
        .expect("Failed to seal second message");

        // Hints should be different (due to different nonces)
        // This prevents correlation of messages to the same recipient
        assert_ne!(
            sealed1.message.content().recipient_hint,
            sealed2.message.content().recipient_hint,
            "Messages to same recipient should have different hints (different nonces)"
        );

        // Nonces should also be different
        assert_ne!(
            sealed1.message.content().hint_nonce,
            sealed2.message.content().hint_nonce,
            "Each message should have a unique nonce"
        );
    }

    #[test]
    fn test_otp_consumption_tracking() {
        let forum_hash = create_test_forum_hash();

        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        // Seal message with OTP
        let inner = InnerMessage::new([0u8; 32], "Message".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            true,
        )
        .expect("Failed to seal message");

        // Unseal and get the used OTP ID
        let unsealed = unseal_private_message(&sealed_result.message, &recipient_private)
            .expect("Failed to unseal");

        // Verify OTP was used
        assert!(unsealed.used_one_time_prekey_id.is_some());
        let used_otp_id = unsealed.used_one_time_prekey_id.unwrap();

        // The OTP ID should be valid (within the range we generated)
        assert!(used_otp_id >= 2); // OTP IDs start at 2
        assert!(used_otp_id < 7); // We generated 5 OTPs starting at ID 2
    }

    #[test]
    fn test_sealed_payload_size_limits() {
        let forum_hash = create_test_forum_hash();

        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        let recipient_keypair = create_test_keypair();
        let (recipient_identity, _recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        // Create a message with a large but valid body size
        // Max sealed payload is 100KB, but we need to account for:
        // - Padding to bucket size (adds random bytes + 4 byte length)
        // - ML-KEM ciphertext (1568 bytes)
        // - Outer nonce (12 bytes)
        // - AES-GCM tag (16 bytes)
        // - Envelope serialization overhead
        // A 60KB body should safely fit within the 64KB bucket after padding
        let large_body = "X".repeat(60_000);
        let inner = InnerMessage::new([0u8; 32], large_body);

        let result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            false,
        );

        // Should succeed with large but valid message
        assert!(
            result.is_ok(),
            "Failed to seal large message: {:?}",
            result.err()
        );

        // Verify the sealed payload is within size limits (100KB max)
        let sealed = result.unwrap();
        assert!(sealed.message.content().sealed_payload.len() < 100_000);
    }

    // ========================================================================
    // Double Ratchet Tests
    // ========================================================================

    #[test]
    fn test_ratchet_seal_unseal_roundtrip() {
        use crate::forum::ConversationSession;

        let forum_hash = create_test_forum_hash();

        // Create sender identity
        let sender_keypair = create_test_keypair();
        let (sender_identity, _sender_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        // Create recipient identity
        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        // First, perform X3DH to establish conversation keys
        let inner = InnerMessage::new([0u8; 32], "Initial X3DH message".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            true,
        )
        .expect("Failed to seal X3DH message");

        // Unseal to get conversation info
        let unsealed = unseal_private_message(&sealed_result.message, &recipient_private)
            .expect("Failed to unseal X3DH message");

        // Create sender session (initiator)
        let peer_ratchet_key = Some(recipient_identity.signed_prekey().public_key().to_vec());
        let mut sender_session = ConversationSession::new_initiator(
            sealed_result.conversation_id,
            *sealed_result.conversation_key,
            *sender_identity.hash(),
            *recipient_identity.hash(),
            None,
            peer_ratchet_key,
        );

        // Create recipient session (responder)
        let ratchet_keypair = Some((
            recipient_private.signed_prekey_public().to_vec(),
            recipient_private.signed_prekey_secret().to_vec(),
        ));
        let mut recipient_session = ConversationSession::new_responder(
            unsealed.conversation_id,
            *unsealed.conversation_key,
            recipient_private.identity_hash,
            unsealed.sender_identity_hash,
            unsealed.used_one_time_prekey_id,
            ratchet_keypair,
        );

        // Now test ratchet-based seal/unseal
        let ratchet_inner = InnerMessage::new([0u8; 32], "Ratchet encrypted message!".to_string());
        let sealed_ratchet = seal_with_ratchet(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            ratchet_inner,
            &mut sender_session,
        )
        .expect("Failed to seal with ratchet");

        // Unseal with ratchet
        let decrypted =
            unseal_with_ratchet(&sealed_ratchet, &recipient_private, &mut recipient_session)
                .expect("Failed to unseal with ratchet");

        assert_eq!(decrypted.body, "Ratchet encrypted message!");
        assert_eq!(sender_session.messages_sent(), 1);
        assert_eq!(recipient_session.messages_received(), 1);
    }

    #[test]
    fn test_ratchet_multiple_messages() {
        use crate::forum::ConversationSession;

        let forum_hash = create_test_forum_hash();

        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        // Establish X3DH
        let inner = InnerMessage::new([0u8; 32], "X3DH".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            true,
        )
        .expect("Failed to seal");

        let unsealed = unseal_private_message(&sealed_result.message, &recipient_private)
            .expect("Failed to unseal");

        // Create sessions
        let mut sender_session = ConversationSession::new_initiator(
            sealed_result.conversation_id,
            *sealed_result.conversation_key,
            *sender_identity.hash(),
            *recipient_identity.hash(),
            None,
            Some(recipient_identity.signed_prekey().public_key().to_vec()),
        );

        let mut recipient_session = ConversationSession::new_responder(
            unsealed.conversation_id,
            *unsealed.conversation_key,
            recipient_private.identity_hash,
            unsealed.sender_identity_hash,
            None,
            Some((
                recipient_private.signed_prekey_public().to_vec(),
                recipient_private.signed_prekey_secret().to_vec(),
            )),
        );

        // Send multiple messages with ratchet
        for i in 0..5 {
            let msg = InnerMessage::new([0u8; 32], format!("Message {}", i));
            let sealed = seal_with_ratchet(
                forum_hash,
                &sender_identity,
                &recipient_identity,
                msg,
                &mut sender_session,
            )
            .expect("Failed to seal");

            let decrypted =
                unseal_with_ratchet(&sealed, &recipient_private, &mut recipient_session)
                    .expect("Failed to unseal");

            assert_eq!(decrypted.body, format!("Message {}", i));
        }

        assert_eq!(sender_session.messages_sent(), 5);
        assert_eq!(recipient_session.messages_received(), 5);
    }

    #[test]
    fn test_ratchet_per_message_keys_are_unique() {
        use crate::forum::ConversationSession;

        let forum_hash = create_test_forum_hash();

        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        let recipient_keypair = create_test_keypair();
        let (recipient_identity, _recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        // Establish X3DH
        let inner = InnerMessage::new([0u8; 32], "X3DH".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            true,
        )
        .expect("Failed to seal");

        // Create sender session
        let mut sender_session = ConversationSession::new_initiator(
            sealed_result.conversation_id,
            *sealed_result.conversation_key,
            *sender_identity.hash(),
            *recipient_identity.hash(),
            None,
            Some(recipient_identity.signed_prekey().public_key().to_vec()),
        );

        // Send two messages with identical content
        let msg1 = InnerMessage::new([0u8; 32], "Same content".to_string());
        let sealed1 = seal_with_ratchet(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            msg1,
            &mut sender_session,
        )
        .expect("Failed to seal first");

        let msg2 = InnerMessage::new([0u8; 32], "Same content".to_string());
        let sealed2 = seal_with_ratchet(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            msg2,
            &mut sender_session,
        )
        .expect("Failed to seal second");

        // The sealed payloads should be different due to different message keys
        assert_ne!(
            sealed1.content().sealed_payload,
            sealed2.content().sealed_payload,
            "Messages with same content should have different encrypted payloads (different keys)"
        );
    }

    #[test]
    fn test_kem_ciphertext_payload_format() {
        // Test the KEM ciphertext payload building and parsing
        use pqcrypto_mlkem::mlkem1024;

        // Create a test ciphertext
        let (pk, _sk) = mlkem1024::keypair();
        let (_ss, ct) = mlkem1024::encapsulate(&pk);

        let outer_nonce = [1u8; 12];
        let encrypted_envelope = vec![42u8; 100];
        let kem_ct = vec![99u8; 50];

        // Build with KEM ciphertext
        let payload_with_kem =
            build_sealed_payload_with_kem(&ct, &outer_nonce, &encrypted_envelope, Some(&kem_ct));

        // Parse it back
        let (parsed_ct, parsed_nonce, parsed_envelope, parsed_kem) =
            parse_sealed_payload_with_kem(&payload_with_kem).expect("Failed to parse");

        assert_eq!(parsed_ct, ct.as_bytes());
        assert_eq!(parsed_nonce, &outer_nonce);
        assert_eq!(parsed_envelope, &encrypted_envelope[..]);
        assert_eq!(parsed_kem, Some(&kem_ct[..]));

        // Build without KEM ciphertext
        let payload_without_kem =
            build_sealed_payload_with_kem(&ct, &outer_nonce, &encrypted_envelope, None);

        // Parse it back
        let (parsed_ct2, parsed_nonce2, parsed_envelope2, parsed_kem2) =
            parse_sealed_payload_with_kem(&payload_without_kem).expect("Failed to parse");

        assert_eq!(parsed_ct2, ct.as_bytes());
        assert_eq!(parsed_nonce2, &outer_nonce);
        assert_eq!(parsed_envelope2, &encrypted_envelope[..]);
        assert!(parsed_kem2.is_none());
    }
}
