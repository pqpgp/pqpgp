//! Session management for secure chat.
//!
//! This module provides high-level session management that combines:
//! - X3DH key agreement for session establishment
//! - Double Ratchet for message encryption/decryption
//! - Message ordering and delivery handling
//!
//! ## Session Lifecycle
//!
//! 1. **Initiation**: Alice creates a session using Bob's prekey bundle
//! 2. **First Message**: Alice sends an initial message with X3DH keys
//! 3. **Reception**: Bob receives the message and establishes his session state
//! 4. **Messaging**: Both parties can now exchange encrypted messages
//!
//! ## Session State
//!
//! Each session maintains:
//! - Double ratchet state (root key, chain keys, KEM keypairs)
//! - Peer identity information
//! - Message counters for replay protection
//! - Skipped message keys for out-of-order delivery

use crate::chat::identity::{IdentityKey, IdentityKeyPair};
use crate::chat::prekey::{PreKeyBundle, PreKeyGenerator};
use crate::chat::ratchet::{DoubleRatchet, MessageKey, RatchetKeyPair, RatchetPublicKey};
use crate::chat::x3dh::{X3DHKeys, X3DHReceiver, X3DHSender};
use crate::error::{PqpgpError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Information about the remote peer in a session.
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// The peer's identity key
    pub identity: IdentityKey,
    /// When we first established a session with this peer
    pub session_established: u64,
    /// Human-readable name or identifier (optional)
    pub display_name: Option<String>,
    /// Whether this peer's identity has been verified out-of-band
    /// (e.g., by comparing fingerprints in person, QR code scan, etc.)
    ///
    /// Note: Even unverified peers are cryptographically authenticated via X3DH -
    /// this flag indicates whether the user has manually confirmed the identity
    /// belongs to who they expect (protection against man-in-the-middle attacks).
    pub identity_verified: bool,
}

impl fmt::Debug for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerInfo")
            .field("identity", &self.identity)
            .field("session_established", &self.session_established)
            .field("display_name", &self.display_name)
            .field("identity_verified", &self.identity_verified)
            .finish()
    }
}

impl PeerInfo {
    /// Creates new peer info from an identity key.
    ///
    /// The identity starts as unverified - call `mark_verified()` after
    /// out-of-band verification (e.g., fingerprint comparison).
    pub fn new(identity: IdentityKey) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            identity,
            session_established: now,
            display_name: None,
            identity_verified: false,
        }
    }

    /// Creates peer info with a display name.
    pub fn with_name(identity: IdentityKey, name: String) -> Self {
        let mut info = Self::new(identity);
        info.display_name = Some(name);
        info
    }

    /// Marks this peer's identity as verified.
    ///
    /// Call this after the user has confirmed the peer's identity out-of-band
    /// (e.g., by comparing fingerprints in person or via a secure channel).
    pub fn mark_verified(&mut self) {
        self.identity_verified = true;
    }

    /// Returns whether this peer's identity has been verified out-of-band.
    pub fn is_verified(&self) -> bool {
        self.identity_verified
    }
}

/// State of a chat session that can be serialized.
#[derive(Serialize, Deserialize)]
pub struct SessionState {
    /// Information about the remote peer
    pub peer: PeerInfo,
    /// Whether we initiated this session
    pub is_initiator: bool,
    /// Whether the session has been fully established (both sides have exchanged messages)
    pub established: bool,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
}

impl fmt::Debug for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionState")
            .field("peer", &self.peer)
            .field("is_initiator", &self.is_initiator)
            .field("established", &self.established)
            .field("messages_sent", &self.messages_sent)
            .field("messages_received", &self.messages_received)
            .finish()
    }
}

/// Initial message data sent when establishing a new session.
#[derive(Clone, Serialize, Deserialize)]
pub struct InitialMessage {
    /// X3DH key material
    pub x3dh_keys: X3DHKeys,
    /// The encrypted message content
    pub encrypted_message: Vec<u8>,
    /// Message header containing ratchet info
    pub header: MessageHeader,
}

impl fmt::Debug for InitialMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialMessage")
            .field("x3dh_keys", &self.x3dh_keys)
            .field("encrypted_message_len", &self.encrypted_message.len())
            .finish()
    }
}

/// Message header containing ratchet information.
#[derive(Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Sender's current ratchet public key
    pub ratchet_key: Vec<u8>,
    /// Previous chain length
    pub previous_chain_length: u32,
    /// Message number in current chain
    pub message_number: u32,
    /// KEM ciphertext for ratchet step (if ratchet key changed)
    pub kem_ciphertext: Option<Vec<u8>>,
}

impl fmt::Debug for MessageHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageHeader")
            .field("message_number", &self.message_number)
            .field("previous_chain_length", &self.previous_chain_length)
            .field("has_kem_ciphertext", &self.kem_ciphertext.is_some())
            .finish()
    }
}

/// A complete encrypted message for transmission.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedChatMessage {
    /// Whether this is an initial message (contains X3DH keys)
    pub is_initial: bool,
    /// X3DH keys (only for initial messages)
    pub x3dh_keys: Option<X3DHKeys>,
    /// Message header
    pub header: MessageHeader,
    /// Encrypted content
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for EncryptedChatMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedChatMessage")
            .field("is_initial", &self.is_initial)
            .field("header", &self.header)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// A chat session with a specific peer.
///
/// This is the main interface for sending and receiving encrypted messages.
#[derive(Serialize, Deserialize)]
pub struct Session {
    /// Our identity
    our_identity: IdentityKeyPair,
    /// Session metadata
    state: SessionState,
    /// The double ratchet for message encryption
    ratchet: DoubleRatchet,
    /// X3DH keys to include in next message (for initial messages)
    pending_x3dh_keys: Option<X3DHKeys>,
    /// Track if we've sent our first message
    sent_first_message: bool,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("our_identity", &self.our_identity.key_id())
            .field("state", &self.state)
            .field("sent_first_message", &self.sent_first_message)
            .finish()
    }
}

impl Session {
    /// Initiates a new session with a peer using their prekey bundle.
    ///
    /// This performs X3DH key agreement and sets up the double ratchet
    /// for sending messages. The first message will include the X3DH keys
    /// needed for the recipient to establish their side of the session.
    ///
    /// # Arguments
    /// * `our_identity` - Our identity key pair
    /// * `their_bundle` - The recipient's prekey bundle
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use pqpgp::chat::{IdentityKeyPair, Session, PreKeyBundle};
    /// use pqpgp::chat::prekey::PreKeyGenerator;
    ///
    /// let alice_identity = IdentityKeyPair::generate()?;
    /// let bob_identity = IdentityKeyPair::generate()?;
    ///
    /// // Bob publishes his prekey bundle
    /// let bob_prekeys = PreKeyGenerator::new(&bob_identity, 10)?;
    /// let bob_bundle = bob_prekeys.create_bundle(&bob_identity, true);
    ///
    /// // Alice initiates a session with Bob
    /// let mut alice_session = Session::initiate(&alice_identity, &bob_bundle)?;
    ///
    /// // Alice can now send messages
    /// let encrypted = alice_session.encrypt(b"Hello Bob!")?;
    /// # Ok::<(), pqpgp::error::PqpgpError>(())
    /// ```
    pub fn initiate(our_identity: &IdentityKeyPair, their_bundle: &PreKeyBundle) -> Result<Self> {
        // Perform X3DH key agreement
        let (shared_secret, x3dh_keys) = X3DHSender::perform(our_identity, their_bundle)?;

        // Get the signed prekey as the initial ratchet key
        let their_ratchet_key =
            RatchetPublicKey::from_bytes(their_bundle.signed_prekey().public_key().to_vec())?;

        // Create the double ratchet
        let ratchet = DoubleRatchet::new_initiator(
            *shared_secret.root_key(),
            their_ratchet_key,
            shared_secret.associated_data().to_vec(),
        )?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let state = SessionState {
            peer: PeerInfo::new(their_bundle.identity_key().clone()),
            is_initiator: true,
            established: false,
            last_activity: now,
            messages_sent: 0,
            messages_received: 0,
        };

        Ok(Self {
            our_identity: our_identity.clone(),
            state,
            ratchet,
            pending_x3dh_keys: Some(x3dh_keys),
            sent_first_message: false,
        })
    }

    /// Receives an initial message and establishes a session.
    ///
    /// This is called by the recipient when they receive the first message
    /// from a new session initiator.
    ///
    /// # Arguments
    /// * `our_identity` - Our identity key pair
    /// * `prekey_generator` - Our prekey generator to look up the used keys
    /// * `initial_message` - The initial message received
    ///
    /// # Returns
    /// A tuple of (session, decrypted_message)
    pub fn receive_initial(
        our_identity: &IdentityKeyPair,
        prekey_generator: &mut PreKeyGenerator,
        initial_message: &EncryptedChatMessage,
    ) -> Result<(Self, Vec<u8>)> {
        if !initial_message.is_initial {
            return Err(PqpgpError::session("Expected initial message"));
        }

        let x3dh_keys = initial_message
            .x3dh_keys
            .as_ref()
            .ok_or_else(|| PqpgpError::session("Initial message missing X3DH keys"))?;

        // Verify the signed prekey ID matches
        if prekey_generator.signed_prekey().id() != x3dh_keys.signed_prekey_id {
            return Err(PqpgpError::session("Signed prekey ID mismatch"));
        }

        // Get the one-time prekey private if used
        let otp_private = x3dh_keys
            .one_time_prekey_id
            .and_then(|id| prekey_generator.consume_one_time_prekey(id));

        // Perform X3DH key agreement
        let shared_secret = X3DHReceiver::perform(
            our_identity,
            prekey_generator.signed_prekey_private(),
            otp_private.as_ref(),
            x3dh_keys,
        )?;

        // Create our ratchet keypair from the signed prekey
        // The initiator encapsulated against our signed prekey, so we need to use
        // the signed prekey private key for the initial decapsulation
        let our_ratchet_keypair = RatchetKeyPair::from_bytes(
            prekey_generator.signed_prekey().public_key().to_vec(),
            prekey_generator
                .signed_prekey_private()
                .secret_key_bytes()
                .to_vec(),
        )?;

        // Create the double ratchet as responder
        let mut ratchet = DoubleRatchet::new_responder(
            *shared_secret.root_key(),
            our_ratchet_keypair,
            shared_secret.associated_data().to_vec(),
        );

        // Parse the sender's ratchet key from the header
        let their_ratchet_key =
            RatchetPublicKey::from_bytes(initial_message.header.ratchet_key.clone())?;

        // Get the KEM ciphertext - required for the first message
        let kem_ciphertext = initial_message
            .header
            .kem_ciphertext
            .as_ref()
            .ok_or_else(|| PqpgpError::session("Initial message missing KEM ciphertext"))?;

        // Initialize the responder's ratchet with the sender's key and ciphertext
        ratchet.initialize_responder(&their_ratchet_key, kem_ciphertext)?;

        // Decrypt the first message using the initialized receiving chain
        let message_key = ratchet.decrypt_first_message(initial_message.header.message_number)?;

        let plaintext = decrypt_with_message_key(
            &message_key,
            &initial_message.ciphertext,
            ratchet.associated_data(),
        )?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let state = SessionState {
            peer: PeerInfo::new(x3dh_keys.sender_identity.clone()),
            is_initiator: false,
            established: true, // Established after receiving first message
            last_activity: now,
            messages_sent: 0,
            messages_received: 1,
        };

        let session = Self {
            our_identity: our_identity.clone(),
            state,
            ratchet,
            pending_x3dh_keys: None,
            sent_first_message: false,
        };

        Ok((session, plaintext))
    }

    /// Encrypts a message for the peer.
    ///
    /// The first message will include X3DH keys for session establishment.
    /// Subsequent messages only include ratchet information.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedChatMessage> {
        // Get encryption keys from the ratchet
        let (message_key, ratchet_key, message_number, previous_chain_length) =
            self.ratchet.encrypt()?;

        // Generate KEM ciphertext if needed (for ratchet step)
        let kem_ciphertext = self.ratchet.state_mut().generate_kem_ciphertext()?;

        // Encrypt the plaintext
        let ciphertext =
            encrypt_with_message_key(&message_key, plaintext, self.ratchet.associated_data())?;

        // Build the header
        let header = MessageHeader {
            ratchet_key: ratchet_key.as_bytes().to_vec(),
            previous_chain_length,
            message_number,
            kem_ciphertext,
        };

        // Check if this is the first message (include X3DH keys)
        let is_initial = !self.sent_first_message && self.pending_x3dh_keys.is_some();
        let x3dh_keys = if is_initial {
            self.sent_first_message = true;
            self.pending_x3dh_keys.take()
        } else {
            None
        };

        // Update state
        self.state.messages_sent += 1;
        self.state.last_activity = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(EncryptedChatMessage {
            is_initial,
            x3dh_keys,
            header,
            ciphertext,
        })
    }

    /// Decrypts a message from the peer.
    ///
    /// Handles out-of-order message delivery by using skipped message keys.
    pub fn decrypt(&mut self, message: &EncryptedChatMessage) -> Result<Vec<u8>> {
        if message.is_initial {
            return Err(PqpgpError::session(
                "Use receive_initial for initial messages",
            ));
        }

        // Parse the sender's ratchet key
        let their_ratchet_key = RatchetPublicKey::from_bytes(message.header.ratchet_key.clone())?;

        // Get the message key from the ratchet
        let message_key = self.ratchet.decrypt(
            &their_ratchet_key,
            message.header.message_number,
            message.header.previous_chain_length,
            message.header.kem_ciphertext.as_deref(),
        )?;

        // Decrypt the message
        let plaintext = decrypt_with_message_key(
            &message_key,
            &message.ciphertext,
            self.ratchet.associated_data(),
        )?;

        // Update state
        self.state.messages_received += 1;
        self.state.established = true;
        self.state.last_activity = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(plaintext)
    }

    /// Returns the peer's identity key.
    pub fn peer_identity(&self) -> &IdentityKey {
        &self.state.peer.identity
    }

    /// Returns the session state.
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// Returns whether the session is fully established.
    pub fn is_established(&self) -> bool {
        self.state.established
    }

    /// Returns our identity key ID.
    pub fn our_identity_key_id(&self) -> u64 {
        self.our_identity.key_id()
    }

    /// Returns the peer's identity key ID.
    pub fn peer_identity_key_id(&self) -> u64 {
        self.state.peer.identity.key_id()
    }
}

/// AES-GCM nonce size in bytes
const NONCE_SIZE: usize = 12;

/// Encrypts data using a message key with a random nonce.
///
/// The nonce is prepended to the ciphertext, so the output format is:
/// `[nonce (12 bytes)][ciphertext]`
fn encrypt_with_message_key(
    message_key: &MessageKey,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Key, Nonce,
    };
    use rand::RngCore;

    let aes_key_bytes = message_key.derive_aes_key()?;

    // Generate a random nonce for each encryption
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| PqpgpError::session("Message encryption failed"))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypts data using a message key.
///
/// Expects the input format to be: `[nonce (12 bytes)][ciphertext]`
fn decrypt_with_message_key(
    message_key: &MessageKey,
    ciphertext_with_nonce: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Key, Nonce,
    };

    // Validate minimum length (nonce + at least auth tag)
    if ciphertext_with_nonce.len() < NONCE_SIZE + 16 {
        return Err(PqpgpError::session("Ciphertext too short"));
    }

    // Extract nonce and ciphertext
    let nonce_bytes = &ciphertext_with_nonce[..NONCE_SIZE];
    let ciphertext = &ciphertext_with_nonce[NONCE_SIZE..];

    let aes_key_bytes = message_key.derive_aes_key()?;

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| PqpgpError::session("Message decryption failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::prekey::PreKeyGenerator;

    #[test]
    fn test_session_initiation() {
        let alice_identity = IdentityKeyPair::generate().unwrap();
        let bob_identity = IdentityKeyPair::generate().unwrap();

        let bob_prekeys = PreKeyGenerator::new(&bob_identity, 10).unwrap();
        let bob_bundle = bob_prekeys.create_bundle(&bob_identity, true);

        let session = Session::initiate(&alice_identity, &bob_bundle).unwrap();

        assert!(session.state.is_initiator);
        assert!(!session.state.established);
        assert_eq!(session.peer_identity_key_id(), bob_identity.key_id());
    }

    #[test]
    fn test_encrypt_first_message() {
        let alice_identity = IdentityKeyPair::generate().unwrap();
        let bob_identity = IdentityKeyPair::generate().unwrap();

        let bob_prekeys = PreKeyGenerator::new(&bob_identity, 10).unwrap();
        let bob_bundle = bob_prekeys.create_bundle(&bob_identity, true);

        let mut session = Session::initiate(&alice_identity, &bob_bundle).unwrap();

        let message = b"Hello, Bob!";
        let encrypted = session.encrypt(message).unwrap();

        assert!(encrypted.is_initial);
        assert!(encrypted.x3dh_keys.is_some());
        assert!(!encrypted.ciphertext.is_empty());
    }

    #[test]
    fn test_full_session_exchange() {
        let alice_identity = IdentityKeyPair::generate().unwrap();
        let bob_identity = IdentityKeyPair::generate().unwrap();

        // Bob generates prekeys
        let mut bob_prekeys = PreKeyGenerator::new(&bob_identity, 10).unwrap();
        let bob_bundle = bob_prekeys.create_bundle(&bob_identity, true);

        // Alice initiates session and sends first message
        let mut alice_session = Session::initiate(&alice_identity, &bob_bundle).unwrap();
        let first_message = b"Hello, Bob!";
        let encrypted = alice_session.encrypt(first_message).unwrap();

        // Bob receives and establishes his session
        let (mut bob_session, decrypted) =
            Session::receive_initial(&bob_identity, &mut bob_prekeys, &encrypted).unwrap();

        assert_eq!(decrypted, first_message);
        assert!(bob_session.is_established());

        // Bob sends a reply
        let reply = b"Hello, Alice!";
        let encrypted_reply = bob_session.encrypt(reply).unwrap();

        assert!(!encrypted_reply.is_initial);
        assert!(encrypted_reply.x3dh_keys.is_none());

        // Alice decrypts the reply
        let decrypted_reply = alice_session.decrypt(&encrypted_reply).unwrap();
        assert_eq!(decrypted_reply, reply);
        assert!(alice_session.is_established());
    }

    #[test]
    fn test_multiple_messages() {
        let alice_identity = IdentityKeyPair::generate().unwrap();
        let bob_identity = IdentityKeyPair::generate().unwrap();

        let mut bob_prekeys = PreKeyGenerator::new(&bob_identity, 10).unwrap();
        let bob_bundle = bob_prekeys.create_bundle(&bob_identity, true);

        let mut alice_session = Session::initiate(&alice_identity, &bob_bundle).unwrap();

        // First message (initial)
        let msg1 = b"Message 1";
        let enc1 = alice_session.encrypt(msg1).unwrap();
        assert!(enc1.is_initial);

        let (mut bob_session, dec1) =
            Session::receive_initial(&bob_identity, &mut bob_prekeys, &enc1).unwrap();
        assert_eq!(dec1, msg1);

        // Second message (not initial)
        let msg2 = b"Message 2";
        let enc2 = alice_session.encrypt(msg2).unwrap();
        assert!(!enc2.is_initial);

        let dec2 = bob_session.decrypt(&enc2).unwrap();
        assert_eq!(dec2, msg2);

        // Third message (not initial)
        let msg3 = b"Message 3";
        let enc3 = alice_session.encrypt(msg3).unwrap();
        assert!(!enc3.is_initial);

        let dec3 = bob_session.decrypt(&enc3).unwrap();
        assert_eq!(dec3, msg3);

        // Check message counts
        assert_eq!(alice_session.state().messages_sent, 3);
        assert_eq!(bob_session.state().messages_received, 3);
    }

    #[test]
    fn test_bidirectional_messaging() {
        let alice_identity = IdentityKeyPair::generate().unwrap();
        let bob_identity = IdentityKeyPair::generate().unwrap();

        let mut bob_prekeys = PreKeyGenerator::new(&bob_identity, 10).unwrap();
        let bob_bundle = bob_prekeys.create_bundle(&bob_identity, true);

        let mut alice_session = Session::initiate(&alice_identity, &bob_bundle).unwrap();

        // Alice -> Bob
        let enc1 = alice_session.encrypt(b"Hi Bob").unwrap();
        let (mut bob_session, _) =
            Session::receive_initial(&bob_identity, &mut bob_prekeys, &enc1).unwrap();

        // Bob -> Alice
        let enc2 = bob_session.encrypt(b"Hi Alice").unwrap();
        let dec2 = alice_session.decrypt(&enc2).unwrap();
        assert_eq!(dec2, b"Hi Alice");

        // Alice -> Bob again
        let enc3 = alice_session.encrypt(b"How are you?").unwrap();
        let dec3 = bob_session.decrypt(&enc3).unwrap();
        assert_eq!(dec3, b"How are you?");

        // Bob -> Alice again
        let enc4 = bob_session.encrypt(b"Great!").unwrap();
        let dec4 = alice_session.decrypt(&enc4).unwrap();
        assert_eq!(dec4, b"Great!");
    }

    #[test]
    fn test_message_tampering_detected() {
        let alice_identity = IdentityKeyPair::generate().unwrap();
        let bob_identity = IdentityKeyPair::generate().unwrap();

        let mut bob_prekeys = PreKeyGenerator::new(&bob_identity, 10).unwrap();
        let bob_bundle = bob_prekeys.create_bundle(&bob_identity, true);

        let mut alice_session = Session::initiate(&alice_identity, &bob_bundle).unwrap();

        let mut encrypted = alice_session.encrypt(b"Secret message").unwrap();

        // Tamper with the ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        // Bob should fail to decrypt
        let result = Session::receive_initial(&bob_identity, &mut bob_prekeys, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_peer_info() {
        let identity = IdentityKeyPair::generate().unwrap();
        let peer = PeerInfo::new(identity.public.clone());

        assert!(peer.display_name.is_none());
        assert!(peer.session_established > 0);

        let peer_with_name = PeerInfo::with_name(identity.public, "Alice".to_string());
        assert_eq!(peer_with_name.display_name, Some("Alice".to_string()));
    }
}
