//! Private message conversation session management.
//!
//! This module manages the state of private message conversations in the forum.
//! Each conversation maintains:
//!
//! - **Session state**: Cryptographic keys for message encryption/decryption
//! - **Message history**: Local cache of decrypted messages
//! - **Ratchet state**: Double Ratchet for forward secrecy
//!
//! ## Security Model
//!
//! - All conversation state is stored locally, never in the DAG
//! - Session keys are derived from X3DH key agreement
//! - **Double Ratchet provides per-message keys and post-compromise security**
//! - Message history is encrypted at rest
//!
//! ## Double Ratchet Protocol
//!
//! The Double Ratchet provides:
//! - **Forward Secrecy**: Each message has a unique key; compromising one doesn't
//!   reveal past messages
//! - **Post-Compromise Security**: After a key compromise, future messages become
//!   secure again after a round-trip exchange
//! - **Out-of-Order Delivery**: Handles messages arriving in different order than sent
//!
//! ### Key Hierarchy
//!
//! ```text
//! X3DH Key Agreement
//!        ↓
//!    Root Key (from conversation_key)
//!        ↓ KEM Ratchet (on each turn)
//!    Chain Key
//!        ↓ Symmetric Ratchet (each message)
//!    Message Key (unique per message)
//! ```

use crate::chat::prekey::PreKeyId;
use crate::chat::ratchet::{DoubleRatchet, MessageKey, RatchetKeyPair, RatchetPublicKey};
use crate::error::{PqpgpError, Result};
use crate::forum::sealed_message::InnerMessage;
use crate::forum::types::ContentHash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use zeroize::Zeroize;

/// Size of conversation ID in bytes.
pub const CONVERSATION_ID_SIZE: usize = 32;

/// Size of conversation key in bytes.
pub const CONVERSATION_KEY_SIZE: usize = 32;

/// Maximum number of messages to store per conversation.
pub const MAX_MESSAGES_PER_CONVERSATION: usize = 10000;

/// Cursor for message pagination: (timestamp, first 16 bytes of message_id).
pub type MessageCursor = (u64, [u8; 16]);

/// Result of paginated message query: (messages, total_count, next_cursor).
pub type PaginatedMessagesResult<'a> = (Vec<&'a StoredMessage>, usize, Option<MessageCursor>);

/// Unique identifier for a conversation.
///
/// This is derived from the X3DH key agreement and is known only to the
/// two parties in the conversation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConversationId([u8; CONVERSATION_ID_SIZE]);

impl ConversationId {
    /// Creates a conversation ID from bytes.
    pub fn from_bytes(bytes: [u8; CONVERSATION_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns the conversation ID as bytes.
    pub fn as_bytes(&self) -> &[u8; CONVERSATION_ID_SIZE] {
        &self.0
    }

    /// Returns a short hex representation for display.
    pub fn short(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

impl fmt::Debug for ConversationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConversationId({}...)", self.short())
    }
}

impl fmt::Display for ConversationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

/// State of a private message conversation.
///
/// This is stored locally and contains all cryptographic material needed
/// to encrypt and decrypt messages in the conversation.
#[derive(Serialize, Deserialize)]
pub struct ConversationSession {
    /// Unique conversation identifier (derived from X3DH).
    conversation_id: ConversationId,

    /// The peer's encryption identity hash.
    peer_identity_hash: ContentHash,

    /// Our encryption identity hash.
    our_identity_hash: ContentHash,

    /// Conversation key for message encryption (from X3DH).
    /// This is the root key for the Double Ratchet.
    #[serde(with = "conversation_key_serde")]
    conversation_key: [u8; CONVERSATION_KEY_SIZE],

    /// Whether we initiated this conversation.
    is_initiator: bool,

    /// One-time prekey ID that was consumed (if any).
    /// Stored to prevent replay attacks.
    consumed_otp_id: Option<PreKeyId>,

    /// Timestamp when conversation was created.
    created_at: u64,

    /// Timestamp of last message activity.
    last_activity: u64,

    /// Number of messages sent in this conversation.
    messages_sent: u64,

    /// Number of messages received in this conversation.
    messages_received: u64,

    /// Double Ratchet instance for forward secrecy.
    /// Initialized on first message exchange.
    #[serde(skip)]
    double_ratchet: Option<DoubleRatchet>,

    /// Whether the ratchet has been initialized.
    ratchet_initialized: bool,

    /// Peer's initial ratchet public key (from their signed prekey).
    /// Used to initialize the ratchet on first send/receive.
    peer_ratchet_public_key: Option<Vec<u8>>,

    /// Our ratchet keypair bytes for persistence.
    /// (public_key, secret_key) - restored on load.
    our_ratchet_keypair_bytes: Option<(Vec<u8>, Vec<u8>)>,
}

// Custom serialization for conversation key
mod conversation_key_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(key: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        key.to_vec().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes for conversation key"))
    }
}

impl Drop for ConversationSession {
    fn drop(&mut self) {
        // Zeroize sensitive key material
        self.conversation_key.zeroize();
    }
}

impl fmt::Debug for ConversationSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConversationSession")
            .field("conversation_id", &self.conversation_id)
            .field("peer_identity_hash", &self.peer_identity_hash.short())
            .field("is_initiator", &self.is_initiator)
            .field("messages_sent", &self.messages_sent)
            .field("messages_received", &self.messages_received)
            .field("ratchet_initialized", &self.ratchet_initialized)
            .finish_non_exhaustive()
    }
}

impl ConversationSession {
    /// Creates a new conversation session as the initiator.
    ///
    /// The initiator has the peer's ratchet public key (from their signed prekey)
    /// and can immediately initialize the Double Ratchet for sending.
    ///
    /// # Arguments
    /// * `conversation_id` - Unique ID derived from X3DH
    /// * `conversation_key` - Shared key derived from X3DH (becomes root key)
    /// * `our_identity_hash` - Our encryption identity hash
    /// * `peer_identity_hash` - Peer's encryption identity hash
    /// * `consumed_otp_id` - One-time prekey ID that was used (if any)
    /// * `peer_ratchet_public_key` - Peer's signed prekey public key (for ratchet)
    pub fn new_initiator(
        conversation_id: [u8; CONVERSATION_ID_SIZE],
        conversation_key: [u8; CONVERSATION_KEY_SIZE],
        our_identity_hash: ContentHash,
        peer_identity_hash: ContentHash,
        consumed_otp_id: Option<PreKeyId>,
        peer_ratchet_public_key: Option<Vec<u8>>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            conversation_id: ConversationId::from_bytes(conversation_id),
            peer_identity_hash,
            our_identity_hash,
            conversation_key,
            is_initiator: true,
            consumed_otp_id,
            created_at: now,
            last_activity: now,
            messages_sent: 0,
            messages_received: 0,
            double_ratchet: None,
            ratchet_initialized: false,
            peer_ratchet_public_key,
            our_ratchet_keypair_bytes: None,
        }
    }

    /// Creates a new conversation session as the responder.
    ///
    /// The responder provided their ratchet public key (via signed prekey) and
    /// will initialize the Double Ratchet when receiving the first message.
    ///
    /// # Arguments
    /// * `conversation_id` - Unique ID derived from X3DH
    /// * `conversation_key` - Shared key derived from X3DH (becomes root key)
    /// * `our_identity_hash` - Our encryption identity hash
    /// * `peer_identity_hash` - Peer's encryption identity hash
    /// * `consumed_otp_id` - One-time prekey ID that was consumed
    /// * `our_ratchet_keypair` - Our signed prekey keypair (for receiving)
    pub fn new_responder(
        conversation_id: [u8; CONVERSATION_ID_SIZE],
        conversation_key: [u8; CONVERSATION_KEY_SIZE],
        our_identity_hash: ContentHash,
        peer_identity_hash: ContentHash,
        consumed_otp_id: Option<PreKeyId>,
        our_ratchet_keypair: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            conversation_id: ConversationId::from_bytes(conversation_id),
            peer_identity_hash,
            our_identity_hash,
            conversation_key,
            is_initiator: false,
            consumed_otp_id,
            created_at: now,
            last_activity: now,
            messages_sent: 0,
            messages_received: 0,
            double_ratchet: None,
            ratchet_initialized: false,
            peer_ratchet_public_key: None,
            our_ratchet_keypair_bytes: our_ratchet_keypair,
        }
    }

    /// Returns the conversation ID.
    pub fn conversation_id(&self) -> &ConversationId {
        &self.conversation_id
    }

    /// Returns the peer's encryption identity hash.
    pub fn peer_identity_hash(&self) -> &ContentHash {
        &self.peer_identity_hash
    }

    /// Returns our encryption identity hash.
    pub fn our_identity_hash(&self) -> &ContentHash {
        &self.our_identity_hash
    }

    /// Returns whether we initiated this conversation.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Returns the one-time prekey ID that was consumed.
    pub fn consumed_otp_id(&self) -> Option<PreKeyId> {
        self.consumed_otp_id
    }

    /// Returns the creation timestamp.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the last activity timestamp.
    pub fn last_activity(&self) -> u64 {
        self.last_activity
    }

    /// Returns the number of messages sent.
    pub fn messages_sent(&self) -> u64 {
        self.messages_sent
    }

    /// Returns the number of messages received.
    pub fn messages_received(&self) -> u64 {
        self.messages_received
    }

    /// Returns the base conversation key (from X3DH).
    ///
    /// Note: For proper forward secrecy, use `get_sending_key()` or `get_receiving_key()`
    /// which derive per-message keys via the Double Ratchet.
    pub fn conversation_key(&self) -> &[u8; CONVERSATION_KEY_SIZE] {
        &self.conversation_key
    }

    /// Records that a message was sent.
    pub fn record_sent(&mut self) {
        self.messages_sent += 1;
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
    }

    /// Records that a message was received.
    pub fn record_received(&mut self) {
        self.messages_received += 1;
        self.last_activity = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
    }

    /// Returns whether the ratchet has been initialized.
    pub fn is_ratchet_initialized(&self) -> bool {
        self.ratchet_initialized
    }

    /// Initializes the Double Ratchet as the initiator (sender of first message).
    ///
    /// The initiator uses the peer's signed prekey as the initial ratchet public key.
    /// The KEM ciphertext is stored internally and will be returned by `get_sending_key()`.
    ///
    /// # Arguments
    /// * `peer_ratchet_key` - Peer's signed prekey public key bytes
    pub fn initialize_ratchet_initiator(&mut self, peer_ratchet_key: &[u8]) -> Result<()> {
        if self.ratchet_initialized {
            return Err(PqpgpError::session("Ratchet already initialized"));
        }

        let their_key = RatchetPublicKey::from_bytes(peer_ratchet_key.to_vec())?;

        // Create associated data binding the conversation
        let ad = self.build_associated_data();

        // Initialize as initiator - the KEM ciphertext is stored in pending_kem_ciphertext
        // and will be retrieved by get_sending_key()
        let ratchet = DoubleRatchet::new_initiator(self.conversation_key, their_key, ad)?;

        self.double_ratchet = Some(ratchet);
        self.ratchet_initialized = true;
        self.peer_ratchet_public_key = Some(peer_ratchet_key.to_vec());

        Ok(())
    }

    /// Initializes the Double Ratchet as the responder (receiver of first message).
    ///
    /// The responder uses their signed prekey keypair for the initial ratchet.
    ///
    /// # Arguments
    /// * `our_ratchet_keypair` - Our signed prekey keypair (public, secret)
    pub fn initialize_ratchet_responder(
        &mut self,
        our_ratchet_keypair: (Vec<u8>, Vec<u8>),
    ) -> Result<()> {
        if self.ratchet_initialized {
            return Err(PqpgpError::session("Ratchet already initialized"));
        }

        let keypair = RatchetKeyPair::from_bytes(
            our_ratchet_keypair.0.clone(),
            our_ratchet_keypair.1.clone(),
        )?;

        // Create associated data binding the conversation
        let ad = self.build_associated_data();

        // Initialize as responder
        let ratchet = DoubleRatchet::new_responder(self.conversation_key, keypair, ad);

        self.double_ratchet = Some(ratchet);
        self.ratchet_initialized = true;
        self.our_ratchet_keypair_bytes = Some(our_ratchet_keypair);

        Ok(())
    }

    /// Gets a message key for sending (encrypting) a message.
    ///
    /// Returns (message_key, ratchet_public_key, message_number, previous_chain_length, kem_ciphertext)
    /// for inclusion in the message header.
    ///
    /// # Security
    /// Each call advances the ratchet and returns a unique message key.
    /// The key should be used once and then discarded.
    pub fn get_sending_key(&mut self) -> Result<RatchetSendInfo> {
        if !self.ratchet_initialized {
            return Err(PqpgpError::session(
                "Ratchet not initialized - call initialize_ratchet_initiator first",
            ));
        }

        let ratchet = self
            .double_ratchet
            .as_mut()
            .ok_or_else(|| PqpgpError::session("Double ratchet not present"))?;

        // Get the KEM ciphertext if available (for key rotation)
        let kem_ciphertext = ratchet.state_mut().generate_kem_ciphertext()?;

        // Advance the ratchet and get the message key
        let (message_key, ratchet_public_key, message_number, previous_chain_length) =
            ratchet.encrypt()?;

        Ok(RatchetSendInfo {
            message_key,
            ratchet_public_key,
            message_number,
            previous_chain_length,
            kem_ciphertext,
        })
    }

    /// Gets a message key for receiving (decrypting) a message.
    ///
    /// # Arguments
    /// * `their_ratchet_key` - Peer's ratchet public key from the message header
    /// * `message_number` - Message number from the header
    /// * `previous_chain_length` - Previous chain length from the header
    /// * `kem_ciphertext` - KEM ciphertext from the header (if present)
    ///
    /// # Security
    /// The ratchet handles out-of-order delivery by storing skipped message keys.
    pub fn get_receiving_key(
        &mut self,
        their_ratchet_key: &[u8],
        message_number: u32,
        previous_chain_length: u32,
        kem_ciphertext: Option<&[u8]>,
    ) -> Result<MessageKey> {
        // If ratchet not initialized, this is the first received message
        // Initialize as responder using the stored keypair
        if !self.ratchet_initialized {
            let keypair = self
                .our_ratchet_keypair_bytes
                .take()
                .ok_or_else(|| PqpgpError::session("No keypair for responder initialization"))?;
            self.initialize_ratchet_responder(keypair)?;

            // Now initialize with the sender's first message
            let their_key = RatchetPublicKey::from_bytes(their_ratchet_key.to_vec())?;
            let ct = kem_ciphertext
                .ok_or_else(|| PqpgpError::session("KEM ciphertext required for first message"))?;

            let ratchet = self
                .double_ratchet
                .as_mut()
                .ok_or_else(|| PqpgpError::session("Ratchet not initialized"))?;

            ratchet.initialize_responder(&their_key, ct)?;
            return ratchet.decrypt_first_message(message_number);
        }

        let ratchet = self
            .double_ratchet
            .as_mut()
            .ok_or_else(|| PqpgpError::session("Double ratchet not present"))?;

        let their_key = RatchetPublicKey::from_bytes(their_ratchet_key.to_vec())?;

        ratchet.decrypt(
            &their_key,
            message_number,
            previous_chain_length,
            kem_ciphertext,
        )
    }

    /// Builds associated data for AEAD binding.
    fn build_associated_data(&self) -> Vec<u8> {
        let mut ad = Vec::with_capacity(128);
        ad.extend_from_slice(self.conversation_id.as_bytes());
        ad.extend_from_slice(self.our_identity_hash.as_bytes());
        ad.extend_from_slice(self.peer_identity_hash.as_bytes());
        ad
    }

    /// Returns our current ratchet public key (if ratchet is initialized).
    pub fn our_ratchet_public_key(&self) -> Option<Vec<u8>> {
        self.double_ratchet
            .as_ref()
            .and_then(|r| r.our_ratchet_public_key())
            .map(|k| k.as_bytes().to_vec())
    }

    /// Returns the peer's ratchet public key (if known).
    pub fn peer_ratchet_public_key(&self) -> Option<&[u8]> {
        self.peer_ratchet_public_key.as_deref()
    }
}

/// Information returned when getting a sending key from the ratchet.
#[derive(Debug)]
pub struct RatchetSendInfo {
    /// The message key for encryption.
    pub message_key: MessageKey,
    /// Our current ratchet public key (for the header).
    pub ratchet_public_key: RatchetPublicKey,
    /// Message number in the current chain.
    pub message_number: u32,
    /// Previous chain length (for header).
    pub previous_chain_length: u32,
    /// KEM ciphertext to include (if key rotation occurred).
    pub kem_ciphertext: Option<Vec<u8>>,
}

/// A decrypted message stored in local conversation history.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    /// The inner message content.
    pub inner: InnerMessage,

    /// Hash of the sealed message node in the DAG.
    pub dag_hash: ContentHash,

    /// Whether this message was sent by us.
    pub is_outgoing: bool,

    /// Timestamp when we processed this message.
    pub processed_at: u64,
}

impl fmt::Debug for StoredMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredMessage")
            .field("message_id", &hex::encode(&self.inner.message_id[..8]))
            .field("is_outgoing", &self.is_outgoing)
            .field("processed_at", &self.processed_at)
            .finish_non_exhaustive()
    }
}

/// Summary info for a conversation (for inbox display).
#[derive(Debug)]
pub struct ConversationSummary<'a> {
    /// The conversation session.
    pub session: &'a ConversationSession,
    /// Last message body (if any).
    pub last_message: Option<&'a str>,
    /// Total message count.
    pub message_count: usize,
}

/// Manager for all conversation sessions.
///
/// This stores session state for all active conversations and provides
/// methods to look up sessions by various keys.
#[derive(Default, Serialize, Deserialize)]
pub struct ConversationManager {
    /// Sessions indexed by conversation ID.
    sessions: HashMap<[u8; CONVERSATION_ID_SIZE], ConversationSession>,

    /// Index from peer identity hash to conversation IDs.
    /// A peer may have multiple conversations (e.g., different forums).
    /// This is rebuilt on load from sessions.
    #[serde(skip)]
    peer_index: HashMap<ContentHash, Vec<[u8; CONVERSATION_ID_SIZE]>>,

    /// Message history indexed by conversation ID.
    message_history: HashMap<[u8; CONVERSATION_ID_SIZE], Vec<StoredMessage>>,
}

impl fmt::Debug for ConversationManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConversationManager")
            .field("session_count", &self.sessions.len())
            .field("peer_count", &self.peer_index.len())
            .finish()
    }
}

impl ConversationManager {
    /// Creates a new conversation manager.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            peer_index: HashMap::new(),
            message_history: HashMap::new(),
        }
    }

    /// Adds a new conversation session.
    ///
    /// Returns an error if a session with the same ID already exists.
    pub fn add_session(&mut self, session: ConversationSession) -> Result<()> {
        let conv_id = *session.conversation_id().as_bytes();

        if self.sessions.contains_key(&conv_id) {
            return Err(PqpgpError::session("Conversation session already exists"));
        }

        // Add to peer index
        let peer_hash = *session.peer_identity_hash();
        self.peer_index.entry(peer_hash).or_default().push(conv_id);

        self.sessions.insert(conv_id, session);
        Ok(())
    }

    /// Gets a session by conversation ID.
    pub fn get_session(
        &self,
        conversation_id: &[u8; CONVERSATION_ID_SIZE],
    ) -> Option<&ConversationSession> {
        self.sessions.get(conversation_id)
    }

    /// Gets a mutable session by conversation ID.
    pub fn get_session_mut(
        &mut self,
        conversation_id: &[u8; CONVERSATION_ID_SIZE],
    ) -> Option<&mut ConversationSession> {
        self.sessions.get_mut(conversation_id)
    }

    /// Gets all conversations with a specific peer.
    pub fn get_sessions_with_peer(
        &self,
        peer_identity_hash: &ContentHash,
    ) -> Vec<&ConversationSession> {
        self.peer_index
            .get(peer_identity_hash)
            .map(|ids| ids.iter().filter_map(|id| self.sessions.get(id)).collect())
            .unwrap_or_default()
    }

    /// Returns all conversation sessions.
    pub fn all_sessions(&self) -> impl Iterator<Item = &ConversationSession> {
        self.sessions.values()
    }

    /// Returns conversations with cursor-based pagination.
    ///
    /// Conversations are sorted by last activity (newest first).
    /// Returns session summaries including last message preview and message count.
    ///
    /// # Arguments
    /// * `cursor` - Optional cursor (last_activity timestamp, conversation_id) to start after
    /// * `limit` - Maximum number of conversations to return
    ///
    /// # Returns
    /// A tuple of (summaries, next_cursor) where next_cursor is Some if there are more.
    pub fn all_sessions_paginated(
        &self,
        cursor: Option<(u64, [u8; CONVERSATION_ID_SIZE])>,
        limit: usize,
    ) -> (
        Vec<ConversationSummary<'_>>,
        Option<(u64, [u8; CONVERSATION_ID_SIZE])>,
    ) {
        // Collect and sort by last_activity descending
        let mut sessions: Vec<_> = self.sessions.values().collect();
        sessions.sort_by(|a, b| {
            b.last_activity().cmp(&a.last_activity()).then_with(|| {
                b.conversation_id()
                    .as_bytes()
                    .cmp(a.conversation_id().as_bytes())
            })
        });

        // Apply cursor filter
        let filtered: Vec<_> = if let Some((cursor_ts, cursor_id)) = cursor {
            sessions
                .into_iter()
                .skip_while(|s| {
                    s.last_activity() > cursor_ts
                        || (s.last_activity() == cursor_ts
                            && s.conversation_id().as_bytes() >= &cursor_id)
                })
                .collect()
        } else {
            sessions
        };

        // Take limit + 1 to check if there are more
        let has_more = filtered.len() > limit;
        let page: Vec<_> = filtered.into_iter().take(limit).collect();

        // Create next cursor from the last item
        let next_cursor = if has_more && !page.is_empty() {
            let last = page.last().unwrap();
            Some((last.last_activity(), *last.conversation_id().as_bytes()))
        } else {
            None
        };

        // Build summaries with message info in single pass
        let summaries: Vec<_> = page
            .into_iter()
            .map(|session| {
                let conv_id = session.conversation_id().as_bytes();
                let messages = self.message_history.get(conv_id);
                ConversationSummary {
                    session,
                    last_message: messages
                        .and_then(|m| m.last())
                        .map(|m| m.inner.body.as_str()),
                    message_count: messages.map(|m| m.len()).unwrap_or(0),
                }
            })
            .collect();

        (summaries, next_cursor)
    }

    /// Returns the total number of conversations.
    pub fn total_conversations(&self) -> usize {
        self.sessions.len()
    }

    /// Returns the number of sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Removes a session by conversation ID.
    pub fn remove_session(
        &mut self,
        conversation_id: &[u8; CONVERSATION_ID_SIZE],
    ) -> Option<ConversationSession> {
        if let Some(session) = self.sessions.remove(conversation_id) {
            // Remove from peer index
            if let Some(ids) = self.peer_index.get_mut(session.peer_identity_hash()) {
                ids.retain(|id| id != conversation_id);
                if ids.is_empty() {
                    self.peer_index.remove(session.peer_identity_hash());
                }
            }
            // Remove message history
            self.message_history.remove(conversation_id);
            Some(session)
        } else {
            None
        }
    }

    /// Stores a message in the conversation history.
    pub fn store_message(
        &mut self,
        conversation_id: &[u8; CONVERSATION_ID_SIZE],
        message: StoredMessage,
    ) -> Result<()> {
        let history = self.message_history.entry(*conversation_id).or_default();

        if history.len() >= MAX_MESSAGES_PER_CONVERSATION {
            // Remove oldest messages to make room
            let to_remove = history.len() - MAX_MESSAGES_PER_CONVERSATION + 1;
            history.drain(0..to_remove);
        }

        history.push(message);
        Ok(())
    }

    /// Gets the message history for a conversation.
    pub fn get_messages(
        &self,
        conversation_id: &[u8; CONVERSATION_ID_SIZE],
    ) -> Option<&[StoredMessage]> {
        self.message_history
            .get(conversation_id)
            .map(|v| v.as_slice())
    }

    /// Gets messages with cursor-based pagination.
    ///
    /// Messages are sorted by timestamp (oldest first for chronological reading).
    ///
    /// # Arguments
    /// * `conversation_id` - The conversation to get messages from
    /// * `cursor` - Optional cursor (timestamp, message_id) to start after
    /// * `limit` - Maximum number of messages to return
    ///
    /// # Returns
    /// A tuple of (messages, total_count, next_cursor) where next_cursor is Some if there are more.
    pub fn get_messages_paginated(
        &self,
        conversation_id: &[u8; CONVERSATION_ID_SIZE],
        cursor: Option<MessageCursor>,
        limit: usize,
    ) -> PaginatedMessagesResult<'_> {
        let Some(history) = self.message_history.get(conversation_id) else {
            return (Vec::new(), 0, None);
        };

        let total_count = history.len();

        // Messages are already stored in chronological order (oldest first)
        // Apply cursor filter
        let start_idx = if let Some((cursor_ts, cursor_msg_id)) = cursor {
            history
                .iter()
                .position(|m| {
                    m.inner.timestamp > cursor_ts
                        || (m.inner.timestamp == cursor_ts && m.inner.message_id > cursor_msg_id)
                })
                .unwrap_or(history.len())
        } else {
            0
        };

        // Take limit + 1 to check if there are more
        let end_idx = (start_idx + limit + 1).min(history.len());
        let slice = &history[start_idx..end_idx];

        let has_more = slice.len() > limit;
        let page: Vec<_> = slice.iter().take(limit).collect();

        // Create next cursor from the last item
        let next_cursor = if has_more && !page.is_empty() {
            let last = page.last().unwrap();
            Some((last.inner.timestamp, last.inner.message_id))
        } else {
            None
        };

        (page, total_count, next_cursor)
    }

    /// Gets the total message count for a conversation.
    pub fn get_message_count(&self, conversation_id: &[u8; CONVERSATION_ID_SIZE]) -> usize {
        self.message_history
            .get(conversation_id)
            .map(|h| h.len())
            .unwrap_or(0)
    }

    /// Finds a message by its message ID within a conversation.
    pub fn find_message(
        &self,
        conversation_id: &[u8; CONVERSATION_ID_SIZE],
        message_id: &[u8; 16],
    ) -> Option<&StoredMessage> {
        self.message_history
            .get(conversation_id)?
            .iter()
            .find(|m| &m.inner.message_id == message_id)
    }

    /// Checks if a one-time prekey has been consumed in any session.
    ///
    /// This is used to prevent replay attacks.
    pub fn is_otp_consumed(&self, otp_id: PreKeyId) -> bool {
        self.sessions
            .values()
            .any(|s| s.consumed_otp_id() == Some(otp_id))
    }

    /// Rebuilds the peer index after deserialization.
    pub fn rebuild_indexes(&mut self) {
        self.peer_index.clear();
        for (conv_id, session) in &self.sessions {
            self.peer_index
                .entry(*session.peer_identity_hash())
                .or_default()
                .push(*conv_id);
        }
    }

    /// Expires (deletes) messages older than the specified age.
    ///
    /// # Arguments
    /// * `max_age_ms` - Maximum message age in milliseconds
    ///
    /// # Returns
    /// Number of messages deleted.
    ///
    /// # Security
    /// This helps limit data exposure from compromised storage and reduces
    /// storage growth over time.
    pub fn expire_old_messages(&mut self, max_age_ms: u64) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let cutoff = now.saturating_sub(max_age_ms);
        let mut deleted = 0;

        for history in self.message_history.values_mut() {
            let before = history.len();
            history.retain(|msg| msg.inner.timestamp >= cutoff);
            deleted += before - history.len();
        }

        deleted
    }

    /// Expires messages older than the specified number of days.
    ///
    /// Convenience wrapper around `expire_old_messages`.
    pub fn expire_messages_older_than_days(&mut self, days: u32) -> usize {
        let max_age_ms = u64::from(days) * 24 * 60 * 60 * 1000;
        self.expire_old_messages(max_age_ms)
    }

    /// Removes conversations with no messages and no activity for the specified duration.
    ///
    /// # Arguments
    /// * `max_inactive_ms` - Maximum inactivity time in milliseconds
    ///
    /// # Returns
    /// Number of conversations removed.
    pub fn cleanup_inactive_conversations(&mut self, max_inactive_ms: u64) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let cutoff = now.saturating_sub(max_inactive_ms);

        // Find conversations to remove
        let to_remove: Vec<[u8; CONVERSATION_ID_SIZE]> = self
            .sessions
            .iter()
            .filter(|(conv_id, session)| {
                // Check if inactive
                session.last_activity() < cutoff
                    // AND has no messages
                    && self
                        .message_history
                        .get(*conv_id)
                        .map(|h| h.is_empty())
                        .unwrap_or(true)
            })
            .map(|(conv_id, _)| *conv_id)
            .collect();

        // Remove them
        let count = to_remove.len();
        for conv_id in to_remove {
            self.remove_session(&conv_id);
        }

        count
    }

    /// Gets the total message count across all conversations.
    pub fn total_message_count(&self) -> usize {
        self.message_history.values().map(|h| h.len()).sum()
    }

    /// Gets storage statistics for monitoring.
    pub fn storage_stats(&self) -> ConversationStats {
        let mut oldest_message: Option<u64> = None;
        let mut newest_message: Option<u64> = None;

        for history in self.message_history.values() {
            for msg in history {
                let ts = msg.inner.timestamp;
                oldest_message = Some(oldest_message.map(|o| o.min(ts)).unwrap_or(ts));
                newest_message = Some(newest_message.map(|n| n.max(ts)).unwrap_or(ts));
            }
        }

        ConversationStats {
            session_count: self.sessions.len(),
            total_messages: self.total_message_count(),
            oldest_message_timestamp: oldest_message,
            newest_message_timestamp: newest_message,
        }
    }
}

/// Statistics about conversation storage.
#[derive(Debug, Clone)]
pub struct ConversationStats {
    /// Number of active conversation sessions.
    pub session_count: usize,
    /// Total number of stored messages.
    pub total_messages: usize,
    /// Timestamp of oldest message (milliseconds since epoch).
    pub oldest_message_timestamp: Option<u64>,
    /// Timestamp of newest message (milliseconds since epoch).
    pub newest_message_timestamp: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_hash(seed: u8) -> ContentHash {
        ContentHash::from_bytes([seed; 64])
    }

    fn create_test_conversation_id(seed: u8) -> [u8; CONVERSATION_ID_SIZE] {
        [seed; CONVERSATION_ID_SIZE]
    }

    fn create_test_key(seed: u8) -> [u8; CONVERSATION_KEY_SIZE] {
        [seed; CONVERSATION_KEY_SIZE]
    }

    #[test]
    fn test_conversation_id_display() {
        let id = ConversationId::from_bytes([0xab; 32]);
        assert!(id.short().starts_with("abab"));
        assert_eq!(format!("{}", id), id.short());
    }

    #[test]
    fn test_session_creation_initiator() {
        let session = ConversationSession::new_initiator(
            create_test_conversation_id(1),
            create_test_key(2),
            create_test_hash(3),
            create_test_hash(4),
            Some(42),
            None, // peer_ratchet_public_key
        );

        assert!(session.is_initiator());
        assert_eq!(session.consumed_otp_id(), Some(42));
        assert_eq!(session.messages_sent(), 0);
        assert_eq!(session.messages_received(), 0);
        assert!(!session.is_ratchet_initialized());
    }

    #[test]
    fn test_session_creation_responder() {
        let session = ConversationSession::new_responder(
            create_test_conversation_id(1),
            create_test_key(2),
            create_test_hash(3),
            create_test_hash(4),
            None,
            None, // our_ratchet_keypair
        );

        assert!(!session.is_initiator());
        assert_eq!(session.consumed_otp_id(), None);
    }

    #[test]
    fn test_session_record_activity() {
        let mut session = ConversationSession::new_initiator(
            create_test_conversation_id(1),
            create_test_key(2),
            create_test_hash(3),
            create_test_hash(4),
            None,
            None, // peer_ratchet_public_key
        );

        let initial_activity = session.last_activity();

        session.record_sent();
        assert_eq!(session.messages_sent(), 1);
        assert!(session.last_activity() >= initial_activity);

        session.record_received();
        assert_eq!(session.messages_received(), 1);
    }

    #[test]
    fn test_conversation_manager_add_get() {
        let mut manager = ConversationManager::new();

        let session = ConversationSession::new_initiator(
            create_test_conversation_id(1),
            create_test_key(2),
            create_test_hash(3),
            create_test_hash(4),
            None,
            None, // peer_ratchet_public_key
        );

        let conv_id = *session.conversation_id().as_bytes();
        manager.add_session(session).expect("Should add session");

        assert_eq!(manager.session_count(), 1);
        assert!(manager.get_session(&conv_id).is_some());
    }

    #[test]
    fn test_conversation_manager_duplicate_rejected() {
        let mut manager = ConversationManager::new();

        let session1 = ConversationSession::new_initiator(
            create_test_conversation_id(1),
            create_test_key(2),
            create_test_hash(3),
            create_test_hash(4),
            None,
            None, // peer_ratchet_public_key
        );

        let session2 = ConversationSession::new_initiator(
            create_test_conversation_id(1), // Same ID
            create_test_key(5),
            create_test_hash(6),
            create_test_hash(7),
            None,
            None, // peer_ratchet_public_key
        );

        manager
            .add_session(session1)
            .expect("Should add first session");
        assert!(manager.add_session(session2).is_err());
    }

    #[test]
    fn test_conversation_manager_peer_index() {
        let mut manager = ConversationManager::new();

        let peer_hash = create_test_hash(10);

        let session1 = ConversationSession::new_initiator(
            create_test_conversation_id(1),
            create_test_key(2),
            create_test_hash(3),
            peer_hash,
            None,
            None, // peer_ratchet_public_key
        );

        let session2 = ConversationSession::new_initiator(
            create_test_conversation_id(2),
            create_test_key(5),
            create_test_hash(6),
            peer_hash, // Same peer
            None,
            None, // peer_ratchet_public_key
        );

        manager.add_session(session1).unwrap();
        manager.add_session(session2).unwrap();

        let peer_sessions = manager.get_sessions_with_peer(&peer_hash);
        assert_eq!(peer_sessions.len(), 2);
    }

    #[test]
    fn test_conversation_manager_remove_session() {
        let mut manager = ConversationManager::new();

        let session = ConversationSession::new_initiator(
            create_test_conversation_id(1),
            create_test_key(2),
            create_test_hash(3),
            create_test_hash(4),
            None,
            None, // peer_ratchet_public_key
        );

        let conv_id = *session.conversation_id().as_bytes();
        let peer_hash = *session.peer_identity_hash();

        manager.add_session(session).unwrap();
        assert_eq!(manager.session_count(), 1);

        let removed = manager.remove_session(&conv_id);
        assert!(removed.is_some());
        assert_eq!(manager.session_count(), 0);
        assert!(manager.get_sessions_with_peer(&peer_hash).is_empty());
    }

    #[test]
    fn test_message_storage() {
        let mut manager = ConversationManager::new();

        let session = ConversationSession::new_initiator(
            create_test_conversation_id(1),
            create_test_key(2),
            create_test_hash(3),
            create_test_hash(4),
            None,
            None, // peer_ratchet_public_key
        );

        let conv_id = *session.conversation_id().as_bytes();
        manager.add_session(session).unwrap();

        let message = StoredMessage {
            inner: InnerMessage::new([1u8; 32], "Test message".to_string()),
            dag_hash: create_test_hash(5),
            is_outgoing: true,
            processed_at: 12345,
        };

        manager.store_message(&conv_id, message).unwrap();

        let messages = manager.get_messages(&conv_id).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].inner.body, "Test message");
    }

    #[test]
    fn test_find_message() {
        let mut manager = ConversationManager::new();

        let session = ConversationSession::new_initiator(
            create_test_conversation_id(1),
            create_test_key(2),
            create_test_hash(3),
            create_test_hash(4),
            None,
            None, // peer_ratchet_public_key
        );

        let conv_id = *session.conversation_id().as_bytes();
        manager.add_session(session).unwrap();

        // Create the inner message (message_id is generated randomly)
        let inner = InnerMessage::new([42u8; 32], "Findable message".to_string());
        let msg_id = inner.message_id; // Capture the generated message_id

        let message = StoredMessage {
            inner,
            dag_hash: create_test_hash(5),
            is_outgoing: false,
            processed_at: 12345,
        };

        manager.store_message(&conv_id, message).unwrap();

        let found = manager.find_message(&conv_id, &msg_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().inner.body, "Findable message");

        let not_found = manager.find_message(&conv_id, &[99u8; 16]);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_otp_consumed_tracking() {
        let mut manager = ConversationManager::new();

        let session = ConversationSession::new_initiator(
            create_test_conversation_id(1),
            create_test_key(2),
            create_test_hash(3),
            create_test_hash(4),
            Some(42),
            None, // peer_ratchet_public_key
        );

        manager.add_session(session).unwrap();

        assert!(manager.is_otp_consumed(42));
        assert!(!manager.is_otp_consumed(99));
    }

    #[test]
    fn test_session_serialization() {
        let session = ConversationSession::new_initiator(
            create_test_conversation_id(1),
            create_test_key(2),
            create_test_hash(3),
            create_test_hash(4),
            Some(42),
            None, // peer_ratchet_public_key
        );

        let serialized = bincode::serialize(&session).expect("Should serialize");
        let deserialized: ConversationSession =
            bincode::deserialize(&serialized).expect("Should deserialize");

        assert_eq!(
            session.conversation_id().as_bytes(),
            deserialized.conversation_id().as_bytes()
        );
        assert_eq!(session.is_initiator(), deserialized.is_initiator());
        assert_eq!(session.consumed_otp_id(), deserialized.consumed_otp_id());
    }

    #[test]
    fn test_manager_rebuild_indexes() {
        let mut manager = ConversationManager::new();

        let peer_hash = create_test_hash(10);

        let session = ConversationSession::new_initiator(
            create_test_conversation_id(1),
            create_test_key(2),
            create_test_hash(3),
            peer_hash,
            None,
            None, // peer_ratchet_public_key
        );

        manager.add_session(session).unwrap();

        // Clear and rebuild
        manager.peer_index.clear();
        assert!(manager.get_sessions_with_peer(&peer_hash).is_empty());

        manager.rebuild_indexes();
        assert_eq!(manager.get_sessions_with_peer(&peer_hash).len(), 1);
    }
}
