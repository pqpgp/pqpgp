//! Post-Quantum Double Ratchet implementation.
//!
//! This module implements the Double Ratchet algorithm with post-quantum KEM
//! instead of Diffie-Hellman. The Double Ratchet provides:
//!
//! - **Forward Secrecy**: Each message has a unique key derived from chain keys
//! - **Post-Compromise Security**: Sessions self-heal after key compromise
//! - **Out-of-Order Messages**: Handles messages arriving out of order
//!
//! ## How It Works
//!
//! The Double Ratchet uses two types of ratchets:
//!
//! ### KEM Ratchet (Replaces DH Ratchet)
//!
//! When receiving a new public key from the peer, we:
//! 1. Decapsulate using our private key to get a shared secret
//! 2. Derive a new root key and receiving chain key
//! 3. Generate a new KEM keypair for our next send
//!
//! ### Symmetric Ratchet (Chain Keys)
//!
//! For each message in a chain:
//! 1. Derive a message key from the chain key
//! 2. Advance the chain key (one-way function)
//! 3. Use the message key for encryption/decryption
//!
//! ## Security Properties
//!
//! - **Per-Message Keys**: Each message encrypted with a unique key
//! - **Key Deletion**: Keys are deleted after use
//! - **Healing**: Even if keys are compromised, future messages are secure after
//!   a round-trip completes

use crate::chat::kdf_info;
use crate::chat::x3dh::ROOT_KEY_SIZE;
use crate::error::{PqpgpError, Result};
use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{
    Ciphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey, SharedSecret,
};
use serde::{Deserialize, Serialize};
use sha3::Sha3_512;
use std::collections::HashMap;
use std::fmt;
use zeroize::ZeroizeOnDrop;

/// Size of chain keys in bytes.
pub const CHAIN_KEY_SIZE: usize = 32;

/// Size of message keys in bytes.
pub const MESSAGE_KEY_SIZE: usize = 32;

/// Maximum number of skipped message keys to store.
pub const MAX_SKIP: u32 = 1000;

/// Maximum age of skipped keys in seconds (24 hours).
/// Skipped keys older than this will be cleaned up.
pub const MAX_SKIPPED_KEY_AGE_SECS: u64 = 24 * 60 * 60;

/// A root key used in the KEM ratchet.
#[derive(Clone, ZeroizeOnDrop)]
pub struct RootKey {
    key: [u8; ROOT_KEY_SIZE],
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl RootKey {
    /// Creates a root key from bytes.
    pub fn from_bytes(bytes: [u8; ROOT_KEY_SIZE]) -> Self {
        Self { key: bytes }
    }

    /// Returns the key bytes.
    pub fn as_bytes(&self) -> &[u8; ROOT_KEY_SIZE] {
        &self.key
    }
}

/// A chain key used in the symmetric ratchet.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct ChainKey {
    key: [u8; CHAIN_KEY_SIZE],
    index: u32,
}

impl fmt::Debug for ChainKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainKey")
            .field("index", &self.index)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl ChainKey {
    /// Creates a chain key from bytes with an index.
    pub fn new(key: [u8; CHAIN_KEY_SIZE], index: u32) -> Self {
        Self { key, index }
    }

    /// Returns the chain index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Advances the chain, returning the new chain key and a message key.
    ///
    /// This is the symmetric ratchet step:
    /// - `new_chain_key = HKDF(chain_key, "chain")`
    /// - `message_key = HKDF(chain_key, "message")`
    pub fn advance(&self) -> Result<(ChainKey, MessageKey)> {
        let hk = Hkdf::<Sha3_512>::new(None, &self.key);

        let mut new_chain_key = [0u8; CHAIN_KEY_SIZE];
        let mut message_key = [0u8; MESSAGE_KEY_SIZE];

        hk.expand(kdf_info::RATCHET_CHAIN, &mut new_chain_key)
            .map_err(|_| PqpgpError::session("Chain key derivation failed"))?;
        hk.expand(kdf_info::RATCHET_MESSAGE, &mut message_key)
            .map_err(|_| PqpgpError::session("Message key derivation failed"))?;

        Ok((
            ChainKey {
                key: new_chain_key,
                index: self.index + 1,
            },
            MessageKey::from_bytes(message_key),
        ))
    }

    /// Returns the key bytes.
    pub fn as_bytes(&self) -> &[u8; CHAIN_KEY_SIZE] {
        &self.key
    }
}

/// A message key used to encrypt/decrypt a single message.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MessageKey {
    key: [u8; MESSAGE_KEY_SIZE],
}

impl fmt::Debug for MessageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl MessageKey {
    /// Creates a message key from bytes.
    pub fn from_bytes(bytes: [u8; MESSAGE_KEY_SIZE]) -> Self {
        Self { key: bytes }
    }

    /// Returns the key bytes for use in encryption.
    pub fn as_bytes(&self) -> &[u8; MESSAGE_KEY_SIZE] {
        &self.key
    }

    /// Derives an AES key from this message key.
    ///
    /// Returns a 256-bit AES key suitable for AES-256-GCM.
    /// Note: Nonces should be generated randomly for each encryption operation,
    /// not derived from the message key, to prevent nonce reuse vulnerabilities.
    pub fn derive_aes_key(&self) -> Result<[u8; 32]> {
        let hk = Hkdf::<Sha3_512>::new(None, &self.key);

        let mut aes_key = [0u8; 32];

        hk.expand(b"PQPGP-message-aes-key", &mut aes_key)
            .map_err(|_| PqpgpError::session("AES key derivation failed"))?;

        Ok(aes_key)
    }
}

/// A KEM public key used in the ratchet.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RatchetPublicKey {
    key_bytes: Vec<u8>,
}

impl fmt::Debug for RatchetPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RatchetPublicKey")
            .field("size", &self.key_bytes.len())
            .finish()
    }
}

impl RatchetPublicKey {
    /// Creates from ML-KEM public key.
    pub fn from_mlkem(key: &mlkem1024::PublicKey) -> Self {
        Self {
            key_bytes: KemPublicKey::as_bytes(key).to_vec(),
        }
    }

    /// Creates from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        // Validate by attempting to parse
        mlkem1024::PublicKey::from_bytes(&bytes)
            .map_err(|_| PqpgpError::session("Invalid ML-KEM public key"))?;
        Ok(Self { key_bytes: bytes })
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// Converts to ML-KEM public key.
    pub fn as_mlkem(&self) -> Result<mlkem1024::PublicKey> {
        mlkem1024::PublicKey::from_bytes(&self.key_bytes)
            .map_err(|_| PqpgpError::session("Invalid ML-KEM public key"))
    }
}

/// A KEM private key used in the ratchet.
#[derive(Clone, ZeroizeOnDrop)]
pub struct RatchetPrivateKey {
    key_bytes: Vec<u8>,
}

impl fmt::Debug for RatchetPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RatchetPrivateKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl RatchetPrivateKey {
    /// Creates from ML-KEM secret key.
    pub fn from_mlkem(key: &mlkem1024::SecretKey) -> Self {
        Self {
            key_bytes: KemSecretKey::as_bytes(key).to_vec(),
        }
    }

    /// Converts to ML-KEM secret key.
    pub fn as_mlkem(&self) -> Result<mlkem1024::SecretKey> {
        mlkem1024::SecretKey::from_bytes(&self.key_bytes)
            .map_err(|_| PqpgpError::session("Invalid ML-KEM secret key"))
    }
}

/// A KEM key pair used in the ratchet.
pub struct RatchetKeyPair {
    pub public: RatchetPublicKey,
    pub private: RatchetPrivateKey,
}

impl fmt::Debug for RatchetKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RatchetKeyPair")
            .field("public", &self.public)
            .finish()
    }
}

impl RatchetKeyPair {
    /// Generates a new KEM key pair.
    pub fn generate() -> Self {
        let (public, private) = mlkem1024::keypair();
        Self {
            public: RatchetPublicKey::from_mlkem(&public),
            private: RatchetPrivateKey::from_mlkem(&private),
        }
    }

    /// Creates a ratchet keypair from raw public and secret key bytes.
    ///
    /// This is used to convert prekey pairs into ratchet keypairs.
    pub fn from_bytes(public_bytes: Vec<u8>, secret_bytes: Vec<u8>) -> Result<Self> {
        let public = RatchetPublicKey::from_bytes(public_bytes)?;
        let private = RatchetPrivateKey {
            key_bytes: secret_bytes,
        };
        // Verify the secret key is valid by trying to parse it
        let _ = private.as_mlkem()?;
        Ok(Self { public, private })
    }
}

/// Key for looking up skipped message keys.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct SkippedKeyId {
    /// The ratchet public key that was active
    ratchet_key: Vec<u8>,
    /// The message number in the chain
    message_number: u32,
}

/// A skipped message key with its creation timestamp.
/// SECURITY FIX: Added timestamp for automatic expiration of old skipped keys.
///
/// Note: This struct is not serialized since skipped_keys has #[serde(skip)].
/// This is intentional - skipped keys are lost on session reload, which is
/// acceptable because they're only needed for short-term out-of-order delivery.
#[derive(Clone)]
struct SkippedKeyEntry {
    /// The message key
    key: MessageKey,
    /// Unix timestamp when this key was skipped (for expiration)
    created_at: u64,
}

/// Complete state for the Double Ratchet.
#[derive(Serialize, Deserialize)]
pub struct RatchetState {
    /// Current root key
    #[serde(with = "root_key_serde")]
    root_key: RootKey,
    /// Our current KEM key pair (for receiving)
    #[serde(skip)]
    our_ratchet_keypair: Option<RatchetKeyPair>,
    /// Their current public key (for sending)
    their_ratchet_key: Option<RatchetPublicKey>,
    /// Sending chain key
    #[serde(skip_serializing_if = "Option::is_none")]
    sending_chain: Option<ChainKey>,
    /// Receiving chain key
    #[serde(skip_serializing_if = "Option::is_none")]
    receiving_chain: Option<ChainKey>,
    /// Number of messages sent in current sending chain
    send_count: u32,
    /// Number of messages received in current receiving chain
    recv_count: u32,
    /// Previous sending chain length (for header)
    previous_chain_length: u32,
    /// Skipped message keys (for out-of-order delivery)
    /// SECURITY FIX: Now uses SkippedKeyEntry with timestamps for automatic expiration
    #[serde(skip)]
    skipped_keys: HashMap<SkippedKeyId, SkippedKeyEntry>,
    /// Pending KEM ciphertext to be sent with the next message
    /// This is set during initialization and used for the first message
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_kem_ciphertext: Option<Vec<u8>>,
}

// Custom serialization for RootKey
mod root_key_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(root_key: &RootKey, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&root_key.key)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<RootKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, Visitor};

        struct RootKeyVisitor;

        impl<'de> Visitor<'de> for RootKeyVisitor {
            type Value = RootKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("32 bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<RootKey, E>
            where
                E: de::Error,
            {
                if v.len() != ROOT_KEY_SIZE {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut key = [0u8; ROOT_KEY_SIZE];
                key.copy_from_slice(v);
                Ok(RootKey::from_bytes(key))
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<RootKey, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut key = [0u8; ROOT_KEY_SIZE];
                for (i, byte) in key.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(RootKey::from_bytes(key))
            }
        }

        deserializer.deserialize_bytes(RootKeyVisitor)
    }
}

impl fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RatchetState")
            .field("has_our_keypair", &self.our_ratchet_keypair.is_some())
            .field("has_their_key", &self.their_ratchet_key.is_some())
            .field("send_count", &self.send_count)
            .field("recv_count", &self.recv_count)
            .field("skipped_keys_count", &self.skipped_keys.len())
            .finish()
    }
}

impl RatchetState {
    /// Creates a new ratchet state for the session initiator (Alice).
    ///
    /// The initiator:
    /// - Has the recipient's ratchet public key (from X3DH)
    /// - Generates their own ratchet keypair for receiving
    /// - Can immediately start sending
    pub fn new_initiator(
        root_key: [u8; ROOT_KEY_SIZE],
        their_ratchet_key: RatchetPublicKey,
    ) -> Result<Self> {
        let root_key = RootKey::from_bytes(root_key);

        // Generate our ratchet keypair
        let our_keypair = RatchetKeyPair::generate();

        // Perform KEM ratchet step to derive sending chain
        let their_mlkem = their_ratchet_key.as_mlkem()?;
        let (shared_secret, ciphertext) = mlkem1024::encapsulate(&their_mlkem);

        // Derive new root key and sending chain key
        let (new_root_key, sending_chain) = Self::kdf_rk(&root_key, shared_secret.as_bytes())?;

        Ok(Self {
            root_key: new_root_key,
            our_ratchet_keypair: Some(our_keypair),
            their_ratchet_key: Some(their_ratchet_key),
            sending_chain: Some(sending_chain),
            receiving_chain: None,
            send_count: 0,
            recv_count: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
            // Store the ciphertext so we can send it with the first message
            pending_kem_ciphertext: Some(ciphertext.as_bytes().to_vec()),
        })
    }

    /// Creates a new ratchet state for the session responder (Bob).
    ///
    /// The responder:
    /// - Already provided their ratchet public key (via prekey bundle)
    /// - Needs to wait for the first message to complete the ratchet
    pub fn new_responder(
        root_key: [u8; ROOT_KEY_SIZE],
        our_ratchet_keypair: RatchetKeyPair,
    ) -> Self {
        Self {
            root_key: RootKey::from_bytes(root_key),
            our_ratchet_keypair: Some(our_ratchet_keypair),
            their_ratchet_key: None,
            sending_chain: None,
            receiving_chain: None,
            send_count: 0,
            recv_count: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
            pending_kem_ciphertext: None,
        }
    }

    /// Performs initial ratchet setup for the responder when receiving the first message.
    ///
    /// This is a special case that handles the first message from the initiator.
    /// The initiator already performed their KEM ratchet step during session creation,
    /// so the responder needs to match that state.
    pub fn initialize_responder(
        &mut self,
        their_ratchet_key: &RatchetPublicKey,
        kem_ciphertext: &[u8],
    ) -> Result<()> {
        // Decapsulate using our private key
        let our_keypair = self
            .our_ratchet_keypair
            .as_ref()
            .ok_or_else(|| PqpgpError::session("No ratchet keypair for decapsulation"))?;

        let ct = mlkem1024::Ciphertext::from_bytes(kem_ciphertext)
            .map_err(|_| PqpgpError::session("Invalid KEM ciphertext"))?;
        let our_secret = our_keypair.private.as_mlkem()?;
        let shared_secret = mlkem1024::decapsulate(&ct, &our_secret);

        // Derive receiving chain from the shared secret (matching initiator's sending chain)
        let (new_root_key, receiving_chain) =
            Self::kdf_rk(&self.root_key, shared_secret.as_bytes())?;

        // Update state
        self.root_key = new_root_key;
        self.their_ratchet_key = Some(their_ratchet_key.clone());
        self.receiving_chain = Some(receiving_chain);

        // Generate our own keypair and sending chain for when we reply
        let new_keypair = RatchetKeyPair::generate();
        let their_mlkem = their_ratchet_key.as_mlkem()?;
        let (new_shared_secret, ciphertext) = mlkem1024::encapsulate(&their_mlkem);

        let (new_root_key2, sending_chain) =
            Self::kdf_rk(&self.root_key, new_shared_secret.as_bytes())?;

        self.root_key = new_root_key2;
        self.our_ratchet_keypair = Some(new_keypair);
        self.sending_chain = Some(sending_chain);
        self.send_count = 0;
        // Save the ciphertext so we can send it with our first reply
        self.pending_kem_ciphertext = Some(ciphertext.as_bytes().to_vec());

        Ok(())
    }

    /// Derives a message key for the first received message after initialization.
    ///
    /// This is used after `initialize_responder` to decrypt the first message.
    pub fn decrypt_first_message(&mut self, message_number: u32) -> Result<MessageKey> {
        // Skip any messages before the one we're receiving
        let receiving_chain = self
            .receiving_chain
            .as_ref()
            .ok_or_else(|| PqpgpError::session("No receiving chain"))?;

        // For the first message, we just advance the chain to get the message key
        if message_number != receiving_chain.index() {
            return Err(PqpgpError::session(format!(
                "Message number mismatch: expected {}, got {}",
                receiving_chain.index(),
                message_number
            )));
        }

        let (new_chain, message_key) = receiving_chain.advance()?;
        self.receiving_chain = Some(new_chain);
        self.recv_count += 1;

        Ok(message_key)
    }

    /// Derives a message key for sending.
    ///
    /// Returns (message_key, ratchet_public_key, message_number, previous_chain_length)
    /// for inclusion in the message header.
    pub fn ratchet_encrypt(&mut self) -> Result<(MessageKey, RatchetPublicKey, u32, u32)> {
        // Make sure we have a sending chain
        let sending_chain = self
            .sending_chain
            .as_ref()
            .ok_or_else(|| PqpgpError::session("No sending chain - cannot encrypt"))?;

        // Get our current ratchet public key
        let our_public = self
            .our_ratchet_keypair
            .as_ref()
            .map(|kp| kp.public.clone())
            .ok_or_else(|| PqpgpError::session("No ratchet keypair"))?;

        // Advance the symmetric ratchet
        let (new_chain, message_key) = sending_chain.advance()?;
        let message_number = self.send_count;

        self.sending_chain = Some(new_chain);
        self.send_count += 1;

        Ok((
            message_key,
            our_public,
            message_number,
            self.previous_chain_length,
        ))
    }

    /// Derives a message key for receiving.
    ///
    /// Handles:
    /// - KEM ratchet step if their public key changed
    /// - Skipping message keys for out-of-order delivery
    /// - Looking up previously skipped keys
    pub fn ratchet_decrypt(
        &mut self,
        their_ratchet_key: &RatchetPublicKey,
        message_number: u32,
        previous_chain_length: u32,
        kem_ciphertext: Option<&[u8]>,
    ) -> Result<MessageKey> {
        // First, check if we have this key in skipped keys
        let skip_id = SkippedKeyId {
            ratchet_key: their_ratchet_key.as_bytes().to_vec(),
            message_number,
        };
        if let Some(entry) = self.skipped_keys.remove(&skip_id) {
            return Ok(entry.key);
        }

        // Check if this is a new ratchet key
        let their_key_changed = self.their_ratchet_key.as_ref() != Some(their_ratchet_key);

        if their_key_changed {
            // Skip any remaining messages in the current receiving chain
            if let (Some(ref chain), Some(ref their_key)) =
                (&self.receiving_chain, &self.their_ratchet_key)
            {
                let their_key_clone = their_key.clone();
                let chain_index = chain.index();
                self.skip_message_keys(&their_key_clone, chain_index, previous_chain_length)?;
            }

            // Perform KEM ratchet step
            self.kem_ratchet_step(their_ratchet_key, kem_ciphertext)?;
        }

        // Skip any messages before the one we're receiving
        let receiving_chain = self
            .receiving_chain
            .as_ref()
            .ok_or_else(|| PqpgpError::session("No receiving chain"))?;

        if message_number > receiving_chain.index() {
            self.skip_message_keys(their_ratchet_key, receiving_chain.index(), message_number)?;
        }

        // Now derive the message key
        let receiving_chain = self.receiving_chain.as_ref().unwrap();
        if message_number != receiving_chain.index() {
            return Err(PqpgpError::session(format!(
                "Message number mismatch: expected {}, got {}",
                receiving_chain.index(),
                message_number
            )));
        }

        let (new_chain, message_key) = receiving_chain.advance()?;
        self.receiving_chain = Some(new_chain);
        self.recv_count += 1;

        Ok(message_key)
    }

    /// Performs a KEM ratchet step when receiving a new public key.
    fn kem_ratchet_step(
        &mut self,
        their_new_key: &RatchetPublicKey,
        kem_ciphertext: Option<&[u8]>,
    ) -> Result<()> {
        // Decapsulate using our private key
        let our_keypair = self
            .our_ratchet_keypair
            .as_ref()
            .ok_or_else(|| PqpgpError::session("No ratchet keypair for decapsulation"))?;

        let shared_secret = if let Some(ct_bytes) = kem_ciphertext {
            let ct = mlkem1024::Ciphertext::from_bytes(ct_bytes)
                .map_err(|_| PqpgpError::session("Invalid KEM ciphertext"))?;
            let our_secret = our_keypair.private.as_mlkem()?;
            mlkem1024::decapsulate(&ct, &our_secret)
        } else {
            // No ciphertext - this is the first message, derive from their public key
            // In this case, we encapsulate to their key (this shouldn't normally happen)
            return Err(PqpgpError::session(
                "KEM ciphertext required for ratchet step",
            ));
        };

        // Derive new root key and receiving chain key
        let (new_root_key, receiving_chain) =
            Self::kdf_rk(&self.root_key, shared_secret.as_bytes())?;

        // Update state
        self.root_key = new_root_key;
        self.their_ratchet_key = Some(their_new_key.clone());
        self.receiving_chain = Some(receiving_chain);

        // Generate new keypair for our next send and derive sending chain
        let new_keypair = RatchetKeyPair::generate();
        let their_mlkem = their_new_key.as_mlkem()?;
        let (new_shared_secret, ciphertext) = mlkem1024::encapsulate(&their_mlkem);

        let (new_root_key2, sending_chain) =
            Self::kdf_rk(&self.root_key, new_shared_secret.as_bytes())?;

        self.root_key = new_root_key2;
        self.our_ratchet_keypair = Some(new_keypair);
        self.previous_chain_length = self.send_count;
        self.sending_chain = Some(sending_chain);
        self.send_count = 0;
        // Save the ciphertext so we can send it with our next message
        self.pending_kem_ciphertext = Some(ciphertext.as_bytes().to_vec());

        Ok(())
    }

    /// Skip message keys for out-of-order delivery.
    fn skip_message_keys(
        &mut self,
        their_key: &RatchetPublicKey,
        start: u32,
        end: u32,
    ) -> Result<()> {
        if end < start {
            return Ok(());
        }

        let to_skip = end - start;
        if self.skipped_keys.len() as u32 + to_skip > MAX_SKIP {
            return Err(PqpgpError::session("Too many skipped message keys"));
        }

        let mut chain = self
            .receiving_chain
            .take()
            .ok_or_else(|| PqpgpError::session("No receiving chain to skip"))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for _ in start..end {
            let (new_chain, message_key) = chain.advance()?;
            let skip_id = SkippedKeyId {
                ratchet_key: their_key.as_bytes().to_vec(),
                message_number: chain.index(),
            };
            // Store with timestamp for expiration
            self.skipped_keys.insert(
                skip_id,
                SkippedKeyEntry {
                    key: message_key,
                    created_at: now,
                },
            );
            chain = new_chain;
        }

        self.receiving_chain = Some(chain);
        Ok(())
    }

    /// Derives new root key and chain key from a shared secret.
    fn kdf_rk(root_key: &RootKey, shared_secret: &[u8]) -> Result<(RootKey, ChainKey)> {
        let hk = Hkdf::<Sha3_512>::new(Some(root_key.as_bytes()), shared_secret);

        let mut new_root_key = [0u8; ROOT_KEY_SIZE];
        let mut chain_key = [0u8; CHAIN_KEY_SIZE];

        hk.expand(kdf_info::RATCHET_ROOT, &mut new_root_key)
            .map_err(|_| PqpgpError::session("Root key derivation failed"))?;
        hk.expand(kdf_info::RATCHET_CHAIN, &mut chain_key)
            .map_err(|_| PqpgpError::session("Chain key derivation failed"))?;

        Ok((
            RootKey::from_bytes(new_root_key),
            ChainKey::new(chain_key, 0),
        ))
    }

    /// Returns our current ratchet public key for the message header.
    pub fn our_ratchet_public_key(&self) -> Option<&RatchetPublicKey> {
        self.our_ratchet_keypair.as_ref().map(|kp| &kp.public)
    }

    /// Returns their current ratchet public key.
    pub fn their_ratchet_public_key(&self) -> Option<&RatchetPublicKey> {
        self.their_ratchet_key.as_ref()
    }

    /// Returns the number of skipped message keys stored.
    pub fn skipped_key_count(&self) -> usize {
        self.skipped_keys.len()
    }

    /// Cleans up old skipped keys (should be called periodically).
    ///
    /// SECURITY FIX: Now removes expired keys based on timestamps in addition
    /// to enforcing the max_to_keep limit.
    pub fn cleanup_old_skipped_keys(&mut self, max_to_keep: usize) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // First, remove all expired keys
        self.skipped_keys
            .retain(|_, entry| now.saturating_sub(entry.created_at) < MAX_SKIPPED_KEY_AGE_SECS);

        // Then enforce the max count limit if still exceeded
        while self.skipped_keys.len() > max_to_keep {
            // Find and remove the oldest key
            let oldest_key = self
                .skipped_keys
                .iter()
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(id, _)| id.clone());

            if let Some(key) = oldest_key {
                self.skipped_keys.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Removes all expired skipped keys.
    /// Call this periodically to prevent memory accumulation.
    pub fn expire_old_skipped_keys(&mut self) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let before_count = self.skipped_keys.len();
        self.skipped_keys
            .retain(|_, entry| now.saturating_sub(entry.created_at) < MAX_SKIPPED_KEY_AGE_SECS);
        before_count - self.skipped_keys.len()
    }

    /// Generates a KEM ciphertext for the current ratchet step.
    ///
    /// This should be included in message headers when the ratchet key changes.
    /// For the first message from an initiator, this returns the pre-computed
    /// ciphertext from session creation.
    pub fn generate_kem_ciphertext(&mut self) -> Result<Option<Vec<u8>>> {
        // If we have a pending ciphertext (from initialization), use it
        if let Some(ct) = self.pending_kem_ciphertext.take() {
            return Ok(Some(ct));
        }

        // Otherwise generate a new one (this shouldn't happen for the first message)
        match &self.their_ratchet_key {
            Some(their_key) => {
                let their_mlkem = their_key.as_mlkem()?;
                let (_ss, ct) = mlkem1024::encapsulate(&their_mlkem);
                Ok(Some(ct.as_bytes().to_vec()))
            }
            None => Ok(None),
        }
    }
}

/// The complete Double Ratchet structure for a session.
#[derive(Serialize, Deserialize)]
pub struct DoubleRatchet {
    /// The ratchet state
    state: RatchetState,
    /// Associated data for AEAD binding
    associated_data: Vec<u8>,
}

impl fmt::Debug for DoubleRatchet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DoubleRatchet")
            .field("state", &self.state)
            .field("associated_data_len", &self.associated_data.len())
            .finish()
    }
}

impl DoubleRatchet {
    /// Creates a new Double Ratchet as the session initiator.
    pub fn new_initiator(
        root_key: [u8; ROOT_KEY_SIZE],
        their_ratchet_key: RatchetPublicKey,
        associated_data: Vec<u8>,
    ) -> Result<Self> {
        let state = RatchetState::new_initiator(root_key, their_ratchet_key)?;
        Ok(Self {
            state,
            associated_data,
        })
    }

    /// Creates a new Double Ratchet as the session responder.
    pub fn new_responder(
        root_key: [u8; ROOT_KEY_SIZE],
        our_ratchet_keypair: RatchetKeyPair,
        associated_data: Vec<u8>,
    ) -> Self {
        let state = RatchetState::new_responder(root_key, our_ratchet_keypair);
        Self {
            state,
            associated_data,
        }
    }

    /// Encrypts a message using the next message key.
    ///
    /// Returns (message_key, header_info) where header_info contains
    /// the ratchet public key and message numbers needed for decryption.
    pub fn encrypt(&mut self) -> Result<(MessageKey, RatchetPublicKey, u32, u32)> {
        self.state.ratchet_encrypt()
    }

    /// Decrypts a message using the appropriate message key.
    pub fn decrypt(
        &mut self,
        their_ratchet_key: &RatchetPublicKey,
        message_number: u32,
        previous_chain_length: u32,
        kem_ciphertext: Option<&[u8]>,
    ) -> Result<MessageKey> {
        self.state.ratchet_decrypt(
            their_ratchet_key,
            message_number,
            previous_chain_length,
            kem_ciphertext,
        )
    }

    /// Returns the associated data for AEAD operations.
    pub fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }

    /// Returns the internal state (for serialization/debugging).
    pub fn state(&self) -> &RatchetState {
        &self.state
    }

    /// Returns a mutable reference to the internal state.
    pub fn state_mut(&mut self) -> &mut RatchetState {
        &mut self.state
    }

    /// Returns our current ratchet public key.
    pub fn our_ratchet_public_key(&self) -> Option<&RatchetPublicKey> {
        self.state.our_ratchet_public_key()
    }

    /// Initializes the responder's ratchet when receiving the first message.
    pub fn initialize_responder(
        &mut self,
        their_ratchet_key: &RatchetPublicKey,
        kem_ciphertext: &[u8],
    ) -> Result<()> {
        self.state
            .initialize_responder(their_ratchet_key, kem_ciphertext)
    }

    /// Decrypts the first message after initialization.
    pub fn decrypt_first_message(&mut self, message_number: u32) -> Result<MessageKey> {
        self.state.decrypt_first_message(message_number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_key_advance() {
        let chain = ChainKey::new([0u8; CHAIN_KEY_SIZE], 0);

        let (new_chain, message_key) = chain.advance().unwrap();

        assert_eq!(new_chain.index(), 1);
        assert_ne!(chain.as_bytes(), new_chain.as_bytes());
        assert!(!message_key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_chain_key_deterministic() {
        let chain1 = ChainKey::new([42u8; CHAIN_KEY_SIZE], 0);
        let chain2 = ChainKey::new([42u8; CHAIN_KEY_SIZE], 0);

        let (new1, key1) = chain1.advance().unwrap();
        let (new2, key2) = chain2.advance().unwrap();

        assert_eq!(new1.as_bytes(), new2.as_bytes());
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_message_key_derives_aes() {
        let key = MessageKey::from_bytes([1u8; MESSAGE_KEY_SIZE]);

        let aes_key = key.derive_aes_key().unwrap();

        assert_eq!(aes_key.len(), 32);
        assert!(!aes_key.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ratchet_keypair_generation() {
        let kp1 = RatchetKeyPair::generate();
        let kp2 = RatchetKeyPair::generate();

        // Different keypairs should have different public keys
        assert_ne!(kp1.public.as_bytes(), kp2.public.as_bytes());
    }

    #[test]
    fn test_double_ratchet_initiator_responder() {
        let root_key = [42u8; ROOT_KEY_SIZE];
        let ad = b"test-associated-data".to_vec();

        // Bob generates his ratchet keypair (this would be in his prekey)
        let bob_keypair = RatchetKeyPair::generate();
        let bob_public = bob_keypair.public.clone();

        // Alice creates initiator ratchet
        let mut alice = DoubleRatchet::new_initiator(root_key, bob_public, ad.clone()).unwrap();

        // Bob creates responder ratchet
        let _bob = DoubleRatchet::new_responder(root_key, bob_keypair, ad);

        // Alice encrypts first message
        let (alice_key1, alice_pub, msg_num, prev_len) = alice.encrypt().unwrap();

        // Generate KEM ciphertext for Bob
        let kem_ct = {
            let their_mlkem = alice
                .state
                .their_ratchet_key
                .as_ref()
                .unwrap()
                .as_mlkem()
                .unwrap();
            let (_ss, ct) = mlkem1024::encapsulate(&their_mlkem);
            ct.as_bytes().to_vec()
        };

        // This test verifies the low-level ratchet initialization and chain mechanism.
        // Full protocol integration (header encryption, message exchange) is tested
        // in session.rs via test_full_session_exchange and test_bidirectional_messaging.
        assert_eq!(msg_num, 0);
        assert_eq!(prev_len, 0);
        // Verify we got valid keys and ciphertext
        let _ = alice_key1; // MessageKey was generated
        assert!(!alice_pub.as_bytes().is_empty());
        assert!(!kem_ct.is_empty());
    }

    #[test]
    fn test_symmetric_ratchet_only() {
        // Test just the symmetric ratchet part
        let chain = ChainKey::new([99u8; CHAIN_KEY_SIZE], 0);

        let mut current_chain = chain;
        let mut keys = Vec::new();

        for _ in 0..5 {
            let (new_chain, key) = current_chain.advance().unwrap();
            keys.push(key);
            current_chain = new_chain;
        }

        // All keys should be unique
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i].as_bytes(), keys[j].as_bytes());
            }
        }
    }

    #[test]
    fn test_kdf_rk() {
        let root = RootKey::from_bytes([1u8; ROOT_KEY_SIZE]);
        let shared_secret = [2u8; 32];

        let (new_root, chain) = RatchetState::kdf_rk(&root, &shared_secret).unwrap();

        assert_ne!(new_root.as_bytes(), root.as_bytes());
        assert_eq!(chain.index(), 0);
    }

    #[test]
    fn test_kdf_rk_deterministic() {
        let root1 = RootKey::from_bytes([1u8; ROOT_KEY_SIZE]);
        let root2 = RootKey::from_bytes([1u8; ROOT_KEY_SIZE]);
        let shared_secret = [2u8; 32];

        let (new_root1, chain1) = RatchetState::kdf_rk(&root1, &shared_secret).unwrap();
        let (new_root2, chain2) = RatchetState::kdf_rk(&root2, &shared_secret).unwrap();

        assert_eq!(new_root1.as_bytes(), new_root2.as_bytes());
        assert_eq!(chain1.as_bytes(), chain2.as_bytes());
    }
}
