//! Post-quantum secure chat protocol implementation.
//!
//! This module provides a Signal-like chat protocol with post-quantum security,
//! implementing:
//!
//! - **Post-Quantum X3DH**: Asynchronous key agreement using ML-KEM-1024
//! - **Double Ratchet**: Per-message forward secrecy with KEM-based ratcheting
//! - **Sealed Sender**: Metadata protection hiding sender identity
//! - **Group Chat**: TreeKEM-based group key agreement
//!
//! ## Security Properties
//!
//! - **Quantum Resistance**: All operations use NIST post-quantum algorithms
//! - **Forward Secrecy**: Past messages remain secure if keys are compromised
//! - **Post-Compromise Security**: Future messages secure after session heals
//! - **Deniability**: No cryptographic proof of message authorship
//!
//! ## Protocol Overview
//!
//! ### Session Establishment (X3DH)
//!
//! 1. Bob publishes a `PreKeyBundle` containing his identity key, signed prekey,
//!    and optional one-time prekeys
//! 2. Alice fetches Bob's bundle and performs KEM encapsulation to each key
//! 3. Alice derives a shared secret and initializes the Double Ratchet
//! 4. Alice sends her initial message with the KEM ciphertexts
//! 5. Bob decapsulates to derive the same shared secret
//!
//! ### Message Encryption (Double Ratchet)
//!
//! Each message uses a unique encryption key derived through two ratchets:
//! - **KEM Ratchet**: New KEM operation when receiving a new public key
//! - **Symmetric Ratchet**: HKDF chain for consecutive messages
//!
//! ## Example
//!
//! ```rust,no_run
//! use pqpgp::chat::{IdentityKeyPair, Session};
//! use pqpgp::chat::prekey::PreKeyGenerator;
//!
//! // Generate identities
//! let alice_identity = IdentityKeyPair::generate()?;
//! let bob_identity = IdentityKeyPair::generate()?;
//!
//! // Bob creates and publishes his prekey bundle
//! let bob_prekeys = PreKeyGenerator::new(&bob_identity, 10)?;
//! let bob_bundle = bob_prekeys.create_bundle(&bob_identity, true);
//!
//! // Alice initiates a session with Bob
//! let mut alice_session = Session::initiate(&alice_identity, &bob_bundle)?;
//!
//! // Alice can now send messages using the double ratchet
//! let encrypted = alice_session.encrypt(b"Hello Bob!")?;
//! # Ok::<(), pqpgp::error::PqpgpError>(())
//! ```

pub mod header;
pub mod identity;
pub mod message;
pub mod prekey;
pub mod ratchet;
pub mod session;
pub mod x3dh;

pub use header::{EncryptedHeader, HeaderKey, MessageHeader};
pub use identity::{Identity, IdentityKey, IdentityKeyPair};
pub use message::{
    Attachment, ChatMessage, ContentType, Location, MessageId, MessagePayload, Reaction,
};
pub use prekey::{OneTimePreKey, PreKeyBundle, PreKeyId, SignedPreKey};
pub use ratchet::{
    ChainKey, DoubleRatchet, MessageKey, RatchetKeyPair, RatchetPublicKey, RatchetState,
};
pub use session::{EncryptedChatMessage, PeerInfo, Session, SessionState};
pub use x3dh::{X3DHKeys, X3DHReceiver, X3DHSender, X3DHSharedSecret};

/// Maximum number of skipped message keys to store per session.
/// This limits memory usage while allowing reasonable out-of-order delivery.
pub const MAX_SKIP: u32 = 1000;

/// Maximum age of a skipped message key before it's discarded (in seconds).
/// Keys older than this are removed to limit the window for replay attacks.
pub const MAX_SKIP_AGE_SECS: u64 = 7 * 24 * 60 * 60; // 7 days

/// Prekey rotation interval (in seconds).
/// Signed prekeys should be rotated periodically for forward secrecy.
pub const PREKEY_ROTATION_SECS: u64 = 7 * 24 * 60 * 60; // 7 days

/// Number of one-time prekeys to maintain.
/// The server should alert when the count drops below a threshold.
pub const ONE_TIME_PREKEY_COUNT: u32 = 100;

/// Protocol version identifier.
pub const PROTOCOL_VERSION: u8 = 1;

/// Domain separation constants for HKDF operations.
pub mod kdf_info {
    /// Root key derivation from X3DH.
    pub const X3DH_ROOT: &[u8] = b"PQPGP-X3DH-v1-root";
    /// Chain key derivation from root key.
    pub const RATCHET_ROOT: &[u8] = b"PQPGP-ratchet-v1-root";
    /// New chain key from previous chain key.
    pub const RATCHET_CHAIN: &[u8] = b"PQPGP-ratchet-v1-chain";
    /// Message key from chain key.
    pub const RATCHET_MESSAGE: &[u8] = b"PQPGP-ratchet-v1-message";
    /// Header encryption key derivation.
    pub const HEADER_KEY: &[u8] = b"PQPGP-header-v1-key";
    /// Sealed sender key derivation.
    pub const SEALED_SENDER: &[u8] = b"PQPGP-sealed-v1-key";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version() {
        // Verify the protocol version constant is accessible and has expected value
        let version: u8 = PROTOCOL_VERSION;
        assert_eq!(version, 1);
    }

    #[test]
    fn test_kdf_info_labels_are_unique() {
        // Ensure all KDF info labels are distinct to prevent key confusion
        let labels: Vec<&[u8]> = vec![
            kdf_info::X3DH_ROOT,
            kdf_info::RATCHET_ROOT,
            kdf_info::RATCHET_CHAIN,
            kdf_info::RATCHET_MESSAGE,
            kdf_info::HEADER_KEY,
            kdf_info::SEALED_SENDER,
        ];

        // Check all pairs are distinct
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(labels[i], labels[j], "KDF labels must be unique");
            }
        }
    }
}
