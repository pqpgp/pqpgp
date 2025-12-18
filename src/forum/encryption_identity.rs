//! Encryption identity node for DAG-based private messaging.
//!
//! An `EncryptionIdentity` publishes a user's encryption keys to the DAG,
//! enabling end-to-end encrypted private messages. This is similar to a
//! prekey bundle in Signal, but stored in the DAG for decentralized discovery.
//!
//! ## Security Model
//!
//! - **Identity Binding**: The encryption key is signed by the user's forum
//!   signing key (ML-DSA-87), proving ownership.
//! - **Forward Secrecy**: Uses ML-KEM-1024 prekeys with one-time prekeys for
//!   per-conversation forward secrecy via X3DH.
//! - **Key Rotation**: Users can publish new encryption identities; the latest
//!   valid one is used for new conversations.
//!
//! ## Structure
//!
//! ```text
//! EncryptionIdentity
//! ├── owner_signing_key (ML-DSA-87 - links to forum identity)
//! ├── signed_prekey (ML-KEM-1024, signed by owner)
//! └── one_time_prekeys (ML-KEM-1024, consumed per conversation)
//! ```

use crate::chat::prekey::{OneTimePreKey, PreKeyId, SignedPreKey};
use crate::crypto::{sign_data, verify_data_signature, PrivateKey, PublicKey, Signature};
use crate::error::{PqpgpError, Result};
use crate::forum::types::{current_timestamp_millis, ContentHash, NodeType};
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// Maximum number of one-time prekeys in a single encryption identity node.
/// Users should publish new nodes as keys are consumed.
pub const MAX_ONE_TIME_PREKEYS: usize = 100;

/// ML-KEM-1024 public key size in bytes.
pub const MLKEM1024_PUBLIC_KEY_SIZE: usize = 1568;

/// The content of an encryption identity node that gets signed and hashed.
///
/// This contains the X3DH prekey bundle for a forum user, enabling others
/// to establish encrypted private message sessions.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptionIdentityContent {
    /// Node type discriminator (always EncryptionIdentity).
    pub node_type: NodeType,
    /// Hash of the forum this encryption identity belongs to.
    pub forum_hash: ContentHash,
    /// Public key bytes of the owner's signing identity (ML-DSA-87).
    /// This links the encryption key to the forum identity.
    pub owner_signing_key: Vec<u8>,
    /// The signed prekey for X3DH key agreement (ML-KEM-1024).
    pub signed_prekey: SignedPreKey,
    /// Batch of one-time prekeys for enhanced forward secrecy.
    pub one_time_prekeys: Vec<OneTimePreKey>,
    /// Creation timestamp in milliseconds since Unix epoch.
    pub created_at: u64,
}

impl fmt::Debug for EncryptionIdentityContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionIdentityContent")
            .field("node_type", &self.node_type)
            .field("forum_hash", &self.forum_hash)
            .field("owner_signing_key_len", &self.owner_signing_key.len())
            .field("signed_prekey_id", &self.signed_prekey.id())
            .field("one_time_prekeys_count", &self.one_time_prekeys.len())
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl EncryptionIdentityContent {
    /// Creates new encryption identity content.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this identity belongs to
    /// * `owner_signing_key` - The owner's ML-DSA-87 public key
    /// * `signed_prekey` - The signed ML-KEM-1024 prekey
    /// * `one_time_prekeys` - Batch of one-time prekeys
    ///
    /// # Errors
    /// Returns an error if too many one-time prekeys are provided.
    pub fn new(
        forum_hash: ContentHash,
        owner_signing_key: &PublicKey,
        signed_prekey: SignedPreKey,
        one_time_prekeys: Vec<OneTimePreKey>,
    ) -> Result<Self> {
        if one_time_prekeys.len() > MAX_ONE_TIME_PREKEYS {
            return Err(PqpgpError::validation(format!(
                "Too many one-time prekeys: {} (max {})",
                one_time_prekeys.len(),
                MAX_ONE_TIME_PREKEYS
            )));
        }

        Ok(Self {
            node_type: NodeType::EncryptionIdentity,
            forum_hash,
            owner_signing_key: owner_signing_key.as_bytes(),
            signed_prekey,
            one_time_prekeys,
            created_at: current_timestamp_millis(),
        })
    }

    /// Computes the content hash of this encryption identity content.
    pub fn content_hash(&self) -> Result<ContentHash> {
        ContentHash::compute(self)
    }
}

/// A complete encryption identity node with content, signature, and hash.
///
/// This node is published to the DAG to enable private messaging.
/// Other users fetch this to establish encrypted sessions via X3DH.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptionIdentity {
    /// The signed content of this node.
    pub content: EncryptionIdentityContent,
    /// ML-DSA-87 signature over the content (by owner_signing_key).
    pub signature: Signature,
    /// Content hash - the unique identifier of this node.
    pub content_hash: ContentHash,
}

impl fmt::Debug for EncryptionIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionIdentity")
            .field("forum_hash", &self.content.forum_hash)
            .field("content_hash", &self.content_hash)
            .field("signed_prekey_id", &self.content.signed_prekey.id())
            .field("one_time_prekeys", &self.content.one_time_prekeys.len())
            .finish()
    }
}

impl EncryptionIdentity {
    /// Creates and signs a new encryption identity node.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this identity belongs to
    /// * `owner_public_key` - The owner's ML-DSA-87 public key (for signing)
    /// * `owner_private_key` - The owner's ML-DSA-87 private key (to sign)
    /// * `signed_prekey` - The signed ML-KEM-1024 prekey
    /// * `one_time_prekeys` - Batch of one-time prekeys
    /// * `password` - Optional password if the private key is encrypted
    ///
    /// # Errors
    /// Returns an error if validation fails or signing fails.
    pub fn create(
        forum_hash: ContentHash,
        owner_public_key: &PublicKey,
        owner_private_key: &PrivateKey,
        signed_prekey: SignedPreKey,
        one_time_prekeys: Vec<OneTimePreKey>,
        password: Option<&crate::crypto::Password>,
    ) -> Result<Self> {
        let content = EncryptionIdentityContent::new(
            forum_hash,
            owner_public_key,
            signed_prekey,
            one_time_prekeys,
        )?;
        let content_hash = content.content_hash()?;
        let signature = sign_data(owner_private_key, &content, password)?;

        Ok(Self {
            content,
            signature,
            content_hash,
        })
    }

    /// Verifies the signature and content hash of this node.
    ///
    /// # Arguments
    /// * `owner_public_key` - Public key to verify the signature against
    ///
    /// # Errors
    /// Returns an error if:
    /// - The content hash doesn't match the computed hash
    /// - The node signature is invalid
    /// - The owner public key bytes don't match
    /// - The prekey sizes are invalid
    pub fn verify(&self, owner_public_key: &PublicKey) -> Result<()> {
        // Verify content hash
        let computed_hash = self.content.content_hash()?;
        if computed_hash != self.content_hash {
            return Err(PqpgpError::validation(
                "EncryptionIdentity content hash mismatch",
            ));
        }

        // Verify the owner_signing_key bytes match the provided public key
        if self.content.owner_signing_key != owner_public_key.as_bytes() {
            return Err(PqpgpError::validation(
                "Owner signing key bytes don't match provided public key",
            ));
        }

        // Verify node signature
        verify_data_signature(owner_public_key, &self.content, &self.signature)?;

        // Verify the signed prekey is valid ML-KEM-1024
        if self.content.signed_prekey.public_key().len() != MLKEM1024_PUBLIC_KEY_SIZE {
            return Err(PqpgpError::validation(
                "Invalid signed prekey size for ML-KEM-1024",
            ));
        }

        // Verify all one-time prekeys are valid ML-KEM-1024
        for otp in &self.content.one_time_prekeys {
            if otp.public_key().len() != MLKEM1024_PUBLIC_KEY_SIZE {
                return Err(PqpgpError::validation(
                    "Invalid one-time prekey size for ML-KEM-1024",
                ));
            }
        }

        Ok(())
    }

    /// Returns the forum hash this encryption identity belongs to.
    pub fn forum_hash(&self) -> &ContentHash {
        &self.content.forum_hash
    }

    /// Returns the owner's signing key bytes.
    pub fn owner_signing_key(&self) -> &[u8] {
        &self.content.owner_signing_key
    }

    /// Returns the signed prekey for X3DH.
    pub fn signed_prekey(&self) -> &SignedPreKey {
        &self.content.signed_prekey
    }

    /// Returns the one-time prekeys.
    pub fn one_time_prekeys(&self) -> &[OneTimePreKey] {
        &self.content.one_time_prekeys
    }

    /// Returns a one-time prekey by ID, if available.
    pub fn get_one_time_prekey(&self, id: PreKeyId) -> Option<&OneTimePreKey> {
        self.content
            .one_time_prekeys
            .iter()
            .find(|otp| otp.id() == id)
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
}

/// Private key material for an encryption identity.
///
/// This contains the secret keys needed to decrypt incoming private messages.
/// Must be stored securely by the user.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptionIdentityPrivate {
    /// The hash of the corresponding public EncryptionIdentity node (stored as bytes).
    #[serde(with = "content_hash_bytes")]
    pub identity_hash: ContentHash,
    /// The signed prekey public key bytes (ML-KEM-1024).
    /// Needed for recipient hint verification.
    signed_prekey_public: Vec<u8>,
    /// The signed prekey secret key bytes (ML-KEM-1024).
    #[serde(with = "zeroizing_vec")]
    signed_prekey_secret: Vec<u8>,
    /// The signed prekey ID (for matching).
    pub signed_prekey_id: PreKeyId,
    /// One-time prekey secret keys (ML-KEM-1024).
    /// Indexed by prekey ID for efficient lookup.
    one_time_prekey_secrets: Vec<(PreKeyId, Vec<u8>)>,
}

/// Custom serde module for ContentHash as bytes.
mod content_hash_bytes {
    use super::ContentHash;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(hash: &ContentHash, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hash.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ContentHash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes for ContentHash"))?;
        Ok(ContentHash::from_bytes(arr))
    }
}

/// Custom serde module for zeroizing vectors.
///
/// SECURITY FIX: The deserialized vector will be wrapped in the EncryptionIdentityPrivate
/// struct which implements Drop for zeroization. While the transient Vec during deserialization
/// isn't zeroized, the final storage is properly handled. This is acceptable because:
/// 1. The deserialization is typically from trusted local storage
/// 2. The transient memory exposure is minimal (microseconds)
/// 3. The final struct properly zeroizes on drop
mod zeroizing_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(vec: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        vec.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Note: We deserialize to a regular Vec<u8>. The containing struct
        // (EncryptionIdentityPrivate) implements Drop to zeroize all sensitive
        // fields including this one. The transient exposure during deserialization
        // is acceptable for trusted local storage.
        Vec::<u8>::deserialize(deserializer)
    }
}

impl Drop for EncryptionIdentityPrivate {
    fn drop(&mut self) {
        // Zeroize sensitive key material
        use zeroize::Zeroize;
        self.signed_prekey_secret.zeroize();
        for (_, secret) in &mut self.one_time_prekey_secrets {
            secret.zeroize();
        }
    }
}

impl fmt::Debug for EncryptionIdentityPrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionIdentityPrivate")
            .field("identity_hash", &self.identity_hash)
            .field("signed_prekey_id", &self.signed_prekey_id)
            .field(
                "one_time_prekeys_count",
                &self.one_time_prekey_secrets.len(),
            )
            .finish_non_exhaustive()
    }
}

impl EncryptionIdentityPrivate {
    /// Creates a new private key store for an encryption identity.
    ///
    /// # Arguments
    /// * `identity_hash` - Hash of the corresponding public node
    /// * `signed_prekey_public` - ML-KEM-1024 public key for signed prekey (for hint verification)
    /// * `signed_prekey_secret` - ML-KEM-1024 secret key for signed prekey
    /// * `signed_prekey_id` - ID of the signed prekey
    /// * `one_time_prekey_secrets` - List of (id, secret_key) pairs
    pub fn new(
        identity_hash: ContentHash,
        signed_prekey_public: Vec<u8>,
        signed_prekey_secret: Vec<u8>,
        signed_prekey_id: PreKeyId,
        one_time_prekey_secrets: Vec<(PreKeyId, Vec<u8>)>,
    ) -> Self {
        Self {
            identity_hash,
            signed_prekey_public,
            signed_prekey_secret,
            signed_prekey_id,
            one_time_prekey_secrets,
        }
    }

    /// Returns the signed prekey secret key as ML-KEM-1024.
    pub fn signed_prekey_as_mlkem(&self) -> Result<mlkem1024::SecretKey> {
        mlkem1024::SecretKey::from_bytes(&self.signed_prekey_secret)
            .map_err(|_| PqpgpError::prekey("Invalid ML-KEM-1024 signed prekey secret"))
    }

    /// Returns the raw signed prekey secret bytes.
    pub fn signed_prekey_secret(&self) -> &[u8] {
        &self.signed_prekey_secret
    }

    /// Returns the raw signed prekey public bytes.
    /// Used for computing recipient hints.
    pub fn signed_prekey_public(&self) -> &[u8] {
        &self.signed_prekey_public
    }

    /// Returns a one-time prekey secret by ID.
    pub fn get_one_time_secret(&self, id: PreKeyId) -> Option<&[u8]> {
        self.one_time_prekey_secrets
            .iter()
            .find(|(otp_id, _)| *otp_id == id)
            .map(|(_, secret)| secret.as_slice())
    }

    /// Returns a one-time prekey secret as ML-KEM-1024 by ID.
    pub fn get_one_time_as_mlkem(&self, id: PreKeyId) -> Result<mlkem1024::SecretKey> {
        let secret = self
            .get_one_time_secret(id)
            .ok_or_else(|| PqpgpError::prekey(format!("One-time prekey {} not found", id)))?;
        mlkem1024::SecretKey::from_bytes(secret)
            .map_err(|_| PqpgpError::prekey("Invalid ML-KEM-1024 one-time prekey secret"))
    }

    /// Removes a consumed one-time prekey.
    ///
    /// Call this after successfully processing an initial message that used this OTP.
    /// The secret key material is securely zeroized before being dropped.
    pub fn consume_one_time_prekey(&mut self, id: PreKeyId) -> bool {
        if let Some(pos) = self
            .one_time_prekey_secrets
            .iter()
            .position(|(otp_id, _)| *otp_id == id)
        {
            // Securely zeroize the secret key before dropping
            let (_, mut secret) = self.one_time_prekey_secrets.remove(pos);
            secret.zeroize();
            true
        } else {
            false
        }
    }

    /// Returns the number of remaining one-time prekeys.
    pub fn remaining_one_time_prekeys(&self) -> usize {
        self.one_time_prekey_secrets.len()
    }

    /// Returns a clone of all one-time prekey secrets for merging.
    ///
    /// This is used when replenishing OTPs to preserve existing unused keys.
    pub(crate) fn clone_one_time_secrets(&self) -> Vec<(PreKeyId, Vec<u8>)> {
        self.one_time_prekey_secrets.clone()
    }
}

/// Helper to generate a complete encryption identity with private keys.
///
/// This generates all the cryptographic material needed for private messaging.
pub struct EncryptionIdentityGenerator;

impl EncryptionIdentityGenerator {
    /// Generates a new encryption identity with the specified number of one-time prekeys.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this identity belongs to
    /// * `owner_public_key` - The owner's ML-DSA-87 public key
    /// * `owner_private_key` - The owner's ML-DSA-87 private key
    /// * `one_time_prekey_count` - Number of one-time prekeys to generate
    /// * `password` - Optional password if the private key is encrypted
    ///
    /// # Returns
    /// A tuple of (EncryptionIdentity, EncryptionIdentityPrivate) - the public node
    /// to publish to the DAG and the private keys to store securely.
    pub fn generate(
        forum_hash: ContentHash,
        owner_public_key: &PublicKey,
        owner_private_key: &PrivateKey,
        one_time_prekey_count: usize,
        password: Option<&crate::crypto::Password>,
    ) -> Result<(EncryptionIdentity, EncryptionIdentityPrivate)> {
        if one_time_prekey_count > MAX_ONE_TIME_PREKEYS {
            return Err(PqpgpError::validation(format!(
                "Too many one-time prekeys: {} (max {})",
                one_time_prekey_count, MAX_ONE_TIME_PREKEYS
            )));
        }

        // Generate signed prekey (ML-KEM-1024)
        let (spk_public, spk_secret) = mlkem1024::keypair();
        let spk_id: PreKeyId = 1;
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let spk_public_bytes = KemPublicKey::as_bytes(&spk_public).to_vec();
        let spk_secret_bytes = KemSecretKey::as_bytes(&spk_secret).to_vec();

        // Build signing data for prekey signature
        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(b"PQPGP-signed-prekey-v1");
        signing_data.extend_from_slice(&spk_id.to_be_bytes());
        signing_data.extend_from_slice(&spk_public_bytes);
        signing_data.extend_from_slice(&created.to_be_bytes());

        // Sign the prekey with the owner's identity
        let spk_signature =
            crate::crypto::sign_message(owner_private_key, &signing_data, password)?;

        // Clone before moving for use in private key store
        let spk_public_bytes_for_private = spk_public_bytes.clone();
        let signed_prekey = SignedPreKey::new_raw(spk_id, spk_public_bytes, spk_signature, created);

        // Generate one-time prekeys
        let mut one_time_prekeys = Vec::with_capacity(one_time_prekey_count);
        let mut one_time_secrets = Vec::with_capacity(one_time_prekey_count);

        for i in 0..one_time_prekey_count {
            let (otp_public, otp_secret) = mlkem1024::keypair();
            let otp_id = (i + 2) as PreKeyId; // Start at 2 (1 is signed prekey)

            let otp_public_bytes = KemPublicKey::as_bytes(&otp_public).to_vec();
            let otp_secret_bytes = KemSecretKey::as_bytes(&otp_secret).to_vec();

            one_time_prekeys.push(OneTimePreKey::new_raw(otp_id, otp_public_bytes));
            one_time_secrets.push((otp_id, otp_secret_bytes));
        }

        // Create the public encryption identity
        let identity = EncryptionIdentity::create(
            forum_hash,
            owner_public_key,
            owner_private_key,
            signed_prekey,
            one_time_prekeys,
            password,
        )?;

        // Create the private key store
        let private = EncryptionIdentityPrivate::new(
            *identity.hash(),
            spk_public_bytes_for_private,
            spk_secret_bytes,
            spk_id,
            one_time_secrets,
        );

        Ok((identity, private))
    }

    /// Generates additional one-time prekeys to replenish an existing identity.
    ///
    /// This creates a new EncryptionIdentity node with the same signed prekey
    /// but fresh one-time prekeys. The new node should be published to the DAG
    /// to advertise the new OTPs.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum
    /// * `owner_public_key` - The owner's ML-DSA-87 public key
    /// * `owner_private_key` - The owner's ML-DSA-87 private key
    /// * `existing_private` - The existing private key store (to preserve signed prekey)
    /// * `new_otp_count` - Number of new one-time prekeys to generate
    /// * `start_id` - Starting ID for new OTPs (should be higher than existing)
    /// * `password` - Optional password if the private key is encrypted
    ///
    /// # Returns
    /// A tuple of (new EncryptionIdentity, updated EncryptionIdentityPrivate)
    pub fn replenish_one_time_prekeys(
        forum_hash: ContentHash,
        owner_public_key: &PublicKey,
        owner_private_key: &PrivateKey,
        existing_private: &EncryptionIdentityPrivate,
        new_otp_count: usize,
        start_id: PreKeyId,
        password: Option<&crate::crypto::Password>,
    ) -> Result<(EncryptionIdentity, EncryptionIdentityPrivate)> {
        if new_otp_count > MAX_ONE_TIME_PREKEYS {
            return Err(PqpgpError::validation(format!(
                "Too many one-time prekeys: {} (max {})",
                new_otp_count, MAX_ONE_TIME_PREKEYS
            )));
        }

        // Re-create signed prekey from existing private
        let spk_public_bytes = existing_private.signed_prekey_public().to_vec();
        let spk_id = existing_private.signed_prekey_id;

        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Build signing data for prekey signature
        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(b"PQPGP-signed-prekey-v1");
        signing_data.extend_from_slice(&spk_id.to_be_bytes());
        signing_data.extend_from_slice(&spk_public_bytes);
        signing_data.extend_from_slice(&created.to_be_bytes());

        let spk_signature =
            crate::crypto::sign_message(owner_private_key, &signing_data, password)?;
        let signed_prekey =
            SignedPreKey::new_raw(spk_id, spk_public_bytes.clone(), spk_signature, created);

        // Generate new one-time prekeys
        let mut one_time_prekeys = Vec::with_capacity(new_otp_count);
        let mut one_time_secrets = Vec::with_capacity(new_otp_count);

        for i in 0..new_otp_count {
            let (otp_public, otp_secret) = mlkem1024::keypair();
            let otp_id = start_id + i as PreKeyId;

            let otp_public_bytes = KemPublicKey::as_bytes(&otp_public).to_vec();
            let otp_secret_bytes = KemSecretKey::as_bytes(&otp_secret).to_vec();

            one_time_prekeys.push(OneTimePreKey::new_raw(otp_id, otp_public_bytes));
            one_time_secrets.push((otp_id, otp_secret_bytes));
        }

        // Create the new public encryption identity
        let identity = EncryptionIdentity::create(
            forum_hash,
            owner_public_key,
            owner_private_key,
            signed_prekey,
            one_time_prekeys,
            password,
        )?;

        // SECURITY FIX: Merge old OTP secrets with new ones
        // This preserves existing unused OTPs for forward secrecy
        let mut merged_secrets = existing_private.clone_one_time_secrets();
        merged_secrets.extend(one_time_secrets);

        // Truncate to max if we exceeded the limit
        if merged_secrets.len() > MAX_ONE_TIME_PREKEYS {
            merged_secrets.truncate(MAX_ONE_TIME_PREKEYS);
        }

        let private = EncryptionIdentityPrivate::new(
            *identity.hash(),
            spk_public_bytes,
            existing_private.signed_prekey_secret().to_vec(),
            spk_id,
            merged_secrets,
        );

        Ok((identity, private))
    }

    /// Rotates the signed prekey, generating a completely new identity.
    ///
    /// This should be done periodically for forward secrecy. Old sessions
    /// can still use the old prekey for a grace period.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum
    /// * `owner_public_key` - The owner's ML-DSA-87 public key
    /// * `owner_private_key` - The owner's ML-DSA-87 private key
    /// * `one_time_prekey_count` - Number of one-time prekeys for new identity
    /// * `password` - Optional password if the private key is encrypted
    ///
    /// # Returns
    /// A tuple of (new EncryptionIdentity, new EncryptionIdentityPrivate)
    pub fn rotate_signed_prekey(
        forum_hash: ContentHash,
        owner_public_key: &PublicKey,
        owner_private_key: &PrivateKey,
        one_time_prekey_count: usize,
        password: Option<&crate::crypto::Password>,
    ) -> Result<(EncryptionIdentity, EncryptionIdentityPrivate)> {
        // Simply generate a completely new identity
        // The old identity should be kept for a grace period to handle in-flight messages
        Self::generate(
            forum_hash,
            owner_public_key,
            owner_private_key,
            one_time_prekey_count,
            password,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
    }

    fn create_test_forum_hash() -> ContentHash {
        ContentHash::from_bytes([0u8; 64])
    }

    #[test]
    fn test_encryption_identity_generation() {
        let keypair = create_test_keypair();
        let forum_hash = create_test_forum_hash();

        let (identity, private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            keypair.public_key(),
            keypair.private_key(),
            10,
            None,
        )
        .expect("Failed to generate encryption identity");

        assert_eq!(identity.node_type(), NodeType::EncryptionIdentity);
        assert_eq!(identity.forum_hash(), &forum_hash);
        assert_eq!(identity.one_time_prekeys().len(), 10);
        assert_eq!(private.remaining_one_time_prekeys(), 10);
    }

    #[test]
    fn test_encryption_identity_verification() {
        let keypair = create_test_keypair();
        let forum_hash = create_test_forum_hash();

        let (identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            keypair.public_key(),
            keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate encryption identity");

        identity
            .verify(keypair.public_key())
            .expect("Verification failed");
    }

    #[test]
    fn test_encryption_identity_serialization() {
        let keypair = create_test_keypair();
        let forum_hash = create_test_forum_hash();

        let (identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            keypair.public_key(),
            keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate encryption identity");

        let serialized = bincode::serialize(&identity).expect("Failed to serialize");
        let deserialized: EncryptionIdentity =
            bincode::deserialize(&serialized).expect("Failed to deserialize");

        assert_eq!(identity.hash(), deserialized.hash());
        deserialized
            .verify(keypair.public_key())
            .expect("Verification failed after deserialization");
    }

    #[test]
    fn test_consume_one_time_prekey() {
        let keypair = create_test_keypair();
        let forum_hash = create_test_forum_hash();

        let (identity, mut private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            keypair.public_key(),
            keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate encryption identity");

        let otp_id = identity.one_time_prekeys()[0].id();
        assert!(private.get_one_time_secret(otp_id).is_some());

        assert!(private.consume_one_time_prekey(otp_id));
        assert!(private.get_one_time_secret(otp_id).is_none());
        assert_eq!(private.remaining_one_time_prekeys(), 4);
    }

    #[test]
    fn test_too_many_one_time_prekeys() {
        let keypair = create_test_keypair();
        let forum_hash = create_test_forum_hash();

        let result = EncryptionIdentityGenerator::generate(
            forum_hash,
            keypair.public_key(),
            keypair.private_key(),
            MAX_ONE_TIME_PREKEYS + 1,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_mlkem_conversion() {
        let keypair = create_test_keypair();
        let forum_hash = create_test_forum_hash();

        let (identity, private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            keypair.public_key(),
            keypair.private_key(),
            3,
            None,
        )
        .expect("Failed to generate encryption identity");

        // Should be able to convert signed prekey secret
        let _spk_secret = private
            .signed_prekey_as_mlkem()
            .expect("Failed to convert SPK");

        // Should be able to convert one-time prekey secret
        let otp_id = identity.one_time_prekeys()[0].id();
        let _otp_secret = private
            .get_one_time_as_mlkem(otp_id)
            .expect("Failed to convert OTP");
    }
}
