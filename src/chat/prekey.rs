//! Prekey bundle management for asynchronous key agreement.
//!
//! This module provides prekeys used in the X3DH protocol for establishing
//! encrypted sessions without requiring both parties to be online simultaneously.
//!
//! ## Prekey Types
//!
//! - **Signed Prekey**: ML-KEM-1024 key pair, signed by identity key, rotated periodically
//! - **One-Time Prekey**: ML-KEM-1024 key pair, used exactly once, provides extra forward secrecy
//!
//! ## Prekey Bundle
//!
//! A bundle contains:
//! - Identity key (for verification)
//! - Signed prekey (with signature)
//! - Optional one-time prekeys
//!
//! ## Server Responsibilities
//!
//! A chat server should:
//! 1. Store prekey bundles for each user
//! 2. Return bundles when requested (including one OTP if available)
//! 3. Delete one-time prekeys after they're fetched
//! 4. Alert users when their OTP supply is low
//!
//! ## Security Considerations
//!
//! - Signed prekeys should be rotated every 7-30 days
//! - One-time prekeys provide extra forward secrecy (important for first message)
//! - All prekey private keys should be stored securely

use crate::chat::identity::{IdentityKey, IdentityKeyPair};
use crate::crypto::Signature;
use crate::error::{PqpgpError, Result};
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::ZeroizeOnDrop;

/// Unique identifier for prekeys.
pub type PreKeyId = u32;

/// A signed prekey for key agreement.
///
/// This is an ML-KEM-1024 public key signed by the owner's identity key.
/// It's used in X3DH to provide asynchronous key agreement while ensuring
/// the key actually belongs to the claimed identity.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPreKey {
    /// Unique identifier for this prekey
    id: PreKeyId,
    /// The ML-KEM-1024 public key bytes
    public_key: Vec<u8>,
    /// Signature from the identity key
    signature: Signature,
    /// Creation timestamp
    created: u64,
}

impl fmt::Debug for SignedPreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedPreKey")
            .field("id", &self.id)
            .field("public_key_size", &self.public_key.len())
            .field("created", &self.created)
            .finish()
    }
}

impl fmt::Display for SignedPreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignedPreKey(id={})", self.id)
    }
}

impl SignedPreKey {
    /// Creates a new signed prekey from raw components.
    ///
    /// This is used when constructing prekeys outside the PreKeyGenerator,
    /// such as in the forum's EncryptionIdentityGenerator.
    ///
    /// # Arguments
    /// * `id` - Unique prekey identifier
    /// * `public_key` - ML-KEM-1024 public key bytes
    /// * `signature` - Signature from identity key
    /// * `created` - Creation timestamp (Unix seconds)
    pub fn new_raw(id: PreKeyId, public_key: Vec<u8>, signature: Signature, created: u64) -> Self {
        Self {
            id,
            public_key,
            signature,
            created,
        }
    }

    /// Returns the prekey ID.
    pub fn id(&self) -> PreKeyId {
        self.id
    }

    /// Returns the public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns the signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the creation timestamp.
    pub fn created(&self) -> u64 {
        self.created
    }

    /// Verifies the signature on this prekey.
    ///
    /// # Arguments
    /// * `identity_key` - The identity key that should have signed this prekey
    ///
    /// # Errors
    /// Returns an error if the signature is invalid.
    pub fn verify(&self, identity_key: &IdentityKey) -> Result<()> {
        let message = self.signing_data();
        identity_key.verify(&message, &self.signature)
    }

    /// Returns the data that is/was signed.
    fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"PQPGP-signed-prekey-v1");
        data.extend_from_slice(&self.id.to_be_bytes());
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(&self.created.to_be_bytes());
        data
    }

    /// Parses the ML-KEM public key.
    pub(crate) fn as_mlkem_public(&self) -> Result<mlkem1024::PublicKey> {
        mlkem1024::PublicKey::from_bytes(&self.public_key)
            .map_err(|_| PqpgpError::prekey("Invalid ML-KEM-1024 public key in signed prekey"))
    }
}

/// Private component of a signed prekey.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct SignedPreKeyPrivate {
    /// Prekey ID (matches public)
    id: PreKeyId,
    /// The ML-KEM-1024 secret key bytes
    secret_key: Vec<u8>,
}

impl fmt::Debug for SignedPreKeyPrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedPreKeyPrivate")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl SignedPreKeyPrivate {
    /// Returns the prekey ID.
    pub fn id(&self) -> PreKeyId {
        self.id
    }

    /// Parses the ML-KEM secret key.
    pub(crate) fn as_mlkem_secret(&self) -> Result<mlkem1024::SecretKey> {
        mlkem1024::SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| PqpgpError::prekey("Invalid ML-KEM-1024 secret key"))
    }

    /// Returns the raw secret key bytes.
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }
}

/// A one-time prekey for enhanced forward secrecy.
///
/// These keys are used exactly once and then deleted, providing
/// additional forward secrecy for the first message in a session.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OneTimePreKey {
    /// Unique identifier for this prekey
    id: PreKeyId,
    /// The ML-KEM-1024 public key bytes
    public_key: Vec<u8>,
}

impl fmt::Debug for OneTimePreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneTimePreKey")
            .field("id", &self.id)
            .field("public_key_size", &self.public_key.len())
            .finish()
    }
}

impl fmt::Display for OneTimePreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OneTimePreKey(id={})", self.id)
    }
}

impl OneTimePreKey {
    /// Creates a new one-time prekey from raw components.
    ///
    /// This is used when constructing prekeys outside the PreKeyGenerator,
    /// such as in the forum's EncryptionIdentityGenerator.
    ///
    /// # Arguments
    /// * `id` - Unique prekey identifier
    /// * `public_key` - ML-KEM-1024 public key bytes
    pub fn new_raw(id: PreKeyId, public_key: Vec<u8>) -> Self {
        Self { id, public_key }
    }

    /// Returns the prekey ID.
    pub fn id(&self) -> PreKeyId {
        self.id
    }

    /// Returns the public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Parses the ML-KEM public key.
    pub(crate) fn as_mlkem_public(&self) -> Result<mlkem1024::PublicKey> {
        mlkem1024::PublicKey::from_bytes(&self.public_key)
            .map_err(|_| PqpgpError::prekey("Invalid ML-KEM-1024 public key in one-time prekey"))
    }
}

/// Private component of a one-time prekey.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct OneTimePreKeyPrivate {
    /// Prekey ID (matches public)
    id: PreKeyId,
    /// The ML-KEM-1024 secret key bytes
    secret_key: Vec<u8>,
}

impl fmt::Debug for OneTimePreKeyPrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneTimePreKeyPrivate")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl OneTimePreKeyPrivate {
    /// Returns the prekey ID.
    pub fn id(&self) -> PreKeyId {
        self.id
    }

    /// Parses the ML-KEM secret key.
    pub(crate) fn as_mlkem_secret(&self) -> Result<mlkem1024::SecretKey> {
        mlkem1024::SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| PqpgpError::prekey("Invalid ML-KEM-1024 secret key"))
    }
}

/// A complete prekey bundle for publishing to a server.
///
/// This contains all the public keys needed for someone to establish
/// an encrypted session with the bundle owner.
#[derive(Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// The owner's identity key
    identity_key: IdentityKey,
    /// The signed prekey
    signed_prekey: SignedPreKey,
    /// Optional one-time prekey (one per bundle request)
    one_time_prekey: Option<OneTimePreKey>,
}

impl fmt::Debug for PreKeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreKeyBundle")
            .field("identity_key", &self.identity_key)
            .field("signed_prekey", &self.signed_prekey)
            .field("has_one_time_prekey", &self.one_time_prekey.is_some())
            .finish()
    }
}

impl PreKeyBundle {
    /// Creates a new prekey bundle.
    ///
    /// # Arguments
    /// * `identity_key` - The owner's identity key
    /// * `signed_prekey` - A signed prekey
    /// * `one_time_prekey` - Optional one-time prekey
    pub fn new(
        identity_key: IdentityKey,
        signed_prekey: SignedPreKey,
        one_time_prekey: Option<OneTimePreKey>,
    ) -> Self {
        Self {
            identity_key,
            signed_prekey,
            one_time_prekey,
        }
    }

    /// Returns the identity key.
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    /// Returns the signed prekey.
    pub fn signed_prekey(&self) -> &SignedPreKey {
        &self.signed_prekey
    }

    /// Returns the one-time prekey if present.
    pub fn one_time_prekey(&self) -> Option<&OneTimePreKey> {
        self.one_time_prekey.as_ref()
    }

    /// Verifies the bundle's signature and validates all keys are well-formed.
    ///
    /// This ensures:
    /// 1. The identity key is a valid ML-DSA-87 public key
    /// 2. The signed prekey is a valid ML-KEM-1024 public key
    /// 3. The signed prekey signature is valid (signed by the identity key)
    /// 4. The one-time prekey (if present) is a valid ML-KEM-1024 public key
    pub fn verify(&self) -> Result<()> {
        // 1. Validate identity key is well-formed (can be parsed as ML-DSA-87)
        self.identity_key
            .as_public_key()
            .map_err(|_| PqpgpError::prekey("Invalid identity key in prekey bundle"))?;

        // 2. Validate signed prekey is well-formed (can be parsed as ML-KEM-1024)
        self.signed_prekey
            .as_mlkem_public()
            .map_err(|_| PqpgpError::prekey("Invalid signed prekey in prekey bundle"))?;

        // 3. Verify the signature on the signed prekey
        self.signed_prekey.verify(&self.identity_key)?;

        // 4. Validate one-time prekey if present
        if let Some(otpk) = &self.one_time_prekey {
            otpk.as_mlkem_public()
                .map_err(|_| PqpgpError::prekey("Invalid one-time prekey in prekey bundle"))?;
        }

        Ok(())
    }
}

/// Generator for prekeys and prekey bundles.
///
/// This handles the creation of signed prekeys and one-time prekeys,
/// maintaining the private keys for later use in session establishment.
#[derive(Serialize, Deserialize)]
pub struct PreKeyGenerator {
    /// Current signed prekey (public part)
    signed_prekey: SignedPreKey,
    /// Current signed prekey (private part)
    signed_prekey_private: SignedPreKeyPrivate,
    /// Pool of one-time prekeys (public parts)
    one_time_prekeys: Vec<OneTimePreKey>,
    /// Pool of one-time prekey private keys
    one_time_prekeys_private: Vec<OneTimePreKeyPrivate>,
    /// Next prekey ID to use
    next_id: PreKeyId,
}

impl fmt::Debug for PreKeyGenerator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreKeyGenerator")
            .field("signed_prekey_id", &self.signed_prekey.id())
            .field("one_time_prekey_count", &self.one_time_prekeys.len())
            .field("next_id", &self.next_id)
            .finish()
    }
}

impl PreKeyGenerator {
    /// Creates a new prekey generator with initial keys.
    ///
    /// # Arguments
    /// * `identity` - The identity to sign prekeys with
    /// * `initial_one_time_count` - Number of one-time prekeys to generate initially
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use pqpgp::chat::IdentityKeyPair;
    /// use pqpgp::chat::prekey::PreKeyGenerator;
    ///
    /// let identity = IdentityKeyPair::generate()?;
    /// let generator = PreKeyGenerator::new(&identity, 100)?;
    /// # Ok::<(), pqpgp::error::PqpgpError>(())
    /// ```
    pub fn new(identity: &IdentityKeyPair, initial_one_time_count: u32) -> Result<Self> {
        let mut next_id: PreKeyId = 1;

        // Generate signed prekey
        let (signed_prekey, signed_prekey_private) =
            Self::generate_signed_prekey(identity, next_id)?;
        next_id += 1;

        // Generate one-time prekeys
        let mut one_time_prekeys = Vec::with_capacity(initial_one_time_count as usize);
        let mut one_time_prekeys_private = Vec::with_capacity(initial_one_time_count as usize);

        for _ in 0..initial_one_time_count {
            let (public, private) = Self::generate_one_time_prekey(next_id)?;
            one_time_prekeys.push(public);
            one_time_prekeys_private.push(private);
            next_id += 1;
        }

        Ok(Self {
            signed_prekey,
            signed_prekey_private,
            one_time_prekeys,
            one_time_prekeys_private,
            next_id,
        })
    }

    /// Generates a new signed prekey.
    fn generate_signed_prekey(
        identity: &IdentityKeyPair,
        id: PreKeyId,
    ) -> Result<(SignedPreKey, SignedPreKeyPrivate)> {
        let (public_key, secret_key) = mlkem1024::keypair();

        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let public_bytes = KemPublicKey::as_bytes(&public_key).to_vec();
        let secret_bytes = KemSecretKey::as_bytes(&secret_key).to_vec();

        // Compute signing data directly (matches SignedPreKey::signing_data format)
        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(b"PQPGP-signed-prekey-v1");
        signing_data.extend_from_slice(&id.to_be_bytes());
        signing_data.extend_from_slice(&public_bytes);
        signing_data.extend_from_slice(&created.to_be_bytes());

        // Sign the prekey data
        let signature = identity.sign(&signing_data, None)?;

        let prekey = SignedPreKey {
            id,
            public_key: public_bytes,
            signature,
            created,
        };

        let private = SignedPreKeyPrivate {
            id,
            secret_key: secret_bytes,
        };

        Ok((prekey, private))
    }

    /// Generates a new one-time prekey.
    fn generate_one_time_prekey(id: PreKeyId) -> Result<(OneTimePreKey, OneTimePreKeyPrivate)> {
        let (public_key, secret_key) = mlkem1024::keypair();

        let public_bytes = KemPublicKey::as_bytes(&public_key).to_vec();
        let secret_bytes = KemSecretKey::as_bytes(&secret_key).to_vec();

        let public = OneTimePreKey {
            id,
            public_key: public_bytes,
        };

        let private = OneTimePreKeyPrivate {
            id,
            secret_key: secret_bytes,
        };

        Ok((public, private))
    }

    /// Creates a prekey bundle for publishing.
    ///
    /// This returns a bundle containing the identity key, signed prekey,
    /// and optionally one one-time prekey.
    ///
    /// # Arguments
    /// * `identity` - The identity to include in the bundle
    /// * `include_one_time` - Whether to include a one-time prekey
    pub fn create_bundle(
        &self,
        identity: &IdentityKeyPair,
        include_one_time: bool,
    ) -> PreKeyBundle {
        let one_time = if include_one_time {
            self.one_time_prekeys.first().cloned()
        } else {
            None
        };

        PreKeyBundle::new(
            identity.public.clone(),
            self.signed_prekey.clone(),
            one_time,
        )
    }

    /// Consumes a one-time prekey (after it's been used).
    ///
    /// Returns the private key for the consumed prekey.
    ///
    /// # Arguments
    /// * `id` - The ID of the prekey that was used
    ///
    /// # Security
    /// SECURITY FIX: Uses ID-based lookup for both public and private key vectors
    /// to prevent index misalignment if they become out of sync.
    pub fn consume_one_time_prekey(&mut self, id: PreKeyId) -> Option<OneTimePreKeyPrivate> {
        // Find and remove from public keys by ID
        let public_pos = self.one_time_prekeys.iter().position(|p| p.id == id)?;
        self.one_time_prekeys.remove(public_pos);

        // Find and remove from private keys by ID (not by index)
        // This ensures we get the correct private key even if vectors are misaligned
        let private_pos = self
            .one_time_prekeys_private
            .iter()
            .position(|p| p.id == id)?;
        Some(self.one_time_prekeys_private.remove(private_pos))
    }

    /// Generates additional one-time prekeys.
    ///
    /// # Arguments
    /// * `count` - Number of new prekeys to generate
    pub fn generate_more_one_time_prekeys(&mut self, count: u32) -> Result<Vec<OneTimePreKey>> {
        let mut new_prekeys = Vec::with_capacity(count as usize);

        for _ in 0..count {
            let (public, private) = Self::generate_one_time_prekey(self.next_id)?;
            new_prekeys.push(public.clone());
            self.one_time_prekeys.push(public);
            self.one_time_prekeys_private.push(private);
            self.next_id += 1;
        }

        Ok(new_prekeys)
    }

    /// Rotates the signed prekey.
    ///
    /// This generates a new signed prekey and archives the old one.
    /// The old prekey should be kept for a period to handle in-flight messages.
    ///
    /// # Arguments
    /// * `identity` - The identity to sign the new prekey with
    pub fn rotate_signed_prekey(
        &mut self,
        identity: &IdentityKeyPair,
    ) -> Result<(SignedPreKey, SignedPreKeyPrivate)> {
        let old_prekey = self.signed_prekey.clone();
        let old_private = self.signed_prekey_private.clone();

        let (new_prekey, new_private) = Self::generate_signed_prekey(identity, self.next_id)?;
        self.next_id += 1;

        self.signed_prekey = new_prekey;
        self.signed_prekey_private = new_private;

        Ok((old_prekey, old_private))
    }

    /// Returns the current signed prekey.
    pub fn signed_prekey(&self) -> &SignedPreKey {
        &self.signed_prekey
    }

    /// Returns the signed prekey private key.
    pub fn signed_prekey_private(&self) -> &SignedPreKeyPrivate {
        &self.signed_prekey_private
    }

    /// Returns the count of available one-time prekeys.
    pub fn one_time_prekey_count(&self) -> usize {
        self.one_time_prekeys.len()
    }

    /// Returns all one-time prekeys (for bulk upload to server).
    pub fn one_time_prekeys(&self) -> &[OneTimePreKey] {
        &self.one_time_prekeys
    }

    /// Finds a one-time prekey private by ID.
    pub fn find_one_time_prekey_private(&self, id: PreKeyId) -> Option<&OneTimePreKeyPrivate> {
        self.one_time_prekeys_private.iter().find(|p| p.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_prekey_generation() {
        let identity = IdentityKeyPair::generate().unwrap();
        let (prekey, private) = PreKeyGenerator::generate_signed_prekey(&identity, 1).unwrap();

        assert_eq!(prekey.id(), 1);
        assert_eq!(private.id(), 1);
        assert!(!prekey.public_key().is_empty());

        // Signature should verify
        prekey.verify(&identity.public).unwrap();
    }

    #[test]
    fn test_signed_prekey_verification_fails_wrong_identity() {
        let identity1 = IdentityKeyPair::generate().unwrap();
        let identity2 = IdentityKeyPair::generate().unwrap();

        let (prekey, _) = PreKeyGenerator::generate_signed_prekey(&identity1, 1).unwrap();

        // Should fail verification with wrong identity
        assert!(prekey.verify(&identity2.public).is_err());
    }

    #[test]
    fn test_one_time_prekey_generation() {
        let (prekey, private) = PreKeyGenerator::generate_one_time_prekey(42).unwrap();

        assert_eq!(prekey.id(), 42);
        assert_eq!(private.id(), 42);
        assert!(!prekey.public_key().is_empty());
    }

    #[test]
    fn test_prekey_generator() {
        let identity = IdentityKeyPair::generate().unwrap();
        let generator = PreKeyGenerator::new(&identity, 10).unwrap();

        assert_eq!(generator.one_time_prekey_count(), 10);
        assert!(generator.signed_prekey().id() > 0);
    }

    #[test]
    fn test_prekey_bundle_creation() {
        let identity = IdentityKeyPair::generate().unwrap();
        let generator = PreKeyGenerator::new(&identity, 5).unwrap();

        let bundle = generator.create_bundle(&identity, true);

        assert_eq!(bundle.identity_key().key_id(), identity.key_id());
        assert!(bundle.one_time_prekey().is_some());

        // Bundle should verify
        bundle.verify().unwrap();
    }

    #[test]
    fn test_prekey_bundle_without_one_time() {
        let identity = IdentityKeyPair::generate().unwrap();
        let generator = PreKeyGenerator::new(&identity, 5).unwrap();

        let bundle = generator.create_bundle(&identity, false);

        assert!(bundle.one_time_prekey().is_none());
        bundle.verify().unwrap();
    }

    #[test]
    fn test_consume_one_time_prekey() {
        let identity = IdentityKeyPair::generate().unwrap();
        let mut generator = PreKeyGenerator::new(&identity, 5).unwrap();

        let initial_count = generator.one_time_prekey_count();
        let prekey_id = generator.one_time_prekeys()[0].id();

        let private = generator.consume_one_time_prekey(prekey_id);
        assert!(private.is_some());
        assert_eq!(private.unwrap().id(), prekey_id);
        assert_eq!(generator.one_time_prekey_count(), initial_count - 1);
    }

    #[test]
    fn test_generate_more_one_time_prekeys() {
        let identity = IdentityKeyPair::generate().unwrap();
        let mut generator = PreKeyGenerator::new(&identity, 5).unwrap();

        let initial_count = generator.one_time_prekey_count();
        let new_prekeys = generator.generate_more_one_time_prekeys(10).unwrap();

        assert_eq!(new_prekeys.len(), 10);
        assert_eq!(generator.one_time_prekey_count(), initial_count + 10);
    }

    #[test]
    fn test_rotate_signed_prekey() {
        let identity = IdentityKeyPair::generate().unwrap();
        let mut generator = PreKeyGenerator::new(&identity, 5).unwrap();

        let old_id = generator.signed_prekey().id();
        let (old_prekey, _old_private) = generator.rotate_signed_prekey(&identity).unwrap();

        assert_eq!(old_prekey.id(), old_id);
        assert_ne!(generator.signed_prekey().id(), old_id);

        // New prekey should verify
        generator.signed_prekey().verify(&identity.public).unwrap();
    }

    #[test]
    fn test_prekey_mlkem_conversion() {
        let identity = IdentityKeyPair::generate().unwrap();
        let (prekey, private) = PreKeyGenerator::generate_signed_prekey(&identity, 1).unwrap();

        // Should be able to convert to ML-KEM types
        let _public = prekey.as_mlkem_public().unwrap();
        let _secret = private.as_mlkem_secret().unwrap();
    }

    #[test]
    fn test_prekey_bundle_serialization() {
        let identity = IdentityKeyPair::generate().unwrap();
        let generator = PreKeyGenerator::new(&identity, 5).unwrap();
        let bundle = generator.create_bundle(&identity, true);

        // Serialize and deserialize
        let serialized = bincode::serialize(&bundle).unwrap();
        let deserialized: PreKeyBundle = bincode::deserialize(&serialized).unwrap();

        assert_eq!(
            deserialized.identity_key().key_id(),
            bundle.identity_key().key_id()
        );
        assert_eq!(
            deserialized.signed_prekey().id(),
            bundle.signed_prekey().id()
        );

        // Deserialized bundle should still verify
        deserialized.verify().unwrap();
    }
}
