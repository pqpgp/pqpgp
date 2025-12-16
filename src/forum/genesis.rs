//! Forum genesis node for the DAG-based forum system.
//!
//! The ForumGenesis is the root node of a forum DAG. It contains:
//! - Forum name and description
//! - Creator identity (who can manage moderators)
//! - Creation timestamp
//!
//! All other nodes in the forum DAG ultimately trace back to this genesis node.
//! The creator of the forum genesis is automatically the first moderator with
//! full administrative privileges.

use crate::crypto::{sign_data, verify_data_signature, PublicKey, Signature};
use crate::error::{PqpgpError, Result};
use crate::forum::types::{current_timestamp_millis, ContentHash, NodeType};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum length for forum name in characters.
pub const MAX_FORUM_NAME_LENGTH: usize = 100;

/// Maximum length for forum description in characters.
pub const MAX_FORUM_DESCRIPTION_LENGTH: usize = 10_000;

/// The content of a forum genesis node that gets signed and hashed.
///
/// This structure is serialized with bincode for deterministic hashing and signing.
/// The content hash of this struct becomes the forum's unique identifier.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForumGenesisContent {
    /// Node type discriminator (always ForumGenesis).
    pub node_type: NodeType,
    /// Human-readable forum name.
    pub name: String,
    /// Forum description explaining its purpose.
    pub description: String,
    /// Public key bytes of the forum creator.
    /// The creator has full administrative privileges.
    pub creator_identity: Vec<u8>,
    /// Creation timestamp in milliseconds since Unix epoch.
    pub created_at: u64,
}

impl fmt::Debug for ForumGenesisContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForumGenesisContent")
            .field("node_type", &self.node_type)
            .field("name", &self.name)
            .field("description_len", &self.description.len())
            .field("creator_identity_len", &self.creator_identity.len())
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl ForumGenesisContent {
    /// Creates new forum genesis content.
    ///
    /// # Arguments
    /// * `name` - Human-readable forum name (1-100 characters)
    /// * `description` - Forum description (up to 10,000 characters)
    /// * `creator_public_key` - Public key of the forum creator
    ///
    /// # Errors
    /// Returns an error if:
    /// - Name is empty or exceeds 100 characters
    /// - Description exceeds 10,000 characters
    pub fn new(name: String, description: String, creator_public_key: &PublicKey) -> Result<Self> {
        // Validate name
        if name.is_empty() {
            return Err(PqpgpError::validation("Forum name cannot be empty"));
        }
        if name.len() > MAX_FORUM_NAME_LENGTH {
            return Err(PqpgpError::validation(format!(
                "Forum name exceeds maximum length of {} characters",
                MAX_FORUM_NAME_LENGTH
            )));
        }

        // Validate description
        if description.len() > MAX_FORUM_DESCRIPTION_LENGTH {
            return Err(PqpgpError::validation(format!(
                "Forum description exceeds maximum length of {} characters",
                MAX_FORUM_DESCRIPTION_LENGTH
            )));
        }

        Ok(Self {
            node_type: NodeType::ForumGenesis,
            name,
            description,
            creator_identity: creator_public_key.as_bytes(),
            created_at: current_timestamp_millis(),
        })
    }

    /// Computes the content hash of this genesis content.
    pub fn content_hash(&self) -> Result<ContentHash> {
        ContentHash::compute(self)
    }
}

/// A complete forum genesis node with content, signature, and content hash.
///
/// This is the root node of a forum DAG. It contains:
/// - The content (name, description, creator)
/// - A signature from the creator
/// - The content hash (serves as the node's unique identifier)
#[derive(Clone, Serialize, Deserialize)]
pub struct ForumGenesis {
    /// The signed content of this node.
    pub content: ForumGenesisContent,
    /// ML-DSA-87 signature over the content.
    pub signature: Signature,
    /// Content hash - the unique identifier of this node.
    pub content_hash: ContentHash,
}

impl fmt::Debug for ForumGenesis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForumGenesis")
            .field("name", &self.content.name)
            .field("content_hash", &self.content_hash)
            .field("created_at", &self.content.created_at)
            .finish()
    }
}

impl ForumGenesis {
    /// Creates and signs a new forum genesis node.
    ///
    /// # Arguments
    /// * `name` - Human-readable forum name
    /// * `description` - Forum description
    /// * `creator_public_key` - Public key of the forum creator
    /// * `creator_private_key` - Private key to sign with (must match public key)
    /// * `password` - Optional password if the private key is encrypted
    ///
    /// # Errors
    /// Returns an error if validation fails or signing fails.
    pub fn create(
        name: String,
        description: String,
        creator_public_key: &PublicKey,
        creator_private_key: &crate::crypto::PrivateKey,
        password: Option<&crate::crypto::Password>,
    ) -> Result<Self> {
        let content = ForumGenesisContent::new(name, description, creator_public_key)?;
        let content_hash = content.content_hash()?;
        let signature = sign_data(creator_private_key, &content, password)?;

        Ok(Self {
            content,
            signature,
            content_hash,
        })
    }

    /// Verifies the signature and content hash of this node.
    ///
    /// # Arguments
    /// * `creator_public_key` - Public key to verify the signature against
    ///
    /// # Errors
    /// Returns an error if:
    /// - The content hash doesn't match the computed hash
    /// - The signature is invalid
    pub fn verify(&self, creator_public_key: &PublicKey) -> Result<()> {
        // Verify content hash
        let computed_hash = self.content.content_hash()?;
        if computed_hash != self.content_hash {
            return Err(PqpgpError::validation(
                "Forum genesis content hash mismatch",
            ));
        }

        // Verify signature
        verify_data_signature(creator_public_key, &self.content, &self.signature)?;

        Ok(())
    }

    /// Returns the forum name.
    pub fn name(&self) -> &str {
        &self.content.name
    }

    /// Returns the forum description.
    pub fn description(&self) -> &str {
        &self.content.description
    }

    /// Returns the creator identity bytes.
    pub fn creator_identity(&self) -> &[u8] {
        &self.content.creator_identity
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
    }

    #[test]
    fn test_forum_genesis_creation() {
        let keypair = create_test_keypair();

        let forum = ForumGenesis::create(
            "Test Forum".to_string(),
            "A test forum for unit testing".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create forum genesis");

        assert_eq!(forum.name(), "Test Forum");
        assert_eq!(forum.description(), "A test forum for unit testing");
        assert_eq!(forum.node_type(), NodeType::ForumGenesis);
    }

    #[test]
    fn test_forum_genesis_verification() {
        let keypair = create_test_keypair();

        let forum = ForumGenesis::create(
            "Verified Forum".to_string(),
            "Testing verification".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create forum genesis");

        // Verification should succeed with correct key
        forum
            .verify(keypair.public_key())
            .expect("Verification failed");
    }

    #[test]
    fn test_forum_genesis_verification_wrong_key() {
        let creator_keypair = create_test_keypair();
        let other_keypair = create_test_keypair();

        let forum = ForumGenesis::create(
            "Forum".to_string(),
            "Description".to_string(),
            creator_keypair.public_key(),
            creator_keypair.private_key(),
            None,
        )
        .expect("Failed to create forum genesis");

        // Verification should fail with wrong key
        assert!(forum.verify(other_keypair.public_key()).is_err());
    }

    #[test]
    fn test_forum_genesis_content_hash_deterministic() {
        let keypair = create_test_keypair();

        // Create content manually with fixed timestamp
        let content = ForumGenesisContent {
            node_type: NodeType::ForumGenesis,
            name: "Deterministic Forum".to_string(),
            description: "Testing hash determinism".to_string(),
            creator_identity: keypair.public_key().as_bytes(),
            created_at: 1700000000000,
        };

        let hash1 = content.content_hash().unwrap();
        let hash2 = content.content_hash().unwrap();

        assert_eq!(hash1, hash2, "Same content should produce same hash");
    }

    #[test]
    fn test_forum_genesis_empty_name_rejected() {
        let keypair = create_test_keypair();

        let result = ForumGenesisContent::new(
            "".to_string(),
            "Description".to_string(),
            keypair.public_key(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_forum_genesis_name_too_long() {
        let keypair = create_test_keypair();

        let long_name = "x".repeat(MAX_FORUM_NAME_LENGTH + 1);
        let result =
            ForumGenesisContent::new(long_name, "Description".to_string(), keypair.public_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_forum_genesis_description_too_long() {
        let keypair = create_test_keypair();

        let long_description = "x".repeat(MAX_FORUM_DESCRIPTION_LENGTH + 1);
        let result =
            ForumGenesisContent::new("Forum".to_string(), long_description, keypair.public_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_forum_genesis_max_valid_lengths() {
        let keypair = create_test_keypair();

        // Maximum valid name length
        let max_name = "x".repeat(MAX_FORUM_NAME_LENGTH);
        let result =
            ForumGenesisContent::new(max_name, "Description".to_string(), keypair.public_key());
        assert!(result.is_ok());

        // Maximum valid description length
        let max_description = "x".repeat(MAX_FORUM_DESCRIPTION_LENGTH);
        let result =
            ForumGenesisContent::new("Forum".to_string(), max_description, keypair.public_key());
        assert!(result.is_ok());
    }

    #[test]
    fn test_forum_genesis_serialization_roundtrip() {
        let keypair = create_test_keypair();

        let forum = ForumGenesis::create(
            "Serialization Test".to_string(),
            "Testing serialization".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create forum genesis");

        // Serialize and deserialize
        let serialized = bincode::serialize(&forum).expect("Failed to serialize");
        let deserialized: ForumGenesis =
            bincode::deserialize(&serialized).expect("Failed to deserialize");

        assert_eq!(forum.name(), deserialized.name());
        assert_eq!(forum.description(), deserialized.description());
        assert_eq!(forum.content_hash, deserialized.content_hash);

        // Verification should still work
        deserialized
            .verify(keypair.public_key())
            .expect("Verification failed after deserialization");
    }

    #[test]
    fn test_forum_genesis_content_hash_changes_with_content() {
        let keypair = create_test_keypair();
        let created_at = 1700000000000;

        let content1 = ForumGenesisContent {
            node_type: NodeType::ForumGenesis,
            name: "Forum A".to_string(),
            description: "Description".to_string(),
            creator_identity: keypair.public_key().as_bytes(),
            created_at,
        };

        let content2 = ForumGenesisContent {
            node_type: NodeType::ForumGenesis,
            name: "Forum B".to_string(),
            description: "Description".to_string(),
            creator_identity: keypair.public_key().as_bytes(),
            created_at,
        };

        let hash1 = content1.content_hash().unwrap();
        let hash2 = content2.content_hash().unwrap();

        assert_ne!(
            hash1, hash2,
            "Different content should produce different hashes"
        );
    }
}
