//! Board genesis node for the DAG-based forum system.
//!
//! A BoardGenesis creates a new discussion board within a forum. It references
//! the forum genesis node and must be created by a user with moderator privileges
//! (the forum owner or an appointed moderator).
//!
//! Boards organize discussions into categories. Each board can contain multiple
//! threads, and threads contain posts.

use crate::crypto::{sign_data, verify_data_signature, PublicKey, Signature};
use crate::error::{PqpgpError, Result};
use crate::forum::types::{current_timestamp_millis, ContentHash, NodeType};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum length for board name in characters.
pub const MAX_BOARD_NAME_LENGTH: usize = 100;

/// Maximum length for board description in characters.
pub const MAX_BOARD_DESCRIPTION_LENGTH: usize = 5_000;

/// The content of a board genesis node that gets signed and hashed.
///
/// This structure is serialized with bincode for deterministic hashing and signing.
/// The content hash of this struct becomes the board's unique identifier.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoardGenesisContent {
    /// Node type discriminator (always BoardGenesis).
    pub node_type: NodeType,
    /// Hash of the parent forum genesis.
    pub forum_hash: ContentHash,
    /// Human-readable board name.
    pub name: String,
    /// Board description explaining its purpose.
    pub description: String,
    /// Public key bytes of the board creator.
    pub creator_identity: Vec<u8>,
    /// Creation timestamp in milliseconds since Unix epoch.
    pub created_at: u64,
}

impl fmt::Debug for BoardGenesisContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoardGenesisContent")
            .field("node_type", &self.node_type)
            .field("forum_hash", &self.forum_hash)
            .field("name", &self.name)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl BoardGenesisContent {
    /// Creates new board genesis content.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the parent forum genesis
    /// * `name` - Human-readable board name (1-100 characters)
    /// * `description` - Board description (up to 5,000 characters)
    /// * `creator_public_key` - Public key of the board creator
    ///
    /// # Errors
    /// Returns an error if:
    /// - Name is empty or exceeds 100 characters
    /// - Description exceeds 5,000 characters
    pub fn new(
        forum_hash: ContentHash,
        name: String,
        description: String,
        creator_public_key: &PublicKey,
    ) -> Result<Self> {
        // Validate name
        if name.is_empty() {
            return Err(PqpgpError::validation("Board name cannot be empty"));
        }
        if name.len() > MAX_BOARD_NAME_LENGTH {
            return Err(PqpgpError::validation(format!(
                "Board name exceeds maximum length of {} characters",
                MAX_BOARD_NAME_LENGTH
            )));
        }

        // Validate description
        if description.len() > MAX_BOARD_DESCRIPTION_LENGTH {
            return Err(PqpgpError::validation(format!(
                "Board description exceeds maximum length of {} characters",
                MAX_BOARD_DESCRIPTION_LENGTH
            )));
        }

        Ok(Self {
            node_type: NodeType::BoardGenesis,
            forum_hash,
            name,
            description,
            creator_identity: creator_public_key.as_bytes(),
            created_at: current_timestamp_millis(),
        })
    }

    /// Computes the content hash of this board genesis content.
    pub fn content_hash(&self) -> Result<ContentHash> {
        ContentHash::compute(self)
    }
}

/// A complete board genesis node with content, signature, and content hash.
///
/// Boards organize threads within a forum. Only moderators can create boards.
#[derive(Clone, Serialize, Deserialize)]
pub struct BoardGenesis {
    /// The signed content of this node.
    pub content: BoardGenesisContent,
    /// ML-DSA-87 signature over the content.
    pub signature: Signature,
    /// Content hash - the unique identifier of this node.
    pub content_hash: ContentHash,
}

impl fmt::Debug for BoardGenesis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoardGenesis")
            .field("name", &self.content.name)
            .field("forum_hash", &self.content.forum_hash)
            .field("content_hash", &self.content_hash)
            .finish()
    }
}

impl BoardGenesis {
    /// Creates and signs a new board genesis node.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the parent forum genesis
    /// * `name` - Human-readable board name
    /// * `description` - Board description
    /// * `creator_public_key` - Public key of the board creator
    /// * `creator_private_key` - Private key to sign with
    /// * `password` - Optional password if the private key is encrypted
    ///
    /// # Errors
    /// Returns an error if validation fails or signing fails.
    ///
    /// # Note
    /// Permission checking (whether the creator is a moderator) is not done here.
    /// It must be validated at the application layer when accepting nodes into the DAG.
    pub fn create(
        forum_hash: ContentHash,
        name: String,
        description: String,
        creator_public_key: &PublicKey,
        creator_private_key: &crate::crypto::PrivateKey,
        password: Option<&crate::crypto::Password>,
    ) -> Result<Self> {
        let content = BoardGenesisContent::new(forum_hash, name, description, creator_public_key)?;
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
    ///
    /// # Note
    /// This does not verify that the creator has permission to create boards.
    /// Permission checking must be done at the application layer.
    pub fn verify(&self, creator_public_key: &PublicKey) -> Result<()> {
        // Verify content hash
        let computed_hash = self.content.content_hash()?;
        if computed_hash != self.content_hash {
            return Err(PqpgpError::validation(
                "Board genesis content hash mismatch",
            ));
        }

        // Verify signature
        verify_data_signature(creator_public_key, &self.content, &self.signature)?;

        Ok(())
    }

    /// Returns the board name.
    pub fn name(&self) -> &str {
        &self.content.name
    }

    /// Returns the board description.
    pub fn description(&self) -> &str {
        &self.content.description
    }

    /// Returns the parent forum hash.
    pub fn forum_hash(&self) -> &ContentHash {
        &self.content.forum_hash
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
    use crate::forum::ForumGenesis;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
    }

    fn create_test_forum(keypair: &KeyPair) -> ForumGenesis {
        ForumGenesis::create(
            "Test Forum".to_string(),
            "A test forum".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create forum")
    }

    #[test]
    fn test_board_genesis_creation() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let board = BoardGenesis::create(
            *forum.hash(),
            "Test Board".to_string(),
            "A test board for discussions".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board genesis");

        assert_eq!(board.name(), "Test Board");
        assert_eq!(board.description(), "A test board for discussions");
        assert_eq!(board.forum_hash(), forum.hash());
        assert_eq!(board.node_type(), NodeType::BoardGenesis);
    }

    #[test]
    fn test_board_genesis_verification() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let board = BoardGenesis::create(
            *forum.hash(),
            "Verified Board".to_string(),
            "Testing verification".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board genesis");

        board
            .verify(keypair.public_key())
            .expect("Verification failed");
    }

    #[test]
    fn test_board_genesis_verification_wrong_key() {
        let creator_keypair = create_test_keypair();
        let other_keypair = create_test_keypair();
        let forum = create_test_forum(&creator_keypair);

        let board = BoardGenesis::create(
            *forum.hash(),
            "Board".to_string(),
            "Description".to_string(),
            creator_keypair.public_key(),
            creator_keypair.private_key(),
            None,
        )
        .expect("Failed to create board genesis");

        assert!(board.verify(other_keypair.public_key()).is_err());
    }

    #[test]
    fn test_board_genesis_empty_name_rejected() {
        let keypair = create_test_keypair();
        let forum_hash = ContentHash::from_bytes([0u8; 64]);

        let result = BoardGenesisContent::new(
            forum_hash,
            "".to_string(),
            "Description".to_string(),
            keypair.public_key(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_board_genesis_name_too_long() {
        let keypair = create_test_keypair();
        let forum_hash = ContentHash::from_bytes([0u8; 64]);

        let long_name = "x".repeat(MAX_BOARD_NAME_LENGTH + 1);
        let result = BoardGenesisContent::new(
            forum_hash,
            long_name,
            "Description".to_string(),
            keypair.public_key(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_board_genesis_serialization_roundtrip() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let board = BoardGenesis::create(
            *forum.hash(),
            "Serialization Test".to_string(),
            "Testing serialization".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board genesis");

        let serialized = bincode::serialize(&board).expect("Failed to serialize");
        let deserialized: BoardGenesis =
            bincode::deserialize(&serialized).expect("Failed to deserialize");

        assert_eq!(board.name(), deserialized.name());
        assert_eq!(board.description(), deserialized.description());
        assert_eq!(board.content_hash, deserialized.content_hash);

        deserialized
            .verify(keypair.public_key())
            .expect("Verification failed after deserialization");
    }
}
