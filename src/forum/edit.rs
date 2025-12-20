//! Edit node for the DAG-based forum system.
//!
//! EditNode allows authorized users to update forum or board metadata:
//! - **Forum owner only**: Can edit forum name/description
//! - **Forum owner + forum moderators**: Can edit board name/description
//!
//! User content (threads and posts) is immutable and cannot be edited.
//! Content moderation is handled through hide/unhide actions instead.
//!
//! Edit nodes reference the original node by hash and provide the updated
//! field values. The most recent edit (by timestamp) for a given target
//! determines the current displayed values.

use crate::crypto::{sign_data, verify_data_signature, PublicKey, Signature};
use crate::error::{PqpgpError, Result};
use crate::forum::types::{current_timestamp_millis, ContentHash, NodeType};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum length for forum/board name in characters.
pub const MAX_EDIT_NAME_LENGTH: usize = 100;

/// Maximum length for forum/board description in characters.
pub const MAX_EDIT_DESCRIPTION_LENGTH: usize = 5_000;

/// The type of edit being performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EditType {
    /// Edit forum name and/or description. Requires forum owner.
    EditForum = 1,
    /// Edit board name and/or description. Requires forum owner or forum moderator.
    EditBoard = 2,
}

impl fmt::Display for EditType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EditType::EditForum => write!(f, "EditForum"),
            EditType::EditBoard => write!(f, "EditBoard"),
        }
    }
}

/// The content of an edit node that gets signed and hashed.
///
/// This structure is serialized with bincode for deterministic hashing and signing.
/// The content hash of this struct becomes the edit's unique identifier.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EditNodeContent {
    /// Node type discriminator (always Edit).
    pub node_type: NodeType,
    /// Hash of the forum this edit applies to.
    pub forum_hash: ContentHash,
    /// Hash of the target node being edited (forum genesis or board genesis).
    pub target_hash: ContentHash,
    /// The type of edit being performed.
    pub edit_type: EditType,
    /// New name (if being changed). None means keep existing.
    pub new_name: Option<String>,
    /// New description (if being changed). None means keep existing.
    pub new_description: Option<String>,
    /// Public key bytes of the user issuing this edit.
    pub editor_identity: Vec<u8>,
    /// Creation timestamp in milliseconds since Unix epoch.
    pub created_at: u64,
}

impl fmt::Debug for EditNodeContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EditNodeContent")
            .field("node_type", &self.node_type)
            .field("forum_hash", &self.forum_hash)
            .field("target_hash", &self.target_hash)
            .field("edit_type", &self.edit_type)
            .field("has_new_name", &self.new_name.is_some())
            .field("has_new_description", &self.new_description.is_some())
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl EditNodeContent {
    /// Creates new edit content for a forum.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum being edited (also the target)
    /// * `new_name` - New forum name, or None to keep existing
    /// * `new_description` - New forum description, or None to keep existing
    /// * `editor_public_key` - Public key of the editor (must be forum owner)
    ///
    /// # Errors
    /// Returns an error if:
    /// - Both new_name and new_description are None (nothing to edit)
    /// - Name exceeds 100 characters
    /// - Description exceeds 5,000 characters
    pub fn new_forum_edit(
        forum_hash: ContentHash,
        new_name: Option<String>,
        new_description: Option<String>,
        editor_public_key: &PublicKey,
    ) -> Result<Self> {
        // Must have at least one field to edit
        if new_name.is_none() && new_description.is_none() {
            return Err(PqpgpError::validation(
                "Edit must change at least one field (name or description)",
            ));
        }

        // Validate name if provided
        if let Some(ref name) = new_name {
            if name.is_empty() {
                return Err(PqpgpError::validation("Forum name cannot be empty"));
            }
            if name.len() > MAX_EDIT_NAME_LENGTH {
                return Err(PqpgpError::validation(format!(
                    "Forum name exceeds maximum length of {} characters",
                    MAX_EDIT_NAME_LENGTH
                )));
            }
        }

        // Validate description if provided
        if let Some(ref desc) = new_description {
            if desc.len() > MAX_EDIT_DESCRIPTION_LENGTH {
                return Err(PqpgpError::validation(format!(
                    "Forum description exceeds maximum length of {} characters",
                    MAX_EDIT_DESCRIPTION_LENGTH
                )));
            }
        }

        Ok(Self {
            node_type: NodeType::Edit,
            forum_hash,
            target_hash: forum_hash, // For forum edits, target is the forum itself
            edit_type: EditType::EditForum,
            new_name,
            new_description,
            editor_identity: editor_public_key.as_bytes(),
            created_at: current_timestamp_millis(),
        })
    }

    /// Creates new edit content for a board.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum containing the board
    /// * `board_hash` - Hash of the board being edited
    /// * `new_name` - New board name, or None to keep existing
    /// * `new_description` - New board description, or None to keep existing
    /// * `editor_public_key` - Public key of the editor (must be forum owner or moderator)
    ///
    /// # Errors
    /// Returns an error if:
    /// - Both new_name and new_description are None (nothing to edit)
    /// - Name exceeds 100 characters
    /// - Description exceeds 5,000 characters
    pub fn new_board_edit(
        forum_hash: ContentHash,
        board_hash: ContentHash,
        new_name: Option<String>,
        new_description: Option<String>,
        editor_public_key: &PublicKey,
    ) -> Result<Self> {
        // Must have at least one field to edit
        if new_name.is_none() && new_description.is_none() {
            return Err(PqpgpError::validation(
                "Edit must change at least one field (name or description)",
            ));
        }

        // Validate name if provided
        if let Some(ref name) = new_name {
            if name.is_empty() {
                return Err(PqpgpError::validation("Board name cannot be empty"));
            }
            if name.len() > MAX_EDIT_NAME_LENGTH {
                return Err(PqpgpError::validation(format!(
                    "Board name exceeds maximum length of {} characters",
                    MAX_EDIT_NAME_LENGTH
                )));
            }
        }

        // Validate description if provided
        if let Some(ref desc) = new_description {
            if desc.len() > MAX_EDIT_DESCRIPTION_LENGTH {
                return Err(PqpgpError::validation(format!(
                    "Board description exceeds maximum length of {} characters",
                    MAX_EDIT_DESCRIPTION_LENGTH
                )));
            }
        }

        Ok(Self {
            node_type: NodeType::Edit,
            forum_hash,
            target_hash: board_hash,
            edit_type: EditType::EditBoard,
            new_name,
            new_description,
            editor_identity: editor_public_key.as_bytes(),
            created_at: current_timestamp_millis(),
        })
    }

    /// Computes the content hash of this edit node content.
    pub fn content_hash(&self) -> Result<ContentHash> {
        ContentHash::compute(self)
    }
}

/// A complete edit node with content, signature, and content hash.
///
/// Edit nodes allow forum owners and moderators to update forum/board metadata.
/// The most recent edit for a target determines the current displayed values.
#[derive(Clone, Serialize, Deserialize)]
pub struct EditNode {
    /// The signed content of this node.
    pub content: EditNodeContent,
    /// ML-DSA-87 signature over the content.
    pub signature: Signature,
    /// Content hash - the unique identifier of this node.
    pub content_hash: ContentHash,
}

impl fmt::Debug for EditNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EditNode")
            .field("edit_type", &self.content.edit_type)
            .field("target_hash", &self.content.target_hash)
            .field("content_hash", &self.content_hash)
            .finish()
    }
}

impl EditNode {
    /// Creates and signs a new forum edit node.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum being edited
    /// * `new_name` - New forum name, or None to keep existing
    /// * `new_description` - New forum description, or None to keep existing
    /// * `editor_public_key` - Public key of the editor
    /// * `editor_private_key` - Private key to sign with
    /// * `password` - Optional password if the private key is encrypted
    ///
    /// # Errors
    /// Returns an error if validation fails or signing fails.
    ///
    /// # Note
    /// Permission checking (whether the editor is the forum owner) is not done here.
    /// It must be validated at the application layer when accepting nodes into the DAG.
    pub fn create_forum_edit(
        forum_hash: ContentHash,
        new_name: Option<String>,
        new_description: Option<String>,
        editor_public_key: &PublicKey,
        editor_private_key: &crate::crypto::PrivateKey,
        password: Option<&crate::crypto::Password>,
    ) -> Result<Self> {
        let content = EditNodeContent::new_forum_edit(
            forum_hash,
            new_name,
            new_description,
            editor_public_key,
        )?;
        let content_hash = content.content_hash()?;
        let signature = sign_data(editor_private_key, &content, password)?;

        Ok(Self {
            content,
            signature,
            content_hash,
        })
    }

    /// Creates and signs a new board edit node.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum containing the board
    /// * `board_hash` - Hash of the board being edited
    /// * `new_name` - New board name, or None to keep existing
    /// * `new_description` - New board description, or None to keep existing
    /// * `editor_public_key` - Public key of the editor
    /// * `editor_private_key` - Private key to sign with
    /// * `password` - Optional password if the private key is encrypted
    ///
    /// # Errors
    /// Returns an error if validation fails or signing fails.
    ///
    /// # Note
    /// Permission checking (whether the editor is the forum owner or moderator)
    /// is not done here. It must be validated at the application layer.
    pub fn create_board_edit(
        forum_hash: ContentHash,
        board_hash: ContentHash,
        new_name: Option<String>,
        new_description: Option<String>,
        editor_public_key: &PublicKey,
        editor_private_key: &crate::crypto::PrivateKey,
        password: Option<&crate::crypto::Password>,
    ) -> Result<Self> {
        let content = EditNodeContent::new_board_edit(
            forum_hash,
            board_hash,
            new_name,
            new_description,
            editor_public_key,
        )?;
        let content_hash = content.content_hash()?;
        let signature = sign_data(editor_private_key, &content, password)?;

        Ok(Self {
            content,
            signature,
            content_hash,
        })
    }

    /// Verifies the signature and content hash of this node.
    ///
    /// # Arguments
    /// * `editor_public_key` - Public key to verify the signature against
    ///
    /// # Errors
    /// Returns an error if:
    /// - The content hash doesn't match the computed hash
    /// - The signature is invalid
    ///
    /// # Note
    /// This does not verify that the editor has permission to make edits.
    /// Permission checking must be done at the application layer.
    pub fn verify(&self, editor_public_key: &PublicKey) -> Result<()> {
        // Verify content hash
        let computed_hash = self.content.content_hash()?;
        if computed_hash != self.content_hash {
            return Err(PqpgpError::validation("Edit node content hash mismatch"));
        }

        // Verify signature
        verify_data_signature(editor_public_key, &self.content, &self.signature)?;

        Ok(())
    }

    /// Returns the forum hash this edit applies to.
    pub fn forum_hash(&self) -> &ContentHash {
        &self.content.forum_hash
    }

    /// Returns the target node hash being edited.
    pub fn target_hash(&self) -> &ContentHash {
        &self.content.target_hash
    }

    /// Returns the edit type.
    pub fn edit_type(&self) -> EditType {
        self.content.edit_type
    }

    /// Returns the new name if being changed.
    pub fn new_name(&self) -> Option<&str> {
        self.content.new_name.as_deref()
    }

    /// Returns the new description if being changed.
    pub fn new_description(&self) -> Option<&str> {
        self.content.new_description.as_deref()
    }

    /// Returns the editor identity bytes.
    pub fn editor_identity(&self) -> &[u8] {
        &self.content.editor_identity
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
    use crate::forum::{BoardGenesis, ForumGenesis};

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

    fn create_test_board(keypair: &KeyPair, forum: &ForumGenesis) -> BoardGenesis {
        BoardGenesis::create(
            *forum.hash(),
            "Test Board".to_string(),
            "A test board".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board")
    }

    #[test]
    fn test_forum_edit_name_only() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let edit = EditNode::create_forum_edit(
            *forum.hash(),
            Some("New Forum Name".to_string()),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create forum edit");

        assert_eq!(edit.edit_type(), EditType::EditForum);
        assert_eq!(edit.target_hash(), forum.hash());
        assert_eq!(edit.new_name(), Some("New Forum Name"));
        assert!(edit.new_description().is_none());
    }

    #[test]
    fn test_forum_edit_description_only() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let edit = EditNode::create_forum_edit(
            *forum.hash(),
            None,
            Some("New description".to_string()),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create forum edit");

        assert!(edit.new_name().is_none());
        assert_eq!(edit.new_description(), Some("New description"));
    }

    #[test]
    fn test_forum_edit_both_fields() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let edit = EditNode::create_forum_edit(
            *forum.hash(),
            Some("New Name".to_string()),
            Some("New Description".to_string()),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create forum edit");

        assert_eq!(edit.new_name(), Some("New Name"));
        assert_eq!(edit.new_description(), Some("New Description"));
    }

    #[test]
    fn test_forum_edit_no_changes_rejected() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let result = EditNode::create_forum_edit(
            *forum.hash(),
            None,
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_forum_edit_empty_name_rejected() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let result = EditNode::create_forum_edit(
            *forum.hash(),
            Some("".to_string()),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_forum_edit_name_too_long() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let long_name = "x".repeat(MAX_EDIT_NAME_LENGTH + 1);
        let result = EditNode::create_forum_edit(
            *forum.hash(),
            Some(long_name),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_forum_edit_verification() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let edit = EditNode::create_forum_edit(
            *forum.hash(),
            Some("New Name".to_string()),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create forum edit");

        edit.verify(keypair.public_key())
            .expect("Verification failed");
    }

    #[test]
    fn test_forum_edit_verification_wrong_key() {
        let owner_keypair = create_test_keypair();
        let other_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let edit = EditNode::create_forum_edit(
            *forum.hash(),
            Some("New Name".to_string()),
            None,
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
        )
        .expect("Failed to create forum edit");

        assert!(edit.verify(other_keypair.public_key()).is_err());
    }

    #[test]
    fn test_board_edit_name_only() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let board = create_test_board(&keypair, &forum);

        let edit = EditNode::create_board_edit(
            *forum.hash(),
            *board.hash(),
            Some("New Board Name".to_string()),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board edit");

        assert_eq!(edit.edit_type(), EditType::EditBoard);
        assert_eq!(edit.forum_hash(), forum.hash());
        assert_eq!(edit.target_hash(), board.hash());
        assert_eq!(edit.new_name(), Some("New Board Name"));
        assert!(edit.new_description().is_none());
    }

    #[test]
    fn test_board_edit_description_only() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let board = create_test_board(&keypair, &forum);

        let edit = EditNode::create_board_edit(
            *forum.hash(),
            *board.hash(),
            None,
            Some("New board description".to_string()),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board edit");

        assert!(edit.new_name().is_none());
        assert_eq!(edit.new_description(), Some("New board description"));
    }

    #[test]
    fn test_board_edit_both_fields() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let board = create_test_board(&keypair, &forum);

        let edit = EditNode::create_board_edit(
            *forum.hash(),
            *board.hash(),
            Some("New Name".to_string()),
            Some("New Description".to_string()),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board edit");

        assert_eq!(edit.new_name(), Some("New Name"));
        assert_eq!(edit.new_description(), Some("New Description"));
    }

    #[test]
    fn test_board_edit_no_changes_rejected() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let board = create_test_board(&keypair, &forum);

        let result = EditNode::create_board_edit(
            *forum.hash(),
            *board.hash(),
            None,
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_board_edit_verification() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let board = create_test_board(&keypair, &forum);

        let edit = EditNode::create_board_edit(
            *forum.hash(),
            *board.hash(),
            Some("New Name".to_string()),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board edit");

        edit.verify(keypair.public_key())
            .expect("Verification failed");
    }

    #[test]
    fn test_edit_serialization_roundtrip() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let edit = EditNode::create_forum_edit(
            *forum.hash(),
            Some("Serialization Test".to_string()),
            Some("Testing serialization".to_string()),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create edit");

        let serialized = bincode::serialize(&edit).expect("Failed to serialize");
        let deserialized: EditNode =
            bincode::deserialize(&serialized).expect("Failed to deserialize");

        assert_eq!(edit.new_name(), deserialized.new_name());
        assert_eq!(edit.new_description(), deserialized.new_description());
        assert_eq!(edit.content_hash, deserialized.content_hash);

        deserialized
            .verify(keypair.public_key())
            .expect("Verification failed after deserialization");
    }

    #[test]
    fn test_multiple_edits_different_hashes() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let edit1 = EditNode::create_forum_edit(
            *forum.hash(),
            Some("First Edit".to_string()),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create edit 1");

        // Small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(1));

        let edit2 = EditNode::create_forum_edit(
            *forum.hash(),
            Some("Second Edit".to_string()),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create edit 2");

        assert_ne!(edit1.hash(), edit2.hash());
        assert!(edit2.created_at() >= edit1.created_at());
    }
}
