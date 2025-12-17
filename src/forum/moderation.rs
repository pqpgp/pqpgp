//! Moderation action nodes for the DAG-based forum system.
//!
//! Moderation actions are recorded in the DAG to track changes in forum
//! permissions over time. These actions include:
//! - Adding moderators
//! - Removing moderators
//!
//! Only the forum owner can issue moderation actions. The current moderator
//! set can be reconstructed by replaying all moderation actions from the
//! forum genesis in order.

use crate::crypto::{sign_data, verify_data_signature, PublicKey, Signature};
use crate::error::{PqpgpError, Result};
use crate::forum::constants::MAX_MOD_ACTION_PARENTS;
use crate::forum::types::{current_timestamp_millis, ContentHash, ModAction, NodeType};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The content of a moderation action node that gets signed and hashed.
///
/// This structure is serialized with bincode for deterministic hashing and signing.
/// The content hash of this struct becomes the action's unique identifier.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModActionContent {
    /// Node type discriminator (always ModAction).
    pub node_type: NodeType,
    /// Hash of the forum this action applies to.
    pub forum_hash: ContentHash,
    /// Optional board hash for board-level moderation actions.
    /// Required for AddBoardModerator/RemoveBoardModerator actions.
    pub board_hash: Option<ContentHash>,
    /// Optional target node hash for content moderation actions (hide/unhide).
    /// Required for HideThread/UnhideThread/HidePost/UnhidePost actions.
    pub target_node_hash: Option<ContentHash>,
    /// Parent hashes for DAG ordering and causal consistency.
    /// Should reference the current DAG heads when the action is created.
    /// This ensures mod actions are ordered relative to other content/actions.
    pub parent_hashes: Vec<ContentHash>,
    /// The specific moderation action being performed.
    pub action: ModAction,
    /// Public key bytes of the user being affected (added/removed as moderator).
    /// For content actions, this is empty (not applicable).
    pub target_identity: Vec<u8>,
    /// Public key bytes of the user issuing this action (must be forum owner or moderator).
    pub issuer_identity: Vec<u8>,
    /// Creation timestamp in milliseconds since Unix epoch.
    pub created_at: u64,
}

impl fmt::Debug for ModActionContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModActionContent")
            .field("node_type", &self.node_type)
            .field("forum_hash", &self.forum_hash)
            .field("action", &self.action)
            .field("target_identity_len", &self.target_identity.len())
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl ModActionContent {
    /// Creates new forum-level moderation action content.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this action applies to
    /// * `action` - The moderation action to perform (must be AddModerator or RemoveModerator)
    /// * `target_public_key` - Public key of the user being affected
    /// * `issuer_public_key` - Public key of the user issuing this action
    /// * `parent_hashes` - Current DAG heads for causal ordering
    ///
    /// # Errors
    /// Returns an error if the action is a board-level or content action, or if too many parents.
    pub fn new(
        forum_hash: ContentHash,
        action: ModAction,
        target_public_key: &PublicKey,
        issuer_public_key: &PublicKey,
        parent_hashes: Vec<ContentHash>,
    ) -> Result<Self> {
        if action.is_board_action() {
            return Err(PqpgpError::validation(
                "Use new_board_action for board-level moderation actions",
            ));
        }
        if action.is_content_action() {
            return Err(PqpgpError::validation(
                "Use new_content_action for content moderation actions",
            ));
        }
        if parent_hashes.len() > MAX_MOD_ACTION_PARENTS {
            return Err(PqpgpError::validation(format!(
                "Too many parent hashes: {} (max {})",
                parent_hashes.len(),
                MAX_MOD_ACTION_PARENTS
            )));
        }
        Ok(Self {
            node_type: NodeType::ModAction,
            forum_hash,
            board_hash: None,
            target_node_hash: None,
            parent_hashes,
            action,
            target_identity: target_public_key.as_bytes(),
            issuer_identity: issuer_public_key.as_bytes(),
            created_at: current_timestamp_millis(),
        })
    }

    /// Creates new board-level moderation action content.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this action applies to
    /// * `board_hash` - Hash of the board this action applies to
    /// * `action` - The moderation action to perform (must be AddBoardModerator or RemoveBoardModerator)
    /// * `target_public_key` - Public key of the user being affected
    /// * `issuer_public_key` - Public key of the user issuing this action
    /// * `parent_hashes` - Current DAG heads for causal ordering
    ///
    /// # Errors
    /// Returns an error if the action is not a board-level action, or if too many parents.
    pub fn new_board_action(
        forum_hash: ContentHash,
        board_hash: ContentHash,
        action: ModAction,
        target_public_key: &PublicKey,
        issuer_public_key: &PublicKey,
        parent_hashes: Vec<ContentHash>,
    ) -> Result<Self> {
        if !action.is_board_action() {
            return Err(PqpgpError::validation(
                "Use new for forum-level moderation actions",
            ));
        }
        if parent_hashes.len() > MAX_MOD_ACTION_PARENTS {
            return Err(PqpgpError::validation(format!(
                "Too many parent hashes: {} (max {})",
                parent_hashes.len(),
                MAX_MOD_ACTION_PARENTS
            )));
        }
        Ok(Self {
            node_type: NodeType::ModAction,
            forum_hash,
            board_hash: Some(board_hash),
            target_node_hash: None,
            parent_hashes,
            action,
            target_identity: target_public_key.as_bytes(),
            issuer_identity: issuer_public_key.as_bytes(),
            created_at: current_timestamp_millis(),
        })
    }

    /// Creates new content moderation action content (hide/unhide thread or post).
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this action applies to
    /// * `target_node_hash` - Hash of the thread or post being hidden/unhidden
    /// * `action` - The moderation action to perform (must be HideThread/UnhideThread/HidePost/UnhidePost)
    /// * `issuer_public_key` - Public key of the user issuing this action
    /// * `parent_hashes` - Current DAG heads for causal ordering
    ///
    /// # Errors
    /// Returns an error if the action is not a content action, or if too many parents.
    pub fn new_content_action(
        forum_hash: ContentHash,
        target_node_hash: ContentHash,
        action: ModAction,
        issuer_public_key: &PublicKey,
        parent_hashes: Vec<ContentHash>,
    ) -> Result<Self> {
        if !action.is_content_action() {
            return Err(PqpgpError::validation(
                "Use new or new_board_action for non-content moderation actions",
            ));
        }
        if parent_hashes.len() > MAX_MOD_ACTION_PARENTS {
            return Err(PqpgpError::validation(format!(
                "Too many parent hashes: {} (max {})",
                parent_hashes.len(),
                MAX_MOD_ACTION_PARENTS
            )));
        }
        Ok(Self {
            node_type: NodeType::ModAction,
            forum_hash,
            board_hash: None,
            target_node_hash: Some(target_node_hash),
            parent_hashes,
            action,
            target_identity: Vec::new(), // Not applicable for content actions
            issuer_identity: issuer_public_key.as_bytes(),
            created_at: current_timestamp_millis(),
        })
    }

    /// Creates new board hide/unhide action content.
    ///
    /// Unlike `new_board_action` which is for moderator assignment (AddBoardModerator/RemoveBoardModerator),
    /// this method is specifically for hiding or unhiding boards themselves.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this action applies to
    /// * `board_hash` - Hash of the board being hidden/unhidden
    /// * `action` - The moderation action to perform (must be HideBoard or UnhideBoard)
    /// * `issuer_public_key` - Public key of the user issuing this action
    /// * `parent_hashes` - Current DAG heads for causal ordering
    ///
    /// # Errors
    /// Returns an error if the action is not HideBoard/UnhideBoard, or if too many parents.
    pub fn new_hide_board_action(
        forum_hash: ContentHash,
        board_hash: ContentHash,
        action: ModAction,
        issuer_public_key: &PublicKey,
        parent_hashes: Vec<ContentHash>,
    ) -> Result<Self> {
        if !matches!(action, ModAction::HideBoard | ModAction::UnhideBoard) {
            return Err(PqpgpError::validation(
                "Use new_hide_board_action only for HideBoard/UnhideBoard actions",
            ));
        }
        if parent_hashes.len() > MAX_MOD_ACTION_PARENTS {
            return Err(PqpgpError::validation(format!(
                "Too many parent hashes: {} (max {})",
                parent_hashes.len(),
                MAX_MOD_ACTION_PARENTS
            )));
        }
        Ok(Self {
            node_type: NodeType::ModAction,
            forum_hash,
            board_hash: Some(board_hash),
            target_node_hash: None,
            parent_hashes,
            action,
            target_identity: Vec::new(), // Not applicable for hide board actions
            issuer_identity: issuer_public_key.as_bytes(),
            created_at: current_timestamp_millis(),
        })
    }

    /// Creates new move thread action content.
    ///
    /// This action moves a thread from its current board to a different board.
    /// The thread's original board reference in the ThreadRoot remains unchanged
    /// in the DAG, but this moderation action indicates the thread should be
    /// displayed on the destination board instead.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this action applies to
    /// * `thread_hash` - Hash of the thread being moved
    /// * `destination_board_hash` - Hash of the board to move the thread to
    /// * `issuer_public_key` - Public key of the user issuing this action
    /// * `parent_hashes` - Current DAG heads for causal ordering
    ///
    /// # Errors
    /// Returns an error if too many parents.
    pub fn new_move_thread_action(
        forum_hash: ContentHash,
        thread_hash: ContentHash,
        destination_board_hash: ContentHash,
        issuer_public_key: &PublicKey,
        parent_hashes: Vec<ContentHash>,
    ) -> Result<Self> {
        if parent_hashes.len() > MAX_MOD_ACTION_PARENTS {
            return Err(PqpgpError::validation(format!(
                "Too many parent hashes: {} (max {})",
                parent_hashes.len(),
                MAX_MOD_ACTION_PARENTS
            )));
        }
        Ok(Self {
            node_type: NodeType::ModAction,
            forum_hash,
            board_hash: Some(destination_board_hash), // Destination board
            target_node_hash: Some(thread_hash),      // Thread being moved
            parent_hashes,
            action: ModAction::MoveThread,
            target_identity: Vec::new(), // Not applicable for move actions
            issuer_identity: issuer_public_key.as_bytes(),
            created_at: current_timestamp_millis(),
        })
    }

    /// Computes the content hash of this moderation action content.
    pub fn content_hash(&self) -> Result<ContentHash> {
        ContentHash::compute(self)
    }

    /// Returns the target node hash if this is a content action.
    pub fn target_node_hash(&self) -> Option<&ContentHash> {
        self.target_node_hash.as_ref()
    }
}

/// A complete moderation action node with content, signature, and content hash.
///
/// Moderation actions modify the forum's permission state. They must be
/// issued by the forum owner and are stored in the DAG for auditability.
#[derive(Clone, Serialize, Deserialize)]
pub struct ModActionNode {
    /// The signed content of this node.
    pub content: ModActionContent,
    /// ML-DSA-87 signature over the content.
    pub signature: Signature,
    /// Content hash - the unique identifier of this node.
    pub content_hash: ContentHash,
}

impl fmt::Debug for ModActionNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModActionNode")
            .field("action", &self.content.action)
            .field("forum_hash", &self.content.forum_hash)
            .field("content_hash", &self.content_hash)
            .finish()
    }
}

impl ModActionNode {
    /// Creates and signs a new forum-level moderation action node.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this action applies to
    /// * `action` - The moderation action to perform (AddModerator or RemoveModerator)
    /// * `target_public_key` - Public key of the user being affected
    /// * `issuer_public_key` - Public key of the user issuing this action
    /// * `issuer_private_key` - Private key to sign with (must match issuer_public_key)
    /// * `password` - Optional password if the private key is encrypted
    /// * `parent_hashes` - Current DAG heads for causal ordering
    ///
    /// # Errors
    /// Returns an error if validation fails or signing fails.
    ///
    /// # Note
    /// Permission checking (whether the issuer is the forum owner) is not done here.
    /// It must be validated at the application layer when accepting nodes into the DAG.
    pub fn create(
        forum_hash: ContentHash,
        action: ModAction,
        target_public_key: &PublicKey,
        issuer_public_key: &PublicKey,
        issuer_private_key: &crate::crypto::PrivateKey,
        password: Option<&crate::crypto::Password>,
        parent_hashes: Vec<ContentHash>,
    ) -> Result<Self> {
        let content = ModActionContent::new(
            forum_hash,
            action,
            target_public_key,
            issuer_public_key,
            parent_hashes,
        )?;
        let content_hash = content.content_hash()?;
        let signature = sign_data(issuer_private_key, &content, password)?;

        Ok(Self {
            content,
            signature,
            content_hash,
        })
    }

    /// Creates and signs a new board-level moderation action node.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this action applies to
    /// * `board_hash` - Hash of the board this action applies to
    /// * `action` - The moderation action to perform (AddBoardModerator or RemoveBoardModerator)
    /// * `target_public_key` - Public key of the user being affected
    /// * `issuer_public_key` - Public key of the user issuing this action
    /// * `issuer_private_key` - Private key to sign with (must match issuer_public_key)
    /// * `password` - Optional password if the private key is encrypted
    /// * `parent_hashes` - Current DAG heads for causal ordering
    ///
    /// # Errors
    /// Returns an error if validation fails or signing fails.
    ///
    /// # Note
    /// Permission checking (whether the issuer has permission to add board moderators)
    /// is not done here. It must be validated at the application layer.
    #[allow(clippy::too_many_arguments)]
    pub fn create_board_action(
        forum_hash: ContentHash,
        board_hash: ContentHash,
        action: ModAction,
        target_public_key: &PublicKey,
        issuer_public_key: &PublicKey,
        issuer_private_key: &crate::crypto::PrivateKey,
        password: Option<&crate::crypto::Password>,
        parent_hashes: Vec<ContentHash>,
    ) -> Result<Self> {
        let content = ModActionContent::new_board_action(
            forum_hash,
            board_hash,
            action,
            target_public_key,
            issuer_public_key,
            parent_hashes,
        )?;
        let content_hash = content.content_hash()?;
        let signature = sign_data(issuer_private_key, &content, password)?;

        Ok(Self {
            content,
            signature,
            content_hash,
        })
    }

    /// Creates and signs a new content moderation action node (hide/unhide thread or post).
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this action applies to
    /// * `target_node_hash` - Hash of the thread or post being hidden/unhidden
    /// * `action` - The moderation action to perform (HideThread/UnhideThread/HidePost/UnhidePost)
    /// * `issuer_public_key` - Public key of the user issuing this action
    /// * `issuer_private_key` - Private key to sign with (must match issuer_public_key)
    /// * `password` - Optional password if the private key is encrypted
    /// * `parent_hashes` - Current DAG heads for causal ordering
    ///
    /// # Errors
    /// Returns an error if validation fails or signing fails.
    ///
    /// # Note
    /// Permission checking (whether the issuer is the author or a moderator)
    /// is not done here. It must be validated at the application layer.
    pub fn create_content_action(
        forum_hash: ContentHash,
        target_node_hash: ContentHash,
        action: ModAction,
        issuer_public_key: &PublicKey,
        issuer_private_key: &crate::crypto::PrivateKey,
        password: Option<&crate::crypto::Password>,
        parent_hashes: Vec<ContentHash>,
    ) -> Result<Self> {
        let content = ModActionContent::new_content_action(
            forum_hash,
            target_node_hash,
            action,
            issuer_public_key,
            parent_hashes,
        )?;
        let content_hash = content.content_hash()?;
        let signature = sign_data(issuer_private_key, &content, password)?;

        Ok(Self {
            content,
            signature,
            content_hash,
        })
    }

    /// Creates and signs a new board hide/unhide action node.
    ///
    /// Unlike `create_board_action` which is for moderator assignment (AddBoardModerator/RemoveBoardModerator),
    /// this method is specifically for hiding or unhiding boards themselves.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this action applies to
    /// * `board_hash` - Hash of the board being hidden/unhidden
    /// * `action` - The moderation action to perform (must be HideBoard or UnhideBoard)
    /// * `issuer_public_key` - Public key of the user issuing this action
    /// * `issuer_private_key` - Private key to sign with (must match issuer_public_key)
    /// * `password` - Optional password if the private key is encrypted
    /// * `parent_hashes` - Current DAG heads for causal ordering
    ///
    /// # Errors
    /// Returns an error if validation fails or signing fails.
    ///
    /// # Note
    /// Permission checking (whether the issuer is a moderator) is not done here.
    /// It must be validated at the application layer.
    pub fn create_hide_board_action(
        forum_hash: ContentHash,
        board_hash: ContentHash,
        action: ModAction,
        issuer_public_key: &PublicKey,
        issuer_private_key: &crate::crypto::PrivateKey,
        password: Option<&crate::crypto::Password>,
        parent_hashes: Vec<ContentHash>,
    ) -> Result<Self> {
        let content = ModActionContent::new_hide_board_action(
            forum_hash,
            board_hash,
            action,
            issuer_public_key,
            parent_hashes,
        )?;
        let content_hash = content.content_hash()?;
        let signature = sign_data(issuer_private_key, &content, password)?;

        Ok(Self {
            content,
            signature,
            content_hash,
        })
    }

    /// Creates and signs a new move thread action node.
    ///
    /// This action moves a thread from its current board to a different board.
    /// The thread's original board reference in the ThreadRoot remains unchanged
    /// in the DAG, but this moderation action indicates the thread should be
    /// displayed on the destination board instead.
    ///
    /// # Arguments
    /// * `forum_hash` - Hash of the forum this action applies to
    /// * `thread_hash` - Hash of the thread being moved
    /// * `destination_board_hash` - Hash of the board to move the thread to
    /// * `issuer_public_key` - Public key of the user issuing this action
    /// * `issuer_private_key` - Private key to sign with (must match issuer_public_key)
    /// * `password` - Optional password if the private key is encrypted
    /// * `parent_hashes` - Current DAG heads for causal ordering
    ///
    /// # Errors
    /// Returns an error if validation fails or signing fails.
    ///
    /// # Note
    /// Permission checking (whether the issuer has permission to move threads)
    /// is not done here. It must be validated at the application layer.
    #[allow(clippy::too_many_arguments)]
    pub fn create_move_thread_action(
        forum_hash: ContentHash,
        thread_hash: ContentHash,
        destination_board_hash: ContentHash,
        issuer_public_key: &PublicKey,
        issuer_private_key: &crate::crypto::PrivateKey,
        password: Option<&crate::crypto::Password>,
        parent_hashes: Vec<ContentHash>,
    ) -> Result<Self> {
        let content = ModActionContent::new_move_thread_action(
            forum_hash,
            thread_hash,
            destination_board_hash,
            issuer_public_key,
            parent_hashes,
        )?;
        let content_hash = content.content_hash()?;
        let signature = sign_data(issuer_private_key, &content, password)?;

        Ok(Self {
            content,
            signature,
            content_hash,
        })
    }

    /// Verifies the signature and content hash of this node.
    ///
    /// # Arguments
    /// * `issuer_public_key` - Public key to verify the signature against
    ///
    /// # Errors
    /// Returns an error if:
    /// - The content hash doesn't match the computed hash
    /// - The signature is invalid
    ///
    /// # Note
    /// This does not verify that the issuer has permission to issue moderation actions.
    /// Permission checking must be done at the application layer.
    pub fn verify(&self, issuer_public_key: &PublicKey) -> Result<()> {
        // Verify content hash
        let computed_hash = self.content.content_hash()?;
        if computed_hash != self.content_hash {
            return Err(PqpgpError::validation(
                "Moderation action content hash mismatch",
            ));
        }

        // Verify signature
        verify_data_signature(issuer_public_key, &self.content, &self.signature)?;

        Ok(())
    }

    /// Returns the forum hash this action applies to.
    pub fn forum_hash(&self) -> &ContentHash {
        &self.content.forum_hash
    }

    /// Returns the board hash if this is a board-level action.
    pub fn board_hash(&self) -> Option<&ContentHash> {
        self.content.board_hash.as_ref()
    }

    /// Returns the target node hash if this is a content action.
    pub fn target_node_hash(&self) -> Option<&ContentHash> {
        self.content.target_node_hash.as_ref()
    }

    /// Returns the parent hashes for DAG ordering.
    pub fn parent_hashes(&self) -> &[ContentHash] {
        &self.content.parent_hashes
    }

    /// Returns the moderation action type.
    pub fn action(&self) -> ModAction {
        self.content.action
    }

    /// Returns the target identity bytes.
    pub fn target_identity(&self) -> &[u8] {
        &self.content.target_identity
    }

    /// Returns the issuer identity bytes.
    pub fn issuer_identity(&self) -> &[u8] {
        &self.content.issuer_identity
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
    fn test_mod_action_add_moderator() {
        let owner_keypair = create_test_keypair();
        let new_mod_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            new_mod_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()], // Reference forum genesis as parent
        )
        .expect("Failed to create mod action");

        assert_eq!(action.action(), ModAction::AddModerator);
        assert_eq!(action.forum_hash(), forum.hash());
        assert_eq!(action.node_type(), NodeType::ModAction);
        assert_eq!(
            action.target_identity(),
            new_mod_keypair.public_key().as_bytes()
        );
    }

    #[test]
    fn test_mod_action_remove_moderator() {
        let owner_keypair = create_test_keypair();
        let mod_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::RemoveModerator,
            mod_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()],
        )
        .expect("Failed to create mod action");

        assert_eq!(action.action(), ModAction::RemoveModerator);
    }

    #[test]
    fn test_mod_action_verification() {
        let owner_keypair = create_test_keypair();
        let new_mod_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            new_mod_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()],
        )
        .expect("Failed to create mod action");

        action
            .verify(owner_keypair.public_key())
            .expect("Verification failed");
    }

    #[test]
    fn test_mod_action_verification_wrong_key() {
        let owner_keypair = create_test_keypair();
        let other_keypair = create_test_keypair();
        let new_mod_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            new_mod_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()],
        )
        .expect("Failed to create mod action");

        // Verification with wrong key should fail
        assert!(action.verify(other_keypair.public_key()).is_err());
    }

    #[test]
    fn test_mod_action_serialization_roundtrip() {
        let owner_keypair = create_test_keypair();
        let new_mod_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            new_mod_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()],
        )
        .expect("Failed to create mod action");

        let serialized = bincode::serialize(&action).expect("Failed to serialize");
        let deserialized: ModActionNode =
            bincode::deserialize(&serialized).expect("Failed to deserialize");

        assert_eq!(action.action(), deserialized.action());
        assert_eq!(action.content_hash, deserialized.content_hash);

        deserialized
            .verify(owner_keypair.public_key())
            .expect("Verification failed after deserialization");
    }

    #[test]
    fn test_mod_action_content_hash_deterministic() {
        let owner_keypair = create_test_keypair();
        let target_keypair = create_test_keypair();
        let forum_hash = ContentHash::from_bytes([0u8; 64]);

        let content = ModActionContent {
            node_type: NodeType::ModAction,
            forum_hash,
            board_hash: None,
            target_node_hash: None,
            parent_hashes: vec![],
            action: ModAction::AddModerator,
            target_identity: target_keypair.public_key().as_bytes(),
            issuer_identity: owner_keypair.public_key().as_bytes(),
            created_at: 1700000000000,
        };

        let hash1 = content.content_hash().unwrap();
        let hash2 = content.content_hash().unwrap();

        assert_eq!(hash1, hash2, "Same content should produce same hash");
    }

    #[test]
    fn test_mod_action_different_actions_different_hashes() {
        let owner_keypair = create_test_keypair();
        let target_keypair = create_test_keypair();
        let forum_hash = ContentHash::from_bytes([0u8; 64]);
        let created_at = 1700000000000;

        let content_add = ModActionContent {
            node_type: NodeType::ModAction,
            forum_hash,
            board_hash: None,
            target_node_hash: None,
            parent_hashes: vec![],
            action: ModAction::AddModerator,
            target_identity: target_keypair.public_key().as_bytes(),
            issuer_identity: owner_keypair.public_key().as_bytes(),
            created_at,
        };

        let content_remove = ModActionContent {
            node_type: NodeType::ModAction,
            forum_hash,
            board_hash: None,
            target_node_hash: None,
            parent_hashes: vec![],
            action: ModAction::RemoveModerator,
            target_identity: target_keypair.public_key().as_bytes(),
            issuer_identity: owner_keypair.public_key().as_bytes(),
            created_at,
        };

        let hash_add = content_add.content_hash().unwrap();
        let hash_remove = content_remove.content_hash().unwrap();

        assert_ne!(
            hash_add, hash_remove,
            "Different actions should produce different hashes"
        );
    }

    #[test]
    fn test_mod_action_sequence() {
        let owner_keypair = create_test_keypair();
        let mod1_keypair = create_test_keypair();
        let mod2_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        // Add first moderator (parent is forum genesis)
        let add_mod1 = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            mod1_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()],
        )
        .expect("Failed to add mod1");

        // Add second moderator (parent is previous mod action for causal ordering)
        let add_mod2 = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            mod2_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*add_mod1.hash()],
        )
        .expect("Failed to add mod2");

        // Remove first moderator (parent is add_mod2 for causal ordering)
        let remove_mod1 = ModActionNode::create(
            *forum.hash(),
            ModAction::RemoveModerator,
            mod1_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*add_mod2.hash()],
        )
        .expect("Failed to remove mod1");

        // All actions should verify
        add_mod1
            .verify(owner_keypair.public_key())
            .expect("add_mod1 verification failed");
        add_mod2
            .verify(owner_keypair.public_key())
            .expect("add_mod2 verification failed");
        remove_mod1
            .verify(owner_keypair.public_key())
            .expect("remove_mod1 verification failed");

        // All hashes should be unique
        assert_ne!(add_mod1.hash(), add_mod2.hash());
        assert_ne!(add_mod1.hash(), remove_mod1.hash());
        assert_ne!(add_mod2.hash(), remove_mod1.hash());
    }
}
