//! DAG node wrapper for the forum system.
//!
//! The `DagNode` enum wraps all node types in the forum DAG, providing
//! a unified interface for:
//! - Serialization/deserialization
//! - Content hash access
//! - Node type identification
//!
//! This enables generic processing of any node type while preserving
//! type safety.

use crate::dag::DagNodeOps;
use crate::error::Result;
use crate::forum::{
    BoardGenesis, ContentHash, EditNode, EncryptionIdentity, ForumGenesis, ModActionNode, NodeType,
    Post, SealedPrivateMessage, ThreadRoot,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A wrapper enum for all node types in the forum DAG.
///
/// This provides a unified interface for working with any type of DAG node,
/// enabling generic storage, serialization, and processing.
#[derive(Clone, Serialize, Deserialize)]
pub enum DagNode {
    /// Forum genesis - the root of a forum hierarchy.
    ForumGenesis(ForumGenesis),
    /// Board genesis - creates a board within a forum.
    BoardGenesis(BoardGenesis),
    /// Thread root - starts a discussion thread.
    ThreadRoot(ThreadRoot),
    /// Post - a reply within a thread.
    Post(Post),
    /// Moderation action - adds or removes moderators.
    ModAction(ModActionNode),
    /// Edit node - updates forum/board metadata.
    Edit(EditNode),
    /// Encryption identity - publishes encryption keys for private messaging.
    EncryptionIdentity(EncryptionIdentity),
    /// Sealed private message - end-to-end encrypted message with hidden metadata.
    SealedPrivateMessage(SealedPrivateMessage),
}

impl fmt::Debug for DagNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DagNode::ForumGenesis(node) => f
                .debug_struct("DagNode::ForumGenesis")
                .field("name", &node.name())
                .field("hash", &node.hash())
                .finish(),
            DagNode::BoardGenesis(node) => f
                .debug_struct("DagNode::BoardGenesis")
                .field("name", &node.name())
                .field("hash", &node.hash())
                .finish(),
            DagNode::ThreadRoot(node) => f
                .debug_struct("DagNode::ThreadRoot")
                .field("title", &node.title())
                .field("hash", &node.hash())
                .finish(),
            DagNode::Post(node) => f
                .debug_struct("DagNode::Post")
                .field("body_len", &node.body().len())
                .field("hash", &node.hash())
                .finish(),
            DagNode::ModAction(node) => f
                .debug_struct("DagNode::ModAction")
                .field("action", &node.action())
                .field("hash", &node.hash())
                .finish(),
            DagNode::Edit(node) => f
                .debug_struct("DagNode::Edit")
                .field("edit_type", &node.edit_type())
                .field("target_hash", &node.target_hash())
                .field("hash", &node.hash())
                .finish(),
            DagNode::EncryptionIdentity(node) => f
                .debug_struct("DagNode::EncryptionIdentity")
                .field("forum_hash", &node.forum_hash())
                .field("hash", &node.hash())
                .finish(),
            DagNode::SealedPrivateMessage(node) => f
                .debug_struct("DagNode::SealedPrivateMessage")
                .field("forum_hash", &node.forum_hash())
                .field("hash", &node.hash())
                .finish(),
        }
    }
}

impl DagNode {
    /// Returns the content hash of this node.
    pub fn hash(&self) -> &ContentHash {
        match self {
            DagNode::ForumGenesis(node) => node.hash(),
            DagNode::BoardGenesis(node) => node.hash(),
            DagNode::ThreadRoot(node) => node.hash(),
            DagNode::Post(node) => node.hash(),
            DagNode::ModAction(node) => node.hash(),
            DagNode::Edit(node) => node.hash(),
            DagNode::EncryptionIdentity(node) => node.hash(),
            DagNode::SealedPrivateMessage(node) => node.hash(),
        }
    }

    /// Returns the node type.
    pub fn node_type(&self) -> NodeType {
        match self {
            DagNode::ForumGenesis(_) => NodeType::ForumGenesis,
            DagNode::BoardGenesis(_) => NodeType::BoardGenesis,
            DagNode::ThreadRoot(_) => NodeType::ThreadRoot,
            DagNode::Post(_) => NodeType::Post,
            DagNode::ModAction(_) => NodeType::ModAction,
            DagNode::Edit(_) => NodeType::Edit,
            DagNode::EncryptionIdentity(_) => NodeType::EncryptionIdentity,
            DagNode::SealedPrivateMessage(_) => NodeType::SealedPrivateMessage,
        }
    }

    /// Returns the creation timestamp of this node in milliseconds.
    pub fn created_at(&self) -> u64 {
        match self {
            DagNode::ForumGenesis(node) => node.created_at(),
            DagNode::BoardGenesis(node) => node.created_at(),
            DagNode::ThreadRoot(node) => node.created_at(),
            DagNode::Post(node) => node.created_at(),
            DagNode::ModAction(node) => node.created_at(),
            DagNode::Edit(node) => node.created_at(),
            DagNode::EncryptionIdentity(node) => node.created_at(),
            DagNode::SealedPrivateMessage(node) => node.created_at(),
        }
    }

    /// Returns the author/creator identity bytes.
    ///
    /// For sealed private messages, this returns the owner signing key from the
    /// encryption identity node, NOT the actual sender (which is encrypted).
    pub fn author_identity(&self) -> &[u8] {
        match self {
            DagNode::ForumGenesis(node) => node.creator_identity(),
            DagNode::BoardGenesis(node) => node.creator_identity(),
            DagNode::ThreadRoot(node) => node.author_identity(),
            DagNode::Post(node) => node.author_identity(),
            DagNode::ModAction(node) => node.issuer_identity(),
            DagNode::Edit(node) => node.editor_identity(),
            DagNode::EncryptionIdentity(node) => node.owner_signing_key(),
            // Sealed messages have no visible author - sender is encrypted
            DagNode::SealedPrivateMessage(_) => &[],
        }
    }

    /// Returns the parent hashes that this node references.
    ///
    /// - ForumGenesis: None (root node)
    /// - BoardGenesis: Forum hash
    /// - ThreadRoot: Board hash
    /// - Post: Thread hash + parent post hashes
    /// - ModAction: Forum hash + explicit parent hashes (for causal ordering)
    /// - Edit: Forum hash
    /// - EncryptionIdentity: Forum hash
    /// - SealedPrivateMessage: Forum hash (no other references to preserve privacy)
    pub fn parent_hashes(&self) -> Vec<ContentHash> {
        match self {
            DagNode::ForumGenesis(_) => vec![],
            DagNode::BoardGenesis(node) => vec![*node.forum_hash()],
            DagNode::ThreadRoot(node) => vec![*node.board_hash()],
            DagNode::Post(node) => {
                let mut parents = vec![*node.thread_hash()];
                parents.extend(node.parent_hashes().iter().copied());
                parents
            }
            DagNode::ModAction(node) => {
                let mut parents = vec![*node.forum_hash()];
                parents.extend(node.parent_hashes().iter().copied());
                parents
            }
            DagNode::Edit(node) => vec![*node.forum_hash()],
            DagNode::EncryptionIdentity(node) => vec![*node.forum_hash()],
            DagNode::SealedPrivateMessage(node) => vec![*node.forum_hash()],
        }
    }

    /// Returns true if this is a root node (has no parents).
    pub fn is_root(&self) -> bool {
        matches!(self, DagNode::ForumGenesis(_))
    }

    /// Serializes this node to bytes using bincode.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            crate::error::PqpgpError::serialization(format!("Failed to serialize DagNode: {}", e))
        })
    }

    /// Deserializes a node from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| {
            crate::error::PqpgpError::serialization(format!("Failed to deserialize DagNode: {}", e))
        })
    }

    /// Returns a reference to the inner ForumGenesis if this is one.
    pub fn as_forum_genesis(&self) -> Option<&ForumGenesis> {
        match self {
            DagNode::ForumGenesis(node) => Some(node),
            _ => None,
        }
    }

    /// Returns a reference to the inner BoardGenesis if this is one.
    pub fn as_board_genesis(&self) -> Option<&BoardGenesis> {
        match self {
            DagNode::BoardGenesis(node) => Some(node),
            _ => None,
        }
    }

    /// Returns a reference to the inner ThreadRoot if this is one.
    pub fn as_thread_root(&self) -> Option<&ThreadRoot> {
        match self {
            DagNode::ThreadRoot(node) => Some(node),
            _ => None,
        }
    }

    /// Returns a reference to the inner Post if this is one.
    pub fn as_post(&self) -> Option<&Post> {
        match self {
            DagNode::Post(node) => Some(node),
            _ => None,
        }
    }

    /// Returns a reference to the inner ModActionNode if this is one.
    pub fn as_mod_action(&self) -> Option<&ModActionNode> {
        match self {
            DagNode::ModAction(node) => Some(node),
            _ => None,
        }
    }

    /// Returns a reference to the inner EditNode if this is one.
    pub fn as_edit(&self) -> Option<&EditNode> {
        match self {
            DagNode::Edit(node) => Some(node),
            _ => None,
        }
    }

    /// Returns a reference to the inner EncryptionIdentity if this is one.
    pub fn as_encryption_identity(&self) -> Option<&EncryptionIdentity> {
        match self {
            DagNode::EncryptionIdentity(node) => Some(node),
            _ => None,
        }
    }

    /// Returns a reference to the inner SealedPrivateMessage if this is one.
    pub fn as_sealed_private_message(&self) -> Option<&SealedPrivateMessage> {
        match self {
            DagNode::SealedPrivateMessage(node) => Some(node),
            _ => None,
        }
    }
}

impl DagNodeOps for DagNode {
    fn hash(&self) -> &ContentHash {
        self.hash()
    }

    fn parent_hashes(&self) -> Vec<ContentHash> {
        self.parent_hashes()
    }

    fn created_at(&self) -> u64 {
        self.created_at()
    }
}

impl From<ForumGenesis> for DagNode {
    fn from(node: ForumGenesis) -> Self {
        DagNode::ForumGenesis(node)
    }
}

impl From<BoardGenesis> for DagNode {
    fn from(node: BoardGenesis) -> Self {
        DagNode::BoardGenesis(node)
    }
}

impl From<ThreadRoot> for DagNode {
    fn from(node: ThreadRoot) -> Self {
        DagNode::ThreadRoot(node)
    }
}

impl From<Post> for DagNode {
    fn from(node: Post) -> Self {
        DagNode::Post(node)
    }
}

impl From<ModActionNode> for DagNode {
    fn from(node: ModActionNode) -> Self {
        DagNode::ModAction(node)
    }
}

impl From<EditNode> for DagNode {
    fn from(node: EditNode) -> Self {
        DagNode::Edit(node)
    }
}

impl From<EncryptionIdentity> for DagNode {
    fn from(node: EncryptionIdentity) -> Self {
        DagNode::EncryptionIdentity(node)
    }
}

impl From<SealedPrivateMessage> for DagNode {
    fn from(node: SealedPrivateMessage) -> Self {
        DagNode::SealedPrivateMessage(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::forum::ModAction;

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

    fn create_test_thread(keypair: &KeyPair, board: &BoardGenesis) -> ThreadRoot {
        ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "Thread body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create thread")
    }

    fn create_test_post(keypair: &KeyPair, thread: &ThreadRoot) -> Post {
        Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Test post body".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create post")
    }

    #[test]
    fn test_dag_node_forum_genesis() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let dag_node: DagNode = forum.clone().into();

        assert_eq!(dag_node.node_type(), NodeType::ForumGenesis);
        assert_eq!(dag_node.hash(), forum.hash());
        assert!(dag_node.is_root());
        assert!(dag_node.parent_hashes().is_empty());
        assert!(dag_node.as_forum_genesis().is_some());
        assert!(dag_node.as_board_genesis().is_none());
    }

    #[test]
    fn test_dag_node_board_genesis() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let board = create_test_board(&keypair, &forum);
        let dag_node: DagNode = board.clone().into();

        assert_eq!(dag_node.node_type(), NodeType::BoardGenesis);
        assert_eq!(dag_node.hash(), board.hash());
        assert!(!dag_node.is_root());
        assert_eq!(dag_node.parent_hashes(), vec![*forum.hash()]);
        assert!(dag_node.as_board_genesis().is_some());
    }

    #[test]
    fn test_dag_node_thread_root() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let board = create_test_board(&keypair, &forum);
        let thread = create_test_thread(&keypair, &board);
        let dag_node: DagNode = thread.clone().into();

        assert_eq!(dag_node.node_type(), NodeType::ThreadRoot);
        assert_eq!(dag_node.hash(), thread.hash());
        assert!(!dag_node.is_root());
        assert_eq!(dag_node.parent_hashes(), vec![*board.hash()]);
        assert!(dag_node.as_thread_root().is_some());
    }

    #[test]
    fn test_dag_node_post() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let board = create_test_board(&keypair, &forum);
        let thread = create_test_thread(&keypair, &board);
        let post = create_test_post(&keypair, &thread);
        let dag_node: DagNode = post.clone().into();

        assert_eq!(dag_node.node_type(), NodeType::Post);
        assert_eq!(dag_node.hash(), post.hash());
        assert!(!dag_node.is_root());
        // Post parents include thread hash + parent post hashes
        let expected_parents = vec![*thread.hash(), *thread.hash()];
        assert_eq!(dag_node.parent_hashes(), expected_parents);
        assert!(dag_node.as_post().is_some());
    }

    #[test]
    fn test_dag_node_mod_action() {
        let owner_keypair = create_test_keypair();
        let target_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            target_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()], // Reference forum as parent for causal ordering
        )
        .expect("Failed to create mod action");

        let dag_node: DagNode = action.clone().into();

        assert_eq!(dag_node.node_type(), NodeType::ModAction);
        assert_eq!(dag_node.hash(), action.hash());
        assert!(!dag_node.is_root());
        // Forum hash appears twice: once as the action's forum reference, once as explicit parent
        assert_eq!(dag_node.parent_hashes(), vec![*forum.hash(), *forum.hash()]);
        assert!(dag_node.as_mod_action().is_some());
    }

    #[test]
    fn test_dag_node_serialization_roundtrip() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let dag_node: DagNode = forum.into();

        let bytes = dag_node.to_bytes().expect("Failed to serialize");
        let restored = DagNode::from_bytes(&bytes).expect("Failed to deserialize");

        assert_eq!(dag_node.hash(), restored.hash());
        assert_eq!(dag_node.node_type(), restored.node_type());
    }

    #[test]
    fn test_dag_node_serialization_all_types() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let board = create_test_board(&keypair, &forum);
        let thread = create_test_thread(&keypair, &board);
        let post = create_test_post(&keypair, &thread);

        let nodes: Vec<DagNode> = vec![forum.into(), board.into(), thread.into(), post.into()];

        for original in nodes {
            let bytes = original.to_bytes().expect("Failed to serialize");
            let restored = DagNode::from_bytes(&bytes).expect("Failed to deserialize");
            assert_eq!(original.hash(), restored.hash());
            assert_eq!(original.node_type(), restored.node_type());
        }
    }

    #[test]
    fn test_dag_node_author_identity() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let dag_node: DagNode = forum.into();

        assert_eq!(dag_node.author_identity(), keypair.public_key().as_bytes());
    }

    #[test]
    fn test_dag_node_created_at() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let expected_created_at = forum.created_at();

        let dag_node: DagNode = forum.into();

        assert_eq!(dag_node.created_at(), expected_created_at);
    }

    #[test]
    fn test_dag_node_debug_format() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let dag_node: DagNode = forum.into();

        let debug_str = format!("{:?}", dag_node);
        assert!(debug_str.contains("ForumGenesis"));
        assert!(debug_str.contains("name"));
    }
}
