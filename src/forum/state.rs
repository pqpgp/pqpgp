//! Forum in-memory state management.
//!
//! This module provides in-memory state for forum DAG nodes, tracking heads
//! and permissions. It can be used by relays for serving forums or by clients
//! for local caching.
//!
//! For persistent storage, see the `storage` module.

use crate::forum::dag_ops::nodes_in_topological_order;
use crate::forum::{
    ContentHash, DagNode, ForumGenesis, ForumPermissions, NodeType, PermissionBuilder,
};
use std::collections::{HashMap, HashSet};

/// In-memory state for a single forum.
#[derive(Debug, Default)]
pub struct ForumState {
    /// All nodes in this forum's DAG, keyed by content hash.
    pub nodes: HashMap<ContentHash, DagNode>,
    /// Current DAG heads (nodes with no children).
    pub heads: HashSet<ContentHash>,
    /// Cached permission state for this forum.
    pub permissions: Option<ForumPermissions>,
    /// Forum name (extracted from genesis).
    pub name: String,
    /// Forum description (extracted from genesis).
    pub description: String,
    /// Creation timestamp.
    pub created_at: u64,
}

impl ForumState {
    /// Creates a new forum state from a genesis node.
    pub fn from_genesis(genesis: &ForumGenesis) -> Self {
        let permissions = ForumPermissions::from_genesis(genesis);
        let hash = *genesis.hash();

        let mut nodes = HashMap::new();
        nodes.insert(hash, DagNode::from(genesis.clone()));

        let mut heads = HashSet::new();
        heads.insert(hash);

        Self {
            nodes,
            heads,
            permissions: Some(permissions),
            name: genesis.name().to_string(),
            description: genesis.description().to_string(),
            created_at: genesis.created_at(),
        }
    }

    /// Adds a node to the forum state.
    ///
    /// Returns true if the node was new, false if it already existed.
    pub fn add_node(&mut self, node: DagNode) -> bool {
        let hash = *node.hash();

        // Check if already exists
        if self.nodes.contains_key(&hash) {
            return false;
        }

        // Update heads: remove parents from heads, add this node
        for parent_hash in node.parent_hashes() {
            self.heads.remove(&parent_hash);
        }
        self.heads.insert(hash);

        // Update permissions if this is a mod action
        if let DagNode::ModAction(action) = &node {
            if let Some(ref mut perms) = self.permissions {
                if let Err(e) = perms.apply_action(action) {
                    tracing::warn!("Failed to apply mod action: {}", e);
                }
            }
        }

        // Store the node
        self.nodes.insert(hash, node);
        true
    }

    /// Returns the number of nodes in this forum.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Gets a reference to a node by hash.
    pub fn get_node(&self, hash: &ContentHash) -> Option<&DagNode> {
        self.nodes.get(hash)
    }

    /// Checks if a node exists in this forum.
    pub fn has_node(&self, hash: &ContentHash) -> bool {
        self.nodes.contains_key(hash)
    }

    /// Returns an iterator over all nodes.
    pub fn iter_nodes(&self) -> impl Iterator<Item = (&ContentHash, &DagNode)> {
        self.nodes.iter()
    }

    /// Rebuilds permissions from scratch by replaying all nodes.
    pub fn rebuild_permissions(&mut self) {
        let mut builder = PermissionBuilder::new();

        for node in nodes_in_topological_order(&self.nodes) {
            let _ = builder.process_node(node);
        }

        if let Some(hash) = self.nodes.values().find_map(|n| {
            if n.node_type() == NodeType::ForumGenesis {
                Some(*n.hash())
            } else {
                None
            }
        }) {
            self.permissions = builder.into_permissions().remove(&hash);
        }
    }

    /// Returns the effective board hash for a thread, considering any moves.
    ///
    /// If the thread has been moved via a `MoveThread` moderation action, this returns
    /// the destination board. Otherwise, returns the original board from the thread's
    /// `board_hash` field.
    ///
    /// # Arguments
    /// * `thread_hash` - The content hash of the thread root
    ///
    /// # Returns
    /// * `Some(board_hash)` - The effective board hash (moved destination or original)
    /// * `None` - If the thread doesn't exist in this forum
    pub fn get_effective_board_for_thread(&self, thread_hash: &ContentHash) -> Option<ContentHash> {
        // First check if the thread has been moved
        if let Some(perms) = &self.permissions {
            if let Some(moved_board) = perms.get_thread_current_board(thread_hash) {
                return Some(*moved_board);
            }
        }

        // Not moved - get the original board from the thread root
        if let Some(node) = self.nodes.get(thread_hash) {
            if let Some(thread) = node.as_thread_root() {
                return Some(*thread.board_hash());
            }
        }

        None
    }

    /// Returns the effective board hash for a post, considering thread moves.
    ///
    /// This follows the post -> thread -> board chain, and accounts for any
    /// `MoveThread` moderation actions that may have relocated the thread.
    ///
    /// # Arguments
    /// * `post_hash` - The content hash of the post
    ///
    /// # Returns
    /// * `Some(board_hash)` - The effective board hash for the post's thread
    /// * `None` - If the post or its thread doesn't exist in this forum
    pub fn get_effective_board_for_post(&self, post_hash: &ContentHash) -> Option<ContentHash> {
        // Get the post's thread hash
        let thread_hash = self
            .nodes
            .get(post_hash)
            .and_then(|node| node.as_post().map(|post| *post.thread_hash()))?;

        // Delegate to thread lookup
        self.get_effective_board_for_thread(&thread_hash)
    }

    /// Returns the effective board hash for any node type.
    ///
    /// This is a convenience method that handles posts, threads, and boards uniformly:
    /// - For posts: returns the effective board via the thread (considering moves)
    /// - For threads: returns the effective board (considering moves)
    /// - For boards: returns the board's own hash
    /// - For other node types: returns None
    ///
    /// # Arguments
    /// * `node_hash` - The content hash of the node
    ///
    /// # Returns
    /// * `Some(board_hash)` - The effective board hash
    /// * `None` - If the node doesn't exist or is not a post/thread/board
    pub fn get_effective_board(&self, node_hash: &ContentHash) -> Option<ContentHash> {
        let node = self.nodes.get(node_hash)?;

        match node.node_type() {
            NodeType::Post => self.get_effective_board_for_post(node_hash),
            NodeType::ThreadRoot => self.get_effective_board_for_thread(node_hash),
            NodeType::BoardGenesis => Some(*node_hash),
            _ => None,
        }
    }
}

/// Container for multiple forums' in-memory state.
#[derive(Debug, Default)]
pub struct ForumRelayState {
    /// All forums by their genesis hash.
    pub forums: HashMap<ContentHash, ForumState>,
}

impl ForumRelayState {
    /// Creates a new empty forum relay state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new forum from a genesis node.
    ///
    /// Returns the forum hash if successful.
    pub fn create_forum(&mut self, genesis: ForumGenesis) -> Result<ContentHash, String> {
        let hash = *genesis.hash();

        if self.forums.contains_key(&hash) {
            return Err("Forum already exists".to_string());
        }

        let state = ForumState::from_genesis(&genesis);
        self.forums.insert(hash, state);

        Ok(hash)
    }

    /// Adds a node to a forum.
    ///
    /// Returns an error if the forum doesn't exist or the node is invalid.
    pub fn add_node(&mut self, forum_hash: &ContentHash, node: DagNode) -> Result<bool, String> {
        let forum = self
            .forums
            .get_mut(forum_hash)
            .ok_or_else(|| "Forum not found".to_string())?;

        // If this is a forum genesis, it should match the forum hash
        if let DagNode::ForumGenesis(genesis) = &node {
            if genesis.hash() != forum_hash {
                return Err("Forum genesis hash mismatch".to_string());
            }
        }

        Ok(forum.add_node(node))
    }

    /// Gets a reference to a forum's state.
    pub fn get_forum(&self, hash: &ContentHash) -> Option<&ForumState> {
        self.forums.get(hash)
    }

    /// Gets a mutable reference to a forum's state.
    pub fn get_forum_mut(&mut self, hash: &ContentHash) -> Option<&mut ForumState> {
        self.forums.get_mut(hash)
    }

    /// Returns the total number of nodes across all forums.
    pub fn total_nodes(&self) -> usize {
        self.forums.values().map(|f| f.node_count()).sum()
    }

    /// Returns the number of forums.
    pub fn forum_count(&self) -> usize {
        self.forums.len()
    }

    /// Returns an iterator over all forum hashes.
    pub fn forum_hashes(&self) -> impl Iterator<Item = &ContentHash> {
        self.forums.keys()
    }

    /// Removes a forum.
    ///
    /// Returns true if the forum existed and was removed.
    pub fn remove_forum(&mut self, hash: &ContentHash) -> bool {
        self.forums.remove(hash).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::forum::dag_ops::compute_missing;
    use crate::forum::BoardGenesis;

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
    fn test_forum_state_from_genesis() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let state = ForumState::from_genesis(&genesis);

        assert_eq!(state.node_count(), 1);
        assert_eq!(state.heads.len(), 1);
        assert!(state.heads.contains(genesis.hash()));
        assert_eq!(state.name, "Test Forum");
    }

    #[test]
    fn test_forum_state_add_node() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let added = state.add_node(DagNode::from(board.clone()));
        assert!(added);
        assert_eq!(state.node_count(), 2);

        // Board should be the only head now
        assert_eq!(state.heads.len(), 1);
        assert!(state.heads.contains(board.hash()));

        // Adding same node again should return false
        let added_again = state.add_node(DagNode::from(board));
        assert!(!added_again);
    }

    #[test]
    fn test_forum_state_compute_missing() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        state.add_node(DagNode::from(board.clone()));

        // Client with empty heads should get everything
        let missing = compute_missing(&state.nodes, &[]);
        assert_eq!(missing.len(), 2);

        // Client with genesis should only need board
        let missing = compute_missing(&state.nodes, &[*genesis.hash()]);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], *board.hash());

        // Client with board should need nothing
        let missing = compute_missing(&state.nodes, &[*board.hash()]);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_forum_relay_state() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);
        let hash = *genesis.hash();

        let mut relay = ForumRelayState::new();

        // Create forum
        let result = relay.create_forum(genesis.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), hash);

        // Should not be able to create duplicate
        let result = relay.create_forum(genesis);
        assert!(result.is_err());

        // Should be able to get forum
        assert!(relay.get_forum(&hash).is_some());
        assert_eq!(relay.forums.len(), 1);
    }

    #[test]
    fn test_forum_relay_add_node() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);
        let forum_hash = *genesis.hash();

        let mut relay = ForumRelayState::new();
        relay.create_forum(genesis.clone()).unwrap();

        let board = BoardGenesis::create(
            forum_hash,
            "Test Board".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let result = relay.add_node(&forum_hash, DagNode::from(board));
        assert!(result.is_ok());
        assert!(result.unwrap());

        assert_eq!(relay.total_nodes(), 2);
    }

    #[test]
    fn test_forum_state_accessors() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);
        let hash = *genesis.hash();

        let state = ForumState::from_genesis(&genesis);

        // Test get_node
        assert!(state.get_node(&hash).is_some());
        let fake_hash = ContentHash::from_bytes([0u8; 64]);
        assert!(state.get_node(&fake_hash).is_none());

        // Test has_node
        assert!(state.has_node(&hash));
        assert!(!state.has_node(&fake_hash));

        // Test iter_nodes
        assert_eq!(state.iter_nodes().count(), 1);
    }

    #[test]
    fn test_forum_relay_state_accessors() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);
        let hash = *genesis.hash();

        let mut relay = ForumRelayState::new();
        relay.create_forum(genesis).unwrap();

        // Test get_forum_mut
        assert!(relay.get_forum_mut(&hash).is_some());

        // Test forum_count
        assert_eq!(relay.forum_count(), 1);

        // Test forum_hashes
        let hashes: Vec<_> = relay.forum_hashes().collect();
        assert_eq!(hashes.len(), 1);
        assert_eq!(*hashes[0], hash);

        // Test remove_forum
        assert!(relay.remove_forum(&hash));
        assert_eq!(relay.forum_count(), 0);
        assert!(!relay.remove_forum(&hash)); // Already removed
    }

    #[test]
    fn test_get_effective_board_for_thread() {
        use crate::forum::ThreadRoot;

        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Create a board
        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board.clone()));

        // Create a thread in that board
        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "Thread body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread.clone()));

        // Effective board should be the original board
        let effective = state.get_effective_board_for_thread(thread.hash());
        assert_eq!(effective, Some(*board.hash()));

        // Non-existent thread should return None
        let fake_hash = ContentHash::from_bytes([0u8; 64]);
        assert!(state.get_effective_board_for_thread(&fake_hash).is_none());
    }

    #[test]
    fn test_get_effective_board_for_post() {
        use crate::forum::{Post, ThreadRoot};

        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Create a board
        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board.clone()));

        // Create a thread in that board
        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "Thread body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread.clone()));

        // Create a post in that thread
        let post = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Test post".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(post.clone()));

        // Effective board for the post should be the original board
        let effective = state.get_effective_board_for_post(post.hash());
        assert_eq!(effective, Some(*board.hash()));
    }

    #[test]
    fn test_get_effective_board_generic() {
        use crate::forum::{Post, ThreadRoot};

        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Create a board
        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board.clone()));

        // Create a thread
        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "Thread body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread.clone()));

        // Create a post
        let post = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Test post".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(post.clone()));

        // Test get_effective_board for each node type
        assert_eq!(state.get_effective_board(board.hash()), Some(*board.hash()));
        assert_eq!(
            state.get_effective_board(thread.hash()),
            Some(*board.hash())
        );
        assert_eq!(state.get_effective_board(post.hash()), Some(*board.hash()));

        // Forum genesis should return None (not a board/thread/post)
        assert!(state.get_effective_board(genesis.hash()).is_none());
    }

    #[test]
    fn test_get_effective_board_with_moved_thread() {
        use crate::forum::{ModActionNode, Post, ThreadRoot};

        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Create two boards
        let board1 = BoardGenesis::create(
            *genesis.hash(),
            "Board 1".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board1.clone()));

        let board2 = BoardGenesis::create(
            *genesis.hash(),
            "Board 2".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board2.clone()));

        // Create a thread in board1
        let thread = ThreadRoot::create(
            *board1.hash(),
            "Test Thread".to_string(),
            "Thread body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread.clone()));

        // Create a post in that thread
        let post = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Test post".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(post.clone()));

        // Initially, effective board is board1
        assert_eq!(
            state.get_effective_board_for_thread(thread.hash()),
            Some(*board1.hash())
        );
        assert_eq!(
            state.get_effective_board_for_post(post.hash()),
            Some(*board1.hash())
        );

        // Move the thread to board2
        let move_action = ModActionNode::create_move_thread_action(
            *genesis.hash(),
            *thread.hash(),
            *board2.hash(),
            keypair.public_key(),
            keypair.private_key(),
            None,
            vec![*post.hash()],
        )
        .unwrap();
        state.add_node(DagNode::from(move_action));

        // After move, effective board should be board2
        assert_eq!(
            state.get_effective_board_for_thread(thread.hash()),
            Some(*board2.hash())
        );
        assert_eq!(
            state.get_effective_board_for_post(post.hash()),
            Some(*board2.hash())
        );
        assert_eq!(
            state.get_effective_board(thread.hash()),
            Some(*board2.hash())
        );
        assert_eq!(state.get_effective_board(post.hash()), Some(*board2.hash()));
    }
}
