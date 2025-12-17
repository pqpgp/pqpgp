//! Forum relay state management.
//!
//! This module manages the server-side state for forum DAG synchronization.
//! The relay stores all forum nodes and tracks DAG heads for efficient sync.

use pqpgp::forum::dag_ops::{compute_missing, nodes_in_topological_order};
use pqpgp::forum::{
    ContentHash, DagNode, ForumGenesis, ForumPermissions, NodeType, PermissionBuilder,
};
use std::collections::{HashMap, HashSet};

/// State for a single forum.
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

    /// Computes which nodes a client is missing given their known heads.
    ///
    /// Returns hashes in topological order (parents before children).
    pub fn compute_missing_nodes(&self, client_heads: &[ContentHash]) -> Vec<ContentHash> {
        compute_missing(&self.nodes, client_heads)
    }

    /// Returns all nodes in topological order.
    pub fn nodes_in_order(&self) -> Vec<&DagNode> {
        nodes_in_topological_order(&self.nodes)
    }

    /// Rebuilds permissions from scratch by replaying all nodes.
    pub fn rebuild_permissions(&mut self) {
        let mut builder = PermissionBuilder::new();

        for node in self.nodes_in_order() {
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
}

/// Global forum relay state containing all forums.
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

    /// Returns the total number of nodes across all forums.
    pub fn total_nodes(&self) -> usize {
        self.forums.values().map(|f| f.node_count()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqpgp::crypto::KeyPair;
    use pqpgp::forum::BoardGenesis;

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
        let missing = state.compute_missing_nodes(&[]);
        assert_eq!(missing.len(), 2);

        // Client with genesis should only need board
        let missing = state.compute_missing_nodes(&[*genesis.hash()]);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], *board.hash());

        // Client with board should need nothing
        let missing = state.compute_missing_nodes(&[*board.hash()]);
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
}
