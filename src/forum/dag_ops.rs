//! Forum-specific DAG operations.
//!
//! This module re-exports the generic DAG operations from `crate::dag::ops`
//! and provides forum-specific type aliases for convenience.
//!
//! For the generic DAG trait and operations, see `crate::dag`.

// Re-export the generic DAG operations trait
pub use crate::dag::DagNodeOps;

// Re-export generic functions - they work with any type implementing DagNodeOps
pub use crate::dag::ops::{
    compute_missing, compute_reachable, nodes_in_topological_order, topological_sort_hashes,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::forum::{BoardGenesis, ContentHash, DagNode, ForumGenesis, ThreadRoot};
    use std::collections::HashMap;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
    }

    #[test]
    fn test_compute_reachable_single_node() {
        let keypair = create_test_keypair();
        let forum = ForumGenesis::create(
            "Test".to_string(),
            "Desc".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let mut nodes: HashMap<ContentHash, DagNode> = HashMap::new();
        let hash = *forum.hash();
        nodes.insert(hash, DagNode::from(forum));

        let reachable = compute_reachable(&nodes, &[hash]);
        assert_eq!(reachable.len(), 1);
        assert!(reachable.contains(&hash));
    }

    #[test]
    fn test_compute_reachable_chain() {
        let keypair = create_test_keypair();
        let forum = ForumGenesis::create(
            "Test".to_string(),
            "Desc".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let board = BoardGenesis::create(
            *forum.hash(),
            "Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let thread = ThreadRoot::create(
            *board.hash(),
            "Thread".to_string(),
            "Body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let mut nodes: HashMap<ContentHash, DagNode> = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
        nodes.insert(*board.hash(), DagNode::from(board.clone()));
        nodes.insert(*thread.hash(), DagNode::from(thread.clone()));

        // From thread, should reach all three
        let reachable = compute_reachable(&nodes, &[*thread.hash()]);
        assert_eq!(reachable.len(), 3);
        assert!(reachable.contains(forum.hash()));
        assert!(reachable.contains(board.hash()));
        assert!(reachable.contains(thread.hash()));

        // From board, should reach forum and board
        let reachable = compute_reachable(&nodes, &[*board.hash()]);
        assert_eq!(reachable.len(), 2);
        assert!(reachable.contains(forum.hash()));
        assert!(reachable.contains(board.hash()));
    }

    #[test]
    fn test_compute_missing() {
        let keypair = create_test_keypair();
        let forum = ForumGenesis::create(
            "Test".to_string(),
            "Desc".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let board = BoardGenesis::create(
            *forum.hash(),
            "Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let mut nodes: HashMap<ContentHash, DagNode> = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
        nodes.insert(*board.hash(), DagNode::from(board.clone()));

        // Client has only forum
        let missing = compute_missing(&nodes, &[*forum.hash()]);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], *board.hash());

        // Client has nothing
        let missing = compute_missing(&nodes, &[]);
        assert_eq!(missing.len(), 2);
        // Forum should come before board
        assert_eq!(missing[0], *forum.hash());
        assert_eq!(missing[1], *board.hash());
    }

    #[test]
    fn test_topological_order() {
        let keypair = create_test_keypair();
        let forum = ForumGenesis::create(
            "Test".to_string(),
            "Desc".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let board = BoardGenesis::create(
            *forum.hash(),
            "Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let mut nodes: HashMap<ContentHash, DagNode> = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
        nodes.insert(*board.hash(), DagNode::from(board.clone()));

        let ordered = nodes_in_topological_order(&nodes);
        assert_eq!(ordered.len(), 2);
        // Forum must come before board
        assert_eq!(ordered[0].hash(), forum.hash());
        assert_eq!(ordered[1].hash(), board.hash());
    }
}
