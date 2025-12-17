//! Shared DAG operations for forum synchronization.
//!
//! These algorithms are used by both the relay server and client for:
//! - Computing reachable nodes from a set of heads
//! - Finding missing nodes between client and server states
//! - Topologically sorting nodes (parents before children)
//!
//! All operations work on generic node collections to support both in-memory
//! state (relay) and persistent storage (client).

use crate::forum::{ContentHash, DagNode};
use std::collections::{HashMap, HashSet, VecDeque};

/// Computes all nodes reachable by walking backwards from heads.
///
/// Starting from the given head nodes, traverses parent links to find all
/// ancestors. This is used to determine what nodes a client already has.
///
/// # Arguments
/// * `nodes` - Map of all nodes in the DAG
/// * `heads` - Starting points for traversal
///
/// # Returns
/// Set of all reachable node hashes (including the heads themselves)
pub fn compute_reachable(
    nodes: &HashMap<ContentHash, DagNode>,
    heads: &[ContentHash],
) -> HashSet<ContentHash> {
    let mut reachable = HashSet::new();
    let mut queue: VecDeque<ContentHash> = heads.iter().copied().collect();

    while let Some(hash) = queue.pop_front() {
        if reachable.contains(&hash) {
            continue;
        }

        if let Some(node) = nodes.get(&hash) {
            reachable.insert(hash);
            for parent_hash in node.parent_hashes() {
                if !reachable.contains(&parent_hash) {
                    queue.push_back(parent_hash);
                }
            }
        }
    }

    reachable
}

/// Computes which nodes a client is missing given their known heads.
///
/// Returns hashes in topological order (parents before children), ensuring
/// the client can process them sequentially without missing dependencies.
///
/// # Arguments
/// * `nodes` - Map of all nodes in the DAG (server state)
/// * `client_heads` - The head nodes the client currently has
///
/// # Returns
/// Vector of missing node hashes in topological order
pub fn compute_missing(
    nodes: &HashMap<ContentHash, DagNode>,
    client_heads: &[ContentHash],
) -> Vec<ContentHash> {
    // Compute what the client has by walking backwards from their heads
    let client_has = compute_reachable(nodes, client_heads);

    // Find nodes the client doesn't have
    let mut missing: Vec<&DagNode> = nodes
        .values()
        .filter(|node| !client_has.contains(node.hash()))
        .collect();

    // Sort by created_at as initial approximation
    missing.sort_by_key(|n| n.created_at());

    // Proper topological sort: ensure parents come before children
    topological_sort_hashes(&missing)
}

/// Sorts nodes into topological order (parents before children).
///
/// Uses Kahn's algorithm variant with created_at as tiebreaker.
/// Guarantees that for any node in the result, all its parents that are
/// also in the input appear earlier in the output.
///
/// # Arguments
/// * `nodes` - Slice of node references to sort
///
/// # Returns
/// Vector of node hashes in topological order
pub fn topological_sort_hashes(nodes: &[&DagNode]) -> Vec<ContentHash> {
    let node_set: HashSet<ContentHash> = nodes.iter().map(|n| *n.hash()).collect();
    let mut result = Vec::with_capacity(nodes.len());
    let mut added: HashSet<ContentHash> = HashSet::new();

    // Keep iterating until all nodes are added
    while added.len() < nodes.len() {
        for node in nodes {
            let hash = *node.hash();
            if added.contains(&hash) {
                continue;
            }

            // Check if all parents in the node set are already added
            let parents_ready = node
                .parent_hashes()
                .iter()
                .all(|parent| !node_set.contains(parent) || added.contains(parent));

            if parents_ready {
                result.push(hash);
                added.insert(hash);
            }
        }
    }

    result
}

/// Returns nodes in topological order (parents before children).
///
/// Unlike `topological_sort_hashes`, this returns references to the actual
/// nodes rather than just their hashes.
///
/// # Arguments
/// * `nodes` - Map of all nodes in the DAG
///
/// # Returns
/// Vector of node references in topological order
pub fn nodes_in_topological_order(nodes: &HashMap<ContentHash, DagNode>) -> Vec<&DagNode> {
    let mut node_vec: Vec<&DagNode> = nodes.values().collect();
    node_vec.sort_by_key(|n| n.created_at());

    let all_hashes: HashSet<ContentHash> = node_vec.iter().map(|n| *n.hash()).collect();
    let mut result = Vec::with_capacity(node_vec.len());
    let mut added: HashSet<ContentHash> = HashSet::new();

    while added.len() < node_vec.len() {
        for node in &node_vec {
            let hash = *node.hash();
            if added.contains(&hash) {
                continue;
            }

            let parents_ready = node
                .parent_hashes()
                .iter()
                .all(|parent| !all_hashes.contains(parent) || added.contains(parent));

            if parents_ready {
                result.push(*node);
                added.insert(hash);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::forum::{BoardGenesis, ForumGenesis, ThreadRoot};

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

        let mut nodes = HashMap::new();
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
            vec![],
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

        let mut nodes = HashMap::new();
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
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let mut nodes = HashMap::new();
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
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let mut nodes = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
        nodes.insert(*board.hash(), DagNode::from(board.clone()));

        let ordered = nodes_in_topological_order(&nodes);
        assert_eq!(ordered.len(), 2);
        // Forum must come before board
        assert_eq!(ordered[0].hash(), forum.hash());
        assert_eq!(ordered[1].hash(), board.hash());
    }
}
