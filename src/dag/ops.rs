//! Generic DAG operations for synchronization.
//!
//! These algorithms work on any DAG structure and are used for:
//! - Computing reachable nodes from a set of heads
//! - Finding missing nodes between client and server states
//! - Topologically sorting nodes (parents before children)
//!
//! The operations are generic over node types via the `DagNodeOps` trait,
//! supporting both in-memory state and persistent storage backends.

use crate::dag::ContentHash;
use std::collections::{HashMap, HashSet, VecDeque};

/// Trait for types that can participate in DAG operations.
///
/// This trait provides the minimal interface needed for generic DAG algorithms
/// like reachability computation and topological sorting.
pub trait DagNodeOps {
    /// Returns the content hash of this node.
    fn hash(&self) -> &ContentHash;

    /// Returns the hashes of this node's parent nodes.
    fn parent_hashes(&self) -> Vec<ContentHash>;

    /// Returns the creation timestamp in milliseconds since Unix epoch.
    fn created_at(&self) -> u64;
}

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
pub fn compute_reachable<N: DagNodeOps>(
    nodes: &HashMap<ContentHash, N>,
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
pub fn compute_missing<N: DagNodeOps>(
    nodes: &HashMap<ContentHash, N>,
    client_heads: &[ContentHash],
) -> Vec<ContentHash> {
    // Compute what the client has by walking backwards from their heads
    let client_has = compute_reachable(nodes, client_heads);

    // Find nodes the client doesn't have
    let mut missing: Vec<&N> = nodes
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
pub fn topological_sort_hashes<N: DagNodeOps>(nodes: &[&N]) -> Vec<ContentHash> {
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

/// Returns node references in topological order (parents before children).
///
/// Unlike `topological_sort_hashes`, this returns references to the actual
/// nodes rather than just their hashes.
///
/// # Arguments
/// * `nodes` - Map of all nodes in the DAG
///
/// # Returns
/// Vector of node references in topological order
pub fn nodes_in_topological_order<N: DagNodeOps>(nodes: &HashMap<ContentHash, N>) -> Vec<&N> {
    let mut node_vec: Vec<&N> = nodes.values().collect();
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

    /// Simple test node for verifying DAG operations.
    #[derive(Clone, Copy)]
    struct TestNode {
        hash: ContentHash,
        parent: Option<ContentHash>,
        created_at: u64,
    }

    impl DagNodeOps for TestNode {
        fn hash(&self) -> &ContentHash {
            &self.hash
        }

        fn parent_hashes(&self) -> Vec<ContentHash> {
            self.parent.into_iter().collect()
        }

        fn created_at(&self) -> u64 {
            self.created_at
        }
    }

    fn make_hash(id: u8) -> ContentHash {
        let mut bytes = [0u8; 64];
        bytes[0] = id;
        ContentHash::from_bytes(bytes)
    }

    #[test]
    fn test_compute_reachable_single_node() {
        let hash = make_hash(1);
        let node = TestNode {
            hash,
            parent: None,
            created_at: 1000,
        };

        let mut nodes = HashMap::new();
        nodes.insert(hash, node);

        let reachable = compute_reachable(&nodes, &[hash]);
        assert_eq!(reachable.len(), 1);
        assert!(reachable.contains(&hash));
    }

    #[test]
    fn test_compute_reachable_chain() {
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);
        let hash3 = make_hash(3);

        let node1 = TestNode {
            hash: hash1,
            parent: None,
            created_at: 1000,
        };
        let node2 = TestNode {
            hash: hash2,
            parent: Some(hash1),
            created_at: 2000,
        };
        let node3 = TestNode {
            hash: hash3,
            parent: Some(hash2),
            created_at: 3000,
        };

        let mut nodes = HashMap::new();
        nodes.insert(hash1, node1);
        nodes.insert(hash2, node2);
        nodes.insert(hash3, node3);

        // From node3, should reach all three
        let reachable = compute_reachable(&nodes, &[hash3]);
        assert_eq!(reachable.len(), 3);
        assert!(reachable.contains(&hash1));
        assert!(reachable.contains(&hash2));
        assert!(reachable.contains(&hash3));

        // From node2, should reach node1 and node2
        let reachable = compute_reachable(&nodes, &[hash2]);
        assert_eq!(reachable.len(), 2);
        assert!(reachable.contains(&hash1));
        assert!(reachable.contains(&hash2));
    }

    #[test]
    fn test_compute_missing() {
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        let node1 = TestNode {
            hash: hash1,
            parent: None,
            created_at: 1000,
        };
        let node2 = TestNode {
            hash: hash2,
            parent: Some(hash1),
            created_at: 2000,
        };

        let mut nodes = HashMap::new();
        nodes.insert(hash1, node1);
        nodes.insert(hash2, node2);

        // Client has only node1
        let missing = compute_missing(&nodes, &[hash1]);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], hash2);

        // Client has nothing
        let missing = compute_missing(&nodes, &[]);
        assert_eq!(missing.len(), 2);
        // Node1 should come before node2
        assert_eq!(missing[0], hash1);
        assert_eq!(missing[1], hash2);
    }

    #[test]
    fn test_topological_order() {
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        let node1 = TestNode {
            hash: hash1,
            parent: None,
            created_at: 1000,
        };
        let node2 = TestNode {
            hash: hash2,
            parent: Some(hash1),
            created_at: 2000,
        };

        let mut nodes = HashMap::new();
        nodes.insert(hash1, node1);
        nodes.insert(hash2, node2);

        let ordered = nodes_in_topological_order(&nodes);
        assert_eq!(ordered.len(), 2);
        // Node1 must come before node2
        assert_eq!(ordered[0].hash, hash1);
        assert_eq!(ordered[1].hash, hash2);
    }
}
