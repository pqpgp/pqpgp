//! Generic DAG operations for synchronization.
//!
//! These algorithms work on any DAG structure and are used for:
//! - Computing reachable nodes from a set of heads
//! - Finding missing nodes between client and server states
//! - Topologically sorting nodes (parents before children)
//! - Detecting cycles in the DAG
//!
//! The operations are generic over node types via the `DagNodeOps` trait,
//! supporting both in-memory state and persistent storage backends.
//!
//! ## Performance
//!
//! - `compute_reachable`: O(n + e) where n is nodes and e is edges
//! - `compute_missing`: O(n + e) using Kahn's algorithm
//! - `topological_sort_hashes`: O(n + e) using Kahn's algorithm
//! - `detect_cycle`: O(n + e) using DFS with coloring

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
/// Uses Kahn's algorithm for O(n + e) complexity where n is nodes and e is edges.
/// Guarantees that for any node in the result, all its parents that are
/// also in the input appear earlier in the output.
///
/// # Arguments
/// * `nodes` - Slice of node references to sort
///
/// # Returns
/// Vector of node hashes in topological order. If a cycle is detected,
/// returns as many nodes as possible in valid order (nodes in cycles are omitted).
///
/// # Algorithm
/// Kahn's algorithm:
/// 1. Compute in-degree for each node (count of parents within the set)
/// 2. Start with nodes that have in-degree 0 (no parents in set)
/// 3. For each processed node, decrement in-degree of its children
/// 4. Add newly zero-degree nodes to the queue
pub fn topological_sort_hashes<N: DagNodeOps>(nodes: &[&N]) -> Vec<ContentHash> {
    if nodes.is_empty() {
        return Vec::new();
    }

    // Build node set for O(1) membership checks
    let node_set: HashSet<ContentHash> = nodes.iter().map(|n| *n.hash()).collect();

    // Build a map from hash to node for quick lookup
    let node_map: HashMap<ContentHash, &N> = nodes.iter().map(|n| (*n.hash(), *n)).collect();

    // Compute in-degree for each node (count of parents within the node set)
    let mut in_degree: HashMap<ContentHash, usize> = HashMap::with_capacity(nodes.len());
    for node in nodes {
        let hash = *node.hash();
        let degree = node
            .parent_hashes()
            .iter()
            .filter(|p| node_set.contains(p))
            .count();
        in_degree.insert(hash, degree);
    }

    // Build reverse adjacency: for each node, which nodes have it as a parent?
    // This allows us to efficiently find children when processing a node.
    let mut children: HashMap<ContentHash, Vec<ContentHash>> = HashMap::with_capacity(nodes.len());
    for node in nodes {
        let hash = *node.hash();
        for parent in node.parent_hashes() {
            if node_set.contains(&parent) {
                children.entry(parent).or_default().push(hash);
            }
        }
    }

    // Initialize queue with nodes that have no parents in the set (in-degree 0)
    // Sort by created_at for deterministic ordering among nodes with same in-degree
    let mut ready: Vec<ContentHash> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(hash, _)| *hash)
        .collect();
    ready.sort_by_key(|hash| node_map.get(hash).map(|n| n.created_at()).unwrap_or(0));

    let mut queue: VecDeque<ContentHash> = ready.into_iter().collect();
    let mut result = Vec::with_capacity(nodes.len());

    // Process nodes in topological order
    while let Some(hash) = queue.pop_front() {
        result.push(hash);

        // For each child of this node, decrement its in-degree
        if let Some(child_list) = children.get(&hash) {
            // Collect newly ready children and sort them by timestamp for determinism
            let mut newly_ready: Vec<ContentHash> = Vec::new();

            for &child_hash in child_list {
                if let Some(degree) = in_degree.get_mut(&child_hash) {
                    *degree = degree.saturating_sub(1);
                    if *degree == 0 {
                        newly_ready.push(child_hash);
                    }
                }
            }

            // Sort newly ready nodes by timestamp for deterministic ordering
            newly_ready.sort_by_key(|hash| node_map.get(hash).map(|n| n.created_at()).unwrap_or(0));
            for child in newly_ready {
                queue.push_back(child);
            }
        }
    }

    // If result.len() < nodes.len(), there was a cycle - some nodes couldn't be added
    // We return what we could process; the cycle detection should be done at validation time
    result
}

/// Returns node references in topological order (parents before children).
///
/// Unlike `topological_sort_hashes`, this returns references to the actual
/// nodes rather than just their hashes.
///
/// Uses Kahn's algorithm for O(n + e) complexity.
///
/// # Arguments
/// * `nodes` - Map of all nodes in the DAG
///
/// # Returns
/// Vector of node references in topological order
pub fn nodes_in_topological_order<N: DagNodeOps>(nodes: &HashMap<ContentHash, N>) -> Vec<&N> {
    if nodes.is_empty() {
        return Vec::new();
    }

    // Build set of all hashes for membership checks
    let all_hashes: HashSet<ContentHash> = nodes.keys().copied().collect();

    // Compute in-degree for each node
    let mut in_degree: HashMap<ContentHash, usize> = HashMap::with_capacity(nodes.len());
    for (hash, node) in nodes {
        let degree = node
            .parent_hashes()
            .iter()
            .filter(|p| all_hashes.contains(p))
            .count();
        in_degree.insert(*hash, degree);
    }

    // Build reverse adjacency: parent -> children
    let mut children: HashMap<ContentHash, Vec<ContentHash>> = HashMap::with_capacity(nodes.len());
    for (hash, node) in nodes {
        for parent in node.parent_hashes() {
            if all_hashes.contains(&parent) {
                children.entry(parent).or_default().push(*hash);
            }
        }
    }

    // Initialize with zero in-degree nodes, sorted by timestamp for determinism
    let mut ready: Vec<ContentHash> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(hash, _)| *hash)
        .collect();
    ready.sort_by_key(|hash| nodes.get(hash).map(|n| n.created_at()).unwrap_or(0));

    let mut queue: VecDeque<ContentHash> = ready.into_iter().collect();
    let mut result = Vec::with_capacity(nodes.len());

    while let Some(hash) = queue.pop_front() {
        if let Some(node) = nodes.get(&hash) {
            result.push(node);
        }

        if let Some(child_list) = children.get(&hash) {
            let mut newly_ready: Vec<ContentHash> = Vec::new();

            for &child_hash in child_list {
                if let Some(degree) = in_degree.get_mut(&child_hash) {
                    *degree = degree.saturating_sub(1);
                    if *degree == 0 {
                        newly_ready.push(child_hash);
                    }
                }
            }

            newly_ready.sort_by_key(|h| nodes.get(h).map(|n| n.created_at()).unwrap_or(0));
            for child in newly_ready {
                queue.push_back(child);
            }
        }
    }

    result
}

/// Detects if adding a node with the given parent hashes would create a cycle.
///
/// This is used during validation to prevent cycles in the DAG.
/// Since the new node doesn't exist in the DAG yet, the only way to create
/// a cycle is through self-reference (parent_hashes contains new_node_hash).
///
/// # Arguments
/// * `new_node_hash` - The hash of the node being added
/// * `parent_hashes` - The parent hashes the new node references
///
/// # Returns
/// `true` if a cycle would be created, `false` otherwise
pub fn would_create_cycle(new_node_hash: &ContentHash, parent_hashes: &[ContentHash]) -> bool {
    // Check for self-reference - the only way to create a cycle when adding a new node
    // since no existing node can reference a node that doesn't exist yet
    parent_hashes.contains(new_node_hash)
}

/// Checks if the given set of nodes contains a cycle.
///
/// Uses Kahn's algorithm - if we can't process all nodes, there's a cycle.
///
/// # Arguments
/// * `nodes` - The nodes to check
///
/// # Returns
/// `true` if a cycle exists, `false` otherwise
pub fn contains_cycle<N: DagNodeOps>(nodes: &HashMap<ContentHash, N>) -> bool {
    if nodes.is_empty() {
        return false;
    }

    let all_hashes: HashSet<ContentHash> = nodes.keys().copied().collect();

    // Compute in-degree for each node
    let mut in_degree: HashMap<ContentHash, usize> = HashMap::with_capacity(nodes.len());
    for (hash, node) in nodes {
        let degree = node
            .parent_hashes()
            .iter()
            .filter(|p| all_hashes.contains(p))
            .count();
        in_degree.insert(*hash, degree);
    }

    // Build reverse adjacency
    let mut children: HashMap<ContentHash, Vec<ContentHash>> = HashMap::with_capacity(nodes.len());
    for (hash, node) in nodes {
        for parent in node.parent_hashes() {
            if all_hashes.contains(&parent) {
                children.entry(parent).or_default().push(*hash);
            }
        }
    }

    // Process nodes with zero in-degree
    let mut queue: VecDeque<ContentHash> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(hash, _)| *hash)
        .collect();

    let mut processed = 0;

    while let Some(hash) = queue.pop_front() {
        processed += 1;

        if let Some(child_list) = children.get(&hash) {
            for &child_hash in child_list {
                if let Some(degree) = in_degree.get_mut(&child_hash) {
                    *degree = degree.saturating_sub(1);
                    if *degree == 0 {
                        queue.push_back(child_hash);
                    }
                }
            }
        }
    }

    // If we couldn't process all nodes, there's a cycle
    processed < nodes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple test node for verifying DAG operations.
    #[derive(Clone)]
    struct TestNode {
        hash: ContentHash,
        parents: Vec<ContentHash>,
        created_at: u64,
    }

    impl TestNode {
        fn new(hash: ContentHash, parent: Option<ContentHash>, created_at: u64) -> Self {
            Self {
                hash,
                parents: parent.into_iter().collect(),
                created_at,
            }
        }

        fn with_parents(hash: ContentHash, parents: Vec<ContentHash>, created_at: u64) -> Self {
            Self {
                hash,
                parents,
                created_at,
            }
        }
    }

    impl DagNodeOps for TestNode {
        fn hash(&self) -> &ContentHash {
            &self.hash
        }

        fn parent_hashes(&self) -> Vec<ContentHash> {
            self.parents.clone()
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
        let node = TestNode::new(hash, None, 1000);

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

        let node1 = TestNode::new(hash1, None, 1000);
        let node2 = TestNode::new(hash2, Some(hash1), 2000);
        let node3 = TestNode::new(hash3, Some(hash2), 3000);

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

        let node1 = TestNode::new(hash1, None, 1000);
        let node2 = TestNode::new(hash2, Some(hash1), 2000);

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

        let node1 = TestNode::new(hash1, None, 1000);
        let node2 = TestNode::new(hash2, Some(hash1), 2000);

        let mut nodes = HashMap::new();
        nodes.insert(hash1, node1);
        nodes.insert(hash2, node2);

        let ordered = nodes_in_topological_order(&nodes);
        assert_eq!(ordered.len(), 2);
        // Node1 must come before node2
        assert_eq!(ordered[0].hash, hash1);
        assert_eq!(ordered[1].hash, hash2);
    }

    #[test]
    fn test_would_create_cycle_self_reference() {
        let hash1 = make_hash(1);

        // Self-reference should be detected
        assert!(would_create_cycle(&hash1, &[hash1]));
    }

    #[test]
    fn test_would_create_cycle_no_cycle() {
        let hash2 = make_hash(2);
        let hash3 = make_hash(3);

        // Adding hash3 with parent hash2 should not create a cycle
        assert!(!would_create_cycle(&hash3, &[hash2]));
    }

    #[test]
    fn test_contains_cycle_no_cycle() {
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);
        let hash3 = make_hash(3);

        let node1 = TestNode::new(hash1, None, 1000);
        let node2 = TestNode::new(hash2, Some(hash1), 2000);
        let node3 = TestNode::new(hash3, Some(hash2), 3000);

        let mut nodes = HashMap::new();
        nodes.insert(hash1, node1);
        nodes.insert(hash2, node2);
        nodes.insert(hash3, node3);

        assert!(!contains_cycle(&nodes));
    }

    #[test]
    fn test_contains_cycle_with_cycle() {
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);
        let hash3 = make_hash(3);

        // Create a cycle: 1 -> 2 -> 3 -> 1
        let node1 = TestNode::new(hash1, Some(hash3), 1000);
        let node2 = TestNode::new(hash2, Some(hash1), 2000);
        let node3 = TestNode::new(hash3, Some(hash2), 3000);

        let mut nodes = HashMap::new();
        nodes.insert(hash1, node1);
        nodes.insert(hash2, node2);
        nodes.insert(hash3, node3);

        assert!(contains_cycle(&nodes));
    }

    #[test]
    fn test_contains_cycle_self_loop() {
        let hash1 = make_hash(1);

        // Node references itself
        let node1 = TestNode::new(hash1, Some(hash1), 1000);

        let mut nodes = HashMap::new();
        nodes.insert(hash1, node1);

        assert!(contains_cycle(&nodes));
    }

    #[test]
    fn test_topological_sort_handles_cycle_gracefully() {
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        // Create a cycle: 1 -> 2 -> 1
        let node1 = TestNode::new(hash1, Some(hash2), 1000);
        let node2 = TestNode::new(hash2, Some(hash1), 2000);

        let nodes_vec: Vec<&TestNode> = vec![&node1, &node2];

        // Should return empty or partial result, not hang
        let result = topological_sort_hashes(&nodes_vec);
        // Neither node can be added because each depends on the other
        assert!(result.is_empty());
    }

    #[test]
    fn test_topological_sort_empty() {
        let nodes: Vec<&TestNode> = vec![];
        let result = topological_sort_hashes(&nodes);
        assert!(result.is_empty());
    }

    #[test]
    fn test_contains_cycle_empty() {
        let nodes: HashMap<ContentHash, TestNode> = HashMap::new();
        assert!(!contains_cycle(&nodes));
    }

    #[test]
    fn test_topological_order_diamond() {
        // Diamond structure: 1 -> 2, 1 -> 3, 2 -> 4, 3 -> 4
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);
        let hash3 = make_hash(3);
        let hash4 = make_hash(4);

        let node1 = TestNode::new(hash1, None, 1000);
        let node2 = TestNode::new(hash2, Some(hash1), 2000);
        let node3 = TestNode::new(hash3, Some(hash1), 2001);
        let node4 = TestNode::with_parents(hash4, vec![hash2, hash3], 3000);

        let mut nodes = HashMap::new();
        nodes.insert(hash1, node1);
        nodes.insert(hash2, node2);
        nodes.insert(hash3, node3);
        nodes.insert(hash4, node4);

        let ordered = nodes_in_topological_order(&nodes);
        assert_eq!(ordered.len(), 4);

        // Find positions
        let pos1 = ordered.iter().position(|n| n.hash == hash1).unwrap();
        let pos2 = ordered.iter().position(|n| n.hash == hash2).unwrap();
        let pos3 = ordered.iter().position(|n| n.hash == hash3).unwrap();
        let pos4 = ordered.iter().position(|n| n.hash == hash4).unwrap();

        // Verify ordering constraints
        assert!(pos1 < pos2, "node1 must come before node2");
        assert!(pos1 < pos3, "node1 must come before node3");
        assert!(pos2 < pos4, "node2 must come before node4");
        assert!(pos3 < pos4, "node3 must come before node4");
    }
}
