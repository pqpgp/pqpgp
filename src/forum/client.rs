//! Forum client with sync capabilities.
//!
//! This module provides a client for interacting with forum relays,
//! including synchronization of forum DAG data.
//!
//! ## Usage
//!
//! ```ignore
//! let storage = ForumStorage::new("./forum_data")?;
//! let client = ForumClient::new(storage, "http://relay.example.com");
//!
//! // Sync a forum
//! client.sync_forum(&forum_hash).await?;
//!
//! // Create and submit a post
//! let post = Post::create(...)?;
//! client.submit_node(&DagNode::from(post)).await?;
//! ```

use crate::error::{PqpgpError, Result};
use crate::forum::permissions::ForumPermissions;
use crate::forum::sync::{
    ExportForumRequest, ExportForumResponse, SerializedNode, SubmitNodeRequest, SubmitNodeResponse,
    SyncRequest, SyncResponse,
};
use crate::forum::types::current_timestamp_millis;
use crate::forum::validation::{validate_node, ValidationContext};
use crate::forum::{ContentHash, DagNode, ForumStorage, PermissionBuilder};
use std::collections::{HashMap, HashSet, VecDeque};

/// Client for interacting with forum relays.
///
/// Handles synchronization of forum data between local storage and remote relays.
pub struct ForumClient {
    /// Local storage for forum data.
    storage: ForumStorage,
    /// Base URL of the relay server.
    relay_url: String,
}

impl ForumClient {
    /// Creates a new forum client.
    pub fn new(storage: ForumStorage, relay_url: impl Into<String>) -> Self {
        Self {
            storage,
            relay_url: relay_url.into(),
        }
    }

    /// Returns a reference to the local storage.
    pub fn storage(&self) -> &ForumStorage {
        &self.storage
    }

    /// Returns a mutable reference to the local storage.
    pub fn storage_mut(&mut self) -> &mut ForumStorage {
        &mut self.storage
    }

    /// Returns the relay URL.
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// Sets the relay URL.
    pub fn set_relay_url(&mut self, url: impl Into<String>) {
        self.relay_url = url.into();
    }

    /// Builds a sync request for a forum.
    ///
    /// Creates a request with the cursor for incremental sync.
    /// The cursor is stored locally and updated after each successful sync.
    pub fn build_sync_request(
        &self,
        forum_hash: &ContentHash,
        cursor_timestamp: u64,
        cursor_hash: Option<ContentHash>,
    ) -> SyncRequest {
        SyncRequest::with_cursor(*forum_hash, cursor_timestamp, cursor_hash)
    }

    /// Processes a sync response by storing the nodes.
    ///
    /// Returns the number of nodes stored.
    /// The response contains nodes directly, ordered by (timestamp, hash).
    pub fn process_sync_response(&self, response: &SyncResponse) -> Result<usize> {
        self.store_nodes(&response.nodes)
    }

    /// Builds the validation context from existing storage.
    ///
    /// Loads all nodes and computes permissions for validation.
    fn build_validation_context(
        &self,
    ) -> Result<(
        HashMap<ContentHash, DagNode>,
        HashMap<ContentHash, ForumPermissions>,
    )> {
        let nodes = self.storage.load_all_nodes()?;

        // Build permissions by replaying nodes
        let mut builder = PermissionBuilder::new();
        let mut sorted_nodes: Vec<&DagNode> = nodes.values().collect();
        sorted_nodes.sort_by_key(|n| n.created_at());

        for node in sorted_nodes {
            // Ignore errors for non-permission nodes
            let _ = builder.process_node(node);
        }

        let permissions = builder.into_permissions();
        Ok((nodes, permissions))
    }

    /// Validates and stores serialized nodes.
    ///
    /// Nodes should be in topological order (parents before children).
    /// Returns the number of nodes successfully stored.
    pub fn store_nodes(&self, nodes_to_store: &[SerializedNode]) -> Result<usize> {
        let mut stored = 0;

        // Build validation context from existing nodes
        let (mut nodes, mut permissions) = self.build_validation_context()?;
        let current_time = current_timestamp_millis();

        // Process nodes in order (should be topological)
        for serialized in nodes_to_store {
            // Deserialize
            let node: DagNode = serialized.deserialize()?;

            // Verify hash matches
            if node.hash() != &serialized.hash {
                return Err(PqpgpError::validation(format!(
                    "Hash mismatch: expected {}, got {}",
                    serialized.hash.to_hex(),
                    node.hash().to_hex()
                )));
            }

            // Build context with current state
            let ctx = ValidationContext::new(&nodes, &permissions, current_time);

            // Validate the node
            let result = validate_node(&node, &ctx)?;
            if !result.is_valid {
                return Err(PqpgpError::validation(format!(
                    "Node validation failed: {:?}",
                    result.errors
                )));
            }

            // Store the node
            self.storage.store_node(&node)?;

            // Update state for subsequent validations
            // Add to nodes map
            nodes.insert(*node.hash(), node.clone());

            // Update permissions if this is a forum genesis or mod action
            let mut builder = PermissionBuilder::new();
            // Copy existing permissions by replaying forum geneses
            for hash in permissions.keys() {
                if let Some(existing_node) = nodes.get(hash) {
                    if let DagNode::ForumGenesis(_) = existing_node {
                        let _ = builder.process_node(existing_node);
                    }
                }
            }
            // Process new node
            let _ = builder.process_node(&node);
            // Merge new permissions
            for (hash, new_perms) in builder.into_permissions() {
                permissions.insert(hash, new_perms);
            }

            stored += 1;
        }

        Ok(stored)
    }

    /// Updates local heads after a successful sync.
    pub fn update_heads(
        &self,
        forum_hash: &ContentHash,
        server_heads: &[ContentHash],
    ) -> Result<()> {
        let heads: HashSet<ContentHash> = server_heads.iter().copied().collect();
        self.storage.set_heads(forum_hash, &heads)
    }

    /// Builds a submit request for a node.
    pub fn build_submit_request(
        &self,
        forum_hash: &ContentHash,
        node: &DagNode,
    ) -> Result<SubmitNodeRequest> {
        SubmitNodeRequest::new(*forum_hash, node)
    }

    /// Processes a submit response and updates local state if accepted.
    pub fn process_submit_response(
        &self,
        response: &SubmitNodeResponse,
        node: &DagNode,
        forum_hash: &ContentHash,
    ) -> Result<()> {
        if !response.accepted {
            return Err(PqpgpError::validation(
                response
                    .error
                    .clone()
                    .unwrap_or_else(|| "Unknown error".to_string()),
            ));
        }

        // Store the node locally
        self.storage.store_node(node)?;

        // Update heads: the new node becomes a head, its parents are no longer heads
        let mut heads = self.storage.get_heads(forum_hash)?;

        // Remove parent hashes from heads
        for parent_hash in node.parent_hashes() {
            heads.remove(&parent_hash);
        }

        // Add this node as a new head
        heads.insert(*node.hash());

        self.storage.set_heads(forum_hash, &heads)?;

        Ok(())
    }

    /// Builds an export request for a forum.
    pub fn build_export_request(&self, forum_hash: &ContentHash) -> ExportForumRequest {
        ExportForumRequest::new(*forum_hash)
    }

    /// Imports a full forum export.
    ///
    /// Returns the number of nodes imported.
    pub fn import_forum(&self, response: &ExportForumResponse) -> Result<usize> {
        let stored = self.store_nodes(&response.nodes)?;

        // Set heads from the imported data
        let heads = self.compute_heads_from_nodes(&response.nodes)?;
        self.storage.set_heads(&response.forum_hash, &heads)?;

        Ok(stored)
    }

    /// Computes DAG heads from a set of serialized nodes.
    ///
    /// Heads are nodes that are not referenced as parents by any other node.
    fn compute_heads_from_nodes(
        &self,
        nodes: &[crate::forum::sync::SerializedNode],
    ) -> Result<HashSet<ContentHash>> {
        // Collect all node hashes
        let all_hashes: HashSet<ContentHash> = nodes.iter().map(|n| n.hash).collect();

        // Collect all parent references
        let mut parent_refs: HashSet<ContentHash> = HashSet::new();
        for serialized in nodes {
            let node = serialized.deserialize()?;
            for parent_hash in node.parent_hashes() {
                parent_refs.insert(parent_hash);
            }
        }

        // Heads are nodes not referenced as parents
        Ok(all_hashes.difference(&parent_refs).copied().collect())
    }

    /// Performs topological sort of nodes.
    ///
    /// Returns nodes in an order where parents come before children.
    pub fn topological_sort(&self, nodes: &[DagNode]) -> Result<Vec<DagNode>> {
        // Build adjacency information
        let node_map: HashMap<ContentHash, &DagNode> =
            nodes.iter().map(|n| (*n.hash(), n)).collect();
        let mut in_degree: HashMap<ContentHash, usize> = HashMap::new();
        let mut children: HashMap<ContentHash, Vec<ContentHash>> = HashMap::new();

        // Initialize all nodes with 0 in-degree
        for node in nodes {
            let hash = *node.hash();
            in_degree.entry(hash).or_insert(0);
            children.entry(hash).or_default();
        }

        // Count in-degrees based on parent references within this set
        for node in nodes {
            let hash = *node.hash();
            for parent_hash in node.parent_hashes() {
                if node_map.contains_key(&parent_hash) {
                    *in_degree.entry(hash).or_insert(0) += 1;
                    children.entry(parent_hash).or_default().push(hash);
                }
            }
        }

        // Kahn's algorithm
        let mut queue: VecDeque<ContentHash> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(hash, _)| *hash)
            .collect();

        let mut sorted = Vec::new();

        while let Some(hash) = queue.pop_front() {
            if let Some(&node) = node_map.get(&hash) {
                sorted.push(node.clone());
            }

            if let Some(child_hashes) = children.get(&hash) {
                for &child_hash in child_hashes {
                    if let Some(deg) = in_degree.get_mut(&child_hash) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            queue.push_back(child_hash);
                        }
                    }
                }
            }
        }

        if sorted.len() != nodes.len() {
            return Err(PqpgpError::validation("Cycle detected in DAG"));
        }

        Ok(sorted)
    }

    /// Computes nodes reachable from a set of heads.
    ///
    /// This is useful for determining what nodes a client needs based on their heads.
    pub fn compute_reachable(
        &self,
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

    /// Computes the difference between server and client knowledge.
    ///
    /// Returns hashes of nodes the client is missing.
    pub fn compute_missing(
        &self,
        all_nodes: &HashMap<ContentHash, DagNode>,
        server_heads: &[ContentHash],
        client_heads: &[ContentHash],
    ) -> Vec<ContentHash> {
        let server_reachable = self.compute_reachable(all_nodes, server_heads);
        let client_reachable = self.compute_reachable(all_nodes, client_heads);

        // Nodes the server has that client doesn't
        let missing: Vec<ContentHash> = server_reachable
            .difference(&client_reachable)
            .copied()
            .collect();

        // Sort topologically for proper ordering
        let mut missing_nodes: Vec<DagNode> = missing
            .iter()
            .filter_map(|h| all_nodes.get(h).cloned())
            .collect();

        if let Ok(sorted) = self.topological_sort(&missing_nodes) {
            missing_nodes = sorted;
        }

        missing_nodes.iter().map(|n| *n.hash()).collect()
    }

    /// Validates all nodes in storage for a forum.
    ///
    /// Returns validation errors if any nodes are invalid.
    pub fn validate_forum(&self, forum_hash: &ContentHash) -> Result<Vec<String>> {
        let forum_nodes = self.storage.load_forum_nodes(forum_hash)?;
        let mut errors = Vec::new();

        // Sort topologically
        let sorted = self.topological_sort(&forum_nodes)?;

        // Build state incrementally during validation
        let mut nodes: HashMap<ContentHash, DagNode> = HashMap::new();
        let mut permissions: HashMap<ContentHash, ForumPermissions> = HashMap::new();
        let current_time = current_timestamp_millis();

        for node in &sorted {
            // Build context with current state
            let ctx = ValidationContext::new(&nodes, &permissions, current_time);

            match validate_node(node, &ctx) {
                Ok(result) => {
                    if !result.is_valid {
                        for error in result.errors {
                            errors.push(format!("{}: {}", node.hash().to_hex(), error));
                        }
                    } else {
                        // Add validated node to state
                        nodes.insert(*node.hash(), node.clone());

                        // Update permissions if needed
                        if let DagNode::ForumGenesis(forum) = node {
                            permissions
                                .insert(*forum.hash(), ForumPermissions::from_genesis(forum));
                        }
                        if let DagNode::ModAction(action) = node {
                            if let Some(perms) = permissions.get_mut(action.forum_hash()) {
                                let _ = perms.apply_action(action);
                            }
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!("{}: {}", node.hash().to_hex(), e));
                }
            }
        }

        Ok(errors)
    }

    /// Rebuilds forum permissions from the DAG.
    pub fn rebuild_permissions(&self, forum_hash: &ContentHash) -> Result<PermissionBuilder> {
        let nodes = self.storage.load_forum_nodes(forum_hash)?;
        let sorted = self.topological_sort(&nodes)?;

        let mut builder = PermissionBuilder::new();
        for node in &sorted {
            builder.process_node(node)?;
        }

        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::forum::{BoardGenesis, ForumGenesis, Post, ThreadRoot};
    use tempfile::TempDir;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
    }

    fn create_test_client() -> (ForumClient, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let storage = ForumStorage::new(temp_dir.path().join("forum_data"))
            .expect("Failed to create storage");
        let client = ForumClient::new(storage, "http://localhost:8080");
        (client, temp_dir)
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
    fn test_client_creation() {
        let (client, _temp_dir) = create_test_client();
        assert_eq!(client.relay_url(), "http://localhost:8080");
    }

    #[test]
    fn test_build_sync_request() {
        let (client, _temp_dir) = create_test_client();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        // Initial sync request with cursor at 0
        let req = client.build_sync_request(forum.hash(), 0, None);
        assert_eq!(req.forum_hash, *forum.hash());
        assert_eq!(req.cursor_timestamp, 0);
        assert!(req.cursor_hash.is_none());
    }

    #[test]
    fn test_build_sync_request_with_heads() {
        let (client, _temp_dir) = create_test_client();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        // Store forum and set heads
        client
            .storage()
            .store_node(&DagNode::from(forum.clone()))
            .unwrap();

        let mut heads = HashSet::new();
        heads.insert(*forum.hash());
        client.storage().set_heads(forum.hash(), &heads).unwrap();

        let req = client.build_sync_request(forum.hash(), 0, None);
        assert_eq!(req.forum_hash, *forum.hash());
        assert_eq!(req.cursor_timestamp, 0);
        assert!(req.cursor_hash.is_none());
    }

    #[test]
    fn test_process_sync_response() {
        let (client, _temp_dir) = create_test_client();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        // Store the forum first so we can add nodes to it
        client
            .storage()
            .store_node(&DagNode::from(forum.clone()))
            .unwrap();

        let serialized = SerializedNode {
            hash: *forum.hash(),
            data: DagNode::from(forum.clone()).to_bytes().unwrap(),
        };

        let response = SyncResponse::new(*forum.hash())
            .with_nodes(vec![serialized], forum.created_at(), *forum.hash())
            .with_has_more(false);

        // Processing should succeed
        let stored = client.process_sync_response(&response).unwrap();
        // Node already exists so 0 new stored (validation context has it)
        assert!(stored <= 1);
    }

    #[test]
    fn test_update_heads() {
        let (client, _temp_dir) = create_test_client();
        let forum_hash = ContentHash::from_bytes([0u8; 64]);
        let head1 = ContentHash::from_bytes([1u8; 64]);
        let head2 = ContentHash::from_bytes([2u8; 64]);

        client.update_heads(&forum_hash, &[head1, head2]).unwrap();

        let heads = client.storage().get_heads(&forum_hash).unwrap();
        assert_eq!(heads.len(), 2);
        assert!(heads.contains(&head1));
        assert!(heads.contains(&head2));
    }

    #[test]
    fn test_topological_sort_simple() {
        let (client, _temp_dir) = create_test_client();
        let keypair = create_test_keypair();

        let forum = create_test_forum(&keypair);
        let board = BoardGenesis::create(
            *forum.hash(),
            "Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        // Unsorted order (child before parent)
        let nodes = vec![DagNode::from(board.clone()), DagNode::from(forum.clone())];

        let sorted = client.topological_sort(&nodes).unwrap();

        // Forum should come first
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].hash(), forum.hash());
        assert_eq!(sorted[1].hash(), board.hash());
    }

    #[test]
    fn test_topological_sort_complex() {
        let (client, _temp_dir) = create_test_client();
        let keypair = create_test_keypair();

        let forum = create_test_forum(&keypair);
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
        let post = Post::create(
            *thread.hash(),
            vec![],
            "Post".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        // Shuffled order
        let nodes = vec![
            DagNode::from(post.clone()),
            DagNode::from(forum.clone()),
            DagNode::from(thread.clone()),
            DagNode::from(board.clone()),
        ];

        let sorted = client.topological_sort(&nodes).unwrap();

        assert_eq!(sorted.len(), 4);
        // Find positions
        let forum_pos = sorted
            .iter()
            .position(|n| n.hash() == forum.hash())
            .unwrap();
        let board_pos = sorted
            .iter()
            .position(|n| n.hash() == board.hash())
            .unwrap();
        let thread_pos = sorted
            .iter()
            .position(|n| n.hash() == thread.hash())
            .unwrap();
        let post_pos = sorted.iter().position(|n| n.hash() == post.hash()).unwrap();

        // Verify order constraints
        assert!(forum_pos < board_pos);
        assert!(board_pos < thread_pos);
        assert!(thread_pos < post_pos);
    }

    #[test]
    fn test_compute_reachable() {
        let (client, _temp_dir) = create_test_client();
        let keypair = create_test_keypair();

        let forum = create_test_forum(&keypair);
        let board = BoardGenesis::create(
            *forum.hash(),
            "Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let mut nodes = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
        nodes.insert(*board.hash(), DagNode::from(board.clone()));

        // From board head, should reach both board and forum
        let reachable = client.compute_reachable(&nodes, &[*board.hash()]);
        assert_eq!(reachable.len(), 2);
        assert!(reachable.contains(forum.hash()));
        assert!(reachable.contains(board.hash()));
    }

    #[test]
    fn test_compute_missing() {
        let (client, _temp_dir) = create_test_client();
        let keypair = create_test_keypair();

        let forum = create_test_forum(&keypair);
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

        let mut nodes = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
        nodes.insert(*board.hash(), DagNode::from(board.clone()));
        nodes.insert(*thread.hash(), DagNode::from(thread.clone()));

        // Server has everything (thread is head)
        // Client only has forum (forum is head)
        let missing = client.compute_missing(&nodes, &[*thread.hash()], &[*forum.hash()]);

        // Client should be missing board and thread
        assert_eq!(missing.len(), 2);
        // Board should come before thread (topological order)
        let board_pos = missing.iter().position(|h| h == board.hash()).unwrap();
        let thread_pos = missing.iter().position(|h| h == thread.hash()).unwrap();
        assert!(board_pos < thread_pos);
    }

    #[test]
    fn test_validate_forum() {
        let (client, _temp_dir) = create_test_client();
        let keypair = create_test_keypair();

        let forum = create_test_forum(&keypair);
        let board = BoardGenesis::create(
            *forum.hash(),
            "Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        client
            .storage()
            .store_node(&DagNode::from(forum.clone()))
            .unwrap();
        client.storage().store_node(&DagNode::from(board)).unwrap();

        let errors = client.validate_forum(forum.hash()).unwrap();
        assert!(errors.is_empty(), "Unexpected errors: {:?}", errors);
    }

    #[test]
    fn test_rebuild_permissions() {
        let (client, _temp_dir) = create_test_client();
        let keypair = create_test_keypair();

        let forum = create_test_forum(&keypair);
        client
            .storage()
            .store_node(&DagNode::from(forum.clone()))
            .unwrap();

        let builder = client.rebuild_permissions(forum.hash()).unwrap();
        let permissions = builder.get_permissions(forum.hash()).unwrap();

        assert!(permissions.is_owner(keypair.public_key().as_bytes().as_slice()));
        assert!(permissions.is_moderator(keypair.public_key().as_bytes().as_slice()));
    }

    #[test]
    fn test_set_relay_url() {
        let (mut client, _temp_dir) = create_test_client();
        client.set_relay_url("http://new-relay.example.com");
        assert_eq!(client.relay_url(), "http://new-relay.example.com");
    }

    #[test]
    fn test_compute_heads_from_nodes() {
        let (client, _temp_dir) = create_test_client();
        let keypair = create_test_keypair();

        let forum = create_test_forum(&keypair);
        let board = BoardGenesis::create(
            *forum.hash(),
            "Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let nodes = vec![
            crate::forum::sync::SerializedNode {
                hash: *forum.hash(),
                data: DagNode::from(forum.clone()).to_bytes().unwrap(),
            },
            crate::forum::sync::SerializedNode {
                hash: *board.hash(),
                data: DagNode::from(board.clone()).to_bytes().unwrap(),
            },
        ];

        let heads = client.compute_heads_from_nodes(&nodes).unwrap();

        // Board is the only head (forum is referenced by board)
        assert_eq!(heads.len(), 1);
        assert!(heads.contains(board.hash()));
    }

    #[test]
    fn test_build_submit_request() {
        let (client, _temp_dir) = create_test_client();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let node = DagNode::from(forum.clone());
        let request = client.build_submit_request(forum.hash(), &node).unwrap();

        assert_eq!(request.forum_hash, *forum.hash());

        // Verify we can deserialize it
        let deserialized = request.deserialize_node().unwrap();
        assert_eq!(deserialized.hash(), forum.hash());
    }

    #[test]
    fn test_build_export_request() {
        let (client, _temp_dir) = create_test_client();
        let hash = ContentHash::from_bytes([42u8; 64]);

        let request = client.build_export_request(&hash);
        assert_eq!(request.forum_hash, hash);
    }
}
