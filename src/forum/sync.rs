//! Sync protocol types for forum DAG synchronization.
//!
//! This module defines the request/response types used for syncing forum data
//! between clients and relays. The protocol is designed to:
//! - Minimize data transfer with cursor-based pagination
//! - Support incremental sync with batching for scalability
//! - Be stateless on the server side
//!
//! ## Sync Protocol
//!
//! The sync protocol uses cursor-based pagination with a (timestamp, hash) cursor:
//!
//! 1. Client sends: `{ forum_hash, cursor_timestamp, cursor_hash, batch_size }`
//! 2. Server returns nodes after the cursor, up to batch_size
//! 3. Client stores nodes, uses response cursor for next request
//! 4. Repeat until `has_more = false`
//!
//! ### Cursor Format
//!
//! The cursor is `(timestamp, hash)` which provides:
//! - Efficient O(log n) seek using timestamp index
//! - Correct handling of multiple nodes with same timestamp (hash tiebreaker)
//! - No gaps or duplicates when paginating
//!
//! ### Benefits
//!
//! - O(log n) relay lookup with timestamp index
//! - Constant request size (just cursor fields)
//! - Constant response size (batch_size limit)
//! - Simple, stateless protocol

use crate::forum::{ContentHash, DagNode};
use serde::{Deserialize, Serialize};

/// Default batch size for sync requests.
pub const DEFAULT_SYNC_BATCH_SIZE: usize = 100;

/// Maximum batch size to prevent oversized responses.
pub const MAX_SYNC_BATCH_SIZE: usize = 500;

/// Request to sync with a forum's DAG.
///
/// Uses cursor-based pagination for efficient incremental sync.
///
/// ## Usage
///
/// 1. First sync: `cursor_timestamp = 0, cursor_hash = None`
/// 2. Response includes `next_cursor_*` fields
/// 3. Next request uses those as the new cursor
/// 4. Continue until `has_more = false`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    /// The forum hash to sync.
    pub forum_hash: ContentHash,
    /// Cursor timestamp: fetch nodes with timestamp >= this value.
    /// Use 0 for initial sync to get all nodes.
    pub cursor_timestamp: u64,
    /// Cursor hash: if provided, skip nodes at `cursor_timestamp` until after this hash.
    /// This handles ties when multiple nodes have the same timestamp.
    /// Use None for initial sync or when starting at a new timestamp.
    pub cursor_hash: Option<ContentHash>,
    /// Maximum number of nodes to return in this batch.
    /// Defaults to DEFAULT_SYNC_BATCH_SIZE if not specified.
    /// Capped at MAX_SYNC_BATCH_SIZE.
    pub batch_size: Option<usize>,
}

impl SyncRequest {
    /// Creates a new sync request for initial sync (all nodes).
    pub fn new(forum_hash: ContentHash) -> Self {
        Self {
            forum_hash,
            cursor_timestamp: 0,
            cursor_hash: None,
            batch_size: None,
        }
    }

    /// Creates a sync request with a cursor from a previous response.
    pub fn with_cursor(
        forum_hash: ContentHash,
        cursor_timestamp: u64,
        cursor_hash: Option<ContentHash>,
    ) -> Self {
        Self {
            forum_hash,
            cursor_timestamp,
            cursor_hash,
            batch_size: None,
        }
    }

    /// Sets the batch size for this request.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = Some(size.min(MAX_SYNC_BATCH_SIZE));
        self
    }

    /// Returns the effective batch size (applies defaults and limits).
    pub fn effective_batch_size(&self) -> usize {
        self.batch_size
            .unwrap_or(DEFAULT_SYNC_BATCH_SIZE)
            .min(MAX_SYNC_BATCH_SIZE)
    }
}

/// Response to a sync request.
///
/// Contains a batch of nodes and cursor for the next request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    /// The forum hash this response is for.
    pub forum_hash: ContentHash,
    /// Nodes in this batch, ordered by (timestamp, hash).
    /// These are serialized nodes ready for storage.
    pub nodes: Vec<SerializedNode>,
    /// Cursor timestamp for the next request.
    /// This is the timestamp of the last node in the batch.
    pub next_cursor_timestamp: u64,
    /// Cursor hash for the next request.
    /// This is the hash of the last node in the batch.
    /// Use both cursor fields in the next SyncRequest to continue.
    pub next_cursor_hash: Option<ContentHash>,
    /// Whether there are more nodes available after this batch.
    /// If true, client should make another request with the cursor fields.
    pub has_more: bool,
    /// Total number of nodes in the forum (optional, for progress display).
    pub total_nodes: Option<usize>,
}

impl SyncResponse {
    /// Creates a new sync response.
    pub fn new(forum_hash: ContentHash) -> Self {
        Self {
            forum_hash,
            nodes: Vec::new(),
            next_cursor_timestamp: 0,
            next_cursor_hash: None,
            has_more: false,
            total_nodes: None,
        }
    }

    /// Sets the nodes and cursor for this response.
    pub fn with_nodes(
        mut self,
        nodes: Vec<SerializedNode>,
        next_cursor_timestamp: u64,
        next_cursor_hash: ContentHash,
    ) -> Self {
        self.nodes = nodes;
        self.next_cursor_timestamp = next_cursor_timestamp;
        self.next_cursor_hash = Some(next_cursor_hash);
        self
    }

    /// Sets whether there are more nodes.
    pub fn with_has_more(mut self, has_more: bool) -> Self {
        self.has_more = has_more;
        self
    }

    /// Sets the total node count.
    pub fn with_total_nodes(mut self, total: usize) -> Self {
        self.total_nodes = Some(total);
        self
    }
}

/// A serialized node with its hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedNode {
    /// The content hash of the node.
    pub hash: ContentHash,
    /// The serialized node data (bincode format).
    pub data: Vec<u8>,
}

impl SerializedNode {
    /// Deserializes the node data.
    pub fn deserialize(&self) -> crate::error::Result<DagNode> {
        DagNode::from_bytes(&self.data)
    }
}

/// Request to submit a new node to the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitNodeRequest {
    /// The forum this node belongs to.
    pub forum_hash: ContentHash,
    /// The serialized node data.
    pub node_data: Vec<u8>,
}

impl SubmitNodeRequest {
    /// Creates a new submit request from a node.
    pub fn new(forum_hash: ContentHash, node: &DagNode) -> crate::error::Result<Self> {
        Ok(Self {
            forum_hash,
            node_data: node.to_bytes()?,
        })
    }

    /// Deserializes the node.
    pub fn deserialize_node(&self) -> crate::error::Result<DagNode> {
        DagNode::from_bytes(&self.node_data)
    }
}

/// Response to a submit request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitNodeResponse {
    /// Whether the node was accepted.
    pub accepted: bool,
    /// The hash of the accepted node (if accepted).
    pub node_hash: Option<ContentHash>,
    /// Error message if rejected.
    pub error: Option<String>,
}

impl SubmitNodeResponse {
    /// Creates a successful response.
    pub fn accepted(hash: ContentHash) -> Self {
        Self {
            accepted: true,
            node_hash: Some(hash),
            error: None,
        }
    }

    /// Creates a rejection response.
    pub fn rejected(error: impl Into<String>) -> Self {
        Self {
            accepted: false,
            node_hash: None,
            error: Some(error.into()),
        }
    }
}

/// Request to export an entire forum's DAG.
///
/// Used for backup or full clone operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportForumRequest {
    /// The forum hash to export.
    pub forum_hash: ContentHash,
}

impl ExportForumRequest {
    /// Creates a new export request.
    pub fn new(forum_hash: ContentHash) -> Self {
        Self { forum_hash }
    }
}

/// Response containing a forum export (paginated).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportForumResponse {
    /// The forum hash.
    pub forum_hash: ContentHash,
    /// Nodes in this page, in topological order.
    pub nodes: Vec<SerializedNode>,
    /// Total number of nodes in the forum (across all pages).
    pub total_nodes: Option<usize>,
    /// Whether there are more pages available.
    #[serde(default)]
    pub has_more: bool,
}

impl ExportForumResponse {
    /// Creates a new export response.
    pub fn new(forum_hash: ContentHash) -> Self {
        Self {
            forum_hash,
            nodes: Vec::new(),
            total_nodes: None,
            has_more: false,
        }
    }

    /// Adds nodes to the response.
    pub fn with_nodes(mut self, nodes: Vec<SerializedNode>) -> Self {
        self.total_nodes = Some(nodes.len());
        self.nodes = nodes;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash() -> ContentHash {
        ContentHash::from_bytes([42u8; 64])
    }

    #[test]
    fn test_sync_request_creation() {
        let hash = test_hash();
        let req = SyncRequest::new(hash);

        assert_eq!(req.forum_hash, hash);
        assert_eq!(req.cursor_timestamp, 0);
        assert!(req.cursor_hash.is_none());
        assert!(req.batch_size.is_none());
    }

    #[test]
    fn test_sync_request_with_cursor() {
        let hash = test_hash();
        let cursor_hash = ContentHash::from_bytes([1u8; 64]);
        let req = SyncRequest::with_cursor(hash, 12345, Some(cursor_hash));

        assert_eq!(req.forum_hash, hash);
        assert_eq!(req.cursor_timestamp, 12345);
        assert_eq!(req.cursor_hash, Some(cursor_hash));
    }

    #[test]
    fn test_sync_request_with_batch_size() {
        let hash = test_hash();
        let req = SyncRequest::new(hash).with_batch_size(50);

        assert_eq!(req.batch_size, Some(50));
        assert_eq!(req.effective_batch_size(), 50);
    }

    #[test]
    fn test_sync_request_batch_size_capped() {
        let hash = test_hash();
        let req = SyncRequest::new(hash).with_batch_size(1000);

        // Should be capped at MAX_SYNC_BATCH_SIZE
        assert_eq!(req.batch_size, Some(MAX_SYNC_BATCH_SIZE));
        assert_eq!(req.effective_batch_size(), MAX_SYNC_BATCH_SIZE);
    }

    #[test]
    fn test_sync_request_default_batch_size() {
        let hash = test_hash();
        let req = SyncRequest::new(hash);

        assert_eq!(req.effective_batch_size(), DEFAULT_SYNC_BATCH_SIZE);
    }

    #[test]
    fn test_sync_response_creation() {
        let hash = test_hash();
        let node_hash = ContentHash::from_bytes([1u8; 64]);
        let nodes = vec![SerializedNode {
            hash: node_hash,
            data: vec![1, 2, 3],
        }];

        let resp = SyncResponse::new(hash)
            .with_nodes(nodes, 12345, node_hash)
            .with_has_more(true)
            .with_total_nodes(100);

        assert_eq!(resp.forum_hash, hash);
        assert_eq!(resp.nodes.len(), 1);
        assert_eq!(resp.next_cursor_timestamp, 12345);
        assert_eq!(resp.next_cursor_hash, Some(node_hash));
        assert!(resp.has_more);
        assert_eq!(resp.total_nodes, Some(100));
    }

    #[test]
    fn test_submit_node_response_accepted() {
        let hash = test_hash();
        let resp = SubmitNodeResponse::accepted(hash);

        assert!(resp.accepted);
        assert_eq!(resp.node_hash, Some(hash));
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_submit_node_response_rejected() {
        let resp = SubmitNodeResponse::rejected("Invalid signature");

        assert!(!resp.accepted);
        assert!(resp.node_hash.is_none());
        assert_eq!(resp.error, Some("Invalid signature".to_string()));
    }

    #[test]
    fn test_export_forum_request() {
        let hash = test_hash();
        let req = ExportForumRequest::new(hash);

        assert_eq!(req.forum_hash, hash);
    }

    #[test]
    fn test_export_forum_response() {
        let hash = test_hash();
        let nodes = vec![SerializedNode {
            hash: ContentHash::from_bytes([1u8; 64]),
            data: vec![1, 2, 3],
        }];
        let resp = ExportForumResponse::new(hash).with_nodes(nodes);

        assert_eq!(resp.forum_hash, hash);
        assert_eq!(resp.nodes.len(), 1);
        assert_eq!(resp.total_nodes, Some(1));
    }

    #[test]
    fn test_serialized_node() {
        let node = SerializedNode {
            hash: test_hash(),
            data: vec![1, 2, 3],
        };

        assert_eq!(node.hash, test_hash());
        assert_eq!(node.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_sync_request_serialization() {
        let req = SyncRequest::new(test_hash()).with_batch_size(50);
        let bytes = bincode::serialize(&req).expect("Failed to serialize");
        let deserialized: SyncRequest =
            bincode::deserialize(&bytes).expect("Failed to deserialize");

        assert_eq!(req.forum_hash, deserialized.forum_hash);
        assert_eq!(req.cursor_timestamp, deserialized.cursor_timestamp);
        assert_eq!(req.batch_size, deserialized.batch_size);
    }

    #[test]
    fn test_sync_response_serialization() {
        let node_hash = ContentHash::from_bytes([1u8; 64]);
        let nodes = vec![SerializedNode {
            hash: node_hash,
            data: vec![1, 2, 3],
        }];
        let resp = SyncResponse::new(test_hash())
            .with_nodes(nodes, 12345, node_hash)
            .with_has_more(true);

        let bytes = bincode::serialize(&resp).expect("Failed to serialize");
        let deserialized: SyncResponse =
            bincode::deserialize(&bytes).expect("Failed to deserialize");

        assert_eq!(resp.forum_hash, deserialized.forum_hash);
        assert_eq!(resp.nodes.len(), deserialized.nodes.len());
        assert_eq!(
            resp.next_cursor_timestamp,
            deserialized.next_cursor_timestamp
        );
        assert_eq!(resp.has_more, deserialized.has_more);
    }
}
