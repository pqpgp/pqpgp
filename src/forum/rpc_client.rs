//! Forum-specific JSON-RPC 2.0 types and client helpers.
//!
//! This module provides forum-specific RPC method parameters, results,
//! and a specialized client helper for forum operations. It builds on
//! the generic RPC types from [`crate::rpc`].
//!
//! ## Usage
//!
//! ```ignore
//! use pqpgp::forum::rpc_client::ForumRpcClient;
//!
//! let client = ForumRpcClient::new("http://relay.example.com/rpc");
//!
//! // List forums
//! let request = client.build_list_request();
//! // Send `request` and parse response with `client.parse_list_response()`
//!
//! // Sync forum
//! let request = client.build_sync_request(&forum_hash, &known_heads, None);
//! // Send `request` and parse response with `client.parse_sync_response()`
//! ```

use crate::error::{PqpgpError, Result};
use crate::forum::{ContentHash, DagNode};
use base64::Engine;
use serde::{Deserialize, Serialize};

// Re-export core RPC types for backwards compatibility
pub use crate::rpc::{
    RpcClient, RpcError, RpcRequest, RpcResponse, RpcServerRequest, RpcServerResponse,
};

// =============================================================================
// Forum RPC Method Parameters
// =============================================================================

/// Parameters for `forum.sync` method.
///
/// Uses cursor-based pagination for efficient incremental sync.
/// The cursor is `(timestamp, hash)` which provides O(log n) seek
/// and handles ties when multiple nodes have the same timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncParams {
    /// Forum hash (hex string).
    pub forum_hash: String,
    /// Cursor timestamp: fetch nodes with timestamp >= this value.
    /// Use 0 for initial sync to get all nodes.
    pub cursor_timestamp: u64,
    /// Cursor hash (hex string): if provided, skip nodes at `cursor_timestamp`
    /// until after this hash. Handles ties when multiple nodes share a timestamp.
    pub cursor_hash: Option<String>,
    /// Maximum number of nodes to return in this batch.
    pub batch_size: Option<usize>,
}

/// Parameters for `forum.fetch` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchParams {
    /// Hashes to fetch (hex strings).
    pub hashes: Vec<String>,
}

/// Parameters for `forum.submit` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitParams {
    /// Forum hash (hex string).
    pub forum_hash: String,
    /// Base64-encoded node data.
    pub node_data: String,
}

/// Parameters for `forum.export` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportParams {
    /// Forum hash (hex string).
    pub forum_hash: String,
    /// Page number (0-indexed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<usize>,
    /// Page size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<usize>,
}

// =============================================================================
// Forum RPC Method Results
// =============================================================================

/// Result from `forum.list` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForumInfo {
    /// Forum hash (hex string).
    pub hash: String,
    /// Forum name.
    pub name: String,
    /// Forum description.
    pub description: String,
    /// Number of nodes in the forum.
    pub node_count: usize,
    /// Creation timestamp.
    pub created_at: u64,
}

/// Result from `forum.sync` method.
///
/// Contains a batch of nodes and cursor for the next request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    /// Forum hash (hex string).
    pub forum_hash: String,
    /// Nodes in this batch, ordered by (timestamp, hash).
    pub nodes: Vec<NodeData>,
    /// Cursor timestamp for the next request.
    /// This is the timestamp of the last node in the batch.
    pub next_cursor_timestamp: u64,
    /// Cursor hash (hex string) for the next request.
    /// This is the hash of the last node in the batch.
    pub next_cursor_hash: Option<String>,
    /// Whether there are more nodes available after this batch.
    pub has_more: bool,
    /// Total number of nodes in the forum (optional, for progress display).
    pub total_nodes: Option<usize>,
}

impl SyncResult {
    /// Deserializes all nodes in the result.
    pub fn deserialize_nodes(&self) -> Result<Vec<(ContentHash, DagNode)>> {
        let mut results = Vec::with_capacity(self.nodes.len());
        for node_data in &self.nodes {
            let hash = ContentHash::from_hex(&node_data.hash)
                .map_err(|e| PqpgpError::Serialization(format!("Invalid hash: {}", e)))?;
            let data = base64::engine::general_purpose::STANDARD
                .decode(&node_data.data)
                .map_err(|e| PqpgpError::Serialization(format!("Invalid base64: {}", e)))?;
            let node = DagNode::from_bytes(&data)?;
            results.push((hash, node));
        }
        Ok(results)
    }

    /// Parses the next cursor hash.
    pub fn parse_next_cursor_hash(&self) -> Option<ContentHash> {
        self.next_cursor_hash
            .as_ref()
            .and_then(|h| ContentHash::from_hex(h).ok())
    }
}

/// Result from `forum.fetch` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchResult {
    /// Fetched nodes.
    pub nodes: Vec<NodeData>,
    /// Hashes that were not found (hex strings).
    pub not_found: Vec<String>,
}

impl FetchResult {
    /// Deserializes all nodes.
    pub fn deserialize_nodes(&self) -> Result<Vec<(ContentHash, DagNode)>> {
        let mut results = Vec::with_capacity(self.nodes.len());
        for node_data in &self.nodes {
            let hash = ContentHash::from_hex(&node_data.hash)
                .map_err(|e| PqpgpError::Serialization(format!("Invalid hash: {}", e)))?;
            let data = base64::engine::general_purpose::STANDARD
                .decode(&node_data.data)
                .map_err(|e| PqpgpError::Serialization(format!("Invalid base64: {}", e)))?;
            let node = DagNode::from_bytes(&data)?;
            results.push((hash, node));
        }
        Ok(results)
    }
}

/// A node with its hash and base64-encoded data.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeData {
    /// Node hash (hex string).
    pub hash: String,
    /// Base64-encoded node data.
    pub data: String,
}

/// Result from `forum.submit` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitResult {
    /// Whether the node was accepted.
    pub accepted: bool,
    /// Node hash (hex string).
    pub hash: String,
}

impl SubmitResult {
    /// Parses the node hash.
    pub fn parse_hash(&self) -> Result<ContentHash> {
        ContentHash::from_hex(&self.hash)
            .map_err(|e| PqpgpError::Serialization(format!("Invalid hash: {}", e)))
    }
}

/// Result from `forum.export` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    /// Forum hash (hex string).
    pub forum_hash: String,
    /// Nodes in this page.
    pub nodes: Vec<NodeData>,
    /// Total number of nodes.
    pub total_nodes: usize,
    /// Whether there are more pages.
    pub has_more: bool,
}

/// Result from `forum.stats` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResult {
    /// Total number of forums.
    pub total_forums: usize,
    /// Total number of nodes.
    pub total_nodes: usize,
}

// =============================================================================
// Forum RPC Client Helper
// =============================================================================

/// Helper for building JSON-RPC 2.0 requests for forum operations.
///
/// This struct wraps the generic [`RpcClient`] and provides convenient
/// methods to build properly formatted requests for forum-specific RPC
/// methods. The actual HTTP transport is left to the application.
#[derive(Debug)]
pub struct ForumRpcClient {
    /// The underlying generic RPC client.
    inner: RpcClient,
}

impl ForumRpcClient {
    /// Creates a new forum RPC client helper.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            inner: RpcClient::new(endpoint),
        }
    }

    /// Returns a reference to the endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.inner.endpoint
    }

    /// Builds a `forum.list` request.
    pub fn build_list_request(&self) -> RpcRequest {
        self.inner
            .build_request("forum.list", serde_json::json!({}))
    }

    /// Builds a `forum.sync` request with cursor-based pagination.
    ///
    /// # Arguments
    /// * `forum_hash` - The forum to sync
    /// * `cursor_timestamp` - Fetch nodes with timestamp >= this value (0 for initial sync)
    /// * `cursor_hash` - Skip nodes at cursor_timestamp until after this hash (handles ties)
    /// * `batch_size` - Maximum nodes to return in this batch
    pub fn build_sync_request(
        &self,
        forum_hash: &ContentHash,
        cursor_timestamp: u64,
        cursor_hash: Option<&ContentHash>,
        batch_size: Option<usize>,
    ) -> RpcRequest {
        let params = SyncParams {
            forum_hash: forum_hash.to_hex(),
            cursor_timestamp,
            cursor_hash: cursor_hash.map(|h| h.to_hex()),
            batch_size,
        };
        self.inner.build_request("forum.sync", params)
    }

    /// Builds a `forum.fetch` request.
    pub fn build_fetch_request(&self, hashes: &[ContentHash]) -> RpcRequest {
        let params = FetchParams {
            hashes: hashes.iter().map(|h| h.to_hex()).collect(),
        };
        self.inner.build_request("forum.fetch", params)
    }

    /// Builds a `forum.submit` request.
    pub fn build_submit_request(
        &self,
        forum_hash: &ContentHash,
        node: &DagNode,
    ) -> Result<RpcRequest> {
        let node_data = node.to_bytes()?;
        let params = SubmitParams {
            forum_hash: forum_hash.to_hex(),
            node_data: base64::engine::general_purpose::STANDARD.encode(&node_data),
        };
        Ok(self.inner.build_request("forum.submit", params))
    }

    /// Builds a `forum.export` request.
    pub fn build_export_request(
        &self,
        forum_hash: &ContentHash,
        page: Option<usize>,
        page_size: Option<usize>,
    ) -> RpcRequest {
        let params = ExportParams {
            forum_hash: forum_hash.to_hex(),
            page,
            page_size,
        };
        self.inner.build_request("forum.export", params)
    }

    /// Builds a `forum.stats` request.
    pub fn build_stats_request(&self) -> RpcRequest {
        self.inner
            .build_request("forum.stats", serde_json::json!({}))
    }

    /// Parses a `forum.list` response.
    pub fn parse_list_response(&self, response: RpcResponse) -> Result<Vec<ForumInfo>> {
        response.into_typed_result()
    }

    /// Parses a `forum.sync` response.
    pub fn parse_sync_response(&self, response: RpcResponse) -> Result<SyncResult> {
        response.into_typed_result()
    }

    /// Parses a `forum.fetch` response.
    pub fn parse_fetch_response(&self, response: RpcResponse) -> Result<FetchResult> {
        response.into_typed_result()
    }

    /// Parses a `forum.submit` response.
    pub fn parse_submit_response(&self, response: RpcResponse) -> Result<SubmitResult> {
        response.into_typed_result()
    }

    /// Parses a `forum.export` response.
    pub fn parse_export_response(&self, response: RpcResponse) -> Result<ExportResult> {
        response.into_typed_result()
    }

    /// Parses a `forum.stats` response.
    pub fn parse_stats_response(&self, response: RpcResponse) -> Result<StatsResult> {
        response.into_typed_result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forum_rpc_client_list_request() {
        let client = ForumRpcClient::new("http://localhost:3001/rpc");
        let request = client.build_list_request();

        assert_eq!(request.method, "forum.list");
        assert_eq!(request.id, 1);
    }

    #[test]
    fn test_forum_rpc_client_sync_request() {
        let client = ForumRpcClient::new("http://localhost:3001/rpc");
        let forum_hash = ContentHash::from_bytes([1u8; 64]);
        let cursor_hash = ContentHash::from_bytes([2u8; 64]);

        let request = client.build_sync_request(&forum_hash, 12345, Some(&cursor_hash), Some(100));

        assert_eq!(request.method, "forum.sync");
        let params: SyncParams = serde_json::from_value(request.params).unwrap();
        assert_eq!(params.forum_hash, forum_hash.to_hex());
        assert_eq!(params.cursor_timestamp, 12345);
        assert_eq!(params.cursor_hash, Some(cursor_hash.to_hex()));
        assert_eq!(params.batch_size, Some(100));
    }

    #[test]
    fn test_forum_rpc_client_fetch_request() {
        let client = ForumRpcClient::new("http://localhost:3001/rpc");
        let hashes = vec![
            ContentHash::from_bytes([1u8; 64]),
            ContentHash::from_bytes([2u8; 64]),
        ];

        let request = client.build_fetch_request(&hashes);

        assert_eq!(request.method, "forum.fetch");
        let params: FetchParams = serde_json::from_value(request.params).unwrap();
        assert_eq!(params.hashes.len(), 2);
    }

    #[test]
    fn test_forum_rpc_client_increments_id() {
        let client = ForumRpcClient::new("http://localhost:3001/rpc");

        let r1 = client.build_list_request();
        let r2 = client.build_list_request();
        let r3 = client.build_stats_request();

        assert_eq!(r1.id, 1);
        assert_eq!(r2.id, 2);
        assert_eq!(r3.id, 3);
    }

    #[test]
    fn test_rpc_response_success() {
        let response = RpcResponse::success(
            1,
            serde_json::json!({"total_forums": 5, "total_nodes": 100}),
        );

        let stats: StatsResult = response.into_typed_result().unwrap();
        assert_eq!(stats.total_forums, 5);
        assert_eq!(stats.total_nodes, 100);
    }

    #[test]
    fn test_rpc_response_error() {
        let response = RpcResponse::error(1, RpcError::not_found("Forum not found"));

        let result: Result<StatsResult> = response.into_typed_result();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("-32001"));
        assert!(err.contains("Forum not found"));
    }

    #[test]
    fn test_sync_result_parsing() {
        let result = SyncResult {
            forum_hash: "ab".repeat(64),
            nodes: vec![NodeData {
                hash: "cd".repeat(64),
                data: base64::engine::general_purpose::STANDARD.encode(&[1, 2, 3]),
            }],
            next_cursor_timestamp: 12345,
            next_cursor_hash: Some("ef".repeat(64)),
            has_more: true,
            total_nodes: Some(100),
        };

        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.next_cursor_timestamp, 12345);
        assert!(result.parse_next_cursor_hash().is_some());
        assert!(result.has_more);
        assert_eq!(result.total_nodes, Some(100));
    }

    #[test]
    fn test_export_params() {
        let client = ForumRpcClient::new("http://localhost:3001/rpc");
        let forum_hash = ContentHash::from_bytes([1u8; 64]);

        let request = client.build_export_request(&forum_hash, Some(2), Some(100));

        assert_eq!(request.method, "forum.export");
        let params: ExportParams = serde_json::from_value(request.params).unwrap();
        assert_eq!(params.page, Some(2));
        assert_eq!(params.page_size, Some(100));
    }
}
