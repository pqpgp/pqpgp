//! JSON-RPC 2.0 client helpers for forum sync.
//!
//! This module provides types and utilities for making JSON-RPC 2.0 calls
//! to forum relay servers. It handles the RPC protocol wrapping while
//! using the existing sync types from the `sync` module.
//!
//! ## Usage
//!
//! ```ignore
//! use pqpgp::forum::rpc_client::RpcClient;
//!
//! let client = RpcClient::new("http://relay.example.com/forums/rpc");
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
use ::base64::Engine;
use ::serde_json::Value;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

// =============================================================================
// JSON-RPC 2.0 Types
// =============================================================================

/// JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize)]
pub struct RpcRequest {
    /// Protocol version (always "2.0").
    pub jsonrpc: &'static str,
    /// Method name.
    pub method: &'static str,
    /// Method parameters.
    pub params: Value,
    /// Request ID.
    pub id: u64,
}

impl RpcRequest {
    /// Creates a new RPC request.
    pub fn new(method: &'static str, params: impl Serialize) -> Self {
        Self {
            jsonrpc: "2.0",
            method,
            params: ::serde_json::to_value(params).unwrap_or(Value::Null),
            id: 1,
        }
    }

    /// Creates a new RPC request with a specific ID.
    pub fn with_id(method: &'static str, params: impl Serialize, id: u64) -> Self {
        Self {
            jsonrpc: "2.0",
            method,
            params: ::serde_json::to_value(params).unwrap_or(Value::Null),
            id,
        }
    }
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Clone, Deserialize)]
pub struct RpcResponse {
    /// Protocol version.
    pub jsonrpc: String,
    /// Result (present on success).
    pub result: Option<Value>,
    /// Error (present on failure).
    pub error: Option<RpcError>,
    /// Request ID.
    pub id: Option<Value>,
}

impl RpcResponse {
    /// Extracts the result value, returning an error if the response contains an error.
    pub fn into_result(self) -> Result<Value> {
        if let Some(err) = self.error {
            return Err(PqpgpError::Chat(format!(
                "RPC error {}: {}",
                err.code, err.message
            )));
        }

        self.result
            .ok_or_else(|| PqpgpError::Chat("Empty RPC result".to_string()))
    }

    /// Extracts and deserializes the result as a specific type.
    pub fn into_typed_result<T: DeserializeOwned>(self) -> Result<T> {
        let value = self.into_result()?;
        ::serde_json::from_value(value)
            .map_err(|e| PqpgpError::Serialization(format!("Failed to parse RPC result: {}", e)))
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
    /// Additional error data.
    pub data: Option<Value>,
}

impl RpcError {
    // Standard JSON-RPC 2.0 error codes
    /// Parse error (-32700).
    pub const PARSE_ERROR: i32 = -32700;
    /// Invalid request (-32600).
    pub const INVALID_REQUEST: i32 = -32600;
    /// Method not found (-32601).
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid params (-32602).
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal error (-32603).
    pub const INTERNAL_ERROR: i32 = -32603;

    // Application-specific error codes (-32000 to -32099)
    /// Forum not found (-32001).
    pub const FORUM_NOT_FOUND: i32 = -32001;
    /// Validation failed (-32002).
    pub const VALIDATION_FAILED: i32 = -32002;
    /// Rate limited (-32003).
    pub const RATE_LIMITED: i32 = -32003;
    /// Resource exhausted (-32004).
    pub const RESOURCE_EXHAUSTED: i32 = -32004;

    /// Creates an invalid request error.
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self {
            code: Self::INVALID_REQUEST,
            message: msg.into(),
            data: None,
        }
    }

    /// Creates a method not found error.
    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: Self::METHOD_NOT_FOUND,
            message: format!("Method '{}' not found", method),
            data: None,
        }
    }

    /// Creates an invalid params error.
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self {
            code: Self::INVALID_PARAMS,
            message: msg.into(),
            data: None,
        }
    }

    /// Creates an internal error.
    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self {
            code: Self::INTERNAL_ERROR,
            message: msg.into(),
            data: None,
        }
    }

    /// Creates a not found error.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            code: Self::FORUM_NOT_FOUND,
            message: msg.into(),
            data: None,
        }
    }

    /// Creates a validation failed error with details.
    pub fn validation_failed(errors: Vec<String>) -> Self {
        Self {
            code: Self::VALIDATION_FAILED,
            message: "Validation failed".to_string(),
            data: Some(Value::Array(
                errors.into_iter().map(Value::String).collect(),
            )),
        }
    }

    /// Creates a resource exhausted error.
    pub fn resource_exhausted(msg: impl Into<String>) -> Self {
        Self {
            code: Self::RESOURCE_EXHAUSTED,
            message: msg.into(),
            data: None,
        }
    }
}

// =============================================================================
// RPC Method Parameters
// =============================================================================

/// Parameters for `forum.sync` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncParams {
    /// Forum hash (hex string).
    pub forum_hash: String,
    /// Known heads (hex strings).
    pub known_heads: Vec<String>,
    /// Maximum results to return.
    pub max_results: Option<usize>,
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
// RPC Method Results
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    /// Forum hash (hex string).
    pub forum_hash: String,
    /// Missing node hashes (hex strings).
    pub missing_hashes: Vec<String>,
    /// Server's current heads (hex strings).
    pub server_heads: Vec<String>,
    /// Whether there are more missing nodes.
    pub has_more: bool,
}

impl SyncResult {
    /// Parses missing hashes into ContentHash values.
    pub fn parse_missing_hashes(&self) -> Vec<ContentHash> {
        self.missing_hashes
            .iter()
            .filter_map(|h| ContentHash::from_hex(h).ok())
            .collect()
    }

    /// Parses server heads into ContentHash values.
    pub fn parse_server_heads(&self) -> Vec<ContentHash> {
        self.server_heads
            .iter()
            .filter_map(|h| ContentHash::from_hex(h).ok())
            .collect()
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
            let data = ::base64::engine::general_purpose::STANDARD
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
// RPC Client Helper
// =============================================================================

/// Helper for building JSON-RPC 2.0 requests for forum operations.
///
/// This struct provides convenient methods to build properly formatted
/// RPC requests. The actual HTTP transport is left to the application.
#[derive(Debug)]
pub struct RpcClient {
    /// RPC endpoint URL.
    pub endpoint: String,
    /// Next request ID.
    next_id: std::sync::atomic::AtomicU64,
}

impl RpcClient {
    /// Creates a new RPC client helper.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Returns the next request ID.
    fn next_id(&self) -> u64 {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Builds a `forum.list` request.
    pub fn build_list_request(&self) -> RpcRequest {
        RpcRequest::with_id("forum.list", ::serde_json::json!({}), self.next_id())
    }

    /// Builds a `forum.sync` request.
    pub fn build_sync_request(
        &self,
        forum_hash: &ContentHash,
        known_heads: &[ContentHash],
        max_results: Option<usize>,
    ) -> RpcRequest {
        let params = SyncParams {
            forum_hash: forum_hash.to_hex(),
            known_heads: known_heads.iter().map(|h| h.to_hex()).collect(),
            max_results,
        };
        RpcRequest::with_id("forum.sync", params, self.next_id())
    }

    /// Builds a `forum.fetch` request.
    pub fn build_fetch_request(&self, hashes: &[ContentHash]) -> RpcRequest {
        let params = FetchParams {
            hashes: hashes.iter().map(|h| h.to_hex()).collect(),
        };
        RpcRequest::with_id("forum.fetch", params, self.next_id())
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
            node_data: ::base64::engine::general_purpose::STANDARD.encode(&node_data),
        };
        Ok(RpcRequest::with_id("forum.submit", params, self.next_id()))
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
        RpcRequest::with_id("forum.export", params, self.next_id())
    }

    /// Builds a `forum.stats` request.
    pub fn build_stats_request(&self) -> RpcRequest {
        RpcRequest::with_id("forum.stats", ::serde_json::json!({}), self.next_id())
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
    fn test_rpc_request_serialization() {
        let request = RpcRequest::new("forum.list", serde_json::json!({}));
        let json = serde_json::to_string(&request).unwrap();

        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"forum.list\""));
    }

    #[test]
    fn test_rpc_client_list_request() {
        let client = RpcClient::new("http://localhost:3001/forums/rpc");
        let request = client.build_list_request();

        assert_eq!(request.method, "forum.list");
        assert_eq!(request.id, 1);
    }

    #[test]
    fn test_rpc_client_sync_request() {
        let client = RpcClient::new("http://localhost:3001/forums/rpc");
        let forum_hash = ContentHash::from_bytes([1u8; 64]);
        let heads = vec![ContentHash::from_bytes([2u8; 64])];

        let request = client.build_sync_request(&forum_hash, &heads, Some(100));

        assert_eq!(request.method, "forum.sync");
        let params: SyncParams = serde_json::from_value(request.params).unwrap();
        assert_eq!(params.forum_hash, forum_hash.to_hex());
        assert_eq!(params.known_heads.len(), 1);
        assert_eq!(params.max_results, Some(100));
    }

    #[test]
    fn test_rpc_client_fetch_request() {
        let client = RpcClient::new("http://localhost:3001/forums/rpc");
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
    fn test_rpc_client_increments_id() {
        let client = RpcClient::new("http://localhost:3001/forums/rpc");

        let r1 = client.build_list_request();
        let r2 = client.build_list_request();
        let r3 = client.build_stats_request();

        assert_eq!(r1.id, 1);
        assert_eq!(r2.id, 2);
        assert_eq!(r3.id, 3);
    }

    #[test]
    fn test_rpc_response_success() {
        let response = RpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(serde_json::json!({"total_forums": 5, "total_nodes": 100})),
            error: None,
            id: Some(Value::Number(1.into())),
        };

        let stats: StatsResult = response.into_typed_result().unwrap();
        assert_eq!(stats.total_forums, 5);
        assert_eq!(stats.total_nodes, 100);
    }

    #[test]
    fn test_rpc_response_error() {
        let response = RpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(RpcError {
                code: RpcError::FORUM_NOT_FOUND,
                message: "Forum not found".to_string(),
                data: None,
            }),
            id: Some(Value::Number(1.into())),
        };

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
            missing_hashes: vec!["cd".repeat(64), "ef".repeat(64)],
            server_heads: vec!["12".repeat(64)],
            has_more: false,
        };

        let missing = result.parse_missing_hashes();
        assert_eq!(missing.len(), 2);

        let heads = result.parse_server_heads();
        assert_eq!(heads.len(), 1);
    }

    #[test]
    fn test_export_params() {
        let client = RpcClient::new("http://localhost:3001/forums/rpc");
        let forum_hash = ContentHash::from_bytes([1u8; 64]);

        let request = client.build_export_request(&forum_hash, Some(2), Some(100));

        assert_eq!(request.method, "forum.export");
        let params: ExportParams = serde_json::from_value(request.params).unwrap();
        assert_eq!(params.page, Some(2));
        assert_eq!(params.page_size, Some(100));
    }
}
