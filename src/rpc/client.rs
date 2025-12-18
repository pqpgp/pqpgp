//! Generic JSON-RPC 2.0 client helper.
//!
//! This module provides a generic RPC client that handles request ID generation
//! and response parsing. The actual HTTP transport is left to the application.
//!
//! # Example
//!
//! ```
//! use pqpgp::rpc::{RpcClient, RpcRequest};
//! use serde_json::json;
//!
//! let client = RpcClient::new("http://localhost:8080/rpc");
//!
//! // Build a request with auto-incrementing ID
//! let request = client.build_request("some.method", json!({"key": "value"}));
//! assert_eq!(request.method, "some.method");
//! assert_eq!(request.id, 1);
//!
//! // Build another request - ID increments
//! let request2 = client.build_request("other.method", json!({}));
//! assert_eq!(request2.id, 2);
//! ```

use super::types::RpcRequest;
use std::sync::atomic::{AtomicU64, Ordering};

/// Generic JSON-RPC 2.0 client helper.
///
/// Provides request ID management and convenient request building.
/// The actual HTTP transport is left to the application, allowing
/// flexibility in choosing HTTP clients (reqwest, hyper, etc.).
#[derive(Debug)]
pub struct RpcClient {
    /// RPC endpoint URL.
    pub endpoint: String,
    /// Next request ID (atomically incremented).
    next_id: AtomicU64,
}

impl RpcClient {
    /// Creates a new RPC client helper with the given endpoint URL.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            next_id: AtomicU64::new(1),
        }
    }

    /// Returns the next request ID and increments the counter.
    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Returns the current ID without incrementing.
    pub fn current_id(&self) -> u64 {
        self.next_id.load(Ordering::Relaxed)
    }

    /// Resets the ID counter to 1.
    pub fn reset_id(&self) {
        self.next_id.store(1, Ordering::Relaxed);
    }

    /// Builds an RPC request with auto-incrementing ID.
    ///
    /// # Arguments
    ///
    /// * `method` - The RPC method name (must be a static string)
    /// * `params` - The method parameters (any serializable type)
    pub fn build_request(&self, method: &'static str, params: impl serde::Serialize) -> RpcRequest {
        RpcRequest::with_id(method, params, self.next_id())
    }

    /// Builds an RPC request with a specific ID (does not increment counter).
    pub fn build_request_with_id(
        &self,
        method: &'static str,
        params: impl serde::Serialize,
        id: u64,
    ) -> RpcRequest {
        RpcRequest::with_id(method, params, id)
    }
}

impl Clone for RpcClient {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            // Start new clone with fresh ID counter
            next_id: AtomicU64::new(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_client_new() {
        let client = RpcClient::new("http://localhost:8080/rpc");
        assert_eq!(client.endpoint, "http://localhost:8080/rpc");
        assert_eq!(client.current_id(), 1);
    }

    #[test]
    fn test_client_id_increment() {
        let client = RpcClient::new("http://localhost/rpc");

        assert_eq!(client.next_id(), 1);
        assert_eq!(client.next_id(), 2);
        assert_eq!(client.next_id(), 3);
        assert_eq!(client.current_id(), 4);
    }

    #[test]
    fn test_client_reset_id() {
        let client = RpcClient::new("http://localhost/rpc");

        client.next_id();
        client.next_id();
        assert_eq!(client.current_id(), 3);

        client.reset_id();
        assert_eq!(client.current_id(), 1);
    }

    #[test]
    fn test_build_request() {
        let client = RpcClient::new("http://localhost/rpc");

        let req1 = client.build_request("test.method", json!({"key": "value"}));
        assert_eq!(req1.method, "test.method");
        assert_eq!(req1.jsonrpc, "2.0");
        assert_eq!(req1.id, 1);

        let req2 = client.build_request("other.method", json!({}));
        assert_eq!(req2.id, 2);
    }

    #[test]
    fn test_build_request_with_id() {
        let client = RpcClient::new("http://localhost/rpc");

        let req = client.build_request_with_id("test.method", json!({}), 999);
        assert_eq!(req.id, 999);

        // Counter should not have been affected
        assert_eq!(client.current_id(), 1);
    }

    #[test]
    fn test_client_clone() {
        let client = RpcClient::new("http://localhost/rpc");
        client.next_id();
        client.next_id();

        let cloned = client.clone();
        assert_eq!(cloned.endpoint, client.endpoint);
        // Clone starts with fresh ID
        assert_eq!(cloned.current_id(), 1);
    }
}
