//! Client for communicating with the PQPGP relay server.
//!
//! This module provides an async HTTP client for interacting with the
//! dedicated relay server via JSON-RPC 2.0.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, info, instrument};

/// Default relay server URL
pub const DEFAULT_RELAY_URL: &str = "http://127.0.0.1:3001";

// =============================================================================
// JSON-RPC 2.0 Types
// =============================================================================

/// JSON-RPC 2.0 request.
#[derive(Debug, Serialize)]
struct RpcRequest {
    jsonrpc: &'static str,
    method: String,
    params: Value,
    id: u64,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    result: Option<Value>,
    error: Option<RpcError>,
    #[allow(dead_code)]
    id: Option<Value>,
}

/// JSON-RPC 2.0 error.
#[derive(Debug, Deserialize)]
struct RpcError {
    #[allow(dead_code)]
    code: i32,
    message: String,
    #[allow(dead_code)]
    data: Option<Value>,
}

// =============================================================================
// Domain Types
// =============================================================================

/// A registered user on the relay
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisteredUser {
    /// User's display name
    pub name: String,
    /// User's identity fingerprint (hex string)
    pub fingerprint: String,
    /// Base64-encoded prekey bundle for session establishment
    pub prekey_bundle: String,
    /// Registration timestamp
    pub registered_at: u64,
    /// Last seen timestamp
    pub last_seen: u64,
}

/// A message fetched from the relay
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayedMessage {
    /// Sender's fingerprint
    pub sender_fingerprint: String,
    /// Base64-encoded encrypted message
    pub encrypted_data: String,
    /// Unix timestamp when message was received by relay
    pub timestamp: u64,
    /// Unique message ID
    pub message_id: String,
}

// =============================================================================
// Error Type
// =============================================================================

/// Error type for relay client operations
#[derive(Debug, thiserror::Error)]
pub enum RelayClientError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Relay returned error: {0}")]
    RelayError(String),

    #[error("Invalid response from relay: {0}")]
    InvalidResponse(String),
}

// =============================================================================
// Relay Client
// =============================================================================

/// Client for communicating with the relay server via JSON-RPC 2.0.
#[derive(Debug)]
pub struct RelayClient {
    /// HTTP client
    client: Client,
    /// Base URL of the relay server
    base_url: String,
    /// Request ID counter
    request_id: AtomicU64,
}

impl RelayClient {
    /// Creates a new relay client with the default URL
    pub fn new() -> Self {
        Self::with_url(DEFAULT_RELAY_URL)
    }

    /// Creates a new relay client with a custom URL
    pub fn with_url(url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: url.into().trim_end_matches('/').to_string(),
            request_id: AtomicU64::new(1),
        }
    }

    /// Returns the RPC endpoint URL.
    fn rpc_url(&self) -> String {
        format!("{}/rpc", self.base_url)
    }

    /// Generates the next request ID.
    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Sends an RPC request and returns the result.
    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, RelayClientError> {
        let request = RpcRequest {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
            id: self.next_id(),
        };

        let response = self
            .client
            .post(self.rpc_url())
            .json(&request)
            .send()
            .await?;

        let rpc_response: RpcResponse = response.json().await?;

        if let Some(error) = rpc_response.error {
            return Err(RelayClientError::RelayError(error.message));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| RelayClientError::InvalidResponse("Missing result".to_string()))?;

        serde_json::from_value(result).map_err(|e| {
            RelayClientError::InvalidResponse(format!("Failed to parse result: {}", e))
        })
    }

    /// Registers a user with the relay server
    #[instrument(skip(self, prekey_bundle))]
    pub async fn register_user(
        &self,
        name: String,
        fingerprint: String,
        prekey_bundle: String,
    ) -> Result<(), RelayClientError> {
        let params = serde_json::json!({
            "name": name,
            "fingerprint": fingerprint,
            "prekey_bundle": prekey_bundle,
        });

        let _: Value = self.call("user.register", params).await?;

        info!(
            "Registered user on relay: {} ({})",
            name,
            &fingerprint[..16.min(fingerprint.len())]
        );
        Ok(())
    }

    /// Unregisters a user from the relay
    #[allow(dead_code)]
    #[instrument(skip(self))]
    pub async fn unregister_user(&self, fingerprint: &str) -> Result<(), RelayClientError> {
        let params = serde_json::json!({
            "fingerprint": fingerprint,
        });

        let _: Value = self.call("user.unregister", params).await?;

        info!(
            "Unregistered user from relay: {}",
            &fingerprint[..16.min(fingerprint.len())]
        );
        Ok(())
    }

    /// Lists all registered users on the relay
    #[instrument(skip(self))]
    pub async fn list_users(&self) -> Result<Vec<RegisteredUser>, RelayClientError> {
        let users: Vec<RegisteredUser> = self.call("user.list", serde_json::json!({})).await?;
        info!("Fetched {} users from relay", users.len());
        Ok(users)
    }

    /// Gets a specific user's information
    #[allow(dead_code)]
    #[instrument(skip(self))]
    pub async fn get_user(
        &self,
        fingerprint: &str,
    ) -> Result<Option<RegisteredUser>, RelayClientError> {
        let params = serde_json::json!({
            "fingerprint": fingerprint,
        });

        // user.get returns null if not found, or the user object
        let result: Value = self.call("user.get", params).await?;

        if result.is_null() {
            Ok(None)
        } else {
            let user: RegisteredUser = serde_json::from_value(result)
                .map_err(|e| RelayClientError::InvalidResponse(e.to_string()))?;
            Ok(Some(user))
        }
    }

    /// Sends an encrypted message to a recipient via the relay
    #[instrument(skip(self, encrypted_data))]
    pub async fn send_message(
        &self,
        sender_fingerprint: String,
        recipient_fingerprint: String,
        encrypted_data: String,
    ) -> Result<(), RelayClientError> {
        let params = serde_json::json!({
            "recipient_fingerprint": recipient_fingerprint,
            "sender_fingerprint": sender_fingerprint,
            "encrypted_data": encrypted_data,
        });

        let _: Value = self.call("message.send", params).await?;

        info!(
            "Sent message via relay: {} -> {}",
            &sender_fingerprint[..16.min(sender_fingerprint.len())],
            &recipient_fingerprint[..16.min(recipient_fingerprint.len())]
        );
        Ok(())
    }

    /// Fetches all pending messages for a recipient
    #[instrument(skip(self))]
    pub async fn fetch_messages(
        &self,
        fingerprint: &str,
    ) -> Result<Vec<RelayedMessage>, RelayClientError> {
        let params = serde_json::json!({
            "fingerprint": fingerprint,
        });

        #[derive(Deserialize)]
        struct FetchResponse {
            messages: Vec<RelayedMessage>,
        }

        let response: FetchResponse = self.call("message.fetch", params).await?;
        let count = response.messages.len();

        if count > 0 {
            info!(
                "Fetched {} messages for {}",
                count,
                &fingerprint[..16.min(fingerprint.len())]
            );
        }
        Ok(response.messages)
    }

    /// Checks how many messages are pending without fetching them
    #[allow(dead_code)]
    #[instrument(skip(self))]
    pub async fn check_message_count(&self, fingerprint: &str) -> Result<usize, RelayClientError> {
        let params = serde_json::json!({
            "fingerprint": fingerprint,
        });

        #[derive(Deserialize)]
        struct CheckResponse {
            pending_count: usize,
        }

        let response: CheckResponse = self.call("message.check", params).await?;
        Ok(response.pending_count)
    }

    /// Checks if the relay server is healthy
    #[allow(dead_code)]
    #[instrument(skip(self))]
    pub async fn health_check(&self) -> Result<bool, RelayClientError> {
        #[derive(Deserialize)]
        struct HealthResponse {
            status: String,
        }

        match self
            .call::<HealthResponse>("relay.health", serde_json::json!({}))
            .await
        {
            Ok(response) => Ok(response.status == "ok"),
            Err(e) => {
                error!("Relay health check failed: {:?}", e);
                Ok(false)
            }
        }
    }
}

impl Default for RelayClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for RelayClient {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
            request_id: AtomicU64::new(self.request_id.load(Ordering::Relaxed)),
        }
    }
}

/// Shared relay client for use across handlers
pub type SharedRelayClient = Arc<RelayClient>;

/// Creates a new shared relay client
pub fn create_relay_client(url: Option<String>) -> SharedRelayClient {
    let client = match url {
        Some(url) => RelayClient::with_url(url),
        None => RelayClient::new(),
    };
    Arc::new(client)
}
