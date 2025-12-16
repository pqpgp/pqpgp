//! Client for communicating with the PQPGP relay server.
//!
//! This module provides an async HTTP client for interacting with the
//! dedicated relay server for message delivery and user discovery.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, instrument};

/// Default relay server URL
pub const DEFAULT_RELAY_URL: &str = "http://127.0.0.1:3001";

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

/// Request to register a user
#[derive(Debug, Serialize)]
struct RegisterRequest {
    name: String,
    fingerprint: String,
    prekey_bundle: String,
}

/// Request to send a message
#[derive(Debug, Serialize)]
struct SendMessageRequest {
    sender_fingerprint: String,
    encrypted_data: String,
}

/// Response from fetching messages
#[derive(Debug, Deserialize)]
struct FetchMessagesResponse {
    messages: Vec<RelayedMessage>,
}

/// Generic API response
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ApiResponse {
    success: bool,
    message: Option<String>,
    error: Option<String>,
}

/// Error type for relay client operations
#[derive(Debug, thiserror::Error)]
pub enum RelayClientError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Relay returned error: {0}")]
    RelayError(String),

    #[error("Invalid response from relay")]
    InvalidResponse,
}

/// Client for communicating with the relay server
#[derive(Clone)]
pub struct RelayClient {
    /// HTTP client
    client: Client,
    /// Base URL of the relay server
    base_url: String,
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
        }
    }

    /// Registers a user with the relay server
    #[instrument(skip(self, prekey_bundle))]
    pub async fn register_user(
        &self,
        name: String,
        fingerprint: String,
        prekey_bundle: String,
    ) -> Result<(), RelayClientError> {
        let url = format!("{}/register", self.base_url);

        let request = RegisterRequest {
            name: name.clone(),
            fingerprint: fingerprint.clone(),
            prekey_bundle,
        };

        let response = self.client.post(&url).json(&request).send().await?;

        if response.status().is_success() {
            info!(
                "Registered user on relay: {} ({})",
                name,
                &fingerprint[..16.min(fingerprint.len())]
            );
            Ok(())
        } else {
            let api_response: ApiResponse = response.json().await?;
            Err(RelayClientError::RelayError(
                api_response
                    .error
                    .unwrap_or_else(|| "Unknown error".to_string()),
            ))
        }
    }

    /// Unregisters a user from the relay
    #[allow(dead_code)]
    #[instrument(skip(self))]
    pub async fn unregister_user(&self, fingerprint: &str) -> Result<(), RelayClientError> {
        let url = format!("{}/register/{}", self.base_url, fingerprint);

        let response = self.client.delete(&url).send().await?;

        if response.status().is_success() {
            info!(
                "Unregistered user from relay: {}",
                &fingerprint[..16.min(fingerprint.len())]
            );
            Ok(())
        } else {
            let api_response: ApiResponse = response.json().await?;
            Err(RelayClientError::RelayError(
                api_response
                    .error
                    .unwrap_or_else(|| "Unknown error".to_string()),
            ))
        }
    }

    /// Lists all registered users on the relay
    #[instrument(skip(self))]
    pub async fn list_users(&self) -> Result<Vec<RegisteredUser>, RelayClientError> {
        let url = format!("{}/users", self.base_url);

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let users: Vec<RegisteredUser> = response.json().await?;
            info!("Fetched {} users from relay", users.len());
            Ok(users)
        } else {
            Err(RelayClientError::InvalidResponse)
        }
    }

    /// Gets a specific user's information
    #[allow(dead_code)]
    #[instrument(skip(self))]
    pub async fn get_user(
        &self,
        fingerprint: &str,
    ) -> Result<Option<RegisteredUser>, RelayClientError> {
        let url = format!("{}/users/{}", self.base_url, fingerprint);

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let user: Option<RegisteredUser> = response.json().await?;
            Ok(user)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(None)
        } else {
            Err(RelayClientError::InvalidResponse)
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
        let url = format!("{}/messages/{}", self.base_url, recipient_fingerprint);

        let request = SendMessageRequest {
            sender_fingerprint: sender_fingerprint.clone(),
            encrypted_data,
        };

        let response = self.client.post(&url).json(&request).send().await?;

        if response.status().is_success() {
            info!(
                "Sent message via relay: {} -> {}",
                &sender_fingerprint[..16.min(sender_fingerprint.len())],
                &recipient_fingerprint[..16.min(recipient_fingerprint.len())]
            );
            Ok(())
        } else {
            let api_response: ApiResponse = response.json().await?;
            Err(RelayClientError::RelayError(
                api_response
                    .error
                    .unwrap_or_else(|| "Unknown error".to_string()),
            ))
        }
    }

    /// Fetches all pending messages for a recipient
    #[instrument(skip(self))]
    pub async fn fetch_messages(
        &self,
        fingerprint: &str,
    ) -> Result<Vec<RelayedMessage>, RelayClientError> {
        let url = format!("{}/messages/{}", self.base_url, fingerprint);

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let fetch_response: FetchMessagesResponse = response.json().await?;
            let count = fetch_response.messages.len();
            if count > 0 {
                info!(
                    "Fetched {} messages for {}",
                    count,
                    &fingerprint[..16.min(fingerprint.len())]
                );
            }
            Ok(fetch_response.messages)
        } else {
            Err(RelayClientError::InvalidResponse)
        }
    }

    /// Checks how many messages are pending without fetching them
    #[allow(dead_code)]
    #[instrument(skip(self))]
    pub async fn check_message_count(&self, fingerprint: &str) -> Result<usize, RelayClientError> {
        let url = format!("{}/messages/{}/check", self.base_url, fingerprint);

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            #[derive(Deserialize)]
            struct CountResponse {
                pending_count: usize,
            }
            let count_response: CountResponse = response.json().await?;
            Ok(count_response.pending_count)
        } else {
            Err(RelayClientError::InvalidResponse)
        }
    }

    /// Checks if the relay server is healthy
    #[allow(dead_code)]
    #[instrument(skip(self))]
    pub async fn health_check(&self) -> Result<bool, RelayClientError> {
        let url = format!("{}/health", self.base_url);

        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status().is_success()),
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
