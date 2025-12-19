//! Relay management for the simulator.
//!
//! Starts relay processes and provides RPC client functionality using
//! the existing pqpgp::forum::rpc_client types.

use pqpgp::forum::rpc_client::{
    FetchResult, ForumInfo, ForumRpcClient, RpcResponse, SubmitResult, SyncResult,
};
use pqpgp::forum::{ContentHash, DagNode, ForumGenesis};
use pqpgp::rpc::RpcRequest;
use reqwest::Client;
use serde_json::Value;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tracing::info;

/// A relay instance managed by the simulator.
pub struct SimulatorRelay {
    /// The port this relay runs on.
    port: u16,
    /// HTTP client for RPC calls.
    http_client: Client,
    /// Forum RPC client helper for building requests.
    rpc_client: ForumRpcClient,
    /// The relay process handle (if we spawned it).
    #[allow(dead_code)]
    process: Option<Child>,
}

impl SimulatorRelay {
    /// Starts a new relay process on the given port.
    pub async fn start(
        port: u16,
        data_dir: &Path,
        peers: Vec<String>,
        sync_interval: u64,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let bind_addr = format!("127.0.0.1:{}", port);
        let rpc_url = format!("http://127.0.0.1:{}/rpc", port);

        // Build command arguments
        let mut args = vec!["--bind".to_string(), bind_addr.clone()];

        if !peers.is_empty() {
            args.push("--peers".to_string());
            args.push(peers.join(","));
            args.push("--sync-interval".to_string());
            args.push(sync_interval.to_string());
        }

        // Set environment for data directory
        let data_dir_str = data_dir.to_string_lossy().to_string();

        info!(
            "Starting relay on port {} with data dir: {}",
            port, data_dir_str
        );

        // Add data directory argument
        args.push("--data-dir".to_string());
        args.push(data_dir_str.clone());

        // Spawn the relay process
        let process = Command::new("cargo")
            .args(["run", "--release", "-p", "pqpgp-relay", "--"])
            .args(&args)
            .env("RUST_LOG", "pqpgp_relay=info")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        let http_client = Client::builder().timeout(Duration::from_secs(10)).build()?;

        let rpc_client = ForumRpcClient::new(&rpc_url);

        let relay = Self {
            port,
            http_client,
            rpc_client,
            process: Some(process),
        };

        // Wait for relay to be ready
        relay.wait_for_ready().await?;

        Ok(relay)
    }

    /// Waits for the relay to be ready to accept connections.
    async fn wait_for_ready(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 240 attempts * 500ms = 2 minutes max wait time
        let max_attempts = 240;
        for attempt in 1..=max_attempts {
            match self.health_check().await {
                Ok(_) => {
                    info!("Relay on port {} is ready", self.port);
                    return Ok(());
                }
                Err(_) => {
                    if attempt == max_attempts {
                        return Err(format!(
                            "Relay on port {} failed to start after {} attempts",
                            self.port, max_attempts
                        )
                        .into());
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        Ok(())
    }

    /// Sends an RPC request and returns the response.
    async fn send_request(&self, request: &RpcRequest) -> Result<RpcResponse, String> {
        let response = self
            .http_client
            .post(self.rpc_client.endpoint())
            .json(request)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        // Check for non-success status codes (like 429 rate limit)
        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("HTTP {}: {}", status.as_u16(), body));
        }

        let rpc_response: RpcResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        Ok(rpc_response)
    }

    /// Health check.
    pub async fn health_check(&self) -> Result<(), String> {
        let request = pqpgp::rpc::RpcRequest::new("relay.health", serde_json::json!({}));
        let response = self.send_request(&request).await?;

        if response.error.is_some() {
            return Err("Health check failed".to_string());
        }
        Ok(())
    }

    /// Gets the node count for all forums.
    pub async fn node_count(&self) -> usize {
        match self.list_forums().await {
            Ok(forums) => forums.iter().map(|f| f.node_count).sum(),
            Err(_) => 0,
        }
    }

    /// Lists all forums on this relay.
    pub async fn list_forums(&self) -> Result<Vec<ForumInfo>, String> {
        let request = self.rpc_client.build_list_request();
        let response = self.send_request(&request).await?;

        self.rpc_client
            .parse_list_response(response)
            .map_err(|e| format!("Failed to parse forum list: {}", e))
    }

    /// Submits a node to a forum.
    pub async fn submit_node(
        &self,
        forum_hash: &ContentHash,
        node: &DagNode,
    ) -> Result<SubmitResult, String> {
        let request = self
            .rpc_client
            .build_submit_request(forum_hash, node)
            .map_err(|e| format!("Failed to build submit request: {}", e))?;

        let response = self.send_request(&request).await?;

        self.rpc_client
            .parse_submit_response(response)
            .map_err(|e| format!("Failed to parse submit result: {}", e))
    }

    /// Creates a new forum (submits genesis node).
    pub async fn create_forum(&self, genesis: &ForumGenesis) -> Result<SubmitResult, String> {
        let node = DagNode::from(genesis.clone());
        self.submit_node(genesis.hash(), &node).await
    }

    /// Fetches nodes by their hashes.
    pub async fn fetch_nodes(&self, hashes: &[ContentHash]) -> Result<FetchResult, String> {
        let request = self.rpc_client.build_fetch_request(hashes);
        let response = self.send_request(&request).await?;

        self.rpc_client
            .parse_fetch_response(response)
            .map_err(|e| format!("Failed to parse fetch result: {}", e))
    }

    /// Gets sync information for a forum using cursor-based pagination.
    ///
    /// For initial sync, use cursor_timestamp=0 and cursor_hash=None.
    /// Returns nodes after the cursor position.
    pub async fn sync_forum(
        &self,
        forum_hash: &ContentHash,
        cursor_timestamp: u64,
        cursor_hash: Option<&ContentHash>,
    ) -> Result<SyncResult, String> {
        let request =
            self.rpc_client
                .build_sync_request(forum_hash, cursor_timestamp, cursor_hash, None);
        let response = self.send_request(&request).await?;

        self.rpc_client
            .parse_sync_response(response)
            .map_err(|e| format!("Failed to parse sync result: {}", e))
    }

    /// Submits raw data as a node (for malicious testing).
    pub async fn submit_raw(&self, forum_hash: &str, node_data: &str) -> Result<Value, String> {
        let request = pqpgp::rpc::RpcRequest::new(
            "forum.submit",
            serde_json::json!({
                "forum_hash": forum_hash,
                "node_data": node_data
            }),
        );

        let response = self.send_request(&request).await?;

        if let Some(error) = response.error {
            return Err(format!("RPC error: {}", error.message));
        }

        response.result.ok_or_else(|| "Empty result".to_string())
    }
}

impl Drop for SimulatorRelay {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            let _ = process.kill();
        }
    }
}
