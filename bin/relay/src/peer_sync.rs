//! Relay-to-relay synchronization module.
//!
//! Enables relays to pull forum data from peer relays, supporting decentralization
//! and redundancy. Relays can sync specific forums from configured upstream peers.
//!
//! Uses JSON-RPC 2.0 for communication with peer relays.
//!
//! ## Configuration
//!
//! - `--peers <url1,url2,...>` - Comma-separated list of peer relay URLs
//! - `--sync-forums <hash1,hash2,...>` - Specific forum hashes to sync (optional, syncs all if omitted)
//! - `--sync-interval <seconds>` - Interval between sync attempts (default: 60)
//!
//! ## Security Model
//!
//! All synced nodes are validated locally before storage:
//! - Cryptographic signatures are verified
//! - Content hashes are verified
//! - Permission checks are applied
//! - Invalid nodes are rejected
//!
//! The relay doesn't trust peer data - it verifies everything.

use crate::rpc::SharedForumState;
use base64::Engine;
use pqpgp::forum::rpc_client::{
    FetchParams, FetchResult, ForumInfo, RpcRequest, RpcResponse, SyncParams, SyncResult,
};
use pqpgp::forum::{ContentHash, DagNode};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Configuration for peer relay synchronization.
#[derive(Clone, Debug)]
pub struct PeerSyncConfig {
    /// URLs of peer relays to sync from.
    pub peer_urls: Vec<String>,
    /// Specific forum hashes to sync. If empty, syncs all forums from peers.
    pub forum_filter: HashSet<ContentHash>,
    /// Interval between sync cycles in seconds.
    pub sync_interval_secs: u64,
    /// Maximum nodes to fetch per batch.
    pub batch_size: usize,
}

impl Default for PeerSyncConfig {
    fn default() -> Self {
        Self {
            peer_urls: Vec::new(),
            forum_filter: HashSet::new(),
            sync_interval_secs: 60,
            batch_size: 500,
        }
    }
}

impl PeerSyncConfig {
    /// Creates a new config from command line arguments.
    pub fn from_args() -> Self {
        let mut config = Self::default();

        // Parse --peers
        if let Some(peers_arg) = std::env::args()
            .position(|arg| arg == "--peers")
            .and_then(|pos| std::env::args().nth(pos + 1))
        {
            config.peer_urls = peers_arg
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Parse --sync-forums
        if let Some(forums_arg) = std::env::args()
            .position(|arg| arg == "--sync-forums")
            .and_then(|pos| std::env::args().nth(pos + 1))
        {
            config.forum_filter = forums_arg
                .split(',')
                .filter_map(|s| ContentHash::from_hex(s.trim()).ok())
                .collect();
        }

        // Parse --sync-interval
        if let Some(interval_arg) = std::env::args()
            .position(|arg| arg == "--sync-interval")
            .and_then(|pos| std::env::args().nth(pos + 1))
        {
            if let Ok(secs) = interval_arg.parse() {
                config.sync_interval_secs = secs;
            }
        }

        config
    }

    /// Returns true if peer sync is enabled (has at least one peer).
    pub fn is_enabled(&self) -> bool {
        !self.peer_urls.is_empty()
    }
}

// =============================================================================
// Peer Sync Client
// =============================================================================

/// HTTP client for communicating with peer relays via JSON-RPC 2.0.
pub struct PeerSyncClient {
    client: Client,
    config: PeerSyncConfig,
}

impl PeerSyncClient {
    /// Creates a new peer sync client.
    pub fn new(config: PeerSyncConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    /// Sends an RPC request and extracts the result.
    async fn rpc_call<T: for<'de> Deserialize<'de>>(
        &self,
        peer_url: &str,
        method: &'static str,
        params: impl Serialize,
    ) -> Result<T, String> {
        let url = format!("{}/rpc", peer_url.trim_end_matches('/'));
        let request = RpcRequest::new(method, params);

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("RPC call {} to {} failed: {}", method, peer_url, e))?;

        if !response.status().is_success() {
            return Err(format!(
                "Peer {} returned HTTP status {} for {}",
                peer_url,
                response.status(),
                method
            ));
        }

        let rpc_resp: RpcResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse RPC response from {}: {}", peer_url, e))?;

        if let Some(err) = rpc_resp.error {
            return Err(format!("RPC error from {}: {}", peer_url, err.message));
        }

        let result = rpc_resp
            .result
            .ok_or_else(|| format!("Empty RPC result from {} for {}", peer_url, method))?;

        serde_json::from_value(result)
            .map_err(|e| format!("Failed to parse {} result from {}: {}", method, peer_url, e))
    }

    /// Fetches the list of forums from a peer relay.
    async fn fetch_forum_list(&self, peer_url: &str) -> Result<Vec<ForumInfo>, String> {
        self.rpc_call(peer_url, "forum.list", serde_json::json!({}))
            .await
    }

    /// Sends a sync request to a peer relay.
    async fn sync_request(
        &self,
        peer_url: &str,
        forum_hash: ContentHash,
        known_heads: Vec<ContentHash>,
    ) -> Result<SyncResult, String> {
        let params = SyncParams {
            forum_hash: forum_hash.to_hex(),
            known_heads: known_heads.iter().map(|h| h.to_hex()).collect(),
            max_results: None,
        };
        self.rpc_call(peer_url, "forum.sync", params).await
    }

    /// Fetches nodes by hash from a peer relay.
    async fn fetch_nodes(
        &self,
        peer_url: &str,
        hashes: &[ContentHash],
    ) -> Result<FetchResult, String> {
        let params = FetchParams {
            hashes: hashes.iter().map(|h| h.to_hex()).collect(),
        };
        self.rpc_call(peer_url, "forum.fetch", params).await
    }

    /// Syncs a single forum from a peer relay.
    async fn sync_forum_from_peer(
        &self,
        peer_url: &str,
        forum_hash: ContentHash,
        state: &SharedForumState,
    ) -> Result<SyncStats, String> {
        let mut stats = SyncStats::default();

        // Get our current heads for this forum
        let known_heads: Vec<ContentHash> = {
            let relay = state.read().unwrap();
            relay
                .get_forum(&forum_hash)
                .map(|f| f.heads.iter().copied().collect())
                .unwrap_or_default()
        };

        debug!(
            "Syncing forum {} from {}, we have {} heads",
            forum_hash.short(),
            peer_url,
            known_heads.len()
        );

        // Send sync request via RPC
        let sync_resp = self.sync_request(peer_url, forum_hash, known_heads).await?;

        if sync_resp.missing_hashes.is_empty() {
            debug!(
                "Forum {} is up to date with {}",
                forum_hash.short(),
                peer_url
            );
            return Ok(stats);
        }

        // Parse missing hashes
        let missing_hashes: Vec<ContentHash> = sync_resp
            .missing_hashes
            .iter()
            .filter_map(|h| ContentHash::from_hex(h).ok())
            .collect();

        info!(
            "Forum {} has {} missing nodes from {}",
            forum_hash.short(),
            missing_hashes.len(),
            peer_url
        );

        // Fetch missing nodes in batches
        for chunk in missing_hashes.chunks(self.config.batch_size) {
            let fetch_resp = self.fetch_nodes(peer_url, chunk).await?;

            // Process fetched nodes
            for node_data in &fetch_resp.nodes {
                let hash = match ContentHash::from_hex(&node_data.hash) {
                    Ok(h) => h,
                    Err(_) => {
                        warn!(
                            "Invalid hash in response from {}: {}",
                            peer_url, node_data.hash
                        );
                        stats.rejected += 1;
                        continue;
                    }
                };

                // Decode base64 data
                let data = match base64::engine::general_purpose::STANDARD.decode(&node_data.data) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!(
                            "Failed to decode base64 for node {} from {}: {}",
                            hash.short(),
                            peer_url,
                            e
                        );
                        stats.rejected += 1;
                        continue;
                    }
                };

                match DagNode::from_bytes(&data) {
                    Ok(node) => {
                        // Verify the hash matches
                        if *node.hash() != hash {
                            warn!(
                                "Hash mismatch for node from {}: expected {}, got {}",
                                peer_url,
                                hash.short(),
                                node.hash().short()
                            );
                            stats.rejected += 1;
                            continue;
                        }

                        // Try to add the node (validation happens inside)
                        let mut relay = state.write().unwrap();
                        match relay.add_node(&forum_hash, node) {
                            Ok(true) => {
                                stats.added += 1;
                            }
                            Ok(false) => {
                                stats.duplicates += 1;
                            }
                            Err(e) => {
                                debug!("Failed to add node {}: {}", hash.short(), e);
                                stats.rejected += 1;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to deserialize node {} from {}: {}",
                            hash.short(),
                            peer_url,
                            e
                        );
                        stats.rejected += 1;
                    }
                }
            }

            stats.not_found += fetch_resp.not_found.len();
        }

        Ok(stats)
    }

    /// Runs a full sync cycle against all configured peers.
    pub async fn sync_cycle(&self, state: &SharedForumState) -> SyncStats {
        let mut total_stats = SyncStats::default();

        for peer_url in &self.config.peer_urls {
            info!("Starting sync from peer: {}", peer_url);

            // Get forums to sync
            let forums_to_sync: Vec<ContentHash> = if self.config.forum_filter.is_empty() {
                // Sync all forums from peer via RPC
                match self.fetch_forum_list(peer_url).await {
                    Ok(forums) => forums
                        .into_iter()
                        .filter_map(|f| ContentHash::from_hex(&f.hash).ok())
                        .collect(),
                    Err(e) => {
                        error!("Failed to fetch forum list from {}: {}", peer_url, e);
                        continue;
                    }
                }
            } else {
                // Sync only configured forums
                self.config.forum_filter.iter().copied().collect()
            };

            info!("Syncing {} forums from {}", forums_to_sync.len(), peer_url);

            for forum_hash in forums_to_sync {
                // Ensure forum exists locally (create if new)
                let forum_exists = {
                    let relay = state.read().unwrap();
                    relay.get_forum(&forum_hash).is_some()
                };

                if !forum_exists {
                    // Try to fetch and create the forum genesis
                    if let Err(e) = self
                        .bootstrap_forum_from_peer(peer_url, forum_hash, state)
                        .await
                    {
                        warn!(
                            "Failed to bootstrap forum {} from {}: {}",
                            forum_hash.short(),
                            peer_url,
                            e
                        );
                        continue;
                    }
                }

                // Sync the forum
                match self.sync_forum_from_peer(peer_url, forum_hash, state).await {
                    Ok(stats) => {
                        if stats.added > 0 {
                            info!(
                                "Synced forum {} from {}: {} added, {} rejected, {} duplicates",
                                forum_hash.short(),
                                peer_url,
                                stats.added,
                                stats.rejected,
                                stats.duplicates
                            );
                        }
                        total_stats.merge(&stats);
                    }
                    Err(e) => {
                        error!(
                            "Failed to sync forum {} from {}: {}",
                            forum_hash.short(),
                            peer_url,
                            e
                        );
                    }
                }
            }
        }

        total_stats
    }

    /// Bootstraps a new forum by fetching its genesis node from a peer.
    async fn bootstrap_forum_from_peer(
        &self,
        peer_url: &str,
        forum_hash: ContentHash,
        state: &SharedForumState,
    ) -> Result<(), String> {
        info!(
            "Bootstrapping forum {} from {}",
            forum_hash.short(),
            peer_url
        );

        // Fetch the genesis node via RPC
        let fetch_resp = self.fetch_nodes(peer_url, &[forum_hash]).await?;

        let node_data = fetch_resp
            .nodes
            .iter()
            .find(|n| ContentHash::from_hex(&n.hash).ok() == Some(forum_hash))
            .ok_or_else(|| format!("Forum genesis {} not found on peer", forum_hash.short()))?;

        // Decode base64 data
        let genesis_bytes = base64::engine::general_purpose::STANDARD
            .decode(&node_data.data)
            .map_err(|e| format!("Invalid base64 for genesis: {}", e))?;

        let node = DagNode::from_bytes(&genesis_bytes)
            .map_err(|e| format!("Invalid genesis node: {}", e))?;

        let genesis = match node {
            DagNode::ForumGenesis(g) => g,
            _ => return Err("Expected ForumGenesis node".to_string()),
        };

        // Create the forum locally
        let mut relay = state.write().unwrap();
        relay
            .create_forum(genesis)
            .map_err(|e| format!("Failed to create forum: {}", e))?;

        info!(
            "Bootstrapped forum {} from {}",
            forum_hash.short(),
            peer_url
        );
        Ok(())
    }
}

/// Statistics from a sync operation.
#[derive(Default, Debug)]
pub struct SyncStats {
    /// Number of nodes successfully added.
    pub added: usize,
    /// Number of nodes rejected (validation failed).
    pub rejected: usize,
    /// Number of duplicate nodes (already existed).
    pub duplicates: usize,
    /// Number of nodes not found on peer.
    pub not_found: usize,
}

impl SyncStats {
    fn merge(&mut self, other: &SyncStats) {
        self.added += other.added;
        self.rejected += other.rejected;
        self.duplicates += other.duplicates;
        self.not_found += other.not_found;
    }
}

/// Spawns the background peer sync task.
pub fn spawn_peer_sync_task(config: PeerSyncConfig, state: SharedForumState) {
    if !config.is_enabled() {
        info!("Peer sync disabled (no peers configured)");
        return;
    }

    info!(
        "Starting peer sync with {} peers, interval: {}s",
        config.peer_urls.len(),
        config.sync_interval_secs
    );

    for (i, peer) in config.peer_urls.iter().enumerate() {
        info!("  Peer {}: {}", i + 1, peer);
    }

    if !config.forum_filter.is_empty() {
        info!("  Forum filter: {} forums", config.forum_filter.len());
        for hash in &config.forum_filter {
            info!("    - {}", hash.short());
        }
    } else {
        info!("  Forum filter: all forums");
    }

    let interval_secs = config.sync_interval_secs;
    let client = PeerSyncClient::new(config);

    tokio::spawn(async move {
        // Initial sync on startup
        info!("Running initial peer sync...");
        let stats = client.sync_cycle(&state).await;
        info!(
            "Initial sync complete: {} added, {} rejected, {} duplicates",
            stats.added, stats.rejected, stats.duplicates
        );

        // Periodic sync
        let interval = Duration::from_secs(interval_secs);
        let mut interval_timer = tokio::time::interval(interval);
        interval_timer.tick().await; // Skip first immediate tick

        loop {
            interval_timer.tick().await;
            debug!("Running periodic peer sync...");
            let stats = client.sync_cycle(&state).await;
            if stats.added > 0 || stats.rejected > 0 {
                info!(
                    "Peer sync: {} added, {} rejected, {} duplicates",
                    stats.added, stats.rejected, stats.duplicates
                );
            }
        }
    });
}
