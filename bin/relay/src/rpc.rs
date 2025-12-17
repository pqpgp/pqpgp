//! Unified JSON-RPC 2.0 handler for the relay server.
//!
//! Provides a single `/rpc` endpoint for all relay operations:
//!
//! ## Messaging Methods
//! - `user.register` - Register user with prekey bundle
//! - `user.unregister` - Unregister a user
//! - `user.get` - Get user's prekey bundle
//! - `user.list` - List all registered users
//! - `message.send` - Send message to recipient
//! - `message.fetch` - Fetch messages for recipient
//! - `message.check` - Check pending message count
//!
//! ## Forum Methods
//! - `forum.list` - List all forums
//! - `forum.sync` - Get missing node hashes
//! - `forum.fetch` - Fetch nodes by hash
//! - `forum.submit` - Submit a new node
//! - `forum.export` - Export forum DAG (paginated)
//!
//! ## System Methods
//! - `relay.health` - Health check
//! - `relay.stats` - Server statistics

use crate::forum::persistence::PersistentForumState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::Engine;
use pqpgp::forum::constants::{
    MAX_EXPORT_PAGE_SIZE, MAX_FETCH_BATCH_SIZE, MAX_NODES_PER_FORUM, MAX_SYNC_MISSING_HASHES,
};
use pqpgp::forum::permissions::ForumPermissions;
use pqpgp::forum::rpc_client::{
    ExportParams, ExportResult, FetchParams, FetchResult, ForumInfo, NodeData, RpcError,
    SubmitParams, SubmitResult, SyncParams, SyncResult,
};
use pqpgp::forum::types::current_timestamp_millis;
use pqpgp::forum::{
    validate_content_limits, validate_node, ContentHash, DagNode, ForumGenesis, ValidationContext,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{info, instrument};

// =============================================================================
// Constants
// =============================================================================

/// Maximum messages to queue per recipient
const MAX_QUEUED_MESSAGES: usize = 1000;

/// Maximum message size in bytes (base64 encoded)
const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB

// =============================================================================
// State Types
// =============================================================================

/// A registered user on the relay
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisteredUser {
    pub name: String,
    pub fingerprint: String,
    pub prekey_bundle: String,
    pub registered_at: u64,
    pub last_seen: u64,
}

/// A message queued for delivery
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueuedMessage {
    pub sender_fingerprint: String,
    pub encrypted_data: String,
    pub timestamp: u64,
    pub message_id: String,
}

/// Messaging relay state
#[derive(Default)]
pub struct RelayState {
    pub users: HashMap<String, RegisteredUser>,
    pub messages: HashMap<String, VecDeque<QueuedMessage>>,
}

impl RelayState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Thread-safe relay state
pub type SharedRelayState = Arc<RwLock<RelayState>>;

/// Thread-safe forum state
pub type SharedForumState = Arc<RwLock<PersistentForumState>>;

/// Combined application state
#[derive(Clone)]
pub struct AppState {
    pub relay: SharedRelayState,
    pub forum: SharedForumState,
}

// =============================================================================
// JSON-RPC 2.0 Types
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    pub id: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: Option<Value>,
}

impl RpcResponse {
    fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    fn error(id: Option<Value>, error: RpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(error),
            id,
        }
    }
}

// =============================================================================
// RwLock Helpers
// =============================================================================

fn acquire_relay_read(state: &RwLock<RelayState>) -> RwLockReadGuard<'_, RelayState> {
    state.read().unwrap_or_else(|p| p.into_inner())
}

fn acquire_relay_write(state: &RwLock<RelayState>) -> RwLockWriteGuard<'_, RelayState> {
    state.write().unwrap_or_else(|p| p.into_inner())
}

fn acquire_forum_read(
    state: &RwLock<PersistentForumState>,
) -> RwLockReadGuard<'_, PersistentForumState> {
    state.read().unwrap_or_else(|p| p.into_inner())
}

fn acquire_forum_write(
    state: &RwLock<PersistentForumState>,
) -> RwLockWriteGuard<'_, PersistentForumState> {
    state.write().unwrap_or_else(|p| p.into_inner())
}

// =============================================================================
// Main RPC Handler
// =============================================================================

#[instrument(skip(state, request))]
pub async fn handle_rpc(
    State(state): State<AppState>,
    Json(request): Json<RpcRequest>,
) -> impl IntoResponse {
    if request.jsonrpc != "2.0" {
        return (
            StatusCode::OK,
            Json(RpcResponse::error(
                request.id,
                RpcError::invalid_request("Invalid JSON-RPC version"),
            )),
        );
    }

    let result = match request.method.as_str() {
        // User methods
        "user.register" => handle_user_register(&state.relay, request.params),
        "user.unregister" => handle_user_unregister(&state.relay, request.params),
        "user.get" => handle_user_get(&state.relay, request.params),
        "user.list" => handle_user_list(&state.relay),

        // Message methods
        "message.send" => handle_message_send(&state.relay, request.params),
        "message.fetch" => handle_message_fetch(&state.relay, request.params),
        "message.check" => handle_message_check(&state.relay, request.params),

        // Forum methods
        "forum.list" => handle_forum_list(&state.forum),
        "forum.sync" => handle_forum_sync(&state.forum, request.params),
        "forum.fetch" => handle_forum_fetch(&state.forum, request.params),
        "forum.submit" => handle_forum_submit(&state.forum, request.params),
        "forum.export" => handle_forum_export(&state.forum, request.params),

        // System methods
        "relay.health" => handle_health(),
        "relay.stats" => handle_stats(&state),

        _ => Err(RpcError::method_not_found(&request.method)),
    };

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(RpcResponse::success(request.id, value)),
        ),
        Err(error) => (StatusCode::OK, Json(RpcResponse::error(request.id, error))),
    }
}

// =============================================================================
// User Handlers
// =============================================================================

#[derive(Debug, Deserialize)]
struct UserRegisterParams {
    name: String,
    fingerprint: String,
    prekey_bundle: String,
}

fn handle_user_register(state: &SharedRelayState, params: Value) -> Result<Value, RpcError> {
    let params: UserRegisterParams =
        serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))?;

    // Validate fingerprint
    if params.fingerprint.len() < 16 || !params.fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(RpcError::invalid_params("Invalid fingerprint format"));
    }

    if params.prekey_bundle.is_empty() {
        return Err(RpcError::invalid_params("Prekey bundle required"));
    }

    let now = current_timestamp_millis() / 1000;

    let user = RegisteredUser {
        name: params.name.clone(),
        fingerprint: params.fingerprint.clone(),
        prekey_bundle: params.prekey_bundle,
        registered_at: now,
        last_seen: now,
    };

    let mut relay = acquire_relay_write(state);
    let is_update = relay.users.contains_key(&params.fingerprint);
    relay.users.insert(params.fingerprint.clone(), user);

    info!(
        "user.register: {} {} ({})",
        if is_update { "updated" } else { "registered" },
        params.name,
        &params.fingerprint[..16]
    );

    Ok(serde_json::json!({
        "registered": true,
        "updated": is_update
    }))
}

#[derive(Debug, Deserialize)]
struct UserUnregisterParams {
    fingerprint: String,
}

fn handle_user_unregister(state: &SharedRelayState, params: Value) -> Result<Value, RpcError> {
    let params: UserUnregisterParams =
        serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))?;

    let mut relay = acquire_relay_write(state);

    if relay.users.remove(&params.fingerprint).is_some() {
        relay.messages.remove(&params.fingerprint);
        info!(
            "user.unregister: {}",
            &params.fingerprint[..16.min(params.fingerprint.len())]
        );
        Ok(serde_json::json!({ "unregistered": true }))
    } else {
        Err(RpcError::not_found("User not found"))
    }
}

#[derive(Debug, Deserialize)]
struct UserGetParams {
    fingerprint: String,
}

fn handle_user_get(state: &SharedRelayState, params: Value) -> Result<Value, RpcError> {
    let params: UserGetParams =
        serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))?;

    let relay = acquire_relay_read(state);

    relay
        .users
        .get(&params.fingerprint)
        .map(|user| serde_json::to_value(user).unwrap())
        .ok_or_else(|| RpcError::not_found("User not found"))
}

fn handle_user_list(state: &SharedRelayState) -> Result<Value, RpcError> {
    let relay = acquire_relay_read(state);
    let users: Vec<&RegisteredUser> = relay.users.values().collect();
    info!("user.list: {} users", users.len());
    serde_json::to_value(users).map_err(|e| RpcError::internal_error(e.to_string()))
}

// =============================================================================
// Message Handlers
// =============================================================================

#[derive(Debug, Deserialize)]
struct MessageSendParams {
    recipient_fingerprint: String,
    sender_fingerprint: String,
    encrypted_data: String,
}

fn handle_message_send(state: &SharedRelayState, params: Value) -> Result<Value, RpcError> {
    let params: MessageSendParams =
        serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))?;

    if params.encrypted_data.len() > MAX_MESSAGE_SIZE {
        return Err(RpcError::invalid_params("Message too large"));
    }

    if params.sender_fingerprint.is_empty() {
        return Err(RpcError::invalid_params("Sender fingerprint required"));
    }

    let now = current_timestamp_millis() / 1000;
    let message_id = format!("{}-{}", now, rand_id());

    let message = QueuedMessage {
        sender_fingerprint: params.sender_fingerprint.clone(),
        encrypted_data: params.encrypted_data,
        timestamp: now,
        message_id: message_id.clone(),
    };

    let mut relay = acquire_relay_write(state);

    let queue = relay
        .messages
        .entry(params.recipient_fingerprint.clone())
        .or_default();

    if queue.len() >= MAX_QUEUED_MESSAGES {
        return Err(RpcError::resource_exhausted("Recipient queue full"));
    }

    queue.push_back(message);

    info!(
        "message.send: {} -> {}",
        &params.sender_fingerprint[..16.min(params.sender_fingerprint.len())],
        &params.recipient_fingerprint[..16.min(params.recipient_fingerprint.len())]
    );

    Ok(serde_json::json!({
        "sent": true,
        "message_id": message_id
    }))
}

#[derive(Debug, Deserialize)]
struct MessageFetchParams {
    fingerprint: String,
}

fn handle_message_fetch(state: &SharedRelayState, params: Value) -> Result<Value, RpcError> {
    let params: MessageFetchParams =
        serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))?;

    let mut relay = acquire_relay_write(state);

    // Update last seen
    if let Some(user) = relay.users.get_mut(&params.fingerprint) {
        user.last_seen = current_timestamp_millis() / 1000;
    }

    let messages: Vec<QueuedMessage> = relay
        .messages
        .remove(&params.fingerprint)
        .map(|q| q.into_iter().collect())
        .unwrap_or_default();

    let count = messages.len();
    if count > 0 {
        info!(
            "message.fetch: delivered {} to {}",
            count,
            &params.fingerprint[..16.min(params.fingerprint.len())]
        );
    }

    Ok(serde_json::json!({ "messages": messages }))
}

fn handle_message_check(state: &SharedRelayState, params: Value) -> Result<Value, RpcError> {
    let params: MessageFetchParams =
        serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))?;

    let relay = acquire_relay_read(state);

    let count = relay
        .messages
        .get(&params.fingerprint)
        .map(|q| q.len())
        .unwrap_or(0);

    Ok(serde_json::json!({ "pending_count": count }))
}

// =============================================================================
// Forum Handlers
// =============================================================================

fn handle_forum_list(state: &SharedForumState) -> Result<Value, RpcError> {
    let relay = acquire_forum_read(state);

    let forums: Vec<ForumInfo> = relay
        .forums()
        .iter()
        .map(|(hash, forum)| ForumInfo {
            hash: hash.to_hex(),
            name: forum.name.clone(),
            description: forum.description.clone(),
            node_count: forum.node_count(),
            created_at: forum.created_at,
        })
        .collect();

    info!("forum.list: {} forums", forums.len());
    serde_json::to_value(forums).map_err(|e| RpcError::internal_error(e.to_string()))
}

fn handle_forum_sync(state: &SharedForumState, params: Value) -> Result<Value, RpcError> {
    let params: SyncParams =
        serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))?;

    let forum_hash = ContentHash::from_hex(&params.forum_hash)
        .map_err(|_| RpcError::invalid_params("Invalid forum hash"))?;

    let known_heads: Vec<ContentHash> = params
        .known_heads
        .iter()
        .filter_map(|h| ContentHash::from_hex(h).ok())
        .collect();

    let relay = acquire_forum_read(state);

    let forum = relay
        .get_forum(&forum_hash)
        .ok_or_else(|| RpcError::not_found("Forum not found"))?;

    let mut missing = forum.compute_missing_nodes(&known_heads);

    let client_max = params.max_results.unwrap_or(MAX_SYNC_MISSING_HASHES);
    let effective_max = client_max.min(MAX_SYNC_MISSING_HASHES);

    let has_more = if missing.len() > effective_max {
        missing.truncate(effective_max);
        true
    } else {
        false
    };

    let server_heads: Vec<String> = forum.heads.iter().map(|h| h.to_hex()).collect();

    info!(
        "forum.sync: {} missing {} nodes (has_more={})",
        forum_hash.short(),
        missing.len(),
        has_more
    );

    let result = SyncResult {
        forum_hash: params.forum_hash,
        missing_hashes: missing.iter().map(|h| h.to_hex()).collect(),
        server_heads,
        has_more,
    };

    serde_json::to_value(result).map_err(|e| RpcError::internal_error(e.to_string()))
}

fn handle_forum_fetch(state: &SharedForumState, params: Value) -> Result<Value, RpcError> {
    let params: FetchParams =
        serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))?;

    if params.hashes.len() > MAX_FETCH_BATCH_SIZE {
        return Err(RpcError::invalid_params(format!(
            "Too many hashes (max {})",
            MAX_FETCH_BATCH_SIZE
        )));
    }

    let unique_hashes: HashSet<ContentHash> = params
        .hashes
        .iter()
        .filter_map(|h| ContentHash::from_hex(h).ok())
        .collect();

    let relay = acquire_forum_read(state);
    let mut nodes = Vec::new();
    let mut not_found = Vec::new();

    for hash in unique_hashes {
        let mut found = false;
        for forum in relay.forums().values() {
            if let Some(node) = forum.nodes.get(&hash) {
                if let Ok(data) = node.to_bytes() {
                    nodes.push(NodeData {
                        hash: hash.to_hex(),
                        data: base64::engine::general_purpose::STANDARD.encode(&data),
                    });
                    found = true;
                    break;
                }
            }
        }
        if !found {
            not_found.push(hash.to_hex());
        }
    }

    info!(
        "forum.fetch: {} found, {} not found",
        nodes.len(),
        not_found.len()
    );

    let result = FetchResult { nodes, not_found };
    serde_json::to_value(result).map_err(|e| RpcError::internal_error(e.to_string()))
}

fn handle_forum_submit(state: &SharedForumState, params: Value) -> Result<Value, RpcError> {
    let params: SubmitParams =
        serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))?;

    let node_bytes = base64::engine::general_purpose::STANDARD
        .decode(&params.node_data)
        .map_err(|e| RpcError::invalid_params(format!("Invalid base64: {}", e)))?;

    let node = DagNode::from_bytes(&node_bytes)
        .map_err(|e| RpcError::invalid_params(format!("Invalid node: {}", e)))?;

    let node_hash = *node.hash();

    // Check content limits
    if let Some(error) = validate_content_limits(&node) {
        return Err(RpcError::validation_failed(vec![error]));
    }

    // Handle ForumGenesis specially
    if let DagNode::ForumGenesis(ref genesis) = node {
        return handle_forum_genesis_submit(state, genesis.clone());
    }

    let forum_hash = ContentHash::from_hex(&params.forum_hash)
        .map_err(|_| RpcError::invalid_params("Invalid forum hash"))?;

    let mut relay = acquire_forum_write(state);

    // Validate against forum state
    let validation_result = {
        let forum = relay
            .get_forum(&forum_hash)
            .ok_or_else(|| RpcError::not_found("Forum not found"))?;

        if forum.node_count() >= MAX_NODES_PER_FORUM {
            return Err(RpcError::resource_exhausted(format!(
                "Forum at capacity ({} nodes)",
                MAX_NODES_PER_FORUM
            )));
        }

        let permissions: HashMap<ContentHash, ForumPermissions> = forum
            .permissions
            .as_ref()
            .map(|p| {
                let mut map = HashMap::new();
                map.insert(forum_hash, p.clone());
                map
            })
            .unwrap_or_default();

        let ctx = ValidationContext::new(&forum.nodes, &permissions, current_timestamp_millis());
        validate_node(&node, &ctx)
    };

    match validation_result {
        Ok(result) if !result.is_valid => {
            return Err(RpcError::validation_failed(result.errors));
        }
        Err(e) => {
            return Err(RpcError::validation_failed(vec![e.to_string()]));
        }
        _ => {}
    }

    relay
        .add_node(&forum_hash, node.clone())
        .map_err(RpcError::internal_error)?;

    info!(
        "forum.submit: accepted {} ({:?})",
        node_hash.short(),
        node.node_type()
    );

    let result = SubmitResult {
        accepted: true,
        hash: node_hash.to_hex(),
    };
    serde_json::to_value(result).map_err(|e| RpcError::internal_error(e.to_string()))
}

fn handle_forum_genesis_submit(
    state: &SharedForumState,
    genesis: ForumGenesis,
) -> Result<Value, RpcError> {
    let empty_nodes = HashMap::new();
    let empty_perms = HashMap::new();
    let ctx = ValidationContext::new(&empty_nodes, &empty_perms, current_timestamp_millis());

    match validate_node(&DagNode::from(genesis.clone()), &ctx) {
        Ok(result) if !result.is_valid => {
            return Err(RpcError::validation_failed(result.errors));
        }
        Err(e) => {
            return Err(RpcError::validation_failed(vec![e.to_string()]));
        }
        _ => {}
    }

    let mut relay = acquire_forum_write(state);
    let hash = relay
        .create_forum(genesis.clone())
        .map_err(RpcError::internal_error)?;

    info!(
        "forum.submit: created forum '{}' ({})",
        genesis.name(),
        hash.short()
    );

    let result = SubmitResult {
        accepted: true,
        hash: hash.to_hex(),
    };
    serde_json::to_value(result).map_err(|e| RpcError::internal_error(e.to_string()))
}

fn handle_forum_export(state: &SharedForumState, params: Value) -> Result<Value, RpcError> {
    let params: ExportParams =
        serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))?;

    let forum_hash = ContentHash::from_hex(&params.forum_hash)
        .map_err(|_| RpcError::invalid_params("Invalid forum hash"))?;

    let relay = acquire_forum_read(state);

    let forum = relay
        .get_forum(&forum_hash)
        .ok_or_else(|| RpcError::not_found("Forum not found"))?;

    let page = params.page.unwrap_or(0);
    let page_size = params
        .page_size
        .unwrap_or(MAX_EXPORT_PAGE_SIZE)
        .min(MAX_EXPORT_PAGE_SIZE);

    let skip = page.saturating_mul(page_size);

    let all_nodes: Vec<&DagNode> = forum.nodes_in_order();
    let total_nodes = all_nodes.len();

    let mut nodes = Vec::new();
    for node in all_nodes.into_iter().skip(skip).take(page_size) {
        if let Ok(data) = node.to_bytes() {
            nodes.push(NodeData {
                hash: node.hash().to_hex(),
                data: base64::engine::general_purpose::STANDARD.encode(&data),
            });
        }
    }

    let has_more = skip + nodes.len() < total_nodes;

    info!(
        "forum.export: {} page {} ({} nodes, has_more={})",
        forum_hash.short(),
        page,
        nodes.len(),
        has_more
    );

    let result = ExportResult {
        forum_hash: params.forum_hash,
        nodes,
        total_nodes,
        has_more,
    };
    serde_json::to_value(result).map_err(|e| RpcError::internal_error(e.to_string()))
}

// =============================================================================
// System Handlers
// =============================================================================

fn handle_health() -> Result<Value, RpcError> {
    Ok(serde_json::json!({
        "status": "ok",
        "service": "pqpgp-relay",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

fn handle_stats(state: &AppState) -> Result<Value, RpcError> {
    let relay = acquire_relay_read(&state.relay);
    let forum = acquire_forum_read(&state.forum);

    let total_queued: usize = relay.messages.values().map(|q| q.len()).sum();

    Ok(serde_json::json!({
        "messaging": {
            "registered_users": relay.users.len(),
            "total_queued_messages": total_queued,
            "queues_active": relay.messages.len()
        },
        "forums": {
            "total_forums": forum.forums().len(),
            "total_nodes": forum.total_nodes()
        }
    }))
}

// =============================================================================
// Helpers
// =============================================================================

fn rand_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 16] = rng.gen();
    hex::encode(random_bytes)
}
