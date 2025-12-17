//! HTTP handlers for forum API endpoints.
//!
//! This module provides Axum handlers for the forum sync protocol.
//!
//! ## Security Measures
//!
//! - **Batch size limits**: Fetch and sync requests are limited to prevent DoS
//! - **Content size limits**: Node content is validated for maximum size
//! - **Authorization**: Delete operations require owner signature
//! - **Pagination**: Export uses pagination to prevent memory exhaustion
//! - **Global resource limits**: Maximum forums and nodes per forum enforced
//!
//! ## Privacy Model for Hidden Content
//!
//! Hidden content (threads, posts, boards) remains accessible via direct fetch by hash.
//! This is intentional for DAG integrity and synchronization:
//!
//! - **DAG requires all nodes**: Cryptographic verification needs complete node set
//! - **Hidden status is mutable**: Content can be unhidden later
//! - **Listing endpoints filter**: `list_threads` and `list_posts` exclude hidden content
//! - **Sync returns all nodes**: Clients need complete DAG for signature verification
//!
//! Hiding is a display-level moderation action, not data deletion. The relay stores
//! all valid nodes; clients are responsible for respecting hidden flags in their UI.

use super::persistence::PersistentForumState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use pqpgp::crypto::PublicKey;
use pqpgp::forum::permissions::ForumPermissions;
use pqpgp::forum::types::current_timestamp_millis;
use pqpgp::forum::{
    validate_node, ContentHash, DagNode, ExportForumResponse, FetchNodesRequest,
    FetchNodesResponse, SerializedNode, SubmitNodeRequest, SubmitNodeResponse, SyncRequest,
    SyncResponse, ValidationContext,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{error, info, instrument, warn};

// =============================================================================
// RwLock Helpers (Handle Poisoning Gracefully)
// =============================================================================

/// Acquires a read lock on the state, recovering from poison if necessary.
/// Returns the guard, clearing the poisoned state if one was present.
fn acquire_read_lock(
    state: &RwLock<PersistentForumState>,
) -> RwLockReadGuard<'_, PersistentForumState> {
    state.read().unwrap_or_else(|poisoned| {
        error!("RwLock was poisoned on read, recovering");
        poisoned.into_inner()
    })
}

/// Acquires a write lock on the state, recovering from poison if necessary.
/// Returns the guard, clearing the poisoned state if one was present.
fn acquire_write_lock(
    state: &RwLock<PersistentForumState>,
) -> RwLockWriteGuard<'_, PersistentForumState> {
    state.write().unwrap_or_else(|poisoned| {
        error!("RwLock was poisoned on write, recovering");
        poisoned.into_inner()
    })
}

// =============================================================================
// Security Constants
// =============================================================================

/// Maximum number of hashes allowed in a single fetch request.
const MAX_FETCH_BATCH_SIZE: usize = 1000;

/// Maximum number of missing hashes returned in a sync response.
const MAX_SYNC_MISSING_HASHES: usize = 10000;

/// Maximum nodes returned in a single export page.
const MAX_EXPORT_PAGE_SIZE: usize = 1000;

/// Maximum length for forum/board names.
const MAX_NAME_LENGTH: usize = 256;

/// Maximum length for forum/board descriptions.
const MAX_DESCRIPTION_LENGTH: usize = 10 * 1024; // 10KB

/// Maximum length for thread titles.
const MAX_TITLE_LENGTH: usize = 512;

/// Maximum length for thread/post body content.
const MAX_BODY_LENGTH: usize = 100 * 1024; // 100KB

/// Maximum number of tags per board.
const MAX_TAGS_COUNT: usize = 10;

/// Maximum length of a single tag.
const MAX_TAG_LENGTH: usize = 64;

/// Minimum valid timestamp (2024-01-01 00:00:00 UTC in milliseconds).
/// Nodes with timestamps before this are rejected as invalid.
const MIN_VALID_TIMESTAMP_MS: u64 = 1704067200000;

// =============================================================================
// Global Resource Limits
// =============================================================================

/// Maximum number of forums that can be hosted on this relay.
/// This prevents storage exhaustion attacks by limiting forum creation.
const MAX_FORUMS: usize = 10000;

/// Maximum number of nodes per forum (includes all node types).
/// This prevents any single forum from consuming excessive storage.
const MAX_NODES_PER_FORUM: usize = 1_000_000;

/// Computes a fingerprint from raw ML-DSA-87 identity bytes and returns first 8 bytes as hex.
fn compute_identity_fingerprint(identity: &[u8]) -> String {
    let fingerprint = PublicKey::fingerprint_from_mldsa87_bytes(identity);
    hex::encode(&fingerprint[..8])
}

/// Validates content size limits for a node.
///
/// Returns an error message if any content exceeds limits, or None if valid.
fn validate_content_limits(node: &DagNode) -> Option<String> {
    match node {
        DagNode::ForumGenesis(forum) => {
            if forum.name().len() > MAX_NAME_LENGTH {
                return Some(format!(
                    "Forum name exceeds maximum length of {} characters",
                    MAX_NAME_LENGTH
                ));
            }
            if forum.description().len() > MAX_DESCRIPTION_LENGTH {
                return Some(format!(
                    "Forum description exceeds maximum length of {} bytes",
                    MAX_DESCRIPTION_LENGTH
                ));
            }
            if forum.created_at() < MIN_VALID_TIMESTAMP_MS {
                return Some("Forum timestamp is unreasonably old".to_string());
            }
        }
        DagNode::BoardGenesis(board) => {
            if board.name().len() > MAX_NAME_LENGTH {
                return Some(format!(
                    "Board name exceeds maximum length of {} characters",
                    MAX_NAME_LENGTH
                ));
            }
            if board.description().len() > MAX_DESCRIPTION_LENGTH {
                return Some(format!(
                    "Board description exceeds maximum length of {} bytes",
                    MAX_DESCRIPTION_LENGTH
                ));
            }
            if board.tags().len() > MAX_TAGS_COUNT {
                return Some(format!("Board has too many tags (max {})", MAX_TAGS_COUNT));
            }
            for tag in board.tags() {
                if tag.len() > MAX_TAG_LENGTH {
                    return Some(format!(
                        "Tag exceeds maximum length of {} characters",
                        MAX_TAG_LENGTH
                    ));
                }
            }
            if board.created_at() < MIN_VALID_TIMESTAMP_MS {
                return Some("Board timestamp is unreasonably old".to_string());
            }
        }
        DagNode::ThreadRoot(thread) => {
            if thread.title().len() > MAX_TITLE_LENGTH {
                return Some(format!(
                    "Thread title exceeds maximum length of {} characters",
                    MAX_TITLE_LENGTH
                ));
            }
            if thread.body().len() > MAX_BODY_LENGTH {
                return Some(format!(
                    "Thread body exceeds maximum length of {} bytes",
                    MAX_BODY_LENGTH
                ));
            }
            if thread.created_at() < MIN_VALID_TIMESTAMP_MS {
                return Some("Thread timestamp is unreasonably old".to_string());
            }
        }
        DagNode::Post(post) => {
            if post.body().len() > MAX_BODY_LENGTH {
                return Some(format!(
                    "Post body exceeds maximum length of {} bytes",
                    MAX_BODY_LENGTH
                ));
            }
            if post.created_at() < MIN_VALID_TIMESTAMP_MS {
                return Some("Post timestamp is unreasonably old".to_string());
            }
        }
        DagNode::ModAction(action) => {
            if action.created_at() < MIN_VALID_TIMESTAMP_MS {
                return Some("Mod action timestamp is unreasonably old".to_string());
            }
        }
        DagNode::Edit(edit) => {
            // Check edited content limits
            if let Some(name) = edit.new_name() {
                if name.len() > MAX_NAME_LENGTH {
                    return Some(format!(
                        "Edit name exceeds maximum length of {} characters",
                        MAX_NAME_LENGTH
                    ));
                }
            }
            if let Some(desc) = edit.new_description() {
                if desc.len() > MAX_DESCRIPTION_LENGTH {
                    return Some(format!(
                        "Edit description exceeds maximum length of {} bytes",
                        MAX_DESCRIPTION_LENGTH
                    ));
                }
            }
            if edit.created_at() < MIN_VALID_TIMESTAMP_MS {
                return Some("Edit timestamp is unreasonably old".to_string());
            }
        }
        DagNode::EncryptionIdentity(identity) => {
            // Encryption identities have size limits enforced by the library
            // Just validate timestamp for reasonableness
            if identity.content.created_at < MIN_VALID_TIMESTAMP_MS {
                return Some("Encryption identity timestamp is unreasonably old".to_string());
            }
        }
        DagNode::SealedPrivateMessage(sealed) => {
            // Sealed messages have payload size enforced by the library (100KB max)
            // Just validate timestamp for reasonableness
            if sealed.content.created_at < MIN_VALID_TIMESTAMP_MS {
                return Some("Sealed message timestamp is unreasonably old".to_string());
            }
        }
    }
    None
}

/// Thread-safe forum state
pub type SharedForumState = Arc<RwLock<PersistentForumState>>;

/// Forum info returned in list responses.
#[derive(Debug, Serialize)]
pub struct ForumInfo {
    pub hash: String,
    pub name: String,
    pub description: String,
    pub node_count: usize,
    pub created_at: u64,
}

/// Request to create a forum.
#[derive(Debug, Deserialize)]
pub struct CreateForumRequest {
    /// Base64-encoded serialized ForumGenesis node
    pub genesis_data: String,
}

/// Generic forum API response.
#[derive(Debug, Serialize)]
pub struct ForumApiResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl ForumApiResponse {
    fn success_with_hash(message: impl Into<String>, hash: &ContentHash) -> Self {
        Self {
            success: true,
            message: Some(message.into()),
            error: None,
            hash: Some(hash.to_hex()),
        }
    }

    fn error(error: impl Into<String>) -> Self {
        Self {
            success: false,
            message: None,
            error: Some(error.into()),
            hash: None,
        }
    }
}

/// List all forums.
#[instrument(skip(state))]
pub async fn list_forums(State(state): State<SharedForumState>) -> impl IntoResponse {
    let relay = acquire_read_lock(&state);

    let forums: Vec<ForumInfo> = relay
        .forums()
        .iter()
        .map(|(hash, forum)| ForumInfo {
            hash: hash.to_hex(),
            name: forum.effective_forum_name(hash),
            description: forum.effective_forum_description(hash),
            node_count: forum.node_count(),
            created_at: forum.created_at,
        })
        .collect();

    info!("Listed {} forums", forums.len());
    Json(forums)
}

/// Create a new forum.
#[instrument(skip(state, request))]
pub async fn create_forum(
    State(state): State<SharedForumState>,
    Json(request): Json<CreateForumRequest>,
) -> impl IntoResponse {
    // Decode the genesis data
    let genesis_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &request.genesis_data,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ForumApiResponse::error(format!("Invalid base64: {}", e))),
            );
        }
    };

    // Deserialize the genesis node
    let node = match DagNode::from_bytes(&genesis_bytes) {
        Ok(node) => node,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ForumApiResponse::error(format!("Invalid node data: {}", e))),
            );
        }
    };

    // Ensure it's a forum genesis
    let genesis = match node {
        DagNode::ForumGenesis(g) => g,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ForumApiResponse::error("Expected ForumGenesis node")),
            );
        }
    };

    // Validate the genesis (signature, hash)
    let empty_nodes = HashMap::new();
    let empty_perms = HashMap::new();
    let ctx = ValidationContext::new(&empty_nodes, &empty_perms, current_timestamp_millis());

    match validate_node(&DagNode::from(genesis.clone()), &ctx) {
        Ok(result) if !result.is_valid => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ForumApiResponse::error(format!(
                    "Validation failed: {:?}",
                    result.errors
                ))),
            );
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ForumApiResponse::error(format!("Validation error: {}", e))),
            );
        }
        _ => {}
    }

    // Check global forum limit before acquiring write lock
    {
        let relay = acquire_read_lock(&state);
        if relay.forums().len() >= MAX_FORUMS {
            warn!(
                "Forum creation rejected: relay at maximum capacity ({} forums)",
                MAX_FORUMS
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ForumApiResponse::error(format!(
                    "Relay at maximum capacity ({} forums)",
                    MAX_FORUMS
                ))),
            );
        }
    }

    // Create the forum
    let mut relay = acquire_write_lock(&state);
    match relay.create_forum(genesis.clone()) {
        Ok(hash) => {
            info!(
                "Created forum '{}' with hash {}",
                genesis.name(),
                hash.short()
            );
            (
                StatusCode::CREATED,
                Json(ForumApiResponse::success_with_hash("Forum created", &hash)),
            )
        }
        Err(e) => (StatusCode::CONFLICT, Json(ForumApiResponse::error(e))),
    }
}

/// Get forum details.
#[instrument(skip(state))]
pub async fn get_forum(
    State(state): State<SharedForumState>,
    Path(hash_hex): Path<String>,
) -> impl IntoResponse {
    let hash = match ContentHash::from_hex(&hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(None));
        }
    };

    let relay = acquire_read_lock(&state);
    match relay.get_forum(&hash) {
        Some(forum) => {
            let info = ForumInfo {
                hash: hash.to_hex(),
                name: forum.effective_forum_name(&hash),
                description: forum.effective_forum_description(&hash),
                node_count: forum.node_count(),
                created_at: forum.created_at,
            };
            (StatusCode::OK, Json(Some(info)))
        }
        None => (StatusCode::NOT_FOUND, Json(None)),
    }
}

/// Sync request - client sends known heads, server returns missing hashes.
///
/// Server enforces a maximum limit on returned hashes to prevent memory exhaustion.
#[instrument(skip(state, request))]
pub async fn sync_forum(
    State(state): State<SharedForumState>,
    Json(request): Json<SyncRequest>,
) -> impl IntoResponse {
    let relay = acquire_read_lock(&state);

    let forum = match relay.get_forum(&request.forum_hash) {
        Some(f) => f,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(SyncResponse::new(request.forum_hash)),
            );
        }
    };

    // Compute what the client is missing
    let mut missing = forum.compute_missing(&request.known_heads);

    // Apply client-specified limit, but enforce server maximum
    let client_max = request.max_results.unwrap_or(MAX_SYNC_MISSING_HASHES);
    let effective_max = client_max.min(MAX_SYNC_MISSING_HASHES);

    let has_more = if missing.len() > effective_max {
        missing.truncate(effective_max);
        true
    } else {
        false
    };

    let server_heads: Vec<ContentHash> = forum.heads.iter().copied().collect();

    info!(
        "Sync request for forum {}: client has {} heads, missing {} nodes (has_more={})",
        request.forum_hash.short(),
        request.known_heads.len(),
        missing.len(),
        has_more
    );

    let response = SyncResponse::new(request.forum_hash)
        .with_missing(missing)
        .with_has_more(has_more)
        .with_server_heads(server_heads);

    (StatusCode::OK, Json(response))
}

/// Fetch nodes by hash.
///
/// Limited to [`MAX_FETCH_BATCH_SIZE`] hashes per request to prevent DoS.
/// Duplicate hashes in the request are deduplicated.
#[instrument(skip(state, request))]
pub async fn fetch_nodes(
    State(state): State<SharedForumState>,
    Json(request): Json<FetchNodesRequest>,
) -> impl IntoResponse {
    // Enforce batch size limit
    if request.hashes.len() > MAX_FETCH_BATCH_SIZE {
        warn!(
            "Fetch request rejected: {} hashes exceeds limit of {}",
            request.hashes.len(),
            MAX_FETCH_BATCH_SIZE
        );
        return (StatusCode::BAD_REQUEST, Json(FetchNodesResponse::new()));
    }

    // Deduplicate requested hashes
    let unique_hashes: HashSet<ContentHash> = request.hashes.iter().copied().collect();

    let relay = acquire_read_lock(&state);

    let mut response = FetchNodesResponse::new();

    for hash in unique_hashes {
        // Search all forums for the node
        let mut found = false;
        for forum in relay.forums().values() {
            if let Some(node) = forum.nodes.get(&hash) {
                match node.to_bytes() {
                    Ok(data) => {
                        response.add_node(hash, data);
                        found = true;
                        break;
                    }
                    Err(_) => {
                        response.add_not_found(hash);
                        found = true;
                        break;
                    }
                }
            }
        }
        if !found {
            response.add_not_found(hash);
        }
    }

    info!(
        "Fetch request: {} requested, {} unique, {} found, {} not found",
        request.hashes.len(),
        request.hashes.len(),
        response.nodes.len(),
        response.not_found.len()
    );

    (StatusCode::OK, Json(response))
}

/// Submit a new node to a forum.
///
/// Validates:
/// - Content size limits (names, descriptions, bodies)
/// - Minimum timestamp (rejects unreasonably old nodes)
/// - Cryptographic signature and hash
/// - Permission checks
#[instrument(skip(state, request))]
pub async fn submit_node(
    State(state): State<SharedForumState>,
    Json(request): Json<SubmitNodeRequest>,
) -> impl IntoResponse {
    // Deserialize the node
    let node = match DagNode::from_bytes(&request.node_data) {
        Ok(n) => n,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitNodeResponse::rejected(format!(
                    "Invalid node data: {}",
                    e
                ))),
            );
        }
    };

    let node_hash = *node.hash();

    // Validate content size limits BEFORE cryptographic validation (cheaper check first)
    if let Some(error) = validate_content_limits(&node) {
        warn!(
            "Node {} rejected for content limits: {}",
            node_hash.short(),
            error
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(SubmitNodeResponse::rejected(error)),
        );
    }

    // Get the forum for validation context
    let mut relay = acquire_write_lock(&state);

    // First, validate the node against the forum's current state
    let validation_result = {
        let forum = match relay.get_forum(&request.forum_hash) {
            Some(f) => f,
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(SubmitNodeResponse::rejected("Forum not found")),
                );
            }
        };

        // Check per-forum node limit
        if forum.node_count() >= MAX_NODES_PER_FORUM {
            warn!(
                "Node rejected: forum {} at maximum capacity ({} nodes)",
                request.forum_hash.short(),
                MAX_NODES_PER_FORUM
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(SubmitNodeResponse::rejected(format!(
                    "Forum at maximum capacity ({} nodes)",
                    MAX_NODES_PER_FORUM
                ))),
            );
        }

        // Build validation context
        let permissions: HashMap<ContentHash, ForumPermissions> = forum
            .permissions
            .as_ref()
            .map(|p| {
                let mut map = HashMap::new();
                map.insert(request.forum_hash, p.clone());
                map
            })
            .unwrap_or_default();

        let ctx = ValidationContext::new(&forum.nodes, &permissions, current_timestamp_millis());

        // Validate the node
        validate_node(&node, &ctx)
    };

    match validation_result {
        Ok(result) if !result.is_valid => {
            warn!("Node {} rejected: {:?}", node_hash.short(), result.errors);
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitNodeResponse::rejected(format!(
                    "Validation failed: {:?}",
                    result.errors
                ))),
            );
        }
        Err(e) => {
            warn!("Node {} validation error: {}", node_hash.short(), e);
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitNodeResponse::rejected(format!(
                    "Validation error: {}",
                    e
                ))),
            );
        }
        _ => {}
    }

    // Add the node through PersistentForumState to ensure it's persisted
    match relay.add_node(&request.forum_hash, node.clone()) {
        Ok(added) => {
            if added {
                info!(
                    "Accepted node {} ({:?}) for forum {}",
                    node_hash.short(),
                    node.node_type(),
                    request.forum_hash.short()
                );
            } else {
                info!("Node {} already exists", node_hash.short());
            }
            (
                StatusCode::OK,
                Json(SubmitNodeResponse::accepted(node_hash)),
            )
        }
        Err(e) => {
            warn!("Failed to add node {}: {}", node_hash.short(), e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SubmitNodeResponse::rejected(format!(
                    "Failed to add node: {}",
                    e
                ))),
            )
        }
    }
}

/// Query parameters for export pagination.
#[derive(Debug, Deserialize)]
pub struct ExportParams {
    /// Page number (0-indexed). Default: 0
    #[serde(default)]
    pub page: usize,
    /// Page size. Default and max: [`MAX_EXPORT_PAGE_SIZE`]
    pub page_size: Option<usize>,
}

/// Export a forum's DAG with pagination.
///
/// Uses pagination to prevent memory exhaustion on large forums.
/// Query params:
/// - `page`: Page number (0-indexed, default 0)
/// - `page_size`: Nodes per page (default and max: 1000)
#[instrument(skip(state))]
pub async fn export_forum(
    State(state): State<SharedForumState>,
    Path(hash_hex): Path<String>,
    Query(params): Query<ExportParams>,
) -> impl IntoResponse {
    let hash = match ContentHash::from_hex(&hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ExportForumResponse::new(ContentHash::from_bytes([0u8; 64]))),
            );
        }
    };

    let relay = acquire_read_lock(&state);

    let forum = match relay.get_forum(&hash) {
        Some(f) => f,
        None => {
            return (StatusCode::NOT_FOUND, Json(ExportForumResponse::new(hash)));
        }
    };

    // Enforce page size limits
    let page_size = params
        .page_size
        .unwrap_or(MAX_EXPORT_PAGE_SIZE)
        .min(MAX_EXPORT_PAGE_SIZE);
    let page = params.page;
    // Use checked arithmetic to prevent integer overflow
    let skip = match page.checked_mul(page_size) {
        Some(s) => s,
        None => {
            // Overflow - return empty page
            return (StatusCode::OK, Json(ExportForumResponse::new(hash)));
        }
    };

    // Serialize nodes in topological order with pagination
    let all_nodes: Vec<&DagNode> = forum.nodes_in_order();
    let total_nodes = all_nodes.len();

    let mut nodes = Vec::new();
    for node in all_nodes.into_iter().skip(skip).take(page_size) {
        if let Ok(data) = node.to_bytes() {
            nodes.push(SerializedNode {
                hash: *node.hash(),
                data,
            });
        }
    }

    let has_more = skip + nodes.len() < total_nodes;

    info!(
        "Exported forum {} page {} ({} nodes, has_more={})",
        hash.short(),
        page,
        nodes.len(),
        has_more
    );

    let mut response = ExportForumResponse::new(hash).with_nodes(nodes);
    response.has_more = has_more;
    response.total_nodes = Some(total_nodes);
    (StatusCode::OK, Json(response))
}

/// Forum statistics.
#[instrument(skip(state))]
pub async fn forum_stats(State(state): State<SharedForumState>) -> impl IntoResponse {
    let relay = acquire_read_lock(&state);

    Json(serde_json::json!({
        "total_forums": relay.forums().len(),
        "total_nodes": relay.total_nodes()
    }))
}

/// List boards in a forum.
#[instrument(skip(state))]
pub async fn list_boards(
    State(state): State<SharedForumState>,
    Path(forum_hash_hex): Path<String>,
) -> impl IntoResponse {
    let forum_hash = match ContentHash::from_hex(&forum_hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(Vec::<BoardInfo>::new()));
        }
    };

    let relay = acquire_read_lock(&state);
    let forum = match relay.get_forum(&forum_hash) {
        Some(f) => f,
        None => {
            return (StatusCode::NOT_FOUND, Json(Vec::new()));
        }
    };

    // Find all board genesis nodes, using effective names/descriptions
    let boards: Vec<BoardInfo> = forum
        .nodes
        .values()
        .filter_map(|node| {
            if let DagNode::BoardGenesis(board) = node {
                let board_hash = board.hash();
                Some(BoardInfo {
                    hash: board_hash.to_hex(),
                    name: forum
                        .effective_board_name(board_hash)
                        .unwrap_or_else(|| board.name().to_string()),
                    description: forum
                        .effective_board_description(board_hash)
                        .unwrap_or_else(|| board.description().to_string()),
                    tags: board.tags().to_vec(),
                    created_at: board.created_at(),
                })
            } else {
                None
            }
        })
        .collect();

    (StatusCode::OK, Json(boards))
}

/// Board info for list responses.
#[derive(Debug, Serialize)]
pub struct BoardInfo {
    pub hash: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub created_at: u64,
}

/// Moderator info for list responses.
#[derive(Debug, Serialize)]
pub struct ModeratorInfo {
    pub identity_fingerprint: String,
    pub is_owner: bool,
}

/// List moderators in a forum.
#[instrument(skip(state))]
pub async fn list_moderators(
    State(state): State<SharedForumState>,
    Path(forum_hash_hex): Path<String>,
) -> impl IntoResponse {
    let forum_hash = match ContentHash::from_hex(&forum_hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(Vec::<ModeratorInfo>::new()));
        }
    };

    let relay = acquire_read_lock(&state);
    let forum = match relay.get_forum(&forum_hash) {
        Some(f) => f,
        None => {
            return (StatusCode::NOT_FOUND, Json(Vec::new()));
        }
    };

    // Get permissions to get moderator list
    let moderators: Vec<ModeratorInfo> = match &forum.permissions {
        Some(perms) => perms
            .moderators()
            .map(|identity| {
                let fingerprint_hex = compute_identity_fingerprint(identity);
                let is_owner = perms.is_owner(identity);
                ModeratorInfo {
                    identity_fingerprint: fingerprint_hex,
                    is_owner,
                }
            })
            .collect(),
        None => Vec::new(),
    };

    (StatusCode::OK, Json(moderators))
}

/// Board moderator info for API response.
#[derive(Debug, Serialize)]
pub struct BoardModeratorInfo {
    pub identity_fingerprint: String,
}

/// List moderators for a specific board.
#[instrument(skip(state))]
pub async fn list_board_moderators(
    State(state): State<SharedForumState>,
    Path((forum_hash_hex, board_hash_hex)): Path<(String, String)>,
) -> impl IntoResponse {
    let forum_hash = match ContentHash::from_hex(&forum_hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(Vec::<BoardModeratorInfo>::new()),
            );
        }
    };

    let board_hash = match ContentHash::from_hex(&board_hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(Vec::<BoardModeratorInfo>::new()),
            );
        }
    };

    let relay = acquire_read_lock(&state);
    let forum = match relay.get_forum(&forum_hash) {
        Some(f) => f,
        None => {
            return (StatusCode::NOT_FOUND, Json(Vec::new()));
        }
    };

    // Get board moderators
    let moderators: Vec<BoardModeratorInfo> = match &forum.permissions {
        Some(perms) => {
            let count = perms.board_moderator_count(&board_hash);
            info!(
                "Board {} has {} moderators in permissions",
                board_hash_hex, count
            );
            perms
                .board_moderators(&board_hash)
                .map(|identity| {
                    let fingerprint_hex = compute_identity_fingerprint(identity);
                    BoardModeratorInfo {
                        identity_fingerprint: fingerprint_hex,
                    }
                })
                .collect()
        }
        None => {
            info!("No permissions found for forum {}", forum_hash_hex);
            Vec::new()
        }
    };

    (StatusCode::OK, Json(moderators))
}

/// List threads in a board.
#[instrument(skip(state))]
pub async fn list_threads(
    State(state): State<SharedForumState>,
    Path((forum_hash_hex, board_hash_hex)): Path<(String, String)>,
) -> impl IntoResponse {
    let forum_hash = match ContentHash::from_hex(&forum_hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(Vec::<ThreadInfo>::new()));
        }
    };

    let board_hash = match ContentHash::from_hex(&board_hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(Vec::new()));
        }
    };

    let relay = acquire_read_lock(&state);
    let forum = match relay.get_forum(&forum_hash) {
        Some(f) => f,
        None => {
            return (StatusCode::NOT_FOUND, Json(Vec::new()));
        }
    };

    // Find all thread root nodes for this board, filtering out hidden threads
    let threads: Vec<ThreadInfo> = forum
        .nodes
        .values()
        .filter_map(|node| {
            if let DagNode::ThreadRoot(thread) = node {
                if thread.board_hash() == &board_hash {
                    // Check if thread is hidden
                    if let Some(ref perms) = forum.permissions {
                        if perms.is_thread_hidden(thread.hash()) {
                            return None;
                        }
                    }

                    // Count visible posts in this thread (exclude hidden posts)
                    let post_count = forum
                        .nodes
                        .values()
                        .filter(|n| {
                            if let DagNode::Post(post) = n {
                                if post.thread_hash() == thread.hash() {
                                    // Check if post is hidden
                                    if let Some(ref perms) = forum.permissions {
                                        return !perms.is_post_hidden(post.hash());
                                    }
                                    return true;
                                }
                            }
                            false
                        })
                        .count();

                    // Compute proper fingerprint: SHA3-512(algorithm_byte || key_bytes)
                    let author_fingerprint = compute_identity_fingerprint(thread.author_identity());

                    return Some(ThreadInfo {
                        hash: thread.hash().to_hex(),
                        title: thread.title().to_string(),
                        body_preview: thread.body().chars().take(200).collect(),
                        author_fingerprint,
                        post_count,
                        created_at: thread.created_at(),
                    });
                }
            }
            None
        })
        .collect();

    (StatusCode::OK, Json(threads))
}

/// Thread info for list responses.
#[derive(Debug, Serialize)]
pub struct ThreadInfo {
    pub hash: String,
    pub title: String,
    pub body_preview: String,
    pub author_fingerprint: String,
    pub post_count: usize,
    pub created_at: u64,
}

/// List posts in a thread.
#[instrument(skip(state))]
pub async fn list_posts(
    State(state): State<SharedForumState>,
    Path((forum_hash_hex, thread_hash_hex)): Path<(String, String)>,
) -> impl IntoResponse {
    let forum_hash = match ContentHash::from_hex(&forum_hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(Vec::<PostInfo>::new()));
        }
    };

    let thread_hash = match ContentHash::from_hex(&thread_hash_hex) {
        Ok(h) => h,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(Vec::new()));
        }
    };

    let relay = acquire_read_lock(&state);
    let forum = match relay.get_forum(&forum_hash) {
        Some(f) => f,
        None => {
            return (StatusCode::NOT_FOUND, Json(Vec::new()));
        }
    };

    // Find all posts in this thread, filtering out hidden posts
    let mut posts: Vec<PostInfo> = forum
        .nodes
        .values()
        .filter_map(|node| {
            if let DagNode::Post(post) = node {
                if post.thread_hash() == &thread_hash {
                    // Check if post is hidden
                    if let Some(ref perms) = forum.permissions {
                        if perms.is_post_hidden(post.hash()) {
                            return None;
                        }
                    }

                    return Some(PostInfo {
                        hash: post.hash().to_hex(),
                        body: post.body().to_string(),
                        author_fingerprint: compute_identity_fingerprint(post.author_identity()),
                        quote_hash: post.quote_hash().map(|h| h.to_hex()),
                        created_at: post.created_at(),
                    });
                }
            }
            None
        })
        .collect();

    // Sort by creation time
    posts.sort_by_key(|p| p.created_at);

    (StatusCode::OK, Json(posts))
}

/// Post info for list responses.
#[derive(Debug, Serialize)]
pub struct PostInfo {
    pub hash: String,
    pub body: String,
    pub author_fingerprint: String,
    pub quote_hash: Option<String>,
    pub created_at: u64,
}
