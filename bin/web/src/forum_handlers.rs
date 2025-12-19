//! Forum web handlers for PQPGP web interface.
//!
//! These handlers communicate with the relay server's forum API to provide
//! a web interface for viewing and participating in forums.

use crate::csrf::{get_csrf_token, validate_csrf_token, CsrfProtectedForm};
use crate::templates::{
    BoardDisplayInfo, BoardViewTemplate, ConversationInfo, EncryptionIdentityInfo,
    ForumDisplayInfo, ForumListTemplate, ForumViewTemplate, ModeratorDisplayInfo,
    PMComposeTemplate, PMConversationTemplate, PMInboxTemplate, PMRecipientInfo, PostDisplayInfo,
    PrivateMessageInfo, SigningKeyInfo, ThreadDisplayInfo, ThreadViewTemplate,
};
use crate::AppState;
use crate::SharedForumPersistence;
use askama::Template;
use axum::{
    extract::{Form, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json, Redirect},
};
use pqpgp::cli::utils::create_keyring_manager;
use pqpgp::crypto::Password;
use pqpgp::forum::{
    constants::{
        MAX_DESCRIPTION_SIZE, MAX_HASH_INPUT_SIZE, MAX_NAME_SIZE, MAX_PASSWORD_SIZE,
        MAX_POST_BODY_SIZE, MAX_TAGS_INPUT_SIZE, MAX_THREAD_BODY_SIZE, MAX_THREAD_TITLE_SIZE,
    },
    permissions::ForumPermissions,
    rpc_client::{FetchResult, ForumRpcClient, RpcRequest, RpcResponse, SyncResult},
    seal_private_message,
    storage::{Cursor, DEFAULT_PAGE_SIZE},
    types::current_timestamp_millis,
    validation::{validate_node, ValidationContext},
    BoardGenesis, ContentHash, ConversationManager, ConversationSession, DagNode, EditNode,
    EncryptionIdentity, EncryptionIdentityGenerator, ForumGenesis, ForumMetadata, InnerMessage,
    ModAction, ModActionNode, Post, PrivateMessageScanner, SealedPrivateMessage, StoredMessage,
    ThreadRoot,
};
use std::collections::{HashMap, HashSet};

// =============================================================================
// Security Constants
// =============================================================================

/// Maximum recursion depth for sync (prevents infinite loops from malicious relays).
const MAX_SYNC_DEPTH: usize = 100;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use tracing::{error, info, warn};

/// Relay URL - should match the relay server
const DEFAULT_RELAY_URL: &str = "http://127.0.0.1:3001";

fn get_relay_url() -> String {
    std::env::var("PQPGP_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string())
}

/// Gets the RPC endpoint URL.
fn get_rpc_endpoint() -> String {
    format!("{}/rpc", get_relay_url())
}

/// Creates an RPC client for relay communication.
fn create_rpc_client() -> ForumRpcClient {
    ForumRpcClient::new(get_rpc_endpoint())
}

/// Sends an RPC request and parses the response.
async fn send_rpc_request(
    http_client: &Client,
    rpc_client: &ForumRpcClient,
    request: &RpcRequest,
) -> Result<RpcResponse, String> {
    http_client
        .post(rpc_client.endpoint())
        .json(request)
        .send()
        .await
        .map_err(|e| format!("Failed to send RPC request: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse RPC response: {}", e))
}

/// Computes a fingerprint from identity bytes using the same algorithm as PublicKey::fingerprint().
///
/// This ensures fingerprints match between keys loaded from the keyring and identities
/// stored in forum nodes.
fn fingerprint_from_identity(identity: &[u8]) -> String {
    use pqpgp::crypto::PublicKey;
    let fingerprint = PublicKey::fingerprint_from_mldsa87_bytes(identity);
    hex::encode(&fingerprint[..8]) // First 16 hex chars
}

/// Gets effective forum name/description after applying edits.
fn get_effective_forum_info(
    persistence: &SharedForumPersistence,
    forum_hash: &ContentHash,
    fallback_name: &str,
    fallback_description: &str,
) -> (String, String) {
    persistence
        .get_effective_forum_info(forum_hash)
        .unwrap_or_else(|_| Some((fallback_name.to_string(), fallback_description.to_string())))
        .unwrap_or_else(|| (fallback_name.to_string(), fallback_description.to_string()))
}

/// Gets effective board name/description after applying edits.
///
/// Uses the pre-loaded board to avoid redundant disk reads.
/// Builds a BoardDisplayInfo from a BoardSummary (already has edits applied).
fn build_board_display_info_from_summary(summary: &pqpgp::forum::BoardSummary) -> BoardDisplayInfo {
    BoardDisplayInfo {
        hash: summary.board.hash().to_hex(),
        name: summary.effective_name.clone(),
        description: summary.effective_description.clone(),
        tags: summary.board.tags().to_vec(),
        created_at_display: format_timestamp(summary.board.created_at()),
        thread_count: summary.thread_count,
    }
}

/// Builds a BoardDisplayInfo with edits applied (for single board lookups).
/// Note: thread_count is set to 0 since this is used for single board lookups
/// where we don't need to display thread counts (e.g., move thread dropdown).
fn build_board_display_info(
    persistence: &SharedForumPersistence,
    forum_hash: &ContentHash,
    board: &BoardGenesis,
) -> BoardDisplayInfo {
    let (name, description) = persistence
        .apply_board_edits(forum_hash, board)
        .unwrap_or_else(|_| Some((board.name().to_string(), board.description().to_string())))
        .unwrap_or_else(|| (board.name().to_string(), board.description().to_string()));

    BoardDisplayInfo {
        hash: board.hash().to_hex(),
        name,
        description,
        tags: board.tags().to_vec(),
        created_at_display: format_timestamp(board.created_at()),
        thread_count: 0, // Not needed for single board lookups
    }
}

// =============================================================================
// Pagination Query Params
// =============================================================================

/// Query parameters for paginated views.
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    /// Cursor for the current page (base64-encoded).
    pub cursor: Option<String>,
    /// Previous cursor to enable back navigation.
    pub prev: Option<String>,
    /// Optional page size override (defaults to DEFAULT_PAGE_SIZE).
    pub limit: Option<usize>,
}

impl PaginationQuery {
    /// Gets the limit, clamped to a reasonable range.
    pub fn get_limit(&self) -> usize {
        self.limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, 100)
    }

    /// Decodes the cursor if present.
    pub fn get_cursor(&self) -> Option<Cursor> {
        self.cursor.as_ref().and_then(|s| Cursor::decode(s))
    }
}

// =============================================================================
// Permission Checking Helpers
// =============================================================================

/// Permission level required for a moderation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PermissionLevel {
    /// Only the forum owner can perform this action.
    OwnerOnly,
    /// Forum owner or forum-level moderator can perform this action.
    ForumModerator,
}

/// Checks if the signing key has the required permission level for a forum action.
///
/// This is a server-side pre-check to avoid wasting resources on unauthorized actions.
/// The DAG validation will still verify permissions cryptographically.
fn check_forum_permission(
    persistence: &SharedForumPersistence,
    forum_hash: &ContentHash,
    signing_key_fingerprint: &str,
    required_level: PermissionLevel,
) -> bool {
    let (mod_fingerprints, owner_fingerprint) = match persistence.get_forum_moderators(forum_hash) {
        Ok(result) => result,
        Err(e) => {
            warn!("Failed to get forum moderators for permission check: {}", e);
            return false;
        }
    };

    match required_level {
        PermissionLevel::OwnerOnly => {
            // Only owner can perform this action
            owner_fingerprint
                .as_ref()
                .is_some_and(|owner| owner == signing_key_fingerprint)
        }
        PermissionLevel::ForumModerator => {
            // Owner or any forum moderator can perform this action
            mod_fingerprints.contains(signing_key_fingerprint)
        }
    }
}

/// Gets the fingerprint of a signing key by its ID.
fn get_signing_key_fingerprint(signing_key_id: &str) -> Option<String> {
    let signing = get_signing_materials(signing_key_id).ok()?;
    let fp = signing.public_key.fingerprint();
    Some(hex::encode(&fp[..8]))
}

/// Syncs a forum from the relay to local storage.
///
/// This implements the full sync protocol:
/// 1. Get local heads from storage
/// 2. Send SyncRequest to relay with known heads
/// 3. Receive list of missing node hashes
/// 4. Fetch missing nodes from relay
/// 5. Validate and store nodes locally (topological order)
/// 6. Update local heads (only with validated, stored hashes)
///
/// Nodes are validated using the shared validation logic from pqpgp::forum::validation.
/// Invalid nodes are rejected and not stored.
///
/// Returns the number of nodes synced, or an error message.
pub async fn sync_forum(
    persistence: &SharedForumPersistence,
    forum_hash: &ContentHash,
) -> Result<usize, String> {
    sync_forum_with_depth(persistence, forum_hash, 0).await
}

/// Internal sync implementation with recursion depth tracking.
async fn sync_forum_with_depth(
    persistence: &SharedForumPersistence,
    forum_hash: &ContentHash,
    depth: usize,
) -> Result<usize, String> {
    // Prevent infinite recursion from malicious relay
    if depth >= MAX_SYNC_DEPTH {
        warn!(
            "Forum {}: max sync depth {} reached, stopping",
            forum_hash.short(),
            MAX_SYNC_DEPTH
        );
        return Ok(0);
    }

    let http_client = Client::new();
    let rpc_client = create_rpc_client();

    // Step 1: Build sync request with known heads
    let known_heads = persistence
        .get_heads(forum_hash)
        .map_err(|e| e.to_string())?;
    let known_heads_vec: Vec<ContentHash> = known_heads.into_iter().collect();

    info!(
        "Syncing forum {}: sending {} known heads (depth {})",
        forum_hash.short(),
        known_heads_vec.len(),
        depth
    );

    // Step 2: Send sync request to relay via JSON-RPC
    let sync_request = rpc_client.build_sync_request(forum_hash, &known_heads_vec, None);
    let sync_rpc_response = send_rpc_request(&http_client, &rpc_client, &sync_request).await?;
    let sync_result: SyncResult = rpc_client
        .parse_sync_response(sync_rpc_response)
        .map_err(|e| format!("Failed to parse sync response: {}", e))?;

    // Step 3: Filter out nodes we already have and deduplicate
    let missing_hashes = sync_result.parse_missing_hashes();
    let mut nodes_to_fetch: Vec<ContentHash> = Vec::new();
    let mut seen: HashSet<ContentHash> = HashSet::new();
    for hash in &missing_hashes {
        if !seen.contains(hash) && !persistence.node_exists(forum_hash, hash).unwrap_or(false) {
            nodes_to_fetch.push(*hash);
            seen.insert(*hash);
        }
    }

    if nodes_to_fetch.is_empty() {
        info!("Forum {} is already up to date", forum_hash.short());
        // Only update heads with hashes that exist locally (security: don't trust relay blindly)
        let local_nodes = persistence
            .load_forum_nodes(forum_hash)
            .map_err(|e| e.to_string())?;
        let local_hashes: HashSet<ContentHash> = local_nodes.iter().map(|n| *n.hash()).collect();
        let server_heads = sync_result.parse_server_heads();
        let verified_heads: HashSet<ContentHash> = server_heads
            .into_iter()
            .filter(|h| local_hashes.contains(h))
            .collect();
        if !verified_heads.is_empty() {
            persistence
                .set_heads(forum_hash, &verified_heads)
                .map_err(|e| e.to_string())?;
        }
        return Ok(0);
    }

    info!(
        "Forum {}: fetching {} missing nodes",
        forum_hash.short(),
        nodes_to_fetch.len()
    );

    // Step 4: Fetch missing nodes via JSON-RPC
    let fetch_request = rpc_client.build_fetch_request(&nodes_to_fetch);
    let fetch_rpc_response = send_rpc_request(&http_client, &rpc_client, &fetch_request).await?;
    let fetch_result: FetchResult = rpc_client
        .parse_fetch_response(fetch_rpc_response)
        .map_err(|e| format!("Failed to parse fetch response: {}", e))?;

    if !fetch_result.not_found.is_empty() {
        warn!(
            "Forum {}: {} nodes not found on relay",
            forum_hash.short(),
            fetch_result.not_found.len()
        );
    }

    // Step 5: Deserialize, deduplicate, sort topologically, validate, and store nodes
    //
    // We need to validate and store nodes in topological order so that:
    // - Parent nodes exist before children are validated
    // - Permissions are computed correctly for each node

    // First, deserialize all nodes and deduplicate by hash
    let mut deserialized_map: HashMap<ContentHash, DagNode> = HashMap::new();
    let fetched_nodes = fetch_result
        .deserialize_nodes()
        .map_err(|e| format!("Failed to deserialize nodes: {}", e))?;
    for (hash, node) in fetched_nodes {
        // Deduplicate: only keep first occurrence
        deserialized_map.entry(hash).or_insert(node);
    }

    let mut deserialized_nodes: Vec<DagNode> = deserialized_map.into_values().collect();

    // Sort topologically: forum genesis first, then boards, then threads, then posts/mod actions
    // This ensures parents are validated and stored before children
    deserialized_nodes.sort_by_key(|n| match n {
        DagNode::ForumGenesis(_) => (0, n.created_at()),
        DagNode::BoardGenesis(_) => (1, n.created_at()),
        DagNode::ThreadRoot(_) => (2, n.created_at()),
        DagNode::Post(_) => (3, n.created_at()),
        DagNode::ModAction(_) => (3, n.created_at()),
        DagNode::Edit(_) => (4, n.created_at()),
        // PM nodes come after regular forum content
        DagNode::EncryptionIdentity(_) => (5, n.created_at()),
        DagNode::SealedPrivateMessage(_) => (6, n.created_at()),
    });

    // Load existing nodes from local storage for validation context
    let existing_nodes = persistence
        .load_forum_nodes(forum_hash)
        .map_err(|e| e.to_string())?;
    let mut nodes_map: HashMap<ContentHash, DagNode> =
        existing_nodes.into_iter().map(|n| (*n.hash(), n)).collect();

    // Build initial permissions from existing nodes
    let mut permissions_map: HashMap<ContentHash, ForumPermissions> = HashMap::new();
    if let Some(genesis) = nodes_map.values().find_map(|n| n.as_forum_genesis()) {
        let mut perms = ForumPermissions::from_genesis(genesis);
        // Replay existing mod actions to build current permission state
        let mut mod_actions: Vec<&DagNode> = nodes_map
            .values()
            .filter(|n| n.as_mod_action().is_some())
            .collect();
        mod_actions.sort_by_key(|n| n.created_at());
        for action_node in mod_actions {
            if let Some(action) = action_node.as_mod_action() {
                let _ = perms.apply_action(action);
            }
        }
        permissions_map.insert(*forum_hash, perms);
    }

    let mut stored = 0;
    let mut rejected = 0;

    for node in deserialized_nodes {
        // Build validation context with current state
        let ctx = ValidationContext::new(&nodes_map, &permissions_map, current_timestamp_millis());

        // Validate the node
        let validation_result = match validate_node(&node, &ctx) {
            Ok(result) => result,
            Err(e) => {
                warn!(
                    "Forum {}: validation error for node {}: {}",
                    forum_hash.short(),
                    node.hash().short(),
                    e
                );
                rejected += 1;
                continue;
            }
        };

        if !validation_result.is_valid {
            warn!(
                "Forum {}: rejected node {} - {:?}",
                forum_hash.short(),
                node.hash().short(),
                validation_result.errors
            );
            rejected += 1;
            continue;
        }

        // Store the validated node
        persistence
            .store_node_for_forum(forum_hash, &node)
            .map_err(|e| e.to_string())?;

        // If this is a forum genesis, store metadata and initialize permissions
        if let Some(genesis) = node.as_forum_genesis() {
            let metadata = ForumMetadata {
                name: genesis.name().to_string(),
                description: genesis.description().to_string(),
                created_at: genesis.created_at(),
                owner_identity: genesis.creator_identity().to_vec(),
            };
            persistence
                .store_forum_metadata(forum_hash, &metadata)
                .map_err(|e| e.to_string())?;

            // Initialize permissions from genesis
            permissions_map.insert(*forum_hash, ForumPermissions::from_genesis(genesis));
        }

        // Update permissions if this is a mod action
        if let Some(action) = node.as_mod_action() {
            if let Some(perms) = permissions_map.get_mut(forum_hash) {
                let _ = perms.apply_action(action);
            }
        }

        // Add to our validation context for subsequent nodes
        nodes_map.insert(*node.hash(), node);
        stored += 1;
    }

    if rejected > 0 {
        info!(
            "Forum {}: rejected {} invalid nodes during sync",
            forum_hash.short(),
            rejected
        );
    }

    // Step 6: Update local heads - ONLY with hashes that exist locally
    // Security: Don't blindly trust server_heads from relay
    let verified_heads: HashSet<ContentHash> = sync_result
        .parse_server_heads()
        .into_iter()
        .filter(|h| nodes_map.contains_key(h))
        .collect();

    if !verified_heads.is_empty() {
        persistence
            .set_heads(forum_hash, &verified_heads)
            .map_err(|e| e.to_string())?;
    }

    info!(
        "Forum {}: synced {} nodes successfully (depth {})",
        forum_hash.short(),
        stored,
        depth
    );

    // If there are more nodes, sync again with incremented depth
    if sync_result.has_more {
        info!(
            "Forum {}: more nodes available, continuing sync",
            forum_hash.short()
        );
        let additional =
            Box::pin(sync_forum_with_depth(persistence, forum_hash, depth + 1)).await?;
        return Ok(stored + additional);
    }

    Ok(stored)
}

/// Checks if a forum exists locally (has been synced before).
pub fn forum_exists_locally(
    persistence: &SharedForumPersistence,
    forum_hash: &ContentHash,
) -> bool {
    persistence.forum_exists(forum_hash).unwrap_or(false)
}

/// API response for forum creation
#[derive(Debug, Deserialize)]
struct ForumApiResponse {
    success: bool,
    #[allow(dead_code)]
    message: Option<String>,
    error: Option<String>,
    #[allow(dead_code)]
    hash: Option<String>,
}

/// Form for creating a forum
#[derive(Debug, Deserialize)]
pub struct CreateForumForm {
    name: String,
    description: String,
    signing_key: String,
    password: Option<String>,
}

/// Form for creating a board
#[derive(Debug, Deserialize)]
pub struct CreateBoardForm {
    name: String,
    description: String,
    tags: String,
    signing_key: String,
    password: Option<String>,
}

/// Form for creating a thread
#[derive(Debug, Deserialize)]
pub struct CreateThreadForm {
    title: String,
    body: String,
    signing_key: String,
    password: Option<String>,
}

/// Form for posting a reply
#[derive(Debug, Deserialize)]
pub struct PostReplyForm {
    body: String,
    quote_hash: Option<String>,
    signing_key: String,
    password: Option<String>,
}

/// Form for adding a moderator
#[derive(Debug, Deserialize)]
pub struct AddModeratorForm {
    target_fingerprint: String,
    signing_key: String,
    password: Option<String>,
}

/// Form for removing a moderator
#[derive(Debug, Deserialize)]
pub struct RemoveModeratorForm {
    target_fingerprint: String,
    signing_key: String,
    password: Option<String>,
}

/// Form for adding a board moderator
#[derive(Debug, Deserialize)]
pub struct AddBoardModeratorForm {
    target_fingerprint: String,
    signing_key: String,
    password: Option<String>,
}

/// Form for removing a board moderator
#[derive(Debug, Deserialize)]
pub struct RemoveBoardModeratorForm {
    target_fingerprint: String,
    signing_key: String,
    password: Option<String>,
}

/// Form for hiding a thread
#[derive(Debug, Deserialize)]
pub struct HideThreadForm {
    signing_key: String,
    password: Option<String>,
}

/// Form for moving a thread to a different board
#[derive(Debug, Deserialize)]
pub struct MoveThreadForm {
    destination_board: String,
    signing_key: String,
    password: Option<String>,
}

/// Form for hiding a post
#[derive(Debug, Deserialize)]
pub struct HidePostForm {
    post_hash: String,
    signing_key: String,
    password: Option<String>,
}

/// Form for hiding a board
#[derive(Debug, Deserialize)]
pub struct HideBoardForm {
    signing_key: String,
    password: Option<String>,
}

/// Form for editing forum metadata
#[derive(Debug, Deserialize)]
pub struct EditForumForm {
    new_name: Option<String>,
    new_description: Option<String>,
    signing_key: String,
    password: Option<String>,
}

/// Form for editing board metadata
#[derive(Debug, Deserialize)]
pub struct EditBoardForm {
    new_name: Option<String>,
    new_description: Option<String>,
    signing_key: String,
    password: Option<String>,
}

/// Form for removing a forum from the relay
#[derive(Debug, Deserialize)]
pub struct RemoveForumForm {
    _confirm: Option<String>, // Just for form submission, not used
}

/// Form for joining a forum by hash
#[derive(Debug, Deserialize)]
pub struct JoinForumForm {
    forum_hash: String,
}

/// Helper to format timestamp for display
fn format_timestamp(ts: u64) -> String {
    use chrono::{TimeZone, Utc};
    Utc.timestamp_millis_opt(ts as i64)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

/// Get signing keys from keyring (ML-DSA-87 keys only)
fn get_signing_keys() -> Vec<SigningKeyInfo> {
    let keyring = match create_keyring_manager() {
        Ok(km) => km,
        Err(_) => return Vec::new(),
    };

    keyring
        .list_all_keys()
        .into_iter()
        .filter_map(|(key_id, entry, has_private)| {
            // Only include keys that can verify signatures (ML-DSA-87) and have a private key
            if has_private && entry.public_key.can_verify() {
                let fingerprint = entry.public_key.fingerprint();
                let fingerprint_hex = hex::encode(&fingerprint[..8]);
                Some(SigningKeyInfo {
                    key_id: format!("{:016X}", key_id),
                    user_id: entry
                        .user_ids
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "Unknown".to_string()),
                    fingerprint: fingerprint_hex,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Signing materials - public key and private key for signing forum content
struct SigningMaterials {
    public_key: pqpgp::crypto::PublicKey,
    private_key: pqpgp::crypto::PrivateKey,
}

/// Get signing materials from the keyring
fn get_signing_materials(key_id: &str) -> Result<SigningMaterials, String> {
    let keyring = create_keyring_manager().map_err(|e| format!("Failed to load keyring: {}", e))?;

    // Parse key ID from hex
    let key_id_num = u64::from_str_radix(key_id, 16)
        .map_err(|_| format!("Invalid key ID format: {}", key_id))?;

    // Get key entry
    let entries = keyring.list_all_keys();
    let (_id, entry, has_private) = entries
        .iter()
        .find(|(id, _, _)| *id == key_id_num)
        .ok_or_else(|| "Key not found".to_string())?;

    if !has_private {
        return Err("Key has no private key".to_string());
    }

    // Get public key
    let public_key = entry.public_key.clone();

    // Get private key
    let private_key = keyring
        .get_private_key(key_id_num)
        .ok_or_else(|| "Private key not found".to_string())?;

    Ok(SigningMaterials {
        public_key,
        private_key: private_key.clone(),
    })
}

/// Forum list page handler
pub async fn forum_list_page(
    State(app_state): State<AppState>,
    session: Session,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Html<String>, StatusCode> {
    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .unwrap_or_default();

    let cursor = pagination.get_cursor();
    let limit = pagination.get_limit();

    // Get locally synced forums with pagination (ForumSummary includes board_count for O(1) access)
    let paginated_result = app_state
        .forum_persistence
        .list_forums_paginated(cursor.as_ref(), limit)
        .unwrap_or_else(|e| {
            warn!("Failed to list local forums: {}", e);
            pqpgp::forum::PaginatedResult {
                items: Vec::new(),
                next_cursor: None,
                total_count: Some(0),
            }
        });

    let has_more = paginated_result.next_cursor.is_some();
    let total_forums = paginated_result.total_count.unwrap_or(0);

    // ForumSummary already includes effective name/description and board_count
    let forums: Vec<ForumDisplayInfo> = paginated_result
        .items
        .iter()
        .map(|summary| ForumDisplayInfo {
            hash: summary.hash.to_hex(),
            name: summary.effective_name.clone(),
            description: summary.effective_description.clone(),
            created_at_display: format_timestamp(summary.metadata.created_at),
            board_count: summary.board_count,
        })
        .collect();

    let next_cursor = paginated_result.next_cursor.as_ref().map(|c| c.encode());
    let prev_cursor = pagination.prev.clone();
    let current_cursor = pagination.cursor.clone();

    let template = ForumListTemplate {
        active_page: "forum".to_string(),
        csrf_token,
        forums,
        signing_keys: get_signing_keys(),
        result: None,
        error: None,
        has_result: false,
        has_error: false,
        prev_cursor,
        next_cursor,
        current_cursor,
        total_forums,
        has_more,
    };

    Ok(Html(template.to_string()))
}

/// Create forum handler
pub async fn create_forum_handler(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<CreateForumForm>>,
) -> impl IntoResponse {
    // Validate CSRF
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for forum creation");
        return Redirect::to("/forum").into_response();
    }

    let data = form.data;

    // Validate input sizes (DoS prevention)
    if data.name.len() > MAX_NAME_SIZE {
        warn!("Forum name too large: {} bytes", data.name.len());
        return Redirect::to("/forum").into_response();
    }
    if data.description.len() > MAX_DESCRIPTION_SIZE {
        warn!(
            "Forum description too large: {} bytes",
            data.description.len()
        );
        return Redirect::to("/forum").into_response();
    }
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to("/forum").into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to("/forum").into_response();
    }

    // Get signing materials
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to("/forum").into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Create forum genesis
    let genesis = match ForumGenesis::create(
        data.name.clone(),
        data.description.clone(),
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
    ) {
        Ok(g) => g,
        Err(e) => {
            error!("Failed to create forum: {}", e);
            return Redirect::to("/forum").into_response();
        }
    };

    let forum_hash = *genesis.hash();

    // Store locally first
    let metadata = ForumMetadata {
        name: genesis.name().to_string(),
        description: genesis.description().to_string(),
        created_at: genesis.created_at(),
        owner_identity: genesis.creator_identity().to_vec(),
    };

    if let Err(e) = app_state
        .forum_persistence
        .store_forum_metadata(&forum_hash, &metadata)
    {
        error!("Failed to store forum metadata locally: {}", e);
        return Redirect::to("/forum").into_response();
    }

    let node = DagNode::from(genesis);
    if let Err(e) = app_state
        .forum_persistence
        .store_node_for_forum(&forum_hash, &node)
    {
        error!("Failed to store forum node locally: {}", e);
        return Redirect::to("/forum").into_response();
    }

    // Serialize and encode for relay
    let node_bytes = match node.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            error!("Serialization error: {}", e);
            return Redirect::to("/forum").into_response();
        }
    };

    let genesis_data =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &node_bytes);

    // Send to relay
    let client = Client::new();
    let relay_url = get_relay_url();

    #[derive(Serialize)]
    struct CreateRequest {
        genesis_data: String,
    }

    match client
        .post(format!("{}/forums", relay_url))
        .json(&CreateRequest { genesis_data })
        .send()
        .await
    {
        Ok(resp) => match resp.json::<ForumApiResponse>().await {
            Ok(api_resp) => {
                if api_resp.success {
                    info!("Created forum: {}", data.name);
                } else {
                    error!(
                        "Forum creation failed: {}",
                        api_resp.error.unwrap_or_default()
                    );
                }
            }
            Err(e) => {
                error!("API error: {}", e);
            }
        },
        Err(e) => {
            error!("Connection error: {}", e);
        }
    }

    Redirect::to("/forum").into_response()
}

/// Forum view page handler
pub async fn forum_view_page(
    State(app_state): State<AppState>,
    session: Session,
    Path(forum_hash): Path<String>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Html<String>, StatusCode> {
    // Forum data is synced by background polling task - read from local storage

    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .unwrap_or_default();

    // Parse forum hash
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            return Ok(Html("<h1>Invalid forum hash</h1>".to_string()));
        }
    };

    // Load forum metadata from local storage
    let metadata = match app_state
        .forum_persistence
        .load_forum_metadata(&forum_content_hash)
    {
        Ok(Some(m)) => m,
        Ok(None) => {
            return Ok(Html(
                "<h1>Forum not found locally. Try adding it first.</h1>".to_string(),
            ));
        }
        Err(e) => {
            error!("Failed to load forum metadata: {}", e);
            return Ok(Html("<h1>Error loading forum</h1>".to_string()));
        }
    };

    // Load boards with pagination
    let hidden_boards = app_state
        .forum_persistence
        .get_hidden_boards(&forum_content_hash)
        .unwrap_or_default();

    let cursor = pagination.get_cursor();
    let limit = pagination.get_limit();

    let paginated_result = app_state
        .forum_persistence
        .get_boards_paginated(&forum_content_hash, cursor.as_ref(), limit + 1) // +1 to check for more
        .unwrap_or_else(|_| pqpgp::forum::PaginatedResult {
            items: Vec::new(),
            next_cursor: None,
            total_count: Some(0),
        });

    // Filter hidden boards and apply limit
    let filtered_boards: Vec<_> = paginated_result
        .items
        .into_iter()
        .filter(|b| !hidden_boards.contains(b.board.hash()))
        .collect();

    let has_more = filtered_boards.len() > limit;
    let boards: Vec<BoardDisplayInfo> = filtered_boards
        .iter()
        .take(limit)
        .map(build_board_display_info_from_summary)
        .collect();

    // Compute next cursor from the last item
    let next_cursor = if has_more {
        paginated_result.next_cursor.as_ref().map(|c| c.encode())
    } else {
        None
    };

    let total_boards = paginated_result.total_count.unwrap_or(0);

    // Load moderators from local storage
    let (mod_fingerprints, owner_fingerprint) = app_state
        .forum_persistence
        .get_forum_moderators(&forum_content_hash)
        .unwrap_or_default();

    let moderators: Vec<ModeratorDisplayInfo> = mod_fingerprints
        .iter()
        .map(|fp| ModeratorDisplayInfo {
            identity_fingerprint: fp.clone(),
            is_owner: Some(fp) == owner_fingerprint.as_ref(),
        })
        .collect();

    // Get user's signing keys to check if they're an owner or moderator
    let signing_keys = get_signing_keys();
    let user_fingerprints: Vec<&str> = signing_keys
        .iter()
        .map(|k| k.fingerprint.as_str())
        .collect();

    // Check if user is owner (exact match required for security)
    let is_owner = owner_fingerprint
        .as_ref()
        .map(|owner_fp| user_fingerprints.iter().any(|fp| *fp == owner_fp))
        .unwrap_or(false);

    // Check if user is a moderator (owner or regular mod) - exact match required
    let is_moderator = mod_fingerprints
        .iter()
        .any(|mod_fp| user_fingerprints.iter().any(|fp| *fp == mod_fp));

    // Get effective forum name/description (after applying any edits)
    let (forum_name, forum_description) = get_effective_forum_info(
        &app_state.forum_persistence,
        &forum_content_hash,
        &metadata.name,
        &metadata.description,
    );

    // Pagination: prev_cursor comes from query param, current_cursor is what we used
    let prev_cursor = pagination.prev.clone();
    let current_cursor = pagination.cursor.clone();

    let template = ForumViewTemplate {
        active_page: "forum".to_string(),
        csrf_token,
        forum_hash: forum_hash.clone(),
        forum_hash_short: forum_hash.chars().take(16).collect(),
        forum_name,
        forum_description,
        created_at_display: format_timestamp(metadata.created_at),
        boards,
        signing_keys,
        moderators,
        is_owner,
        is_moderator,
        result: None,
        error: None,
        has_result: false,
        has_error: false,
        prev_cursor,
        next_cursor,
        current_cursor,
        total_boards,
        has_more,
    };

    Ok(Html(template.to_string()))
}

/// Create board handler
pub async fn create_board_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path(forum_hash): Path<String>,
    Form(form): Form<CsrfProtectedForm<CreateBoardForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for board creation");
        return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
    }

    let data = form.data;

    // Validate input sizes (DoS prevention)
    if data.name.len() > MAX_NAME_SIZE {
        warn!("Board name too large: {} bytes", data.name.len());
        return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
    }
    if data.description.len() > MAX_DESCRIPTION_SIZE {
        warn!(
            "Board description too large: {} bytes",
            data.description.len()
        );
        return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
    }
    if data.tags.len() > MAX_TAGS_INPUT_SIZE {
        warn!("Tags input too large: {} bytes", data.tags.len());
        return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
    }
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
    }

    // Parse forum hash
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid forum hash: {}", forum_hash);
            return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
        }
    };

    // Get signing materials
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Parse tags
    let tags: Vec<String> = data
        .tags
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Create board
    let board = match BoardGenesis::create(
        forum_content_hash,
        data.name.clone(),
        data.description.clone(),
        tags,
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
    ) {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to create board: {}", e);
            return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
        }
    };

    // Store locally and submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(board),
    )
    .await;

    Redirect::to(&format!("/forum/{}", forum_hash)).into_response()
}

/// Board view page handler
pub async fn board_view_page(
    State(app_state): State<AppState>,
    session: Session,
    Path((forum_hash, board_hash)): Path<(String, String)>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Html<String>, StatusCode> {
    // Forum data is synced by background polling task - read from local storage

    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .unwrap_or_default();

    // Parse hashes
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => return Ok(Html("<h1>Invalid forum hash</h1>".to_string())),
    };
    let board_content_hash = match ContentHash::from_hex(&board_hash) {
        Ok(h) => h,
        Err(_) => return Ok(Html("<h1>Invalid board hash</h1>".to_string())),
    };

    // Load forum metadata from local storage
    let forum_metadata = match app_state
        .forum_persistence
        .load_forum_metadata(&forum_content_hash)
    {
        Ok(Some(m)) => m,
        Ok(None) => return Ok(Html("<h1>Forum not found locally</h1>".to_string())),
        Err(e) => {
            error!("Failed to load forum metadata: {}", e);
            return Ok(Html("<h1>Error loading forum</h1>".to_string()));
        }
    };

    // Load board from local storage
    let board = match app_state
        .forum_persistence
        .get_board(&forum_content_hash, &board_content_hash)
    {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(Html("<h1>Board not found locally</h1>".to_string())),
        Err(e) => {
            error!("Failed to load board: {}", e);
            return Ok(Html("<h1>Error loading board</h1>".to_string()));
        }
    };

    // Load threads with pagination
    let hidden_threads = app_state
        .forum_persistence
        .get_hidden_threads(&forum_content_hash)
        .unwrap_or_default();

    let cursor = pagination.get_cursor();
    let limit = pagination.get_limit();

    let paginated_result = app_state
        .forum_persistence
        .get_threads_paginated(
            &forum_content_hash,
            &board_content_hash,
            cursor.as_ref(),
            limit + 1,
        )
        .unwrap_or_else(|_| pqpgp::forum::PaginatedResult {
            items: Vec::new(),
            next_cursor: None,
            total_count: Some(0),
        });

    // Filter hidden threads and apply limit
    let filtered_threads: Vec<_> = paginated_result
        .items
        .into_iter()
        .filter(|s| !hidden_threads.contains(s.thread.hash()))
        .collect();

    let has_more = filtered_threads.len() > limit;
    let threads: Vec<ThreadDisplayInfo> = filtered_threads
        .into_iter()
        .take(limit)
        .map(|summary| {
            let body_preview: String = summary.thread.body().chars().take(100).collect();
            ThreadDisplayInfo {
                hash: summary.thread.hash().to_hex(),
                title: summary.thread.title().to_string(),
                body_preview,
                author_short: fingerprint_from_identity(summary.thread.author_identity()),
                post_count: summary.post_count,
                created_at_display: format_timestamp(summary.thread.created_at()),
            }
        })
        .collect();

    let next_cursor = if has_more {
        paginated_result.next_cursor.as_ref().map(|c| c.encode())
    } else {
        None
    };

    let total_threads = paginated_result.total_count.unwrap_or(0);

    // Load forum moderators from local storage
    let (forum_mod_fingerprints, _owner_fingerprint) = app_state
        .forum_persistence
        .get_forum_moderators(&forum_content_hash)
        .unwrap_or_default();

    // Load board moderators from local storage
    let board_mod_fingerprints = app_state
        .forum_persistence
        .get_board_moderators(&forum_content_hash, &board_content_hash)
        .unwrap_or_default();

    let board_moderators: Vec<ModeratorDisplayInfo> = board_mod_fingerprints
        .iter()
        .map(|fp| ModeratorDisplayInfo {
            identity_fingerprint: fp.clone(),
            is_owner: false, // Board moderators are never owners
        })
        .collect();

    // Get user's signing keys to check if they're a forum moderator
    let signing_keys = get_signing_keys();
    let user_fingerprints: Vec<&str> = signing_keys
        .iter()
        .map(|k| k.fingerprint.as_str())
        .collect();

    // Check if user is a forum-level moderator (can manage board moderators) - exact match required
    let is_forum_moderator = forum_mod_fingerprints
        .iter()
        .any(|mod_fp| user_fingerprints.iter().any(|fp| *fp == mod_fp));

    // Get effective board name/description (after applying any edits)
    let (board_name, board_description) = app_state
        .forum_persistence
        .apply_board_edits(&forum_content_hash, &board)
        .unwrap_or_else(|_| Some((board.name().to_string(), board.description().to_string())))
        .unwrap_or_else(|| (board.name().to_string(), board.description().to_string()));

    // Get effective forum name (after applying any edits)
    let (forum_name, _) = get_effective_forum_info(
        &app_state.forum_persistence,
        &forum_content_hash,
        &forum_metadata.name,
        &forum_metadata.description,
    );

    // Pagination: prev_cursor comes from query param, current_cursor is what we used
    let prev_cursor = pagination.prev.clone();
    let current_cursor = pagination.cursor.clone();

    let template = BoardViewTemplate {
        active_page: "forum".to_string(),
        csrf_token,
        forum_hash: forum_hash.clone(),
        forum_name,
        board_hash: board_hash.clone(),
        board_name,
        board_description,
        board_tags: board.tags().to_vec(),
        threads,
        signing_keys,
        board_moderators,
        is_forum_moderator,
        result: None,
        error: None,
        has_result: false,
        has_error: false,
        prev_cursor,
        next_cursor,
        current_cursor,
        total_threads,
        has_more,
    };

    Ok(Html(template.to_string()))
}

/// Create thread handler
pub async fn create_thread_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path((forum_hash, board_hash)): Path<(String, String)>,
    Form(form): Form<CsrfProtectedForm<CreateThreadForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for thread creation");
        return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
            .into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}/board/{}", forum_hash, board_hash);

    // Validate input sizes (DoS prevention)
    if data.title.len() > MAX_THREAD_TITLE_SIZE {
        warn!("Thread title too large: {} bytes", data.title.len());
        return Redirect::to(&redirect_url).into_response();
    }
    if data.body.len() > MAX_THREAD_BODY_SIZE {
        warn!("Thread body too large: {} bytes", data.body.len());
        return Redirect::to(&redirect_url).into_response();
    }
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Parse board hash
    let board_content_hash = match ContentHash::from_hex(&board_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid board hash: {}", board_hash);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    // Get signing materials
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Create thread
    let thread = match ThreadRoot::create(
        board_content_hash,
        data.title.clone(),
        data.body.clone(),
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
    ) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to create thread: {}", e);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    let thread_hash = thread.hash().to_hex();

    // Store locally and submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(thread),
    )
    .await;

    Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash)).into_response()
}

/// Thread view page handler
pub async fn thread_view_page(
    State(app_state): State<AppState>,
    session: Session,
    Path((forum_hash, thread_hash)): Path<(String, String)>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Html<String>, StatusCode> {
    // Forum data is synced by background polling task - read from local storage

    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .unwrap_or_default();

    // Parse hashes
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => return Ok(Html("<h1>Invalid forum hash</h1>".to_string())),
    };
    let thread_content_hash = match ContentHash::from_hex(&thread_hash) {
        Ok(h) => h,
        Err(_) => return Ok(Html("<h1>Invalid thread hash</h1>".to_string())),
    };

    // Load forum metadata from local storage
    let forum_metadata = match app_state
        .forum_persistence
        .load_forum_metadata(&forum_content_hash)
    {
        Ok(Some(m)) => m,
        Ok(None) => return Ok(Html("<h1>Forum not found locally</h1>".to_string())),
        Err(e) => {
            error!("Failed to load forum metadata: {}", e);
            return Ok(Html("<h1>Error loading forum</h1>".to_string()));
        }
    };

    // Load thread from local storage
    let thread = match app_state
        .forum_persistence
        .get_thread(&forum_content_hash, &thread_content_hash)
    {
        Ok(Some(t)) => t,
        Ok(None) => return Ok(Html("<h1>Thread not found locally</h1>".to_string())),
        Err(e) => {
            error!("Failed to load thread: {}", e);
            return Ok(Html("<h1>Error loading thread</h1>".to_string()));
        }
    };

    // Load the board for this thread
    let board = match app_state
        .forum_persistence
        .get_board(&forum_content_hash, thread.board_hash())
    {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(Html("<h1>Board not found locally</h1>".to_string())),
        Err(e) => {
            error!("Failed to load board: {}", e);
            return Ok(Html("<h1>Error loading board</h1>".to_string()));
        }
    };

    // Load posts with pagination (oldest first for chronological reading)
    let hidden_posts = app_state
        .forum_persistence
        .get_hidden_posts(&forum_content_hash)
        .unwrap_or_default();

    let cursor = pagination.get_cursor();
    let limit = pagination.get_limit();

    let paginated_result = app_state
        .forum_persistence
        .get_posts_paginated(
            &forum_content_hash,
            &thread_content_hash,
            cursor.as_ref(),
            limit + 1,
        )
        .unwrap_or_else(|_| pqpgp::forum::PaginatedResult {
            items: Vec::new(),
            next_cursor: None,
            total_count: Some(0),
        });

    // Filter hidden posts and apply limit
    // PostSummary already includes resolved quote previews (batch-loaded)
    let filtered_posts: Vec<_> = paginated_result
        .items
        .into_iter()
        .filter(|p| !hidden_posts.contains(p.post.hash()))
        .collect();

    let has_more = filtered_posts.len() > limit;

    // Build post display info (quote previews already resolved in PostSummary)
    let post_displays: Vec<PostDisplayInfo> = filtered_posts
        .into_iter()
        .take(limit)
        .map(|p| PostDisplayInfo {
            hash: p.post.hash().to_hex(),
            body: p.post.body().to_string(),
            author_short: fingerprint_from_identity(p.post.author_identity()),
            quote_body: p.quote_preview,
            created_at_display: format_timestamp(p.post.created_at()),
        })
        .collect();

    let next_cursor = if has_more {
        paginated_result.next_cursor.as_ref().map(|c| c.encode())
    } else {
        None
    };

    let total_posts = paginated_result.total_count.unwrap_or(0);

    // Load forum moderators from local storage
    let (forum_mod_fingerprints, _owner_fingerprint) = app_state
        .forum_persistence
        .get_forum_moderators(&forum_content_hash)
        .unwrap_or_default();

    // Get user's signing keys to check if they're a moderator
    let signing_keys = get_signing_keys();
    let user_fingerprints: Vec<&str> = signing_keys
        .iter()
        .map(|k| k.fingerprint.as_str())
        .collect();

    // Check if user is a moderator (owner or regular mod) - exact match required
    let is_moderator = forum_mod_fingerprints
        .iter()
        .any(|mod_fp| user_fingerprints.iter().any(|fp| *fp == mod_fp));

    // Load all boards for the move thread dropdown
    let all_boards_data = app_state
        .forum_persistence
        .get_boards(&forum_content_hash)
        .unwrap_or_default();

    let hidden_boards = app_state
        .forum_persistence
        .get_hidden_boards(&forum_content_hash)
        .unwrap_or_default();

    let all_boards: Vec<BoardDisplayInfo> = all_boards_data
        .into_iter()
        .filter(|b| !hidden_boards.contains(b.hash()))
        .map(|b| build_board_display_info(&app_state.forum_persistence, &forum_content_hash, &b))
        .collect();

    // Get effective board name (after applying any edits)
    let (board_name, _) = app_state
        .forum_persistence
        .apply_board_edits(&forum_content_hash, &board)
        .unwrap_or_else(|_| Some((board.name().to_string(), board.description().to_string())))
        .unwrap_or_else(|| (board.name().to_string(), board.description().to_string()));

    // Get effective forum name (after applying any edits)
    let (forum_name, _) = get_effective_forum_info(
        &app_state.forum_persistence,
        &forum_content_hash,
        &forum_metadata.name,
        &forum_metadata.description,
    );

    // Pagination: prev_cursor comes from query param, current_cursor is what we used
    let prev_cursor = pagination.prev.clone();
    let current_cursor = pagination.cursor.clone();

    let template = ThreadViewTemplate {
        active_page: "forum".to_string(),
        csrf_token,
        forum_hash: forum_hash.clone(),
        forum_name,
        board_hash: board.hash().to_hex(),
        board_name,
        thread_hash: thread_hash.clone(),
        thread_title: thread.title().to_string(),
        thread_body: thread.body().to_string(),
        thread_author_short: fingerprint_from_identity(thread.author_identity()),
        thread_created_at_display: format_timestamp(thread.created_at()),
        posts: post_displays,
        signing_keys,
        is_moderator,
        all_boards,
        result: None,
        error: None,
        has_result: false,
        has_error: false,
        prev_cursor,
        next_cursor,
        current_cursor,
        total_posts,
        has_more,
    };

    Ok(Html(template.to_string()))
}

/// Post reply handler
pub async fn post_reply_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path((forum_hash, thread_hash)): Path<(String, String)>,
    Form(form): Form<CsrfProtectedForm<PostReplyForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for post reply");
        return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
            .into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}/thread/{}", forum_hash, thread_hash);

    // Validate input sizes (DoS prevention)
    if data.body.len() > MAX_POST_BODY_SIZE {
        warn!("Post body too large: {} bytes", data.body.len());
        return Redirect::to(&redirect_url).into_response();
    }
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .quote_hash
        .as_ref()
        .is_some_and(|h| h.len() > MAX_HASH_INPUT_SIZE)
    {
        warn!("Quote hash too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Parse thread hash
    let thread_content_hash = match ContentHash::from_hex(&thread_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid thread hash: {}", thread_hash);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    // Get signing materials
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Parse quote hash if provided
    let quote_hash = data
        .quote_hash
        .filter(|h| !h.is_empty())
        .and_then(|h| ContentHash::from_hex(&h).ok());

    // Create post
    let post = match Post::create(
        thread_content_hash,
        vec![], // No direct parent posts for simplicity
        data.body.clone(),
        quote_hash,
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
    ) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to create post: {}", e);
            return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
                .into_response();
        }
    };

    // Store locally and submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(post),
    )
    .await;

    Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash)).into_response()
}

/// Helper to get current DAG heads from the relay for causal ordering
async fn get_dag_heads(forum_hash: &str) -> Vec<ContentHash> {
    let http_client = Client::new();
    let rpc_client = create_rpc_client();

    let forum_content_hash = match ContentHash::from_hex(forum_hash) {
        Ok(h) => h,
        Err(e) => {
            error!("Invalid forum hash for heads fetch: {}", e);
            return vec![];
        }
    };

    // Use sync endpoint with empty known_heads to get server's current heads
    let request = rpc_client.build_sync_request(&forum_content_hash, &[], None);

    match send_rpc_request(&http_client, &rpc_client, &request).await {
        Ok(rpc_response) => match rpc_client.parse_sync_response(rpc_response) {
            Ok(sync_result) => {
                let heads = sync_result.parse_server_heads();
                info!("Got {} DAG heads for forum {}", heads.len(), forum_hash);
                heads
            }
            Err(e) => {
                error!("Failed to parse sync response: {}", e);
                vec![]
            }
        },
        Err(e) => {
            error!("Failed to fetch DAG heads: {}", e);
            vec![]
        }
    }
}

/// Submits a node to the relay and stores it locally if validation passes.
///
/// The node is validated locally first using the same validation logic as the relay.
/// Only if validation passes do we store locally and submit to relay. This prevents
/// storing invalid nodes (e.g., mod actions without sufficient permissions).
async fn submit_node(persistence: &SharedForumPersistence, forum_hash: &str, node: DagNode) {
    let forum_content_hash = match ContentHash::from_hex(forum_hash) {
        Ok(h) => h,
        Err(e) => {
            error!("Invalid forum hash: {}", e);
            return;
        }
    };

    // Step 1: Validate locally first using the same logic as the relay
    let existing_nodes = match persistence.load_forum_nodes(&forum_content_hash) {
        Ok(nodes) => nodes,
        Err(e) => {
            error!("Failed to load existing nodes for validation: {}", e);
            return;
        }
    };

    let nodes_map: HashMap<ContentHash, DagNode> =
        existing_nodes.into_iter().map(|n| (*n.hash(), n)).collect();

    // Build permissions from existing nodes
    let mut permissions_map: HashMap<ContentHash, ForumPermissions> = HashMap::new();
    if let Some(genesis) = nodes_map.values().find_map(|n| n.as_forum_genesis()) {
        let mut perms = ForumPermissions::from_genesis(genesis);
        let mut mod_actions: Vec<&DagNode> = nodes_map
            .values()
            .filter(|n| n.as_mod_action().is_some())
            .collect();
        mod_actions.sort_by_key(|n| n.created_at());
        for action_node in mod_actions {
            if let Some(action) = action_node.as_mod_action() {
                let _ = perms.apply_action(action);
            }
        }
        permissions_map.insert(forum_content_hash, perms);
    }

    let ctx = ValidationContext::new(&nodes_map, &permissions_map, current_timestamp_millis());

    match validate_node(&node, &ctx) {
        Ok(result) if !result.is_valid => {
            error!(
                "Node {} failed local validation: {:?}",
                node.hash().short(),
                result.errors
            );
            return;
        }
        Err(e) => {
            error!("Node {} validation error: {}", node.hash().short(), e);
            return;
        }
        _ => {}
    }

    // Step 2: Store locally (validation passed)
    if let Err(e) = persistence.store_node_for_forum(&forum_content_hash, &node) {
        warn!("Failed to store node locally: {}", e);
    } else {
        // Update local heads
        if let Err(e) = persistence.update_heads_for_node(&forum_content_hash, &node) {
            warn!("Failed to update local heads: {}", e);
        }
    }

    // Step 3: Submit to relay (best effort - relay might be unavailable)
    let http_client = Client::new();
    let rpc_client = create_rpc_client();

    let request = match rpc_client.build_submit_request(&forum_content_hash, &node) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create submit request: {}", e);
            return;
        }
    };

    match send_rpc_request(&http_client, &rpc_client, &request).await {
        Ok(rpc_response) => match rpc_client.parse_submit_response(rpc_response) {
            Ok(result) => {
                if result.accepted {
                    info!(
                        "Node {} submitted to relay successfully",
                        node.hash().short()
                    );
                } else {
                    warn!("Node {} submission to relay rejected", node.hash().short());
                }
            }
            Err(e) => {
                warn!(
                    "Node {} submission to relay failed: {}",
                    node.hash().short(),
                    e
                );
            }
        },
        Err(e) => {
            warn!(
                "Failed to submit node {} to relay: {}",
                node.hash().short(),
                e
            );
        }
    }
}

/// Add moderator handler
pub async fn add_moderator_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path(forum_hash): Path<String>,
    Form(form): Form<CsrfProtectedForm<AddModeratorForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for add moderator");
        return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}", forum_hash);

    // Validate input sizes (DoS prevention)
    if data.target_fingerprint.len() > MAX_HASH_INPUT_SIZE {
        warn!("Target fingerprint too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Parse forum hash
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid forum hash: {}", forum_hash);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    // Server-side permission check: AddModerator requires owner
    let signer_fingerprint = match get_signing_key_fingerprint(&data.signing_key) {
        Some(fp) => fp,
        None => {
            warn!("Invalid signing key for add moderator");
            return Redirect::to(&redirect_url).into_response();
        }
    };
    if !check_forum_permission(
        &app_state.forum_persistence,
        &forum_content_hash,
        &signer_fingerprint,
        PermissionLevel::OwnerOnly,
    ) {
        warn!(
            "Unauthorized add moderator attempt by {} on forum {}",
            signer_fingerprint, forum_hash
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Get signing materials (owner's key)
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    // Get target user's public key from fingerprint
    let target_public_key = match get_public_key_by_fingerprint(&data.target_fingerprint) {
        Some(pk) => pk,
        None => {
            error!(
                "Target public key not found for fingerprint: {}",
                data.target_fingerprint
            );
            return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Get current DAG heads for causal ordering
    let parent_hashes = get_dag_heads(&forum_hash).await;

    // Create mod action node
    let mod_action = match ModActionNode::create(
        forum_content_hash,
        ModAction::AddModerator,
        &target_public_key,
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
        parent_hashes,
    ) {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to create mod action: {}", e);
            return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
        }
    };

    // Submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(mod_action),
    )
    .await;

    info!("Added moderator: {}", data.target_fingerprint);
    Redirect::to(&format!("/forum/{}", forum_hash)).into_response()
}

/// Remove moderator handler
pub async fn remove_moderator_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path(forum_hash): Path<String>,
    Form(form): Form<CsrfProtectedForm<RemoveModeratorForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for remove moderator");
        return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}", forum_hash);

    // Validate input sizes (DoS prevention)
    if data.target_fingerprint.len() > MAX_HASH_INPUT_SIZE {
        warn!("Target fingerprint too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Parse forum hash
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid forum hash: {}", forum_hash);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    // Server-side permission check: RemoveModerator requires owner
    let signer_fingerprint = match get_signing_key_fingerprint(&data.signing_key) {
        Some(fp) => fp,
        None => {
            warn!("Invalid signing key for remove moderator");
            return Redirect::to(&redirect_url).into_response();
        }
    };
    if !check_forum_permission(
        &app_state.forum_persistence,
        &forum_content_hash,
        &signer_fingerprint,
        PermissionLevel::OwnerOnly,
    ) {
        warn!(
            "Unauthorized remove moderator attempt by {} on forum {}",
            signer_fingerprint, forum_hash
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Get signing materials (owner's key)
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    // Get target user's public key from fingerprint
    let target_public_key = match get_public_key_by_fingerprint(&data.target_fingerprint) {
        Some(pk) => pk,
        None => {
            error!(
                "Target public key not found for fingerprint: {}",
                data.target_fingerprint
            );
            return Redirect::to(&redirect_url).into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Get current DAG heads for causal ordering
    let parent_hashes = get_dag_heads(&forum_hash).await;

    // Create mod action node
    let mod_action = match ModActionNode::create(
        forum_content_hash,
        ModAction::RemoveModerator,
        &target_public_key,
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
        parent_hashes,
    ) {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to create mod action: {}", e);
            return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
        }
    };

    // Submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(mod_action),
    )
    .await;

    info!("Removed moderator: {}", data.target_fingerprint);
    Redirect::to(&format!("/forum/{}", forum_hash)).into_response()
}

/// Get public key by fingerprint (searches keyring for exact match).
///
/// Requires exact match on the first 16 hex characters (8 bytes) of the fingerprint
/// for security - prefix matching could allow impersonation attacks.
fn get_public_key_by_fingerprint(fingerprint: &str) -> Option<pqpgp::crypto::PublicKey> {
    let keyring = create_keyring_manager().ok()?;
    let entries = keyring.list_all_keys();

    for (_, entry, _) in entries {
        let fp = entry.public_key.fingerprint();
        let fp_hex = hex::encode(&fp[..8]);
        // Require exact match for security
        if fp_hex == fingerprint {
            return Some(entry.public_key.clone());
        }
    }
    None
}

/// Add board moderator handler
pub async fn add_board_moderator_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path((forum_hash, board_hash)): Path<(String, String)>,
    Form(form): Form<CsrfProtectedForm<AddBoardModeratorForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for add board moderator");
        return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
            .into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}/board/{}", forum_hash, board_hash);

    // Validate input sizes (DoS prevention)
    if data.target_fingerprint.len() > MAX_HASH_INPUT_SIZE {
        warn!("Target fingerprint too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Parse hashes
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid forum hash: {}", forum_hash);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    let board_content_hash = match ContentHash::from_hex(&board_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid board hash: {}", board_hash);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Server-side permission check: AddBoardModerator requires forum moderator
    let signer_fingerprint = match get_signing_key_fingerprint(&data.signing_key) {
        Some(fp) => fp,
        None => {
            warn!("Invalid signing key for add board moderator");
            return Redirect::to(&redirect_url).into_response();
        }
    };
    if !check_forum_permission(
        &app_state.forum_persistence,
        &forum_content_hash,
        &signer_fingerprint,
        PermissionLevel::ForumModerator,
    ) {
        warn!(
            "Unauthorized add board moderator attempt by {} on board {}",
            signer_fingerprint, board_hash
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Get signing materials (forum moderator's key)
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Get target user's public key from fingerprint
    let target_public_key = match get_public_key_by_fingerprint(&data.target_fingerprint) {
        Some(pk) => pk,
        None => {
            error!(
                "Target public key not found for fingerprint: {}",
                data.target_fingerprint
            );
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Get current DAG heads for causal ordering
    let parent_hashes = get_dag_heads(&forum_hash).await;

    // Create board mod action node
    let mod_action = match ModActionNode::create_board_action(
        forum_content_hash,
        board_content_hash,
        ModAction::AddBoardModerator,
        &target_public_key,
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
        parent_hashes,
    ) {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to create board mod action: {}", e);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(mod_action),
    )
    .await;

    info!(
        "Added board moderator: {} to board {}",
        data.target_fingerprint, board_hash
    );
    Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash)).into_response()
}

/// Remove board moderator handler
pub async fn remove_board_moderator_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path((forum_hash, board_hash)): Path<(String, String)>,
    Form(form): Form<CsrfProtectedForm<RemoveBoardModeratorForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for remove board moderator");
        return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
            .into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}/board/{}", forum_hash, board_hash);

    // Validate input sizes (DoS prevention)
    if data.target_fingerprint.len() > MAX_HASH_INPUT_SIZE {
        warn!("Target fingerprint too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Parse hashes
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid forum hash: {}", forum_hash);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    let board_content_hash = match ContentHash::from_hex(&board_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid board hash: {}", board_hash);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Server-side permission check: RemoveBoardModerator requires forum moderator
    let signer_fingerprint = match get_signing_key_fingerprint(&data.signing_key) {
        Some(fp) => fp,
        None => {
            warn!("Invalid signing key for remove board moderator");
            return Redirect::to(&redirect_url).into_response();
        }
    };
    if !check_forum_permission(
        &app_state.forum_persistence,
        &forum_content_hash,
        &signer_fingerprint,
        PermissionLevel::ForumModerator,
    ) {
        warn!(
            "Unauthorized remove board moderator attempt by {} on board {}",
            signer_fingerprint, board_hash
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Get signing materials (forum moderator's key)
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Get target user's public key from fingerprint
    let target_public_key = match get_public_key_by_fingerprint(&data.target_fingerprint) {
        Some(pk) => pk,
        None => {
            error!(
                "Target public key not found for fingerprint: {}",
                data.target_fingerprint
            );
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Get current DAG heads for causal ordering
    let parent_hashes = get_dag_heads(&forum_hash).await;

    // Create board mod action node
    let mod_action = match ModActionNode::create_board_action(
        forum_content_hash,
        board_content_hash,
        ModAction::RemoveBoardModerator,
        &target_public_key,
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
        parent_hashes,
    ) {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to create board mod action: {}", e);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(mod_action),
    )
    .await;

    info!(
        "Removed board moderator: {} from board {}",
        data.target_fingerprint, board_hash
    );
    Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash)).into_response()
}

/// Move thread to a different board handler
pub async fn move_thread_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path((forum_hash, thread_hash)): Path<(String, String)>,
    Form(form): Form<CsrfProtectedForm<MoveThreadForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for move thread");
        return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
            .into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}/thread/{}", forum_hash, thread_hash);

    // Validate input sizes (DoS prevention)
    if data.destination_board.len() > MAX_HASH_INPUT_SIZE {
        warn!("Destination board hash too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Parse hashes
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid forum hash: {}", forum_hash);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    let thread_content_hash = match ContentHash::from_hex(&thread_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid thread hash: {}", thread_hash);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    let dest_board_hash = match ContentHash::from_hex(&data.destination_board) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid destination board hash: {}", data.destination_board);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    // Server-side permission check: MoveThread requires forum moderator
    let signer_fingerprint = match get_signing_key_fingerprint(&data.signing_key) {
        Some(fp) => fp,
        None => {
            warn!("Invalid signing key for move thread");
            return Redirect::to(&redirect_url).into_response();
        }
    };
    if !check_forum_permission(
        &app_state.forum_persistence,
        &forum_content_hash,
        &signer_fingerprint,
        PermissionLevel::ForumModerator,
    ) {
        warn!(
            "Unauthorized move thread attempt by {} on thread {}",
            signer_fingerprint, thread_hash
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Get signing materials (moderator's key)
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Get current DAG heads for causal ordering
    let parent_hashes = get_dag_heads(&forum_hash).await;

    // Create move thread action node
    let mod_action = match ModActionNode::create_move_thread_action(
        forum_content_hash,
        thread_content_hash,
        dest_board_hash,
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
        parent_hashes,
    ) {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to create move thread action: {}", e);
            return Redirect::to(&redirect_url).into_response();
        }
    };

    // Submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(mod_action),
    )
    .await;

    info!(
        "Moved thread {} to board {}",
        thread_hash, data.destination_board
    );

    // Redirect to the thread (now on the new board)
    Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash)).into_response()
}

/// Hide thread handler
pub async fn hide_thread_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path((forum_hash, thread_hash)): Path<(String, String)>,
    Form(form): Form<CsrfProtectedForm<HideThreadForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for hide thread");
        return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
            .into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}/thread/{}", forum_hash, thread_hash);

    // Validate input sizes (DoS prevention)
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Parse hashes
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid forum hash: {}", forum_hash);
            return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
                .into_response();
        }
    };

    let thread_content_hash = match ContentHash::from_hex(&thread_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid thread hash: {}", thread_hash);
            return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
                .into_response();
        }
    };

    // Get the thread to find its board hash (before we hide it)
    let board_hash = match app_state
        .forum_persistence
        .get_thread(&forum_content_hash, &thread_content_hash)
    {
        Ok(Some(thread)) => thread.board_hash().to_hex(),
        Ok(None) => {
            error!("Thread not found: {}", thread_hash);
            return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
        }
        Err(e) => {
            error!("Failed to load thread: {}", e);
            return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
        }
    };

    // Server-side permission check: HideThread requires forum moderator
    let signer_fingerprint = match get_signing_key_fingerprint(&data.signing_key) {
        Some(fp) => fp,
        None => {
            warn!("Invalid signing key for hide thread");
            return Redirect::to(&redirect_url).into_response();
        }
    };
    if !check_forum_permission(
        &app_state.forum_persistence,
        &forum_content_hash,
        &signer_fingerprint,
        PermissionLevel::ForumModerator,
    ) {
        warn!(
            "Unauthorized hide thread attempt by {} on thread {}",
            signer_fingerprint, thread_hash
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Get signing materials (moderator's key)
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
                .into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Get current DAG heads for causal ordering
    let parent_hashes = get_dag_heads(&forum_hash).await;

    // Create content action node for hiding the thread
    let mod_action = match ModActionNode::create_content_action(
        forum_content_hash,
        thread_content_hash,
        ModAction::HideThread,
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
        parent_hashes,
    ) {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to create hide thread action: {}", e);
            return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
                .into_response();
        }
    };

    // Submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(mod_action),
    )
    .await;

    info!("Hidden thread: {}", thread_hash);

    // Redirect back to the board
    Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash)).into_response()
}

/// Hide post handler
pub async fn hide_post_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path((forum_hash, thread_hash)): Path<(String, String)>,
    Form(form): Form<CsrfProtectedForm<HidePostForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for hide post");
        return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
            .into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}/thread/{}", forum_hash, thread_hash);

    // Validate input sizes (DoS prevention)
    if data.post_hash.len() > MAX_HASH_INPUT_SIZE {
        warn!("Post hash too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Parse hashes
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid forum hash: {}", forum_hash);
            return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
                .into_response();
        }
    };

    let post_content_hash = match ContentHash::from_hex(&data.post_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid post hash: {}", data.post_hash);
            return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
                .into_response();
        }
    };

    // Server-side permission check: HidePost requires forum moderator
    let signer_fingerprint = match get_signing_key_fingerprint(&data.signing_key) {
        Some(fp) => fp,
        None => {
            warn!("Invalid signing key for hide post");
            return Redirect::to(&redirect_url).into_response();
        }
    };
    if !check_forum_permission(
        &app_state.forum_persistence,
        &forum_content_hash,
        &signer_fingerprint,
        PermissionLevel::ForumModerator,
    ) {
        warn!(
            "Unauthorized hide post attempt by {} on post {}",
            signer_fingerprint, data.post_hash
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Get signing materials (moderator's key)
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
                .into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Get current DAG heads for causal ordering
    let parent_hashes = get_dag_heads(&forum_hash).await;

    // Create content action node for hiding the post
    let mod_action = match ModActionNode::create_content_action(
        forum_content_hash,
        post_content_hash,
        ModAction::HidePost,
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
        parent_hashes,
    ) {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to create hide post action: {}", e);
            return Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash))
                .into_response();
        }
    };

    // Submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(mod_action),
    )
    .await;

    info!("Hidden post: {}", data.post_hash);
    Redirect::to(&format!("/forum/{}/thread/{}", forum_hash, thread_hash)).into_response()
}

/// Hide board handler
pub async fn hide_board_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path((forum_hash, board_hash)): Path<(String, String)>,
    Form(form): Form<CsrfProtectedForm<HideBoardForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for hide board");
        return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
            .into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}/board/{}", forum_hash, board_hash);

    // Validate input sizes (DoS prevention)
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Parse hashes
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid forum hash: {}", forum_hash);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    let board_content_hash = match ContentHash::from_hex(&board_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid board hash: {}", board_hash);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Server-side permission check: HideBoard requires forum moderator
    let signer_fingerprint = match get_signing_key_fingerprint(&data.signing_key) {
        Some(fp) => fp,
        None => {
            warn!("Invalid signing key for hide board");
            return Redirect::to(&redirect_url).into_response();
        }
    };
    if !check_forum_permission(
        &app_state.forum_persistence,
        &forum_content_hash,
        &signer_fingerprint,
        PermissionLevel::ForumModerator,
    ) {
        warn!(
            "Unauthorized hide board attempt by {} on board {}",
            signer_fingerprint, board_hash
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Get signing materials (moderator's key)
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Get current DAG heads for causal ordering
    let parent_hashes = get_dag_heads(&forum_hash).await;

    // Create hide board action node
    let mod_action = match ModActionNode::create_hide_board_action(
        forum_content_hash,
        board_content_hash,
        ModAction::HideBoard,
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
        parent_hashes,
    ) {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to create hide board action: {}", e);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(mod_action),
    )
    .await;

    info!("Hidden board: {}", board_hash);

    // Redirect back to the forum (since the board is now hidden)
    Redirect::to(&format!("/forum/{}", forum_hash)).into_response()
}

/// Unhide board handler
pub async fn unhide_board_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path((forum_hash, board_hash)): Path<(String, String)>,
    Form(form): Form<CsrfProtectedForm<HideBoardForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for unhide board");
        return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
            .into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}/board/{}", forum_hash, board_hash);

    // Validate input sizes (DoS prevention)
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Parse hashes
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid forum hash: {}", forum_hash);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    let board_content_hash = match ContentHash::from_hex(&board_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid board hash: {}", board_hash);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Server-side permission check: UnhideBoard requires forum moderator
    let signer_fingerprint = match get_signing_key_fingerprint(&data.signing_key) {
        Some(fp) => fp,
        None => {
            warn!("Invalid signing key for unhide board");
            return Redirect::to(&redirect_url).into_response();
        }
    };
    if !check_forum_permission(
        &app_state.forum_persistence,
        &forum_content_hash,
        &signer_fingerprint,
        PermissionLevel::ForumModerator,
    ) {
        warn!(
            "Unauthorized unhide board attempt by {} on board {}",
            signer_fingerprint, board_hash
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Get signing materials (moderator's key)
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Get current DAG heads for causal ordering
    let parent_hashes = get_dag_heads(&forum_hash).await;

    // Create unhide board action node
    let mod_action = match ModActionNode::create_hide_board_action(
        forum_content_hash,
        board_content_hash,
        ModAction::UnhideBoard,
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
        parent_hashes,
    ) {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to create unhide board action: {}", e);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(mod_action),
    )
    .await;

    info!("Unhidden board: {}", board_hash);

    // Redirect back to the board
    Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash)).into_response()
}

/// Edit forum handler (owner only)
pub async fn edit_forum_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path(forum_hash): Path<String>,
    Form(form): Form<CsrfProtectedForm<EditForumForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for edit forum");
        return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}", forum_hash);

    // Validate input sizes (DoS prevention)
    if data
        .new_name
        .as_ref()
        .is_some_and(|n| n.len() > MAX_NAME_SIZE)
    {
        warn!("New name too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .new_description
        .as_ref()
        .is_some_and(|d| d.len() > MAX_DESCRIPTION_SIZE)
    {
        warn!("New description too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Ensure at least one field is being changed
    let new_name = data.new_name.filter(|s| !s.is_empty());
    let new_description = data.new_description.filter(|s| !s.is_empty());

    if new_name.is_none() && new_description.is_none() {
        error!("Edit forum: no changes specified");
        return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
    }

    // Parse forum hash
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid forum hash: {}", forum_hash);
            return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
        }
    };

    // Server-side permission check: EditForum requires owner
    let signer_fingerprint = match get_signing_key_fingerprint(&data.signing_key) {
        Some(fp) => fp,
        None => {
            warn!("Invalid signing key for edit forum");
            return Redirect::to(&redirect_url).into_response();
        }
    };
    if !check_forum_permission(
        &app_state.forum_persistence,
        &forum_content_hash,
        &signer_fingerprint,
        PermissionLevel::OwnerOnly,
    ) {
        warn!(
            "Unauthorized edit forum attempt by {} on forum {}",
            signer_fingerprint, forum_hash
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Get signing materials (owner's key)
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Create forum edit node
    let edit_node = match EditNode::create_forum_edit(
        forum_content_hash,
        new_name.clone(),
        new_description.clone(),
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
    ) {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to create forum edit: {}", e);
            return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
        }
    };

    // Submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(edit_node),
    )
    .await;

    info!(
        "Edited forum {}: name={:?}, description={:?}",
        forum_hash,
        new_name
            .as_deref()
            .map(|s| s.chars().take(20).collect::<String>()),
        new_description
            .as_deref()
            .map(|s| s.chars().take(20).collect::<String>())
    );
    Redirect::to(&format!("/forum/{}", forum_hash)).into_response()
}

/// Edit board handler (owner or moderator)
pub async fn edit_board_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path((forum_hash, board_hash)): Path<(String, String)>,
    Form(form): Form<CsrfProtectedForm<EditBoardForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for edit board");
        return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
            .into_response();
    }

    let data = form.data;
    let redirect_url = format!("/forum/{}/board/{}", forum_hash, board_hash);

    // Validate input sizes (DoS prevention)
    if data
        .new_name
        .as_ref()
        .is_some_and(|n| n.len() > MAX_NAME_SIZE)
    {
        warn!("New name too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .new_description
        .as_ref()
        .is_some_and(|d| d.len() > MAX_DESCRIPTION_SIZE)
    {
        warn!("New description too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data.signing_key.len() > MAX_HASH_INPUT_SIZE {
        warn!("Signing key ID too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .password
        .as_ref()
        .is_some_and(|p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }

    // Ensure at least one field is being changed
    let new_name = data.new_name.filter(|s| !s.is_empty());
    let new_description = data.new_description.filter(|s| !s.is_empty());

    if new_name.is_none() && new_description.is_none() {
        error!("Edit board: no changes specified");
        return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
            .into_response();
    }

    // Parse hashes
    let forum_content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid forum hash: {}", forum_hash);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    let board_content_hash = match ContentHash::from_hex(&board_hash) {
        Ok(h) => h,
        Err(_) => {
            error!("Invalid board hash: {}", board_hash);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Server-side permission check: EditBoard requires forum moderator
    let signer_fingerprint = match get_signing_key_fingerprint(&data.signing_key) {
        Some(fp) => fp,
        None => {
            warn!("Invalid signing key for edit board");
            return Redirect::to(&redirect_url).into_response();
        }
    };
    if !check_forum_permission(
        &app_state.forum_persistence,
        &forum_content_hash,
        &signer_fingerprint,
        PermissionLevel::ForumModerator,
    ) {
        warn!(
            "Unauthorized edit board attempt by {} on board {}",
            signer_fingerprint, board_hash
        );
        return Redirect::to(&redirect_url).into_response();
    }

    // Get signing materials (owner/moderator's key)
    let signing = match get_signing_materials(&data.signing_key) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get signing key: {}", e);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Prepare password if provided
    let password = data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Create board edit node
    let edit_node = match EditNode::create_board_edit(
        forum_content_hash,
        board_content_hash,
        new_name.clone(),
        new_description.clone(),
        &signing.public_key,
        &signing.private_key,
        password.as_ref(),
    ) {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to create board edit: {}", e);
            return Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash))
                .into_response();
        }
    };

    // Submit to relay
    submit_node(
        &app_state.forum_persistence,
        &forum_hash,
        DagNode::from(edit_node),
    )
    .await;

    info!(
        "Edited board {}: name={:?}, description={:?}",
        board_hash,
        new_name
            .as_deref()
            .map(|s| s.chars().take(20).collect::<String>()),
        new_description
            .as_deref()
            .map(|s| s.chars().take(20).collect::<String>())
    );
    Redirect::to(&format!("/forum/{}/board/{}", forum_hash, board_hash)).into_response()
}

/// Remove forum handler - removes forum data from local storage only.
///
/// This does NOT delete the forum from the relay - it only removes the local
/// copy. To get the forum back, user can sync from the relay again.
pub async fn remove_forum_handler(
    State(app_state): State<AppState>,
    session: Session,
    Path(forum_hash): Path<String>,
    Form(form): Form<CsrfProtectedForm<RemoveForumForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for remove forum");
        return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
    }

    // Parse the forum hash
    let content_hash = match ContentHash::from_hex(&forum_hash) {
        Ok(h) => h,
        Err(e) => {
            error!("Invalid forum hash: {}", e);
            return Redirect::to("/forum").into_response();
        }
    };

    // Remove from local storage only
    if let Err(e) = app_state.forum_persistence.remove_forum(&content_hash) {
        error!("Failed to remove forum from local storage: {}", e);
        return Redirect::to(&format!("/forum/{}", forum_hash)).into_response();
    }
    info!("Removed forum from local storage: {}", forum_hash);

    // Redirect to forum list after successful removal
    Redirect::to("/forum").into_response()
}

/// Join forum by hash handler - syncs forum data from relay to local storage.
///
/// This performs a full sync of the forum DAG, storing all nodes locally.
/// If the forum was already synced, it will fetch any new nodes.
pub async fn join_forum_handler(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<JoinForumForm>>,
) -> impl IntoResponse {
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("CSRF validation failed for join forum");
        return Redirect::to("/forum").into_response();
    }

    // Validate input size (DoS prevention)
    if form.data.forum_hash.len() > MAX_HASH_INPUT_SIZE {
        warn!("Forum hash too large");
        return Redirect::to("/forum").into_response();
    }

    let forum_hash_str = form.data.forum_hash.trim();

    // Validate hash format (should be hex)
    if forum_hash_str.is_empty() || !forum_hash_str.chars().all(|c| c.is_ascii_hexdigit()) {
        error!("Invalid forum hash format: {}", forum_hash_str);
        return Redirect::to("/forum").into_response();
    }

    // Parse the hash
    let forum_hash = match ContentHash::from_hex(forum_hash_str) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to parse forum hash: {}", e);
            return Redirect::to("/forum").into_response();
        }
    };

    // Check if already synced locally
    let already_synced = forum_exists_locally(&app_state.forum_persistence, &forum_hash);
    if already_synced {
        info!("Forum {} already synced, updating...", forum_hash.short());
    }

    // Check if forum exists on the relay first by attempting a sync
    let http_client = Client::new();
    let rpc_client = create_rpc_client();

    let check_request = rpc_client.build_sync_request(&forum_hash, &[], Some(1));
    match send_rpc_request(&http_client, &rpc_client, &check_request).await {
        Ok(rpc_response) => {
            if let Err(e) = rpc_client.parse_sync_response(rpc_response) {
                // Forum not found or other error
                warn!("Forum not found on relay: {} - {}", forum_hash_str, e);
                return Redirect::to("/forum").into_response();
            }
        }
        Err(e) => {
            error!("Connection error checking forum: {}", e);
            return Redirect::to("/forum").into_response();
        }
    }

    // Perform the sync
    match sync_forum(&app_state.forum_persistence, &forum_hash).await {
        Ok(nodes_synced) => {
            if already_synced {
                info!(
                    "Forum {} updated: {} new nodes synced",
                    forum_hash.short(),
                    nodes_synced
                );
            } else {
                info!(
                    "Forum {} joined: {} nodes synced",
                    forum_hash.short(),
                    nodes_synced
                );
            }
            Redirect::to(&format!("/forum/{}", forum_hash_str)).into_response()
        }
        Err(e) => {
            error!("Failed to sync forum {}: {}", forum_hash.short(), e);
            // Still redirect to forum page - relay might have data even if sync failed
            Redirect::to(&format!("/forum/{}", forum_hash_str)).into_response()
        }
    }
}

// =============================================================================
// Private Message Handlers
// =============================================================================

/// Maximum PM body size (64KB).
const MAX_PM_BODY_SIZE: usize = 64 * 1024;

/// Maximum PM subject size (256 bytes).
const MAX_PM_SUBJECT_SIZE: usize = 256;

/// Form data for creating encryption identity.
#[derive(Debug, Deserialize)]
pub struct CreateEncryptionIdentityForm {
    pub csrf_token: String,
    pub signing_key: String,
    /// Password for decrypting the signing key if protected.
    pub password: Option<String>,
    pub otp_count: Option<u32>,
}

/// Form data for sending a private message.
#[derive(Debug, Deserialize)]
pub struct SendPMForm {
    pub csrf_token: String,
    pub recipient: String,
    pub subject: Option<String>,
    pub body: String,
    /// Signing key field for future signature support.
    #[allow(dead_code)]
    pub signing_key: String,
    /// Password field for future key decryption support.
    #[allow(dead_code)]
    pub password: Option<String>,
}

/// Form data for replying to a conversation.
#[derive(Debug, Deserialize)]
pub struct ReplyPMForm {
    pub csrf_token: String,
    pub subject: Option<String>,
    pub body: String,
    pub reply_to: Option<String>,
    /// Signing key field for future signature support.
    #[allow(dead_code)]
    pub signing_key: String,
    /// Password field for future key decryption support.
    #[allow(dead_code)]
    pub password: Option<String>,
}

/// Form data for scanning PMs.
#[derive(Debug, Deserialize)]
pub struct ScanPMForm {
    pub csrf_token: String,
}

/// Query params for compose page.
#[derive(Debug, Deserialize)]
pub struct ComposeQuery {
    pub to: Option<String>,
}

/// Helper to format timestamp for display.
fn format_timestamp_display(millis: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let dt = UNIX_EPOCH + Duration::from_millis(millis);
    // Simple formatting - just show relative time or date
    let now = std::time::SystemTime::now();
    let age = now.duration_since(dt).unwrap_or_default();

    if age.as_secs() < 60 {
        "Just now".to_string()
    } else if age.as_secs() < 3600 {
        format!("{} minutes ago", age.as_secs() / 60)
    } else if age.as_secs() < 86400 {
        format!("{} hours ago", age.as_secs() / 3600)
    } else {
        format!("{} days ago", age.as_secs() / 86400)
    }
}

/// Helper to get all encryption identities in a forum.
fn get_forum_encryption_identities(
    persistence: &SharedForumPersistence,
    forum_hash: &ContentHash,
) -> Vec<(ContentHash, EncryptionIdentity)> {
    let mut identities = Vec::new();

    if let Ok(hashes) = persistence.list_encryption_identities(forum_hash) {
        for hash in hashes {
            if let Ok(Some(DagNode::EncryptionIdentity(ei))) =
                persistence.load_node(forum_hash, &hash)
            {
                identities.push((hash, ei));
            }
        }
    }

    identities
}

/// Helper to find our encryption identity (if we have one).
fn find_our_encryption_identity(
    persistence: &SharedForumPersistence,
    forum_hash: &ContentHash,
    our_fingerprints: &[String],
) -> Option<(ContentHash, EncryptionIdentity)> {
    let identities = get_forum_encryption_identities(persistence, forum_hash);

    for (hash, identity) in identities {
        let owner_fp = fingerprint_from_identity(&identity.content.owner_signing_key);
        if our_fingerprints.contains(&owner_fp) {
            return Some((hash, identity));
        }
    }

    None
}

/// PM Inbox page handler.
pub async fn pm_inbox_page(
    Path(forum_hash_str): Path<String>,
    Query(pagination): Query<PaginationQuery>,
    State(app_state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .unwrap_or_default();

    // Parse forum hash
    let forum_hash = match ContentHash::from_hex(&forum_hash_str) {
        Ok(h) => h,
        Err(_) => {
            return Html(
                "<html><body><h1>Invalid forum hash</h1><a href='/forum'>Back</a></body></html>"
                    .to_string(),
            )
            .into_response();
        }
    };

    // Get forum name
    let forum_name = app_state
        .forum_persistence
        .get_effective_forum_info(&forum_hash)
        .ok()
        .flatten()
        .map(|(name, _)| name)
        .unwrap_or_else(|| "Unknown Forum".to_string());

    // Get signing keys
    let signing_keys = get_signing_keys();
    let our_fingerprints: Vec<String> =
        signing_keys.iter().map(|k| k.fingerprint.clone()).collect();

    // Get all encryption identities in this forum
    let all_identities = get_forum_encryption_identities(&app_state.forum_persistence, &forum_hash);

    // Find all our encryption identities (ones that match our signing keys)
    let our_identities: Vec<EncryptionIdentityInfo> = all_identities
        .iter()
        .filter_map(|(hash, identity)| {
            let fp = fingerprint_from_identity(&identity.content.owner_signing_key);
            if our_fingerprints.contains(&fp) {
                Some(EncryptionIdentityInfo {
                    hash: hash.to_hex(),
                    owner_fingerprint: fp,
                    otp_count: identity.content.one_time_prekeys.len(),
                    created_at_display: format_timestamp_display(identity.content.created_at),
                })
            } else {
                None
            }
        })
        .collect();

    // Get recipients (all identities, for testing we include our own too)
    let recipients: Vec<PMRecipientInfo> = all_identities
        .iter()
        .map(|(hash, identity)| {
            let fp = fingerprint_from_identity(&identity.content.owner_signing_key);
            PMRecipientInfo {
                fingerprint: fp.clone(),
                fingerprint_short: format!("{}...", &fp[..16.min(fp.len())]),
                encryption_identity_hash: hash.to_hex(),
            }
        })
        .collect();

    // Parse cursor if provided (format: "timestamp:conversation_id_hex")
    let cursor = pagination.cursor.as_ref().and_then(|c| {
        let parts: Vec<&str> = c.split(':').collect();
        if parts.len() == 2 {
            let ts = parts[0].parse::<u64>().ok()?;
            let conv_id_bytes = hex::decode(parts[1]).ok()?;
            if conv_id_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&conv_id_bytes);
                Some((ts, arr))
            } else {
                None
            }
        } else {
            None
        }
    });

    // Load conversation manager to get conversations with pagination
    let (conversations, total_conversations, next_cursor, has_more) =
        match app_state.forum_persistence.load_conversation_manager() {
            Ok(manager) => {
                let total = manager.total_conversations();
                let (summaries, next) = manager.all_sessions_paginated(cursor, DEFAULT_PAGE_SIZE);

                let convs: Vec<ConversationInfo> = summaries
                    .into_iter()
                    .map(|summary| {
                        let id = hex::encode(summary.session.conversation_id().as_bytes());
                        let peer_fp = summary.session.peer_identity_hash().to_hex();

                        // Truncate last message preview
                        let last_message_preview = summary
                            .last_message
                            .map(|body| {
                                if body.len() > 50 {
                                    format!("{}...", &body[..50])
                                } else {
                                    body.to_string()
                                }
                            })
                            .unwrap_or_else(|| "No messages".to_string());

                        ConversationInfo {
                            id: id.clone(),
                            id_short: format!("{}...", &id[..16.min(id.len())]),
                            peer_fingerprint: peer_fp.clone(),
                            peer_short: format!("{}...", &peer_fp[..16.min(peer_fp.len())]),
                            last_message_preview,
                            last_activity_display: format_timestamp_display(
                                summary.session.last_activity(),
                            ),
                            message_count: summary.message_count,
                            has_unread: false,
                        }
                    })
                    .collect();

                let has_more = next.is_some();
                let next_cursor_str = next.map(|(ts, id)| format!("{}:{}", ts, hex::encode(id)));

                (convs, total, next_cursor_str, has_more)
            }
            _ => (Vec::new(), 0, None, false),
        };

    let template = PMInboxTemplate {
        active_page: "forum".to_string(),
        csrf_token,
        forum_hash: forum_hash_str,
        forum_name,
        our_identities,
        conversations,
        recipients,
        signing_keys,
        result: None,
        error: None,
        has_result: false,
        has_error: false,
        prev_cursor: pagination.prev.clone(),
        next_cursor,
        current_cursor: pagination.cursor.clone(),
        total_conversations,
        has_more,
    };

    Html(
        template
            .render()
            .unwrap_or_else(|e| format!("Template error: {}", e)),
    )
    .into_response()
}

/// Create encryption identity handler.
pub async fn create_encryption_identity_handler(
    Path(forum_hash_str): Path<String>,
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CreateEncryptionIdentityForm>,
) -> impl IntoResponse {
    // Validate CSRF
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        return Redirect::to(&format!("/forum/{}/pm?error=invalid_csrf", forum_hash_str))
            .into_response();
    }

    // Parse forum hash
    let forum_hash = match ContentHash::from_hex(&forum_hash_str) {
        Ok(h) => h,
        Err(_) => {
            return Redirect::to("/forum?error=invalid_hash").into_response();
        }
    };

    // SECURITY: Rate limit identity creation to prevent prekey bundle spam
    let rate_limit_key = format!("{}:{}", forum_hash_str, form.signing_key);
    if !app_state
        .pm_rate_limiters
        .identity_creation
        .check_and_record(&rate_limit_key)
    {
        warn!("Rate limited identity creation for {}", rate_limit_key);
        return Redirect::to(&format!("/forum/{}/pm?error=rate_limited", forum_hash_str))
            .into_response();
    }

    // Validate inputs
    if form.signing_key.len() > MAX_HASH_INPUT_SIZE {
        return Redirect::to(&format!("/forum/{}/pm?error=invalid_key", forum_hash_str))
            .into_response();
    }

    let otp_count = form.otp_count.unwrap_or(10).clamp(1, 100) as usize;

    // Load signing key using the standard pattern
    let signing_materials = match get_signing_materials(&form.signing_key) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to get signing materials: {}", e);
            return Redirect::to(&format!("/forum/{}/pm?error=key_error", forum_hash_str))
                .into_response();
        }
    };

    let public_key = signing_materials.public_key;
    let private_key = signing_materials.private_key;

    // Prepare password if provided
    let password = form
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Generate encryption identity
    let (identity, private_data) = match EncryptionIdentityGenerator::generate(
        forum_hash,
        &public_key,
        &private_key,
        otp_count,
        password.as_ref(),
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to generate encryption identity: {}", e);
            return Redirect::to(&format!(
                "/forum/{}/pm?error=generation_failed",
                forum_hash_str
            ))
            .into_response();
        }
    };

    // Store the private data locally
    let identity_hash = *identity.hash();
    if let Err(e) = app_state
        .forum_persistence
        .store_encryption_private(&identity_hash, &private_data)
    {
        error!("Failed to store encryption private key: {}", e);
        return Redirect::to(&format!(
            "/forum/{}/pm?error=storage_failed",
            forum_hash_str
        ))
        .into_response();
    }

    // Store the identity node locally
    let node = DagNode::EncryptionIdentity(identity);
    if let Err(e) = app_state
        .forum_persistence
        .store_node_for_forum(&forum_hash, &node)
    {
        error!("Failed to store encryption identity node: {}", e);
        return Redirect::to(&format!(
            "/forum/{}/pm?error=storage_failed",
            forum_hash_str
        ))
        .into_response();
    }

    // Submit to relay via JSON-RPC
    let http_client = Client::new();
    let rpc_client = create_rpc_client();

    let request = match rpc_client.build_submit_request(&forum_hash, &node) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create submit request: {}", e);
            return Redirect::to(&format!(
                "/forum/{}/pm?error=serialization_failed",
                forum_hash_str
            ))
            .into_response();
        }
    };

    match send_rpc_request(&http_client, &rpc_client, &request).await {
        Ok(rpc_response) => match rpc_client.parse_submit_response(rpc_response) {
            Ok(result) if result.accepted => {
                info!(
                    "Created encryption identity for forum {}",
                    forum_hash.short()
                );
                Redirect::to(&format!(
                    "/forum/{}/pm?result=identity_created",
                    forum_hash_str
                ))
                .into_response()
            }
            Ok(_) => {
                warn!("Relay rejected encryption identity");
                Redirect::to(&format!(
                    "/forum/{}/pm?error=relay_rejected",
                    forum_hash_str
                ))
                .into_response()
            }
            Err(e) => {
                error!("Failed to parse submit response: {}", e);
                Redirect::to(&format!("/forum/{}/pm?error=relay_error", forum_hash_str))
                    .into_response()
            }
        },
        Err(e) => {
            error!("Failed to submit to relay: {}", e);
            Redirect::to(&format!("/forum/{}/pm?error=relay_error", forum_hash_str)).into_response()
        }
    }
}

/// Send private message handler.
pub async fn send_pm_handler(
    Path(forum_hash_str): Path<String>,
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<SendPMForm>,
) -> impl IntoResponse {
    // Validate CSRF
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        return Redirect::to(&format!("/forum/{}/pm?error=invalid_csrf", forum_hash_str))
            .into_response();
    }

    // Parse forum hash
    let forum_hash = match ContentHash::from_hex(&forum_hash_str) {
        Ok(h) => h,
        Err(_) => {
            return Redirect::to("/forum?error=invalid_hash").into_response();
        }
    };

    // SECURITY: Rate limit message sending to prevent spam flooding
    let rate_limit_key = format!("{}:{}", forum_hash_str, form.signing_key);
    if !app_state
        .pm_rate_limiters
        .message_send
        .check_and_record(&rate_limit_key)
    {
        warn!("Rate limited message send for {}", rate_limit_key);
        return Redirect::to(&format!("/forum/{}/pm?error=rate_limited", forum_hash_str))
            .into_response();
    }

    // Validate inputs
    if form.body.is_empty() || form.body.len() > MAX_PM_BODY_SIZE {
        return Redirect::to(&format!("/forum/{}/pm?error=invalid_body", forum_hash_str))
            .into_response();
    }

    if let Some(ref subject) = form.subject {
        if subject.len() > MAX_PM_SUBJECT_SIZE {
            return Redirect::to(&format!(
                "/forum/{}/pm?error=invalid_subject",
                forum_hash_str
            ))
            .into_response();
        }
    }

    // Parse recipient encryption identity hash
    let recipient_hash = match ContentHash::from_hex(&form.recipient) {
        Ok(h) => h,
        Err(_) => {
            return Redirect::to(&format!(
                "/forum/{}/pm?error=invalid_recipient",
                forum_hash_str
            ))
            .into_response();
        }
    };

    // Load recipient's encryption identity
    let recipient_identity = match app_state
        .forum_persistence
        .load_node(&forum_hash, &recipient_hash)
    {
        Ok(Some(DagNode::EncryptionIdentity(ei))) => ei,
        _ => {
            return Redirect::to(&format!(
                "/forum/{}/pm?error=recipient_not_found",
                forum_hash_str
            ))
            .into_response();
        }
    };

    // Get our signing keys to find our encryption identity
    let signing_keys = get_signing_keys();
    let our_fingerprints: Vec<String> =
        signing_keys.iter().map(|k| k.fingerprint.clone()).collect();

    let (our_identity_hash, our_identity) = match find_our_encryption_identity(
        &app_state.forum_persistence,
        &forum_hash,
        &our_fingerprints,
    ) {
        Some(result) => result,
        None => {
            return Redirect::to(&format!("/forum/{}/pm?error=no_identity", forum_hash_str))
                .into_response();
        }
    };

    // Create inner message
    let conversation_seed = [0u8; 32]; // Will be overridden by seal function
    let mut inner = InnerMessage::new(conversation_seed, form.body.clone());
    if let Some(ref subject) = form.subject {
        if !subject.is_empty() {
            inner = inner.with_subject(subject.clone());
        }
    }
    let inner_for_storage = inner.clone();

    // Seal the message
    let sealed_result = match seal_private_message(
        forum_hash,
        &our_identity,
        &recipient_identity,
        inner,
        true, // Use one-time prekey
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to seal private message: {}", e);
            return Redirect::to(&format!("/forum/{}/pm?error=seal_failed", forum_hash_str))
                .into_response();
        }
    };

    // Store the sealed message locally
    let node = DagNode::SealedPrivateMessage(sealed_result.message.clone());
    if let Err(e) = app_state
        .forum_persistence
        .store_node_for_forum(&forum_hash, &node)
    {
        error!("Failed to store sealed message: {}", e);
        return Redirect::to(&format!(
            "/forum/{}/pm?error=storage_failed",
            forum_hash_str
        ))
        .into_response();
    }

    // Submit to relay via JSON-RPC
    let http_client = Client::new();
    let rpc_client = create_rpc_client();

    let request = match rpc_client.build_submit_request(&forum_hash, &node) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create submit request: {}", e);
            return Redirect::to(&format!(
                "/forum/{}/pm?error=serialization_failed",
                forum_hash_str
            ))
            .into_response();
        }
    };

    match send_rpc_request(&http_client, &rpc_client, &request).await {
        Ok(rpc_response) => match rpc_client.parse_submit_response(rpc_response) {
            Ok(result) if result.accepted => {
                info!("Sent private message in forum {}", forum_hash.short());

                // Create conversation session locally
                let mut conversation_manager = app_state
                    .forum_persistence
                    .load_conversation_manager()
                    .unwrap_or_else(|_| ConversationManager::new());

                // Check if session already exists, if not create it
                let conv_id_bytes = sealed_result.conversation_id;
                if conversation_manager.get_session(&conv_id_bytes).is_none() {
                    // Get the recipient's signed prekey public key bytes for Double Ratchet initialization
                    let peer_ratchet_key = Some(
                        recipient_identity
                            .content
                            .signed_prekey
                            .public_key()
                            .to_vec(),
                    );
                    let session = ConversationSession::new_initiator(
                        conv_id_bytes,
                        *sealed_result.conversation_key,
                        our_identity_hash,
                        recipient_hash,
                        None, // OTP consumption tracked separately
                        peer_ratchet_key,
                    );
                    if let Err(e) = conversation_manager.add_session(session) {
                        warn!("Failed to add conversation session: {}", e);
                    }
                }

                // Record sent and store the message
                if let Some(session) = conversation_manager.get_session_mut(&conv_id_bytes) {
                    session.record_sent();
                }

                // Store the message in history
                let stored_msg = StoredMessage {
                    inner: inner_for_storage,
                    dag_hash: *node.hash(),
                    is_outgoing: true,
                    processed_at: current_timestamp_millis(),
                };
                if let Err(e) = conversation_manager.store_message(&conv_id_bytes, stored_msg) {
                    warn!("Failed to store message in history: {}", e);
                }

                // Save conversation manager
                if let Err(e) = app_state
                    .forum_persistence
                    .store_conversation_manager(&conversation_manager)
                {
                    warn!("Failed to save conversation manager: {}", e);
                }

                Redirect::to(&format!("/forum/{}/pm?result=message_sent", forum_hash_str))
                    .into_response()
            }
            Ok(_) => {
                warn!("Relay rejected sealed message");
                Redirect::to(&format!(
                    "/forum/{}/pm?error=relay_rejected",
                    forum_hash_str
                ))
                .into_response()
            }
            Err(e) => {
                error!("Failed to parse submit response: {}", e);
                Redirect::to(&format!("/forum/{}/pm?error=relay_error", forum_hash_str))
                    .into_response()
            }
        },
        Err(e) => {
            error!("Failed to submit to relay: {}", e);
            Redirect::to(&format!("/forum/{}/pm?error=relay_error", forum_hash_str)).into_response()
        }
    }
}

/// Scan for new private messages handler.
pub async fn scan_pm_handler(
    Path(forum_hash_str): Path<String>,
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<ScanPMForm>,
) -> impl IntoResponse {
    // Validate CSRF
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        return Redirect::to(&format!("/forum/{}/pm?error=invalid_csrf", forum_hash_str))
            .into_response();
    }

    // Parse forum hash
    let forum_hash = match ContentHash::from_hex(&forum_hash_str) {
        Ok(h) => h,
        Err(_) => {
            return Redirect::to("/forum?error=invalid_hash").into_response();
        }
    };

    // SECURITY: Rate limit scanning to prevent resource exhaustion
    // Use forum hash as key since scanning is per-forum
    if !app_state
        .pm_rate_limiters
        .message_scan
        .check_and_record(&forum_hash_str)
    {
        warn!("Rate limited message scan for forum {}", forum_hash_str);
        return Redirect::to(&format!("/forum/{}/pm?error=rate_limited", forum_hash_str))
            .into_response();
    }

    // Load our encryption private keys
    let private_hashes = match app_state.forum_persistence.list_encryption_privates() {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to list encryption privates: {}", e);
            return Redirect::to(&format!("/forum/{}/pm?error=storage_error", forum_hash_str))
                .into_response();
        }
    };

    if private_hashes.is_empty() {
        return Redirect::to(&format!("/forum/{}/pm?error=no_identity", forum_hash_str))
            .into_response();
    }

    // Load private keys
    let mut privates = Vec::new();
    for hash in &private_hashes {
        if let Ok(Some(private)) = app_state.forum_persistence.load_encryption_private(hash) {
            privates.push(private);
        }
    }

    if privates.is_empty() {
        return Redirect::to(&format!("/forum/{}/pm?error=no_identity", forum_hash_str))
            .into_response();
    }

    // Load conversation manager
    let conversation_manager = app_state
        .forum_persistence
        .load_conversation_manager()
        .unwrap_or_else(|_| ConversationManager::new());

    // Load all sealed messages from storage
    let sealed_hashes = match app_state
        .forum_persistence
        .list_sealed_messages(&forum_hash)
    {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to list sealed messages: {}", e);
            return Redirect::to(&format!("/forum/{}/pm?error=storage_error", forum_hash_str))
                .into_response();
        }
    };

    // Load sealed messages
    let mut sealed_messages: Vec<(ContentHash, SealedPrivateMessage)> = Vec::new();
    for hash in sealed_hashes {
        if let Ok(Some(DagNode::SealedPrivateMessage(msg))) =
            app_state.forum_persistence.load_node(&forum_hash, &hash)
        {
            sealed_messages.push((hash, msg));
        }
    }

    // Create scanner and scan
    let private_refs: Vec<_> = privates.iter().collect();
    let mut scanner = PrivateMessageScanner::new(private_refs);

    let messages_iter = sealed_messages.iter().map(|(h, m)| (h, m));
    let scan_result = scanner.scan_messages(messages_iter, &conversation_manager);

    // Save updated conversation manager
    if let Err(e) = app_state
        .forum_persistence
        .store_conversation_manager(&conversation_manager)
    {
        warn!("Failed to save conversation manager: {}", e);
    }

    info!(
        "PM scan complete: scanned={}, decrypted={}, new_conversations={}",
        scan_result.messages_scanned, scan_result.messages_decrypted, scan_result.new_conversations
    );

    Redirect::to(&format!(
        "/forum/{}/pm?result=scanned_{}_decrypted_{}",
        forum_hash_str, scan_result.messages_scanned, scan_result.messages_decrypted
    ))
    .into_response()
}

/// Compose new PM page handler.
pub async fn pm_compose_page(
    Path(forum_hash_str): Path<String>,
    Query(query): Query<ComposeQuery>,
    State(app_state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .unwrap_or_default();

    // Parse forum hash
    let forum_hash = match ContentHash::from_hex(&forum_hash_str) {
        Ok(h) => h,
        Err(_) => {
            return Html(
                "<html><body><h1>Invalid forum hash</h1><a href='/forum'>Back</a></body></html>"
                    .to_string(),
            )
            .into_response();
        }
    };

    // Get forum name
    let forum_name = app_state
        .forum_persistence
        .get_effective_forum_info(&forum_hash)
        .ok()
        .flatten()
        .map(|(name, _)| name)
        .unwrap_or_else(|| "Unknown Forum".to_string());

    // Get signing keys
    let signing_keys = get_signing_keys();
    let our_fingerprints: Vec<String> =
        signing_keys.iter().map(|k| k.fingerprint.clone()).collect();

    // Find our encryption identity
    let our_identity =
        find_our_encryption_identity(&app_state.forum_persistence, &forum_hash, &our_fingerprints)
            .map(|(hash, identity)| EncryptionIdentityInfo {
                hash: hash.to_hex(),
                owner_fingerprint: fingerprint_from_identity(&identity.content.owner_signing_key),
                otp_count: identity.content.one_time_prekeys.len(),
                created_at_display: format_timestamp_display(identity.content.created_at),
            });

    // Get all encryption identities for recipients (excluding ours)
    let all_identities = get_forum_encryption_identities(&app_state.forum_persistence, &forum_hash);
    let recipients: Vec<PMRecipientInfo> = all_identities
        .iter()
        .filter_map(|(hash, identity)| {
            let fp = fingerprint_from_identity(&identity.content.owner_signing_key);
            if our_fingerprints.contains(&fp) {
                None
            } else {
                Some(PMRecipientInfo {
                    fingerprint: fp.clone(),
                    fingerprint_short: format!("{}...", &fp[..16.min(fp.len())]),
                    encryption_identity_hash: hash.to_hex(),
                })
            }
        })
        .collect();

    // Pre-select recipient if specified in query
    let recipient = query.to.as_ref().and_then(|to_hash| {
        recipients
            .iter()
            .find(|r| r.encryption_identity_hash == *to_hash)
            .cloned()
    });

    let template = PMComposeTemplate {
        active_page: "forum".to_string(),
        csrf_token,
        forum_hash: forum_hash_str,
        forum_name,
        recipient,
        recipients,
        our_identity,
        signing_keys,
        result: None,
        error: None,
        has_result: false,
        has_error: false,
    };

    Html(
        template
            .render()
            .unwrap_or_else(|e| format!("Template error: {}", e)),
    )
    .into_response()
}

/// View conversation page handler.
pub async fn pm_conversation_page(
    Path((forum_hash_str, conversation_id_str)): Path<(String, String)>,
    Query(pagination): Query<PaginationQuery>,
    State(app_state): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .unwrap_or_default();

    // Parse forum hash
    let forum_hash = match ContentHash::from_hex(&forum_hash_str) {
        Ok(h) => h,
        Err(_) => {
            return Html(
                "<html><body><h1>Invalid forum hash</h1><a href='/forum'>Back</a></body></html>"
                    .to_string(),
            )
            .into_response();
        }
    };

    // Parse conversation ID
    let conversation_id: [u8; 32] = match hex::decode(&conversation_id_str) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return Html(format!(
                "<html><body><h1>Invalid conversation ID</h1><a href='/forum/{}/pm'>Back</a></body></html>",
                forum_hash_str
            ))
            .into_response();
        }
    };

    // Get forum name
    let forum_name = app_state
        .forum_persistence
        .get_effective_forum_info(&forum_hash)
        .ok()
        .flatten()
        .map(|(name, _)| name)
        .unwrap_or_else(|| "Unknown Forum".to_string());

    // Load conversation manager
    let conversation_manager = match app_state.forum_persistence.load_conversation_manager() {
        Ok(manager) => manager,
        _ => {
            return Html(format!(
                "<html><body><h1>Conversation not found</h1><a href='/forum/{}/pm'>Back</a></body></html>",
                forum_hash_str
            ))
            .into_response();
        }
    };

    // Get conversation session
    let session_data = match conversation_manager.get_session(&conversation_id) {
        Some(s) => s,
        None => {
            return Html(format!(
                "<html><body><h1>Conversation not found</h1><a href='/forum/{}/pm'>Back</a></body></html>",
                forum_hash_str
            ))
            .into_response();
        }
    };

    let peer_fp = session_data.peer_identity_hash().to_hex();

    // Parse cursor if provided (format: "timestamp:message_id_hex")
    let cursor = pagination.cursor.as_ref().and_then(|c| {
        let parts: Vec<&str> = c.split(':').collect();
        if parts.len() == 2 {
            let ts = parts[0].parse::<u64>().ok()?;
            let msg_id_bytes = hex::decode(parts[1]).ok()?;
            if msg_id_bytes.len() == 16 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&msg_id_bytes);
                Some((ts, arr))
            } else {
                None
            }
        } else {
            None
        }
    });

    // Get messages with pagination
    let (msg_refs, total_messages, next) =
        conversation_manager.get_messages_paginated(&conversation_id, cursor, DEFAULT_PAGE_SIZE);

    let messages: Vec<PrivateMessageInfo> = msg_refs
        .into_iter()
        .map(|m| PrivateMessageInfo {
            message_id: hex::encode(m.inner.message_id),
            body: m.inner.body.clone(),
            subject: m.inner.subject.clone(),
            is_outgoing: m.is_outgoing,
            timestamp_display: format_timestamp_display(m.processed_at),
            reply_to: m.inner.reply_to.map(hex::encode),
        })
        .collect();

    let has_more = next.is_some();
    let next_cursor = next.map(|(ts, id)| format!("{}:{}", ts, hex::encode(id)));

    let signing_keys = get_signing_keys();

    let template = PMConversationTemplate {
        active_page: "forum".to_string(),
        csrf_token,
        forum_hash: forum_hash_str,
        forum_name,
        conversation_id: conversation_id_str,
        peer_fingerprint: peer_fp.clone(),
        peer_short: format!("{}...", &peer_fp[..16.min(peer_fp.len())]),
        messages,
        signing_keys,
        result: None,
        error: None,
        has_result: false,
        has_error: false,
        prev_cursor: pagination.prev.clone(),
        next_cursor,
        current_cursor: pagination.cursor.clone(),
        total_messages,
        has_more,
    };

    Html(
        template
            .render()
            .unwrap_or_else(|e| format!("Template error: {}", e)),
    )
    .into_response()
}

/// Reply to conversation handler.
pub async fn reply_pm_handler(
    Path((forum_hash_str, conversation_id_str)): Path<(String, String)>,
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<ReplyPMForm>,
) -> impl IntoResponse {
    // Validate CSRF
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        return Redirect::to(&format!(
            "/forum/{}/pm/conversation/{}?error=invalid_csrf",
            forum_hash_str, conversation_id_str
        ))
        .into_response();
    }

    // Parse forum hash
    let forum_hash = match ContentHash::from_hex(&forum_hash_str) {
        Ok(h) => h,
        Err(_) => {
            return Redirect::to("/forum?error=invalid_hash").into_response();
        }
    };

    // Parse conversation ID
    let conversation_id: [u8; 32] = match hex::decode(&conversation_id_str) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return Redirect::to(&format!(
                "/forum/{}/pm?error=invalid_conversation",
                forum_hash_str
            ))
            .into_response();
        }
    };

    // Validate inputs
    if form.body.is_empty() || form.body.len() > MAX_PM_BODY_SIZE {
        return Redirect::to(&format!(
            "/forum/{}/pm/conversation/{}?error=invalid_body",
            forum_hash_str, conversation_id_str
        ))
        .into_response();
    }

    // Load conversation manager to get peer info
    let conversation_manager = match app_state.forum_persistence.load_conversation_manager() {
        Ok(manager) => manager,
        _ => {
            return Redirect::to(&format!(
                "/forum/{}/pm?error=conversation_not_found",
                forum_hash_str
            ))
            .into_response();
        }
    };

    let session_data = match conversation_manager.get_session(&conversation_id) {
        Some(s) => s,
        None => {
            return Redirect::to(&format!(
                "/forum/{}/pm?error=conversation_not_found",
                forum_hash_str
            ))
            .into_response();
        }
    };

    // Find peer's encryption identity by their identity node hash
    let peer_identity_hash = *session_data.peer_identity_hash();

    // Load peer's encryption identity directly by hash
    let recipient_identity = match app_state
        .forum_persistence
        .load_node(&forum_hash, &peer_identity_hash)
    {
        Ok(Some(DagNode::EncryptionIdentity(ei))) => ei,
        Ok(Some(_)) => {
            error!("Peer identity hash points to wrong node type");
            return Redirect::to(&format!(
                "/forum/{}/pm/conversation/{}?error=peer_not_found",
                forum_hash_str, conversation_id_str
            ))
            .into_response();
        }
        Ok(None) => {
            error!(
                "Peer identity not found for hash: {}",
                peer_identity_hash.to_hex()
            );
            return Redirect::to(&format!(
                "/forum/{}/pm/conversation/{}?error=peer_not_found",
                forum_hash_str, conversation_id_str
            ))
            .into_response();
        }
        Err(e) => {
            error!("Failed to load peer identity: {}", e);
            return Redirect::to(&format!(
                "/forum/{}/pm/conversation/{}?error=peer_not_found",
                forum_hash_str, conversation_id_str
            ))
            .into_response();
        }
    };

    // Get our signing keys to find our encryption identity
    let signing_keys = get_signing_keys();
    let our_fingerprints: Vec<String> =
        signing_keys.iter().map(|k| k.fingerprint.clone()).collect();

    let (_our_identity_hash, our_identity) = match find_our_encryption_identity(
        &app_state.forum_persistence,
        &forum_hash,
        &our_fingerprints,
    ) {
        Some(result) => result,
        None => {
            return Redirect::to(&format!("/forum/{}/pm?error=no_identity", forum_hash_str))
                .into_response();
        }
    };

    // Create inner message
    let mut inner = InnerMessage::new(conversation_id, form.body);
    if let Some(subject) = form.subject.filter(|s| !s.is_empty()) {
        inner = inner.with_subject(subject);
    }
    if let Some(reply_to) = form.reply_to.filter(|r| !r.is_empty()) {
        if let Ok(bytes) = hex::decode(&reply_to) {
            if bytes.len() == 16 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                inner = inner.with_reply_to(arr);
            }
        }
    }
    let inner_for_storage = inner.clone();

    // Seal the message using existing session key
    let existing_key = session_data.conversation_key();
    let sealed_result = match pqpgp::forum::seal_private_message_with_session(
        forum_hash,
        &our_identity,
        &recipient_identity,
        inner,
        existing_key,
        conversation_id,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to seal reply: {}", e);
            return Redirect::to(&format!(
                "/forum/{}/pm/conversation/{}?error=seal_failed",
                forum_hash_str, conversation_id_str
            ))
            .into_response();
        }
    };

    // Store locally
    let node = DagNode::SealedPrivateMessage(sealed_result.message.clone());
    if let Err(e) = app_state
        .forum_persistence
        .store_node_for_forum(&forum_hash, &node)
    {
        error!("Failed to store sealed reply: {}", e);
        return Redirect::to(&format!(
            "/forum/{}/pm/conversation/{}?error=storage_failed",
            forum_hash_str, conversation_id_str
        ))
        .into_response();
    }

    // Submit to relay via JSON-RPC
    let http_client = Client::new();
    let rpc_client = create_rpc_client();

    let request = match rpc_client.build_submit_request(&forum_hash, &node) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create submit request: {}", e);
            return Redirect::to(&format!(
                "/forum/{}/pm/conversation/{}?error=serialization_failed",
                forum_hash_str, conversation_id_str
            ))
            .into_response();
        }
    };

    match send_rpc_request(&http_client, &rpc_client, &request).await {
        Ok(rpc_response) => match rpc_client.parse_submit_response(rpc_response) {
            Ok(result) if result.accepted => {
                // Store the reply in conversation history
                let mut conversation_manager = app_state
                    .forum_persistence
                    .load_conversation_manager()
                    .unwrap_or_else(|_| ConversationManager::new());

                let stored_msg = StoredMessage {
                    inner: inner_for_storage,
                    dag_hash: *node.hash(),
                    is_outgoing: true,
                    processed_at: current_timestamp_millis(),
                };

                if let Err(e) = conversation_manager.store_message(&conversation_id, stored_msg) {
                    warn!("Failed to store reply in history: {}", e);
                }

                // Record sent message in session
                if let Some(session) = conversation_manager.get_session_mut(&conversation_id) {
                    session.record_sent();
                }

                // Save conversation manager
                if let Err(e) = app_state
                    .forum_persistence
                    .store_conversation_manager(&conversation_manager)
                {
                    warn!("Failed to save conversation manager: {}", e);
                }

                Redirect::to(&format!(
                    "/forum/{}/pm/conversation/{}?result=reply_sent",
                    forum_hash_str, conversation_id_str
                ))
                .into_response()
            }
            Ok(_) => {
                warn!("Relay rejected reply");
                Redirect::to(&format!(
                    "/forum/{}/pm/conversation/{}?error=relay_rejected",
                    forum_hash_str, conversation_id_str
                ))
                .into_response()
            }
            Err(e) => {
                error!("Failed to parse submit response: {}", e);
                Redirect::to(&format!(
                    "/forum/{}/pm/conversation/{}?error=relay_error",
                    forum_hash_str, conversation_id_str
                ))
                .into_response()
            }
        },
        Err(e) => {
            error!("Failed to submit reply: {}", e);
            Redirect::to(&format!(
                "/forum/{}/pm/conversation/{}?error=relay_error",
                forum_hash_str, conversation_id_str
            ))
            .into_response()
        }
    }
}

/// Form for deleting a conversation.
#[derive(Debug, Deserialize)]
pub struct DeleteConversationForm {
    pub csrf_token: String,
}

/// Delete conversation handler.
pub async fn pm_delete_conversation(
    Path((forum_hash_str, conversation_id_str)): Path<(String, String)>,
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<DeleteConversationForm>,
) -> impl IntoResponse {
    // Verify CSRF token
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        return Redirect::to(&format!("/forum/{}/pm?error=invalid_csrf", forum_hash_str))
            .into_response();
    }

    // Parse conversation ID
    let conversation_id: [u8; 32] = match hex::decode(&conversation_id_str) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return Redirect::to(&format!(
                "/forum/{}/pm?error=invalid_conversation_id",
                forum_hash_str
            ))
            .into_response();
        }
    };

    // Load conversation manager and delete the conversation
    let mut conversation_manager = match app_state.forum_persistence.load_conversation_manager() {
        Ok(manager) => manager,
        Err(_) => {
            return Redirect::to(&format!("/forum/{}/pm?error=load_failed", forum_hash_str))
                .into_response();
        }
    };

    // Remove the session (this also removes message history)
    if conversation_manager
        .remove_session(&conversation_id)
        .is_none()
    {
        return Redirect::to(&format!(
            "/forum/{}/pm?error=conversation_not_found",
            forum_hash_str
        ))
        .into_response();
    }

    // Save the updated conversation manager
    if let Err(e) = app_state
        .forum_persistence
        .store_conversation_manager(&conversation_manager)
    {
        error!("Failed to save conversation manager after delete: {}", e);
        return Redirect::to(&format!("/forum/{}/pm?error=save_failed", forum_hash_str))
            .into_response();
    }

    Redirect::to(&format!(
        "/forum/{}/pm?result=conversation_deleted",
        forum_hash_str
    ))
    .into_response()
}

// =============================================================================
// Maintenance Handlers
// =============================================================================

/// Handler to recompute DAG heads for a forum.
///
/// This is useful when head tracking got corrupted (e.g., many heads when there
/// should be few). It scans all nodes and identifies true heads (nodes with no children).
pub async fn recompute_heads_handler(
    State(app_state): State<AppState>,
    Path(forum_hash_str): Path<String>,
) -> impl IntoResponse {
    let forum_hash = match ContentHash::from_hex(&forum_hash_str) {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Invalid forum hash" })),
            )
                .into_response();
        }
    };

    let persistence = &app_state.forum_persistence;

    // Get current head count for comparison
    let old_head_count = persistence
        .get_heads(&forum_hash)
        .map(|h| h.len())
        .unwrap_or(0);

    match persistence.recompute_heads(&forum_hash) {
        Ok(new_head_count) => {
            info!(
                "Recomputed heads for forum {}: {} -> {} heads",
                forum_hash.short(),
                old_head_count,
                new_head_count
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                    "forum_hash": forum_hash_str,
                    "old_head_count": old_head_count,
                    "new_head_count": new_head_count
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Failed to recompute heads: {}", e) })),
        )
            .into_response(),
    }
}
