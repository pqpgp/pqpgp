//! Forum web handlers for PQPGP web interface.
//!
//! These handlers communicate with the relay server's forum API to provide
//! a web interface for viewing and participating in forums.

use crate::csrf::{get_csrf_token, validate_csrf_token, CsrfProtectedForm};
use crate::forum_persistence::ForumMetadata;
use crate::templates::{
    BoardDisplayInfo, BoardViewTemplate, ForumDisplayInfo, ForumListTemplate, ForumViewTemplate,
    ModeratorDisplayInfo, PostDisplayInfo, SigningKeyInfo, ThreadDisplayInfo, ThreadViewTemplate,
};
use crate::AppState;
use crate::SharedForumPersistence;
use axum::{
    extract::{Form, Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
};
use pqpgp::cli::utils::create_keyring_manager;
use pqpgp::crypto::Password;
use pqpgp::forum::{
    permissions::ForumPermissions,
    types::current_timestamp_millis,
    validation::{validate_node, ValidationContext},
    BoardGenesis, ContentHash, DagNode, EditNode, FetchNodesRequest, ForumGenesis, ModAction,
    ModActionNode, Post, SyncRequest, SyncResponse, ThreadRoot,
};
use std::collections::{HashMap, HashSet};

// =============================================================================
// Security Constants
// =============================================================================

/// Maximum recursion depth for sync (prevents infinite loops from malicious relays).
const MAX_SYNC_DEPTH: usize = 100;

/// Maximum post body size (100KB) - matches library validation.
const MAX_POST_BODY_SIZE: usize = 100 * 1024;

/// Maximum thread title size (512 bytes) - matches library validation.
const MAX_THREAD_TITLE_SIZE: usize = 512;

/// Maximum thread body size (100KB) - matches library validation.
const MAX_THREAD_BODY_SIZE: usize = 100 * 1024;

/// Maximum forum/board name size (256 bytes) - matches library validation.
const MAX_NAME_SIZE: usize = 256;

/// Maximum forum/board description size (10KB) - matches library validation.
const MAX_DESCRIPTION_SIZE: usize = 10 * 1024;

/// Maximum fingerprint/hash input size (128 hex chars is more than enough for any hash).
const MAX_HASH_INPUT_SIZE: usize = 128;

/// Maximum password size (reasonable limit for password fields).
const MAX_PASSWORD_SIZE: usize = 1024;

/// Maximum tags input size (reasonable limit for comma-separated tags).
const MAX_TAGS_SIZE: usize = 1024;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use tracing::{error, info, warn};

/// Relay URL - should match the relay server
const DEFAULT_RELAY_URL: &str = "http://127.0.0.1:3001";

fn get_relay_url() -> String {
    std::env::var("PQPGP_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string())
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

    let client = Client::new();
    let relay_url = get_relay_url();

    // Step 1: Build sync request with known heads
    let known_heads = persistence.get_heads(forum_hash)?;
    let sync_request = SyncRequest::with_heads(*forum_hash, known_heads.into_iter().collect());

    info!(
        "Syncing forum {}: sending {} known heads (depth {})",
        forum_hash.short(),
        sync_request.known_heads.len(),
        depth
    );

    // Step 2: Send sync request to relay
    let sync_response: SyncResponse = client
        .post(format!("{}/forums/sync", relay_url))
        .json(&sync_request)
        .send()
        .await
        .map_err(|e| format!("Failed to send sync request: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse sync response: {}", e))?;

    // Step 3: Filter out nodes we already have and deduplicate
    let mut nodes_to_fetch: Vec<ContentHash> = Vec::new();
    let mut seen: HashSet<ContentHash> = HashSet::new();
    for hash in &sync_response.missing_hashes {
        if !seen.contains(hash) && !persistence.node_exists(forum_hash, hash).unwrap_or(false) {
            nodes_to_fetch.push(*hash);
            seen.insert(*hash);
        }
    }

    if nodes_to_fetch.is_empty() {
        info!("Forum {} is already up to date", forum_hash.short());
        // Only update heads with hashes that exist locally (security: don't trust relay blindly)
        let local_nodes = persistence.load_forum_nodes(forum_hash)?;
        let local_hashes: HashSet<ContentHash> = local_nodes.iter().map(|n| *n.hash()).collect();
        let verified_heads: HashSet<ContentHash> = sync_response
            .server_heads
            .into_iter()
            .filter(|h| local_hashes.contains(h))
            .collect();
        if !verified_heads.is_empty() {
            persistence.set_heads(forum_hash, &verified_heads)?;
        }
        return Ok(0);
    }

    info!(
        "Forum {}: fetching {} missing nodes",
        forum_hash.short(),
        nodes_to_fetch.len()
    );

    // Step 4: Fetch missing nodes
    let fetch_request = FetchNodesRequest::new(nodes_to_fetch);
    let fetch_response: pqpgp::forum::FetchNodesResponse = client
        .post(format!("{}/forums/nodes/fetch", relay_url))
        .json(&fetch_request)
        .send()
        .await
        .map_err(|e| format!("Failed to send fetch request: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse fetch response: {}", e))?;

    if !fetch_response.not_found.is_empty() {
        warn!(
            "Forum {}: {} nodes not found on relay",
            forum_hash.short(),
            fetch_response.not_found.len()
        );
    }

    // Step 5: Deserialize, deduplicate, sort topologically, validate, and store nodes
    //
    // We need to validate and store nodes in topological order so that:
    // - Parent nodes exist before children are validated
    // - Permissions are computed correctly for each node

    // First, deserialize all nodes and deduplicate by hash
    let mut deserialized_map: HashMap<ContentHash, DagNode> = HashMap::new();
    for serialized in &fetch_response.nodes {
        match serialized.deserialize() {
            Ok(node) => {
                // Deduplicate: only keep first occurrence
                deserialized_map.entry(*node.hash()).or_insert(node);
            }
            Err(e) => {
                warn!("Failed to deserialize node: {}", e);
            }
        }
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
    });

    // Load existing nodes from local storage for validation context
    let existing_nodes = persistence.load_forum_nodes(forum_hash)?;
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
        persistence.store_node(forum_hash, &node)?;

        // If this is a forum genesis, store metadata and initialize permissions
        if let Some(genesis) = node.as_forum_genesis() {
            let metadata = ForumMetadata {
                name: genesis.name().to_string(),
                description: genesis.description().to_string(),
                created_at: genesis.created_at(),
                owner_identity: genesis.creator_identity().to_vec(),
            };
            persistence.store_forum_metadata(forum_hash, &metadata)?;

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
    let verified_heads: HashSet<ContentHash> = sync_response
        .server_heads
        .into_iter()
        .filter(|h| nodes_map.contains_key(h))
        .collect();

    if !verified_heads.is_empty() {
        persistence.set_heads(forum_hash, &verified_heads)?;
    }

    info!(
        "Forum {}: synced {} nodes successfully (depth {})",
        forum_hash.short(),
        stored,
        depth
    );

    // If there are more nodes, sync again with incremented depth
    if sync_response.has_more {
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

/// Get fingerprint for a key (first 16 hex chars)
fn get_key_fingerprint(key_id: &str) -> Option<String> {
    let keyring = create_keyring_manager().ok()?;
    let key_id_num = u64::from_str_radix(key_id, 16).ok()?;
    let entries = keyring.list_all_keys();
    let (_, entry, _) = entries.iter().find(|(id, _, _)| *id == key_id_num)?;
    let fingerprint = entry.public_key.fingerprint();
    Some(hex::encode(&fingerprint[..8]))
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
) -> Result<Html<String>, StatusCode> {
    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .unwrap_or_default();

    // Get locally synced forums only
    let forums: Vec<ForumDisplayInfo> = match app_state.forum_persistence.list_forums() {
        Ok(forum_hashes) => {
            let mut forums = Vec::new();
            for hash in forum_hashes {
                if let Ok(Some(metadata)) = app_state.forum_persistence.load_forum_metadata(&hash) {
                    // Count nodes for this forum
                    let node_count = app_state
                        .forum_persistence
                        .load_forum_nodes(&hash)
                        .map(|nodes| nodes.len())
                        .unwrap_or(0);

                    forums.push(ForumDisplayInfo {
                        hash: hash.to_hex(),
                        name: metadata.name,
                        description: metadata.description,
                        node_count,
                        created_at_display: format_timestamp(metadata.created_at),
                    });
                }
            }
            forums
        }
        Err(e) => {
            warn!("Failed to list local forums: {}", e);
            Vec::new()
        }
    };

    let template = ForumListTemplate {
        active_page: "forum".to_string(),
        csrf_token,
        forums,
        signing_keys: get_signing_keys(),
        result: None,
        error: None,
        has_result: false,
        has_error: false,
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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

    // Serialize and encode
    let node = DagNode::from(genesis);
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

    // Load boards from local storage (filtering out hidden boards for non-moderators)
    let hidden_boards = app_state
        .forum_persistence
        .get_hidden_boards(&forum_content_hash)
        .unwrap_or_default();
    let boards: Vec<BoardDisplayInfo> = app_state
        .forum_persistence
        .get_boards(&forum_content_hash)
        .unwrap_or_default()
        .into_iter()
        .filter(|b| !hidden_boards.contains(b.hash()))
        .map(|b| BoardDisplayInfo {
            hash: b.hash().to_hex(),
            name: b.name().to_string(),
            description: b.description().to_string(),
            tags: b.tags().to_vec(),
            created_at_display: format_timestamp(b.created_at()),
        })
        .collect();

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
    let user_fingerprints: Vec<String> = signing_keys
        .iter()
        .map(|k| get_key_fingerprint(&k.key_id).unwrap_or_default())
        .collect();

    // Check if user is owner (exact match required for security)
    let is_owner = owner_fingerprint
        .as_ref()
        .map(|owner_fp| user_fingerprints.iter().any(|fp| fp == owner_fp))
        .unwrap_or(false);

    // Check if user is a moderator (owner or regular mod) - exact match required
    let is_moderator = mod_fingerprints
        .iter()
        .any(|mod_fp| user_fingerprints.iter().any(|fp| fp == mod_fp));

    let template = ForumViewTemplate {
        active_page: "forum".to_string(),
        csrf_token,
        forum_hash: forum_hash.clone(),
        forum_hash_short: forum_hash.chars().take(16).collect(),
        forum_name: metadata.name,
        forum_description: metadata.description,
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
    if data.tags.len() > MAX_TAGS_SIZE {
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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

    // Load threads from local storage (newest first)
    let hidden_threads = app_state
        .forum_persistence
        .get_hidden_threads(&forum_content_hash)
        .unwrap_or_default();

    let threads: Vec<ThreadDisplayInfo> = app_state
        .forum_persistence
        .get_threads(&forum_content_hash, &board_content_hash)
        .unwrap_or_default()
        .into_iter()
        .filter(|t| !hidden_threads.contains(t.hash()))
        .map(|t| {
            let post_count = app_state
                .forum_persistence
                .get_post_count(&forum_content_hash, t.hash())
                .unwrap_or(0);
            let body_preview: String = t.body().chars().take(100).collect();
            ThreadDisplayInfo {
                hash: t.hash().to_hex(),
                title: t.title().to_string(),
                body_preview,
                author_short: fingerprint_from_identity(t.author_identity()),
                post_count,
                created_at_display: format_timestamp(t.created_at()),
            }
        })
        .collect();

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
    let user_fingerprints: Vec<String> = signing_keys
        .iter()
        .filter_map(|k| get_key_fingerprint(&k.key_id))
        .collect();

    // Check if user is a forum-level moderator (can manage board moderators) - exact match required
    let is_forum_moderator = forum_mod_fingerprints
        .iter()
        .any(|mod_fp| user_fingerprints.iter().any(|fp| fp == mod_fp));

    let template = BoardViewTemplate {
        active_page: "forum".to_string(),
        csrf_token,
        forum_hash: forum_hash.clone(),
        forum_name: forum_metadata.name,
        board_hash: board_hash.clone(),
        board_name: board.name().to_string(),
        board_description: board.description().to_string(),
        board_tags: board.tags().to_vec(),
        threads,
        signing_keys,
        board_moderators,
        is_forum_moderator,
        result: None,
        error: None,
        has_result: false,
        has_error: false,
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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

    // Load posts from local storage (oldest first for chronological reading)
    let hidden_posts = app_state
        .forum_persistence
        .get_hidden_posts(&forum_content_hash)
        .unwrap_or_default();

    let posts = app_state
        .forum_persistence
        .get_posts(&forum_content_hash, &thread_content_hash)
        .unwrap_or_default();

    // Build post display info with quote resolution
    let post_displays: Vec<PostDisplayInfo> = posts
        .iter()
        .filter(|p| !hidden_posts.contains(p.hash()))
        .map(|p| {
            // Try to resolve quote
            let quote_body = p.quote_hash().and_then(|qh| {
                posts.iter().find(|other| other.hash() == qh).map(|other| {
                    let preview: String = other.body().chars().take(200).collect();
                    preview + if other.body().len() > 200 { "..." } else { "" }
                })
            });

            PostDisplayInfo {
                hash: p.hash().to_hex(),
                body: p.body().to_string(),
                author_short: fingerprint_from_identity(p.author_identity()),
                quote_body,
                created_at_display: format_timestamp(p.created_at()),
            }
        })
        .collect();

    // Load forum moderators from local storage
    let (forum_mod_fingerprints, _owner_fingerprint) = app_state
        .forum_persistence
        .get_forum_moderators(&forum_content_hash)
        .unwrap_or_default();

    // Get user's signing keys to check if they're a moderator
    let signing_keys = get_signing_keys();
    let user_fingerprints: Vec<String> = signing_keys
        .iter()
        .filter_map(|k| get_key_fingerprint(&k.key_id))
        .collect();

    // Check if user is a moderator (owner or regular mod) - exact match required
    let is_moderator = forum_mod_fingerprints
        .iter()
        .any(|mod_fp| user_fingerprints.iter().any(|fp| fp == mod_fp));

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
        .map(|b| BoardDisplayInfo {
            hash: b.hash().to_hex(),
            name: b.name().to_string(),
            description: b.description().to_string(),
            tags: b.tags().to_vec(),
            created_at_display: format_timestamp(b.created_at()),
        })
        .collect();

    let template = ThreadViewTemplate {
        active_page: "forum".to_string(),
        csrf_token,
        forum_hash: forum_hash.clone(),
        forum_name: forum_metadata.name,
        board_hash: board.hash().to_hex(),
        board_name: board.name().to_string(),
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
    {
        warn!("Password too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .quote_hash
        .as_ref()
        .map_or(false, |h| h.len() > MAX_HASH_INPUT_SIZE)
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
    let client = Client::new();
    let relay_url = get_relay_url();

    let forum_content_hash = match ContentHash::from_hex(forum_hash) {
        Ok(h) => h,
        Err(e) => {
            error!("Invalid forum hash for heads fetch: {}", e);
            return vec![];
        }
    };

    // Use sync endpoint with empty known_heads to get server's current heads
    let request = pqpgp::forum::SyncRequest::new(forum_content_hash);

    match client
        .post(format!("{}/forums/sync", relay_url))
        .json(&request)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<pqpgp::forum::SyncResponse>().await {
                    Ok(sync_resp) => {
                        info!(
                            "Got {} DAG heads for forum {}",
                            sync_resp.server_heads.len(),
                            forum_hash
                        );
                        sync_resp.server_heads
                    }
                    Err(e) => {
                        error!("Failed to parse sync response: {}", e);
                        vec![]
                    }
                }
            } else {
                warn!("Sync request failed: {:?}", resp.status());
                vec![]
            }
        }
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
    if let Err(e) = persistence.store_node(&forum_content_hash, &node) {
        warn!("Failed to store node locally: {}", e);
    } else {
        // Update local heads
        if let Err(e) = persistence.update_heads_for_node(&forum_content_hash, &node) {
            warn!("Failed to update local heads: {}", e);
        }
    }

    // Step 3: Submit to relay (best effort - relay might be unavailable)
    let client = Client::new();
    let relay_url = get_relay_url();

    let request = match pqpgp::forum::SubmitNodeRequest::new(forum_content_hash, &node) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create submit request: {}", e);
            return;
        }
    };

    match client
        .post(format!("{}/forums/nodes/submit", relay_url))
        .json(&request)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                info!(
                    "Node {} submitted to relay successfully",
                    node.hash().short()
                );
            } else {
                warn!(
                    "Node {} submission to relay failed: {:?}",
                    node.hash().short(),
                    resp.status()
                );
            }
        }
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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

    // Redirect back to the board (since the thread is now hidden)
    // We need to find the board hash - for now redirect to forum
    Redirect::to(&format!("/forum/{}", forum_hash)).into_response()
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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
        .map_or(false, |n| n.len() > MAX_NAME_SIZE)
    {
        warn!("New name too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .new_description
        .as_ref()
        .map_or(false, |d| d.len() > MAX_DESCRIPTION_SIZE)
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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
        .map_or(false, |n| n.len() > MAX_NAME_SIZE)
    {
        warn!("New name too large");
        return Redirect::to(&redirect_url).into_response();
    }
    if data
        .new_description
        .as_ref()
        .map_or(false, |d| d.len() > MAX_DESCRIPTION_SIZE)
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
        .map_or(false, |p| p.len() > MAX_PASSWORD_SIZE)
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

    // Check if forum exists on the relay first
    let client = Client::new();
    let relay_url = get_relay_url();

    match client
        .get(format!("{}/forums/{}", relay_url, forum_hash_str))
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status() == StatusCode::NOT_FOUND {
                warn!("Forum not found on relay: {}", forum_hash_str);
                return Redirect::to("/forum").into_response();
            } else if !resp.status().is_success() {
                error!("Error checking forum: {:?}", resp.status());
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
