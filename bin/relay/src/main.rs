//! PQPGP Message Relay Server
//!
//! A dedicated relay server for routing encrypted messages between PQPGP chat users.
//! This server stores prekey bundles for user discovery and queues encrypted messages
//! for delivery to offline recipients.
//!
//! Also provides a DAG-based forum system for public discussions with cryptographic
//! integrity guarantees.
//!
//! ## Usage
//!
//! ```bash
//! # Run with default settings (localhost:3001)
//! pqpgp-relay
//!
//! # Run on custom address
//! pqpgp-relay --bind 0.0.0.0:8080
//!
//! # Enable debug logging
//! RUST_LOG=debug pqpgp-relay
//!
//! # Sync from peer relays
//! pqpgp-relay --peers http://relay1.example.com,http://relay2.example.com
//!
//! # Sync only specific forums
//! pqpgp-relay --peers http://relay1.example.com --sync-forums <hash1>,<hash2>
//!
//! # Set sync interval (default: 60 seconds)
//! pqpgp-relay --peers http://relay1.example.com --sync-interval 120
//! ```

mod forum;
mod peer_sync;
mod rate_limit;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use forum::{PersistentForumState, SharedForumState};
use rate_limit::RateLimitLayer;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tracing::{error, info, instrument, warn};
use tracing_subscriber::EnvFilter;

/// Maximum messages to queue per recipient (prevent memory exhaustion)
const MAX_QUEUED_MESSAGES: usize = 1000;

/// Maximum message size in bytes (base64 encoded)
const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB

// ============================================================================
// Data Types
// ============================================================================

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
    /// Last seen timestamp (updated on message fetch)
    pub last_seen: u64,
}

/// A message queued for delivery
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueuedMessage {
    /// Sender's fingerprint
    pub sender_fingerprint: String,
    /// Base64-encoded encrypted message
    pub encrypted_data: String,
    /// Unix timestamp when message was received
    pub timestamp: u64,
    /// Unique message ID for deduplication
    pub message_id: String,
}

/// Request to register a user
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// User's display name
    pub name: String,
    /// User's identity fingerprint
    pub fingerprint: String,
    /// Base64-encoded prekey bundle
    pub prekey_bundle: String,
}

/// Request to send a message
#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    /// Sender's fingerprint
    pub sender_fingerprint: String,
    /// Base64-encoded encrypted message
    pub encrypted_data: String,
}

/// Response for fetching messages
#[derive(Debug, Serialize)]
pub struct FetchMessagesResponse {
    /// List of queued messages
    pub messages: Vec<QueuedMessage>,
}

/// Generic API response
#[derive(Debug, Serialize)]
pub struct ApiResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ApiResponse {
    fn success(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: Some(message.into()),
            error: None,
        }
    }

    fn error(error: impl Into<String>) -> Self {
        Self {
            success: false,
            message: None,
            error: Some(error.into()),
        }
    }
}

// ============================================================================
// Relay State
// ============================================================================

/// The relay server state
#[derive(Default)]
pub struct RelayState {
    /// Registered users by fingerprint
    users: HashMap<String, RegisteredUser>,
    /// Queued messages by recipient fingerprint
    messages: HashMap<String, VecDeque<QueuedMessage>>,
}

impl RelayState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Thread-safe relay state
type SharedRelayState = Arc<RwLock<RelayState>>;

// ============================================================================
// Handlers
// ============================================================================

/// Register a user with their prekey bundle
#[instrument(skip(state, request))]
async fn register_user(
    State(state): State<SharedRelayState>,
    Json(request): Json<RegisterRequest>,
) -> impl IntoResponse {
    // Validate fingerprint format (should be hex)
    if request.fingerprint.len() < 16 || !request.fingerprint.chars().all(|c| c.is_ascii_hexdigit())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Invalid fingerprint format")),
        );
    }

    // Validate prekey bundle is present
    if request.prekey_bundle.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Prekey bundle required")),
        );
    }

    let now = chrono::Utc::now().timestamp() as u64;

    let user = RegisteredUser {
        name: request.name.clone(),
        fingerprint: request.fingerprint.clone(),
        prekey_bundle: request.prekey_bundle,
        registered_at: now,
        last_seen: now,
    };

    let mut relay = state.write().unwrap();
    let is_update = relay.users.contains_key(&request.fingerprint);
    relay.users.insert(request.fingerprint.clone(), user);

    if is_update {
        info!(
            "Updated user registration: {} ({})",
            request.name,
            &request.fingerprint[..16]
        );
    } else {
        info!(
            "New user registered: {} ({})",
            request.name,
            &request.fingerprint[..16]
        );
    }

    (
        StatusCode::OK,
        Json(ApiResponse::success(if is_update {
            "User updated"
        } else {
            "User registered"
        })),
    )
}

/// Unregister a user
#[instrument(skip(state))]
async fn unregister_user(
    State(state): State<SharedRelayState>,
    Path(fingerprint): Path<String>,
) -> impl IntoResponse {
    let mut relay = state.write().unwrap();

    if relay.users.remove(&fingerprint).is_some() {
        // Also remove any queued messages
        relay.messages.remove(&fingerprint);
        info!(
            "User unregistered: {}",
            &fingerprint[..16.min(fingerprint.len())]
        );
        (
            StatusCode::OK,
            Json(ApiResponse::success("User unregistered")),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("User not found")),
        )
    }
}

/// List all registered users
#[instrument(skip(state))]
async fn list_users(State(state): State<SharedRelayState>) -> impl IntoResponse {
    let relay = state.read().unwrap();
    let users: Vec<RegisteredUser> = relay.users.values().cloned().collect();
    info!("Listed {} users", users.len());
    Json(users)
}

/// Get a specific user's prekey bundle
#[instrument(skip(state))]
async fn get_user(
    State(state): State<SharedRelayState>,
    Path(fingerprint): Path<String>,
) -> impl IntoResponse {
    let relay = state.read().unwrap();

    match relay.users.get(&fingerprint) {
        Some(user) => (StatusCode::OK, Json(Some(user.clone()))),
        None => (StatusCode::NOT_FOUND, Json(None)),
    }
}

/// Send a message to a recipient
#[instrument(skip(state, request))]
async fn send_message(
    State(state): State<SharedRelayState>,
    Path(recipient_fingerprint): Path<String>,
    Json(request): Json<SendMessageRequest>,
) -> impl IntoResponse {
    // Validate message size
    if request.encrypted_data.len() > MAX_MESSAGE_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ApiResponse::error("Message too large")),
        );
    }

    // Validate sender fingerprint
    if request.sender_fingerprint.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Sender fingerprint required")),
        );
    }

    let now = chrono::Utc::now().timestamp() as u64;
    let message_id = format!("{}-{}", now, rand_id());

    let message = QueuedMessage {
        sender_fingerprint: request.sender_fingerprint.clone(),
        encrypted_data: request.encrypted_data,
        timestamp: now,
        message_id,
    };

    let mut relay = state.write().unwrap();

    // Check if recipient exists (optional - could allow sending to unknown users)
    if !relay.users.contains_key(&recipient_fingerprint) {
        warn!(
            "Message sent to unregistered user: {}",
            &recipient_fingerprint[..16.min(recipient_fingerprint.len())]
        );
    }

    // Get or create message queue for recipient
    let queue = relay
        .messages
        .entry(recipient_fingerprint.clone())
        .or_default();

    // Enforce queue size limit
    if queue.len() >= MAX_QUEUED_MESSAGES {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse::error("Recipient's message queue is full")),
        );
    }

    queue.push_back(message);

    info!(
        "Queued message from {} to {}",
        &request.sender_fingerprint[..16.min(request.sender_fingerprint.len())],
        &recipient_fingerprint[..16.min(recipient_fingerprint.len())]
    );

    (StatusCode::OK, Json(ApiResponse::success("Message queued")))
}

/// Fetch messages for a recipient (and remove them from queue)
#[instrument(skip(state))]
async fn fetch_messages(
    State(state): State<SharedRelayState>,
    Path(fingerprint): Path<String>,
) -> impl IntoResponse {
    let mut relay = state.write().unwrap();

    // Update last seen timestamp
    if let Some(user) = relay.users.get_mut(&fingerprint) {
        user.last_seen = chrono::Utc::now().timestamp() as u64;
    }

    // Remove and return all queued messages
    let messages: Vec<QueuedMessage> = relay
        .messages
        .remove(&fingerprint)
        .map(|q| q.into_iter().collect())
        .unwrap_or_default();

    let count = messages.len();
    if count > 0 {
        info!(
            "Delivered {} messages to {}",
            count,
            &fingerprint[..16.min(fingerprint.len())]
        );
    }

    Json(FetchMessagesResponse { messages })
}

/// Check pending message count (without fetching)
#[instrument(skip(state))]
async fn check_messages(
    State(state): State<SharedRelayState>,
    Path(fingerprint): Path<String>,
) -> impl IntoResponse {
    let relay = state.read().unwrap();

    let count = relay
        .messages
        .get(&fingerprint)
        .map(|q| q.len())
        .unwrap_or(0);

    Json(serde_json::json!({ "pending_count": count }))
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "pqpgp-relay",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Server stats endpoint
#[instrument(skip(state))]
async fn stats(State(state): State<SharedRelayState>) -> impl IntoResponse {
    let relay = state.read().unwrap();

    let total_queued: usize = relay.messages.values().map(|q| q.len()).sum();

    Json(serde_json::json!({
        "registered_users": relay.users.len(),
        "total_queued_messages": total_queued,
        "queues_active": relay.messages.len()
    }))
}

// ============================================================================
// Helpers
// ============================================================================

/// Generate a cryptographically random ID component
fn rand_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 16] = rng.gen();
    hex::encode(random_bytes)
}

// ============================================================================
// Main
// ============================================================================

/// Combined application state containing both messaging and forum state.
#[derive(Clone)]
pub struct AppState {
    pub relay: SharedRelayState,
    pub forum: SharedForumState,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pqpgp_relay=info,tower_http=debug".into()),
        )
        .init();

    // Parse command line args
    let bind_addr = std::env::args()
        .nth(1)
        .filter(|arg| arg == "--bind")
        .and_then(|_| std::env::args().nth(2))
        .unwrap_or_else(|| "127.0.0.1:3001".to_string());

    // Initialize states
    let relay_state: SharedRelayState = Arc::new(RwLock::new(RelayState::new()));

    // Load forum state from disk (or create fresh if no data exists)
    let forum_state: SharedForumState = match PersistentForumState::new() {
        Ok(persistent) => {
            info!(
                "Forum persistence initialized with {} forums, {} nodes",
                persistent.forums().len(),
                persistent.total_nodes()
            );
            Arc::new(RwLock::new(persistent))
        }
        Err(e) => {
            error!("Failed to initialize forum persistence: {}", e);
            error!("Starting with empty forum state");
            Arc::new(RwLock::new(PersistentForumState::default()))
        }
    };

    // Create rate limit layers
    let read_rate_limit = RateLimitLayer::for_reads();
    let write_rate_limit = RateLimitLayer::for_writes();

    // Build messaging router with rate limiting
    // Write operations get more restrictive rate limits
    let messaging_write_router = Router::new()
        .route("/register", post(register_user))
        .route("/register/:fingerprint", delete(unregister_user))
        .route("/messages/:fingerprint", post(send_message))
        .with_state(relay_state.clone())
        .layer(write_rate_limit.clone());

    // Read operations get more permissive rate limits
    let messaging_read_router = Router::new()
        .route("/health", get(health_check))
        .route("/stats", get(stats))
        .route("/users", get(list_users))
        .route("/users/:fingerprint", get(get_user))
        .route("/messages/:fingerprint", get(fetch_messages))
        .route("/messages/:fingerprint/check", get(check_messages))
        .with_state(relay_state)
        .layer(read_rate_limit.clone());

    let messaging_router = Router::new()
        .merge(messaging_write_router)
        .merge(messaging_read_router);

    // Build forum router with rate limiting
    // Write operations (create forum, sync, submit nodes)
    let forum_write_router = Router::new()
        .route("/", post(forum::handlers::create_forum))
        .route("/sync", post(forum::handlers::sync_forum))
        .route("/nodes/fetch", post(forum::handlers::fetch_nodes))
        .route("/nodes/submit", post(forum::handlers::submit_node))
        .with_state(forum_state.clone())
        .layer(write_rate_limit);

    // Read operations (list forums, get forum, export, etc.)
    let forum_read_router = Router::new()
        .route("/", get(forum::handlers::list_forums))
        .route("/stats", get(forum::handlers::forum_stats))
        .route("/:hash", get(forum::handlers::get_forum))
        .route("/:hash/export", get(forum::handlers::export_forum))
        .route("/:hash/boards", get(forum::handlers::list_boards))
        .route("/:hash/moderators", get(forum::handlers::list_moderators))
        .route(
            "/:forum_hash/boards/:board_hash/moderators",
            get(forum::handlers::list_board_moderators),
        )
        .route(
            "/:forum_hash/boards/:board_hash/threads",
            get(forum::handlers::list_threads),
        )
        .route(
            "/:forum_hash/threads/:thread_hash/posts",
            get(forum::handlers::list_posts),
        )
        .with_state(forum_state.clone())
        .layer(read_rate_limit);

    let forum_router = Router::new()
        .merge(forum_write_router)
        .merge(forum_read_router);

    // Combine routers
    let app = Router::new()
        .merge(messaging_router)
        .nest("/forums", forum_router);

    // Start peer sync if configured
    let peer_sync_config = peer_sync::PeerSyncConfig::from_args();
    peer_sync::spawn_peer_sync_task(peer_sync_config, forum_state.clone());

    // Start server
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("PQPGP Relay Server running on http://{}", bind_addr);
    info!("");
    info!("Messaging Endpoints:");
    info!("  POST   /register              - Register user with prekey bundle");
    info!("  DELETE /register/:fp          - Unregister user");
    info!("  GET    /users                 - List all registered users");
    info!("  GET    /users/:fp             - Get user's prekey bundle");
    info!("  POST   /messages/:fp          - Send message to recipient");
    info!("  GET    /messages/:fp          - Fetch messages for recipient");
    info!("  GET    /messages/:fp/check    - Check pending message count");
    info!("  GET    /health                - Health check");
    info!("  GET    /stats                 - Server statistics");
    info!("");
    info!("Forum Endpoints:");
    info!("  GET    /forums                - List all forums");
    info!("  POST   /forums                - Create a new forum");
    info!("  GET    /forums/stats          - Forum statistics");
    info!("  POST   /forums/sync           - Sync request (get missing hashes)");
    info!("  POST   /forums/nodes/fetch    - Fetch nodes by hash");
    info!("  POST   /forums/nodes/submit   - Submit a new node");
    info!("  GET    /forums/:hash          - Get forum details");
    info!("  GET    /forums/:hash/export   - Export entire forum DAG");
    info!("  GET    /forums/:hash/boards   - List boards in forum");
    info!("  GET    /forums/:fh/boards/:bh/threads - List threads");
    info!("  GET    /forums/:fh/threads/:th/posts  - List posts");
    info!("");
    info!("Peer Sync Options:");
    info!("  --peers <url1,url2,...>         - Peer relay URLs to sync from");
    info!("  --sync-forums <hash1,hash2,...> - Specific forums to sync (optional)");
    info!("  --sync-interval <seconds>       - Sync interval (default: 60)");

    // Use into_make_service_with_connect_info to make client IP available for rate limiting
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
