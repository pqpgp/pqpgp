//! PQPGP Relay Server
//!
//! A relay server providing JSON-RPC 2.0 API for:
//! - Message routing between PQPGP chat users
//! - DAG-based forum system with cryptographic integrity
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
//! ```

mod forum;
mod identity;
mod peer_sync;
mod rate_limit;
mod rpc;

use axum::{
    routing::{get, post},
    Json, Router,
};
use forum::PersistentForumState;
use identity::RelayIdentity;
use rate_limit::RateLimitLayer;
use rpc::{AppState, RelayState, SharedForumState, SharedRelayState};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

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
    let args: Vec<String> = std::env::args().collect();
    let mut bind_addr = "127.0.0.1:3001".to_string();
    let mut data_dir: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                if i + 1 < args.len() {
                    bind_addr = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--data-dir" => {
                if i + 1 < args.len() {
                    data_dir = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    // Initialize relay state
    let relay_state: SharedRelayState = Arc::new(RwLock::new(RelayState::new()));

    // Load forum state from disk
    let forum_state: SharedForumState = match data_dir {
        Some(ref dir) => match PersistentForumState::with_data_dir(dir) {
            Ok(persistent) => {
                info!(
                    "Forum persistence initialized from {} with {} forums, {} nodes",
                    dir,
                    persistent.forums().len(),
                    persistent.total_nodes()
                );
                Arc::new(RwLock::new(persistent))
            }
            Err(e) => {
                error!("Failed to initialize forum persistence: {}", e);
                panic!("Failed to initialize persistent forum state: {:?}", e);
            }
        },
        None => match PersistentForumState::new() {
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
        },
    };

    // Initialize relay identity for signing heads statements
    let identity_data_dir = data_dir
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let relay_identity = match RelayIdentity::load_or_generate(&identity_data_dir) {
        Ok(identity) => {
            info!(
                "Relay identity: {} ({})",
                identity.fingerprint_short(),
                identity.fingerprint_hex()
            );
            Arc::new(identity)
        }
        Err(e) => {
            error!("Failed to initialize relay identity: {}", e);
            panic!("Cannot start relay without identity: {}", e);
        }
    };

    // Combined app state
    let app_state = AppState {
        relay: relay_state,
        forum: forum_state.clone(),
        identity: relay_identity,
    };

    // Create rate limit layer
    let rate_limit = RateLimitLayer::for_writes();

    // Build router with RPC and health endpoints
    let app = Router::new()
        .route("/rpc", post(rpc::handle_rpc))
        .route("/health", get(health_check))
        .with_state(app_state)
        .layer(rate_limit);

    // Start peer sync if configured
    let peer_sync_config = peer_sync::PeerSyncConfig::from_args();
    peer_sync::spawn_peer_sync_task(peer_sync_config, forum_state);

    // Start server
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("PQPGP Relay Server running on http://{}", bind_addr);
    info!("");
    info!("JSON-RPC 2.0 Endpoint: POST /rpc");
    info!("");
    info!("User Methods:");
    info!("  user.register   - Register user with prekey bundle");
    info!("  user.unregister - Unregister a user");
    info!("  user.get        - Get user's prekey bundle");
    info!("  user.list       - List all registered users");
    info!("");
    info!("Message Methods:");
    info!("  message.send    - Send message to recipient");
    info!("  message.fetch   - Fetch messages for recipient");
    info!("  message.check   - Check pending message count");
    info!("");
    info!("Forum Methods:");
    info!("  forum.list      - List all forums");
    info!("  forum.sync      - Get missing node hashes");
    info!("  forum.fetch     - Fetch nodes by hash");
    info!("  forum.submit    - Submit a new node");
    info!("  forum.export    - Export forum DAG (paginated)");
    info!("  forum.heads     - Get signed DAG heads (transparency)");
    info!("");
    info!("System Methods:");
    info!("  relay.health    - Health check");
    info!("  relay.stats     - Server statistics");
    info!("");
    info!("Peer Sync Options:");
    info!("  --peers <url1,url2,...>         - Peer relay URLs to sync from");
    info!("  --sync-forums <hash1,hash2,...> - Specific forums to sync (optional)");
    info!("  --sync-interval <seconds>       - Sync interval (default: 60)");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Health check response.
#[derive(serde::Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// Simple health check endpoint for load balancers and monitoring.
async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}
