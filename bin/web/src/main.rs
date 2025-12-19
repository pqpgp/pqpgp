//! Web server binary for PQPGP - provides a web interface for post-quantum cryptographic operations.

use askama::Template;
use axum::http::{header, HeaderValue};
use axum::{
    extract::{Form, Multipart, Path as AxumPath, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use pqpgp::{
    armor::{create_signed_message, decode, encode, ArmorType},
    cli::utils::create_keyring_manager,
    crypto::{
        decrypt_message, encrypt_message, sign_message, verify_signature, Algorithm, KeyPair,
        Password,
    },
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};
use tracing::{error, info, instrument, warn};
use tracing_subscriber::EnvFilter;

mod chat_state;
mod csrf;
mod handlers;
mod rate_limiter;
mod relay_client;
mod storage;
mod templates;
use chat_state::{create_shared_state_manager, SharedChatStateManager};
use csrf::{get_csrf_token, validate_csrf_token, CsrfProtectedForm, CsrfStore};
use pqpgp::forum::ForumStorage;
use rate_limiter::PmRateLimiterSet;
use relay_client::{create_relay_client, SharedRelayClient};
use storage::ChatStorage;
use templates::{FilesTemplate, SigningKeyInfo, *};

/// Shared forum persistence for local DAG storage.
pub type SharedForumPersistence = Arc<ForumStorage>;

/// Default forum sync interval in seconds.
const FORUM_SYNC_INTERVAL_SECS: u64 = 30;

/// Form data for key generation
#[derive(Debug, Deserialize)]
struct GenerateKeyForm {
    algorithm: String,
    user_id: String,
    use_password: Option<String>,
    password: Option<String>,
    password_confirm: Option<String>,
}

/// Form data for encryption
#[derive(Debug, Deserialize)]
struct EncryptForm {
    recipient: String,
    message: String,
    signing_key: Option<String>,
    password: Option<String>,
}

/// Form data for decryption
#[derive(Debug, Deserialize)]
struct DecryptForm {
    encrypted_message: String,
    password: Option<String>,
}

/// Form data for signing
#[derive(Debug, Deserialize)]
struct SignForm {
    key_id: String,
    message: String,
    password: Option<String>,
}

/// Form data for verification
#[derive(Debug, Deserialize)]
struct VerifyForm {
    message: String,
    signature: String,
}

/// Form data for adding a chat contact
#[derive(Debug, Deserialize)]
struct AddContactForm {
    name: String,
    prekey_bundle: String,
}

/// Form data for sending a chat message
#[derive(Debug, Deserialize)]
struct SendMessageForm {
    recipient: String,
    message: String,
}

/// Form data for fetching messages (preserves current contact)
#[derive(Debug, Deserialize)]
struct FetchMessagesForm {
    current_contact: Option<String>,
}

/// Form data for generating a chat identity with password protection
#[derive(Debug, Deserialize)]
struct GenerateChatIdentityForm {
    password: String,
}

/// Form data for unlocking a saved chat identity
#[derive(Debug, Deserialize)]
struct UnlockIdentityForm {
    fingerprint: String,
    password: String,
}

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub csrf_store: CsrfStore,
    pub chat_states: SharedChatStateManager,
    /// Client for communicating with the dedicated relay server
    pub relay_client: SharedRelayClient,
    /// Forum persistence for local DAG storage
    pub forum_persistence: SharedForumPersistence,
    /// Rate limiters for PM operations (DoS prevention)
    pub pm_rate_limiters: PmRateLimiterSet,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("csrf_store", &"CsrfStore { ... }")
            .field("chat_states", &"SharedChatStateManager { ... }")
            .field("relay_client", &"SharedRelayClient { ... }")
            .field("forum_persistence", &"SharedForumPersistence { ... }")
            .field("pm_rate_limiters", &"PmRateLimiterSet { ... }")
            .finish()
    }
}

/// Background task that periodically syncs all locally-tracked forums.
async fn forum_sync_task(persistence: SharedForumPersistence) {
    let interval = Duration::from_secs(
        std::env::var("PQPGP_FORUM_SYNC_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(FORUM_SYNC_INTERVAL_SECS),
    );

    info!(
        "Forum sync task started with {}s interval",
        interval.as_secs()
    );

    // Use interval timer that ticks immediately on first call
    let mut interval_timer = tokio::time::interval(interval);

    loop {
        interval_timer.tick().await;

        // Get list of locally-tracked forums
        let forums = match persistence.list_forums() {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to list forums for sync: {}", e);
                continue;
            }
        };

        if forums.is_empty() {
            continue;
        }

        info!("Syncing {} forum(s)...", forums.len());

        for forum_hash in forums {
            match handlers::forum::sync_forum(&persistence, &forum_hash).await {
                Ok(count) => {
                    if count > 0 {
                        info!(
                            "Synced {} new node(s) for forum {}",
                            count,
                            forum_hash.short()
                        );
                    }
                }
                Err(e) => {
                    warn!("Failed to sync forum {}: {}", forum_hash.short(), e);
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pqpgp=info,tower_http=debug".into()),
        )
        .init();

    // Get relay server URL from environment or use default
    let relay_url = std::env::var("PQPGP_RELAY_URL").ok();
    if let Some(ref url) = relay_url {
        info!("Using relay server at: {}", url);
    } else {
        info!(
            "Using default relay server at: {}",
            relay_client::DEFAULT_RELAY_URL
        );
    }

    // Initialize CSRF store, chat state manager, and relay client
    let csrf_store = CsrfStore::new();
    let chat_states = create_shared_state_manager();
    let relay_client = create_relay_client(relay_url);

    // Initialize forum persistence using RocksDB
    let forum_data_path =
        std::env::var("PQPGP_FORUM_DATA").unwrap_or_else(|_| "pqpgp_forum_data".to_string());
    let forum_persistence = Arc::new(
        ForumStorage::new(&forum_data_path).expect("Failed to initialize forum persistence"),
    );
    info!("Forum data stored in: {}", forum_data_path);

    let app_state = AppState {
        csrf_store,
        chat_states,
        relay_client,
        forum_persistence: forum_persistence.clone(),
        pm_rate_limiters: PmRateLimiterSet::default(),
    };

    // Set up session management
    // SECURITY FIX: Detect HTTPS mode from environment and set secure cookie flag accordingly
    // Set PQPGP_SECURE_COOKIES=true when deploying behind HTTPS
    let use_secure_cookies = std::env::var("PQPGP_SECURE_COOKIES")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    if use_secure_cookies {
        info!("Secure cookies enabled - cookies will only be sent over HTTPS");
    } else {
        warn!("Secure cookies disabled - set PQPGP_SECURE_COOKIES=true for production");
    }

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(use_secure_cookies)
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_name("pqpgp-session")
        .with_http_only(true);

    // Build our application with routes
    let app = Router::new()
        .route("/", get(index))
        .route("/keys", get(list_keys))
        .route("/keys/generate", post(generate_key))
        .route("/keys/delete/:key_id", post(delete_key))
        .route("/keys/export/:key_id", get(export_public_key))
        .route("/keys/view/:key_id", get(view_public_key))
        .route("/keys/import", post(import_public_key))
        .route("/encrypt", get(encrypt_page).post(encrypt_handler))
        .route("/decrypt", get(decrypt_page).post(decrypt_handler))
        .route("/sign", get(sign_page).post(sign_handler))
        .route("/verify", get(verify_page).post(verify_handler))
        .route("/files", get(files_page))
        .route("/files/encrypt", post(encrypt_file_handler))
        .route("/files/decrypt", post(decrypt_file_handler))
        .route("/files/download", get(download_decrypted_file))
        .route("/chat", get(chat_page))
        .route("/chat/add-contact", post(add_chat_contact))
        .route(
            "/chat/delete-contact/:fingerprint",
            post(delete_chat_contact),
        )
        .route("/chat/send", post(send_chat_message))
        .route("/chat/generate-identity", post(generate_chat_identity))
        .route("/chat/unlock-identity", post(unlock_chat_identity))
        .route("/chat/logout", post(logout_chat_identity))
        .route("/chat/fetch-messages", post(fetch_relay_messages))
        .route("/chat/users", get(list_relay_users))
        // Forum routes
        .route(
            "/forum",
            get(handlers::forum::forum_list_page).post(handlers::forum::create_forum_handler),
        )
        .route("/forum/join", post(handlers::forum::join_forum_handler))
        .route("/forum/:forum_hash", get(handlers::forum::forum_view_page))
        .route(
            "/forum/:forum_hash/board/create",
            post(handlers::forum::create_board_handler),
        )
        .route(
            "/forum/:forum_hash/moderator/add",
            post(handlers::forum::add_moderator_handler),
        )
        .route(
            "/forum/:forum_hash/moderator/remove",
            post(handlers::forum::remove_moderator_handler),
        )
        .route(
            "/forum/:forum_hash/board/:board_hash",
            get(handlers::forum::board_view_page),
        )
        .route(
            "/forum/:forum_hash/board/:board_hash/moderator/add",
            post(handlers::forum::add_board_moderator_handler),
        )
        .route(
            "/forum/:forum_hash/board/:board_hash/moderator/remove",
            post(handlers::forum::remove_board_moderator_handler),
        )
        .route(
            "/forum/:forum_hash/board/:board_hash/thread/create",
            post(handlers::forum::create_thread_handler),
        )
        .route(
            "/forum/:forum_hash/thread/:thread_hash",
            get(handlers::forum::thread_view_page),
        )
        .route(
            "/forum/:forum_hash/thread/:thread_hash/reply",
            post(handlers::forum::post_reply_handler),
        )
        .route(
            "/forum/:forum_hash/thread/:thread_hash/hide",
            post(handlers::forum::hide_thread_handler),
        )
        .route(
            "/forum/:forum_hash/thread/:thread_hash/hide_post",
            post(handlers::forum::hide_post_handler),
        )
        .route(
            "/forum/:forum_hash/thread/:thread_hash/move",
            get(handlers::forum::move_thread_page_handler)
                .post(handlers::forum::move_thread_handler),
        )
        .route(
            "/forum/:forum_hash/edit",
            post(handlers::forum::edit_forum_handler),
        )
        .route(
            "/forum/:forum_hash/remove",
            post(handlers::forum::remove_forum_handler),
        )
        .route(
            "/forum/:forum_hash/board/:board_hash/edit",
            post(handlers::forum::edit_board_handler),
        )
        .route(
            "/forum/:forum_hash/board/:board_hash/hide",
            post(handlers::forum::hide_board_handler),
        )
        .route(
            "/forum/:forum_hash/board/:board_hash/unhide",
            post(handlers::forum::unhide_board_handler),
        )
        // Private message routes
        .route("/forum/:forum_hash/pm", get(handlers::forum::pm_inbox_page))
        .route(
            "/forum/:forum_hash/pm/identity/create",
            post(handlers::forum::create_encryption_identity_handler),
        )
        .route(
            "/forum/:forum_hash/pm/send",
            post(handlers::forum::send_pm_handler),
        )
        .route(
            "/forum/:forum_hash/pm/scan",
            post(handlers::forum::scan_pm_handler),
        )
        .route(
            "/forum/:forum_hash/pm/compose",
            get(handlers::forum::pm_compose_page),
        )
        .route(
            "/forum/:forum_hash/pm/conversation/:conversation_id",
            get(handlers::forum::pm_conversation_page),
        )
        .route(
            "/forum/:forum_hash/pm/conversation/:conversation_id/reply",
            post(handlers::forum::reply_pm_handler),
        )
        .route(
            "/forum/:forum_hash/pm/conversation/:conversation_id/delete",
            post(handlers::forum::pm_delete_conversation),
        )
        // Maintenance endpoints
        .route(
            "/forum/:forum_hash/recompute-heads",
            post(handlers::forum::recompute_heads_handler),
        )
        .nest_service("/static", ServeDir::new("src/web/static"))
        .layer(session_layer)
        // Security headers to prevent common attacks
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_XSS_PROTECTION,
            HeaderValue::from_static("1; mode=block"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .with_state(app_state);

    // Spawn background forum sync task
    tokio::spawn(forum_sync_task(forum_persistence));

    let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
    info!("🚀 PQPGP Web Interface running on http://127.0.0.1:3000");

    axum::serve(listener, app).await.unwrap();
    Ok(())
}

/// Home page
async fn index() -> std::result::Result<Html<String>, StatusCode> {
    let template = IndexTemplate {
        active_page: "home".to_string(),
    };
    Ok(Html(template.render().map_err(|e| {
        error!("Failed to render index template: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// List all keys
async fn list_keys(
    State(app_state): State<AppState>,
    session: Session,
) -> std::result::Result<Html<String>, StatusCode> {
    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager: {:?}", e);
            // For list_keys, we'll show empty list with an error message in the template
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = KeysTemplate {
                keys: vec![],
                active_page: "keys".to_string(),
                result: None,
                error: None,
                has_result: false,
                has_error: false,
                csrf_token,
            };
            return Ok(Html(template.render().map_err(|e| {
                error!("Template rendering failed: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?));
        }
    };

    let entries = keyring.list_all_keys();
    info!("Found {} keys in keyring", entries.len());

    let keys: Vec<KeyInfo> = entries
        .into_iter()
        .map(|(key_id, entry, has_private)| {
            let is_password_protected = if has_private {
                keyring
                    .get_private_key(key_id)
                    .map(|private_key| private_key.is_encrypted())
                    .unwrap_or(false)
            } else {
                false
            };

            // Compute fingerprint (first 16 hex chars of SHA3-512 hash)
            let fp = entry.public_key.fingerprint();
            let fingerprint = hex::encode(&fp[..8]);

            KeyInfo {
                key_id: format!("{:016X}", key_id),
                fingerprint,
                algorithm: entry.public_key.algorithm().to_string(),
                user_ids: entry.user_ids.clone(),
                has_private_key: has_private,
                is_password_protected,
            }
        })
        .collect();

    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .map_err(|_| {
            error!("Failed to generate CSRF token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let template = KeysTemplate {
        keys,
        active_page: "keys".to_string(),
        result: None,
        error: None,
        has_result: false,
        has_error: false,
        csrf_token,
    };
    Ok(Html(template.render().map_err(|e| {
        error!("Template rendering failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// Generate a new key
#[instrument(skip(form), fields(algorithm = %form.data.algorithm, user_id = %form.data.user_id))]
async fn generate_key(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<GenerateKeyForm>>,
) -> std::result::Result<Redirect, StatusCode> {
    // Validate CSRF token
    if !form.validate(&session, &app_state.csrf_store) {
        warn!("CSRF validation failed for key generation");
        return Err(StatusCode::FORBIDDEN);
    }
    let mut keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!(
                "Failed to create keyring manager during key generation: {:?}",
                e
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let algorithm = match form.data.algorithm.as_str() {
        "mlkem1024" => Algorithm::Mlkem1024,
        "mldsa87" => Algorithm::Mldsa87,
        _ => {
            error!("Invalid algorithm specified: {}", form.data.algorithm);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Check password validation if password protection is requested
    let password = if form.data.use_password.is_some() {
        let pwd = form.data.password.as_ref().ok_or_else(|| {
            error!("Password protection requested but no password provided");
            StatusCode::BAD_REQUEST
        })?;
        let pwd_confirm = form.data.password_confirm.as_ref().ok_or_else(|| {
            error!("Password protection requested but no password confirmation provided");
            StatusCode::BAD_REQUEST
        })?;

        if pwd.is_empty() {
            error!("Empty password provided for key protection");
            return Err(StatusCode::BAD_REQUEST);
        }
        if pwd != pwd_confirm {
            error!("Password and confirmation do not match");
            return Err(StatusCode::BAD_REQUEST);
        }

        Some(Password::new(pwd.clone()))
    } else {
        None
    };

    info!(
        "Generating {} key pair for user: {}",
        algorithm, form.data.user_id
    );

    // Generate key pair
    let mut keypair = match algorithm {
        Algorithm::Mlkem1024 => KeyPair::generate_mlkem1024(),
        Algorithm::Mldsa87 => KeyPair::generate_mldsa87(),
        _ => {
            error!("Unsupported algorithm for key generation: {:?}", algorithm);
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    .map_err(|e| {
        error!("Failed to generate key pair: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Encrypt private key with password if requested
    if let Some(ref pwd) = password {
        keypair
            .private_key_mut()
            .encrypt_with_password(pwd)
            .map_err(|e| {
                error!("Failed to encrypt private key with password: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        info!("Private key encrypted with password protection");
    }

    // Add to keyring
    keyring
        .add_keypair(&keypair, Some(form.data.user_id.clone()))
        .map_err(|e| {
            error!("Failed to add keypair to keyring: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    keyring.save().map_err(|e| {
        error!("Failed to save keyring after adding new key: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        key_id = format!("{:016X}", keypair.key_id()),
        password_protected = password.is_some(),
        user_id = %form.data.user_id,
        "Key pair generated and saved successfully"
    );

    Ok(Redirect::to("/keys"))
}

/// Delete a key
async fn delete_key(
    AxumPath(key_id_str): AxumPath<String>,
) -> std::result::Result<Redirect, StatusCode> {
    let key_id = u64::from_str_radix(&key_id_str, 16).map_err(|e| {
        error!(
            "Invalid key ID format for deletion '{}': {:?}",
            key_id_str, e
        );
        StatusCode::BAD_REQUEST
    })?;

    let mut keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!(
                "Failed to create keyring manager during key deletion: {:?}",
                e
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    info!("Attempting to delete key with ID: {:016X}", key_id);

    // Remove from both public and private keyrings
    let public_removed = keyring.public_keyring.remove_key(key_id).is_ok();
    let private_removed = keyring.private_keyring.remove_key(key_id).is_ok();

    if !public_removed && !private_removed {
        warn!(
            "Key {:016X} not found in either public or private keyring",
            key_id
        );
        // Still continue to save and redirect - key might have been already deleted
    } else {
        info!(
            "Key {:016X} removed from keyring (public: {}, private: {})",
            key_id, public_removed, private_removed
        );
    }

    keyring.save().map_err(|e| {
        error!(
            "Failed to save keyring after deleting key {:016X}: {:?}",
            key_id, e
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        "Key deletion completed successfully for key ID: {:016X}",
        key_id
    );
    Ok(Redirect::to("/keys"))
}

/// Export a public key as armored text
async fn export_public_key(
    AxumPath(key_id_str): AxumPath<String>,
) -> std::result::Result<axum::response::Response, StatusCode> {
    let key_id = u64::from_str_radix(&key_id_str, 16).map_err(|e| {
        error!("Invalid key ID format for export '{}': {:?}", key_id_str, e);
        StatusCode::BAD_REQUEST
    })?;

    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!(
                "Failed to create keyring manager during key export: {:?}",
                e
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    info!("Exporting public key with ID: {:016X}", key_id);

    // Export the public key
    let exported = keyring.public_keyring.export_key(key_id).map_err(|e| {
        error!("Failed to export public key {:016X}: {:?}", key_id, e);
        StatusCode::NOT_FOUND
    })?;

    let armored = encode(&exported, ArmorType::PublicKey).map_err(|e| {
        error!("Failed to armor public key {:016X}: {:?}", key_id, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Public key {:016X} exported successfully", key_id);

    // Return as downloadable file
    use axum::http::header;
    let response = axum::response::Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}.asc\"", key_id_str),
        )
        .body(axum::body::Body::from(armored))
        .map_err(|e| {
            error!("Failed to create response for key export: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

/// View a public key in the browser
async fn view_public_key(
    AxumPath(key_id_str): AxumPath<String>,
) -> std::result::Result<Html<String>, StatusCode> {
    let key_id = u64::from_str_radix(&key_id_str, 16).map_err(|e| {
        error!("Invalid key ID format for view '{}': {:?}", key_id_str, e);
        StatusCode::BAD_REQUEST
    })?;

    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager during key view: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    info!("Viewing public key with ID: {:016X}", key_id);

    // Find key entry
    let all_entries = keyring.list_all_keys();
    let key_entry = all_entries
        .iter()
        .find(|(entry_key_id, _entry, _has_private)| *entry_key_id == key_id)
        .map(|(_, entry, _)| entry)
        .ok_or_else(|| {
            error!("Key not found for ID: {:016X}", key_id);
            StatusCode::NOT_FOUND
        })?;

    // Export the public key
    let exported = keyring.public_keyring.export_key(key_id).map_err(|e| {
        error!("Failed to export public key {:016X}: {:?}", key_id, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let armored = encode(&exported, ArmorType::PublicKey).map_err(|e| {
        error!("Failed to armor public key {:016X}: {:?}", key_id, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Public key {:016X} viewed successfully", key_id);

    let template = ViewPublicKeyTemplate {
        key_id: format!("{:016X}", key_id),
        algorithm: key_entry.public_key.algorithm().to_string(),
        user_ids: key_entry.user_ids.clone(),
        public_key_armored: armored,
        active_page: "keys".to_string(),
    };

    Ok(Html(template.render().map_err(|e| {
        error!("Failed to render view public key template: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// Import a public key from multipart form data
#[instrument]
async fn import_public_key(
    mut multipart: Multipart,
) -> std::result::Result<Html<String>, StatusCode> {
    // Helper function to create keys template with message
    let create_keys_template =
        |result: Option<String>, error: Option<String>| -> Result<Html<String>, StatusCode> {
            let keyring = match create_keyring_manager() {
                Ok(kr) => kr,
                Err(e) => {
                    error!("Failed to create keyring manager: {:?}", e);
                    let template = KeysTemplate {
                        keys: vec![],
                        active_page: "keys".to_string(),
                        result: None,
                        error: Some("Failed to access key storage".to_string()),
                        has_result: false,
                        has_error: true,
                        csrf_token: String::new(),
                    };
                    return Ok(Html(
                        template
                            .render()
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                    ));
                }
            };

            let entries = keyring.list_all_keys();
            let keys: Vec<KeyInfo> = entries
                .into_iter()
                .map(|(key_id, entry, has_private)| {
                    let is_password_protected = if has_private {
                        keyring
                            .get_private_key(key_id)
                            .map(|private_key| private_key.is_encrypted())
                            .unwrap_or(false)
                    } else {
                        false
                    };

                    // Compute fingerprint (first 16 hex chars of SHA3-512 hash)
                    let fp = entry.public_key.fingerprint();
                    let fingerprint = hex::encode(&fp[..8]);

                    KeyInfo {
                        key_id: format!("{:016X}", key_id),
                        fingerprint,
                        algorithm: entry.public_key.algorithm().to_string(),
                        user_ids: entry.user_ids.clone(),
                        has_private_key: has_private,
                        is_password_protected,
                    }
                })
                .collect();

            let has_result = result.is_some();
            let has_error = error.is_some();

            let template = KeysTemplate {
                keys,
                active_page: "keys".to_string(),
                result,
                error,
                has_result,
                has_error,
                csrf_token: String::new(),
            };

            Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ))
        };

    let mut keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!(
                "Failed to create keyring manager during key import: {:?}",
                e
            );
            return create_keys_template(None, Some("Failed to access key storage".to_string()));
        }
    };

    info!("Processing multipart form for public key import");

    let mut public_key_text = String::new();
    let mut file_data = Vec::new();

    // Process multipart fields
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        error!("Failed to read multipart field: {:?}", e);
        StatusCode::BAD_REQUEST
    })? {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "public_key" => {
                public_key_text = field.text().await.map_err(|e| {
                    error!("Failed to read public key text: {:?}", e);
                    StatusCode::BAD_REQUEST
                })?;
            }
            "key_file" => {
                file_data = field
                    .bytes()
                    .await
                    .map_err(|e| {
                        error!("Failed to read key file data: {:?}", e);
                        StatusCode::BAD_REQUEST
                    })?
                    .to_vec();
            }
            _ => {
                // Skip unknown fields
                continue;
            }
        }
    }

    // Determine which data to use - prefer text input if both are provided
    let key_input = if !public_key_text.trim().is_empty() {
        info!("Using pasted public key text");
        public_key_text
    } else if !file_data.is_empty() {
        info!("Using uploaded key file");
        String::from_utf8(file_data).map_err(|e| {
            error!("Key file contains invalid UTF-8: {:?}", e);
            StatusCode::BAD_REQUEST
        })?
    } else {
        error!("No public key data provided");
        return create_keys_template(
            None,
            Some("No public key data provided. Please paste a key or select a file.".to_string()),
        );
    };

    // Try to decode as ASCII armor first
    let key_data = match decode(&key_input) {
        Ok(armored_data) => {
            info!("Successfully decoded armored public key");
            armored_data.data
        }
        Err(e) => {
            warn!(
                "Failed to decode as armored data, trying as binary: {:?}",
                e
            );
            // If it's not armored, try as binary data
            key_input.as_bytes().to_vec()
        }
    };

    // Import the key
    let (result_msg, error_msg) = match keyring.public_keyring.import_key(&key_data) {
        Ok(_) => {
            info!("Successfully imported new public key");
            (
                Some("✅ Public key imported successfully".to_string()),
                None,
            )
        }
        Err(e) => {
            let error_msg = format!("{:?}", e);
            if error_msg.contains("already exists") {
                info!("Public key already exists in keyring, skipping duplicate import");
                (None, Some("Key already exists in your keyring".to_string()))
            } else {
                error!("Failed to import public key: {:?}", e);
                (
                    None,
                    Some(
                        "Failed to import public key. Please check the format and try again."
                            .to_string(),
                    ),
                )
            }
        }
    };

    if error_msg.is_some() {
        return create_keys_template(result_msg, error_msg);
    }

    keyring.save().map_err(|e| {
        error!("Failed to save keyring after importing key: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Public key import process completed");
    create_keys_template(result_msg, error_msg)
}

/// Encryption page
async fn encrypt_page(
    State(app_state): State<AppState>,
    session: Session,
) -> std::result::Result<Html<String>, StatusCode> {
    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager for encrypt page: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = EncryptTemplate {
                recipients: vec![],
                signing_keys: vec![],
                result: None,
                error: None,
                has_result: false,
                has_error: false,
                active_page: "encrypt".to_string(),
                csrf_token,
            };
            return Ok(Html(template.render().map_err(|e| {
                error!("Failed to render encrypt template with error: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?));
        }
    };

    let entries = keyring.list_all_keys();

    let recipients: Vec<RecipientInfo> = entries
        .iter()
        .filter(|(_, entry, _)| entry.public_key.algorithm() == Algorithm::Mlkem1024)
        .map(|(key_id, entry, _)| RecipientInfo {
            key_id: format!("{:016X}", key_id),
            user_id: entry.user_ids.first().cloned().unwrap_or_default(),
        })
        .collect();

    let signing_keys: Vec<SigningKeyInfo> = entries
        .into_iter()
        .filter(|(_, entry, has_private)| {
            *has_private && entry.public_key.algorithm() == Algorithm::Mldsa87
        })
        .map(|(key_id, entry, _)| {
            let fingerprint = entry.public_key.fingerprint();
            SigningKeyInfo {
                key_id: format!("{:016X}", key_id),
                user_id: entry.user_ids.first().cloned().unwrap_or_default(),
                fingerprint: hex::encode(&fingerprint[..8]),
            }
        })
        .collect();

    info!(
        "Encrypt page loaded with {} recipients and {} signing keys",
        recipients.len(),
        signing_keys.len()
    );

    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .map_err(|_| {
            error!("Failed to generate CSRF token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let template = EncryptTemplate {
        recipients,
        signing_keys,
        result: None,
        error: None,
        has_result: false,
        has_error: false,
        active_page: "encrypt".to_string(),
        csrf_token,
    };
    Ok(Html(template.render().map_err(|e| {
        error!("Failed to render encrypt template: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// Encrypt a message
#[instrument(skip(form), fields(recipient = %form.data.recipient, message_len = form.data.message.len()))]
async fn encrypt_handler(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<EncryptForm>>,
) -> std::result::Result<Html<String>, StatusCode> {
    // Validate CSRF token
    if !form.validate(&session, &app_state.csrf_store) {
        warn!("CSRF validation failed for encryption");
        return Err(StatusCode::FORBIDDEN);
    }
    // Helper function to create error template
    let create_error_template = |error_msg: String,
                                 all_entries: &[(u64, &pqpgp::keyring::KeyEntry, bool)],
                                 csrf_token: String|
     -> EncryptTemplate {
        let recipients: Vec<RecipientInfo> = all_entries
            .iter()
            .filter(|(_, entry, _)| entry.public_key.algorithm() == Algorithm::Mlkem1024)
            .map(|(key_id, entry, _)| RecipientInfo {
                key_id: format!("{:016X}", key_id),
                user_id: entry.user_ids.first().cloned().unwrap_or_default(),
            })
            .collect();

        let signing_keys: Vec<SigningKeyInfo> = all_entries
            .iter()
            .filter(|(_, entry, has_private)| {
                *has_private && entry.public_key.algorithm() == Algorithm::Mldsa87
            })
            .map(|(key_id, entry, _)| {
                let fingerprint = entry.public_key.fingerprint();
                SigningKeyInfo {
                    key_id: format!("{:016X}", key_id),
                    user_id: entry.user_ids.first().cloned().unwrap_or_default(),
                    fingerprint: hex::encode(&fingerprint[..8]),
                }
            })
            .collect();

        EncryptTemplate {
            recipients,
            signing_keys,
            result: None,
            error: Some(error_msg),
            has_result: false,
            has_error: true,
            active_page: "encrypt".to_string(),
            csrf_token,
        }
    };

    // Load keyring
    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Failed to access key storage. Please check your keyring configuration."
                    .to_string(),
                &[],
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    // Find recipient's public key
    let all_entries = keyring.list_all_keys();
    let matching_entries: Vec<_> = all_entries
        .iter()
        .filter(|(_, entry, _)| {
            // Must be a ML-KEM-1024 key AND match the user ID
            entry.public_key.algorithm() == Algorithm::Mlkem1024
                && entry
                    .user_ids
                    .iter()
                    .any(|uid| uid.contains(&form.data.recipient))
        })
        .collect();

    if matching_entries.is_empty() {
        warn!(
            "No public key found for recipient '{}'",
            form.data.recipient
        );
        let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
            .await
            .unwrap_or_default();
        let template = create_error_template(
            format!("No encryption key found for recipient '{}'. Make sure you have imported their public key.", form.data.recipient),
            &all_entries,
            csrf_token,
        );
        return Ok(Html(
            template
                .render()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        ));
    }

    let recipient_key = &matching_entries[0].1.public_key;
    info!(
        "Found encryption key for recipient '{}'",
        form.data.recipient
    );

    // Prepare message for encryption (sign first if requested)
    let message_to_encrypt = if let Some(signing_key_id) = &form.data.signing_key {
        if !signing_key_id.is_empty() {
            // Parse signing key ID
            let signing_key_id = match u64::from_str_radix(signing_key_id, 16) {
                Ok(id) => id,
                Err(_) => {
                    error!("Invalid signing key ID format: {}", signing_key_id);
                    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                        .await
                        .unwrap_or_default();
                    let template = create_error_template(
                        "Invalid signing key ID format.".to_string(),
                        &all_entries,
                        csrf_token,
                    );
                    return Ok(Html(
                        template
                            .render()
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                    ));
                }
            };

            // Find signing key
            let signing_entry = all_entries.iter().find(|(key_id, entry, has_private)| {
                *key_id == signing_key_id
                    && *has_private
                    && entry.public_key.algorithm() == Algorithm::Mldsa87
            });

            if signing_entry.is_none() {
                error!(
                    "Signing key not found or not available: {:016X}",
                    signing_key_id
                );
                let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                    .await
                    .unwrap_or_default();
                let template = create_error_template(
                    "Signing key not found. Please select a valid signing key.".to_string(),
                    &all_entries,
                    csrf_token,
                );
                return Ok(Html(
                    template
                        .render()
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                ));
            }

            // Get private key for signing
            let private_key = match keyring.get_private_key(signing_key_id) {
                Some(pk) => pk,
                None => {
                    error!("Private signing key not found: {:016X}", signing_key_id);
                    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                        .await
                        .unwrap_or_default();
                    let template = create_error_template(
                        "Private signing key not found. Please check your keyring.".to_string(),
                        &all_entries,
                        csrf_token,
                    );
                    return Ok(Html(
                        template
                            .render()
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                    ));
                }
            };

            // Prepare password for signing (if provided)
            let password = form
                .data
                .password
                .as_ref()
                .filter(|p| !p.is_empty())
                .map(|p| Password::new(p.clone()));

            // Sign the message
            let signature =
                match sign_message(private_key, form.data.message.as_bytes(), password.as_ref()) {
                    Ok(sig) => sig,
                    Err(e) => {
                        error!("Failed to sign message: {:?}", e);
                        let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                            .await
                            .unwrap_or_default();
                        let template = create_error_template(
                            "Failed to sign message. Please try again.".to_string(),
                            &all_entries,
                            csrf_token,
                        );
                        return Ok(Html(
                            template
                                .render()
                                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                        ));
                    }
                };

            // Serialize signature
            let signature_data = match bincode::serialize(&signature) {
                Ok(data) => data,
                Err(e) => {
                    error!("Failed to serialize signature: {:?}", e);
                    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                        .await
                        .unwrap_or_default();
                    let template = create_error_template(
                        "Failed to process signature. Please try again.".to_string(),
                        &all_entries,
                        csrf_token,
                    );
                    return Ok(Html(
                        template
                            .render()
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                    ));
                }
            };

            // Create PGP signed message format
            let signed_message = match create_signed_message(&form.data.message, &signature_data) {
                Ok(msg) => msg,
                Err(e) => {
                    error!("Failed to create signed message: {:?}", e);
                    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                        .await
                        .unwrap_or_default();
                    let template = create_error_template(
                        "Failed to create signed message format. Please try again.".to_string(),
                        &all_entries,
                        csrf_token,
                    );
                    return Ok(Html(
                        template
                            .render()
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                    ));
                }
            };

            info!("Message signed with key: {:016X}", signing_key_id);
            signed_message.into_bytes()
        } else {
            // No signing key selected, use original message
            form.data.message.as_bytes().to_vec()
        }
    } else {
        // No signing key field, use original message
        form.data.message.as_bytes().to_vec()
    };

    // Encrypt the message (signed or original)
    let encrypted = match encrypt_message(recipient_key, &message_to_encrypt) {
        Ok(enc) => enc,
        Err(e) => {
            error!("Encryption failed: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Encryption failed due to a cryptographic error. Please try again.".to_string(),
                &all_entries,
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    // Serialize and armor
    let serialized = match bincode::serialize(&encrypted) {
        Ok(ser) => ser,
        Err(e) => {
            error!("Serialization failed: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Failed to serialize encrypted message. Please try again.".to_string(),
                &all_entries,
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    let armored = match encode(&serialized, ArmorType::Message) {
        Ok(arm) => arm,
        Err(e) => {
            error!("ASCII armor encoding failed: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Failed to encode encrypted message. Please try again.".to_string(),
                &all_entries,
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    info!(
        "Message encrypted successfully for recipient '{}'",
        form.data.recipient
    );

    let recipients: Vec<RecipientInfo> = all_entries
        .iter()
        .filter(|(_, entry, _)| entry.public_key.algorithm() == Algorithm::Mlkem1024)
        .map(|(key_id, entry, _)| RecipientInfo {
            key_id: format!("{:016X}", key_id),
            user_id: entry.user_ids.first().cloned().unwrap_or_default(),
        })
        .collect();

    let signing_keys: Vec<SigningKeyInfo> = all_entries
        .iter()
        .filter(|(_, entry, has_private)| {
            *has_private && entry.public_key.algorithm() == Algorithm::Mldsa87
        })
        .map(|(key_id, entry, _)| {
            let fingerprint = entry.public_key.fingerprint();
            SigningKeyInfo {
                key_id: format!("{:016X}", key_id),
                user_id: entry.user_ids.first().cloned().unwrap_or_default(),
                fingerprint: hex::encode(&fingerprint[..8]),
            }
        })
        .collect();

    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .map_err(|_| {
            error!("Failed to generate CSRF token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let template = EncryptTemplate {
        recipients,
        signing_keys,
        result: Some(armored),
        error: None,
        has_result: true,
        has_error: false,
        active_page: "encrypt".to_string(),
        csrf_token,
    };
    Ok(Html(template.render().map_err(|e| {
        error!("Template rendering failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// Decryption page
async fn decrypt_page(
    State(app_state): State<AppState>,
    session: Session,
) -> std::result::Result<Html<String>, StatusCode> {
    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .map_err(|_| {
            error!("Failed to generate CSRF token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let template = DecryptTemplate {
        active_page: "decrypt".to_string(),
        result: None,
        error: None,
        has_result: false,
        has_error: false,
        csrf_token,
    };
    Ok(Html(template.render().map_err(|e| {
        error!("Failed to render decrypt template: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// Decrypt a message
#[instrument(skip(form), fields(encrypted_message_len = form.data.encrypted_message.len()))]
async fn decrypt_handler(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<DecryptForm>>,
) -> std::result::Result<Html<String>, StatusCode> {
    // Validate CSRF token
    if !form.validate(&session, &app_state.csrf_store) {
        warn!("CSRF validation failed for decryption");
        return Err(StatusCode::FORBIDDEN);
    }
    // Helper function to create error template
    let create_error_template = |error_msg: String, csrf_token: String| -> DecryptTemplate {
        DecryptTemplate {
            result: None,
            error: Some(error_msg),
            has_result: false,
            has_error: true,
            active_page: "decrypt".to_string(),
            csrf_token,
        }
    };

    // Load keyring
    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Failed to access key storage. Please check your keyring configuration."
                    .to_string(),
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    // Convert password if provided
    let password = form
        .data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Decode armored data
    let armored = match decode(&form.data.encrypted_message) {
        Ok(armored) => armored,
        Err(e) => {
            error!("Failed to decode encrypted message armor: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Invalid encrypted message format. Please provide a valid PGP armored message."
                    .to_string(),
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    let encrypted_message: pqpgp::crypto::EncryptedMessage = match bincode::deserialize(
        &armored.data,
    ) {
        Ok(msg) => msg,
        Err(e) => {
            error!("Failed to deserialize encrypted message: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Invalid encrypted message data. The message appears to be corrupted or not properly encrypted.".to_string(),
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    info!(
        "Attempting to decrypt message for recipient key ID: {:016X}",
        encrypted_message.recipient_key_id()
    );

    // Find matching private key
    let all_entries = keyring.list_all_keys();
    let entries_with_private: Vec<_> = all_entries
        .iter()
        .filter_map(|(key_id, _entry, has_private)| {
            if *has_private {
                keyring
                    .get_private_key(*key_id)
                    .map(|private_key| (*key_id, private_key))
            } else {
                None
            }
        })
        .collect();

    if entries_with_private.is_empty() {
        warn!("No private keys available for decryption");
        let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
            .await
            .unwrap_or_default();
        let template = create_error_template(
            "No private keys available for decryption. Please generate or import private keys."
                .to_string(),
            csrf_token,
        );
        return Ok(Html(
            template
                .render()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        ));
    }

    info!(
        "Found {} private keys to try for decryption",
        entries_with_private.len()
    );

    let mut decrypted = None;
    let mut last_error: Option<String> = None;

    // Try exact matching key ID first
    for (key_id, private_key) in entries_with_private.iter() {
        if *key_id == encrypted_message.recipient_key_id() {
            info!("Trying exact match key ID: {:016X}", key_id);
            match decrypt_message(private_key, &encrypted_message, password.as_ref()) {
                Ok(message) => {
                    info!(
                        "Successfully decrypted message with key ID: {:016X}",
                        key_id
                    );
                    decrypted = Some(String::from_utf8_lossy(&message).to_string());
                    break;
                }
                Err(e) => {
                    warn!(
                        "Decryption failed with exact match key {:016X}: {:?}",
                        key_id, e
                    );
                    last_error = Some(format!("{:?}", e));
                }
            }
        }
    }

    // If exact match failed, try all other keys
    if decrypted.is_none() {
        info!("Exact match failed, trying all other available keys");
        for (key_id, private_key) in entries_with_private {
            if key_id != encrypted_message.recipient_key_id() {
                info!("Trying key ID: {:016X}", key_id);
                match decrypt_message(private_key, &encrypted_message, password.as_ref()) {
                    Ok(message) => {
                        info!(
                            "Successfully decrypted message with key ID: {:016X}",
                            key_id
                        );
                        decrypted = Some(String::from_utf8_lossy(&message).to_string());
                        break;
                    }
                    Err(e) => {
                        warn!("Decryption failed with key {:016X}: {:?}", key_id, e);
                        last_error = Some(format!("{:?}", e));
                    }
                }
            }
        }
    }

    let error = if decrypted.is_none() {
        let error_msg = if let Some(err) = last_error {
            if err.contains("Password") {
                "Decryption failed: Incorrect password or the message was not encrypted for your keys. Please check your password and try again.".to_string()
            } else if err.contains("key") {
                "Decryption failed: No matching private key found. The message was not encrypted for any of your available keys.".to_string()
            } else {
                "Decryption failed: Unable to decrypt the message with available keys and password."
                    .to_string()
            }
        } else {
            "Decryption failed: No suitable private keys found for this encrypted message."
                .to_string()
        };
        Some(error_msg)
    } else {
        None
    };

    let has_result = decrypted.is_some();
    let has_error = error.is_some();
    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .map_err(|_| {
            error!("Failed to generate CSRF token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let template = DecryptTemplate {
        result: decrypted,
        error,
        has_result,
        has_error,
        active_page: "decrypt".to_string(),
        csrf_token,
    };
    Ok(Html(template.render().map_err(|e| {
        error!("Template rendering failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// Signing page
async fn sign_page(
    State(app_state): State<AppState>,
    session: Session,
) -> std::result::Result<Html<String>, StatusCode> {
    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager for sign page: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = SignTemplate {
                signing_keys: vec![],
                result: None,
                error: None,
                has_result: false,
                has_error: false,
                active_page: "sign".to_string(),
                csrf_token,
            };
            return Ok(Html(template.render().map_err(|e| {
                error!("Failed to render sign template with error: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?));
        }
    };

    let entries = keyring.list_all_keys();

    let signing_keys: Vec<SigningKeyInfo> = entries
        .into_iter()
        .filter(|(_, entry, has_private)| {
            *has_private && entry.public_key.algorithm() == Algorithm::Mldsa87
        })
        .map(|(key_id, entry, _)| {
            let fingerprint = entry.public_key.fingerprint();
            SigningKeyInfo {
                key_id: format!("{:016X}", key_id),
                user_id: entry.user_ids.first().cloned().unwrap_or_default(),
                fingerprint: hex::encode(&fingerprint[..8]),
            }
        })
        .collect();

    info!("Sign page loaded with {} signing keys", signing_keys.len());

    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .map_err(|_| {
            error!("Failed to generate CSRF token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let template = SignTemplate {
        signing_keys,
        result: None,
        error: None,
        has_result: false,
        has_error: false,
        active_page: "sign".to_string(),
        csrf_token,
    };
    Ok(Html(template.render().map_err(|e| {
        error!("Failed to render sign template: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// Sign a message
#[instrument(skip(form), fields(key_id = %form.data.key_id, message_len = form.data.message.len()))]
async fn sign_handler(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<SignForm>>,
) -> std::result::Result<Html<String>, StatusCode> {
    // Validate CSRF token
    if !form.validate(&session, &app_state.csrf_store) {
        warn!("CSRF validation failed for signing");
        return Err(StatusCode::FORBIDDEN);
    }
    // Helper function to create error template
    let create_error_template = |error_msg: String,
                                 all_entries: &[(u64, &pqpgp::keyring::KeyEntry, bool)],
                                 csrf_token: String|
     -> SignTemplate {
        let signing_keys: Vec<SigningKeyInfo> = all_entries
            .iter()
            .filter(|(_, entry, has_private)| {
                *has_private && entry.public_key.algorithm() == Algorithm::Mldsa87
            })
            .map(|(key_id, entry, _)| {
                let fingerprint = entry.public_key.fingerprint();
                SigningKeyInfo {
                    key_id: format!("{:016X}", key_id),
                    user_id: entry.user_ids.first().cloned().unwrap_or_default(),
                    fingerprint: hex::encode(&fingerprint[..8]),
                }
            })
            .collect();

        SignTemplate {
            signing_keys,
            result: None,
            error: Some(error_msg),
            has_result: false,
            has_error: true,
            active_page: "sign".to_string(),
            csrf_token,
        }
    };

    // Load keyring
    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Failed to access key storage. Please check your keyring configuration."
                    .to_string(),
                &[],
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    // Parse key ID
    let key_id = match u64::from_str_radix(&form.data.key_id, 16) {
        Ok(id) => id,
        Err(e) => {
            error!("Invalid key ID format '{}': {:?}", form.data.key_id, e);
            let all_entries = keyring.list_all_keys();
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                format!(
                    "Invalid key ID format: '{}'. Please select a valid signing key.",
                    form.data.key_id
                ),
                &all_entries,
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    // Convert password if provided
    let password = form
        .data
        .password
        .as_ref()
        .filter(|p| !p.is_empty())
        .map(|p| Password::new(p.clone()));

    // Find private key
    let all_entries = keyring.list_all_keys();
    let private_key = match keyring.get_private_key(key_id) {
        Some(key) => key,
        None => {
            warn!("Private key not found for key ID: {:016X}", key_id);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                format!("Private key not found for the selected signing key. Make sure you have the private key for {:016X}.", key_id),
                &all_entries,
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    info!("Found private key for signing key ID: {:016X}", key_id);

    // Sign message
    let signature = match sign_message(private_key, form.data.message.as_bytes(), password.as_ref())
    {
        Ok(sig) => sig,
        Err(e) => {
            error!("Signing failed for key ID {:016X}: {:?}", key_id, e);
            let error_msg = if password.is_none() && private_key.is_encrypted() {
                "Signing failed: This private key is password protected. Please provide the correct password.".to_string()
            } else if password.is_some() {
                "Signing failed: Incorrect password or key corruption. Please check your password and try again.".to_string()
            } else {
                "Signing failed due to a cryptographic error. Please try again.".to_string()
            };
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(error_msg, &all_entries, csrf_token);
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    // Serialize signature for the signed message armor
    let signature_data = match bincode::serialize(&signature) {
        Ok(ser) => ser,
        Err(e) => {
            error!("Serialization failed for signature: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Failed to serialize signature. Please try again.".to_string(),
                &all_entries,
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    // Create PGP signed message armor (includes cleartext + signature)
    let signed_message_armor = match create_signed_message(&form.data.message, &signature_data) {
        Ok(arm) => arm,
        Err(e) => {
            error!("Failed to create signed message armor: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Failed to create signed message. Please try again.".to_string(),
                &all_entries,
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    info!("Message signed successfully with key ID: {:016X}", key_id);

    let signing_keys: Vec<SigningKeyInfo> = all_entries
        .into_iter()
        .filter(|(_, entry, has_private)| {
            *has_private && entry.public_key.algorithm() == Algorithm::Mldsa87
        })
        .map(|(key_id, entry, _)| {
            let fingerprint = entry.public_key.fingerprint();
            SigningKeyInfo {
                key_id: format!("{:016X}", key_id),
                user_id: entry.user_ids.first().cloned().unwrap_or_default(),
                fingerprint: hex::encode(&fingerprint[..8]),
            }
        })
        .collect();

    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .map_err(|_| {
            error!("Failed to generate CSRF token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let template = SignTemplate {
        signing_keys,
        result: Some(signed_message_armor),
        error: None,
        has_result: true,
        has_error: false,
        active_page: "sign".to_string(),
        csrf_token,
    };
    Ok(Html(template.render().map_err(|e| {
        error!("Template rendering failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// Verification page
async fn verify_page(
    State(app_state): State<AppState>,
    session: Session,
) -> std::result::Result<Html<String>, StatusCode> {
    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .map_err(|_| {
            error!("Failed to generate CSRF token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let template = VerifyTemplate {
        active_page: "verify".to_string(),
        is_valid: None,
        error: None,
        has_result: false,
        has_error: false,
        csrf_token,
    };
    Ok(Html(template.render().map_err(|e| {
        error!("Failed to render verify template: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// Verify a signature
#[instrument(skip(form), fields(message_len = form.data.message.len(), signature_len = form.data.signature.len()))]
async fn verify_handler(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<VerifyForm>>,
) -> std::result::Result<Html<String>, StatusCode> {
    // Validate CSRF token
    if !form.validate(&session, &app_state.csrf_store) {
        warn!("CSRF validation failed for signature verification");
        return Err(StatusCode::FORBIDDEN);
    }
    // Helper function to create error template
    let create_error_template = |error_msg: String, csrf_token: String| -> VerifyTemplate {
        VerifyTemplate {
            is_valid: None,
            error: Some(error_msg),
            has_result: false,
            has_error: true,
            active_page: "verify".to_string(),
            csrf_token,
        }
    };

    // Load keyring
    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Failed to access key storage. Please check your keyring configuration."
                    .to_string(),
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    // Decode signature
    let sig_armored = match decode(&form.data.signature) {
        Ok(armored) => armored,
        Err(e) => {
            error!("Failed to decode signature armor: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Invalid signature format. Please provide a valid PGP armored signature."
                    .to_string(),
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    let signature: pqpgp::crypto::Signature = match bincode::deserialize(&sig_armored.data) {
        Ok(sig) => sig,
        Err(e) => {
            error!("Failed to deserialize signature data: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                "Invalid signature data format. The signature appears to be corrupted.".to_string(),
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    info!("Verifying signature for key ID: {:016X}", signature.key_id);

    // Find public key for signature
    let all_entries = keyring.list_all_keys();
    let verifying_key = match all_entries
        .iter()
        .find(|(key_id, _entry, _has_private)| *key_id == signature.key_id)
        .map(|(_, entry, _)| &entry.public_key)
    {
        Some(key) => key,
        None => {
            warn!(
                "Public key not found for signature key ID: {:016X}",
                signature.key_id
            );
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = create_error_template(
                format!("No public key found for signature key ID {:016X}. Make sure you have imported the signer's public key.", signature.key_id),
                csrf_token,
            );
            return Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ));
        }
    };

    info!("Found public key for signature verification");

    // Verify signature
    let verification_result =
        verify_signature(verifying_key, form.data.message.as_bytes(), &signature);
    let is_valid = verification_result.is_ok();

    if let Err(e) = &verification_result {
        warn!("Signature verification failed: {:?}", e);
    }

    info!(
        "Signature verification result: {}",
        if is_valid { "VALID" } else { "INVALID" }
    );

    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .map_err(|_| {
            error!("Failed to generate CSRF token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let template = VerifyTemplate {
        is_valid: Some(is_valid),
        error: None,
        has_result: true,
        has_error: false,
        active_page: "verify".to_string(),
        csrf_token,
    };
    Ok(Html(template.render().map_err(|e| {
        error!("Template rendering failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// Files page
async fn files_page(
    State(app_state): State<AppState>,
    session: Session,
) -> std::result::Result<Html<String>, StatusCode> {
    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager for files page: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let template = FilesTemplate {
                recipients: vec![],
                signing_keys: vec![],
                result: None,
                error: Some("Failed to access key storage".to_string()),
                has_result: false,
                has_error: true,
                signature_found: false,
                signature_armored: None,
                signer_info: None,
                signature_verified: None,
                verification_message: None,
                active_page: "files".to_string(),
                csrf_token,
            };
            return Ok(Html(template.render().map_err(|e| {
                error!("Failed to render files template with error: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?));
        }
    };

    let entries = keyring.list_all_keys();

    let recipients: Vec<RecipientInfo> = entries
        .iter()
        .filter(|(_, entry, _)| entry.public_key.algorithm() == Algorithm::Mlkem1024)
        .map(|(key_id, entry, _)| RecipientInfo {
            key_id: format!("{:016X}", key_id),
            user_id: entry.user_ids.first().cloned().unwrap_or_default(),
        })
        .collect();

    let signing_keys: Vec<SigningKeyInfo> = entries
        .into_iter()
        .filter(|(_, entry, has_private)| {
            *has_private && entry.public_key.algorithm() == Algorithm::Mldsa87
        })
        .map(|(key_id, entry, _)| {
            let fingerprint = entry.public_key.fingerprint();
            SigningKeyInfo {
                key_id: format!("{:016X}", key_id),
                user_id: entry.user_ids.first().cloned().unwrap_or_default(),
                fingerprint: hex::encode(&fingerprint[..8]),
            }
        })
        .collect();

    info!(
        "Files page loaded with {} recipients and {} signing keys",
        recipients.len(),
        signing_keys.len()
    );

    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .map_err(|_| {
            error!("Failed to generate CSRF token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let template = FilesTemplate {
        recipients,
        signing_keys,
        result: None,
        error: None,
        has_result: false,
        has_error: false,
        signature_found: false,
        signature_armored: None,
        signer_info: None,
        signature_verified: None,
        verification_message: None,
        active_page: "files".to_string(),
        csrf_token,
    };
    Ok(Html(template.render().map_err(|e| {
        error!("Failed to render files template: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// Encrypt a file
#[instrument(skip(multipart), fields(operation = "file_encrypt"))]
async fn encrypt_file_handler(
    State(app_state): State<AppState>,
    session: Session,
    mut multipart: Multipart,
) -> std::result::Result<axum::response::Response, StatusCode> {
    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Parse multipart form
    let mut csrf_token_value = String::new();
    let mut recipient = String::new();
    let mut signing_key = String::new();
    let mut password = String::new();
    let mut file_data = Vec::new();
    let mut filename = String::new();

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        error!("Failed to read multipart field: {:?}", e);
        StatusCode::BAD_REQUEST
    })? {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "csrf_token" => {
                csrf_token_value = field.text().await.map_err(|e| {
                    error!("Failed to read CSRF token: {:?}", e);
                    StatusCode::BAD_REQUEST
                })?;
            }
            "recipient" => {
                recipient = field.text().await.map_err(|e| {
                    error!("Failed to read recipient: {:?}", e);
                    StatusCode::BAD_REQUEST
                })?;
            }
            "signing_key" => {
                signing_key = field.text().await.map_err(|e| {
                    error!("Failed to read signing key: {:?}", e);
                    StatusCode::BAD_REQUEST
                })?;
            }
            "password" => {
                password = field.text().await.map_err(|e| {
                    error!("Failed to read password: {:?}", e);
                    StatusCode::BAD_REQUEST
                })?;
            }
            "file" => {
                filename = field.file_name().unwrap_or("unknown_file").to_string();
                file_data = field
                    .bytes()
                    .await
                    .map_err(|e| {
                        error!("Failed to read file data: {:?}", e);
                        StatusCode::BAD_REQUEST
                    })?
                    .to_vec();
            }
            _ => {
                continue;
            }
        }
    }

    // Validate CSRF token
    if !validate_csrf_token(&session, &app_state.csrf_store, &csrf_token_value) {
        warn!("CSRF validation failed for file encryption");
        return Err(StatusCode::FORBIDDEN);
    }

    if file_data.is_empty() {
        error!("No file provided for encryption");
        return Err(StatusCode::BAD_REQUEST);
    }

    info!(
        "Encrypting file '{}' ({} bytes) for recipient '{}'",
        filename,
        file_data.len(),
        recipient
    );

    // Find recipient's public key
    let all_entries = keyring.list_all_keys();
    let matching_entries: Vec<_> = all_entries
        .iter()
        .filter(|(_, entry, _)| {
            entry.public_key.algorithm() == Algorithm::Mlkem1024
                && entry.user_ids.iter().any(|uid| uid.contains(&recipient))
        })
        .collect();

    if matching_entries.is_empty() {
        error!("No encryption key found for recipient '{}'", recipient);
        return Err(StatusCode::BAD_REQUEST);
    }

    let recipient_key = &matching_entries[0].1.public_key;

    // Prepare file data for encryption (sign first if requested)
    let data_to_encrypt = if !signing_key.is_empty() {
        // Parse signing key ID
        let signing_key_id = match u64::from_str_radix(&signing_key, 16) {
            Ok(id) => id,
            Err(_) => {
                error!("Invalid signing key ID format");
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        // Get private key for signing
        let private_key = match keyring.get_private_key(signing_key_id) {
            Some(pk) => pk,
            None => {
                error!("Private signing key not found");
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        // Prepare password for signing
        let signing_password = if !password.is_empty() {
            Some(Password::new(password))
        } else {
            None
        };

        // Sign the file data
        let signature = match sign_message(private_key, &file_data, signing_password.as_ref()) {
            Ok(sig) => sig,
            Err(e) => {
                error!("Failed to sign file: {:?}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        // Serialize signature
        let signature_data = match bincode::serialize(&signature) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to serialize signature: {:?}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        // Combine filename, file data, and signature
        let mut combined_data = Vec::new();
        combined_data.extend_from_slice(&(filename.len() as u32).to_le_bytes());
        combined_data.extend_from_slice(filename.as_bytes());
        combined_data.extend_from_slice(&(file_data.len() as u64).to_le_bytes());
        combined_data.extend_from_slice(&file_data);
        combined_data.extend_from_slice(&(signature_data.len() as u32).to_le_bytes());
        combined_data.extend_from_slice(&signature_data);
        combined_data
    } else {
        // No signing, just combine filename and file data
        let mut combined_data = Vec::new();
        combined_data.extend_from_slice(&(filename.len() as u32).to_le_bytes());
        combined_data.extend_from_slice(filename.as_bytes());
        combined_data.extend_from_slice(&(file_data.len() as u64).to_le_bytes());
        combined_data.extend_from_slice(&file_data);
        combined_data
    };

    // Encrypt the file
    let encrypted = match encrypt_message(recipient_key, &data_to_encrypt) {
        Ok(enc) => enc,
        Err(e) => {
            error!("File encryption failed: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Serialize encrypted data
    let serialized = match bincode::serialize(&encrypted) {
        Ok(ser) => ser,
        Err(e) => {
            error!("Failed to serialize encrypted file: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    info!("File '{}' encrypted successfully", filename);

    // Create encrypted filename
    let encrypted_filename = format!("{}.pqpgp", filename);

    // Return as downloadable file
    use axum::http::header;
    let response = axum::response::Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", encrypted_filename),
        )
        .body(axum::body::Body::from(serialized))
        .map_err(|e| {
            error!("Failed to create response for file download: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

/// Decrypt a file
#[instrument(skip(multipart), fields(operation = "file_decrypt"))]
async fn decrypt_file_handler(
    State(app_state): State<AppState>,
    session: Session,
    mut multipart: Multipart,
) -> std::result::Result<axum::response::Response, StatusCode> {
    // Helper function to create error template
    let create_error_template =
        |error_msg: String, csrf_token: String| -> Result<Html<String>, StatusCode> {
            let keyring = match create_keyring_manager() {
                Ok(kr) => kr,
                Err(_) => {
                    let template = FilesTemplate {
                        recipients: vec![],
                        signing_keys: vec![],
                        result: None,
                        error: Some("Failed to access key storage".to_string()),
                        has_result: false,
                        has_error: true,
                        signature_found: false,
                        signature_armored: None,
                        signer_info: None,
                        signature_verified: None,
                        verification_message: None,
                        active_page: "files".to_string(),
                        csrf_token,
                    };
                    return Ok(Html(
                        template
                            .render()
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                    ));
                }
            };

            let entries = keyring.list_all_keys();
            let recipients: Vec<RecipientInfo> = entries
                .iter()
                .filter(|(_, entry, _)| entry.public_key.algorithm() == Algorithm::Mlkem1024)
                .map(|(key_id, entry, _)| RecipientInfo {
                    key_id: format!("{:016X}", key_id),
                    user_id: entry.user_ids.first().cloned().unwrap_or_default(),
                })
                .collect();

            let signing_keys: Vec<SigningKeyInfo> = entries
                .iter()
                .filter(|(_, entry, has_private)| {
                    *has_private && entry.public_key.algorithm() == Algorithm::Mldsa87
                })
                .map(|(key_id, entry, _)| {
                    let fingerprint = entry.public_key.fingerprint();
                    SigningKeyInfo {
                        key_id: format!("{:016X}", key_id),
                        user_id: entry.user_ids.first().cloned().unwrap_or_default(),
                        fingerprint: hex::encode(&fingerprint[..8]),
                    }
                })
                .collect();

            let template = FilesTemplate {
                recipients,
                signing_keys,
                result: None,
                error: Some(error_msg),
                has_result: false,
                has_error: true,
                signature_found: false,
                signature_armored: None,
                signer_info: None,
                signature_verified: None,
                verification_message: None,
                active_page: "files".to_string(),
                csrf_token,
            };

            Ok(Html(
                template
                    .render()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            ))
        };

    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager: {:?}", e);
            let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
                .await
                .unwrap_or_default();
            let html = create_error_template(
                "Failed to access key storage. Please check your keyring configuration."
                    .to_string(),
                csrf_token,
            )?;
            return Ok(html.into_response());
        }
    };

    // Parse multipart form
    let mut csrf_token_value = String::new();
    let mut password = String::new();
    let mut file_data = Vec::new();
    let mut filename = String::new();

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        error!("Failed to read multipart field: {:?}", e);
        StatusCode::BAD_REQUEST
    })? {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "csrf_token" => {
                csrf_token_value = field.text().await.map_err(|e| {
                    error!("Failed to read CSRF token: {:?}", e);
                    StatusCode::BAD_REQUEST
                })?;
            }
            "password" => {
                password = field.text().await.map_err(|e| {
                    error!("Failed to read password: {:?}", e);
                    StatusCode::BAD_REQUEST
                })?;
            }
            "file" => {
                filename = field.file_name().unwrap_or("unknown_file").to_string();
                file_data = field
                    .bytes()
                    .await
                    .map_err(|e| {
                        error!("Failed to read file data: {:?}", e);
                        StatusCode::BAD_REQUEST
                    })?
                    .to_vec();
            }
            _ => {
                continue;
            }
        }
    }

    // Validate CSRF token
    if !validate_csrf_token(&session, &app_state.csrf_store, &csrf_token_value) {
        warn!("CSRF validation failed for file decryption");
        return Err(StatusCode::FORBIDDEN);
    }

    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .unwrap_or_default();

    if file_data.is_empty() {
        error!("No file provided for decryption");
        let html = create_error_template(
            "No file provided. Please select an encrypted file to decrypt.".to_string(),
            csrf_token,
        )?;
        return Ok(html.into_response());
    }

    info!("Decrypting file '{}' ({} bytes)", filename, file_data.len());

    // Deserialize encrypted message
    let encrypted_message: pqpgp::crypto::EncryptedMessage = match bincode::deserialize(&file_data)
    {
        Ok(msg) => msg,
        Err(e) => {
            error!("Failed to deserialize encrypted file: {:?}", e);
            let html = create_error_template(
                "Invalid encrypted file format. Please ensure you're uploading a valid .pqpgp encrypted file.".to_string(),
                csrf_token.clone(),
            )?;
            return Ok(html.into_response());
        }
    };

    // Convert password if provided
    let decryption_password = if !password.is_empty() {
        Some(Password::new(password))
    } else {
        None
    };

    // Find matching private key and decrypt
    let all_entries = keyring.list_all_keys();
    let entries_with_private: Vec<_> = all_entries
        .iter()
        .filter_map(|(key_id, _entry, has_private)| {
            if *has_private {
                keyring
                    .get_private_key(*key_id)
                    .map(|private_key| (*key_id, private_key))
            } else {
                None
            }
        })
        .collect();

    if entries_with_private.is_empty() {
        error!("No private keys available for decryption");
        let html = create_error_template(
            "No private keys found in your keyring. You need to generate or import private keys before you can decrypt files.".to_string(),
            csrf_token.clone(),
        )?;
        return Ok(html.into_response());
    }

    let mut decrypted_data = None;

    // Try decryption with available keys
    for (key_id, private_key) in entries_with_private.iter() {
        if *key_id == encrypted_message.recipient_key_id() {
            info!("Trying exact match key ID: {:016X}", key_id);
            match decrypt_message(
                private_key,
                &encrypted_message,
                decryption_password.as_ref(),
            ) {
                Ok(data) => {
                    info!("Successfully decrypted file with key ID: {:016X}", key_id);
                    decrypted_data = Some(data);
                    break;
                }
                Err(e) => {
                    warn!(
                        "Decryption failed with exact match key {:016X}: {:?}",
                        key_id, e
                    );
                }
            }
        }
    }

    // If exact match failed, try all other keys
    if decrypted_data.is_none() {
        for (key_id, private_key) in entries_with_private {
            if key_id != encrypted_message.recipient_key_id() {
                info!("Trying key ID: {:016X}", key_id);
                match decrypt_message(
                    private_key,
                    &encrypted_message,
                    decryption_password.as_ref(),
                ) {
                    Ok(data) => {
                        info!("Successfully decrypted file with key ID: {:016X}", key_id);
                        decrypted_data = Some(data);
                        break;
                    }
                    Err(e) => {
                        warn!("Decryption failed with key {:016X}: {:?}", key_id, e);
                    }
                }
            }
        }
    }

    let decrypted_data = match decrypted_data {
        Some(data) => data,
        None => {
            error!("Decryption failed with all available keys");
            let html = create_error_template(
                "Decryption failed. This could be due to: 1) Wrong password for private key, 2) File not encrypted for your keys, 3) Corrupted encrypted file. Please check your password and ensure you have the correct private key.".to_string(),
                csrf_token.clone(),
            )?;
            return Ok(html.into_response());
        }
    };

    // Parse decrypted data to extract filename and file content
    let mut offset = 0;

    // Read filename length
    if decrypted_data.len() < offset + 4 {
        error!("Corrupted encrypted file data");
        let html = create_error_template(
            "The decrypted file data appears to be corrupted or in an unexpected format."
                .to_string(),
            csrf_token.clone(),
        )?;
        return Ok(html.into_response());
    }
    let filename_len = u32::from_le_bytes([
        decrypted_data[offset],
        decrypted_data[offset + 1],
        decrypted_data[offset + 2],
        decrypted_data[offset + 3],
    ]) as usize;
    offset += 4;

    // Read filename
    if decrypted_data.len() < offset + filename_len {
        error!("Corrupted encrypted file data");
        let html = create_error_template(
            "The decrypted file data appears to be corrupted or in an unexpected format."
                .to_string(),
            csrf_token.clone(),
        )?;
        return Ok(html.into_response());
    }
    let original_filename =
        String::from_utf8_lossy(&decrypted_data[offset..offset + filename_len]).to_string();
    offset += filename_len;

    // Read file data length
    if decrypted_data.len() < offset + 8 {
        error!("Corrupted encrypted file data");
        let html = create_error_template(
            "The decrypted file data appears to be corrupted or in an unexpected format."
                .to_string(),
            csrf_token.clone(),
        )?;
        return Ok(html.into_response());
    }
    let file_data_len = u64::from_le_bytes([
        decrypted_data[offset],
        decrypted_data[offset + 1],
        decrypted_data[offset + 2],
        decrypted_data[offset + 3],
        decrypted_data[offset + 4],
        decrypted_data[offset + 5],
        decrypted_data[offset + 6],
        decrypted_data[offset + 7],
    ]) as usize;
    offset += 8;

    // Read file data
    if decrypted_data.len() < offset + file_data_len {
        error!("Corrupted encrypted file data");
        let html = create_error_template(
            "The decrypted file data appears to be corrupted or in an unexpected format."
                .to_string(),
            csrf_token.clone(),
        )?;
        return Ok(html.into_response());
    }
    let original_file_data = &decrypted_data[offset..offset + file_data_len];
    offset += file_data_len;

    info!("File '{}' decrypted successfully", original_filename);

    // Check if there's a signature after the file data
    let mut signature_armored = None;
    let mut signer_info = None;
    let signature_found = if offset < decrypted_data.len() {
        // Check if there are at least 4 more bytes for signature length
        if decrypted_data.len() >= offset + 4 {
            let signature_len = u32::from_le_bytes([
                decrypted_data[offset],
                decrypted_data[offset + 1],
                decrypted_data[offset + 2],
                decrypted_data[offset + 3],
            ]) as usize;
            offset += 4;

            if decrypted_data.len() >= offset + signature_len {
                let signature_data = &decrypted_data[offset..offset + signature_len];

                // Deserialize the signature
                match bincode::deserialize::<pqpgp::crypto::Signature>(signature_data) {
                    Ok(signature) => {
                        info!("Found signature from key ID: {:016X}", signature.key_id);

                        // Find signer information
                        let all_entries = keyring.list_all_keys();
                        let signer = all_entries
                            .iter()
                            .find(|(key_id, _entry, _has_private)| *key_id == signature.key_id)
                            .map(|(_, entry, _)| {
                                let user_id = entry.user_ids.first().cloned().unwrap_or_default();
                                format!("{} (Key ID: {:016X})", user_id, signature.key_id)
                            })
                            .unwrap_or_else(|| {
                                format!("Unknown signer (Key ID: {:016X})", signature.key_id)
                            });

                        signer_info = Some(signer);

                        // Armor the signature for display
                        match pqpgp::armor::encode(
                            signature_data,
                            pqpgp::armor::ArmorType::Signature,
                        ) {
                            Ok(armored) => {
                                signature_armored = Some(armored.trim().to_string());
                                true
                            }
                            Err(e) => {
                                warn!("Failed to armor signature: {:?}", e);
                                false
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to deserialize signature: {:?}", e);
                        false
                    }
                }
            } else {
                warn!("Signature length exceeds remaining data");
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // Load keyring entries for template
    let entries = keyring.list_all_keys();
    let recipients: Vec<RecipientInfo> = entries
        .iter()
        .filter(|(_, entry, _)| entry.public_key.algorithm() == Algorithm::Mlkem1024)
        .map(|(key_id, entry, _)| RecipientInfo {
            key_id: format!("{:016X}", key_id),
            user_id: entry.user_ids.first().cloned().unwrap_or_default(),
        })
        .collect();

    let signing_keys: Vec<SigningKeyInfo> = entries
        .iter()
        .filter(|(_, entry, has_private)| {
            *has_private && entry.public_key.algorithm() == Algorithm::Mldsa87
        })
        .map(|(key_id, entry, _)| {
            let fingerprint = entry.public_key.fingerprint();
            SigningKeyInfo {
                key_id: format!("{:016X}", key_id),
                user_id: entry.user_ids.first().cloned().unwrap_or_default(),
                fingerprint: hex::encode(&fingerprint[..8]),
            }
        })
        .collect();

    let result_message = if signature_found {
        format!(
            "✅ File '{}' decrypted successfully and signature found! You can download the file and verify the signature below.",
            original_filename
        )
    } else {
        format!(
            "✅ File '{}' decrypted successfully (no signature found).",
            original_filename
        )
    };

    // Store decrypted file data in session for download
    session
        .insert("decrypted_file_data", original_file_data.to_vec())
        .await
        .map_err(|e| {
            error!("Failed to store file data in session: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    session
        .insert("decrypted_filename", original_filename)
        .await
        .map_err(|e| {
            error!("Failed to store filename in session: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Perform automatic signature verification if signature was found
    let (signature_verified, verification_message) = if signature_found {
        // We need to get the signature from the stored armored signature
        // and verify it against the original file data
        match &signature_armored {
            Some(armored_sig) => {
                // Decode the armored signature back to binary
                match pqpgp::armor::decode(armored_sig) {
                    Ok(armored_data) => {
                        // Deserialize the signature
                        match bincode::deserialize::<pqpgp::crypto::Signature>(&armored_data.data) {
                            Ok(signature) => {
                                // Find the public key for verification
                                let all_entries = keyring.list_all_keys();
                                let signer_entry = all_entries
                                    .iter()
                                    .find(|(key_id, _, _)| *key_id == signature.key_id);

                                match signer_entry {
                                    Some((_, entry, _)) => {
                                        // Verify the signature against the original file data
                                        match pqpgp::crypto::verify_signature(
                                            &entry.public_key,
                                            original_file_data,
                                            &signature,
                                        ) {
                                            Ok(()) => {
                                                info!("File signature verification successful");
                                                let user_id = entry
                                                    .user_ids
                                                    .first()
                                                    .cloned()
                                                    .unwrap_or_default();
                                                (Some(true), Some(format!("✅ Signature is VALID and authentic (signed by {} with Key ID: {:016X})", user_id, signature.key_id)))
                                            }
                                            Err(e) => {
                                                warn!(
                                                    "File signature verification failed: {:?}",
                                                    e
                                                );
                                                (Some(false), Some(format!("❌ Signature is INVALID or corrupted (Key ID: {:016X})", signature.key_id)))
                                            }
                                        }
                                    }
                                    None => {
                                        warn!("Signer's public key not found for verification");
                                        (Some(false), Some(format!("⚠️ Cannot verify: Signer's public key not found in keyring (Key ID: {:016X})", signature.key_id)))
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to deserialize signature for verification: {:?}", e);
                                (Some(false), Some("❌ Invalid signature format".to_string()))
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to decode armored signature: {:?}", e);
                        (Some(false), Some("❌ Invalid signature armor".to_string()))
                    }
                }
            }
            None => (None, None),
        }
    } else {
        (None, None)
    };

    let template = FilesTemplate {
        recipients,
        signing_keys,
        result: Some(result_message),
        error: None,
        has_result: true,
        has_error: false,
        signature_found,
        signature_armored,
        signer_info,
        signature_verified,
        verification_message,
        active_page: "files".to_string(),
        csrf_token,
    };

    Ok(Html(template.render().map_err(|e| {
        error!("Failed to render files template: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?)
    .into_response())
}

/// Download decrypted file from session
async fn download_decrypted_file(
    session: Session,
) -> std::result::Result<axum::response::Response, StatusCode> {
    // Get file data from session
    let file_data: Vec<u8> = session
        .get("decrypted_file_data")
        .await
        .map_err(|e| {
            error!("Failed to retrieve file data from session: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            error!("No decrypted file data found in session");
            StatusCode::NOT_FOUND
        })?;

    let filename: String = session
        .get("decrypted_filename")
        .await
        .map_err(|e| {
            error!("Failed to retrieve filename from session: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            error!("No decrypted filename found in session");
            StatusCode::NOT_FOUND
        })?;

    info!("Serving decrypted file '{}' for download", filename);

    // Clean up session data after retrieving
    let _ = session.remove::<Vec<u8>>("decrypted_file_data").await;
    let _ = session.remove::<String>("decrypted_filename").await;

    // Return as downloadable file
    use axum::http::header;
    let response = axum::response::Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(axum::body::Body::from(file_data))
        .map_err(|e| {
            error!("Failed to create response for file download: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(response)
}

// ============================================================================
// Chat handlers
// ============================================================================

/// Query parameters for chat page
#[derive(Debug, Deserialize)]
struct ChatQuery {
    contact: Option<String>,
}

/// Gets a unique session identifier string
fn get_session_id(session: &Session) -> String {
    session
        .id()
        .map(|id| format!("{:x}", id.0))
        .unwrap_or_else(|| "default".to_string())
}

/// Saves chat state to disk if password is available
fn save_chat_state(state: &chat_state::ChatState) {
    if let Some(pwd) = state.password() {
        let password = Password::new(pwd.to_string());
        if let Ok(storage) = ChatStorage::new() {
            if let Err(e) = storage.save_state(state, &password) {
                error!("Failed to save chat state: {:?}", e);
            }
        }
    }
}

/// Chat page handler
#[instrument(skip(app_state, session))]
async fn chat_page(
    State(app_state): State<AppState>,
    session: Session,
    Query(query): Query<ChatQuery>,
) -> std::result::Result<Html<String>, StatusCode> {
    use templates::{ChatContact, ChatMessageDisplay, ChatTemplate};

    let csrf_token = get_csrf_token(&session, &app_state.csrf_store)
        .await
        .unwrap_or_default();

    // Get session-specific chat state
    let session_id = get_session_id(&session);
    let mut chat_states = app_state.chat_states.write().map_err(|e| {
        error!("Failed to acquire chat states lock: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let chat_state = chat_states.get_or_create(&session_id);

    // Load contacts from chat state
    let selected = query.contact.clone();
    let contacts: Vec<ChatContact> = chat_state
        .contacts()
        .into_iter()
        .map(|contact| {
            let is_selected = selected.as_ref() == Some(&contact.fingerprint);
            let initial = contact.name.chars().next().unwrap_or('?');
            ChatContact {
                fingerprint: contact.fingerprint,
                name: contact.name,
                has_session: contact.has_session,
                is_selected,
                initial,
            }
        })
        .collect();

    // Load messages for selected contact
    let messages: Vec<ChatMessageDisplay> = if let Some(ref contact_id) = query.contact {
        chat_state
            .get_messages(contact_id)
            .into_iter()
            .map(|msg| ChatMessageDisplay {
                content: msg.content,
                timestamp: msg.timestamp,
                is_outgoing: msg.is_outgoing,
            })
            .collect()
    } else {
        vec![]
    };

    // Get our identity fingerprint and prekey bundle
    let our_identity = chat_state.our_fingerprint();
    let our_prekey_bundle = chat_state.our_prekey_bundle_encoded();

    // Get selected contact name
    let selected_contact_name = query.contact.as_ref().and_then(|selected_fp| {
        contacts
            .iter()
            .find(|c| c.fingerprint == *selected_fp)
            .map(|c| c.name.clone())
    });

    // Get list of saved identities (only show if not currently logged in)
    let saved_identities = if our_identity.is_none() {
        ChatStorage::new()
            .ok()
            .map(|s| s.list_users().unwrap_or_default())
            .unwrap_or_default()
    } else {
        vec![]
    };

    let template = ChatTemplate {
        active_page: "chat".to_string(),
        csrf_token,
        contacts,
        selected_contact: query.contact,
        selected_contact_name,
        messages,
        our_identity,
        our_prekey_bundle,
        saved_identities,
        result: None,
        error: None,
        has_result: false,
        has_error: false,
    };

    Ok(Html(template.render().map_err(|e| {
        error!("Failed to render chat template: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// Add a chat contact
#[instrument(skip(app_state, session, form))]
async fn add_chat_contact(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<AddContactForm>>,
) -> std::result::Result<impl IntoResponse, StatusCode> {
    // Validate CSRF token
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("Invalid CSRF token in add contact request");
        return Ok(Redirect::to("/chat"));
    }

    // Get session-specific chat state
    let session_id = get_session_id(&session);
    let mut chat_states = app_state.chat_states.write().map_err(|e| {
        error!("Failed to acquire chat states lock: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let chat_state = chat_states.get_or_create(&session_id);

    // Add new contact (fingerprint is extracted from prekey bundle)
    let fingerprint = match chat_state.add_contact(form.data.name.clone(), &form.data.prekey_bundle)
    {
        Ok(fp) => fp,
        Err(e) => {
            error!("Failed to add contact: {:?}", e);
            return Ok(Redirect::to("/chat"));
        }
    };

    // Save state to disk
    save_chat_state(chat_state);

    info!("Added chat contact: {} ({})", form.data.name, fingerprint);

    Ok(Redirect::to(&format!("/chat?contact={}", fingerprint)))
}

/// Delete a chat contact
#[instrument(skip(app_state, session))]
async fn delete_chat_contact(
    State(app_state): State<AppState>,
    session: Session,
    AxumPath(fingerprint): AxumPath<String>,
) -> std::result::Result<impl IntoResponse, StatusCode> {
    // Get session-specific chat state
    let session_id = get_session_id(&session);
    let mut chat_states = app_state.chat_states.write().map_err(|e| {
        error!("Failed to acquire chat states lock: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let chat_state = chat_states.get_or_create(&session_id);

    // Remove the contact
    chat_state.remove_contact(&fingerprint);

    // Save state to disk
    save_chat_state(chat_state);

    info!("Deleted chat contact: {}", fingerprint);

    Ok(Redirect::to("/chat"))
}

/// Send a chat message (fetches incoming messages first)
#[instrument(skip(app_state, session, form))]
async fn send_chat_message(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<SendMessageForm>>,
) -> std::result::Result<impl IntoResponse, StatusCode> {
    use pqpgp::chat::EncryptedChatMessage;

    // Validate CSRF token
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("Invalid CSRF token in send message request");
        return Ok(Redirect::to("/chat"));
    }

    // Get session-specific chat state
    let session_id = get_session_id(&session);

    // First, get our fingerprint and fetch any pending messages
    let our_fingerprint = {
        let chat_states = app_state.chat_states.read().map_err(|e| {
            error!("Failed to acquire chat states lock: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        match chat_states
            .get(&session_id)
            .and_then(|s| s.our_fingerprint())
        {
            Some(fp) => fp,
            None => {
                error!("No identity configured");
                return Ok(Redirect::to("/chat"));
            }
        }
    };

    // Fetch any pending messages from the remote relay before sending
    let incoming_messages = match app_state
        .relay_client
        .fetch_messages(&our_fingerprint)
        .await
    {
        Ok(msgs) => msgs,
        Err(e) => {
            error!("Failed to fetch messages from relay: {:?}", e);
            vec![]
        }
    };

    // Process incoming messages and send our message
    // We need to process everything and extract data before any await
    let encrypted_data_result: Result<Option<String>, StatusCode> = {
        let mut chat_states = app_state.chat_states.write().map_err(|e| {
            error!("Failed to acquire chat states lock: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let chat_state = chat_states.get_or_create(&session_id);

        // Process any incoming messages first
        for relayed_msg in incoming_messages {
            use base64::{engine::general_purpose::STANDARD, Engine};
            let encrypted_bytes = match STANDARD.decode(&relayed_msg.encrypted_data) {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("Failed to decode message: {:?}", e);
                    continue;
                }
            };

            let encrypted_msg: EncryptedChatMessage = match bincode::deserialize(&encrypted_bytes) {
                Ok(msg) => msg,
                Err(e) => {
                    error!("Failed to deserialize message: {:?}", e);
                    continue;
                }
            };

            if let Err(e) =
                chat_state.receive_message(&relayed_msg.sender_fingerprint, &encrypted_msg)
            {
                error!("Failed to decrypt message: {:?}", e);
            }
        }

        // Now send the encrypted message (this will initiate session if needed)
        match chat_state.send_message(&form.data.recipient, &form.data.message) {
            Ok(encrypted_msg) => {
                // Serialize and base64 encode the encrypted message
                let encrypted_data = bincode::serialize(&encrypted_msg)
                    .map(|bytes| {
                        use base64::{engine::general_purpose::STANDARD, Engine};
                        STANDARD.encode(bytes)
                    })
                    .map_err(|e| {
                        error!("Failed to serialize message: {:?}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                // Save state to disk (includes received messages and sent message)
                save_chat_state(chat_state);
                Ok(Some(encrypted_data))
            }
            Err(e) => {
                // Still save any received messages even if send failed
                save_chat_state(chat_state);
                error!("Failed to send message: {:?}", e);
                Ok(None)
            }
        }
    }; // chat_states lock is dropped here

    // Now we can await the relay call
    if let Some(encrypted_data) = encrypted_data_result? {
        if let Err(e) = app_state
            .relay_client
            .send_message(our_fingerprint, form.data.recipient.clone(), encrypted_data)
            .await
        {
            error!("Failed to send message via relay: {:?}", e);
        } else {
            info!("Sent encrypted message to contact: {}", form.data.recipient);
        }
    }

    Ok(Redirect::to(&format!(
        "/chat?contact={}",
        form.data.recipient
    )))
}

/// Generate a new chat identity and register on the relay
#[instrument(skip(app_state, session, form))]
async fn generate_chat_identity(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<GenerateChatIdentityForm>>,
) -> std::result::Result<impl IntoResponse, StatusCode> {
    // Validate CSRF token
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("Invalid CSRF token in generate identity request");
        return Ok(Redirect::to("/chat"));
    }

    // Validate password
    if form.data.password.is_empty() {
        error!("Password is required for identity generation");
        return Ok(Redirect::to("/chat"));
    }

    // Get session-specific chat state and generate identity
    // All lock operations must complete before any await
    let session_id = get_session_id(&session);
    let (fingerprint, prekey_bundle) = {
        let mut chat_states = app_state.chat_states.write().map_err(|e| {
            error!("Failed to acquire chat states lock: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let chat_state = chat_states.get_or_create(&session_id);

        // Generate new identity
        let (fingerprint, prekey_bundle) = match chat_state.generate_identity() {
            Ok(fp) => {
                let bundle = chat_state.our_prekey_bundle_encoded();
                info!("Generated new chat identity: {}", fp);
                (fp, bundle)
            }
            Err(e) => {
                error!("Failed to generate identity: {:?}", e);
                return Ok(Redirect::to("/chat"));
            }
        };

        // Store password in memory for future saves
        chat_state.set_password(form.data.password.clone());

        // Save state to disk with password encryption
        let password = Password::new(form.data.password.clone());
        let storage = ChatStorage::new().map_err(|e| {
            error!("Failed to create storage: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        if let Err(e) = storage.save_state(chat_state, &password) {
            error!("Failed to save state: {:?}", e);
            // Continue anyway - state is in memory
        }

        (fingerprint, prekey_bundle)
    }; // chat_states lock is dropped here

    // Auto-register on the remote relay server
    if let Some(bundle) = prekey_bundle {
        if let Err(e) = app_state
            .relay_client
            .register_user("Anonymous".to_string(), fingerprint.clone(), bundle)
            .await
        {
            error!("Failed to register on relay: {:?}", e);
            // Continue anyway - user can try again
        }
    }

    Ok(Redirect::to("/chat"))
}

/// Unlock a saved chat identity
#[instrument(skip(app_state, session, form))]
async fn unlock_chat_identity(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<UnlockIdentityForm>>,
) -> std::result::Result<impl IntoResponse, StatusCode> {
    // Validate CSRF token
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("Invalid CSRF token in unlock identity request");
        return Ok(Redirect::to("/chat"));
    }

    // Load the saved state
    let storage = ChatStorage::new().map_err(|e| {
        error!("Failed to create storage: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let password = Password::new(form.data.password.clone());
    let mut loaded_state = match storage.load_state(&form.data.fingerprint, &password) {
        Ok(state) => state,
        Err(e) => {
            error!("Failed to unlock identity: {:?}", e);
            // TODO: Show error message to user
            return Ok(Redirect::to("/chat"));
        }
    };

    // Store password in memory for future saves
    loaded_state.set_password(form.data.password.clone());

    // Store in session and get fingerprint/prekey bundle for relay registration
    let session_id = get_session_id(&session);
    let (fingerprint, prekey_bundle) = {
        let mut chat_states = app_state.chat_states.write().map_err(|e| {
            error!("Failed to acquire chat states lock: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        chat_states.set(&session_id, loaded_state);

        // Get the fingerprint and prekey bundle for relay registration
        let state = chat_states.get(&session_id).ok_or_else(|| {
            error!("State not found after setting");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        (state.our_fingerprint(), state.our_prekey_bundle_encoded())
    }; // chat_states lock is dropped here

    // Re-register on remote relay server (in case server restarted)
    if let (Some(fp), Some(bundle)) = (fingerprint, prekey_bundle) {
        if let Err(e) = app_state
            .relay_client
            .register_user("Anonymous".to_string(), fp.clone(), bundle)
            .await
        {
            error!("Failed to register on relay: {:?}", e);
            // Continue anyway - user can try again
        }
    }

    Ok(Redirect::to("/chat"))
}

/// Form for logout (just CSRF token)
#[derive(Debug, Deserialize)]
struct LogoutForm {}

/// Logout from current chat identity (switch identity)
#[instrument(skip(app_state, session, form))]
async fn logout_chat_identity(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<LogoutForm>>,
) -> std::result::Result<impl IntoResponse, StatusCode> {
    // Validate CSRF token
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("Invalid CSRF token in logout request");
        return Ok(Redirect::to("/chat"));
    }

    let session_id = get_session_id(&session);

    // Remove the current identity from memory (but keep it saved on disk)
    {
        let mut chat_states = app_state.chat_states.write().map_err(|e| {
            error!("Failed to acquire chat states lock: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        chat_states.remove(&session_id);
    }

    info!("User logged out of chat identity");
    Ok(Redirect::to("/chat"))
}

/// Fetch pending messages from the relay
#[instrument(skip(app_state, session, form))]
async fn fetch_relay_messages(
    State(app_state): State<AppState>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<FetchMessagesForm>>,
) -> std::result::Result<impl IntoResponse, StatusCode> {
    use pqpgp::chat::EncryptedChatMessage;

    // Validate CSRF token
    if !validate_csrf_token(&session, &app_state.csrf_store, &form.csrf_token) {
        warn!("Invalid CSRF token in fetch request");
        return Ok(Redirect::to("/chat"));
    }

    // Build redirect URL preserving current contact
    let redirect_url = match &form.data.current_contact {
        Some(contact) if !contact.is_empty() => format!("/chat?contact={}", contact),
        _ => "/chat".to_string(),
    };

    // Get session-specific chat state
    let session_id = get_session_id(&session);

    // Get our fingerprint
    let our_fingerprint = {
        let chat_states = app_state.chat_states.read().map_err(|e| {
            error!("Failed to acquire chat states lock: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        match chat_states
            .get(&session_id)
            .and_then(|s| s.our_fingerprint())
        {
            Some(fp) => fp,
            None => return Ok(Redirect::to(&redirect_url)),
        }
    };

    // Fetch messages from remote relay server
    let messages = match app_state
        .relay_client
        .fetch_messages(&our_fingerprint)
        .await
    {
        Ok(msgs) => msgs,
        Err(e) => {
            error!("Failed to fetch messages from relay: {:?}", e);
            vec![]
        }
    };

    // Process each message
    let mut chat_states = app_state.chat_states.write().map_err(|e| {
        error!("Failed to acquire chat states lock: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let chat_state = chat_states.get_or_create(&session_id);

    for relayed_msg in messages {
        // Decode the encrypted message
        use base64::{engine::general_purpose::STANDARD, Engine};
        let encrypted_bytes = match STANDARD.decode(&relayed_msg.encrypted_data) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to decode message: {:?}", e);
                continue;
            }
        };

        let encrypted_msg: EncryptedChatMessage = match bincode::deserialize(&encrypted_bytes) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to deserialize message: {:?}", e);
                continue;
            }
        };

        // Decrypt the message
        match chat_state.receive_message(&relayed_msg.sender_fingerprint, &encrypted_msg) {
            Ok(plaintext) => {
                info!(
                    "Received message from {}: {}",
                    relayed_msg.sender_fingerprint,
                    if plaintext.len() > 20 {
                        format!("{}...", &plaintext[..20])
                    } else {
                        plaintext
                    }
                );
            }
            Err(e) => {
                error!("Failed to decrypt message: {:?}", e);
            }
        }
    }

    // Save state to disk after receiving messages
    save_chat_state(chat_state);

    Ok(Redirect::to(&redirect_url))
}

/// List users registered on the remote relay (for discovery)
#[instrument(skip(app_state))]
async fn list_relay_users(
    State(app_state): State<AppState>,
) -> std::result::Result<axum::Json<Vec<relay_client::RegisteredUser>>, StatusCode> {
    match app_state.relay_client.list_users().await {
        Ok(users) => Ok(axum::Json(users)),
        Err(e) => {
            error!("Failed to list users from relay: {:?}", e);
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}
