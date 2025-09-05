//! CSRF protection for PQPGP web interface
//!
//! Provides Cross-Site Request Forgery protection using session-based tokens.

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tower_sessions::Session;
use uuid::Uuid;

/// CSRF token store - in a production system, this would be backed by a database
#[derive(Clone, Debug)]
pub struct CsrfStore {
    tokens: Arc<RwLock<HashMap<String, String>>>,
}

impl CsrfStore {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a new CSRF token for the session
    pub fn generate_token(&self, session_id: &str) -> String {
        let token = Uuid::new_v4().to_string();
        let mut tokens = self.tokens.write().unwrap();
        tokens.insert(session_id.to_string(), token.clone());
        token
    }

    /// Validate a CSRF token for the session
    pub fn validate_token(&self, session_id: &str, token: &str) -> bool {
        let tokens = self.tokens.read().unwrap();
        tokens.get(session_id).is_some_and(|stored| stored == token)
    }
}

/// Get or create a CSRF token for the current session
pub async fn get_csrf_token(
    session: &Session,
    csrf_store: &CsrfStore,
) -> Result<String, StatusCode> {
    use tracing::{debug, error};

    // Get session ID, create a new session if none exists
    let session_id = match session.id() {
        Some(id) => {
            debug!("Using existing session: {}", id);
            id.to_string()
        }
        None => {
            debug!("Creating new session");
            // Create a new session by inserting data
            session.insert("initialized", true).await.map_err(|e| {
                error!("Failed to initialize session: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            // Save/commit the session to ensure it gets an ID
            session.save().await.map_err(|e| {
                error!("Failed to save session: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            match session.id() {
                Some(id) => {
                    debug!("New session created: {}", id);
                    id.to_string()
                }
                None => {
                    error!("Failed to get session ID after initialization and save");
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
        }
    };

    // Check if we already have a token for this session
    let tokens = csrf_store.tokens.read().unwrap();
    if let Some(existing_token) = tokens.get(&session_id) {
        debug!("Using existing CSRF token for session {}", session_id);
        return Ok(existing_token.clone());
    }
    drop(tokens);

    // Generate new token
    debug!("Generating new CSRF token for session {}", session_id);
    Ok(csrf_store.generate_token(&session_id))
}

/// Form data wrapper that includes CSRF token validation
#[derive(Debug, Deserialize, Serialize)]
pub struct CsrfProtectedForm<T> {
    pub csrf_token: String,
    #[serde(flatten)]
    pub data: T,
}

impl<T> CsrfProtectedForm<T> {
    /// Validate the CSRF token
    pub fn validate(&self, session: &Session, csrf_store: &CsrfStore) -> bool {
        let session_id = match session.id() {
            Some(id) => id.to_string(),
            None => return false,
        };
        csrf_store.validate_token(&session_id, &self.csrf_token)
    }
}
