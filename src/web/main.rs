//! Web server binary for PQPGP - provides a web interface for post-quantum cryptographic operations.

use askama::Template;
use axum::{
    extract::{Form, Multipart, Path as AxumPath, State},
    http::StatusCode,
    response::{Html, Redirect},
    routing::{get, post},
    Router,
};
use pqpgp::{
    armor::{create_signed_message, decode, encode, ArmorType},
    cli::utils::create_keyring_manager,
    crypto::{sign_message as crypto_sign_message, Algorithm, KeyPair, Password},
};
use rand::rngs::OsRng;
use serde::Deserialize;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};
use tracing::{error, info, instrument, warn};
use tracing_subscriber::EnvFilter;

mod csrf;
mod templates;
use csrf::{get_csrf_token, CsrfProtectedForm, CsrfStore};
use templates::{SigningKeyInfo, *};

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

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pqpgp=info,tower_http=debug".into()),
        )
        .init();

    // Initialize CSRF store
    let csrf_store = CsrfStore::new();

    // Set up session management
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false) // Set to true in production with HTTPS
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_name("pqpgp-session") // Give the session cookie a specific name
        .with_http_only(true); // Prevent JavaScript access to session cookie

    // Build our application with routes
    let app = Router::new()
        .route("/", get(index))
        .route("/keys", get(list_keys))
        .route("/keys/generate", post(generate_key))
        .route("/keys/delete/:key_id", post(delete_key))
        .route("/keys/export/:key_id", get(export_public_key))
        .route("/keys/view/:key_id", get(view_public_key))
        .route("/keys/import", post(import_public_key))
        .route("/encrypt", get(encrypt_page).post(encrypt_message))
        .route("/decrypt", get(decrypt_page).post(decrypt_message))
        .route("/sign", get(sign_page).post(sign_message))
        .route("/verify", get(verify_page).post(verify_signature))
        .nest_service("/static", ServeDir::new("src/web/static"))
        .layer(session_layer)
        .with_state(csrf_store);

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
    State(csrf_store): State<CsrfStore>,
    session: Session,
) -> std::result::Result<Html<String>, StatusCode> {
    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager: {:?}", e);
            // For list_keys, we'll show empty list with an error message in the template
            let csrf_token = get_csrf_token(&session, &csrf_store)
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

            KeyInfo {
                key_id: format!("{:016X}", key_id),
                algorithm: entry.public_key.algorithm().to_string(),
                user_ids: entry.user_ids.clone(),
                has_private_key: has_private,
                is_password_protected,
            }
        })
        .collect();

    let csrf_token = get_csrf_token(&session, &csrf_store).await.map_err(|_| {
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
    State(csrf_store): State<CsrfStore>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<GenerateKeyForm>>,
) -> std::result::Result<Redirect, StatusCode> {
    // Validate CSRF token
    if !form.validate(&session, &csrf_store) {
        warn!("CSRF validation failed for key generation");
        return Err(StatusCode::FORBIDDEN);
    }
    let mut rng = OsRng;
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
        Algorithm::Mlkem1024 => KeyPair::generate_mlkem1024(&mut rng),
        Algorithm::Mldsa87 => KeyPair::generate_mldsa87(&mut rng),
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

                    KeyInfo {
                        key_id: format!("{:016X}", key_id),
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
    State(csrf_store): State<CsrfStore>,
    session: Session,
) -> std::result::Result<Html<String>, StatusCode> {
    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager for encrypt page: {:?}", e);
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
        .map(|(key_id, entry, _)| SigningKeyInfo {
            key_id: format!("{:016X}", key_id),
            user_id: entry.user_ids.first().cloned().unwrap_or_default(),
        })
        .collect();

    info!(
        "Encrypt page loaded with {} recipients and {} signing keys",
        recipients.len(),
        signing_keys.len()
    );

    let csrf_token = get_csrf_token(&session, &csrf_store).await.map_err(|_| {
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
async fn encrypt_message(
    State(csrf_store): State<CsrfStore>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<EncryptForm>>,
) -> std::result::Result<Html<String>, StatusCode> {
    // Validate CSRF token
    if !form.validate(&session, &csrf_store) {
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
            .map(|(key_id, entry, _)| SigningKeyInfo {
                key_id: format!("{:016X}", key_id),
                user_id: entry.user_ids.first().cloned().unwrap_or_default(),
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
        let csrf_token = get_csrf_token(&session, &csrf_store)
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
    let mut rng = OsRng;
    let message_to_encrypt = if let Some(signing_key_id) = &form.data.signing_key {
        if !signing_key_id.is_empty() {
            // Parse signing key ID
            let signing_key_id = match u64::from_str_radix(signing_key_id, 16) {
                Ok(id) => id,
                Err(_) => {
                    error!("Invalid signing key ID format: {}", signing_key_id);
                    let csrf_token = get_csrf_token(&session, &csrf_store)
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

            let _signing_entry = match signing_entry {
                Some((_, entry, _)) => entry,
                None => {
                    error!(
                        "Signing key not found or not available: {:016X}",
                        signing_key_id
                    );
                    let csrf_token = get_csrf_token(&session, &csrf_store)
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
            };

            // Get private key for signing
            let private_key = match keyring.get_private_key(signing_key_id) {
                Some(pk) => pk,
                None => {
                    error!("Private signing key not found: {:016X}", signing_key_id);
                    let csrf_token = get_csrf_token(&session, &csrf_store)
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
            let signature = match crypto_sign_message(
                private_key,
                form.data.message.as_bytes(),
                password.as_ref(),
            ) {
                Ok(sig) => sig,
                Err(e) => {
                    error!("Failed to sign message: {:?}", e);
                    let csrf_token = get_csrf_token(&session, &csrf_store)
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
                    let csrf_token = get_csrf_token(&session, &csrf_store)
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
                    let csrf_token = get_csrf_token(&session, &csrf_store)
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
    let encrypted =
        match pqpgp::crypto::encrypt_message(recipient_key, &message_to_encrypt, &mut rng) {
            Ok(enc) => enc,
            Err(e) => {
                error!("Encryption failed: {:?}", e);
                let csrf_token = get_csrf_token(&session, &csrf_store)
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
        .map(|(key_id, entry, _)| SigningKeyInfo {
            key_id: format!("{:016X}", key_id),
            user_id: entry.user_ids.first().cloned().unwrap_or_default(),
        })
        .collect();

    let csrf_token = get_csrf_token(&session, &csrf_store).await.map_err(|_| {
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
    State(csrf_store): State<CsrfStore>,
    session: Session,
) -> std::result::Result<Html<String>, StatusCode> {
    let csrf_token = get_csrf_token(&session, &csrf_store).await.map_err(|_| {
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
async fn decrypt_message(
    State(csrf_store): State<CsrfStore>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<DecryptForm>>,
) -> std::result::Result<Html<String>, StatusCode> {
    // Validate CSRF token
    if !form.validate(&session, &csrf_store) {
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
        let csrf_token = get_csrf_token(&session, &csrf_store)
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
            match pqpgp::crypto::decrypt_message(private_key, &encrypted_message, password.as_ref())
            {
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
                match pqpgp::crypto::decrypt_message(
                    private_key,
                    &encrypted_message,
                    password.as_ref(),
                ) {
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
    let csrf_token = get_csrf_token(&session, &csrf_store).await.map_err(|_| {
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
    State(csrf_store): State<CsrfStore>,
    session: Session,
) -> std::result::Result<Html<String>, StatusCode> {
    let keyring = match create_keyring_manager() {
        Ok(kr) => kr,
        Err(e) => {
            error!("Failed to create keyring manager for sign page: {:?}", e);
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
        .map(|(key_id, entry, _)| SigningKeyInfo {
            key_id: format!("{:016X}", key_id),
            user_id: entry.user_ids.first().cloned().unwrap_or_default(),
        })
        .collect();

    info!("Sign page loaded with {} signing keys", signing_keys.len());

    let csrf_token = get_csrf_token(&session, &csrf_store).await.map_err(|_| {
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
async fn sign_message(
    State(csrf_store): State<CsrfStore>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<SignForm>>,
) -> std::result::Result<Html<String>, StatusCode> {
    // Validate CSRF token
    if !form.validate(&session, &csrf_store) {
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
            .map(|(key_id, entry, _)| SigningKeyInfo {
                key_id: format!("{:016X}", key_id),
                user_id: entry.user_ids.first().cloned().unwrap_or_default(),
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
    let signature = match pqpgp::crypto::sign_message(
        private_key,
        form.data.message.as_bytes(),
        password.as_ref(),
    ) {
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
        .map(|(key_id, entry, _)| SigningKeyInfo {
            key_id: format!("{:016X}", key_id),
            user_id: entry.user_ids.first().cloned().unwrap_or_default(),
        })
        .collect();

    let csrf_token = get_csrf_token(&session, &csrf_store).await.map_err(|_| {
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
    State(csrf_store): State<CsrfStore>,
    session: Session,
) -> std::result::Result<Html<String>, StatusCode> {
    let csrf_token = get_csrf_token(&session, &csrf_store).await.map_err(|_| {
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
async fn verify_signature(
    State(csrf_store): State<CsrfStore>,
    session: Session,
    Form(form): Form<CsrfProtectedForm<VerifyForm>>,
) -> std::result::Result<Html<String>, StatusCode> {
    // Validate CSRF token
    if !form.validate(&session, &csrf_store) {
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
            let csrf_token = get_csrf_token(&session, &csrf_store)
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
        pqpgp::crypto::verify_signature(verifying_key, form.data.message.as_bytes(), &signature);
    let is_valid = verification_result.is_ok();

    if let Err(e) = &verification_result {
        warn!("Signature verification failed: {:?}", e);
    }

    info!(
        "Signature verification result: {}",
        if is_valid { "VALID" } else { "INVALID" }
    );

    let csrf_token = get_csrf_token(&session, &csrf_store).await.map_err(|_| {
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
