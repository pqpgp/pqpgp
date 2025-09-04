//! Askama templates for PQPGP web interface

use askama::Template;

/// Key information for display
#[derive(Debug)]
pub struct KeyInfo {
    pub key_id: String,
    pub algorithm: String,
    pub user_ids: Vec<String>,
    pub has_private_key: bool,
    pub is_password_protected: bool,
}

/// Recipient information for encryption
#[derive(Debug)]
pub struct RecipientInfo {
    pub key_id: String,
    pub user_id: String,
}

/// Signing key information
#[derive(Debug)]
pub struct SigningKeyInfo {
    pub key_id: String,
    pub user_id: String,
}

/// Index page template
#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub active_page: String,
}

/// Keys listing template
#[derive(Template)]
#[template(path = "keys.html")]
pub struct KeysTemplate {
    pub keys: Vec<KeyInfo>,
    pub active_page: String,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    pub csrf_token: String,
}

/// Encryption template
#[derive(Template)]
#[template(path = "encrypt.html")]
pub struct EncryptTemplate {
    pub recipients: Vec<RecipientInfo>,
    pub signing_keys: Vec<SigningKeyInfo>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    pub active_page: String,
    pub csrf_token: String,
}

/// Decryption template
#[derive(Template)]
#[template(path = "decrypt.html")]
pub struct DecryptTemplate {
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    pub active_page: String,
    pub csrf_token: String,
}

/// Signing template
#[derive(Template)]
#[template(path = "sign.html")]
pub struct SignTemplate {
    pub signing_keys: Vec<SigningKeyInfo>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    pub active_page: String,
    pub csrf_token: String,
}

/// Verification template
#[derive(Template)]
#[template(path = "verify.html")]
pub struct VerifyTemplate {
    pub is_valid: Option<bool>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    pub active_page: String,
    pub csrf_token: String,
}

/// View public key template
#[derive(Template)]
#[template(path = "view_public_key.html")]
pub struct ViewPublicKeyTemplate {
    pub key_id: String,
    pub algorithm: String,
    pub user_ids: Vec<String>,
    pub public_key_armored: String,
    pub active_page: String,
}
