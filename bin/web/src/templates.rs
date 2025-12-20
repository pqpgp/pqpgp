//! Askama templates for PQPGP web interface

use askama::Template;

/// Key information for display
#[derive(Debug)]
pub struct KeyInfo {
    pub key_id: String,
    pub fingerprint: String,
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
    /// Public key fingerprint (first 16 hex chars of SHA3-512 hash)
    pub fingerprint: String,
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

/// File encryption/decryption template
#[derive(Template)]
#[template(path = "files.html")]
pub struct FilesTemplate {
    pub recipients: Vec<RecipientInfo>,
    pub signing_keys: Vec<SigningKeyInfo>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    pub signature_found: bool,
    pub signature_armored: Option<String>,
    pub signer_info: Option<String>,
    pub signature_verified: Option<bool>,
    pub verification_message: Option<String>,
    pub active_page: String,
    pub csrf_token: String,
}

/// Chat contact information
#[derive(Debug, Clone)]
pub struct ChatContact {
    pub fingerprint: String,
    pub name: String,
    pub has_session: bool,
    pub is_selected: bool,
    pub initial: char,
}

/// Chat message for display
#[derive(Debug, Clone)]
pub struct ChatMessageDisplay {
    pub content: String,
    pub timestamp: String,
    pub is_outgoing: bool,
}

/// Chat template
#[derive(Template)]
#[template(path = "chat.html")]
pub struct ChatTemplate {
    pub active_page: String,
    pub csrf_token: String,
    pub contacts: Vec<ChatContact>,
    pub selected_contact: Option<String>,
    pub selected_contact_name: Option<String>,
    pub messages: Vec<ChatMessageDisplay>,
    pub our_identity: Option<String>,
    pub our_prekey_bundle: Option<String>,
    pub saved_identities: Vec<String>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
}

// ============================================================================
// Forum Templates
// ============================================================================

/// Forum info for display
#[derive(Debug, Clone)]
pub struct ForumDisplayInfo {
    pub hash: String,
    pub name: String,
    pub description: String,
    pub created_at_display: String,
    pub board_count: usize,
}

/// Board info for display
#[derive(Debug, Clone)]
pub struct BoardDisplayInfo {
    pub hash: String,
    pub name: String,
    pub description: String,
    pub created_at_display: String,
    pub thread_count: usize,
}

/// Thread info for display
#[derive(Debug, Clone)]
pub struct ThreadDisplayInfo {
    pub hash: String,
    pub title: String,
    pub body_preview: String,
    pub author_short: String,
    pub post_count: usize,
    pub created_at_display: String,
}

/// Post info for display
#[derive(Debug, Clone)]
pub struct PostDisplayInfo {
    pub hash: String,
    pub body: String,
    pub author_short: String,
    pub quote_body: Option<String>,
    pub created_at_display: String,
}

/// Moderator info for display
#[derive(Debug, Clone)]
pub struct ModeratorDisplayInfo {
    pub identity_fingerprint: String,
    pub is_owner: bool,
}

/// Forum listing template
#[derive(Template)]
#[template(path = "forum.html")]
pub struct ForumListTemplate {
    pub active_page: String,
    pub csrf_token: String,
    pub forums: Vec<ForumDisplayInfo>,
    pub signing_keys: Vec<SigningKeyInfo>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    // Pagination
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub current_cursor: Option<String>,
    pub total_forums: usize,
    pub has_more: bool,
}

/// Single forum view template
#[derive(Template)]
#[template(path = "forum_view.html")]
pub struct ForumViewTemplate {
    pub active_page: String,
    pub csrf_token: String,
    pub forum_hash: String,
    pub forum_hash_short: String,
    pub forum_name: String,
    pub forum_description: String,
    pub created_at_display: String,
    pub boards: Vec<BoardDisplayInfo>,
    pub signing_keys: Vec<SigningKeyInfo>,
    pub moderators: Vec<ModeratorDisplayInfo>,
    pub is_owner: bool,
    pub is_moderator: bool,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    // Pagination
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub current_cursor: Option<String>,
    pub total_boards: usize,
    pub has_more: bool,
}

/// Board view template
#[derive(Template)]
#[template(path = "board_view.html")]
pub struct BoardViewTemplate {
    pub active_page: String,
    pub csrf_token: String,
    pub forum_hash: String,
    pub forum_name: String,
    pub board_hash: String,
    pub board_name: String,
    pub board_description: String,
    pub threads: Vec<ThreadDisplayInfo>,
    pub signing_keys: Vec<SigningKeyInfo>,
    pub board_moderators: Vec<ModeratorDisplayInfo>,
    pub is_forum_moderator: bool,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    // Pagination
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub current_cursor: Option<String>,
    pub total_threads: usize,
    pub has_more: bool,
}

/// Thread view template
#[derive(Template)]
#[template(path = "thread_view.html")]
pub struct ThreadViewTemplate {
    pub active_page: String,
    pub csrf_token: String,
    pub forum_hash: String,
    pub forum_name: String,
    pub board_hash: String,
    pub board_name: String,
    pub thread_hash: String,
    pub thread_title: String,
    pub thread_body: String,
    pub thread_author_short: String,
    pub thread_created_at_display: String,
    pub posts: Vec<PostDisplayInfo>,
    pub signing_keys: Vec<SigningKeyInfo>,
    /// Whether the current user is a moderator (can hide/unhide content).
    pub is_moderator: bool,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    // Pagination
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub current_cursor: Option<String>,
    pub total_posts: usize,
    pub has_more: bool,
}

/// Move thread page template - shows paginated board selection.
#[derive(Template)]
#[template(path = "move_thread.html")]
pub struct MoveThreadTemplate {
    pub active_page: String,
    pub csrf_token: String,
    pub forum_hash: String,
    pub forum_name: String,
    pub board_hash: String,
    pub board_name: String,
    pub thread_hash: String,
    pub thread_title: String,
    /// Available destination boards (paginated).
    pub boards: Vec<BoardDisplayInfo>,
    pub signing_keys: Vec<SigningKeyInfo>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    // Pagination
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub current_cursor: Option<String>,
    pub total_boards: usize,
    pub has_more: bool,
}

// ============================================================================
// Private Message Templates
// ============================================================================

/// Encryption identity info for display (user's PM identity in a forum).
#[derive(Debug, Clone)]
pub struct EncryptionIdentityInfo {
    /// Hash of the EncryptionIdentity node.
    pub hash: String,
    /// Fingerprint of the owner's signing key.
    pub owner_fingerprint: String,
    /// Number of one-time prekeys remaining.
    pub otp_count: usize,
    /// When the identity was created.
    pub created_at_display: String,
}

/// Conversation info for inbox display.
#[derive(Debug, Clone)]
pub struct ConversationInfo {
    /// Conversation ID (hex encoded).
    pub id: String,
    /// Short display ID (for future use in compact views).
    #[allow(dead_code)]
    pub id_short: String,
    /// Peer's fingerprint (owner of their encryption identity, for future use).
    #[allow(dead_code)]
    pub peer_fingerprint: String,
    /// Short peer fingerprint for display.
    pub peer_short: String,
    /// Last message preview.
    pub last_message_preview: String,
    /// Last activity timestamp.
    pub last_activity_display: String,
    /// Number of messages in conversation.
    pub message_count: usize,
    /// Whether there are unread messages.
    pub has_unread: bool,
}

/// Private message for display.
#[derive(Debug, Clone)]
pub struct PrivateMessageInfo {
    /// Message ID (hex encoded).
    pub message_id: String,
    /// Message body content.
    pub body: String,
    /// Optional subject line.
    pub subject: Option<String>,
    /// Whether this message was sent by us.
    pub is_outgoing: bool,
    /// Timestamp display string.
    pub timestamp_display: String,
    /// ID of message this is replying to (if any).
    pub reply_to: Option<String>,
}

/// User info for recipient selection (someone who has published encryption identity).
#[derive(Debug, Clone)]
pub struct PMRecipientInfo {
    /// Fingerprint of the user's signing key (for future use in expanded views).
    #[allow(dead_code)]
    pub fingerprint: String,
    /// Short fingerprint for display.
    pub fingerprint_short: String,
    /// Hash of their encryption identity node.
    pub encryption_identity_hash: String,
}

/// Private messages inbox template.
#[derive(Template)]
#[template(path = "pm_inbox.html")]
pub struct PMInboxTemplate {
    pub active_page: String,
    pub csrf_token: String,
    pub forum_hash: String,
    pub forum_name: String,
    /// Our encryption identities (all keys we own that have PM identities).
    pub our_identities: Vec<EncryptionIdentityInfo>,
    /// List of conversations.
    pub conversations: Vec<ConversationInfo>,
    /// Available recipients (users with encryption identities).
    pub recipients: Vec<PMRecipientInfo>,
    /// Signing keys for creating encryption identity.
    pub signing_keys: Vec<SigningKeyInfo>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    // Pagination
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub current_cursor: Option<String>,
    pub total_conversations: usize,
    pub has_more: bool,
}

/// Single conversation view template.
#[derive(Template)]
#[template(path = "pm_conversation.html")]
pub struct PMConversationTemplate {
    pub active_page: String,
    pub csrf_token: String,
    pub forum_hash: String,
    pub forum_name: String,
    pub conversation_id: String,
    pub peer_fingerprint: String,
    pub peer_short: String,
    /// Messages in the conversation.
    pub messages: Vec<PrivateMessageInfo>,
    /// Signing keys for sending replies.
    pub signing_keys: Vec<SigningKeyInfo>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
    // Pagination
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub current_cursor: Option<String>,
    pub total_messages: usize,
    pub has_more: bool,
}

/// Compose new private message template.
#[derive(Template)]
#[template(path = "pm_compose.html")]
pub struct PMComposeTemplate {
    pub active_page: String,
    pub csrf_token: String,
    pub forum_hash: String,
    pub forum_name: String,
    /// Pre-selected recipient (if any).
    pub recipient: Option<PMRecipientInfo>,
    /// Available recipients.
    pub recipients: Vec<PMRecipientInfo>,
    /// Our encryption identity.
    pub our_identity: Option<EncryptionIdentityInfo>,
    /// Signing keys.
    pub signing_keys: Vec<SigningKeyInfo>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub has_result: bool,
    pub has_error: bool,
}
