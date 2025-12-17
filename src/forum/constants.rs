//! Shared constants for forum validation and limits.
//!
//! These constants are used by both the library and relay server to ensure
//! consistent validation across all implementations.

// =============================================================================
// Content Size Limits
// =============================================================================

/// Maximum forum/board name size (256 bytes).
pub const MAX_NAME_SIZE: usize = 256;

/// Maximum forum/board description size (10KB).
pub const MAX_DESCRIPTION_SIZE: usize = 10 * 1024;

/// Maximum thread title size (512 bytes).
pub const MAX_THREAD_TITLE_SIZE: usize = 512;

/// Maximum thread body size (100KB).
pub const MAX_THREAD_BODY_SIZE: usize = 100 * 1024;

/// Maximum post body size (100KB).
pub const MAX_POST_BODY_SIZE: usize = 100 * 1024;

/// Maximum number of tags per board.
pub const MAX_TAGS_COUNT: usize = 10;

/// Maximum length of a single tag (64 bytes).
pub const MAX_TAG_SIZE: usize = 64;

// =============================================================================
// DAG Limits
// =============================================================================

/// Maximum number of parent hashes allowed in a post.
/// Set high enough to handle active forums with many concurrent heads.
pub const MAX_PARENT_HASHES: usize = 50;

/// Maximum number of parent hashes allowed in a moderation action.
pub const MAX_MOD_ACTION_PARENTS: usize = 50;

// =============================================================================
// Timestamp Validation
// =============================================================================

/// Maximum allowed clock skew for timestamps (5 minutes in milliseconds).
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

/// Minimum valid timestamp (2024-01-01 00:00:00 UTC in milliseconds).
/// Prevents nodes with unreasonably old or zero timestamps.
pub const MIN_VALID_TIMESTAMP_MS: u64 = 1704067200000;

// =============================================================================
// Sync Protocol Limits
// =============================================================================

/// Maximum number of hashes allowed in a single fetch request.
pub const MAX_FETCH_BATCH_SIZE: usize = 1000;

/// Maximum number of missing hashes returned in a sync response.
pub const MAX_SYNC_MISSING_HASHES: usize = 10000;

/// Maximum nodes returned in a single export page.
pub const MAX_EXPORT_PAGE_SIZE: usize = 1000;

// =============================================================================
// Global Resource Limits
// =============================================================================

/// Maximum number of forums that can be hosted on a relay.
pub const MAX_FORUMS: usize = 10000;

/// Maximum number of nodes per forum (includes all node types).
pub const MAX_NODES_PER_FORUM: usize = 1_000_000;

/// Maximum messages to queue per recipient on the relay.
pub const MAX_QUEUED_MESSAGES: usize = 1000;

/// Maximum message size in bytes (base64 encoded).
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB
