//! Forum data persistence using RocksDB.
//!
//! This module provides persistent storage for forum DAG nodes using RocksDB
//! for efficient key-value storage with column families for logical separation.
//!
//! ## Storage Layout
//!
//! Uses column families for logical separation:
//! - `nodes`: `{forum_hash}:{node_hash}` -> serialized DagNode
//! - `forums`: `{forum_hash}` -> forum metadata
//! - `heads`: `{forum_hash}` -> serialized Vec<ContentHash> (DAG heads)
//! - `meta`: `forum_list` -> list of all synced forum hashes
//! - `private`: Local-only data (encryption keys, conversations, consumed OTPs)
//!
//! ## SECURITY NOTE: Encryption Private Keys
//!
//! **Current Implementation**: Encryption identity private keys are stored using
//! bincode serialization without additional encryption. This means:
//!
//! - **Local storage security depends on file system security**
//! - If an attacker gains access to the storage directory, they can read private keys
//! - All PM decryption capability would be compromised
//!
//! **Recommendation for Production**:
//! - Use full-disk encryption (BitLocker, LUKS, FileVault)
//! - Apply restrictive file permissions (chmod 600 on Unix)
//! - Consider application-level encryption with user-provided password
//!
//! **Future Enhancement**: Add optional password-based encryption using
//! `EncryptedPrivateKey` from `crate::crypto::password` module for private
//! key storage. This would require:
//! - Password prompt on application startup
//! - Key derivation and caching for the session
//! - Secure memory handling with zeroization

use crate::error::{PqpgpError, Result};
use crate::forum::conversation::{ConversationManager, ConversationSession, CONVERSATION_ID_SIZE};
use crate::forum::encryption_identity::EncryptionIdentityPrivate;
use crate::forum::{
    BoardGenesis, ContentHash, DagNode, EditNode, ForumGenesis, ModAction, ModActionNode, Post,
    SealedPrivateMessage, ThreadRoot,
};
use crate::storage::{composite_key, RocksDbConfig, RocksDbHandle};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::{debug, info};

/// Default data directory name.
const DEFAULT_DATA_DIR: &str = "pqpgp_forum_data";

/// Database subdirectory.
const DB_DIR: &str = "forum_db";

/// Column family names.
const CF_NODES: &str = "nodes";
const CF_FORUMS: &str = "forums";
const CF_HEADS: &str = "heads";
const CF_META: &str = "meta";
const CF_PRIVATE: &str = "private";

/// Index column families for fast queries.
/// These store lightweight references to enable O(1) lookups instead of full scans.
const CF_IDX_FORUMS: &str = "idx_forums"; // inverted_timestamp + forum_hash -> () (sorted by time desc)
const CF_IDX_BOARDS: &str = "idx_boards"; // forum_hash + inverted_timestamp + board_hash -> ()
const CF_IDX_THREADS: &str = "idx_threads"; // forum_hash + board_hash + inverted_timestamp + thread_hash -> ()
const CF_IDX_POSTS: &str = "idx_posts"; // forum_hash + thread_hash + timestamp + post_hash -> ()
const CF_IDX_POST_COUNTS: &str = "idx_post_counts"; // forum_hash + thread_hash -> u64 count
const CF_IDX_MOD_ACTIONS: &str = "idx_mod_actions"; // forum_hash + mod_action_hash -> timestamp
const CF_IDX_EDITS: &str = "idx_edits"; // forum_hash + target_hash + edit_hash -> timestamp
const CF_IDX_ENCRYPTION_IDS: &str = "idx_encryption_ids"; // forum_hash + identity_hash -> timestamp
const CF_IDX_SEALED_MSGS: &str = "idx_sealed_msgs"; // forum_hash + timestamp + msg_hash -> () (sorted for scan)

// Count caches for O(1) total count queries (Issue #1, #7)
const CF_IDX_BOARD_COUNTS: &str = "idx_board_counts"; // forum_hash -> u64 board count
const CF_IDX_THREAD_COUNTS: &str = "idx_thread_counts"; // forum_hash + board_hash -> u64 thread count

// Mod action derived state indexes (Issues #2, #3, #4)
const CF_IDX_MOVED_THREADS: &str = "idx_moved_threads"; // forum_hash + thread_hash -> board_hash (current location)
const CF_IDX_MOVED_IN_THREADS: &str = "idx_moved_in_threads"; // forum_hash + dest_board + inverted_ts + thread_hash -> () (for pagination)
const CF_IDX_HIDDEN_THREADS: &str = "idx_hidden_threads"; // forum_hash + thread_hash -> () (presence = hidden)
const CF_IDX_HIDDEN_POSTS: &str = "idx_hidden_posts"; // forum_hash + post_hash -> () (presence = hidden)
const CF_IDX_HIDDEN_BOARDS: &str = "idx_hidden_boards"; // forum_hash + board_hash -> () (presence = hidden)
const CF_IDX_FORUM_MODS: &str = "idx_forum_mods"; // forum_hash + fingerprint -> role byte (1=owner, 2=mod)
const CF_IDX_BOARD_MODS: &str = "idx_board_mods"; // forum_hash + board_hash + fingerprint -> () (presence = mod)

/// Key for global forum count in the meta column family.
const META_FORUM_COUNT: &[u8] = b"forum_count";

/// Key for the forum list in the meta column family.
const META_FORUM_LIST: &[u8] = b"forum_list";

/// Prefix for encryption private keys in the private column family.
const PRIVATE_ENCRYPTION_KEY_PREFIX: &[u8] = b"enc_key:";

/// Prefix for conversation sessions in the private column family.
const PRIVATE_CONVERSATION_PREFIX: &[u8] = b"conv:";

/// Key for conversation manager in the private column family.
const PRIVATE_CONVERSATION_MANAGER: &[u8] = b"conv_manager";

/// Prefix for consumed OTPs in the private column family.
const PRIVATE_CONSUMED_OTP_PREFIX: &[u8] = b"consumed_otp:";

/// Prefix for sync cursors in the private column family.
/// Key format: sync_cursor:{forum_hash} -> (timestamp, Option<hash>)
const PRIVATE_SYNC_CURSOR_PREFIX: &[u8] = b"sync_cursor:";

/// Forum metadata stored in the forums column family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForumMetadata {
    /// Forum name.
    pub name: String,
    /// Forum description.
    pub description: String,
    /// Creation timestamp.
    pub created_at: u64,
    /// Owner's identity bytes.
    pub owner_identity: Vec<u8>,
}

/// Default page size for paginated queries.
pub const DEFAULT_PAGE_SIZE: usize = 20;

/// Cursor for pagination, encoding the position in a sorted list.
///
/// Uses timestamp + hash to ensure stable pagination even with duplicate timestamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cursor {
    /// Timestamp of the last item in the previous page.
    pub timestamp: u64,
    /// Hash of the last item (for tie-breaking when timestamps are equal).
    pub hash: ContentHash,
}

impl Cursor {
    /// Creates a new cursor from timestamp and hash.
    pub fn new(timestamp: u64, hash: ContentHash) -> Self {
        Self { timestamp, hash }
    }

    /// Encodes the cursor as a base64 string for URL-safe transport.
    pub fn encode(&self) -> String {
        let bytes = bincode::serialize(self).unwrap_or_default();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
    }

    /// Decodes a cursor from a base64 string.
    pub fn decode(s: &str) -> Option<Self> {
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s).ok()?;
        bincode::deserialize(&bytes).ok()
    }
}

/// Result of a paginated query.
#[derive(Debug, Clone)]
pub struct PaginatedResult<T> {
    /// The items in this page.
    pub items: Vec<T>,
    /// Cursor for the next page, if there are more items.
    pub next_cursor: Option<Cursor>,
    /// Total count of items (if available, for display purposes).
    pub total_count: Option<usize>,
}

impl<T> PaginatedResult<T> {
    /// Returns true if there are more pages after this one.
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
}

/// Summary of a thread with post count (for efficient listing).
#[derive(Debug, Clone)]
pub struct ThreadSummary {
    /// The thread data.
    pub thread: ThreadRoot,
    /// Number of posts (replies) in the thread.
    pub post_count: usize,
}

/// Summary of a board with effective name/description after edits applied.
#[derive(Debug, Clone)]
pub struct BoardSummary {
    /// The board data.
    pub board: BoardGenesis,
    /// Effective name after edits (or original if no edits).
    pub effective_name: String,
    /// Effective description after edits (or original if no edits).
    pub effective_description: String,
    /// Number of threads in this board.
    pub thread_count: usize,
}

/// Summary of a post with resolved quote content (for efficient listing).
#[derive(Debug, Clone)]
pub struct PostSummary {
    /// The post data.
    pub post: Post,
    /// Resolved quote preview (first 200 chars of quoted post body), if this post quotes another.
    pub quote_preview: Option<String>,
}

/// Summary of a forum with board count (for efficient listing).
#[derive(Debug, Clone)]
pub struct ForumSummary {
    /// The forum hash.
    pub hash: ContentHash,
    /// The forum metadata.
    pub metadata: ForumMetadata,
    /// Effective name after edits (or original if no edits).
    pub effective_name: String,
    /// Effective description after edits (or original if no edits).
    pub effective_description: String,
    /// Number of boards in this forum.
    pub board_count: usize,
}

/// RocksDB-backed forum storage.
#[derive(Debug)]
pub struct ForumStorage {
    db: RocksDbHandle,
}

impl ForumStorage {
    /// Creates a new storage manager with the default data directory.
    pub fn new_default() -> Result<Self> {
        Self::new(DEFAULT_DATA_DIR)
    }

    /// Creates a new storage manager with a custom data directory.
    ///
    /// Automatically rebuilds indexes if they are missing (migration from older versions).
    pub fn new(data_dir: impl AsRef<Path>) -> Result<Self> {
        let db_path = data_dir.as_ref().join(DB_DIR);
        let config = RocksDbConfig::default();
        let column_families = &[
            CF_NODES,
            CF_FORUMS,
            CF_HEADS,
            CF_META,
            CF_PRIVATE,
            // Index column families for fast queries
            CF_IDX_FORUMS,
            CF_IDX_BOARDS,
            CF_IDX_THREADS,
            CF_IDX_POSTS,
            CF_IDX_POST_COUNTS,
            CF_IDX_MOD_ACTIONS,
            CF_IDX_EDITS,
            CF_IDX_ENCRYPTION_IDS,
            CF_IDX_SEALED_MSGS,
            // Count caches
            CF_IDX_BOARD_COUNTS,
            CF_IDX_THREAD_COUNTS,
            // Mod action derived state
            CF_IDX_MOVED_THREADS,
            CF_IDX_MOVED_IN_THREADS,
            CF_IDX_HIDDEN_THREADS,
            CF_IDX_HIDDEN_POSTS,
            CF_IDX_HIDDEN_BOARDS,
            CF_IDX_FORUM_MODS,
            CF_IDX_BOARD_MODS,
        ];

        let db = RocksDbHandle::open(&db_path, &config, column_families)?;
        info!("Opened forum RocksDB at {:?}", db_path);

        let storage = Self { db };

        // Check if indexes need to be rebuilt (migration from older versions)
        storage.ensure_indexes_exist()?;

        Ok(storage)
    }

    /// Checks if indexes exist and rebuilds them if missing.
    ///
    /// This handles migration from older database versions that didn't have indexes.
    fn ensure_indexes_exist(&self) -> Result<()> {
        let forums = self.list_forums()?;
        info!("Index check: found {} forums in list", forums.len());

        if forums.is_empty() {
            info!("No forums found, skipping index check");
            return Ok(()); // No forums, nothing to index
        }

        // Check if we have the forum index (72 bytes: inverted_timestamp 8 + forum_hash 64)
        let mut has_forum_index = false;
        self.db.prefix_iterate(CF_IDX_FORUMS, &[], |key, _| {
            if key.len() == 72 {
                has_forum_index = true;
                return false; // Stop after finding one valid entry
            }
            true
        })?;

        // Check if we have any VALID index entries for the first forum
        // New format: 136 bytes (forum_hash 64 + inverted_timestamp 8 + board_hash 64)
        // Old format: 128 bytes (forum_hash 64 + board_hash 64)
        let first_forum = &forums[0];
        let mut has_new_format_indexes = false;
        let mut has_old_format_indexes = false;
        let mut has_mod_action_indexes = false;

        self.db
            .prefix_iterate(CF_IDX_BOARDS, first_forum.as_bytes(), |key, _| {
                if key.len() == 136 {
                    has_new_format_indexes = true;
                    return false; // Stop after finding one valid entry
                } else if key.len() == 128 {
                    has_old_format_indexes = true;
                    return false;
                }
                true // Continue looking
            })?;

        // Also check mod action index (added later, may be missing)
        self.db
            .prefix_iterate(CF_IDX_MOD_ACTIONS, first_forum.as_bytes(), |key, _| {
                if key.len() == 128 {
                    has_mod_action_indexes = true;
                    return false;
                }
                true
            })?;

        // Check encryption identity index (128 bytes: forum_hash 64 + identity_hash 64)
        let mut has_encryption_id_index = false;
        self.db
            .prefix_iterate(CF_IDX_ENCRYPTION_IDS, first_forum.as_bytes(), |key, _| {
                if key.len() == 128 {
                    has_encryption_id_index = true;
                    return false;
                }
                true
            })?;

        // Check for count caches (new indexes)
        let has_board_count = self
            .db
            .get_raw(CF_IDX_BOARD_COUNTS, first_forum.as_bytes())?
            .is_some();

        // Check for mod-derived indexes (forum_hash 64 bytes prefix)
        let mut has_hidden_indexes = false;
        self.db
            .prefix_iterate(CF_IDX_HIDDEN_THREADS, first_forum.as_bytes(), |_, _| {
                has_hidden_indexes = true;
                false // Stop after finding one
            })?;
        // If no hidden threads, check if forum has any mod actions that would create hidden entries
        // For simplicity, we check if the forum_mods index exists instead
        let mut has_forum_mods_index = false;
        self.db
            .prefix_iterate(CF_IDX_FORUM_MODS, first_forum.as_bytes(), |_, _| {
                has_forum_mods_index = true;
                false
            })?;

        info!(
            "Index check for forum {}: forum_idx={}, new_format={}, old_format={}, mod_actions={}, enc_ids={}, board_counts={}, forum_mods={}",
            first_forum.short(),
            has_forum_index,
            has_new_format_indexes,
            has_old_format_indexes,
            has_mod_action_indexes,
            has_encryption_id_index,
            has_board_count,
            has_forum_mods_index
        );

        // Need to rebuild if:
        // 1. Forum index is missing
        // 2. No board indexes at all (but forum has boards)
        // 3. Old format indexes exist (need to migrate to new sorted format)
        // 4. Count caches are missing
        // 5. Forum mods index is missing (every forum has an owner, so this is a reliable indicator)
        //
        // Note: mod_action_indexes and encryption_id_index may legitimately be empty
        // if the forum has no mod actions or encryption identities. We use has_forum_mods_index
        // as the reliable indicator since every forum has an owner entry.
        let needs_rebuild = if !has_forum_index {
            info!("Forum index missing, will rebuild");
            true
        } else if has_new_format_indexes && has_board_count && has_forum_mods_index {
            false // Already have all indexes (mod_actions and enc_ids may be empty)
        } else if has_old_format_indexes {
            info!("Old index format detected, rebuilding for sorted pagination...");
            true
        } else if !has_new_format_indexes {
            // Check if this forum has any boards that should be indexed
            let nodes = self.load_forum_nodes(first_forum)?;
            let board_count = nodes
                .iter()
                .filter(|n| n.as_board_genesis().is_some())
                .count();
            info!(
                "Forum {} has {} nodes, {} boards",
                first_forum.short(),
                nodes.len(),
                board_count
            );
            board_count > 0
        } else if !has_board_count {
            info!("Board count cache missing, will rebuild");
            true
        } else if !has_forum_mods_index {
            info!("Forum mods index missing, will rebuild");
            true
        } else {
            false
        };

        if needs_rebuild {
            info!("Indexes missing or incomplete, rebuilding for faster queries...");
            self.rebuild_all_indexes()?;
        }

        Ok(())
    }

    /// Creates a composite key for node storage.
    fn node_key(forum_hash: &ContentHash, node_hash: &ContentHash) -> Vec<u8> {
        composite_key(forum_hash.as_bytes(), node_hash.as_bytes())
    }

    /// Inverts a timestamp so newer timestamps sort first in byte order.
    ///
    /// RocksDB sorts keys in ascending byte order, so we use `u64::MAX - timestamp`
    /// to make newer items appear first when iterating.
    fn invert_timestamp(timestamp: u64) -> [u8; 8] {
        (u64::MAX - timestamp).to_be_bytes()
    }

    /// Creates an index key for forum lookup: inverted_timestamp + forum_hash (72 bytes).
    ///
    /// The inverted timestamp ensures newest forums come first in iteration order.
    fn forum_index_key(timestamp: u64, forum_hash: &ContentHash) -> Vec<u8> {
        let mut key = Vec::with_capacity(72);
        key.extend_from_slice(&Self::invert_timestamp(timestamp));
        key.extend_from_slice(forum_hash.as_bytes());
        key
    }

    /// Creates an index key for board lookup: forum_hash + inverted_timestamp + board_hash (136 bytes).
    ///
    /// The inverted timestamp ensures newest boards come first in iteration order.
    fn board_index_key(
        forum_hash: &ContentHash,
        timestamp: u64,
        board_hash: &ContentHash,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(136);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(&Self::invert_timestamp(timestamp));
        key.extend_from_slice(board_hash.as_bytes());
        key
    }

    /// Creates an index key for thread lookup: forum_hash + board_hash + inverted_timestamp + thread_hash (200 bytes).
    ///
    /// The inverted timestamp ensures newest threads come first in iteration order.
    fn thread_index_key(
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
        timestamp: u64,
        thread_hash: &ContentHash,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(200);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(board_hash.as_bytes());
        key.extend_from_slice(&Self::invert_timestamp(timestamp));
        key.extend_from_slice(thread_hash.as_bytes());
        key
    }

    /// Creates a prefix key for threads in a board: forum_hash + board_hash (128 bytes).
    fn thread_index_prefix(forum_hash: &ContentHash, board_hash: &ContentHash) -> Vec<u8> {
        let mut key = Vec::with_capacity(128);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(board_hash.as_bytes());
        key
    }

    /// Creates an index key for post lookup: forum_hash + thread_hash + timestamp + post_hash (200 bytes).
    ///
    /// Unlike boards/threads, posts use NON-inverted timestamps so oldest posts
    /// come first (chronological reading order).
    fn post_index_key(
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
        timestamp: u64,
        post_hash: &ContentHash,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(200);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(thread_hash.as_bytes());
        key.extend_from_slice(&timestamp.to_be_bytes()); // NOT inverted - oldest first
        key.extend_from_slice(post_hash.as_bytes());
        key
    }

    /// Creates a prefix key for posts in a thread: forum_hash + thread_hash (128 bytes).
    fn post_index_prefix(forum_hash: &ContentHash, thread_hash: &ContentHash) -> Vec<u8> {
        let mut key = Vec::with_capacity(128);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(thread_hash.as_bytes());
        key
    }

    /// Creates a key for post count cache: forum_hash + thread_hash (128 bytes).
    fn post_count_key(forum_hash: &ContentHash, thread_hash: &ContentHash) -> Vec<u8> {
        let mut key = Vec::with_capacity(128);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(thread_hash.as_bytes());
        key
    }

    /// Creates an index key for mod action lookup: forum_hash + mod_action_hash (128 bytes).
    fn mod_action_index_key(forum_hash: &ContentHash, action_hash: &ContentHash) -> Vec<u8> {
        let mut key = Vec::with_capacity(128);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(action_hash.as_bytes());
        key
    }

    /// Creates an index key for edit lookup: forum_hash + target_hash + edit_hash (192 bytes).
    fn edit_index_key(
        forum_hash: &ContentHash,
        target_hash: &ContentHash,
        edit_hash: &ContentHash,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(192);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(target_hash.as_bytes());
        key.extend_from_slice(edit_hash.as_bytes());
        key
    }

    /// Creates a prefix key for edits of a target: forum_hash + target_hash (128 bytes).
    fn edit_index_prefix(forum_hash: &ContentHash, target_hash: &ContentHash) -> Vec<u8> {
        let mut key = Vec::with_capacity(128);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(target_hash.as_bytes());
        key
    }

    /// Creates an index key for encryption identity: forum_hash + identity_hash (128 bytes).
    fn encryption_identity_index_key(
        forum_hash: &ContentHash,
        identity_hash: &ContentHash,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(128);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(identity_hash.as_bytes());
        key
    }

    /// Creates an index key for sealed message: forum_hash + timestamp + msg_hash (136 bytes).
    ///
    /// Timestamp is included for sorted iteration during message scanning.
    fn sealed_message_index_key(
        forum_hash: &ContentHash,
        timestamp: u64,
        msg_hash: &ContentHash,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(136);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(&timestamp.to_be_bytes()); // Oldest first for scanning
        key.extend_from_slice(msg_hash.as_bytes());
        key
    }

    // ========================================================================
    // Core Node Storage
    // ========================================================================

    /// Stores a node in the database.
    ///
    /// The forum_hash is extracted from the node itself based on its type.
    pub fn store_node(&self, node: &DagNode) -> Result<()> {
        let forum_hash = self.get_node_forum_hash(node)?;
        self.store_node_for_forum(&forum_hash, node)
    }

    /// Stores a node for a specific forum.
    ///
    /// Also updates indexes for fast queries.
    pub fn store_node_for_forum(&self, forum_hash: &ContentHash, node: &DagNode) -> Result<()> {
        let key = Self::node_key(forum_hash, node.hash());
        let value = node.to_bytes()?;
        self.db.put_raw(CF_NODES, &key, &value)?;

        // Update indexes based on node type
        self.update_indexes_for_node(forum_hash, node)?;

        Ok(())
    }

    /// Updates indexes when a node is stored.
    fn update_indexes_for_node(&self, forum_hash: &ContentHash, node: &DagNode) -> Result<()> {
        match node {
            DagNode::BoardGenesis(board) => {
                // Index: forum + inverted_timestamp + board_hash (sorted by time desc)
                let idx_key = Self::board_index_key(forum_hash, board.created_at(), board.hash());
                // Value stores the board hash for easy retrieval
                self.db
                    .put_raw(CF_IDX_BOARDS, &idx_key, board.hash().as_bytes())?;

                // Update board count cache
                self.increment_board_count(forum_hash)?;

                // Initialize thread count for this board to 0
                let thread_count_key = Self::thread_count_key(forum_hash, board.hash());
                if self
                    .db
                    .get_raw(CF_IDX_THREAD_COUNTS, &thread_count_key)?
                    .is_none()
                {
                    self.db.put_raw(
                        CF_IDX_THREAD_COUNTS,
                        &thread_count_key,
                        &0u64.to_be_bytes(),
                    )?;
                }
            }
            DagNode::ThreadRoot(thread) => {
                // Index: forum + board + inverted_timestamp + thread_hash (sorted by time desc)
                let idx_key = Self::thread_index_key(
                    forum_hash,
                    thread.board_hash(),
                    thread.created_at(),
                    thread.hash(),
                );
                // Value stores the thread hash for easy retrieval
                self.db
                    .put_raw(CF_IDX_THREADS, &idx_key, thread.hash().as_bytes())?;

                // Update thread count cache for the board
                self.increment_thread_count(forum_hash, thread.board_hash())?;
            }
            DagNode::Post(post) => {
                // Index: forum + thread + inverted_timestamp + post_hash (sorted by time desc)
                let idx_key = Self::post_index_key(
                    forum_hash,
                    post.thread_hash(),
                    post.created_at(),
                    post.hash(),
                );
                // Value stores the post hash for easy retrieval
                self.db
                    .put_raw(CF_IDX_POSTS, &idx_key, post.hash().as_bytes())?;

                // Update post count cache
                self.increment_post_count(forum_hash, post.thread_hash())?;
            }
            DagNode::ModAction(action) => {
                // Index: forum -> mod action
                let idx_key = Self::mod_action_index_key(forum_hash, action.hash());
                self.db.put_raw(
                    CF_IDX_MOD_ACTIONS,
                    &idx_key,
                    &action.created_at().to_be_bytes(),
                )?;

                // Update mod-derived indexes based on action type
                self.update_mod_derived_indexes(forum_hash, action)?;
            }
            DagNode::Edit(edit) => {
                // Index: forum + target -> edit
                let idx_key = Self::edit_index_key(forum_hash, edit.target_hash(), edit.hash());
                self.db
                    .put_raw(CF_IDX_EDITS, &idx_key, &edit.created_at().to_be_bytes())?;
            }
            DagNode::EncryptionIdentity(identity) => {
                // Index: forum + identity_hash -> timestamp
                let idx_key = Self::encryption_identity_index_key(forum_hash, identity.hash());
                self.db.put_raw(
                    CF_IDX_ENCRYPTION_IDS,
                    &idx_key,
                    &identity.content.created_at.to_be_bytes(),
                )?;
            }
            DagNode::SealedPrivateMessage(msg) => {
                // Index: forum + timestamp + msg_hash -> () (for sorted scanning)
                let idx_key =
                    Self::sealed_message_index_key(forum_hash, msg.created_at(), msg.hash());
                self.db
                    .put_raw(CF_IDX_SEALED_MSGS, &idx_key, msg.hash().as_bytes())?;
            }
            DagNode::ForumGenesis(genesis) => {
                // Initialize forum mod index with owner
                let owner_fp = fingerprint_from_identity(genesis.creator_identity());
                let mod_key = Self::forum_mod_key(forum_hash, &owner_fp);
                self.db.put_raw(CF_IDX_FORUM_MODS, &mod_key, &[1])?; // 1 = owner
            }
        }
        Ok(())
    }

    /// Increments the cached post count for a thread.
    fn increment_post_count(
        &self,
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
    ) -> Result<()> {
        let key = Self::post_count_key(forum_hash, thread_hash);
        let current: u64 = self
            .db
            .get_raw(CF_IDX_POST_COUNTS, &key)?
            .map(|bytes| {
                if bytes.len() == 8 {
                    u64::from_be_bytes(bytes.try_into().unwrap())
                } else {
                    0
                }
            })
            .unwrap_or(0);
        self.db
            .put_raw(CF_IDX_POST_COUNTS, &key, &(current + 1).to_be_bytes())
    }

    /// Increments the cached board count for a forum.
    fn increment_board_count(&self, forum_hash: &ContentHash) -> Result<()> {
        let current: u64 = self
            .db
            .get_raw(CF_IDX_BOARD_COUNTS, forum_hash.as_bytes())?
            .map(|bytes| {
                if bytes.len() == 8 {
                    u64::from_be_bytes(bytes.try_into().unwrap())
                } else {
                    0
                }
            })
            .unwrap_or(0);
        self.db.put_raw(
            CF_IDX_BOARD_COUNTS,
            forum_hash.as_bytes(),
            &(current + 1).to_be_bytes(),
        )
    }

    /// Creates a key for thread count cache: forum_hash + board_hash (128 bytes).
    fn thread_count_key(forum_hash: &ContentHash, board_hash: &ContentHash) -> Vec<u8> {
        let mut key = Vec::with_capacity(128);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(board_hash.as_bytes());
        key
    }

    /// Increments the cached thread count for a board.
    fn increment_thread_count(
        &self,
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
    ) -> Result<()> {
        let key = Self::thread_count_key(forum_hash, board_hash);
        let current: u64 = self
            .db
            .get_raw(CF_IDX_THREAD_COUNTS, &key)?
            .map(|bytes| {
                if bytes.len() == 8 {
                    u64::from_be_bytes(bytes.try_into().unwrap())
                } else {
                    0
                }
            })
            .unwrap_or(0);
        self.db
            .put_raw(CF_IDX_THREAD_COUNTS, &key, &(current + 1).to_be_bytes())
    }

    /// Creates a key for forum mod index: forum_hash + fingerprint.
    fn forum_mod_key(forum_hash: &ContentHash, fingerprint: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(64 + fingerprint.len());
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(fingerprint.as_bytes());
        key
    }

    /// Creates a key for board mod index: forum_hash + board_hash + fingerprint.
    fn board_mod_key(
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
        fingerprint: &str,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(128 + fingerprint.len());
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(board_hash.as_bytes());
        key.extend_from_slice(fingerprint.as_bytes());
        key
    }

    /// Creates a key for hidden content index: forum_hash + content_hash (128 bytes).
    fn hidden_content_key(forum_hash: &ContentHash, content_hash: &ContentHash) -> Vec<u8> {
        let mut key = Vec::with_capacity(128);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(content_hash.as_bytes());
        key
    }

    /// Creates a key for moved thread index: forum_hash + thread_hash (128 bytes).
    fn moved_thread_key(forum_hash: &ContentHash, thread_hash: &ContentHash) -> Vec<u8> {
        let mut key = Vec::with_capacity(128);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(thread_hash.as_bytes());
        key
    }

    /// Creates a key for moved-in thread index: forum_hash + board_hash + inverted_ts + thread_hash (200 bytes).
    ///
    /// This enables efficient paginated queries for threads moved to a specific board,
    /// sorted by the thread's original creation time.
    fn moved_in_thread_key(
        forum_hash: &ContentHash,
        dest_board_hash: &ContentHash,
        thread_created_at: u64,
        thread_hash: &ContentHash,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(200);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(dest_board_hash.as_bytes());
        key.extend_from_slice(&Self::invert_timestamp(thread_created_at));
        key.extend_from_slice(thread_hash.as_bytes());
        key
    }

    /// Creates a prefix for moved-in threads in a specific board: forum_hash + board_hash (128 bytes).
    fn moved_in_thread_prefix(forum_hash: &ContentHash, board_hash: &ContentHash) -> Vec<u8> {
        let mut key = Vec::with_capacity(128);
        key.extend_from_slice(forum_hash.as_bytes());
        key.extend_from_slice(board_hash.as_bytes());
        key
    }

    /// Updates mod-derived indexes when a mod action is stored.
    ///
    /// This keeps the derived state indexes (hidden, moved, mods) in sync
    /// with mod actions, providing O(1) lookups instead of replaying all actions.
    fn update_mod_derived_indexes(
        &self,
        forum_hash: &ContentHash,
        action: &ModActionNode,
    ) -> Result<()> {
        let target_fp = fingerprint_from_identity(action.target_identity());

        match action.action() {
            // Moderator management
            ModAction::AddModerator => {
                let key = Self::forum_mod_key(forum_hash, &target_fp);
                self.db.put_raw(CF_IDX_FORUM_MODS, &key, &[2])?; // 2 = mod (not owner)
            }
            ModAction::RemoveModerator => {
                let key = Self::forum_mod_key(forum_hash, &target_fp);
                // Only remove if not owner (value != 1)
                if let Some(value) = self.db.get_raw(CF_IDX_FORUM_MODS, &key)? {
                    if value.first() != Some(&1) {
                        self.db.delete(CF_IDX_FORUM_MODS, &key)?;
                    }
                }
            }
            ModAction::AddBoardModerator => {
                if let Some(board_hash) = action.board_hash() {
                    let key = Self::board_mod_key(forum_hash, board_hash, &target_fp);
                    self.db.put_raw(CF_IDX_BOARD_MODS, &key, &[])?;
                }
            }
            ModAction::RemoveBoardModerator => {
                if let Some(board_hash) = action.board_hash() {
                    let key = Self::board_mod_key(forum_hash, board_hash, &target_fp);
                    self.db.delete(CF_IDX_BOARD_MODS, &key)?;
                }
            }

            // Hidden content management
            ModAction::HideThread => {
                if let Some(thread_hash) = action.target_node_hash() {
                    let key = Self::hidden_content_key(forum_hash, thread_hash);
                    self.db.put_raw(CF_IDX_HIDDEN_THREADS, &key, &[])?;
                }
            }
            ModAction::UnhideThread => {
                if let Some(thread_hash) = action.target_node_hash() {
                    let key = Self::hidden_content_key(forum_hash, thread_hash);
                    self.db.delete(CF_IDX_HIDDEN_THREADS, &key)?;
                }
            }
            ModAction::HidePost => {
                if let Some(post_hash) = action.target_node_hash() {
                    let key = Self::hidden_content_key(forum_hash, post_hash);
                    self.db.put_raw(CF_IDX_HIDDEN_POSTS, &key, &[])?;
                }
            }
            ModAction::UnhidePost => {
                if let Some(post_hash) = action.target_node_hash() {
                    let key = Self::hidden_content_key(forum_hash, post_hash);
                    self.db.delete(CF_IDX_HIDDEN_POSTS, &key)?;
                }
            }
            ModAction::HideBoard => {
                if let Some(board_hash) = action.board_hash() {
                    let key = Self::hidden_content_key(forum_hash, board_hash);
                    self.db.put_raw(CF_IDX_HIDDEN_BOARDS, &key, &[])?;
                }
            }
            ModAction::UnhideBoard => {
                if let Some(board_hash) = action.board_hash() {
                    let key = Self::hidden_content_key(forum_hash, board_hash);
                    self.db.delete(CF_IDX_HIDDEN_BOARDS, &key)?;
                }
            }

            // Thread movement
            ModAction::MoveThread => {
                if let (Some(thread_hash), Some(dest_board_hash)) =
                    (action.target_node_hash(), action.board_hash())
                {
                    // Check if thread was previously moved (to remove old moved-in entry)
                    let moved_key = Self::moved_thread_key(forum_hash, thread_hash);
                    let previous_board = self.db.get_raw(CF_IDX_MOVED_THREADS, &moved_key)?;

                    // Store the destination board hash as the value
                    self.db.put_raw(
                        CF_IDX_MOVED_THREADS,
                        &moved_key,
                        dest_board_hash.as_bytes(),
                    )?;

                    // Update thread counts and moved-in index
                    if let Some(thread) = self.get_thread(forum_hash, thread_hash)? {
                        let thread_created_at = thread.created_at();
                        let original_board = thread.board_hash();

                        // Remove old moved-in entry if thread was previously moved
                        if let Some(prev_board_bytes) = previous_board {
                            if prev_board_bytes.len() == 64 {
                                let prev_board =
                                    ContentHash::from_bytes(prev_board_bytes.try_into().unwrap());
                                let old_moved_in_key = Self::moved_in_thread_key(
                                    forum_hash,
                                    &prev_board,
                                    thread_created_at,
                                    thread_hash,
                                );
                                self.db.delete(CF_IDX_MOVED_IN_THREADS, &old_moved_in_key)?;
                                // Decrement count for previous destination board
                                self.decrement_thread_count(forum_hash, &prev_board)?;
                            }
                        } else {
                            // First move: decrement count for original board
                            self.decrement_thread_count(forum_hash, original_board)?;
                        }

                        // Add moved-in index entry for efficient pagination
                        let moved_in_key = Self::moved_in_thread_key(
                            forum_hash,
                            dest_board_hash,
                            thread_created_at,
                            thread_hash,
                        );
                        self.db
                            .put_raw(CF_IDX_MOVED_IN_THREADS, &moved_in_key, &[])?;

                        // Increment count for destination board
                        self.increment_thread_count(forum_hash, dest_board_hash)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Decrements the cached thread count for a board.
    fn decrement_thread_count(
        &self,
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
    ) -> Result<()> {
        let key = Self::thread_count_key(forum_hash, board_hash);
        let current: u64 = self
            .db
            .get_raw(CF_IDX_THREAD_COUNTS, &key)?
            .map(|bytes| {
                if bytes.len() == 8 {
                    u64::from_be_bytes(bytes.try_into().unwrap())
                } else {
                    0
                }
            })
            .unwrap_or(0);
        self.db.put_raw(
            CF_IDX_THREAD_COUNTS,
            &key,
            &current.saturating_sub(1).to_be_bytes(),
        )
    }

    /// Gets the forum hash from a node.
    fn get_node_forum_hash(&self, node: &DagNode) -> Result<ContentHash> {
        match node {
            DagNode::ForumGenesis(forum) => Ok(*forum.hash()),
            DagNode::BoardGenesis(board) => Ok(*board.forum_hash()),
            DagNode::ThreadRoot(thread) => {
                // Need to look up the board to get forum hash
                if let Some(board) = self.load_board_by_scan(thread.board_hash())? {
                    Ok(*board.forum_hash())
                } else {
                    Err(PqpgpError::storage(
                        "Cannot determine forum hash for thread - board not found",
                    ))
                }
            }
            DagNode::Post(post) => {
                // Need to look up the thread to get board, then forum
                if let Some(thread) = self.load_thread_by_scan(post.thread_hash())? {
                    if let Some(board) = self.load_board_by_scan(thread.board_hash())? {
                        Ok(*board.forum_hash())
                    } else {
                        Err(PqpgpError::storage(
                            "Cannot determine forum hash for post - board not found",
                        ))
                    }
                } else {
                    Err(PqpgpError::storage(
                        "Cannot determine forum hash for post - thread not found",
                    ))
                }
            }
            DagNode::ModAction(action) => Ok(*action.forum_hash()),
            DagNode::Edit(edit) => Ok(*edit.forum_hash()),
            DagNode::EncryptionIdentity(identity) => Ok(*identity.forum_hash()),
            DagNode::SealedPrivateMessage(message) => Ok(*message.forum_hash()),
        }
    }

    /// Scans all nodes to find a board by hash.
    fn load_board_by_scan(&self, board_hash: &ContentHash) -> Result<Option<BoardGenesis>> {
        let mut result = None;
        self.db.iterate_all(CF_NODES, |_, value| {
            if let Ok(node) = DagNode::from_bytes(value) {
                if let Some(board) = node.as_board_genesis() {
                    if board.hash() == board_hash {
                        result = Some(board.clone());
                        return false; // Stop iteration
                    }
                }
            }
            true // Continue
        })?;
        Ok(result)
    }

    /// Scans all nodes to find a thread by hash.
    fn load_thread_by_scan(&self, thread_hash: &ContentHash) -> Result<Option<ThreadRoot>> {
        let mut result = None;
        self.db.iterate_all(CF_NODES, |_, value| {
            if let Ok(node) = DagNode::from_bytes(value) {
                if let Some(thread) = node.as_thread_root() {
                    if thread.hash() == thread_hash {
                        result = Some(thread.clone());
                        return false; // Stop iteration
                    }
                }
            }
            true // Continue
        })?;
        Ok(result)
    }

    /// Loads a node by its hash within a specific forum.
    pub fn load_node(
        &self,
        forum_hash: &ContentHash,
        node_hash: &ContentHash,
    ) -> Result<Option<DagNode>> {
        let key = Self::node_key(forum_hash, node_hash);
        match self.db.get_raw(CF_NODES, &key)? {
            Some(value) => {
                let node = DagNode::from_bytes(&value)?;
                Ok(Some(node))
            }
            None => Ok(None),
        }
    }

    /// Checks if a node exists.
    pub fn node_exists(&self, forum_hash: &ContentHash, node_hash: &ContentHash) -> Result<bool> {
        let key = Self::node_key(forum_hash, node_hash);
        self.db.exists(CF_NODES, &key)
    }

    /// Loads all nodes for a forum.
    pub fn load_forum_nodes(&self, forum_hash: &ContentHash) -> Result<Vec<DagNode>> {
        let nodes = self
            .db
            .prefix_collect(CF_NODES, forum_hash.as_bytes(), |value| {
                DagNode::from_bytes(value).map_err(|e| e.to_string())
            })?;

        debug!(
            forum = %forum_hash.short(),
            nodes_loaded = nodes.len(),
            "load_forum_nodes: loaded all nodes for forum"
        );

        Ok(nodes)
    }

    /// Counts nodes for a forum without deserializing them.
    ///
    /// This is much faster than `load_forum_nodes().len()` since it only
    /// iterates keys without reading or deserializing values.
    pub fn count_forum_nodes(&self, forum_hash: &ContentHash) -> Result<usize> {
        let mut count = 0;
        self.db
            .prefix_iterate(CF_NODES, forum_hash.as_bytes(), |_, _| {
                count += 1;
                true
            })?;

        debug!(
            forum = %forum_hash.short(),
            node_count = count,
            "count_forum_nodes: counted nodes for forum"
        );

        Ok(count)
    }

    /// Loads all nodes from all forums.
    pub fn load_all_nodes(&self) -> Result<HashMap<ContentHash, DagNode>> {
        let mut nodes = HashMap::new();
        self.db.iterate_all(CF_NODES, |_, value| {
            if let Ok(node) = DagNode::from_bytes(value) {
                nodes.insert(*node.hash(), node);
            }
            true
        })?;

        debug!(
            total_nodes = nodes.len(),
            "load_all_nodes: loaded all nodes from all forums"
        );

        Ok(nodes)
    }

    // ========================================================================
    // Forum Metadata
    // ========================================================================

    /// Stores forum metadata.
    pub fn store_forum_metadata(
        &self,
        forum_hash: &ContentHash,
        metadata: &ForumMetadata,
    ) -> Result<()> {
        // Check if this is a new forum (for count update)
        let is_new = self.load_forum_metadata(forum_hash)?.is_none();

        self.db.put(CF_FORUMS, forum_hash.as_bytes(), metadata)?;
        self.add_forum_to_list(forum_hash)?;

        // Add to forum index for efficient sorted listing
        let idx_key = Self::forum_index_key(metadata.created_at, forum_hash);
        self.db
            .put_raw(CF_IDX_FORUMS, &idx_key, forum_hash.as_bytes())?;

        // Increment forum count if this is a new forum
        if is_new {
            self.increment_forum_count()?;
        }

        Ok(())
    }

    /// Increments the global forum count.
    fn increment_forum_count(&self) -> Result<()> {
        let current: u64 = self
            .db
            .get_raw(CF_META, META_FORUM_COUNT)?
            .map(|bytes| {
                if bytes.len() == 8 {
                    u64::from_be_bytes(bytes.try_into().unwrap())
                } else {
                    0
                }
            })
            .unwrap_or(0);
        self.db
            .put_raw(CF_META, META_FORUM_COUNT, &(current + 1).to_be_bytes())
    }

    /// Loads forum metadata.
    pub fn load_forum_metadata(&self, forum_hash: &ContentHash) -> Result<Option<ForumMetadata>> {
        self.db.get(CF_FORUMS, forum_hash.as_bytes())
    }

    /// Checks if a forum exists locally.
    pub fn forum_exists(&self, forum_hash: &ContentHash) -> Result<bool> {
        self.load_forum_metadata(forum_hash).map(|m| m.is_some())
    }

    // ========================================================================
    // DAG Heads Management
    // ========================================================================

    /// Gets the current DAG heads for a forum.
    pub fn get_heads(&self, forum_hash: &ContentHash) -> Result<HashSet<ContentHash>> {
        let heads: Option<Vec<ContentHash>> = self.db.get(CF_HEADS, forum_hash.as_bytes())?;
        Ok(heads.map(|v| v.into_iter().collect()).unwrap_or_default())
    }

    /// Sets the DAG heads for a forum.
    pub fn set_heads(&self, forum_hash: &ContentHash, heads: &HashSet<ContentHash>) -> Result<()> {
        let heads_vec: Vec<ContentHash> = heads.iter().copied().collect();
        self.db.put(CF_HEADS, forum_hash.as_bytes(), &heads_vec)
    }

    /// Updates heads after storing a new node.
    pub fn update_heads_for_node(&self, forum_hash: &ContentHash, node: &DagNode) -> Result<()> {
        let mut heads = self.get_heads(forum_hash)?;

        // Remove parents from heads (they now have children)
        for parent_hash in node.parent_hashes() {
            heads.remove(&parent_hash);
        }

        // Add this node as a head
        heads.insert(*node.hash());

        self.set_heads(forum_hash, &heads)
    }

    /// Recomputes the DAG heads for a forum from scratch.
    ///
    /// This scans all nodes and identifies true heads (nodes with no children).
    /// Use this to fix corrupted head state, such as when heads were not properly
    /// maintained during bulk imports.
    ///
    /// # Returns
    /// The number of heads after recomputation.
    pub fn recompute_heads(&self, forum_hash: &ContentHash) -> Result<usize> {
        let nodes = self.load_forum_nodes(forum_hash)?;
        if nodes.is_empty() {
            return Ok(0);
        }

        // Collect all node hashes
        let all_hashes: HashSet<ContentHash> = nodes.iter().map(|n| *n.hash()).collect();

        // Collect all parent hashes (nodes that are referenced by other nodes)
        let mut parent_hashes: HashSet<ContentHash> = HashSet::new();
        for node in &nodes {
            for parent in node.parent_hashes() {
                parent_hashes.insert(parent);
            }
        }

        // Heads are nodes that are NOT parents of any other node
        let heads: HashSet<ContentHash> = all_hashes.difference(&parent_hashes).copied().collect();

        let head_count = heads.len();
        self.set_heads(forum_hash, &heads)?;

        info!(
            "Recomputed heads for forum {}: {} heads (was scanning {} nodes)",
            forum_hash.short(),
            head_count,
            nodes.len()
        );

        Ok(head_count)
    }

    // ========================================================================
    // Forum List Management
    // ========================================================================

    /// Lists all synced forum hashes.
    pub fn list_forums(&self) -> Result<Vec<ContentHash>> {
        let forums = self
            .db
            .get::<Vec<ContentHash>>(CF_META, META_FORUM_LIST)?
            .unwrap_or_default();

        debug!(
            forum_count = forums.len(),
            "list_forums: retrieved forum list"
        );

        Ok(forums)
    }

    /// Lists synced forums with pagination.
    ///
    /// Returns forums sorted by creation time (newest first).
    /// Uses the forum index for efficient cursor-based pagination.
    pub fn list_forums_paginated(
        &self,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<PaginatedResult<ForumSummary>> {
        // Build the seek key for iteration
        // Index key format: inverted_timestamp (8 bytes) + forum_hash (64 bytes) = 72 bytes
        let seek_key = if let Some(cursor) = cursor {
            let mut key = Vec::with_capacity(72);
            key.extend_from_slice(&Self::invert_timestamp(cursor.timestamp));
            key.extend_from_slice(cursor.hash.as_bytes());
            // Increment to skip cursor item
            let mut key_bytes: [u8; 72] = key.try_into().unwrap();
            for i in (0..72).rev() {
                if key_bytes[i] < 255 {
                    key_bytes[i] += 1;
                    break;
                }
                key_bytes[i] = 0;
            }
            key_bytes.to_vec()
        } else {
            Vec::new() // Start from beginning
        };

        // Get total forum count from meta cache (O(1) instead of O(forums))
        let total_count = self
            .db
            .get_raw(CF_META, META_FORUM_COUNT)?
            .map(|bytes| {
                if bytes.len() == 8 {
                    u64::from_be_bytes(bytes.try_into().unwrap()) as usize
                } else {
                    0
                }
            })
            .unwrap_or(0);

        // Collect only limit + 1 items starting from the cursor
        let mut forum_hashes: Vec<ContentHash> = Vec::with_capacity(limit + 1);
        self.db
            .seek_iterate(CF_IDX_FORUMS, &seek_key, &[], |key, _| {
                // Key format: inverted_timestamp (8) + forum_hash (64) = 72 bytes
                if key.len() == 72 {
                    let forum_hash = ContentHash::from_bytes(key[8..72].try_into().unwrap());
                    forum_hashes.push(forum_hash);
                }
                forum_hashes.len() <= limit
            })?;

        let has_more = forum_hashes.len() > limit;
        let page_hashes: Vec<_> = forum_hashes.into_iter().take(limit).collect();

        // Load the actual forum metadata and build summaries
        let mut items = Vec::with_capacity(page_hashes.len());
        for forum_hash in &page_hashes {
            if let Some(metadata) = self.load_forum_metadata(forum_hash)? {
                // Get effective name/description after edits (fallback to metadata if no edits)
                let (effective_name, effective_description) = self
                    .get_effective_forum_info(forum_hash)?
                    .unwrap_or_else(|| (metadata.name.clone(), metadata.description.clone()));

                // Get board count from cache (O(1))
                let board_count = self.get_board_count(forum_hash)?;

                items.push(ForumSummary {
                    hash: *forum_hash,
                    metadata,
                    effective_name,
                    effective_description,
                    board_count,
                });
            }
        }

        // Create cursor for next page from the last loaded forum
        let next_cursor = if has_more && !items.is_empty() {
            let last = items.last().unwrap();
            Some(Cursor::new(last.metadata.created_at, last.hash))
        } else {
            None
        };

        debug!(
            returned = items.len(),
            total = total_count,
            has_more = has_more,
            "list_forums_paginated: returned forum page"
        );

        Ok(PaginatedResult {
            items,
            next_cursor,
            total_count: Some(total_count),
        })
    }

    /// Adds a forum to the list of synced forums.
    fn add_forum_to_list(&self, forum_hash: &ContentHash) -> Result<()> {
        let mut forums = self.list_forums()?;
        if !forums.contains(forum_hash) {
            forums.push(*forum_hash);
            self.db.put(CF_META, META_FORUM_LIST, &forums)?;
        }
        Ok(())
    }

    /// Removes a forum and all its data.
    pub fn remove_forum(&self, forum_hash: &ContentHash) -> Result<()> {
        // Delete all nodes for this forum
        self.db.prefix_delete(CF_NODES, forum_hash.as_bytes())?;

        // Delete all indexes for this forum
        self.db
            .prefix_delete(CF_IDX_BOARDS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_THREADS, forum_hash.as_bytes())?;
        self.db.prefix_delete(CF_IDX_POSTS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_POST_COUNTS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_MOD_ACTIONS, forum_hash.as_bytes())?;
        self.db.prefix_delete(CF_IDX_EDITS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_ENCRYPTION_IDS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_SEALED_MSGS, forum_hash.as_bytes())?;
        // Delete new indexes
        self.db
            .prefix_delete(CF_IDX_THREAD_COUNTS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_MOVED_THREADS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_HIDDEN_THREADS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_HIDDEN_POSTS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_HIDDEN_BOARDS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_FORUM_MODS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_BOARD_MODS, forum_hash.as_bytes())?;
        // Delete board count for this forum
        self.db.delete(CF_IDX_BOARD_COUNTS, forum_hash.as_bytes())?;

        // Delete forum metadata
        self.db.delete(CF_FORUMS, forum_hash.as_bytes())?;

        // Delete heads
        self.db.delete(CF_HEADS, forum_hash.as_bytes())?;

        // Remove from forum list
        let forums = self.list_forums()?;
        let filtered: Vec<_> = forums
            .iter()
            .filter(|h| *h != forum_hash)
            .copied()
            .collect();
        self.db.put(CF_META, META_FORUM_LIST, &filtered)?;

        // Decrement forum count
        self.decrement_forum_count()?;

        info!("Removed forum {} from local storage", forum_hash.short());
        Ok(())
    }

    /// Decrements the global forum count.
    fn decrement_forum_count(&self) -> Result<()> {
        let current: u64 = self
            .db
            .get_raw(CF_META, META_FORUM_COUNT)?
            .map(|bytes| {
                if bytes.len() == 8 {
                    u64::from_be_bytes(bytes.try_into().unwrap())
                } else {
                    0
                }
            })
            .unwrap_or(0);
        self.db.put_raw(
            CF_META,
            META_FORUM_COUNT,
            &current.saturating_sub(1).to_be_bytes(),
        )
    }

    /// Rebuilds all indexes for a forum from existing nodes.
    ///
    /// This is useful for migrating existing databases or recovering from corruption.
    pub fn rebuild_indexes(&self, forum_hash: &ContentHash) -> Result<()> {
        info!("Rebuilding indexes for forum {}...", forum_hash.short());

        // Clear existing indexes for this forum
        self.db
            .prefix_delete(CF_IDX_BOARDS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_THREADS, forum_hash.as_bytes())?;
        self.db.prefix_delete(CF_IDX_POSTS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_POST_COUNTS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_MOD_ACTIONS, forum_hash.as_bytes())?;
        self.db.prefix_delete(CF_IDX_EDITS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_ENCRYPTION_IDS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_SEALED_MSGS, forum_hash.as_bytes())?;
        // Clear new indexes
        self.db
            .prefix_delete(CF_IDX_THREAD_COUNTS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_MOVED_THREADS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_MOVED_IN_THREADS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_HIDDEN_THREADS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_HIDDEN_POSTS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_HIDDEN_BOARDS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_FORUM_MODS, forum_hash.as_bytes())?;
        self.db
            .prefix_delete(CF_IDX_BOARD_MODS, forum_hash.as_bytes())?;
        // Clear board count for this forum
        self.db.delete(CF_IDX_BOARD_COUNTS, forum_hash.as_bytes())?;

        // Load all nodes and rebuild indexes
        let nodes = self.load_forum_nodes(forum_hash)?;
        let mut board_count = 0;
        let mut thread_count = 0;
        let mut post_count = 0;
        let mut mod_action_count = 0;
        let mut edit_count = 0;
        let mut encryption_id_count = 0;
        let mut sealed_msg_count = 0;

        // First pass: collect boards for thread count initialization
        let boards: Vec<_> = nodes.iter().filter_map(|n| n.as_board_genesis()).collect();

        // Initialize thread counts for all boards to 0
        for board in &boards {
            let thread_count_key = Self::thread_count_key(forum_hash, board.hash());
            self.db
                .put_raw(CF_IDX_THREAD_COUNTS, &thread_count_key, &0u64.to_be_bytes())?;
        }

        // Second pass: build basic indexes
        for node in &nodes {
            match node {
                DagNode::ForumGenesis(genesis) => {
                    // Initialize forum mod index with owner
                    let owner_fp = fingerprint_from_identity(genesis.creator_identity());
                    let mod_key = Self::forum_mod_key(forum_hash, &owner_fp);
                    self.db.put_raw(CF_IDX_FORUM_MODS, &mod_key, &[1])?; // 1 = owner
                }
                DagNode::BoardGenesis(board) => {
                    let idx_key =
                        Self::board_index_key(forum_hash, board.created_at(), board.hash());
                    self.db
                        .put_raw(CF_IDX_BOARDS, &idx_key, board.hash().as_bytes())?;
                    board_count += 1;
                }
                DagNode::ThreadRoot(thread) => {
                    let idx_key = Self::thread_index_key(
                        forum_hash,
                        thread.board_hash(),
                        thread.created_at(),
                        thread.hash(),
                    );
                    self.db
                        .put_raw(CF_IDX_THREADS, &idx_key, thread.hash().as_bytes())?;
                    thread_count += 1;
                }
                DagNode::Post(post) => {
                    let idx_key = Self::post_index_key(
                        forum_hash,
                        post.thread_hash(),
                        post.created_at(),
                        post.hash(),
                    );
                    self.db
                        .put_raw(CF_IDX_POSTS, &idx_key, post.hash().as_bytes())?;
                    post_count += 1;
                }
                DagNode::ModAction(action) => {
                    let idx_key = Self::mod_action_index_key(forum_hash, action.hash());
                    self.db.put_raw(
                        CF_IDX_MOD_ACTIONS,
                        &idx_key,
                        &action.created_at().to_be_bytes(),
                    )?;
                    mod_action_count += 1;
                }
                DagNode::Edit(edit) => {
                    let idx_key = Self::edit_index_key(forum_hash, edit.target_hash(), edit.hash());
                    self.db
                        .put_raw(CF_IDX_EDITS, &idx_key, &edit.created_at().to_be_bytes())?;
                    edit_count += 1;
                }
                DagNode::EncryptionIdentity(identity) => {
                    let idx_key = Self::encryption_identity_index_key(forum_hash, identity.hash());
                    self.db.put_raw(
                        CF_IDX_ENCRYPTION_IDS,
                        &idx_key,
                        &identity.content.created_at.to_be_bytes(),
                    )?;
                    encryption_id_count += 1;
                }
                DagNode::SealedPrivateMessage(msg) => {
                    let idx_key =
                        Self::sealed_message_index_key(forum_hash, msg.created_at(), msg.hash());
                    self.db
                        .put_raw(CF_IDX_SEALED_MSGS, &idx_key, msg.hash().as_bytes())?;
                    sealed_msg_count += 1;
                }
            }
        }

        // Rebuild post count caches
        let mut post_counts: HashMap<ContentHash, u64> = HashMap::new();
        for node in &nodes {
            if let DagNode::Post(post) = node {
                *post_counts.entry(*post.thread_hash()).or_insert(0) += 1;
            }
        }

        for (thread_hash, count) in post_counts {
            let key = Self::post_count_key(forum_hash, &thread_hash);
            self.db
                .put_raw(CF_IDX_POST_COUNTS, &key, &count.to_be_bytes())?;
        }

        // Rebuild thread count caches per board
        let mut thread_counts: HashMap<ContentHash, u64> = HashMap::new();
        for node in &nodes {
            if let DagNode::ThreadRoot(thread) = node {
                *thread_counts.entry(*thread.board_hash()).or_insert(0) += 1;
            }
        }
        for (board_hash, count) in &thread_counts {
            let key = Self::thread_count_key(forum_hash, board_hash);
            self.db
                .put_raw(CF_IDX_THREAD_COUNTS, &key, &count.to_be_bytes())?;
        }

        // Store board count for the forum
        self.db.put_raw(
            CF_IDX_BOARD_COUNTS,
            forum_hash.as_bytes(),
            &(board_count as u64).to_be_bytes(),
        )?;

        // Rebuild mod-derived indexes by replaying mod actions in order
        // Collect and sort mod actions by timestamp
        let mut mod_actions: Vec<_> = nodes.iter().filter_map(|n| n.as_mod_action()).collect();
        mod_actions.sort_by_key(|a| a.created_at());

        for action in mod_actions {
            // Apply mod-derived index updates (hidden, moved, mods)
            // We call this separately to avoid re-reading nodes
            self.rebuild_mod_derived_index(forum_hash, action, &nodes)?;
        }

        info!(
            "Rebuilt indexes: {} boards, {} threads, {} posts, {} mod actions, {} edits, {} encryption IDs, {} sealed msgs",
            board_count, thread_count, post_count, mod_action_count, edit_count, encryption_id_count, sealed_msg_count
        );
        Ok(())
    }

    /// Rebuilds mod-derived indexes for a single action during rebuild.
    ///
    /// This is similar to `update_mod_derived_indexes` but doesn't update thread counts
    /// since we're doing a full rebuild with counts computed separately.
    fn rebuild_mod_derived_index(
        &self,
        forum_hash: &ContentHash,
        action: &ModActionNode,
        _nodes: &[DagNode],
    ) -> Result<()> {
        let target_fp = fingerprint_from_identity(action.target_identity());

        match action.action() {
            ModAction::AddModerator => {
                let key = Self::forum_mod_key(forum_hash, &target_fp);
                // Only add if not already owner
                if let Some(value) = self.db.get_raw(CF_IDX_FORUM_MODS, &key)? {
                    if value.first() == Some(&1) {
                        return Ok(()); // Already owner, don't downgrade
                    }
                }
                self.db.put_raw(CF_IDX_FORUM_MODS, &key, &[2])?;
            }
            ModAction::RemoveModerator => {
                let key = Self::forum_mod_key(forum_hash, &target_fp);
                if let Some(value) = self.db.get_raw(CF_IDX_FORUM_MODS, &key)? {
                    if value.first() != Some(&1) {
                        self.db.delete(CF_IDX_FORUM_MODS, &key)?;
                    }
                }
            }
            ModAction::AddBoardModerator => {
                if let Some(board_hash) = action.board_hash() {
                    let key = Self::board_mod_key(forum_hash, board_hash, &target_fp);
                    self.db.put_raw(CF_IDX_BOARD_MODS, &key, &[])?;
                }
            }
            ModAction::RemoveBoardModerator => {
                if let Some(board_hash) = action.board_hash() {
                    let key = Self::board_mod_key(forum_hash, board_hash, &target_fp);
                    self.db.delete(CF_IDX_BOARD_MODS, &key)?;
                }
            }
            ModAction::HideThread => {
                if let Some(thread_hash) = action.target_node_hash() {
                    let key = Self::hidden_content_key(forum_hash, thread_hash);
                    self.db.put_raw(CF_IDX_HIDDEN_THREADS, &key, &[])?;
                }
            }
            ModAction::UnhideThread => {
                if let Some(thread_hash) = action.target_node_hash() {
                    let key = Self::hidden_content_key(forum_hash, thread_hash);
                    self.db.delete(CF_IDX_HIDDEN_THREADS, &key)?;
                }
            }
            ModAction::HidePost => {
                if let Some(post_hash) = action.target_node_hash() {
                    let key = Self::hidden_content_key(forum_hash, post_hash);
                    self.db.put_raw(CF_IDX_HIDDEN_POSTS, &key, &[])?;
                }
            }
            ModAction::UnhidePost => {
                if let Some(post_hash) = action.target_node_hash() {
                    let key = Self::hidden_content_key(forum_hash, post_hash);
                    self.db.delete(CF_IDX_HIDDEN_POSTS, &key)?;
                }
            }
            ModAction::HideBoard => {
                if let Some(board_hash) = action.board_hash() {
                    let key = Self::hidden_content_key(forum_hash, board_hash);
                    self.db.put_raw(CF_IDX_HIDDEN_BOARDS, &key, &[])?;
                }
            }
            ModAction::UnhideBoard => {
                if let Some(board_hash) = action.board_hash() {
                    let key = Self::hidden_content_key(forum_hash, board_hash);
                    self.db.delete(CF_IDX_HIDDEN_BOARDS, &key)?;
                }
            }
            ModAction::MoveThread => {
                if let (Some(thread_hash), Some(dest_board_hash)) =
                    (action.target_node_hash(), action.board_hash())
                {
                    let key = Self::moved_thread_key(forum_hash, thread_hash);
                    self.db
                        .put_raw(CF_IDX_MOVED_THREADS, &key, dest_board_hash.as_bytes())?;

                    // Also populate moved-in index for pagination
                    if let Some(thread) = self.get_thread(forum_hash, thread_hash)? {
                        let moved_in_key = Self::moved_in_thread_key(
                            forum_hash,
                            dest_board_hash,
                            thread.created_at(),
                            thread_hash,
                        );
                        self.db
                            .put_raw(CF_IDX_MOVED_IN_THREADS, &moved_in_key, &[])?;
                    }
                    // Note: thread counts are rebuilt separately from full scan,
                    // so we don't update them here during rebuild
                }
            }
        }

        Ok(())
    }

    /// Rebuilds indexes for all forums.
    pub fn rebuild_all_indexes(&self) -> Result<()> {
        let forums = self.list_forums()?;
        info!("Rebuilding indexes for {} forums...", forums.len());

        // Rebuild the forum index (global, not per-forum)
        self.rebuild_forum_index()?;

        // Rebuild per-forum indexes
        for forum_hash in forums {
            self.rebuild_indexes(&forum_hash)?;
        }

        info!("All indexes rebuilt");
        Ok(())
    }

    /// Rebuilds the global forum index for sorted listing.
    fn rebuild_forum_index(&self) -> Result<()> {
        info!("Rebuilding forum index...");

        // Clear existing forum index
        // Since we can't do prefix_delete with empty prefix, iterate and delete each key
        let mut keys_to_delete: Vec<Vec<u8>> = Vec::new();
        self.db.prefix_iterate(CF_IDX_FORUMS, &[], |key, _| {
            keys_to_delete.push(key.to_vec());
            true
        })?;
        for key in keys_to_delete {
            self.db.delete(CF_IDX_FORUMS, &key)?;
        }

        // Rebuild index from forum metadata
        let forums = self.list_forums()?;
        let mut count = 0;
        for forum_hash in &forums {
            if let Some(metadata) = self.load_forum_metadata(forum_hash)? {
                let idx_key = Self::forum_index_key(metadata.created_at, forum_hash);
                self.db
                    .put_raw(CF_IDX_FORUMS, &idx_key, forum_hash.as_bytes())?;
                count += 1;
            }
        }

        // Store total forum count in meta
        self.db
            .put_raw(CF_META, META_FORUM_COUNT, &(count as u64).to_be_bytes())?;

        info!("Rebuilt forum index: {} forums", count);
        Ok(())
    }

    // ========================================================================
    // Query Methods for UI Display (Indexed - Fast)
    // ========================================================================

    /// Gets all boards in a forum, sorted by creation time (newest first).
    ///
    /// Uses the board index for O(boards) instead of O(all_nodes).
    pub fn get_boards(&self, forum_hash: &ContentHash) -> Result<Vec<BoardGenesis>> {
        // Collect board hashes from the index (already sorted by inverted timestamp)
        let mut board_hashes: Vec<ContentHash> = Vec::new();
        self.db
            .prefix_iterate(CF_IDX_BOARDS, forum_hash.as_bytes(), |key, _value| {
                // Key is forum_hash (64 bytes) + inverted_timestamp (8 bytes) + board_hash (64 bytes) = 136 bytes
                if key.len() == 136 {
                    let board_hash = ContentHash::from_bytes(key[72..136].try_into().unwrap());
                    board_hashes.push(board_hash);
                }
                true // continue iteration
            })?;

        // Load the actual board nodes (already in timestamp-descending order from index)
        let mut boards = Vec::with_capacity(board_hashes.len());
        for board_hash in board_hashes {
            if let Some(board) = self.get_board(forum_hash, &board_hash)? {
                boards.push(board);
            }
        }

        debug!(
            forum = %forum_hash.short(),
            boards_returned = boards.len(),
            "get_boards: retrieved boards for forum"
        );

        Ok(boards)
    }

    /// Gets all threads in a board, sorted by creation time (newest first).
    ///
    /// Uses the thread index for O(threads_in_board) instead of O(all_nodes).
    /// This accounts for moved threads.
    pub fn get_threads(
        &self,
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
    ) -> Result<Vec<ThreadRoot>> {
        // Get the map of moved threads (thread_hash -> current_board_hash)
        let moved_threads = self.get_moved_threads(forum_hash)?;

        // Collect thread hashes from the index (already sorted by inverted timestamp)
        let prefix = Self::thread_index_prefix(forum_hash, board_hash);
        let mut thread_hashes: Vec<ContentHash> = Vec::new();
        self.db
            .prefix_iterate(CF_IDX_THREADS, &prefix, |key, _value| {
                // Key is forum_hash (64) + board_hash (64) + inverted_timestamp (8) + thread_hash (64) = 200 bytes
                if key.len() == 200 {
                    let thread_hash = ContentHash::from_bytes(key[136..200].try_into().unwrap());
                    thread_hashes.push(thread_hash);
                }
                true // continue iteration
            })?;

        // Load threads, filtering out those that have been moved away
        let mut threads = Vec::with_capacity(thread_hashes.len());
        for thread_hash in thread_hashes {
            // Skip threads that have been moved to another board
            if let Some(moved_to) = moved_threads.get(&thread_hash) {
                if moved_to != board_hash {
                    continue;
                }
            }

            if let Some(thread) = self.get_thread(forum_hash, &thread_hash)? {
                threads.push(thread);
            }
        }

        // Also include threads that were moved TO this board from elsewhere
        for (thread_hash, current_board) in &moved_threads {
            if current_board == board_hash {
                // Check if we already have this thread (was originally in this board)
                if !threads.iter().any(|t| t.hash() == thread_hash) {
                    if let Some(thread) = self.get_thread(forum_hash, thread_hash)? {
                        threads.push(thread);
                    }
                }
            }
        }

        // Re-sort after adding moved threads (index order may be disrupted by moved threads)
        threads.sort_by_key(|t| std::cmp::Reverse(t.created_at()));

        debug!(
            forum = %forum_hash.short(),
            board = %board_hash.short(),
            threads_returned = threads.len(),
            "get_threads: retrieved threads for board"
        );

        Ok(threads)
    }

    /// Gets all posts in a thread, sorted by creation time (oldest first for chronological reading).
    ///
    /// Uses the post index for O(posts_in_thread) instead of O(all_nodes).
    pub fn get_posts(
        &self,
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
    ) -> Result<Vec<Post>> {
        // Collect post hashes from the index (already sorted by timestamp ascending - oldest first)
        let prefix = Self::post_index_prefix(forum_hash, thread_hash);
        let mut post_hashes: Vec<ContentHash> = Vec::new();
        self.db
            .prefix_iterate(CF_IDX_POSTS, &prefix, |key, _value| {
                // Key is forum_hash (64) + thread_hash (64) + timestamp (8) + post_hash (64) = 200 bytes
                if key.len() == 200 {
                    let post_hash = ContentHash::from_bytes(key[136..200].try_into().unwrap());
                    post_hashes.push(post_hash);
                }
                true // continue iteration
            })?;

        // Load the actual post nodes (already in chronological order from index)
        let mut posts = Vec::with_capacity(post_hashes.len());
        for post_hash in post_hashes {
            if let Some(post) = self.load_post(forum_hash, &post_hash)? {
                posts.push(post);
            }
        }

        debug!(
            forum = %forum_hash.short(),
            thread = %thread_hash.short(),
            posts_returned = posts.len(),
            "get_posts: retrieved posts for thread"
        );

        Ok(posts)
    }

    /// Gets the post count for a thread.
    ///
    /// Uses cached count for O(1) instead of O(all_nodes).
    pub fn get_post_count(
        &self,
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
    ) -> Result<usize> {
        let key = Self::post_count_key(forum_hash, thread_hash);
        let count = self
            .db
            .get_raw(CF_IDX_POST_COUNTS, &key)?
            .map(|bytes| {
                if bytes.len() == 8 {
                    u64::from_be_bytes(bytes.try_into().unwrap()) as usize
                } else {
                    0
                }
            })
            .unwrap_or(0);
        Ok(count)
    }

    /// Gets the number of boards in a forum.
    ///
    /// Uses cached count for O(1) instead of O(all_boards).
    pub fn get_board_count(&self, forum_hash: &ContentHash) -> Result<usize> {
        let count = self
            .db
            .get_raw(CF_IDX_BOARD_COUNTS, forum_hash.as_bytes())?
            .map(|bytes| {
                if bytes.len() == 8 {
                    u64::from_be_bytes(bytes.try_into().unwrap()) as usize
                } else {
                    0
                }
            })
            .unwrap_or(0);
        Ok(count)
    }

    // ========================================================================
    // Paginated Query Methods
    // ========================================================================

    /// Gets boards in a forum with cursor-based pagination.
    ///
    /// Boards are sorted by creation time (newest first).
    /// Pass `None` for cursor to get the first page.
    ///
    /// Returns `BoardSummary` which includes effective name/description after edits,
    /// batch-loading all edits in a single pass to avoid N+1 queries.
    ///
    /// This method is efficient: it uses sorted indexes and stops iteration
    /// once enough items have been collected.
    pub fn get_boards_paginated(
        &self,
        forum_hash: &ContentHash,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<PaginatedResult<BoardSummary>> {
        let forum_prefix = forum_hash.as_bytes();

        // Build the seek key for iteration
        // Index key format: forum_hash (64) + inverted_timestamp (8) + board_hash (64) = 136 bytes
        let seek_key = if let Some(cursor) = cursor {
            // Start just after the cursor position
            let mut key = Vec::with_capacity(136);
            key.extend_from_slice(forum_prefix);
            key.extend_from_slice(&Self::invert_timestamp(cursor.timestamp));
            key.extend_from_slice(cursor.hash.as_bytes());
            // Increment to skip the cursor item itself
            let mut key_bytes: [u8; 136] = key.try_into().unwrap();
            for i in (0..136).rev() {
                if key_bytes[i] < 255 {
                    key_bytes[i] += 1;
                    break;
                }
                key_bytes[i] = 0;
            }
            key_bytes.to_vec()
        } else {
            forum_prefix.to_vec()
        };

        // Get total board count from cache (O(1) instead of O(boards))
        let total_count = self
            .db
            .get_raw(CF_IDX_BOARD_COUNTS, forum_prefix)?
            .map(|bytes| {
                if bytes.len() == 8 {
                    u64::from_be_bytes(bytes.try_into().unwrap()) as usize
                } else {
                    0
                }
            })
            .unwrap_or(0);

        // Collect only limit + 1 items starting from the cursor
        let mut board_hashes: Vec<ContentHash> = Vec::with_capacity(limit + 1);
        self.db
            .seek_iterate(CF_IDX_BOARDS, &seek_key, forum_prefix, |key, _| {
                // Key format: forum_hash (64) + inverted_timestamp (8) + board_hash (64)
                if key.len() == 136 {
                    let board_hash = ContentHash::from_bytes(key[72..136].try_into().unwrap());
                    board_hashes.push(board_hash);
                }
                // Stop after we have enough
                board_hashes.len() <= limit
            })?;

        let has_more = board_hashes.len() > limit;
        let page_hashes: Vec<_> = board_hashes.into_iter().take(limit).collect();

        // Load the actual board nodes
        let mut boards = Vec::with_capacity(page_hashes.len());
        for board_hash in &page_hashes {
            if let Some(board) = self.get_board(forum_hash, board_hash)? {
                boards.push(board);
            }
        }

        // Issue #6 fix: Load edits only for the specific boards on this page
        // Instead of scanning all edits in the forum, query each board's edits specifically
        let mut edits_by_target: HashMap<ContentHash, Vec<(u64, EditNode)>> = HashMap::new();

        for board in &boards {
            let edit_prefix = Self::edit_index_prefix(forum_hash, board.hash());
            self.db
                .prefix_iterate(CF_IDX_EDITS, &edit_prefix, |key, value| {
                    if key.len() == 192 {
                        let edit_hash = ContentHash::from_bytes(key[128..192].try_into().unwrap());
                        let timestamp = if value.len() == 8 {
                            u64::from_be_bytes(value.try_into().unwrap())
                        } else {
                            0
                        };
                        // Load the edit node
                        if let Ok(Some(node)) = self.load_node(forum_hash, &edit_hash) {
                            if let Some(edit) = node.as_edit() {
                                edits_by_target
                                    .entry(*board.hash())
                                    .or_default()
                                    .push((timestamp, edit.clone()));
                            }
                        }
                    }
                    true
                })?;
        }

        // Sort edits by timestamp for each target (oldest first for proper replay)
        for edits in edits_by_target.values_mut() {
            edits.sort_by_key(|(ts, _)| *ts);
        }

        // Issue #7 fix: Get thread counts from cache instead of counting via prefix scan
        let mut thread_counts: HashMap<ContentHash, usize> = HashMap::new();
        for board in &boards {
            let count_key = Self::thread_count_key(forum_hash, board.hash());
            let count = self
                .db
                .get_raw(CF_IDX_THREAD_COUNTS, &count_key)?
                .map(|bytes| {
                    if bytes.len() == 8 {
                        u64::from_be_bytes(bytes.try_into().unwrap()) as usize
                    } else {
                        0
                    }
                })
                .unwrap_or(0);
            thread_counts.insert(*board.hash(), count);
        }

        // Build BoardSummary with effective name/description and thread count
        let summaries: Vec<BoardSummary> = boards
            .into_iter()
            .map(|board| {
                let mut name = board.name().to_string();
                let mut description = board.description().to_string();

                // Apply edits in order if any exist for this board
                if let Some(edits) = edits_by_target.get(board.hash()) {
                    for (_, edit) in edits {
                        if let Some(new_name) = edit.new_name() {
                            name = new_name.to_string();
                        }
                        if let Some(new_desc) = edit.new_description() {
                            description = new_desc.to_string();
                        }
                    }
                }

                let thread_count = thread_counts.get(board.hash()).copied().unwrap_or(0);

                BoardSummary {
                    board,
                    effective_name: name,
                    effective_description: description,
                    thread_count,
                }
            })
            .collect();

        // Create cursor for next page from the last loaded board
        let next_cursor = if has_more && !summaries.is_empty() {
            let last_board = &summaries.last().unwrap().board;
            Some(Cursor::new(last_board.created_at(), *last_board.hash()))
        } else {
            None
        };

        debug!(
            forum = %forum_hash.short(),
            returned = summaries.len(),
            total = total_count,
            has_more = has_more,
            "get_boards_paginated: returned boards page"
        );

        Ok(PaginatedResult {
            items: summaries,
            next_cursor,
            total_count: Some(total_count),
        })
    }

    /// Gets threads in a board with cursor-based pagination.
    ///
    /// Threads are sorted by creation time (newest first).
    /// Pass `None` for cursor to get the first page.
    ///
    /// Returns `ThreadSummary` which includes post counts, avoiding N+1 queries.
    ///
    /// This method efficiently merges two sorted indexes:
    /// 1. The primary thread index (threads originally created in this board)
    /// 2. The moved-in thread index (threads moved to this board from elsewhere)
    ///
    /// Both indexes use the same key format with inverted timestamps, enabling
    /// a merge-iteration that correctly handles moved threads across all pages.
    pub fn get_threads_paginated(
        &self,
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<PaginatedResult<ThreadSummary>> {
        // Get total thread count from cache (O(1) instead of O(threads))
        // The thread count cache is updated when threads are moved, so it reflects
        // the current count for this board (including moves in, excluding moves out)
        let count_key = Self::thread_count_key(forum_hash, board_hash);
        let total_count = self
            .db
            .get_raw(CF_IDX_THREAD_COUNTS, &count_key)?
            .map(|bytes| {
                if bytes.len() == 8 {
                    u64::from_be_bytes(bytes.try_into().unwrap()) as usize
                } else {
                    0
                }
            })
            .unwrap_or(0);

        // Build seek key based on cursor
        // Index key format: forum_hash (64) + board_hash (64) + inverted_timestamp (8) + thread_hash (64) = 200 bytes
        let seek_key = if let Some(cursor) = cursor {
            let mut key = Vec::with_capacity(200);
            key.extend_from_slice(forum_hash.as_bytes());
            key.extend_from_slice(board_hash.as_bytes());
            key.extend_from_slice(&Self::invert_timestamp(cursor.timestamp));
            key.extend_from_slice(cursor.hash.as_bytes());
            // Increment to skip cursor item
            let mut key_bytes: [u8; 200] = key.try_into().unwrap();
            for i in (0..200).rev() {
                if key_bytes[i] < 255 {
                    key_bytes[i] += 1;
                    break;
                }
                key_bytes[i] = 0;
            }
            key_bytes.to_vec()
        } else {
            Self::thread_index_prefix(forum_hash, board_hash)
        };

        // Collect thread hashes from both indexes and merge them
        // We need to collect more than `limit` from each source to handle filtering
        let collect_limit = limit * 2 + 1;

        // Collect from primary thread index (threads originally in this board)
        let prefix = Self::thread_index_prefix(forum_hash, board_hash);
        let mut primary_threads: Vec<(u64, ContentHash)> = Vec::with_capacity(collect_limit);
        self.db
            .seek_iterate(CF_IDX_THREADS, &seek_key, &prefix, |key, _| {
                if key.len() == 200 {
                    let inverted_ts: [u8; 8] = key[128..136].try_into().unwrap();
                    let timestamp = u64::MAX - u64::from_be_bytes(inverted_ts);
                    let thread_hash = ContentHash::from_bytes(key[136..200].try_into().unwrap());
                    // Check if this thread has been moved away from this board
                    if !self.is_thread_moved_from(forum_hash, &thread_hash, board_hash) {
                        primary_threads.push((timestamp, thread_hash));
                    }
                }
                primary_threads.len() < collect_limit
            })?;

        // Collect from moved-in thread index (threads moved to this board)
        let moved_in_prefix = Self::moved_in_thread_prefix(forum_hash, board_hash);
        let mut moved_in_threads: Vec<(u64, ContentHash)> = Vec::with_capacity(collect_limit);
        self.db.seek_iterate(
            CF_IDX_MOVED_IN_THREADS,
            &seek_key,
            &moved_in_prefix,
            |key, _| {
                if key.len() == 200 {
                    let inverted_ts: [u8; 8] = key[128..136].try_into().unwrap();
                    let timestamp = u64::MAX - u64::from_be_bytes(inverted_ts);
                    let thread_hash = ContentHash::from_bytes(key[136..200].try_into().unwrap());
                    moved_in_threads.push((timestamp, thread_hash));
                }
                moved_in_threads.len() < collect_limit
            },
        )?;

        // Merge the two sorted streams (both sorted by timestamp descending)
        let mut merged: Vec<(u64, ContentHash)> =
            Vec::with_capacity(primary_threads.len() + moved_in_threads.len());
        let mut primary_iter = primary_threads.into_iter().peekable();
        let mut moved_iter = moved_in_threads.into_iter().peekable();

        while merged.len() <= limit {
            match (primary_iter.peek(), moved_iter.peek()) {
                (Some((ts1, _)), Some((ts2, _))) => {
                    // Take the newer one (higher timestamp)
                    if ts1 >= ts2 {
                        merged.push(primary_iter.next().unwrap());
                    } else {
                        merged.push(moved_iter.next().unwrap());
                    }
                }
                (Some(_), None) => {
                    merged.push(primary_iter.next().unwrap());
                }
                (None, Some(_)) => {
                    merged.push(moved_iter.next().unwrap());
                }
                (None, None) => break,
            }
        }

        let has_more = merged.len() > limit;
        let page_items: Vec<_> = merged.into_iter().take(limit).collect();

        // Load the actual thread nodes with post counts in a single pass
        let mut summaries = Vec::with_capacity(page_items.len());
        for (_, thread_hash) in &page_items {
            if let Some(thread) = self.get_thread(forum_hash, thread_hash)? {
                let post_count = self.get_post_count(forum_hash, thread_hash).unwrap_or(0);
                summaries.push(ThreadSummary { thread, post_count });
            }
        }

        let next_cursor = if has_more && !summaries.is_empty() {
            let last = summaries.last().unwrap();
            Some(Cursor::new(last.thread.created_at(), *last.thread.hash()))
        } else {
            None
        };

        debug!(
            forum = %forum_hash.short(),
            board = %board_hash.short(),
            returned = summaries.len(),
            total = total_count,
            has_more = has_more,
            "get_threads_paginated: returned threads page"
        );

        Ok(PaginatedResult {
            items: summaries,
            next_cursor,
            total_count: Some(total_count),
        })
    }

    /// Gets posts in a thread with cursor-based pagination.
    ///
    /// Posts are sorted by creation time (oldest first for chronological reading).
    /// Pass `None` for cursor to get the first page.
    ///
    /// Returns `PostSummary` which includes resolved quote previews, batch-loading
    /// only the quoted posts to avoid loading all posts in the thread.
    ///
    /// This method is efficient: it uses sorted indexes and stops iteration
    /// once enough items have been collected.
    pub fn get_posts_paginated(
        &self,
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<PaginatedResult<PostSummary>> {
        let prefix = Self::post_index_prefix(forum_hash, thread_hash);

        // Build the seek key for iteration
        // Index key format: forum_hash (64) + thread_hash (64) + timestamp (8) + post_hash (64) = 200 bytes
        let seek_key = if let Some(cursor) = cursor {
            let mut key = Vec::with_capacity(200);
            key.extend_from_slice(forum_hash.as_bytes());
            key.extend_from_slice(thread_hash.as_bytes());
            key.extend_from_slice(&cursor.timestamp.to_be_bytes()); // Non-inverted for ascending
            key.extend_from_slice(cursor.hash.as_bytes());
            // Increment to skip cursor item
            let mut key_bytes: [u8; 200] = key.try_into().unwrap();
            for i in (0..200).rev() {
                if key_bytes[i] < 255 {
                    key_bytes[i] += 1;
                    break;
                }
                key_bytes[i] = 0;
            }
            key_bytes.to_vec()
        } else {
            prefix.clone()
        };

        // Get total post count from cache (O(1) instead of O(posts))
        let total_count = self.get_post_count(forum_hash, thread_hash).unwrap_or(0);

        // Collect only limit + 1 items starting from the cursor
        let mut post_hashes: Vec<ContentHash> = Vec::with_capacity(limit + 1);
        self.db
            .seek_iterate(CF_IDX_POSTS, &seek_key, &prefix, |key, _| {
                // Key format: forum_hash (64) + thread_hash (64) + timestamp (8) + post_hash (64)
                if key.len() == 200 {
                    let post_hash = ContentHash::from_bytes(key[136..200].try_into().unwrap());
                    post_hashes.push(post_hash);
                }
                post_hashes.len() <= limit
            })?;

        let has_more = post_hashes.len() > limit;
        let page_hashes: Vec<_> = post_hashes.into_iter().take(limit).collect();

        // Load the actual post nodes
        let mut posts = Vec::with_capacity(page_hashes.len());
        for post_hash in &page_hashes {
            if let Some(post) = self.load_post(forum_hash, post_hash)? {
                posts.push(post);
            }
        }

        // Collect unique quote hashes from posts on this page
        let quote_hashes: HashSet<ContentHash> = posts
            .iter()
            .filter_map(|p| p.quote_hash().copied())
            .collect();

        // Batch-load only the quoted posts (instead of all posts in thread)
        let mut quoted_posts: HashMap<ContentHash, Post> = HashMap::new();
        for quote_hash in &quote_hashes {
            if let Ok(Some(quoted_post)) = self.load_post(forum_hash, quote_hash) {
                quoted_posts.insert(*quote_hash, quoted_post);
            }
        }

        // Build PostSummary with resolved quote previews
        let summaries: Vec<PostSummary> = posts
            .into_iter()
            .map(|post| {
                let quote_preview = post.quote_hash().and_then(|qh| {
                    quoted_posts.get(qh).map(|quoted| {
                        let preview: String = quoted.body().chars().take(200).collect();
                        if quoted.body().len() > 200 {
                            preview + "..."
                        } else {
                            preview
                        }
                    })
                });

                PostSummary {
                    post,
                    quote_preview,
                }
            })
            .collect();

        let next_cursor = if has_more && !summaries.is_empty() {
            let last_post = &summaries.last().unwrap().post;
            Some(Cursor::new(last_post.created_at(), *last_post.hash()))
        } else {
            None
        };

        debug!(
            forum = %forum_hash.short(),
            thread = %thread_hash.short(),
            returned = summaries.len(),
            total = total_count,
            has_more = has_more,
            "get_posts_paginated: returned posts page"
        );

        Ok(PaginatedResult {
            items: summaries,
            next_cursor,
            total_count: Some(total_count),
        })
    }

    /// Gets a specific board by hash.
    pub fn get_board(
        &self,
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
    ) -> Result<Option<BoardGenesis>> {
        let node = self.load_node(forum_hash, board_hash)?;
        Ok(node.and_then(|n| n.as_board_genesis().cloned()))
    }

    /// Gets a specific thread by hash.
    pub fn get_thread(
        &self,
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
    ) -> Result<Option<ThreadRoot>> {
        let node = self.load_node(forum_hash, thread_hash)?;
        Ok(node.and_then(|n| n.as_thread_root().cloned()))
    }

    /// Loads a forum by hash.
    pub fn load_forum(&self, forum_hash: &ContentHash) -> Result<Option<ForumGenesis>> {
        let node = self.load_node(forum_hash, forum_hash)?;
        Ok(node.and_then(|n| n.as_forum_genesis().cloned()))
    }

    /// Loads a board by hash.
    pub fn load_board(
        &self,
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
    ) -> Result<Option<BoardGenesis>> {
        self.get_board(forum_hash, board_hash)
    }

    /// Loads a thread by hash.
    pub fn load_thread(
        &self,
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
    ) -> Result<Option<ThreadRoot>> {
        self.get_thread(forum_hash, thread_hash)
    }

    /// Loads a post by hash.
    pub fn load_post(
        &self,
        forum_hash: &ContentHash,
        post_hash: &ContentHash,
    ) -> Result<Option<Post>> {
        let node = self.load_node(forum_hash, post_hash)?;
        Ok(node.and_then(|n| n.as_post().cloned()))
    }

    /// Gets all mod actions for a forum, sorted by creation time.
    ///
    /// Uses the mod action index for O(mod_actions) instead of O(all_nodes).
    pub fn get_mod_actions(&self, forum_hash: &ContentHash) -> Result<Vec<ModActionNode>> {
        // Collect mod action hashes and timestamps from the index
        let mut action_entries: Vec<(ContentHash, u64)> = Vec::new();
        self.db
            .prefix_iterate(CF_IDX_MOD_ACTIONS, forum_hash.as_bytes(), |key, value| {
                // Key is forum_hash (64 bytes) + action_hash (64 bytes) = 128 bytes
                if key.len() == 128 {
                    let action_hash = ContentHash::from_bytes(key[64..128].try_into().unwrap());
                    let timestamp = if value.len() == 8 {
                        u64::from_be_bytes(value.try_into().unwrap())
                    } else {
                        0
                    };
                    action_entries.push((action_hash, timestamp));
                }
                true // continue iteration
            })?;

        // Sort by timestamp ascending (oldest first for replay order)
        action_entries.sort_by_key(|(_, ts)| *ts);

        // Load the actual mod action nodes
        let mut actions = Vec::with_capacity(action_entries.len());
        for (action_hash, _) in action_entries {
            if let Some(node) = self.load_node(forum_hash, &action_hash)? {
                if let Some(action) = node.as_mod_action() {
                    actions.push(action.clone());
                }
            }
        }

        Ok(actions)
    }

    /// Gets the effective board name and description after applying edits.
    ///
    /// Returns (name, description) with the most recent edit values applied.
    /// Uses the edit index for O(edits_for_board) instead of O(all_nodes).
    pub fn get_effective_board_info(
        &self,
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
    ) -> Result<Option<(String, String)>> {
        // Get the original board
        let board = match self.get_board(forum_hash, board_hash)? {
            Some(b) => b,
            None => return Ok(None),
        };

        self.apply_board_edits(forum_hash, &board)
    }

    /// Applies edits to a board that's already loaded.
    ///
    /// This avoids reloading the board from disk when it's already available.
    pub fn apply_board_edits(
        &self,
        forum_hash: &ContentHash,
        board: &BoardGenesis,
    ) -> Result<Option<(String, String)>> {
        let mut name = board.name().to_string();
        let mut description = board.description().to_string();

        // Get edits for this board from the index
        let edits = self.get_edits_for_target(forum_hash, board.hash())?;

        // Apply edits in order (already sorted by timestamp, most recent wins)
        for edit in edits {
            if let Some(new_name) = edit.new_name() {
                name = new_name.to_string();
            }
            if let Some(new_desc) = edit.new_description() {
                description = new_desc.to_string();
            }
        }

        Ok(Some((name, description)))
    }

    /// Gets all edit nodes for a specific target, sorted by creation time.
    ///
    /// Uses the edit index for O(edits_for_target) instead of O(all_nodes).
    fn get_edits_for_target(
        &self,
        forum_hash: &ContentHash,
        target_hash: &ContentHash,
    ) -> Result<Vec<EditNode>> {
        let prefix = Self::edit_index_prefix(forum_hash, target_hash);
        let mut edit_entries: Vec<(ContentHash, u64)> = Vec::new();

        self.db
            .prefix_iterate(CF_IDX_EDITS, &prefix, |key, value| {
                // Key is forum_hash (64) + target_hash (64) + edit_hash (64) = 192 bytes
                if key.len() == 192 {
                    let edit_hash = ContentHash::from_bytes(key[128..192].try_into().unwrap());
                    let timestamp = if value.len() == 8 {
                        u64::from_be_bytes(value.try_into().unwrap())
                    } else {
                        0
                    };
                    edit_entries.push((edit_hash, timestamp));
                }
                true // continue iteration
            })?;

        // Sort by timestamp ascending (oldest first for replay order)
        edit_entries.sort_by_key(|(_, ts)| *ts);

        // Load the actual edit nodes
        let mut edits = Vec::with_capacity(edit_entries.len());
        for (edit_hash, _) in edit_entries {
            if let Some(node) = self.load_node(forum_hash, &edit_hash)? {
                if let Some(edit) = node.as_edit() {
                    edits.push(edit.clone());
                }
            }
        }

        Ok(edits)
    }

    /// Gets the effective forum name and description after applying edits.
    ///
    /// Returns (name, description) with the most recent edit values applied.
    /// Uses the edit index for O(edits_for_forum) instead of O(all_nodes).
    pub fn get_effective_forum_info(
        &self,
        forum_hash: &ContentHash,
    ) -> Result<Option<(String, String)>> {
        // Get the forum metadata (original values)
        let metadata = match self.load_forum_metadata(forum_hash)? {
            Some(m) => m,
            None => return Ok(None),
        };

        let mut name = metadata.name;
        let mut description = metadata.description;

        // Get edits for this forum from the index (forum edits target the forum itself)
        let edits = self.get_edits_for_target(forum_hash, forum_hash)?;

        // Apply edits in order (already sorted by timestamp, most recent wins)
        for edit in edits {
            if let Some(new_name) = edit.new_name() {
                name = new_name.to_string();
            }
            if let Some(new_desc) = edit.new_description() {
                description = new_desc.to_string();
            }
        }

        Ok(Some((name, description)))
    }

    /// Gets the current forum-level moderators from the index.
    ///
    /// Returns (moderator_fingerprints, owner_fingerprint) where owner is the forum creator.
    /// Uses the forum mods index for O(mods) instead of O(all_mod_actions).
    pub fn get_forum_moderators(
        &self,
        forum_hash: &ContentHash,
    ) -> Result<(HashSet<String>, Option<String>)> {
        let mut moderators: HashSet<String> = HashSet::new();
        let mut owner_fingerprint: Option<String> = None;

        // Scan the forum mods index
        // Key: forum_hash (64) + fingerprint (variable)
        // Value: role byte (1=owner, 2=mod)
        self.db
            .prefix_iterate(CF_IDX_FORUM_MODS, forum_hash.as_bytes(), |key, value| {
                if key.len() > 64 {
                    let fingerprint = String::from_utf8_lossy(&key[64..]).to_string();
                    moderators.insert(fingerprint.clone());

                    // Check if this is the owner
                    if value.first() == Some(&1) {
                        owner_fingerprint = Some(fingerprint);
                    }
                }
                true
            })?;

        Ok((moderators, owner_fingerprint))
    }

    /// Gets the current board-level moderators from the index.
    ///
    /// Uses the board mods index for O(board_mods) instead of O(all_mod_actions).
    pub fn get_board_moderators(
        &self,
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
    ) -> Result<HashSet<String>> {
        let mut moderators: HashSet<String> = HashSet::new();

        // Build prefix: forum_hash + board_hash
        let mut prefix = Vec::with_capacity(128);
        prefix.extend_from_slice(forum_hash.as_bytes());
        prefix.extend_from_slice(board_hash.as_bytes());

        // Scan the board mods index
        // Key: forum_hash (64) + board_hash (64) + fingerprint (variable)
        self.db
            .prefix_iterate(CF_IDX_BOARD_MODS, &prefix, |key, _| {
                if key.len() > 128 {
                    let fingerprint = String::from_utf8_lossy(&key[128..]).to_string();
                    moderators.insert(fingerprint);
                }
                true
            })?;

        Ok(moderators)
    }

    /// Gets set of hidden thread hashes from the index.
    ///
    /// Uses the hidden threads index for O(hidden) instead of O(all_mod_actions).
    pub fn get_hidden_threads(&self, forum_hash: &ContentHash) -> Result<HashSet<ContentHash>> {
        let mut hidden: HashSet<ContentHash> = HashSet::new();

        // Scan the hidden threads index
        // Key: forum_hash (64) + thread_hash (64) = 128 bytes
        self.db
            .prefix_iterate(CF_IDX_HIDDEN_THREADS, forum_hash.as_bytes(), |key, _| {
                if key.len() == 128 {
                    let thread_hash = ContentHash::from_bytes(key[64..128].try_into().unwrap());
                    hidden.insert(thread_hash);
                }
                true
            })?;

        Ok(hidden)
    }

    /// Gets set of hidden post hashes from the index.
    ///
    /// Uses the hidden posts index for O(hidden) instead of O(all_mod_actions).
    pub fn get_hidden_posts(&self, forum_hash: &ContentHash) -> Result<HashSet<ContentHash>> {
        let mut hidden: HashSet<ContentHash> = HashSet::new();

        // Scan the hidden posts index
        // Key: forum_hash (64) + post_hash (64) = 128 bytes
        self.db
            .prefix_iterate(CF_IDX_HIDDEN_POSTS, forum_hash.as_bytes(), |key, _| {
                if key.len() == 128 {
                    let post_hash = ContentHash::from_bytes(key[64..128].try_into().unwrap());
                    hidden.insert(post_hash);
                }
                true
            })?;

        Ok(hidden)
    }

    /// Gets set of hidden board hashes from the index.
    ///
    /// Uses the hidden boards index for O(hidden) instead of O(all_mod_actions).
    pub fn get_hidden_boards(&self, forum_hash: &ContentHash) -> Result<HashSet<ContentHash>> {
        let mut hidden: HashSet<ContentHash> = HashSet::new();

        // Scan the hidden boards index
        // Key: forum_hash (64) + board_hash (64) = 128 bytes
        self.db
            .prefix_iterate(CF_IDX_HIDDEN_BOARDS, forum_hash.as_bytes(), |key, _| {
                if key.len() == 128 {
                    let board_hash = ContentHash::from_bytes(key[64..128].try_into().unwrap());
                    hidden.insert(board_hash);
                }
                true
            })?;

        Ok(hidden)
    }

    /// Checks if a specific thread is hidden using O(1) point lookup.
    ///
    /// Use this instead of `get_hidden_threads()` when checking a single thread
    /// to avoid loading the entire hidden set.
    pub fn is_thread_hidden(
        &self,
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
    ) -> Result<bool> {
        let key = Self::hidden_content_key(forum_hash, thread_hash);
        self.db.exists(CF_IDX_HIDDEN_THREADS, &key)
    }

    /// Checks if a specific post is hidden using O(1) point lookup.
    ///
    /// Use this instead of `get_hidden_posts()` when checking a single post
    /// to avoid loading the entire hidden set.
    pub fn is_post_hidden(
        &self,
        forum_hash: &ContentHash,
        post_hash: &ContentHash,
    ) -> Result<bool> {
        let key = Self::hidden_content_key(forum_hash, post_hash);
        self.db.exists(CF_IDX_HIDDEN_POSTS, &key)
    }

    /// Checks if a specific board is hidden using O(1) point lookup.
    ///
    /// Use this instead of `get_hidden_boards()` when checking a single board
    /// to avoid loading the entire hidden set.
    pub fn is_board_hidden(
        &self,
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
    ) -> Result<bool> {
        let key = Self::hidden_content_key(forum_hash, board_hash);
        self.db.exists(CF_IDX_HIDDEN_BOARDS, &key)
    }

    /// Checks if a thread has been moved away from its original board.
    ///
    /// Returns true if the thread exists in the moved index AND its current
    /// location is different from the specified board.
    fn is_thread_moved_from(
        &self,
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
        original_board: &ContentHash,
    ) -> bool {
        let key = Self::moved_thread_key(forum_hash, thread_hash);
        match self.db.get_raw(CF_IDX_MOVED_THREADS, &key) {
            Ok(Some(bytes)) if bytes.len() == 64 => {
                let current_board = ContentHash::from_bytes(bytes.try_into().unwrap());
                &current_board != original_board
            }
            _ => false,
        }
    }

    /// Gets the current board location for a thread if it has been moved.
    ///
    /// Returns `None` if the thread hasn't been moved (is still in its original board).
    pub fn get_thread_current_board(
        &self,
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
    ) -> Result<Option<ContentHash>> {
        let key = Self::moved_thread_key(forum_hash, thread_hash);
        match self.db.get_raw(CF_IDX_MOVED_THREADS, &key)? {
            Some(bytes) if bytes.len() == 64 => {
                Ok(Some(ContentHash::from_bytes(bytes.try_into().unwrap())))
            }
            _ => Ok(None),
        }
    }

    /// Gets map of moved threads (thread_hash -> current_board_hash) from the index.
    ///
    /// Uses the moved threads index for O(moved) instead of O(all_mod_actions).
    pub fn get_moved_threads(
        &self,
        forum_hash: &ContentHash,
    ) -> Result<HashMap<ContentHash, ContentHash>> {
        let mut moved: HashMap<ContentHash, ContentHash> = HashMap::new();

        // Scan the moved threads index
        // Key: forum_hash (64) + thread_hash (64) = 128 bytes
        // Value: board_hash (64 bytes)
        self.db
            .prefix_iterate(CF_IDX_MOVED_THREADS, forum_hash.as_bytes(), |key, value| {
                if key.len() == 128 && value.len() == 64 {
                    let thread_hash = ContentHash::from_bytes(key[64..128].try_into().unwrap());
                    let board_hash = ContentHash::from_bytes(value.try_into().unwrap());
                    moved.insert(thread_hash, board_hash);
                }
                true
            })?;

        Ok(moved)
    }

    // ========================================================================
    // Private Message Storage Methods
    // ========================================================================

    /// Lists all encryption identities in a forum.
    pub fn list_encryption_identities(&self, forum_hash: &ContentHash) -> Result<Vec<ContentHash>> {
        // Use the index for O(identities) instead of O(all_nodes)
        let mut hashes = Vec::new();
        self.db
            .prefix_iterate(CF_IDX_ENCRYPTION_IDS, forum_hash.as_bytes(), |key, _| {
                // Key: forum_hash (64) + identity_hash (64) = 128 bytes
                if key.len() == 128 {
                    let identity_hash = ContentHash::from_bytes(key[64..128].try_into().unwrap());
                    hashes.push(identity_hash);
                }
                true
            })?;
        Ok(hashes)
    }

    /// Lists all sealed messages in a forum.
    ///
    /// Returns messages sorted by timestamp (oldest first) for efficient scanning.
    pub fn list_sealed_messages(&self, forum_hash: &ContentHash) -> Result<Vec<ContentHash>> {
        // Use the index for O(messages) instead of O(all_nodes)
        let mut hashes = Vec::new();
        self.db
            .prefix_iterate(CF_IDX_SEALED_MSGS, forum_hash.as_bytes(), |key, _| {
                // Key: forum_hash (64) + timestamp (8) + msg_hash (64) = 136 bytes
                if key.len() == 136 {
                    let msg_hash = ContentHash::from_bytes(key[72..136].try_into().unwrap());
                    hashes.push(msg_hash);
                }
                true
            })?;
        Ok(hashes)
    }

    /// Loads a sealed private message by hash.
    pub fn load_sealed_message(
        &self,
        forum_hash: &ContentHash,
        message_hash: &ContentHash,
    ) -> Result<Option<SealedPrivateMessage>> {
        let node = self.load_node(forum_hash, message_hash)?;
        Ok(node.and_then(|n| n.as_sealed_private_message().cloned()))
    }

    /// Stores an encryption identity private key.
    ///
    /// This should be stored securely - the private key enables decrypting
    /// all incoming private messages.
    pub fn store_encryption_private(
        &self,
        identity_hash: &ContentHash,
        private: &EncryptionIdentityPrivate,
    ) -> Result<()> {
        let mut key = PRIVATE_ENCRYPTION_KEY_PREFIX.to_vec();
        key.extend_from_slice(identity_hash.as_bytes());
        self.db.put(CF_PRIVATE, &key, private)
    }

    /// Loads an encryption identity private key.
    pub fn load_encryption_private(
        &self,
        identity_hash: &ContentHash,
    ) -> Result<Option<EncryptionIdentityPrivate>> {
        let mut key = PRIVATE_ENCRYPTION_KEY_PREFIX.to_vec();
        key.extend_from_slice(identity_hash.as_bytes());
        self.db.get(CF_PRIVATE, &key)
    }

    /// Deletes an encryption identity private key.
    pub fn delete_encryption_private(&self, identity_hash: &ContentHash) -> Result<()> {
        let mut key = PRIVATE_ENCRYPTION_KEY_PREFIX.to_vec();
        key.extend_from_slice(identity_hash.as_bytes());
        self.db.delete(CF_PRIVATE, &key)
    }

    /// Lists all encryption identity private keys stored locally.
    pub fn list_encryption_privates(&self) -> Result<Vec<ContentHash>> {
        let prefix = PRIVATE_ENCRYPTION_KEY_PREFIX;
        let mut hashes = Vec::new();
        self.db.prefix_iterate(CF_PRIVATE, prefix, |key, _| {
            let hash_bytes = &key[prefix.len()..];
            if hash_bytes.len() == 64 {
                let mut bytes = [0u8; 64];
                bytes.copy_from_slice(hash_bytes);
                hashes.push(ContentHash::from_bytes(bytes));
            }
            true
        })?;
        Ok(hashes)
    }

    /// Stores a conversation session.
    pub fn store_conversation(&self, session: &ConversationSession) -> Result<()> {
        let mut key = PRIVATE_CONVERSATION_PREFIX.to_vec();
        key.extend_from_slice(session.conversation_id().as_bytes());
        self.db.put(CF_PRIVATE, &key, session)
    }

    /// Loads a conversation session.
    pub fn load_conversation(
        &self,
        conversation_id: &[u8; CONVERSATION_ID_SIZE],
    ) -> Result<Option<ConversationSession>> {
        let mut key = PRIVATE_CONVERSATION_PREFIX.to_vec();
        key.extend_from_slice(conversation_id);
        self.db.get(CF_PRIVATE, &key)
    }

    /// Deletes a conversation session.
    pub fn delete_conversation(&self, conversation_id: &[u8; CONVERSATION_ID_SIZE]) -> Result<()> {
        let mut key = PRIVATE_CONVERSATION_PREFIX.to_vec();
        key.extend_from_slice(conversation_id);
        self.db.delete(CF_PRIVATE, &key)
    }

    /// Stores the complete conversation manager state.
    pub fn store_conversation_manager(&self, manager: &ConversationManager) -> Result<()> {
        self.db
            .put(CF_PRIVATE, PRIVATE_CONVERSATION_MANAGER, manager)
    }

    /// Loads the complete conversation manager state.
    pub fn load_conversation_manager(&self) -> Result<ConversationManager> {
        match self
            .db
            .get::<ConversationManager>(CF_PRIVATE, PRIVATE_CONVERSATION_MANAGER)?
        {
            Some(mut manager) => {
                // Rebuild indexes after loading
                manager.rebuild_indexes();
                Ok(manager)
            }
            None => Ok(ConversationManager::new()),
        }
    }

    /// Lists all conversation IDs stored locally.
    pub fn list_conversations(&self) -> Result<Vec<[u8; CONVERSATION_ID_SIZE]>> {
        let prefix = PRIVATE_CONVERSATION_PREFIX;
        let mut ids = Vec::new();

        self.db.prefix_iterate(CF_PRIVATE, prefix, |key, _| {
            // Extract conversation ID from key (after prefix)
            let id_bytes = &key[prefix.len()..];
            if id_bytes.len() == CONVERSATION_ID_SIZE {
                let mut id = [0u8; CONVERSATION_ID_SIZE];
                id.copy_from_slice(id_bytes);
                ids.push(id);
            }
            true // Continue iteration
        })?;

        Ok(ids)
    }

    /// Records that a one-time prekey has been consumed.
    ///
    /// This is used to prevent replay attacks. A consumed OTP should never
    /// be accepted again.
    pub fn record_consumed_otp(&self, identity_hash: &ContentHash, otp_id: u32) -> Result<()> {
        let mut key = PRIVATE_CONSUMED_OTP_PREFIX.to_vec();
        key.extend_from_slice(identity_hash.as_bytes());
        key.push(b':');
        key.extend_from_slice(&otp_id.to_le_bytes());

        // Value is just a marker (empty bytes)
        self.db.put_raw(CF_PRIVATE, &key, &[])
    }

    /// Checks if a one-time prekey has been consumed.
    pub fn is_otp_consumed(&self, identity_hash: &ContentHash, otp_id: u32) -> Result<bool> {
        let mut key = PRIVATE_CONSUMED_OTP_PREFIX.to_vec();
        key.extend_from_slice(identity_hash.as_bytes());
        key.push(b':');
        key.extend_from_slice(&otp_id.to_le_bytes());
        self.db.exists(CF_PRIVATE, &key)
    }

    /// Lists all consumed OTPs for an encryption identity.
    pub fn list_consumed_otps(&self, identity_hash: &ContentHash) -> Result<Vec<u32>> {
        let mut prefix = PRIVATE_CONSUMED_OTP_PREFIX.to_vec();
        prefix.extend_from_slice(identity_hash.as_bytes());
        prefix.push(b':');

        let mut otps = Vec::new();
        self.db.prefix_iterate(CF_PRIVATE, &prefix, |key, _| {
            // Extract OTP ID from key (after prefix)
            let id_bytes = &key[prefix.len()..];
            if id_bytes.len() == 4 {
                let id = u32::from_le_bytes([id_bytes[0], id_bytes[1], id_bytes[2], id_bytes[3]]);
                otps.push(id);
            }
            true // Continue iteration
        })?;

        Ok(otps)
    }

    /// Finds the next available OTP ID for generating new prekeys.
    pub fn next_available_otp_id(&self, identity_hash: &ContentHash) -> Result<u32> {
        let consumed = self.list_consumed_otps(identity_hash)?;
        let max_consumed = consumed.into_iter().max().unwrap_or(1);
        Ok(max_consumed + 1)
    }

    // =========================================================================
    // Sync Cursor Storage
    // =========================================================================

    /// Stores a sync cursor for a forum.
    ///
    /// The cursor tracks the position for incremental sync from a relay.
    /// On subsequent syncs, we can resume from this position instead of
    /// fetching all nodes from the beginning.
    pub fn set_sync_cursor(
        &self,
        forum_hash: &ContentHash,
        timestamp: u64,
        hash: Option<&ContentHash>,
    ) -> Result<()> {
        let mut key = PRIVATE_SYNC_CURSOR_PREFIX.to_vec();
        key.extend_from_slice(forum_hash.as_bytes());

        // Value: timestamp (8 bytes) + optional hash (64 bytes)
        let mut value = timestamp.to_be_bytes().to_vec();
        if let Some(h) = hash {
            value.extend_from_slice(h.as_bytes());
        }

        self.db.put_raw(CF_PRIVATE, &key, &value)
    }

    /// Gets the sync cursor for a forum.
    ///
    /// Returns `(timestamp, Option<hash>)` if a cursor exists, or `(0, None)` otherwise.
    pub fn get_sync_cursor(&self, forum_hash: &ContentHash) -> Result<(u64, Option<ContentHash>)> {
        let mut key = PRIVATE_SYNC_CURSOR_PREFIX.to_vec();
        key.extend_from_slice(forum_hash.as_bytes());

        match self.db.get_raw(CF_PRIVATE, &key)? {
            Some(value) => {
                if value.len() < 8 {
                    return Ok((0, None));
                }
                let timestamp = u64::from_be_bytes(value[..8].try_into().unwrap());
                let hash = if value.len() >= 8 + 64 {
                    let bytes: [u8; 64] = value[8..8 + 64].try_into().unwrap();
                    Some(ContentHash::from_bytes(bytes))
                } else {
                    None
                };
                Ok((timestamp, hash))
            }
            None => Ok((0, None)),
        }
    }

    /// Deletes the sync cursor for a forum.
    ///
    /// This can be used to force a full re-sync.
    pub fn delete_sync_cursor(&self, forum_hash: &ContentHash) -> Result<()> {
        let mut key = PRIVATE_SYNC_CURSOR_PREFIX.to_vec();
        key.extend_from_slice(forum_hash.as_bytes());
        self.db.delete(CF_PRIVATE, &key)
    }

    /// Clears all data from the database.
    ///
    /// Use with caution!
    pub fn clear(&self) -> Result<()> {
        // Clear each column family by collecting keys first, then deleting
        for cf_name in [CF_NODES, CF_FORUMS, CF_HEADS, CF_META, CF_PRIVATE] {
            let mut keys_to_delete = Vec::new();
            self.db.iterate_all(cf_name, |key, _| {
                keys_to_delete.push(key.to_vec());
                true
            })?;

            for key in keys_to_delete {
                self.db.delete(cf_name, &key)?;
            }
        }

        info!("Cleared all forum storage data");
        Ok(())
    }
}

/// Helper to compute fingerprint from identity bytes.
///
/// Computes a fingerprint from identity bytes using the same algorithm as PublicKey::fingerprint().
/// This ensures fingerprints match between keys loaded from the keyring and identities
/// stored in forum nodes.
fn fingerprint_from_identity(identity: &[u8]) -> String {
    use crate::crypto::PublicKey;
    let fingerprint = PublicKey::fingerprint_from_mldsa87_bytes(identity);
    hex::encode(&fingerprint[..8]) // First 16 hex chars
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use tempfile::TempDir;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
    }

    fn create_test_storage() -> (ForumStorage, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let storage = ForumStorage::new(temp_dir.path().join("forum_data"))
            .expect("Failed to create storage");
        (storage, temp_dir)
    }

    fn create_test_forum(keypair: &KeyPair) -> ForumGenesis {
        ForumGenesis::create(
            "Test Forum".to_string(),
            "A test forum".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create forum")
    }

    #[test]
    fn test_storage_creation() {
        let (_storage, _temp_dir) = create_test_storage();
        // If we get here, storage was created successfully
    }

    #[test]
    fn test_store_and_load_forum() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let forum_hash = *forum.hash();

        // Store metadata first
        let metadata = ForumMetadata {
            name: forum.name().to_string(),
            description: forum.description().to_string(),
            created_at: forum.created_at(),
            owner_identity: forum.creator_identity().to_vec(),
        };
        storage
            .store_forum_metadata(&forum_hash, &metadata)
            .unwrap();

        // Store node
        storage
            .store_node_for_forum(&forum_hash, &DagNode::from(forum.clone()))
            .expect("Failed to store forum");

        // Load
        let loaded = storage
            .load_forum(&forum_hash)
            .expect("Failed to load forum")
            .expect("Forum not found");

        assert_eq!(forum.name(), loaded.name());
        assert_eq!(forum.hash(), loaded.hash());
    }

    #[test]
    fn test_store_and_load_board() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let forum_hash = *forum.hash();

        let board = BoardGenesis::create(
            forum_hash,
            "Test Board".to_string(),
            "A test board".to_string(),
            vec!["tag1".to_string()],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board");

        // Store metadata first
        let metadata = ForumMetadata {
            name: forum.name().to_string(),
            description: forum.description().to_string(),
            created_at: forum.created_at(),
            owner_identity: forum.creator_identity().to_vec(),
        };
        storage
            .store_forum_metadata(&forum_hash, &metadata)
            .unwrap();

        storage
            .store_node_for_forum(&forum_hash, &DagNode::from(forum))
            .unwrap();
        storage
            .store_node_for_forum(&forum_hash, &DagNode::from(board.clone()))
            .unwrap();

        let loaded = storage
            .load_board(&forum_hash, board.hash())
            .unwrap()
            .expect("Board not found");

        assert_eq!(board.name(), loaded.name());
    }

    #[test]
    fn test_list_forums() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();

        // Create forums with different names to ensure unique hashes
        let forum1 = ForumGenesis::create(
            "Test Forum One".to_string(),
            "First test forum".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let forum2 = ForumGenesis::create(
            "Test Forum Two".to_string(),
            "Second test forum".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        // Store metadata for both forums
        for forum in [&forum1, &forum2] {
            let metadata = ForumMetadata {
                name: forum.name().to_string(),
                description: forum.description().to_string(),
                created_at: forum.created_at(),
                owner_identity: forum.creator_identity().to_vec(),
            };
            storage
                .store_forum_metadata(forum.hash(), &metadata)
                .unwrap();
            storage
                .store_node_for_forum(forum.hash(), &DagNode::from(forum.clone()))
                .unwrap();
        }

        let forums = storage.list_forums().unwrap();
        assert_eq!(forums.len(), 2);
        assert!(forums.contains(forum1.hash()));
        assert!(forums.contains(forum2.hash()));
    }

    #[test]
    fn test_get_boards() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let forum_hash = *forum.hash();

        let board1 = BoardGenesis::create(
            forum_hash,
            "Board 1".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let board2 = BoardGenesis::create(
            forum_hash,
            "Board 2".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        // Store metadata
        let metadata = ForumMetadata {
            name: forum.name().to_string(),
            description: forum.description().to_string(),
            created_at: forum.created_at(),
            owner_identity: forum.creator_identity().to_vec(),
        };
        storage
            .store_forum_metadata(&forum_hash, &metadata)
            .unwrap();

        storage
            .store_node_for_forum(&forum_hash, &DagNode::from(forum))
            .unwrap();
        storage
            .store_node_for_forum(&forum_hash, &DagNode::from(board1))
            .unwrap();
        storage
            .store_node_for_forum(&forum_hash, &DagNode::from(board2))
            .unwrap();

        let boards = storage.get_boards(&forum_hash).unwrap();
        assert_eq!(boards.len(), 2);
    }

    #[test]
    fn test_node_exists() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let forum_hash = *forum.hash();

        assert!(!storage.node_exists(&forum_hash, forum.hash()).unwrap());

        // Store metadata
        let metadata = ForumMetadata {
            name: forum.name().to_string(),
            description: forum.description().to_string(),
            created_at: forum.created_at(),
            owner_identity: forum.creator_identity().to_vec(),
        };
        storage
            .store_forum_metadata(&forum_hash, &metadata)
            .unwrap();

        storage
            .store_node_for_forum(&forum_hash, &DagNode::from(forum.clone()))
            .unwrap();
        assert!(storage.node_exists(&forum_hash, forum.hash()).unwrap());
    }

    #[test]
    fn test_heads() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let head1 = ContentHash::from_bytes([1u8; 64]);
        let head2 = ContentHash::from_bytes([2u8; 64]);

        let mut heads = HashSet::new();
        heads.insert(head1);
        heads.insert(head2);

        storage.set_heads(forum.hash(), &heads).unwrap();
        let loaded_heads = storage.get_heads(forum.hash()).unwrap();

        assert_eq!(heads, loaded_heads);
    }

    #[test]
    fn test_load_forum_nodes() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let forum_hash = *forum.hash();

        let board = BoardGenesis::create(
            forum_hash,
            "Board".to_string(),
            "".to_string(),
            vec![],
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let thread = ThreadRoot::create(
            *board.hash(),
            "Thread".to_string(),
            "Body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let post = Post::create(
            *thread.hash(),
            vec![],
            "Post body".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        // Store metadata
        let metadata = ForumMetadata {
            name: forum.name().to_string(),
            description: forum.description().to_string(),
            created_at: forum.created_at(),
            owner_identity: forum.creator_identity().to_vec(),
        };
        storage
            .store_forum_metadata(&forum_hash, &metadata)
            .unwrap();

        storage
            .store_node_for_forum(&forum_hash, &DagNode::from(forum))
            .unwrap();
        storage
            .store_node_for_forum(&forum_hash, &DagNode::from(board))
            .unwrap();
        storage
            .store_node_for_forum(&forum_hash, &DagNode::from(thread))
            .unwrap();
        storage
            .store_node_for_forum(&forum_hash, &DagNode::from(post))
            .unwrap();

        let nodes = storage.load_forum_nodes(&forum_hash).unwrap();
        assert_eq!(nodes.len(), 4);
    }

    #[test]
    fn test_clear_storage() {
        let (storage, _temp_dir) = create_test_storage();
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let forum_hash = *forum.hash();

        // Store metadata
        let metadata = ForumMetadata {
            name: forum.name().to_string(),
            description: forum.description().to_string(),
            created_at: forum.created_at(),
            owner_identity: forum.creator_identity().to_vec(),
        };
        storage
            .store_forum_metadata(&forum_hash, &metadata)
            .unwrap();

        storage
            .store_node_for_forum(&forum_hash, &DagNode::from(forum.clone()))
            .unwrap();
        assert!(storage.node_exists(&forum_hash, forum.hash()).unwrap());

        storage.clear().unwrap();
        assert!(!storage.node_exists(&forum_hash, forum.hash()).unwrap());
    }

    #[test]
    fn test_consumed_otps() {
        let (storage, _temp_dir) = create_test_storage();
        let identity_hash = ContentHash::from_bytes([1u8; 64]);

        // Initially no OTPs consumed
        assert!(!storage.is_otp_consumed(&identity_hash, 1).unwrap());

        // Record consumed OTP
        storage.record_consumed_otp(&identity_hash, 1).unwrap();
        storage.record_consumed_otp(&identity_hash, 3).unwrap();

        // Check consumption
        assert!(storage.is_otp_consumed(&identity_hash, 1).unwrap());
        assert!(!storage.is_otp_consumed(&identity_hash, 2).unwrap());
        assert!(storage.is_otp_consumed(&identity_hash, 3).unwrap());

        // List consumed OTPs
        let consumed = storage.list_consumed_otps(&identity_hash).unwrap();
        assert_eq!(consumed.len(), 2);
        assert!(consumed.contains(&1));
        assert!(consumed.contains(&3));

        // Next available ID
        let next = storage.next_available_otp_id(&identity_hash).unwrap();
        assert_eq!(next, 4);
    }
}
