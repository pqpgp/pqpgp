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
use tracing::info;

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
    pub fn new(data_dir: impl AsRef<Path>) -> Result<Self> {
        let db_path = data_dir.as_ref().join(DB_DIR);
        let config = RocksDbConfig::default();
        let column_families = &[CF_NODES, CF_FORUMS, CF_HEADS, CF_META, CF_PRIVATE];

        let db = RocksDbHandle::open(&db_path, &config, column_families)?;
        info!("Opened forum RocksDB at {:?}", db_path);

        Ok(Self { db })
    }

    /// Creates a composite key for node storage.
    fn node_key(forum_hash: &ContentHash, node_hash: &ContentHash) -> Vec<u8> {
        composite_key(forum_hash.as_bytes(), node_hash.as_bytes())
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
    pub fn store_node_for_forum(&self, forum_hash: &ContentHash, node: &DagNode) -> Result<()> {
        let key = Self::node_key(forum_hash, node.hash());
        let value = node.to_bytes()?;
        self.db.put_raw(CF_NODES, &key, &value)
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
        self.db
            .prefix_collect(CF_NODES, forum_hash.as_bytes(), |value| {
                DagNode::from_bytes(value).map_err(|e| e.to_string())
            })
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
        self.db.put(CF_FORUMS, forum_hash.as_bytes(), metadata)?;
        self.add_forum_to_list(forum_hash)?;
        Ok(())
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

    // ========================================================================
    // Forum List Management
    // ========================================================================

    /// Lists all synced forum hashes.
    pub fn list_forums(&self) -> Result<Vec<ContentHash>> {
        self.db
            .get::<Vec<ContentHash>>(CF_META, META_FORUM_LIST)
            .map(|opt| opt.unwrap_or_default())
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

        info!("Removed forum {} from local storage", forum_hash.short());
        Ok(())
    }

    // ========================================================================
    // Query Methods for UI Display
    // ========================================================================

    /// Gets all boards in a forum, sorted by creation time (newest first).
    pub fn get_boards(&self, forum_hash: &ContentHash) -> Result<Vec<BoardGenesis>> {
        let nodes = self.load_forum_nodes(forum_hash)?;
        let mut boards: Vec<BoardGenesis> = nodes
            .into_iter()
            .filter_map(|n| n.as_board_genesis().cloned())
            .collect();

        // Sort by created_at descending (newest first)
        boards.sort_by_key(|b| std::cmp::Reverse(b.created_at()));
        Ok(boards)
    }

    /// Gets all threads in a board, sorted by creation time (newest first).
    ///
    /// This accounts for moved threads: threads that were originally in another board
    /// but have been moved to this board will be included, and threads that were
    /// originally in this board but have been moved elsewhere will be excluded.
    pub fn get_threads(
        &self,
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
    ) -> Result<Vec<ThreadRoot>> {
        let nodes = self.load_forum_nodes(forum_hash)?;

        // Get the map of moved threads (thread_hash -> current_board_hash)
        let moved_threads = self.get_moved_threads(forum_hash)?;

        let mut threads: Vec<ThreadRoot> = nodes
            .into_iter()
            .filter_map(|n| n.as_thread_root().cloned())
            .filter(|t| {
                // Check if thread has been moved
                let current_board = moved_threads
                    .get(t.hash())
                    .unwrap_or_else(|| t.board_hash());
                current_board == board_hash
            })
            .collect();

        // Sort by created_at descending (newest first)
        threads.sort_by_key(|t| std::cmp::Reverse(t.created_at()));
        Ok(threads)
    }

    /// Gets all posts in a thread, sorted by creation time (oldest first for chronological reading).
    pub fn get_posts(
        &self,
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
    ) -> Result<Vec<Post>> {
        let nodes = self.load_forum_nodes(forum_hash)?;
        let mut posts: Vec<Post> = nodes
            .into_iter()
            .filter_map(|n| n.as_post().cloned())
            .filter(|p| p.thread_hash() == thread_hash)
            .collect();

        // Sort by created_at ascending (oldest first for chronological reading)
        posts.sort_by_key(|p| p.created_at());
        Ok(posts)
    }

    /// Gets the post count for a thread.
    pub fn get_post_count(
        &self,
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
    ) -> Result<usize> {
        let nodes = self.load_forum_nodes(forum_hash)?;
        let count = nodes
            .iter()
            .filter_map(|n| n.as_post())
            .filter(|p| p.thread_hash() == thread_hash)
            .count();
        Ok(count)
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

    /// Gets all mod actions for a forum.
    pub fn get_mod_actions(&self, forum_hash: &ContentHash) -> Result<Vec<ModActionNode>> {
        let nodes = self.load_forum_nodes(forum_hash)?;
        let actions: Vec<ModActionNode> = nodes
            .into_iter()
            .filter_map(|n| n.as_mod_action().cloned())
            .collect();
        Ok(actions)
    }

    /// Gets the effective board name and description after applying edits.
    ///
    /// Returns (name, description) with the most recent edit values applied.
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

        let mut name = board.name().to_string();
        let mut description = board.description().to_string();

        // Get all edit nodes for this board, sorted by timestamp (newest last)
        let nodes = self.load_forum_nodes(forum_hash)?;
        let mut edits: Vec<&EditNode> = nodes
            .iter()
            .filter_map(|n| n.as_edit())
            .filter(|e| e.target_hash() == board_hash)
            .collect();
        edits.sort_by_key(|e| e.created_at());

        // Apply edits in order (most recent wins)
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

    /// Gets the effective forum name and description after applying edits.
    ///
    /// Returns (name, description) with the most recent edit values applied.
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

        // Get all edit nodes for this forum, sorted by timestamp (newest last)
        let nodes = self.load_forum_nodes(forum_hash)?;
        let mut edits: Vec<&EditNode> = nodes
            .iter()
            .filter_map(|n| n.as_edit())
            .filter(|e| e.target_hash() == forum_hash) // Forum edits target the forum itself
            .collect();
        edits.sort_by_key(|e| e.created_at());

        // Apply edits in order (most recent wins)
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

    /// Computes the current forum-level moderators by replaying mod actions.
    ///
    /// Returns (moderator_fingerprints, owner_fingerprint) where owner is the forum creator.
    pub fn get_forum_moderators(
        &self,
        forum_hash: &ContentHash,
    ) -> Result<(HashSet<String>, Option<String>)> {
        let nodes = self.load_forum_nodes(forum_hash)?;

        // Find the forum genesis to get the owner
        let owner_fingerprint = nodes
            .iter()
            .filter_map(|n| n.as_forum_genesis())
            .next()
            .map(|g| fingerprint_from_identity(g.creator_identity()));

        // Build set of moderators by replaying add/remove actions
        let mut moderators: HashSet<String> = HashSet::new();

        // Owner is always a moderator
        if let Some(ref owner_fp) = owner_fingerprint {
            moderators.insert(owner_fp.clone());
        }

        // Sort mod actions by creation time to replay in order
        let mut mod_actions: Vec<&ModActionNode> = nodes
            .iter()
            .filter_map(|n| n.as_mod_action())
            .filter(|m| m.board_hash().is_none()) // Forum-level only
            .collect();
        mod_actions.sort_by_key(|m| m.created_at());

        for action in mod_actions {
            let target_fp = fingerprint_from_identity(action.target_identity());
            match action.action() {
                ModAction::AddModerator => {
                    moderators.insert(target_fp);
                }
                ModAction::RemoveModerator => {
                    // Can't remove the owner
                    if Some(&target_fp) != owner_fingerprint.as_ref() {
                        moderators.remove(&target_fp);
                    }
                }
                _ => {}
            }
        }

        Ok((moderators, owner_fingerprint))
    }

    /// Computes the current board-level moderators by replaying mod actions.
    pub fn get_board_moderators(
        &self,
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
    ) -> Result<HashSet<String>> {
        let nodes = self.load_forum_nodes(forum_hash)?;

        let mut moderators: HashSet<String> = HashSet::new();

        // Sort mod actions by creation time to replay in order
        let mut mod_actions: Vec<&ModActionNode> = nodes
            .iter()
            .filter_map(|n| n.as_mod_action())
            .filter(|m| m.board_hash() == Some(board_hash))
            .collect();
        mod_actions.sort_by_key(|m| m.created_at());

        for action in mod_actions {
            let target_fp = fingerprint_from_identity(action.target_identity());
            match action.action() {
                ModAction::AddBoardModerator => {
                    moderators.insert(target_fp);
                }
                ModAction::RemoveBoardModerator => {
                    moderators.remove(&target_fp);
                }
                _ => {}
            }
        }

        Ok(moderators)
    }

    /// Gets set of hidden thread hashes.
    pub fn get_hidden_threads(&self, forum_hash: &ContentHash) -> Result<HashSet<ContentHash>> {
        let nodes = self.load_forum_nodes(forum_hash)?;

        let mut hidden: HashSet<ContentHash> = HashSet::new();

        let mut mod_actions: Vec<&ModActionNode> = nodes
            .iter()
            .filter_map(|n| n.as_mod_action())
            .filter(|m| matches!(m.action(), ModAction::HideThread | ModAction::UnhideThread))
            .collect();
        mod_actions.sort_by_key(|m| m.created_at());

        for action in mod_actions {
            if let Some(target_hash) = action.target_node_hash() {
                match action.action() {
                    ModAction::HideThread => {
                        hidden.insert(*target_hash);
                    }
                    ModAction::UnhideThread => {
                        hidden.remove(target_hash);
                    }
                    _ => {}
                }
            }
        }

        Ok(hidden)
    }

    /// Gets set of hidden post hashes.
    pub fn get_hidden_posts(&self, forum_hash: &ContentHash) -> Result<HashSet<ContentHash>> {
        let nodes = self.load_forum_nodes(forum_hash)?;

        let mut hidden: HashSet<ContentHash> = HashSet::new();

        let mut mod_actions: Vec<&ModActionNode> = nodes
            .iter()
            .filter_map(|n| n.as_mod_action())
            .filter(|m| matches!(m.action(), ModAction::HidePost | ModAction::UnhidePost))
            .collect();
        mod_actions.sort_by_key(|m| m.created_at());

        for action in mod_actions {
            if let Some(target_hash) = action.target_node_hash() {
                match action.action() {
                    ModAction::HidePost => {
                        hidden.insert(*target_hash);
                    }
                    ModAction::UnhidePost => {
                        hidden.remove(target_hash);
                    }
                    _ => {}
                }
            }
        }

        Ok(hidden)
    }

    /// Gets set of hidden board hashes.
    pub fn get_hidden_boards(&self, forum_hash: &ContentHash) -> Result<HashSet<ContentHash>> {
        let nodes = self.load_forum_nodes(forum_hash)?;

        let mut hidden: HashSet<ContentHash> = HashSet::new();

        let mut mod_actions: Vec<&ModActionNode> = nodes
            .iter()
            .filter_map(|n| n.as_mod_action())
            .filter(|m| matches!(m.action(), ModAction::HideBoard | ModAction::UnhideBoard))
            .collect();
        mod_actions.sort_by_key(|m| m.created_at());

        for action in mod_actions {
            if let Some(board_hash) = action.board_hash() {
                match action.action() {
                    ModAction::HideBoard => {
                        hidden.insert(*board_hash);
                    }
                    ModAction::UnhideBoard => {
                        hidden.remove(board_hash);
                    }
                    _ => {}
                }
            }
        }

        Ok(hidden)
    }

    /// Gets map of moved threads (thread_hash -> current_board_hash).
    ///
    /// MoveThread actions update the board that a thread belongs to.
    /// The most recent MoveThread action for each thread determines its current board.
    pub fn get_moved_threads(
        &self,
        forum_hash: &ContentHash,
    ) -> Result<HashMap<ContentHash, ContentHash>> {
        let nodes = self.load_forum_nodes(forum_hash)?;

        // Get all MoveThread actions sorted by timestamp
        let mut move_actions: Vec<&ModActionNode> = nodes
            .iter()
            .filter_map(|n| n.as_mod_action())
            .filter(|m| m.action() == ModAction::MoveThread)
            .collect();
        move_actions.sort_by_key(|m| m.created_at());

        // Build map of thread -> current board (last move wins)
        let mut moved: HashMap<ContentHash, ContentHash> = HashMap::new();

        for action in move_actions {
            if let (Some(thread_hash), Some(dest_board_hash)) =
                (action.target_node_hash(), action.board_hash())
            {
                moved.insert(*thread_hash, *dest_board_hash);
            }
        }

        Ok(moved)
    }

    // ========================================================================
    // Private Message Storage Methods
    // ========================================================================

    /// Lists all encryption identities in a forum.
    pub fn list_encryption_identities(&self, forum_hash: &ContentHash) -> Result<Vec<ContentHash>> {
        let nodes = self.load_forum_nodes(forum_hash)?;
        let hashes: Vec<ContentHash> = nodes
            .iter()
            .filter_map(|n| n.as_encryption_identity())
            .map(|e| *e.hash())
            .collect();
        Ok(hashes)
    }

    /// Lists all sealed messages in a forum.
    pub fn list_sealed_messages(&self, forum_hash: &ContentHash) -> Result<Vec<ContentHash>> {
        let nodes = self.load_forum_nodes(forum_hash)?;
        let hashes: Vec<ContentHash> = nodes
            .iter()
            .filter_map(|n| n.as_sealed_private_message())
            .map(|m| *m.hash())
            .collect();
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
