//! Forum data persistence for the web client using RocksDB.
//!
//! This module provides disk-based storage for forum DAG nodes, mirroring
//! the relay's storage approach for consistency.
//!
//! ## Storage Layout
//!
//! Uses column families for logical separation:
//! - `nodes`: `{forum_hash}:{node_hash}` -> serialized DagNode
//! - `forums`: `{forum_hash}` -> forum metadata
//! - `heads`: `{forum_hash}` -> serialized Vec<ContentHash> (DAG heads)
//! - `meta`: `forum_list` -> list of all synced forum hashes

use pqpgp::forum::{
    BoardGenesis, ContentHash, DagNode, ModAction, ModActionNode, Post, ThreadRoot,
};
use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// Default data directory name.
const DATA_DIR: &str = "pqpgp_web_forum_data";

/// Database subdirectory.
const DB_DIR: &str = "forum_db";

/// Column family names.
const CF_NODES: &str = "nodes";
const CF_FORUMS: &str = "forums";
const CF_HEADS: &str = "heads";
const CF_META: &str = "meta";

/// Key for the forum list in the meta column family.
const META_FORUM_LIST: &[u8] = b"forum_list";

/// Forum metadata stored in the forums column family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForumMetadata {
    pub name: String,
    pub description: String,
    pub created_at: u64,
    pub owner_identity: Vec<u8>,
}

/// RocksDB-backed forum persistence for web client.
pub struct WebForumPersistence {
    db: Arc<DBWithThreadMode<MultiThreaded>>,
}

impl WebForumPersistence {
    /// Creates a new persistence manager with the default data directory.
    pub fn new() -> Result<Self, String> {
        Self::with_data_dir(DATA_DIR)
    }

    /// Creates a new persistence manager with a custom data directory.
    pub fn with_data_dir(data_dir: impl AsRef<Path>) -> Result<Self, String> {
        let db_path = data_dir.as_ref().join(DB_DIR);

        // Configure RocksDB options
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(128);
        opts.set_keep_log_file_num(2);
        opts.set_max_total_wal_size(32 * 1024 * 1024); // 32MB WAL
        opts.increase_parallelism(num_cpus::get() as i32);

        // Optimize for writes (LSM compaction)
        opts.set_write_buffer_size(32 * 1024 * 1024); // 32MB write buffer
        opts.set_max_write_buffer_number(2);
        opts.set_target_file_size_base(32 * 1024 * 1024);

        // Enable compression
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        // Column family options
        let cf_opts = Options::default();

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_NODES, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_FORUMS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_HEADS, cf_opts.clone()),
            ColumnFamilyDescriptor::new(CF_META, cf_opts),
        ];

        // Open database with column families
        let db =
            DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(&opts, &db_path, cf_descriptors)
                .map_err(|e| format!("Failed to open RocksDB: {}", e))?;

        info!("Opened web forum RocksDB at {:?}", db_path);

        Ok(Self { db: Arc::new(db) })
    }

    /// Gets a column family handle.
    fn cf(&self, name: &str) -> Result<Arc<BoundColumnFamily<'_>>, String> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| format!("Column family '{}' not found", name))
    }

    /// Creates a composite key for node storage.
    fn node_key(forum_hash: &ContentHash, node_hash: &ContentHash) -> Vec<u8> {
        let mut key = Vec::with_capacity(128);
        key.extend_from_slice(forum_hash.as_bytes());
        key.push(b':');
        key.extend_from_slice(node_hash.as_bytes());
        key
    }

    /// Stores a node in the database.
    pub fn store_node(&self, forum_hash: &ContentHash, node: &DagNode) -> Result<(), String> {
        let cf = self.cf(CF_NODES)?;
        let key = Self::node_key(forum_hash, node.hash());
        let value = node
            .to_bytes()
            .map_err(|e| format!("Failed to serialize node: {}", e))?;

        self.db
            .put_cf(&cf, &key, &value)
            .map_err(|e| format!("Failed to store node: {}", e))?;

        Ok(())
    }

    /// Loads a node by its hash.
    pub fn load_node(
        &self,
        forum_hash: &ContentHash,
        node_hash: &ContentHash,
    ) -> Result<Option<DagNode>, String> {
        let cf = self.cf(CF_NODES)?;
        let key = Self::node_key(forum_hash, node_hash);

        match self.db.get_cf(&cf, &key) {
            Ok(Some(value)) => {
                let node = DagNode::from_bytes(&value)
                    .map_err(|e| format!("Failed to deserialize node: {}", e))?;
                Ok(Some(node))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Failed to load node: {}", e)),
        }
    }

    /// Checks if a node exists.
    pub fn node_exists(
        &self,
        forum_hash: &ContentHash,
        node_hash: &ContentHash,
    ) -> Result<bool, String> {
        let cf = self.cf(CF_NODES)?;
        let key = Self::node_key(forum_hash, node_hash);

        self.db
            .get_cf(&cf, &key)
            .map(|v| v.is_some())
            .map_err(|e| format!("Failed to check node: {}", e))
    }

    /// Loads all nodes for a forum.
    pub fn load_forum_nodes(&self, forum_hash: &ContentHash) -> Result<Vec<DagNode>, String> {
        let cf = self.cf(CF_NODES)?;
        let prefix = forum_hash.as_bytes();

        let mut nodes = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf, prefix);

        for item in iter {
            match item {
                Ok((key, value)) => {
                    // Verify key starts with our prefix (prefix iterator may return extra)
                    if !key.starts_with(prefix) {
                        break;
                    }
                    match DagNode::from_bytes(&value) {
                        Ok(node) => nodes.push(node),
                        Err(e) => {
                            warn!("Failed to deserialize node: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Error iterating nodes: {}", e);
                }
            }
        }

        Ok(nodes)
    }

    /// Stores forum metadata.
    pub fn store_forum_metadata(
        &self,
        forum_hash: &ContentHash,
        metadata: &ForumMetadata,
    ) -> Result<(), String> {
        let cf = self.cf(CF_FORUMS)?;
        let value = bincode::serialize(metadata)
            .map_err(|e| format!("Failed to serialize metadata: {}", e))?;

        self.db
            .put_cf(&cf, forum_hash.as_bytes(), &value)
            .map_err(|e| format!("Failed to store metadata: {}", e))?;

        // Add to forum list
        self.add_forum_to_list(forum_hash)?;

        Ok(())
    }

    /// Loads forum metadata.
    pub fn load_forum_metadata(
        &self,
        forum_hash: &ContentHash,
    ) -> Result<Option<ForumMetadata>, String> {
        let cf = self.cf(CF_FORUMS)?;

        match self.db.get_cf(&cf, forum_hash.as_bytes()) {
            Ok(Some(value)) => {
                let metadata: ForumMetadata = bincode::deserialize(&value)
                    .map_err(|e| format!("Failed to deserialize metadata: {}", e))?;
                Ok(Some(metadata))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Failed to load metadata: {}", e)),
        }
    }

    /// Gets the current DAG heads for a forum.
    pub fn get_heads(&self, forum_hash: &ContentHash) -> Result<HashSet<ContentHash>, String> {
        let cf = self.cf(CF_HEADS)?;

        match self.db.get_cf(&cf, forum_hash.as_bytes()) {
            Ok(Some(value)) => {
                let heads: Vec<ContentHash> = bincode::deserialize(&value)
                    .map_err(|e| format!("Failed to deserialize heads: {}", e))?;
                Ok(heads.into_iter().collect())
            }
            Ok(None) => Ok(HashSet::new()),
            Err(e) => Err(format!("Failed to get heads: {}", e)),
        }
    }

    /// Sets the DAG heads for a forum.
    pub fn set_heads(
        &self,
        forum_hash: &ContentHash,
        heads: &HashSet<ContentHash>,
    ) -> Result<(), String> {
        let cf = self.cf(CF_HEADS)?;
        let heads_vec: Vec<ContentHash> = heads.iter().copied().collect();
        let value = bincode::serialize(&heads_vec)
            .map_err(|e| format!("Failed to serialize heads: {}", e))?;

        self.db
            .put_cf(&cf, forum_hash.as_bytes(), &value)
            .map_err(|e| format!("Failed to set heads: {}", e))?;

        Ok(())
    }

    /// Updates heads after storing a new node.
    pub fn update_heads_for_node(
        &self,
        forum_hash: &ContentHash,
        node: &DagNode,
    ) -> Result<(), String> {
        let mut heads = self.get_heads(forum_hash)?;

        // Remove parents from heads (they now have children)
        for parent_hash in node.parent_hashes() {
            heads.remove(&parent_hash);
        }

        // Add this node as a head
        heads.insert(*node.hash());

        self.set_heads(forum_hash, &heads)
    }

    /// Lists all synced forum hashes.
    pub fn list_forums(&self) -> Result<Vec<ContentHash>, String> {
        let cf = self.cf(CF_META)?;

        match self.db.get_cf(&cf, META_FORUM_LIST) {
            Ok(Some(value)) => {
                let forums: Vec<ContentHash> = bincode::deserialize(&value)
                    .map_err(|e| format!("Failed to deserialize forum list: {}", e))?;
                Ok(forums)
            }
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(format!("Failed to list forums: {}", e)),
        }
    }

    /// Adds a forum to the list of synced forums.
    fn add_forum_to_list(&self, forum_hash: &ContentHash) -> Result<(), String> {
        let cf = self.cf(CF_META)?;
        let mut forums = self.list_forums()?;

        if !forums.contains(forum_hash) {
            forums.push(*forum_hash);
            let value = bincode::serialize(&forums)
                .map_err(|e| format!("Failed to serialize forum list: {}", e))?;

            self.db
                .put_cf(&cf, META_FORUM_LIST, &value)
                .map_err(|e| format!("Failed to update forum list: {}", e))?;
        }

        Ok(())
    }

    /// Removes a forum and all its data.
    pub fn remove_forum(&self, forum_hash: &ContentHash) -> Result<(), String> {
        // Delete all nodes for this forum
        let cf_nodes = self.cf(CF_NODES)?;
        let prefix = forum_hash.as_bytes();
        let iter = self.db.prefix_iterator_cf(&cf_nodes, prefix);

        for item in iter {
            match item {
                Ok((key, _)) => {
                    if !key.starts_with(prefix) {
                        break;
                    }
                    self.db
                        .delete_cf(&cf_nodes, &key)
                        .map_err(|e| format!("Failed to delete node: {}", e))?;
                }
                Err(e) => {
                    warn!("Error during node deletion: {}", e);
                }
            }
        }

        // Delete forum metadata
        let cf_forums = self.cf(CF_FORUMS)?;
        self.db
            .delete_cf(&cf_forums, forum_hash.as_bytes())
            .map_err(|e| format!("Failed to delete forum metadata: {}", e))?;

        // Delete heads
        let cf_heads = self.cf(CF_HEADS)?;
        self.db
            .delete_cf(&cf_heads, forum_hash.as_bytes())
            .map_err(|e| format!("Failed to delete heads: {}", e))?;

        // Remove from forum list
        let cf_meta = self.cf(CF_META)?;
        let forums = self.list_forums()?;
        let filtered: Vec<_> = forums
            .iter()
            .filter(|h| *h != forum_hash)
            .copied()
            .collect();
        let value = bincode::serialize(&filtered)
            .map_err(|e| format!("Failed to serialize forum list: {}", e))?;
        self.db
            .put_cf(&cf_meta, META_FORUM_LIST, &value)
            .map_err(|e| format!("Failed to update forum list: {}", e))?;

        info!("Removed forum {} from local storage", forum_hash.short());
        Ok(())
    }

    /// Checks if a forum exists locally.
    pub fn forum_exists(&self, forum_hash: &ContentHash) -> Result<bool, String> {
        self.load_forum_metadata(forum_hash).map(|m| m.is_some())
    }

    // ==================== Query Methods ====================
    // These methods query local DAG nodes for UI display.

    /// Gets all boards in a forum, sorted by creation time (newest first).
    pub fn get_boards(&self, forum_hash: &ContentHash) -> Result<Vec<BoardGenesis>, String> {
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
    ) -> Result<Vec<ThreadRoot>, String> {
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
    ) -> Result<Vec<Post>, String> {
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
    ) -> Result<usize, String> {
        let nodes = self.load_forum_nodes(forum_hash)?;
        let count = nodes
            .iter()
            .filter_map(|n| n.as_post())
            .filter(|p| p.thread_hash() == thread_hash)
            .count();
        Ok(count)
    }

    /// Gets all mod actions for a forum.
    pub fn get_mod_actions(&self, forum_hash: &ContentHash) -> Result<Vec<ModActionNode>, String> {
        let nodes = self.load_forum_nodes(forum_hash)?;
        let actions: Vec<ModActionNode> = nodes
            .into_iter()
            .filter_map(|n| n.as_mod_action().cloned())
            .collect();
        Ok(actions)
    }

    /// Gets a specific board by hash.
    pub fn get_board(
        &self,
        forum_hash: &ContentHash,
        board_hash: &ContentHash,
    ) -> Result<Option<BoardGenesis>, String> {
        let node = self.load_node(forum_hash, board_hash)?;
        Ok(node.and_then(|n| n.as_board_genesis().cloned()))
    }

    /// Gets a specific thread by hash.
    pub fn get_thread(
        &self,
        forum_hash: &ContentHash,
        thread_hash: &ContentHash,
    ) -> Result<Option<ThreadRoot>, String> {
        let node = self.load_node(forum_hash, thread_hash)?;
        Ok(node.and_then(|n| n.as_thread_root().cloned()))
    }

    /// Computes the current forum-level moderators by replaying mod actions.
    ///
    /// Returns (moderator_fingerprints, owner_fingerprint) where owner is the forum creator.
    pub fn get_forum_moderators(
        &self,
        forum_hash: &ContentHash,
    ) -> Result<(HashSet<String>, Option<String>), String> {
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
    ) -> Result<HashSet<String>, String> {
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
    pub fn get_hidden_threads(
        &self,
        forum_hash: &ContentHash,
    ) -> Result<HashSet<ContentHash>, String> {
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
    pub fn get_hidden_posts(
        &self,
        forum_hash: &ContentHash,
    ) -> Result<HashSet<ContentHash>, String> {
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
    pub fn get_hidden_boards(
        &self,
        forum_hash: &ContentHash,
    ) -> Result<HashSet<ContentHash>, String> {
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
    ) -> Result<HashMap<ContentHash, ContentHash>, String> {
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
}

/// Helper to compute fingerprint from identity bytes.
/// Computes a fingerprint from identity bytes using the same algorithm as PublicKey::fingerprint().
///
/// This ensures fingerprints match between keys loaded from the keyring and identities
/// stored in forum nodes.
fn fingerprint_from_identity(identity: &[u8]) -> String {
    use pqpgp::crypto::PublicKey;
    let fingerprint = PublicKey::fingerprint_from_mldsa87_bytes(identity);
    hex::encode(&fingerprint[..8]) // First 16 hex chars
}

impl Default for WebForumPersistence {
    fn default() -> Self {
        Self::new().expect("Failed to create default persistence")
    }
}
