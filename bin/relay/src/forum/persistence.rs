//! Forum data persistence for the relay server using RocksDB.
//!
//! This module provides disk-based storage for forum DAG nodes using RocksDB,
//! a high-performance key-value store optimized for write-heavy workloads.
//!
//! ## Storage Layout
//!
//! Uses column families for logical separation:
//! - `nodes`: `{forum_hash}:{node_hash}` -> serialized DagNode
//! - `forums`: `{forum_hash}` -> forum metadata (name, description, created_at)
//! - `meta`: `forum_list` -> list of all forum hashes
//!
//! ## Key Design
//!
//! Composite keys with forum hash prefix enable efficient per-forum iteration
//! using RocksDB's prefix seek functionality.

use super::state::{ForumRelayState, ForumState};
use pqpgp::forum::dag_ops::nodes_in_topological_order;
use pqpgp::forum::permissions::ForumPermissions;
use pqpgp::forum::types::current_timestamp_millis;
use pqpgp::forum::{validate_node, ContentHash, DagNode, ForumGenesis, ValidationContext};
use pqpgp::storage::{composite_key, RocksDbConfig, RocksDbHandle};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, error, info, warn};

/// Default data directory name.
const DATA_DIR: &str = "pqpgp_relay_data";

/// Database subdirectory.
const DB_DIR: &str = "forum_db";

/// Column family names.
const CF_NODES: &str = "nodes";
const CF_FORUMS: &str = "forums";
const CF_META: &str = "meta";

/// Key for the forum list in the meta column family.
const META_FORUM_LIST: &[u8] = b"forum_list";

/// Forum metadata stored in the forums column family.
#[derive(Debug, Serialize, Deserialize)]
struct ForumMetadata {
    name: String,
    description: String,
    created_at: u64,
    owner_identity: Vec<u8>,
}

/// RocksDB-backed forum persistence.
pub struct ForumPersistence {
    db: RocksDbHandle,
}

impl ForumPersistence {
    /// Creates a new persistence manager with the default data directory.
    pub fn new() -> Result<Self, String> {
        Self::with_data_dir(DATA_DIR)
    }

    /// Creates a new persistence manager with a custom data directory.
    pub fn with_data_dir(data_dir: impl AsRef<Path>) -> Result<Self, String> {
        let db_path = data_dir.as_ref().join(DB_DIR);
        let config = RocksDbConfig::for_server();
        let column_families = &[CF_NODES, CF_FORUMS, CF_META];

        let db = RocksDbHandle::open(&db_path, &config, column_families)
            .map_err(|e| format!("Failed to open RocksDB: {}", e))?;

        info!("Opened relay RocksDB at {:?}", db_path);

        Ok(Self { db })
    }

    /// Creates a composite key for a node: `{forum_hash}:{node_hash}`.
    fn node_key(forum_hash: &ContentHash, node_hash: &ContentHash) -> Vec<u8> {
        composite_key(forum_hash.as_bytes(), node_hash.as_bytes())
    }

    /// Saves a node to the database.
    pub fn save_node(&self, forum_hash: &ContentHash, node: &DagNode) -> Result<(), String> {
        let key = Self::node_key(forum_hash, node.hash());
        let value = node
            .to_bytes()
            .map_err(|e| format!("Failed to serialize node: {}", e))?;

        self.db
            .put_raw(CF_NODES, &key, &value)
            .map_err(|e| format!("Failed to write node: {}", e))
    }

    /// Saves forum metadata.
    fn save_forum_metadata(
        &self,
        forum_hash: &ContentHash,
        metadata: &ForumMetadata,
    ) -> Result<(), String> {
        self.db
            .put(CF_FORUMS, forum_hash.as_bytes(), metadata)
            .map_err(|e| format!("Failed to write forum metadata: {}", e))
    }

    /// Adds a forum hash to the forum list.
    fn add_to_forum_list(&self, forum_hash: &ContentHash) -> Result<(), String> {
        let mut forum_list = self.load_forum_list()?;

        if !forum_list.contains(forum_hash) {
            forum_list.push(*forum_hash);

            self.db
                .put(CF_META, META_FORUM_LIST, &forum_list)
                .map_err(|e| format!("Failed to write forum list: {}", e))?;
        }

        Ok(())
    }

    /// Loads the list of forum hashes.
    fn load_forum_list(&self) -> Result<Vec<ContentHash>, String> {
        let forums = self
            .db
            .get::<Vec<ContentHash>>(CF_META, META_FORUM_LIST)
            .map(|opt| opt.unwrap_or_default())
            .map_err(|e| format!("Failed to read forum list: {}", e))?;

        debug!(
            forum_count = forums.len(),
            "load_forum_list: retrieved forum list"
        );

        Ok(forums)
    }

    /// Loads forum metadata.
    #[allow(dead_code)]
    fn load_forum_metadata(
        &self,
        forum_hash: &ContentHash,
    ) -> Result<Option<ForumMetadata>, String> {
        self.db
            .get(CF_FORUMS, forum_hash.as_bytes())
            .map_err(|e| format!("Failed to read forum metadata: {}", e))
    }

    /// Loads all nodes for a forum.
    fn load_forum_nodes(&self, forum_hash: &ContentHash) -> Result<Vec<DagNode>, String> {
        let nodes = self
            .db
            .prefix_collect(CF_NODES, forum_hash.as_bytes(), |value| {
                DagNode::from_bytes(value).map_err(|e| e.to_string())
            })
            .map_err(|e| format!("Failed to load forum nodes: {}", e))?;

        debug!(
            forum = %forum_hash.short(),
            nodes_loaded = nodes.len(),
            "load_forum_nodes: loaded all nodes for forum"
        );

        Ok(nodes)
    }

    /// Creates a new forum with its genesis node.
    pub fn create_forum(&self, genesis: &ForumGenesis) -> Result<(), String> {
        let forum_hash = *genesis.hash();

        // Save the genesis node
        self.save_node(&forum_hash, &DagNode::from(genesis.clone()))?;

        // Save forum metadata
        let metadata = ForumMetadata {
            name: genesis.name().to_string(),
            description: genesis.description().to_string(),
            created_at: genesis.created_at(),
            owner_identity: genesis.creator_identity().to_vec(),
        };
        self.save_forum_metadata(&forum_hash, &metadata)?;

        // Add to forum list
        self.add_to_forum_list(&forum_hash)?;

        Ok(())
    }

    /// Loads all forums from the database.
    pub fn load_all(&self) -> Result<ForumRelayState, String> {
        let mut state = ForumRelayState::new();

        let forum_hashes = self.load_forum_list()?;
        info!("Loading {} forums from database", forum_hashes.len());

        for forum_hash in forum_hashes {
            match self.load_forum(&forum_hash) {
                Ok(Some(forum_state)) => {
                    let node_count = forum_state.node_count();
                    state.forums.insert(forum_hash, forum_state);
                    info!(
                        "Loaded forum {} with {} nodes",
                        forum_hash.short(),
                        node_count
                    );
                }
                Ok(None) => {
                    warn!("Forum {} has no genesis node, skipping", forum_hash.short());
                }
                Err(e) => {
                    error!("Failed to load forum {}: {}", forum_hash.short(), e);
                }
            }
        }

        info!(
            "Loaded {} forums with {} total nodes",
            state.forums.len(),
            state.total_nodes()
        );

        Ok(state)
    }

    /// Loads a single forum's state with validation.
    ///
    /// All nodes are validated before being added to the state. Invalid nodes
    /// (e.g., unauthorized EditNodes or ModActions) are rejected and logged.
    fn load_forum(&self, forum_hash: &ContentHash) -> Result<Option<ForumState>, String> {
        let nodes = self.load_forum_nodes(forum_hash)?;

        if nodes.is_empty() {
            return Ok(None);
        }

        // Find the genesis node
        let genesis = nodes.iter().find_map(|n| {
            if let DagNode::ForumGenesis(g) = n {
                Some(g.clone())
            } else {
                None
            }
        });

        let genesis = match genesis {
            Some(g) => g,
            None => return Ok(None),
        };

        // Validate genesis first
        match pqpgp::forum::validation::validate_forum_genesis(&genesis) {
            Ok(result) if !result.is_valid => {
                error!(
                    "Forum genesis {} failed validation: {:?}",
                    forum_hash.short(),
                    result.errors
                );
                return Ok(None);
            }
            Err(e) => {
                error!(
                    "Forum genesis {} validation error: {}",
                    forum_hash.short(),
                    e
                );
                return Ok(None);
            }
            _ => {}
        }

        // Create state from genesis
        let mut state = ForumState::from_genesis(&genesis);

        // Convert to HashMap for topological sorting
        let nodes_map: HashMap<ContentHash, DagNode> =
            nodes.into_iter().map(|n| (*n.hash(), n)).collect();

        // Sort nodes topologically (parents before children) to ensure correct
        // head tracking. Simple created_at sorting is insufficient when nodes
        // share timestamps - children might be processed before parents, causing
        // incorrect head state where parent nodes are never removed from heads.
        let sorted_nodes = nodes_in_topological_order(&nodes_map);

        // Build validation context incrementally as we add nodes
        let mut validated_nodes: HashMap<ContentHash, DagNode> = HashMap::new();
        validated_nodes.insert(*genesis.hash(), DagNode::from(genesis.clone()));

        let mut permissions: HashMap<ContentHash, ForumPermissions> = HashMap::new();
        permissions.insert(*forum_hash, ForumPermissions::from_genesis(&genesis));

        let current_time = current_timestamp_millis();
        let mut rejected_count = 0;

        // Add all non-genesis nodes with validation
        for node in sorted_nodes {
            if matches!(node, DagNode::ForumGenesis(_)) {
                continue;
            }

            let node_hash = *node.hash();

            // Create validation context from currently validated nodes
            let ctx = ValidationContext::new(&validated_nodes, &permissions, current_time);

            // Validate the node
            match validate_node(node, &ctx) {
                Ok(result) if result.is_valid => {
                    // Node is valid - add it to state and tracking
                    state.add_node(node.clone());
                    validated_nodes.insert(node_hash, node.clone());

                    // Update permissions if this is a mod action
                    if let DagNode::ModAction(action) = node {
                        if let Some(perms) = permissions.get_mut(forum_hash) {
                            let _ = perms.apply_action(action);
                        }
                    }
                }
                Ok(result) => {
                    // Node failed validation - reject it
                    warn!(
                        "Rejecting invalid node {} ({:?}) during load: {:?}",
                        node_hash.short(),
                        node.node_type(),
                        result.errors
                    );
                    rejected_count += 1;
                }
                Err(e) => {
                    warn!(
                        "Validation error for node {} during load: {}",
                        node_hash.short(),
                        e
                    );
                    rejected_count += 1;
                }
            }
        }

        if rejected_count > 0 {
            warn!(
                "Forum {} loaded with {} invalid nodes rejected",
                forum_hash.short(),
                rejected_count
            );
        }

        // Final permissions rebuild to ensure consistency
        state.rebuild_permissions();

        Ok(Some(state))
    }

    /// Deletes a forum and all its nodes.
    #[allow(dead_code)]
    pub fn delete_forum(&self, forum_hash: &ContentHash) -> Result<(), String> {
        // Delete all nodes for this forum
        self.db
            .prefix_delete(CF_NODES, forum_hash.as_bytes())
            .map_err(|e| format!("Failed to delete forum nodes: {}", e))?;

        // Delete forum metadata
        self.db
            .delete(CF_FORUMS, forum_hash.as_bytes())
            .map_err(|e| format!("Failed to delete forum metadata: {}", e))?;

        // Remove from forum list
        let mut forum_list = self.load_forum_list()?;
        forum_list.retain(|h| h != forum_hash);

        self.db
            .put(CF_META, META_FORUM_LIST, &forum_list)
            .map_err(|e| format!("Failed to write forum list: {}", e))?;

        info!("Deleted forum {}", forum_hash.short());

        Ok(())
    }
}

/// Wrapper around ForumRelayState that automatically persists changes.
pub struct PersistentForumState {
    /// The in-memory state.
    pub state: ForumRelayState,
    /// The persistence manager.
    persistence: ForumPersistence,
}

impl PersistentForumState {
    /// Creates a new persistent forum state, loading existing data from disk.
    pub fn new() -> Result<Self, String> {
        let persistence = ForumPersistence::new()?;
        let state = persistence.load_all()?;

        Ok(Self { state, persistence })
    }

    /// Creates a new persistent forum state with a custom data directory.
    pub fn with_data_dir(data_dir: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let persistence = ForumPersistence::with_data_dir(data_dir)?;
        let state = persistence.load_all()?;

        Ok(Self { state, persistence })
    }

    /// Creates a new forum and persists it.
    ///
    /// Database is the source of truth - we write to DB first, then update cache.
    pub fn create_forum(&mut self, genesis: ForumGenesis) -> Result<ContentHash, String> {
        let hash = *genesis.hash();

        // Check if already exists in cache
        if self.state.forums.contains_key(&hash) {
            return Err("Forum already exists".to_string());
        }

        // Persist to database first
        self.persistence.create_forum(&genesis)?;

        // Update cache on successful persist
        self.state.create_forum(genesis)?;

        Ok(hash)
    }

    /// Adds a node to a forum and persists it.
    ///
    /// Database is the source of truth - we write to DB first, then update cache.
    pub fn add_node(&mut self, forum_hash: &ContentHash, node: DagNode) -> Result<bool, String> {
        // Check if forum exists
        if !self.state.forums.contains_key(forum_hash) {
            return Err("Forum not found".to_string());
        }

        // Check if node already exists in cache
        if let Some(forum) = self.state.forums.get(forum_hash) {
            if forum.nodes.contains_key(node.hash()) {
                return Ok(false); // Already exists
            }
        }

        // Persist to database first
        self.persistence.save_node(forum_hash, &node)?;

        // Update cache on successful persist
        let added = self.state.add_node(forum_hash, node)?;

        Ok(added)
    }

    /// Gets a reference to a forum's state.
    pub fn get_forum(&self, hash: &ContentHash) -> Option<&ForumState> {
        self.state.get_forum(hash)
    }

    /// Returns the total number of nodes across all forums.
    pub fn total_nodes(&self) -> usize {
        self.state.total_nodes()
    }

    /// Provides access to the forums HashMap.
    pub fn forums(&self) -> &HashMap<ContentHash, ForumState> {
        &self.state.forums
    }
}

impl Default for PersistentForumState {
    fn default() -> Self {
        Self::new().expect("Failed to initialize persistent forum state")
    }
}
