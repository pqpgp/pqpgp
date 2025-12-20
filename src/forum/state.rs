//! Forum in-memory state management.
//!
//! This module provides in-memory state for forum DAG nodes, tracking heads
//! and permissions. It can be used by relays for serving forums or by clients
//! for local caching.
//!
//! ## Indexing Strategy
//!
//! For efficient queries, the state maintains secondary indexes:
//! - `boards`: All board hashes for O(1) board listing
//! - `board_threads`: Board hash → thread hashes for O(1) thread listing per board
//! - `thread_posts`: Thread hash → post hashes for O(1) post listing per thread
//!
//! These indexes are automatically maintained when nodes are added.
//!
//! For persistent storage, see the `storage` module.

use crate::forum::dag_ops::nodes_in_topological_order;
use crate::forum::{
    ContentHash, DagNode, ForumGenesis, ForumPermissions, NodeType, PermissionBuilder,
};
use std::collections::{BTreeMap, HashMap, HashSet};

/// In-memory state for a single forum.
///
/// This struct maintains both primary storage (the `nodes` HashMap) and secondary
/// indexes for efficient content retrieval. All indexes are automatically updated
/// when nodes are added via `add_node()`.
#[derive(Debug, Default)]
pub struct ForumState {
    /// All nodes in this forum's DAG, keyed by content hash.
    pub nodes: HashMap<ContentHash, DagNode>,
    /// Current DAG heads (nodes with no children).
    pub heads: HashSet<ContentHash>,
    /// Cached permission state for this forum.
    pub permissions: Option<ForumPermissions>,
    /// Forum name (extracted from genesis).
    pub name: String,
    /// Forum description (extracted from genesis).
    pub description: String,
    /// Creation timestamp.
    pub created_at: u64,

    // ==========================================================================
    // Secondary Indexes for O(1) Content Retrieval
    // ==========================================================================
    /// All board hashes in this forum, ordered by creation time.
    /// Enables O(1) board listing instead of O(n) filtering.
    boards: Vec<ContentHash>,

    /// Maps board hash → thread hashes in that board.
    /// Enables O(1) thread listing per board instead of O(n) filtering.
    /// Note: Threads are stored under their *original* board. Use permissions
    /// to check for moved threads when rendering.
    board_threads: HashMap<ContentHash, Vec<ContentHash>>,

    /// Maps thread hash → post hashes in that thread.
    /// Enables O(1) post listing per thread instead of O(n) filtering.
    thread_posts: HashMap<ContentHash, Vec<ContentHash>>,

    /// Pre-computed topological order of all nodes.
    /// Lazily rebuilt when needed (None = needs rebuild).
    /// Enables O(k) pagination for export instead of O(n log n) per request.
    topological_cache: Option<Vec<ContentHash>>,

    /// Nodes indexed by (timestamp, hash) for efficient timestamp-based sync.
    /// BTreeMap provides O(log n) range queries by timestamp.
    /// The hash is included in the key to handle multiple nodes with same timestamp.
    nodes_by_timestamp: BTreeMap<(u64, ContentHash), ()>,
}

impl ForumState {
    /// Creates a new forum state from a genesis node.
    pub fn from_genesis(genesis: &ForumGenesis) -> Self {
        let permissions = ForumPermissions::from_genesis(genesis);
        let hash = *genesis.hash();

        let mut nodes = HashMap::new();
        nodes.insert(hash, DagNode::from(genesis.clone()));

        let mut heads = HashSet::new();
        heads.insert(hash);

        // Initialize timestamp index with genesis node
        let mut nodes_by_timestamp = BTreeMap::new();
        nodes_by_timestamp.insert((genesis.created_at(), hash), ());

        Self {
            nodes,
            heads,
            permissions: Some(permissions),
            name: genesis.name().to_string(),
            description: genesis.description().to_string(),
            created_at: genesis.created_at(),
            // Initialize empty secondary indexes
            boards: Vec::new(),
            board_threads: HashMap::new(),
            thread_posts: HashMap::new(),
            topological_cache: Some(vec![hash]), // Genesis is the only node
            nodes_by_timestamp,
        }
    }

    /// Adds a node to the forum state.
    ///
    /// Returns `Ok(true)` if the node was new, `Ok(false)` if it already existed.
    /// Returns `Err` if adding the node would cause a permission error.
    /// Automatically updates all secondary indexes for O(1) content retrieval.
    pub fn add_node(&mut self, node: DagNode) -> Result<bool, String> {
        let hash = *node.hash();

        // Check if already exists
        if self.nodes.contains_key(&hash) {
            return Ok(false);
        }

        // Update permissions if this is a mod action - do this BEFORE adding the node
        // so we can reject invalid mod actions without corrupting state
        if let DagNode::ModAction(action) = &node {
            if let Some(ref mut perms) = self.permissions {
                perms
                    .apply_action(action)
                    .map_err(|e| format!("Failed to apply mod action: {}", e))?;
            }
        }

        // Update heads: remove parents from heads, add this node
        for parent_hash in node.parent_hashes() {
            self.heads.remove(&parent_hash);
        }
        self.heads.insert(hash);

        // Update secondary indexes based on node type
        self.update_indexes_for_node(&node);

        // Update timestamp index for sync
        let timestamp = node.created_at();
        self.nodes_by_timestamp.insert((timestamp, hash), ());

        // Invalidate topological cache since we added a new node
        self.topological_cache = None;

        // Store the node
        self.nodes.insert(hash, node);
        Ok(true)
    }

    /// Updates secondary indexes when a new node is added.
    ///
    /// This method maintains O(1) insertion into indexes while enabling
    /// O(1) lookup for common queries like "get all threads in board".
    fn update_indexes_for_node(&mut self, node: &DagNode) {
        let hash = *node.hash();

        match node {
            DagNode::BoardGenesis(_) => {
                // Add board to the boards index
                self.boards.push(hash);
                // Initialize empty thread list for this board
                self.board_threads.entry(hash).or_default();
            }
            DagNode::ThreadRoot(thread) => {
                // Add thread to its board's thread list
                let board_hash = *thread.board_hash();
                self.board_threads.entry(board_hash).or_default().push(hash);
                // Initialize empty post list for this thread
                self.thread_posts.entry(hash).or_default();
            }
            DagNode::Post(post) => {
                // Add post to its thread's post list
                let thread_hash = *post.thread_hash();
                self.thread_posts.entry(thread_hash).or_default().push(hash);
            }
            DagNode::ModAction(action) => {
                // Update secondary indexes for moderation actions that affect structure
                use crate::forum::ModAction;
                if action.action() == ModAction::MoveThread {
                    // MoveThread changes which board a thread belongs to
                    // Remove from old board's index, add to new board's index
                    if let (Some(thread_hash), Some(dest_board_hash)) =
                        (action.target_node_hash(), action.board_hash())
                    {
                        // Find and remove thread from its current board's index
                        // We need to find which board currently has this thread
                        let mut source_board = None;
                        for (board, threads) in &self.board_threads {
                            if threads.contains(thread_hash) {
                                source_board = Some(*board);
                                break;
                            }
                        }

                        // Remove from source board if found
                        if let Some(source) = source_board {
                            if let Some(threads) = self.board_threads.get_mut(&source) {
                                threads.retain(|h| h != thread_hash);
                            }
                        }

                        // Add to destination board
                        self.board_threads
                            .entry(*dest_board_hash)
                            .or_default()
                            .push(*thread_hash);
                    }
                }
            }
            // Other node types don't need indexing
            DagNode::ForumGenesis(_)
            | DagNode::Edit(_)
            | DagNode::EncryptionIdentity(_)
            | DagNode::SealedPrivateMessage(_) => {}
        }
    }

    /// Returns the number of nodes in this forum.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Gets a reference to a node by hash.
    pub fn get_node(&self, hash: &ContentHash) -> Option<&DagNode> {
        self.nodes.get(hash)
    }

    /// Checks if a node exists in this forum.
    pub fn has_node(&self, hash: &ContentHash) -> bool {
        self.nodes.contains_key(hash)
    }

    /// Returns an iterator over all nodes.
    pub fn iter_nodes(&self) -> impl Iterator<Item = (&ContentHash, &DagNode)> {
        self.nodes.iter()
    }

    /// Gets nodes after a cursor for sync, up to a limit.
    ///
    /// Uses the timestamp index for efficient O(log n) seek + O(batch) iteration.
    /// The cursor is `(timestamp, hash)` - nodes at the cursor position are excluded,
    /// and iteration starts from the next node in (timestamp, hash) order.
    ///
    /// # Arguments
    /// * `cursor_timestamp` - Start from nodes with timestamp >= this value (use 0 for all)
    /// * `cursor_hash` - If Some, start AFTER this specific (timestamp, hash) pair
    /// * `limit` - Maximum number of nodes to return
    ///
    /// # Returns
    /// Tuple of (nodes, has_more) where nodes are ordered by (timestamp, hash)
    pub fn get_nodes_after_cursor(
        &self,
        cursor_timestamp: u64,
        cursor_hash: Option<&ContentHash>,
        limit: usize,
    ) -> (Vec<&DagNode>, bool) {
        use std::ops::Bound;

        let mut nodes = Vec::with_capacity(limit);

        // Determine the correct starting bound based on cursor
        let range = if let Some(cursor) = cursor_hash {
            // Start AFTER the cursor position (exclusive)
            let cursor_key = (cursor_timestamp, *cursor);
            self.nodes_by_timestamp
                .range((Bound::Excluded(cursor_key), Bound::Unbounded))
        } else {
            // No cursor hash - start from the timestamp (inclusive)
            let start = (cursor_timestamp, ContentHash::from_bytes([0u8; 64]));
            self.nodes_by_timestamp
                .range((Bound::Included(start), Bound::Unbounded))
        };

        for ((ts, hash), ()) in range {
            // Get the actual node
            if let Some(node) = self.nodes.get(hash) {
                nodes.push(node);
                if nodes.len() >= limit {
                    // Check if there are more nodes after this batch
                    let next_start = (*ts, *hash);
                    let has_more = self
                        .nodes_by_timestamp
                        .range((Bound::Excluded(next_start), Bound::Unbounded))
                        .next()
                        .is_some();
                    return (nodes, has_more);
                }
            }
        }

        (nodes, false)
    }

    /// Rebuilds permissions and secondary indexes from scratch by replaying all nodes.
    ///
    /// This is called during forum loading to ensure indexes are consistent with
    /// the loaded nodes. It replays all nodes in topological order.
    pub fn rebuild_permissions(&mut self) {
        let mut builder = PermissionBuilder::new();

        // Clear and rebuild secondary indexes
        self.boards.clear();
        self.board_threads.clear();
        self.thread_posts.clear();
        self.nodes_by_timestamp.clear();

        // Collect nodes in topological order first to avoid borrow conflict
        let ordered_nodes: Vec<DagNode> = nodes_in_topological_order(&self.nodes)
            .into_iter()
            .cloned()
            .collect();

        for node in &ordered_nodes {
            let _ = builder.process_node(node);
            // Rebuild secondary indexes
            self.update_indexes_for_node(node);
            // Rebuild timestamp index
            self.nodes_by_timestamp
                .insert((node.created_at(), *node.hash()), ());
        }

        if let Some(hash) = self.nodes.values().find_map(|n| {
            if n.node_type() == NodeType::ForumGenesis {
                Some(*n.hash())
            } else {
                None
            }
        }) {
            self.permissions = builder.into_permissions().remove(&hash);
        }

        // Invalidate topological cache to force rebuild on next access
        self.topological_cache = None;
    }

    // ==========================================================================
    // Secondary Index Query Methods - O(1) Content Retrieval
    // ==========================================================================

    /// Returns all board hashes in this forum.
    ///
    /// Boards are returned in the order they were created.
    /// Complexity: O(1) - returns reference to pre-built index.
    ///
    /// # Example
    /// ```ignore
    /// for board_hash in forum.get_boards() {
    ///     let board = forum.get_node(board_hash);
    /// }
    /// ```
    #[inline]
    pub fn get_boards(&self) -> &[ContentHash] {
        &self.boards
    }

    /// Returns the number of boards in this forum.
    ///
    /// Complexity: O(1).
    #[inline]
    pub fn board_count(&self) -> usize {
        self.boards.len()
    }

    /// Returns all thread hashes in a specific board.
    ///
    /// Returns threads under their *original* board assignment. To get the
    /// effective board for a thread (considering moves), use
    /// `get_effective_board_for_thread()`.
    ///
    /// Complexity: O(1) - returns reference to pre-built index.
    ///
    /// # Arguments
    /// * `board_hash` - The hash of the board to query
    ///
    /// # Returns
    /// Slice of thread hashes, or empty slice if board doesn't exist or has no threads.
    #[inline]
    pub fn get_threads_in_board(&self, board_hash: &ContentHash) -> &[ContentHash] {
        self.board_threads
            .get(board_hash)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Returns the number of threads in a specific board.
    ///
    /// Complexity: O(1).
    #[inline]
    pub fn thread_count_in_board(&self, board_hash: &ContentHash) -> usize {
        self.board_threads
            .get(board_hash)
            .map(Vec::len)
            .unwrap_or(0)
    }

    /// Returns all post hashes in a specific thread.
    ///
    /// Posts are returned in the order they were added to the forum.
    /// Complexity: O(1) - returns reference to pre-built index.
    ///
    /// # Arguments
    /// * `thread_hash` - The hash of the thread to query
    ///
    /// # Returns
    /// Slice of post hashes, or empty slice if thread doesn't exist or has no posts.
    #[inline]
    pub fn get_posts_in_thread(&self, thread_hash: &ContentHash) -> &[ContentHash] {
        self.thread_posts
            .get(thread_hash)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Returns the number of posts in a specific thread.
    ///
    /// Complexity: O(1).
    #[inline]
    pub fn post_count_in_thread(&self, thread_hash: &ContentHash) -> usize {
        self.thread_posts
            .get(thread_hash)
            .map(Vec::len)
            .unwrap_or(0)
    }

    /// Returns nodes in topological order, using cached result when available.
    ///
    /// This method lazily computes and caches the topological order. The cache
    /// is invalidated when nodes are added.
    ///
    /// Complexity: O(1) if cached, O(n log n) on cache miss.
    pub fn get_topological_order(&mut self) -> &[ContentHash] {
        if self.topological_cache.is_none() {
            let ordered: Vec<ContentHash> = nodes_in_topological_order(&self.nodes)
                .into_iter()
                .map(|n| *n.hash())
                .collect();
            self.topological_cache = Some(ordered);
        }
        self.topological_cache.as_ref().unwrap()
    }

    /// Returns a paginated slice of nodes in topological order.
    ///
    /// This is more efficient than computing the full topological order
    /// when only a subset of nodes is needed.
    ///
    /// # Arguments
    /// * `skip` - Number of nodes to skip
    /// * `take` - Maximum number of nodes to return
    ///
    /// # Returns
    /// Vector of node hashes in topological order for the requested page.
    pub fn get_topological_page(&mut self, skip: usize, take: usize) -> Vec<ContentHash> {
        // Ensure cache is populated
        if self.topological_cache.is_none() {
            let ordered: Vec<ContentHash> = nodes_in_topological_order(&self.nodes)
                .into_iter()
                .map(|n| *n.hash())
                .collect();
            self.topological_cache = Some(ordered);
        }

        // Return the paginated slice of hashes
        self.topological_cache
            .as_ref()
            .unwrap()
            .iter()
            .skip(skip)
            .take(take)
            .copied()
            .collect()
    }

    /// Returns the effective board hash for a thread, considering any moves.
    ///
    /// If the thread has been moved via a `MoveThread` moderation action, this returns
    /// the destination board. Otherwise, returns the original board from the thread's
    /// `board_hash` field.
    ///
    /// # Arguments
    /// * `thread_hash` - The content hash of the thread root
    ///
    /// # Returns
    /// * `Some(board_hash)` - The effective board hash (moved destination or original)
    /// * `None` - If the thread doesn't exist in this forum
    pub fn get_effective_board_for_thread(&self, thread_hash: &ContentHash) -> Option<ContentHash> {
        // First check if the thread has been moved
        if let Some(perms) = &self.permissions {
            if let Some(moved_board) = perms.get_thread_current_board(thread_hash) {
                return Some(*moved_board);
            }
        }

        // Not moved - get the original board from the thread root
        if let Some(node) = self.nodes.get(thread_hash) {
            if let Some(thread) = node.as_thread_root() {
                return Some(*thread.board_hash());
            }
        }

        None
    }

    /// Returns the effective board hash for a post, considering thread moves.
    ///
    /// This follows the post -> thread -> board chain, and accounts for any
    /// `MoveThread` moderation actions that may have relocated the thread.
    ///
    /// # Arguments
    /// * `post_hash` - The content hash of the post
    ///
    /// # Returns
    /// * `Some(board_hash)` - The effective board hash for the post's thread
    /// * `None` - If the post or its thread doesn't exist in this forum
    pub fn get_effective_board_for_post(&self, post_hash: &ContentHash) -> Option<ContentHash> {
        // Get the post's thread hash
        let thread_hash = self
            .nodes
            .get(post_hash)
            .and_then(|node| node.as_post().map(|post| *post.thread_hash()))?;

        // Delegate to thread lookup
        self.get_effective_board_for_thread(&thread_hash)
    }

    /// Returns the effective board hash for any node type.
    ///
    /// This is a convenience method that handles posts, threads, and boards uniformly:
    /// - For posts: returns the effective board via the thread (considering moves)
    /// - For threads: returns the effective board (considering moves)
    /// - For boards: returns the board's own hash
    /// - For other node types: returns None
    ///
    /// # Arguments
    /// * `node_hash` - The content hash of the node
    ///
    /// # Returns
    /// * `Some(board_hash)` - The effective board hash
    /// * `None` - If the node doesn't exist or is not a post/thread/board
    pub fn get_effective_board(&self, node_hash: &ContentHash) -> Option<ContentHash> {
        let node = self.nodes.get(node_hash)?;

        match node.node_type() {
            NodeType::Post => self.get_effective_board_for_post(node_hash),
            NodeType::ThreadRoot => self.get_effective_board_for_thread(node_hash),
            NodeType::BoardGenesis => Some(*node_hash),
            _ => None,
        }
    }
}

/// Container for multiple forums' in-memory state.
#[derive(Debug, Default)]
pub struct ForumRelayState {
    /// All forums by their genesis hash.
    pub forums: HashMap<ContentHash, ForumState>,
}

impl ForumRelayState {
    /// Creates a new empty forum relay state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new forum from a genesis node.
    ///
    /// Returns the forum hash if successful.
    pub fn create_forum(&mut self, genesis: ForumGenesis) -> Result<ContentHash, String> {
        let hash = *genesis.hash();

        if self.forums.contains_key(&hash) {
            return Err("Forum already exists".to_string());
        }

        let state = ForumState::from_genesis(&genesis);
        self.forums.insert(hash, state);

        Ok(hash)
    }

    /// Adds a node to a forum.
    ///
    /// Returns an error if the forum doesn't exist or the node is invalid.
    pub fn add_node(&mut self, forum_hash: &ContentHash, node: DagNode) -> Result<bool, String> {
        let forum = self
            .forums
            .get_mut(forum_hash)
            .ok_or_else(|| "Forum not found".to_string())?;

        // If this is a forum genesis, it should match the forum hash
        if let DagNode::ForumGenesis(genesis) = &node {
            if genesis.hash() != forum_hash {
                return Err("Forum genesis hash mismatch".to_string());
            }
        }

        forum.add_node(node)
    }

    /// Gets a reference to a forum's state.
    pub fn get_forum(&self, hash: &ContentHash) -> Option<&ForumState> {
        self.forums.get(hash)
    }

    /// Gets a mutable reference to a forum's state.
    pub fn get_forum_mut(&mut self, hash: &ContentHash) -> Option<&mut ForumState> {
        self.forums.get_mut(hash)
    }

    /// Returns the total number of nodes across all forums.
    pub fn total_nodes(&self) -> usize {
        self.forums.values().map(|f| f.node_count()).sum()
    }

    /// Returns the number of forums.
    pub fn forum_count(&self) -> usize {
        self.forums.len()
    }

    /// Returns an iterator over all forum hashes.
    pub fn forum_hashes(&self) -> impl Iterator<Item = &ContentHash> {
        self.forums.keys()
    }

    /// Removes a forum.
    ///
    /// Returns true if the forum existed and was removed.
    pub fn remove_forum(&mut self, hash: &ContentHash) -> bool {
        self.forums.remove(hash).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::forum::dag_ops::compute_missing;
    use crate::forum::BoardGenesis;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
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
    fn test_forum_state_from_genesis() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let state = ForumState::from_genesis(&genesis);

        assert_eq!(state.node_count(), 1);
        assert_eq!(state.heads.len(), 1);
        assert!(state.heads.contains(genesis.hash()));
        assert_eq!(state.name, "Test Forum");
    }

    #[test]
    fn test_forum_state_add_node() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let added = state.add_node(DagNode::from(board.clone())).unwrap();
        assert!(added);
        assert_eq!(state.node_count(), 2);

        // Board should be the only head now
        assert_eq!(state.heads.len(), 1);
        assert!(state.heads.contains(board.hash()));

        // Adding same node again should return false
        let added_again = state.add_node(DagNode::from(board)).unwrap();
        assert!(!added_again);
    }

    #[test]
    fn test_forum_state_compute_missing() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        state.add_node(DagNode::from(board.clone())).unwrap();

        // Client with empty heads should get everything
        let missing = compute_missing(&state.nodes, &[]);
        assert_eq!(missing.len(), 2);

        // Client with genesis should only need board
        let missing = compute_missing(&state.nodes, &[*genesis.hash()]);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], *board.hash());

        // Client with board should need nothing
        let missing = compute_missing(&state.nodes, &[*board.hash()]);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_forum_relay_state() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);
        let hash = *genesis.hash();

        let mut relay = ForumRelayState::new();

        // Create forum
        let result = relay.create_forum(genesis.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), hash);

        // Should not be able to create duplicate
        let result = relay.create_forum(genesis);
        assert!(result.is_err());

        // Should be able to get forum
        assert!(relay.get_forum(&hash).is_some());
        assert_eq!(relay.forums.len(), 1);
    }

    #[test]
    fn test_forum_relay_add_node() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);
        let forum_hash = *genesis.hash();

        let mut relay = ForumRelayState::new();
        relay.create_forum(genesis.clone()).unwrap();

        let board = BoardGenesis::create(
            forum_hash,
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();

        let result = relay.add_node(&forum_hash, DagNode::from(board));
        assert!(result.is_ok());
        assert!(result.unwrap());

        assert_eq!(relay.total_nodes(), 2);
    }

    #[test]
    fn test_forum_state_accessors() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);
        let hash = *genesis.hash();

        let state = ForumState::from_genesis(&genesis);

        // Test get_node
        assert!(state.get_node(&hash).is_some());
        let fake_hash = ContentHash::from_bytes([0u8; 64]);
        assert!(state.get_node(&fake_hash).is_none());

        // Test has_node
        assert!(state.has_node(&hash));
        assert!(!state.has_node(&fake_hash));

        // Test iter_nodes
        assert_eq!(state.iter_nodes().count(), 1);
    }

    #[test]
    fn test_forum_relay_state_accessors() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);
        let hash = *genesis.hash();

        let mut relay = ForumRelayState::new();
        relay.create_forum(genesis).unwrap();

        // Test get_forum_mut
        assert!(relay.get_forum_mut(&hash).is_some());

        // Test forum_count
        assert_eq!(relay.forum_count(), 1);

        // Test forum_hashes
        let hashes: Vec<_> = relay.forum_hashes().collect();
        assert_eq!(hashes.len(), 1);
        assert_eq!(*hashes[0], hash);

        // Test remove_forum
        assert!(relay.remove_forum(&hash));
        assert_eq!(relay.forum_count(), 0);
        assert!(!relay.remove_forum(&hash)); // Already removed
    }

    #[test]
    fn test_get_effective_board_for_thread() {
        use crate::forum::ThreadRoot;

        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Create a board
        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board.clone())).unwrap();

        // Create a thread in that board
        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "Thread body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread.clone())).unwrap();

        // Effective board should be the original board
        let effective = state.get_effective_board_for_thread(thread.hash());
        assert_eq!(effective, Some(*board.hash()));

        // Non-existent thread should return None
        let fake_hash = ContentHash::from_bytes([0u8; 64]);
        assert!(state.get_effective_board_for_thread(&fake_hash).is_none());
    }

    #[test]
    fn test_get_effective_board_for_post() {
        use crate::forum::{Post, ThreadRoot};

        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Create a board
        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board.clone())).unwrap();

        // Create a thread in that board
        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "Thread body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread.clone())).unwrap();

        // Create a post in that thread
        let post = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Test post".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(post.clone())).unwrap();

        // Effective board for the post should be the original board
        let effective = state.get_effective_board_for_post(post.hash());
        assert_eq!(effective, Some(*board.hash()));
    }

    #[test]
    fn test_get_effective_board_generic() {
        use crate::forum::{Post, ThreadRoot};

        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Create a board
        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board.clone())).unwrap();

        // Create a thread
        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "Thread body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread.clone())).unwrap();

        // Create a post
        let post = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Test post".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(post.clone())).unwrap();

        // Test get_effective_board for each node type
        assert_eq!(state.get_effective_board(board.hash()), Some(*board.hash()));
        assert_eq!(
            state.get_effective_board(thread.hash()),
            Some(*board.hash())
        );
        assert_eq!(state.get_effective_board(post.hash()), Some(*board.hash()));

        // Forum genesis should return None (not a board/thread/post)
        assert!(state.get_effective_board(genesis.hash()).is_none());
    }

    #[test]
    fn test_get_effective_board_with_moved_thread() {
        use crate::forum::{ModActionNode, Post, ThreadRoot};

        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Create two boards
        let board1 = BoardGenesis::create(
            *genesis.hash(),
            "Board 1".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board1.clone())).unwrap();

        let board2 = BoardGenesis::create(
            *genesis.hash(),
            "Board 2".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board2.clone())).unwrap();

        // Create a thread in board1
        let thread = ThreadRoot::create(
            *board1.hash(),
            "Test Thread".to_string(),
            "Thread body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread.clone())).unwrap();

        // Create a post in that thread
        let post = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Test post".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(post.clone())).unwrap();

        // Initially, effective board is board1
        assert_eq!(
            state.get_effective_board_for_thread(thread.hash()),
            Some(*board1.hash())
        );
        assert_eq!(
            state.get_effective_board_for_post(post.hash()),
            Some(*board1.hash())
        );

        // Move the thread to board2
        let move_action = ModActionNode::create_move_thread_action(
            *genesis.hash(),
            *thread.hash(),
            *board2.hash(),
            keypair.public_key(),
            keypair.private_key(),
            None,
            vec![*post.hash()],
        )
        .unwrap();
        state.add_node(DagNode::from(move_action)).unwrap();

        // After move, effective board should be board2
        assert_eq!(
            state.get_effective_board_for_thread(thread.hash()),
            Some(*board2.hash())
        );
        assert_eq!(
            state.get_effective_board_for_post(post.hash()),
            Some(*board2.hash())
        );
        assert_eq!(
            state.get_effective_board(thread.hash()),
            Some(*board2.hash())
        );
        assert_eq!(state.get_effective_board(post.hash()), Some(*board2.hash()));
    }

    // ==========================================================================
    // Secondary Index Tests
    // ==========================================================================

    #[test]
    fn test_secondary_index_boards() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Initially no boards
        assert_eq!(state.get_boards().len(), 0);
        assert_eq!(state.board_count(), 0);

        // Create first board
        let board1 = BoardGenesis::create(
            *genesis.hash(),
            "Board 1".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board1.clone())).unwrap();

        assert_eq!(state.get_boards().len(), 1);
        assert_eq!(state.board_count(), 1);
        assert_eq!(state.get_boards()[0], *board1.hash());

        // Create second board
        let board2 = BoardGenesis::create(
            *genesis.hash(),
            "Board 2".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board2.clone())).unwrap();

        assert_eq!(state.get_boards().len(), 2);
        assert_eq!(state.board_count(), 2);
        assert!(state.get_boards().contains(board1.hash()));
        assert!(state.get_boards().contains(board2.hash()));
    }

    #[test]
    fn test_secondary_index_threads_in_board() {
        use crate::forum::ThreadRoot;

        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Create a board
        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board.clone())).unwrap();

        // Initially no threads
        assert_eq!(state.get_threads_in_board(board.hash()).len(), 0);
        assert_eq!(state.thread_count_in_board(board.hash()), 0);

        // Create first thread
        let thread1 = ThreadRoot::create(
            *board.hash(),
            "Thread 1".to_string(),
            "Body 1".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread1.clone())).unwrap();

        assert_eq!(state.get_threads_in_board(board.hash()).len(), 1);
        assert_eq!(state.thread_count_in_board(board.hash()), 1);
        assert_eq!(state.get_threads_in_board(board.hash())[0], *thread1.hash());

        // Create second thread
        let thread2 = ThreadRoot::create(
            *board.hash(),
            "Thread 2".to_string(),
            "Body 2".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread2.clone())).unwrap();

        assert_eq!(state.get_threads_in_board(board.hash()).len(), 2);
        assert_eq!(state.thread_count_in_board(board.hash()), 2);
        assert!(state
            .get_threads_in_board(board.hash())
            .contains(thread1.hash()));
        assert!(state
            .get_threads_in_board(board.hash())
            .contains(thread2.hash()));
    }

    #[test]
    fn test_secondary_index_posts_in_thread() {
        use crate::forum::{Post, ThreadRoot};

        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Create a board
        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board.clone())).unwrap();

        // Create a thread
        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "Body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread.clone())).unwrap();

        // Initially no posts
        assert_eq!(state.get_posts_in_thread(thread.hash()).len(), 0);
        assert_eq!(state.post_count_in_thread(thread.hash()), 0);

        // Create first post
        let post1 = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Post 1".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(post1.clone())).unwrap();

        assert_eq!(state.get_posts_in_thread(thread.hash()).len(), 1);
        assert_eq!(state.post_count_in_thread(thread.hash()), 1);
        assert_eq!(state.get_posts_in_thread(thread.hash())[0], *post1.hash());

        // Create second post
        let post2 = Post::create(
            *thread.hash(),
            vec![*post1.hash()],
            "Post 2".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(post2.clone())).unwrap();

        assert_eq!(state.get_posts_in_thread(thread.hash()).len(), 2);
        assert_eq!(state.post_count_in_thread(thread.hash()), 2);
        assert!(state
            .get_posts_in_thread(thread.hash())
            .contains(post1.hash()));
        assert!(state
            .get_posts_in_thread(thread.hash())
            .contains(post2.hash()));
    }

    #[test]
    fn test_secondary_index_nonexistent_lookups() {
        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);
        let state = ForumState::from_genesis(&genesis);

        let fake_hash = ContentHash::from_bytes([0u8; 64]);

        // Lookups on non-existent entities should return empty slices
        assert_eq!(state.get_threads_in_board(&fake_hash).len(), 0);
        assert_eq!(state.thread_count_in_board(&fake_hash), 0);
        assert_eq!(state.get_posts_in_thread(&fake_hash).len(), 0);
        assert_eq!(state.post_count_in_thread(&fake_hash), 0);
    }

    #[test]
    fn test_topological_cache() {
        use crate::forum::ThreadRoot;

        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Create a board
        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board.clone())).unwrap();

        // Create a thread
        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "Body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread.clone())).unwrap();

        // Get topological order - should build cache
        let order = state.get_topological_order();
        assert_eq!(order.len(), 3); // genesis, board, thread

        // Verify order: genesis first, then board, then thread
        assert_eq!(order[0], *genesis.hash());
        assert_eq!(order[1], *board.hash());
        assert_eq!(order[2], *thread.hash());

        // Test pagination
        let page = state.get_topological_page(0, 2);
        assert_eq!(page.len(), 2);

        let page = state.get_topological_page(1, 2);
        assert_eq!(page.len(), 2);

        let page = state.get_topological_page(2, 2);
        assert_eq!(page.len(), 1);
    }

    #[test]
    fn test_rebuild_permissions_rebuilds_indexes() {
        use crate::forum::{Post, ThreadRoot};

        let keypair = create_test_keypair();
        let genesis = create_test_forum(&keypair);

        let mut state = ForumState::from_genesis(&genesis);

        // Add content
        let board = BoardGenesis::create(
            *genesis.hash(),
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(board.clone())).unwrap();

        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "Body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(thread.clone())).unwrap();

        let post = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Test post".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .unwrap();
        state.add_node(DagNode::from(post.clone())).unwrap();

        // Verify indexes are populated
        assert_eq!(state.board_count(), 1);
        assert_eq!(state.thread_count_in_board(board.hash()), 1);
        assert_eq!(state.post_count_in_thread(thread.hash()), 1);

        // Rebuild permissions (which also rebuilds indexes)
        state.rebuild_permissions();

        // Verify indexes are still correct after rebuild
        assert_eq!(state.board_count(), 1);
        assert_eq!(state.thread_count_in_board(board.hash()), 1);
        assert_eq!(state.post_count_in_thread(thread.hash()), 1);
        assert!(state.get_boards().contains(board.hash()));
        assert!(state
            .get_threads_in_board(board.hash())
            .contains(thread.hash()));
        assert!(state
            .get_posts_in_thread(thread.hash())
            .contains(post.hash()));
    }
}
