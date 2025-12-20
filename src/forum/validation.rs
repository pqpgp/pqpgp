//! Validation rules for forum DAG nodes.
//!
//! This module validates nodes before they are accepted into the DAG:
//! - Signature verification
//! - Content hash verification
//! - Parent existence checks
//! - Permission checks
//! - Timestamp sanity checks
//!
//! Validation ensures DAG integrity and prevents invalid or malicious nodes
//! from being stored.

use crate::crypto::PublicKey;
use crate::error::{PqpgpError, Result};
use crate::forum::constants::{
    MAX_CLOCK_SKEW_MS, MAX_DESCRIPTION_SIZE, MAX_NAME_SIZE, MAX_PARENT_HASHES, MAX_POST_BODY_SIZE,
    MAX_THREAD_BODY_SIZE, MAX_THREAD_TITLE_SIZE, MIN_VALID_TIMESTAMP_MS,
};
use crate::forum::permissions::ForumPermissions;
use crate::forum::{
    BoardGenesis, ContentHash, DagNode, EditNode, EditType, ForumGenesis, ModAction, ModActionNode,
    NodeType, Post, ThreadRoot,
};
use std::collections::HashMap;

/// Context for validating nodes against the existing DAG state.
#[derive(Debug)]
pub struct ValidationContext<'a> {
    /// All nodes in the DAG, keyed by content hash.
    nodes: &'a HashMap<ContentHash, DagNode>,
    /// Permission states for each forum.
    permissions: &'a HashMap<ContentHash, ForumPermissions>,
    /// Current timestamp in milliseconds (for timestamp validation).
    current_time_ms: u64,
}

impl<'a> ValidationContext<'a> {
    /// Creates a new validation context.
    pub fn new(
        nodes: &'a HashMap<ContentHash, DagNode>,
        permissions: &'a HashMap<ContentHash, ForumPermissions>,
        current_time_ms: u64,
    ) -> Self {
        Self {
            nodes,
            permissions,
            current_time_ms,
        }
    }

    /// Checks if a node with the given hash exists in the DAG.
    pub fn node_exists(&self, hash: &ContentHash) -> bool {
        self.nodes.contains_key(hash)
    }

    /// Gets a node by its hash.
    pub fn get_node(&self, hash: &ContentHash) -> Option<&DagNode> {
        self.nodes.get(hash)
    }

    /// Gets permissions for a forum.
    pub fn get_permissions(&self, forum_hash: &ContentHash) -> Option<&ForumPermissions> {
        self.permissions.get(forum_hash)
    }
}

/// Result of validation containing detailed information.
#[derive(Debug)]
pub struct ValidationResult {
    /// Whether the node is valid.
    pub is_valid: bool,
    /// Validation errors, if any.
    pub errors: Vec<String>,
}

impl ValidationResult {
    /// Creates a successful validation result.
    pub fn ok() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
        }
    }

    /// Creates a failed validation result with errors.
    pub fn err(errors: Vec<String>) -> Self {
        Self {
            is_valid: false,
            errors,
        }
    }

    /// Adds an error to the result.
    pub fn add_error(&mut self, error: String) {
        self.is_valid = false;
        self.errors.push(error);
    }
}

/// Validates a forum genesis node.
///
/// Forum genesis nodes have no parent requirements but must have valid
/// signature and content hash.
pub fn validate_forum_genesis(forum: &ForumGenesis) -> Result<ValidationResult> {
    let mut result = ValidationResult::ok();

    // Validate content sizes
    if forum.name().len() > MAX_NAME_SIZE {
        result.add_error(format!(
            "Forum name too long: {} bytes (max {})",
            forum.name().len(),
            MAX_NAME_SIZE
        ));
    }
    if forum.description().len() > MAX_DESCRIPTION_SIZE {
        result.add_error(format!(
            "Forum description too long: {} bytes (max {})",
            forum.description().len(),
            MAX_DESCRIPTION_SIZE
        ));
    }

    // Validate timestamp is reasonable
    if forum.created_at() < MIN_VALID_TIMESTAMP_MS {
        result.add_error("Forum timestamp is unreasonably old or invalid".to_string());
    }

    // Reconstruct public key from stored identity, using key_id from signature
    let public_key =
        PublicKey::from_mldsa87_bytes_with_id(forum.creator_identity(), forum.signature.key_id)
            .map_err(|_| PqpgpError::validation("Invalid creator public key in forum genesis"))?;

    // Verify signature and content hash
    if let Err(e) = forum.verify(&public_key) {
        result.add_error(format!("Forum genesis verification failed: {}", e));
    }

    Ok(result)
}

/// Validates a board genesis node.
///
/// Board genesis nodes must:
/// - Have valid signature and content hash
/// - Reference an existing forum
/// - Be created by a moderator
/// - Have valid content sizes
pub fn validate_board_genesis(
    board: &BoardGenesis,
    ctx: &ValidationContext,
) -> Result<ValidationResult> {
    let mut result = ValidationResult::ok();

    // Validate content sizes
    if board.name().len() > MAX_NAME_SIZE {
        result.add_error(format!(
            "Board name too long: {} bytes (max {})",
            board.name().len(),
            MAX_NAME_SIZE
        ));
    }
    if board.description().len() > MAX_DESCRIPTION_SIZE {
        result.add_error(format!(
            "Board description too long: {} bytes (max {})",
            board.description().len(),
            MAX_DESCRIPTION_SIZE
        ));
    }

    // Validate timestamp is reasonable
    if board.created_at() < MIN_VALID_TIMESTAMP_MS {
        result.add_error("Board timestamp is unreasonably old or invalid".to_string());
    }

    // Verify parent forum exists
    let forum_hash = board.forum_hash();
    if !ctx.node_exists(forum_hash) {
        result.add_error("Board references non-existent forum".to_string());
        return Ok(result);
    }

    // Verify parent is actually a forum genesis
    if let Some(parent) = ctx.get_node(forum_hash) {
        if parent.node_type() != NodeType::ForumGenesis {
            result.add_error("Board parent is not a forum genesis".to_string());
        }
    }

    // Reconstruct public key, using key_id from signature
    let public_key =
        PublicKey::from_mldsa87_bytes_with_id(board.creator_identity(), board.signature.key_id)
            .map_err(|_| PqpgpError::validation("Invalid creator public key in board genesis"))?;

    // Verify signature and content hash
    if let Err(e) = board.verify(&public_key) {
        result.add_error(format!("Board genesis verification failed: {}", e));
    }

    // Check permissions
    if let Some(permissions) = ctx.get_permissions(forum_hash) {
        if !permissions.can_create_board(board.creator_identity()) {
            result.add_error("Board creator is not a moderator".to_string());
        }
    } else {
        result.add_error("No permission state found for forum".to_string());
    }

    // Validate timestamp not too far in the future
    if board.created_at() > ctx.current_time_ms + MAX_CLOCK_SKEW_MS {
        result.add_error("Board timestamp is too far in the future".to_string());
    }

    Ok(result)
}

/// Validates a thread root node.
///
/// Thread root nodes must:
/// - Have valid signature and content hash
/// - Reference an existing board
/// - Have valid content sizes
pub fn validate_thread_root(
    thread: &ThreadRoot,
    ctx: &ValidationContext,
) -> Result<ValidationResult> {
    let mut result = ValidationResult::ok();

    // Validate content sizes
    if thread.title().len() > MAX_THREAD_TITLE_SIZE {
        result.add_error(format!(
            "Thread title too long: {} bytes (max {})",
            thread.title().len(),
            MAX_THREAD_TITLE_SIZE
        ));
    }
    if thread.body().len() > MAX_THREAD_BODY_SIZE {
        result.add_error(format!(
            "Thread body too long: {} bytes (max {})",
            thread.body().len(),
            MAX_THREAD_BODY_SIZE
        ));
    }

    // Validate timestamp is reasonable
    if thread.created_at() < MIN_VALID_TIMESTAMP_MS {
        result.add_error("Thread timestamp is unreasonably old or invalid".to_string());
    }

    // Verify parent board exists
    let board_hash = thread.board_hash();
    if !ctx.node_exists(board_hash) {
        result.add_error("Thread references non-existent board".to_string());
        return Ok(result);
    }

    // Verify parent is actually a board genesis
    if let Some(parent) = ctx.get_node(board_hash) {
        if parent.node_type() != NodeType::BoardGenesis {
            result.add_error("Thread parent is not a board genesis".to_string());
        }
    }

    // Reconstruct public key, using key_id from signature
    let public_key =
        PublicKey::from_mldsa87_bytes_with_id(thread.author_identity(), thread.signature.key_id)
            .map_err(|_| PqpgpError::validation("Invalid author public key in thread root"))?;

    // Verify signature and content hash
    if let Err(e) = thread.verify(&public_key) {
        result.add_error(format!("Thread root verification failed: {}", e));
    }

    // Validate timestamp not too far in the future
    if thread.created_at() > ctx.current_time_ms + MAX_CLOCK_SKEW_MS {
        result.add_error("Thread timestamp is too far in the future".to_string());
    }

    // Timestamp should be >= parent's timestamp
    if let Some(parent) = ctx.get_node(board_hash) {
        if thread.created_at() < parent.created_at() {
            result.add_error("Thread timestamp is before parent board timestamp".to_string());
        }
    }

    Ok(result)
}

/// Validates a post node.
///
/// Post nodes must:
/// - Have valid signature and content hash
/// - Reference an existing thread
/// - Have all parent hashes exist and be valid types (Post or ThreadRoot)
/// - Have all parent posts belong to the same thread
/// - Have valid content sizes
pub fn validate_post(post: &Post, ctx: &ValidationContext) -> Result<ValidationResult> {
    let mut result = ValidationResult::ok();

    // Validate content sizes
    if post.body().len() > MAX_POST_BODY_SIZE {
        result.add_error(format!(
            "Post body too long: {} bytes (max {})",
            post.body().len(),
            MAX_POST_BODY_SIZE
        ));
    }

    // Validate parent hash count - too many
    if post.parent_hashes().len() > MAX_PARENT_HASHES {
        result.add_error(format!(
            "Too many parent hashes: {} (max {})",
            post.parent_hashes().len(),
            MAX_PARENT_HASHES
        ));
    }

    // SECURITY FIX: Require at least one parent hash to prevent orphaned subtrees
    // Posts must reference at least their thread root or another post in the thread
    // This ensures all posts are connected to the DAG through the thread root
    if post.parent_hashes().is_empty() {
        result.add_error(
            "Post must have at least one parent hash (thread root or parent post)".to_string(),
        );
    }

    // Validate timestamp is reasonable
    if post.created_at() < MIN_VALID_TIMESTAMP_MS {
        result.add_error("Post timestamp is unreasonably old or invalid".to_string());
    }

    // Verify thread exists
    let thread_hash = post.thread_hash();
    if !ctx.node_exists(thread_hash) {
        result.add_error("Post references non-existent thread".to_string());
        return Ok(result);
    }

    // Verify thread is actually a thread root
    if let Some(thread) = ctx.get_node(thread_hash) {
        if thread.node_type() != NodeType::ThreadRoot {
            result.add_error("Post thread reference is not a thread root".to_string());
        }
    }

    // Verify all parent hashes exist AND are valid types (Post or ThreadRoot) AND belong to same thread
    for parent_hash in post.parent_hashes() {
        if !ctx.node_exists(parent_hash) {
            result.add_error(format!(
                "Post references non-existent parent: {}",
                parent_hash.short()
            ));
            continue;
        }

        // Validate parent node type - must be Post or ThreadRoot
        if let Some(parent_node) = ctx.get_node(parent_hash) {
            match parent_node.node_type() {
                NodeType::Post => {
                    // Verify parent post belongs to the same thread
                    if let Some(parent_post) = parent_node.as_post() {
                        if parent_post.thread_hash() != thread_hash {
                            result.add_error(format!(
                                "Post parent {} is from a different thread",
                                parent_hash.short()
                            ));
                        }
                    }
                }
                NodeType::ThreadRoot => {
                    // Thread root as parent is valid, but must be THE thread this post belongs to
                    if parent_hash != thread_hash {
                        result.add_error(format!(
                            "Post parent {} is a ThreadRoot but not the post's own thread",
                            parent_hash.short()
                        ));
                    }
                }
                _ => {
                    result.add_error(format!(
                        "Post parent {} has invalid type {:?} (must be Post or ThreadRoot)",
                        parent_hash.short(),
                        parent_node.node_type()
                    ));
                }
            }
        }
    }

    // Verify quote hash exists if specified AND is a valid type AND belongs to same thread
    if let Some(quote_hash) = post.quote_hash() {
        if !ctx.node_exists(quote_hash) {
            result.add_error("Post quotes non-existent post".to_string());
        } else if let Some(quoted_node) = ctx.get_node(quote_hash) {
            // Quote must be a Post or ThreadRoot
            match quoted_node.node_type() {
                NodeType::Post => {
                    // Verify quoted post belongs to the same thread
                    if let Some(quoted_post) = quoted_node.as_post() {
                        if quoted_post.thread_hash() != thread_hash {
                            result.add_error(
                                "Post quotes a post from a different thread".to_string(),
                            );
                        }
                    }
                }
                NodeType::ThreadRoot => {
                    // Quoting the thread root is valid, but must be this thread
                    if quote_hash != thread_hash {
                        result.add_error(
                            "Post quotes a ThreadRoot from a different thread".to_string(),
                        );
                    }
                }
                _ => {
                    result.add_error(format!(
                        "Post quotes invalid node type {:?} (must be Post or ThreadRoot)",
                        quoted_node.node_type()
                    ));
                }
            }
        }
    }

    // Reconstruct public key, using key_id from signature
    let public_key =
        PublicKey::from_mldsa87_bytes_with_id(post.author_identity(), post.signature.key_id)
            .map_err(|_| PqpgpError::validation("Invalid author public key in post"))?;

    // Verify signature and content hash
    if let Err(e) = post.verify(&public_key) {
        result.add_error(format!("Post verification failed: {}", e));
    }

    // Validate timestamp not too far in the future
    if post.created_at() > ctx.current_time_ms + MAX_CLOCK_SKEW_MS {
        result.add_error("Post timestamp is too far in the future".to_string());
    }

    // Timestamp should be >= thread's timestamp
    if let Some(thread) = ctx.get_node(thread_hash) {
        if post.created_at() < thread.created_at() {
            result.add_error("Post timestamp is before thread timestamp".to_string());
        }
    }

    // SECURITY FIX: Validate timestamp monotonicity with parent posts
    // A post cannot have an earlier timestamp than any of its parent posts
    for parent_hash in post.parent_hashes() {
        if let Some(parent_node) = ctx.get_node(parent_hash) {
            if parent_node.node_type() == NodeType::Post {
                if let Some(parent_post) = parent_node.as_post() {
                    if post.created_at() < parent_post.created_at() {
                        result.add_error(format!(
                            "Post timestamp {} is before parent post timestamp {}",
                            post.created_at(),
                            parent_post.created_at()
                        ));
                    }
                }
            }
        }
    }

    Ok(result)
}

/// Validates a moderation action node.
///
/// Moderation action nodes must:
/// - Have valid signature and content hash
/// - Reference an existing forum
/// - Be issued by a user with appropriate permissions
/// - For content actions: reference an existing target node of the correct type
/// - For board actions: reference an existing board that belongs to the forum
pub fn validate_mod_action(
    action: &ModActionNode,
    ctx: &ValidationContext,
) -> Result<ValidationResult> {
    let mut result = ValidationResult::ok();

    // Validate timestamp is reasonable
    if action.created_at() < MIN_VALID_TIMESTAMP_MS {
        result.add_error("Moderation action timestamp is unreasonably old or invalid".to_string());
    }

    // Verify forum exists
    let forum_hash = action.forum_hash();
    if !ctx.node_exists(forum_hash) {
        result.add_error("Moderation action references non-existent forum".to_string());
        return Ok(result);
    }

    // Verify forum is actually a forum genesis
    if let Some(forum) = ctx.get_node(forum_hash) {
        if forum.node_type() != NodeType::ForumGenesis {
            result
                .add_error("Moderation action forum reference is not a forum genesis".to_string());
        }
    }

    // Verify all parent hashes exist (for causal ordering)
    for parent_hash in action.parent_hashes() {
        if !ctx.node_exists(parent_hash) {
            result.add_error(format!(
                "Moderation action references non-existent parent: {}",
                parent_hash.short()
            ));
        }
    }

    // Validate target node for content actions (HideThread/UnhideThread/HidePost/UnhidePost)
    match action.action() {
        ModAction::HideThread | ModAction::UnhideThread => {
            if let Some(target_hash) = action.target_node_hash() {
                if !ctx.node_exists(target_hash) {
                    result.add_error(format!(
                        "HideThread/UnhideThread target {} does not exist",
                        target_hash.short()
                    ));
                } else if let Some(target_node) = ctx.get_node(target_hash) {
                    if target_node.node_type() != NodeType::ThreadRoot {
                        result.add_error(format!(
                            "HideThread/UnhideThread target {} is not a ThreadRoot (got {:?})",
                            target_hash.short(),
                            target_node.node_type()
                        ));
                    }
                }
            } else {
                result.add_error(
                    "HideThread/UnhideThread action missing target_node_hash".to_string(),
                );
            }
        }
        ModAction::HidePost | ModAction::UnhidePost => {
            if let Some(target_hash) = action.target_node_hash() {
                if !ctx.node_exists(target_hash) {
                    result.add_error(format!(
                        "HidePost/UnhidePost target {} does not exist",
                        target_hash.short()
                    ));
                } else if let Some(target_node) = ctx.get_node(target_hash) {
                    if target_node.node_type() != NodeType::Post {
                        result.add_error(format!(
                            "HidePost/UnhidePost target {} is not a Post (got {:?})",
                            target_hash.short(),
                            target_node.node_type()
                        ));
                    }
                }
            } else {
                result.add_error("HidePost/UnhidePost action missing target_node_hash".to_string());
            }
        }
        ModAction::AddBoardModerator
        | ModAction::RemoveBoardModerator
        | ModAction::HideBoard
        | ModAction::UnhideBoard => {
            // Board actions require board_hash
            if let Some(board_hash) = action.board_hash() {
                if !ctx.node_exists(board_hash) {
                    result.add_error(format!(
                        "Board action target {} does not exist",
                        board_hash.short()
                    ));
                } else if let Some(board_node) = ctx.get_node(board_hash) {
                    if board_node.node_type() != NodeType::BoardGenesis {
                        result.add_error(format!(
                            "Board action target {} is not a BoardGenesis (got {:?})",
                            board_hash.short(),
                            board_node.node_type()
                        ));
                    } else if let Some(board) = board_node.as_board_genesis() {
                        // Verify board belongs to this forum
                        if board.forum_hash() != forum_hash {
                            result.add_error(format!(
                                "Board {} does not belong to forum {}",
                                board_hash.short(),
                                forum_hash.short()
                            ));
                        }
                    }
                }
            } else {
                result.add_error("Board moderation action missing board_hash".to_string());
            }
        }
        ModAction::MoveThread => {
            // MoveThread requires both target_node_hash (thread) and board_hash (destination)
            // Validate thread exists and is a ThreadRoot
            if let Some(thread_hash) = action.target_node_hash() {
                if !ctx.node_exists(thread_hash) {
                    result.add_error(format!(
                        "MoveThread target thread {} does not exist",
                        thread_hash.short()
                    ));
                } else if let Some(thread_node) = ctx.get_node(thread_hash) {
                    if thread_node.node_type() != NodeType::ThreadRoot {
                        result.add_error(format!(
                            "MoveThread target {} is not a ThreadRoot (got {:?})",
                            thread_hash.short(),
                            thread_node.node_type()
                        ));
                    } else if let Some(thread) = thread_node.as_thread_root() {
                        // Get thread's original board and verify it belongs to this forum
                        let original_board_hash = thread.board_hash();
                        if let Some(board_node) = ctx.get_node(original_board_hash) {
                            if let Some(board) = board_node.as_board_genesis() {
                                if board.forum_hash() != forum_hash {
                                    result.add_error(format!(
                                        "Thread {} does not belong to forum {}",
                                        thread_hash.short(),
                                        forum_hash.short()
                                    ));
                                }
                            }
                        }
                    }
                }
            } else {
                result.add_error(
                    "MoveThread action missing target_node_hash (thread to move)".to_string(),
                );
            }

            // Validate destination board exists, is a BoardGenesis, and belongs to this forum
            if let Some(dest_board_hash) = action.board_hash() {
                if !ctx.node_exists(dest_board_hash) {
                    result.add_error(format!(
                        "MoveThread destination board {} does not exist",
                        dest_board_hash.short()
                    ));
                } else if let Some(board_node) = ctx.get_node(dest_board_hash) {
                    if board_node.node_type() != NodeType::BoardGenesis {
                        result.add_error(format!(
                            "MoveThread destination {} is not a BoardGenesis (got {:?})",
                            dest_board_hash.short(),
                            board_node.node_type()
                        ));
                    } else if let Some(board) = board_node.as_board_genesis() {
                        // Verify destination board belongs to this forum
                        if board.forum_hash() != forum_hash {
                            result.add_error(format!(
                                "Destination board {} does not belong to forum {}",
                                dest_board_hash.short(),
                                forum_hash.short()
                            ));
                        }
                    }
                }
            } else {
                result.add_error(
                    "MoveThread action missing board_hash (destination board)".to_string(),
                );
            }
        }
        ModAction::AddModerator | ModAction::RemoveModerator => {
            // Forum-level actions don't need additional target validation
        }
    }

    // Reconstruct public key, using key_id from signature
    let public_key =
        PublicKey::from_mldsa87_bytes_with_id(action.issuer_identity(), action.signature.key_id)
            .map_err(|_| {
                PqpgpError::validation("Invalid issuer public key in moderation action")
            })?;

    // Verify signature and content hash
    if let Err(e) = action.verify(&public_key) {
        result.add_error(format!("Moderation action verification failed: {}", e));
    }

    // Check permissions based on action type
    if let Some(permissions) = ctx.get_permissions(forum_hash) {
        let issuer = action.issuer_identity();
        let has_permission = match action.action() {
            // Forum-level moderator actions require owner
            ModAction::AddModerator | ModAction::RemoveModerator => {
                permissions.can_moderate(issuer)
            }
            // Board-level actions, content actions, and move thread require owner or forum moderator
            ModAction::AddBoardModerator
            | ModAction::RemoveBoardModerator
            | ModAction::HideThread
            | ModAction::UnhideThread
            | ModAction::HidePost
            | ModAction::UnhidePost
            | ModAction::HideBoard
            | ModAction::UnhideBoard
            | ModAction::MoveThread => permissions.can_manage_board_moderators(issuer),
        };
        if !has_permission {
            result.add_error(format!(
                "Insufficient permissions to issue {:?} action",
                action.action()
            ));
        }
    } else {
        result.add_error("No permission state found for forum".to_string());
    }

    // Validate timestamp not too far in the future
    if action.created_at() > ctx.current_time_ms + MAX_CLOCK_SKEW_MS {
        result.add_error("Moderation action timestamp is too far in the future".to_string());
    }

    // SECURITY FIX: Validate timestamp monotonicity with target nodes
    // A moderation action cannot have an earlier timestamp than the nodes it targets
    // This prevents backdated moderation actions that could cause replay inconsistencies
    if let Some(target_hash) = action.target_node_hash() {
        if let Some(target_node) = ctx.get_node(target_hash) {
            if action.created_at() < target_node.created_at() {
                result.add_error(format!(
                    "Moderation action timestamp {} is before target node timestamp {}",
                    action.created_at(),
                    target_node.created_at()
                ));
            }
        }
    }

    // Also validate timestamp against board_hash target for board actions
    if let Some(board_hash) = action.board_hash() {
        if let Some(board_node) = ctx.get_node(board_hash) {
            if action.created_at() < board_node.created_at() {
                result.add_error(format!(
                    "Moderation action timestamp {} is before target board timestamp {}",
                    action.created_at(),
                    board_node.created_at()
                ));
            }
        }
    }

    // Validate timestamp monotonicity with parent nodes (causal ordering)
    for parent_hash in action.parent_hashes() {
        if let Some(parent_node) = ctx.get_node(parent_hash) {
            if action.created_at() < parent_node.created_at() {
                result.add_error(format!(
                    "Moderation action timestamp {} is before parent node timestamp {}",
                    action.created_at(),
                    parent_node.created_at()
                ));
            }
        }
    }

    Ok(result)
}

/// Validates an edit node.
///
/// Edit nodes must:
/// - Have valid signature and content hash
/// - Reference an existing forum
/// - For EditForum: Be issued by the forum owner only
/// - For EditBoard: Be issued by the forum owner or a forum moderator
/// - Reference an existing target (forum or board)
/// - Have valid content sizes
pub fn validate_edit(edit: &EditNode, ctx: &ValidationContext) -> Result<ValidationResult> {
    let mut result = ValidationResult::ok();

    // Validate timestamp is reasonable
    if edit.created_at() < MIN_VALID_TIMESTAMP_MS {
        result.add_error("Edit timestamp is unreasonably old or invalid".to_string());
    }

    // Validate content sizes (if present)
    if let Some(name) = edit.new_name() {
        if name.len() > MAX_NAME_SIZE {
            result.add_error(format!(
                "Edit new_name too long: {} bytes (max {})",
                name.len(),
                MAX_NAME_SIZE
            ));
        }
    }
    if let Some(desc) = edit.new_description() {
        if desc.len() > MAX_DESCRIPTION_SIZE {
            result.add_error(format!(
                "Edit new_description too long: {} bytes (max {})",
                desc.len(),
                MAX_DESCRIPTION_SIZE
            ));
        }
    }

    // Verify forum exists
    let forum_hash = edit.forum_hash();
    if !ctx.node_exists(forum_hash) {
        result.add_error("Edit references non-existent forum".to_string());
        return Ok(result);
    }

    // Verify forum is actually a forum genesis
    if let Some(forum) = ctx.get_node(forum_hash) {
        if forum.node_type() != NodeType::ForumGenesis {
            result.add_error("Edit forum reference is not a forum genesis".to_string());
        }
    }

    // Verify target exists and matches the edit type
    let target_hash = edit.target_hash();
    if !ctx.node_exists(target_hash) {
        result.add_error("Edit references non-existent target".to_string());
        return Ok(result);
    }

    // Validate target type matches edit type
    if let Some(target) = ctx.get_node(target_hash) {
        match edit.edit_type() {
            EditType::EditForum => {
                if target.node_type() != NodeType::ForumGenesis {
                    result.add_error("EditForum target is not a forum genesis".to_string());
                }
                // For forum edits, target must be the forum itself
                if target_hash != forum_hash {
                    result.add_error("EditForum target hash must match forum hash".to_string());
                }
            }
            EditType::EditBoard => {
                if target.node_type() != NodeType::BoardGenesis {
                    result.add_error("EditBoard target is not a board genesis".to_string());
                }
                // Verify the board belongs to this forum
                if let Some(board) = target.as_board_genesis() {
                    if board.forum_hash() != forum_hash {
                        result.add_error(
                            "EditBoard target board does not belong to this forum".to_string(),
                        );
                    }
                }
            }
        }
    }

    // Reconstruct public key, using key_id from signature
    let public_key =
        PublicKey::from_mldsa87_bytes_with_id(edit.editor_identity(), edit.signature.key_id)
            .map_err(|_| PqpgpError::validation("Invalid editor public key in edit node"))?;

    // Verify signature and content hash
    if let Err(e) = edit.verify(&public_key) {
        result.add_error(format!("Edit node verification failed: {}", e));
    }

    // Check permissions based on edit type
    if let Some(permissions) = ctx.get_permissions(forum_hash) {
        let editor = edit.editor_identity();
        let has_permission = match edit.edit_type() {
            // Forum edits require owner only
            EditType::EditForum => permissions.can_moderate(editor),
            // Board edits require owner or forum moderator
            EditType::EditBoard => permissions.can_manage_board_moderators(editor),
        };
        if !has_permission {
            result.add_error(format!(
                "Insufficient permissions to issue {:?} edit",
                edit.edit_type()
            ));
        }
    } else {
        result.add_error("No permission state found for forum".to_string());
    }

    // Validate timestamp not too far in the future
    if edit.created_at() > ctx.current_time_ms + MAX_CLOCK_SKEW_MS {
        result.add_error("Edit timestamp is too far in the future".to_string());
    }

    // SECURITY FIX: Validate timestamp monotonicity with target node
    // An edit cannot have an earlier timestamp than the node it modifies
    // This prevents backdated edits that could cause replay inconsistencies
    if let Some(target_node) = ctx.get_node(target_hash) {
        if edit.created_at() < target_node.created_at() {
            result.add_error(format!(
                "Edit timestamp {} is before target node timestamp {}",
                edit.created_at(),
                target_node.created_at()
            ));
        }
    }

    Ok(result)
}

/// Validates any DAG node.
///
/// This is the main entry point for validation. It dispatches to the
/// appropriate validator based on node type.
pub fn validate_node(node: &DagNode, ctx: &ValidationContext) -> Result<ValidationResult> {
    match node {
        DagNode::ForumGenesis(forum) => validate_forum_genesis(forum),
        DagNode::BoardGenesis(board) => validate_board_genesis(board, ctx),
        DagNode::ThreadRoot(thread) => validate_thread_root(thread, ctx),
        DagNode::Post(post) => validate_post(post, ctx),
        DagNode::ModAction(action) => validate_mod_action(action, ctx),
        DagNode::Edit(edit) => validate_edit(edit, ctx),
        DagNode::EncryptionIdentity(identity) => validate_encryption_identity(identity, ctx),
        DagNode::SealedPrivateMessage(message) => validate_sealed_private_message(message, ctx),
    }
}

/// Validates an encryption identity node.
///
/// Checks:
/// - Content hash matches
/// - Signature is valid
/// - Forum exists
/// - ML-KEM key sizes are valid
fn validate_encryption_identity(
    identity: &crate::forum::EncryptionIdentity,
    ctx: &ValidationContext,
) -> Result<ValidationResult> {
    let mut result = ValidationResult::ok();

    // Reconstruct public key using key_id from the signature
    let public_key = PublicKey::from_mldsa87_bytes_with_id(
        identity.owner_signing_key(),
        identity.signature.key_id,
    )
    .map_err(|_| PqpgpError::validation("Invalid owner public key in EncryptionIdentity"))?;

    // Verify the node (hash and signature)
    if let Err(e) = identity.verify(&public_key) {
        result.add_error(format!("EncryptionIdentity verification failed: {}", e));
        return Ok(result);
    }

    // Verify forum exists
    let forum_hash = identity.forum_hash();
    if !ctx.node_exists(forum_hash) {
        result.add_error(format!("Forum {} does not exist", forum_hash.short()));
    }

    // Timestamp validation
    let timestamp_ms = identity.created_at();
    if timestamp_ms < MIN_VALID_TIMESTAMP_MS {
        result.add_error("EncryptionIdentity timestamp is unreasonably old or invalid".to_string());
    }
    if timestamp_ms > ctx.current_time_ms + MAX_CLOCK_SKEW_MS {
        result.add_error("EncryptionIdentity timestamp is too far in the future".to_string());
    }

    Ok(result)
}

/// Validates a sealed private message node.
///
/// Checks:
/// - Content hash matches
/// - Payload size is within limits
/// - Forum exists
/// - Timestamp is reasonable
///
/// Note: We cannot validate encrypted content - only the recipient can do that.
fn validate_sealed_private_message(
    message: &crate::forum::SealedPrivateMessage,
    ctx: &ValidationContext,
) -> Result<ValidationResult> {
    let mut result = ValidationResult::ok();

    // Verify hash
    if let Err(e) = message.verify_hash() {
        result.add_error(format!(
            "SealedPrivateMessage hash verification failed: {}",
            e
        ));
        return Ok(result);
    }

    // Verify forum exists
    let forum_hash = message.forum_hash();
    if !ctx.node_exists(forum_hash) {
        result.add_error(format!("Forum {} does not exist", forum_hash.short()));
    }

    // Timestamp validation
    let timestamp_ms = message.created_at();
    if timestamp_ms < MIN_VALID_TIMESTAMP_MS {
        result
            .add_error("SealedPrivateMessage timestamp is unreasonably old or invalid".to_string());
    }
    if timestamp_ms > ctx.current_time_ms + MAX_CLOCK_SKEW_MS {
        result.add_error("SealedPrivateMessage timestamp is too far in the future".to_string());
    }

    Ok(result)
}

/// Validates content size limits for a node.
///
/// This is a quick validation that checks content sizes without verifying
/// signatures or parent existence. Useful for early rejection of obviously
/// invalid nodes.
///
/// Returns an error message if any content exceeds limits, or None if valid.
pub fn validate_content_limits(node: &DagNode) -> Option<String> {
    match node {
        DagNode::ForumGenesis(forum) => {
            if forum.name().len() > MAX_NAME_SIZE {
                return Some(format!(
                    "Forum name exceeds maximum length of {} bytes",
                    MAX_NAME_SIZE
                ));
            }
            if forum.description().len() > MAX_DESCRIPTION_SIZE {
                return Some(format!(
                    "Forum description exceeds maximum length of {} bytes",
                    MAX_DESCRIPTION_SIZE
                ));
            }
            if forum.created_at() < MIN_VALID_TIMESTAMP_MS {
                return Some("Forum timestamp is unreasonably old".to_string());
            }
        }
        DagNode::BoardGenesis(board) => {
            if board.name().len() > MAX_NAME_SIZE {
                return Some(format!(
                    "Board name exceeds maximum length of {} bytes",
                    MAX_NAME_SIZE
                ));
            }
            if board.description().len() > MAX_DESCRIPTION_SIZE {
                return Some(format!(
                    "Board description exceeds maximum length of {} bytes",
                    MAX_DESCRIPTION_SIZE
                ));
            }
            if board.created_at() < MIN_VALID_TIMESTAMP_MS {
                return Some("Board timestamp is unreasonably old".to_string());
            }
        }
        DagNode::ThreadRoot(thread) => {
            if thread.title().len() > MAX_THREAD_TITLE_SIZE {
                return Some(format!(
                    "Thread title exceeds maximum length of {} bytes",
                    MAX_THREAD_TITLE_SIZE
                ));
            }
            if thread.body().len() > MAX_THREAD_BODY_SIZE {
                return Some(format!(
                    "Thread body exceeds maximum length of {} bytes",
                    MAX_THREAD_BODY_SIZE
                ));
            }
            if thread.created_at() < MIN_VALID_TIMESTAMP_MS {
                return Some("Thread timestamp is unreasonably old".to_string());
            }
        }
        DagNode::Post(post) => {
            if post.body().len() > MAX_POST_BODY_SIZE {
                return Some(format!(
                    "Post body exceeds maximum length of {} bytes",
                    MAX_POST_BODY_SIZE
                ));
            }
            if post.created_at() < MIN_VALID_TIMESTAMP_MS {
                return Some("Post timestamp is unreasonably old".to_string());
            }
        }
        DagNode::ModAction(action) => {
            if action.created_at() < MIN_VALID_TIMESTAMP_MS {
                return Some("Mod action timestamp is unreasonably old".to_string());
            }
        }
        DagNode::Edit(edit) => {
            if let Some(name) = edit.new_name() {
                if name.len() > MAX_NAME_SIZE {
                    return Some(format!(
                        "Edit name exceeds maximum length of {} bytes",
                        MAX_NAME_SIZE
                    ));
                }
            }
            if let Some(desc) = edit.new_description() {
                if desc.len() > MAX_DESCRIPTION_SIZE {
                    return Some(format!(
                        "Edit description exceeds maximum length of {} bytes",
                        MAX_DESCRIPTION_SIZE
                    ));
                }
            }
            if edit.created_at() < MIN_VALID_TIMESTAMP_MS {
                return Some("Edit timestamp is unreasonably old".to_string());
            }
        }
        DagNode::EncryptionIdentity(identity) => {
            if identity.content.created_at < MIN_VALID_TIMESTAMP_MS {
                return Some("Encryption identity timestamp is unreasonably old".to_string());
            }
        }
        DagNode::SealedPrivateMessage(sealed) => {
            if sealed.content.created_at < MIN_VALID_TIMESTAMP_MS {
                return Some("Sealed message timestamp is unreasonably old".to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::forum::{types::current_timestamp_millis, ModAction};

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
    fn test_validate_forum_genesis() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let result = validate_forum_genesis(&forum).unwrap();
        assert!(result.is_valid, "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_board_genesis() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let board = BoardGenesis::create(
            *forum.hash(),
            "Test Board".to_string(),
            "A test board".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board");

        let mut nodes = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));

        let mut permissions = HashMap::new();
        permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

        let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());
        let result = validate_board_genesis(&board, &ctx).unwrap();
        assert!(result.is_valid, "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_board_non_moderator() {
        let owner_keypair = create_test_keypair();
        let other_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        // Non-moderator tries to create board
        let board = BoardGenesis::create(
            *forum.hash(),
            "Test Board".to_string(),
            "A test board".to_string(),
            other_keypair.public_key(),
            other_keypair.private_key(),
            None,
        )
        .expect("Failed to create board");

        let mut nodes = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));

        let mut permissions = HashMap::new();
        permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

        let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());
        let result = validate_board_genesis(&board, &ctx).unwrap();
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.contains("not a moderator")));
    }

    #[test]
    fn test_validate_thread_root() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let board = BoardGenesis::create(
            *forum.hash(),
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board");

        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "Thread body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create thread");

        let mut nodes = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
        nodes.insert(*board.hash(), DagNode::from(board));

        let mut permissions = HashMap::new();
        permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

        let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());
        let result = validate_thread_root(&thread, &ctx).unwrap();
        assert!(result.is_valid, "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_post() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let board = BoardGenesis::create(
            *forum.hash(),
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board");

        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create thread");

        let post = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Test post body".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create post");

        let mut nodes = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
        nodes.insert(*board.hash(), DagNode::from(board));
        nodes.insert(*thread.hash(), DagNode::from(thread));

        let mut permissions = HashMap::new();
        permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

        let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());
        let result = validate_post(&post, &ctx).unwrap();
        assert!(result.is_valid, "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_post_missing_parent() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);
        let board = BoardGenesis::create(
            *forum.hash(),
            "Test Board".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board");

        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create thread");

        // Create post referencing non-existent parent
        let fake_parent = ContentHash::from_bytes([99u8; 64]);
        let post = Post::create(
            *thread.hash(),
            vec![fake_parent],
            "Test post body".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create post");

        let mut nodes = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));
        nodes.insert(*board.hash(), DagNode::from(board));
        nodes.insert(*thread.hash(), DagNode::from(thread));

        let mut permissions = HashMap::new();
        permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

        let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());
        let result = validate_post(&post, &ctx).unwrap();
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("non-existent parent")));
    }

    #[test]
    fn test_validate_mod_action() {
        let owner_keypair = create_test_keypair();
        let target_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            target_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()], // Reference forum as parent
        )
        .expect("Failed to create action");

        let mut nodes = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));

        let mut permissions = HashMap::new();
        permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

        let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());
        let result = validate_mod_action(&action, &ctx).unwrap();
        assert!(result.is_valid, "Errors: {:?}", result.errors);
    }

    #[test]
    fn test_validate_mod_action_non_owner() {
        let owner_keypair = create_test_keypair();
        let other_keypair = create_test_keypair();
        let target_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        // Non-owner tries to add moderator
        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            target_keypair.public_key(),
            other_keypair.public_key(),
            other_keypair.private_key(),
            None,
            vec![*forum.hash()], // Reference forum as parent
        )
        .expect("Failed to create action");

        let mut nodes = HashMap::new();
        nodes.insert(*forum.hash(), DagNode::from(forum.clone()));

        let mut permissions = HashMap::new();
        permissions.insert(*forum.hash(), ForumPermissions::from_genesis(&forum));

        let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());
        let result = validate_mod_action(&action, &ctx).unwrap();
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("Insufficient permissions")),
            "Expected 'Insufficient permissions' error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_validate_node_dispatch() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let nodes = HashMap::new();
        let permissions = HashMap::new();
        let ctx = ValidationContext::new(&nodes, &permissions, current_timestamp_millis());

        let dag_node = DagNode::from(forum);
        let result = validate_node(&dag_node, &ctx).unwrap();
        assert!(result.is_valid, "Errors: {:?}", result.errors);
    }
}
