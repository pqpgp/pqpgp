//! Permission management for the forum DAG system.
//!
//! This module handles:
//! - Resolving the current set of moderators by replaying moderation actions
//! - Checking permissions for various operations
//!
//! The permission model is:
//! - **Forum Owner**: Creator of the forum genesis, can add/remove forum and board moderators
//! - **Forum Moderator**: Can create boards, can add/remove board moderators for boards they create
//! - **Board Moderator**: Can only moderate threads within their assigned board
//! - **Member**: Any authenticated user, can create threads and posts

use crate::crypto::TimingSafe;
use crate::error::{PqpgpError, Result};
use crate::forum::{ContentHash, DagNode, ForumGenesis, ModAction, ModActionNode};
use std::collections::{HashMap, HashSet};

/// Represents the permission state of a forum at a point in time.
///
/// This is computed by replaying all moderation actions from the forum genesis.
#[derive(Debug, Clone)]
pub struct ForumPermissions {
    /// The forum this permission state applies to.
    forum_hash: ContentHash,
    /// The forum owner's identity (creator of forum genesis).
    owner_identity: Vec<u8>,
    /// Set of forum-level moderator identities (public key bytes).
    /// Forum moderators can moderate all boards.
    moderators: HashSet<Vec<u8>>,
    /// Board-level moderators, keyed by board hash.
    /// Board moderators can only moderate within their assigned board.
    board_moderators: HashMap<ContentHash, HashSet<Vec<u8>>>,
    /// Set of hidden board hashes.
    hidden_boards: HashSet<ContentHash>,
    /// Set of hidden thread hashes.
    hidden_threads: HashSet<ContentHash>,
    /// Set of hidden post hashes.
    hidden_posts: HashSet<ContentHash>,
    /// Thread moves: maps thread hash to current board hash.
    /// If a thread has been moved, this contains its new location.
    /// The original board in ThreadRoot is the source; this tracks the destination.
    moved_threads: HashMap<ContentHash, ContentHash>,
}

impl ForumPermissions {
    /// Creates a new permission state from a forum genesis.
    ///
    /// The forum owner is automatically the first moderator.
    pub fn from_genesis(forum: &ForumGenesis) -> Self {
        let owner_identity = forum.creator_identity().to_vec();
        let mut moderators = HashSet::new();
        // Owner is implicitly a moderator
        moderators.insert(owner_identity.clone());

        Self {
            forum_hash: *forum.hash(),
            owner_identity,
            moderators,
            board_moderators: HashMap::new(),
            hidden_boards: HashSet::new(),
            hidden_threads: HashSet::new(),
            hidden_posts: HashSet::new(),
            moved_threads: HashMap::new(),
        }
    }

    /// Applies a moderation action to update the permission state.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The action is for a different forum
    /// - The issuer doesn't have permission (owner for forum-level, owner/mod for board-level)
    pub fn apply_action(&mut self, action: &ModActionNode) -> Result<()> {
        // Verify action is for this forum
        if action.forum_hash() != &self.forum_hash {
            return Err(PqpgpError::validation(
                "Moderation action is for a different forum",
            ));
        }

        // SECURITY: Use constant-time comparison for all identity checks
        let issuer = action.issuer_identity();
        let is_owner = self.is_owner(issuer);
        let is_mod = self.is_moderator(issuer);

        match action.action() {
            ModAction::AddModerator => {
                // Only owner can add forum-level moderators
                if !is_owner {
                    return Err(PqpgpError::validation(
                        "Only the forum owner can add forum-level moderators",
                    ));
                }
                self.moderators.insert(action.target_identity().to_vec());
            }
            ModAction::RemoveModerator => {
                // Only owner can remove forum-level moderators
                if !is_owner {
                    return Err(PqpgpError::validation(
                        "Only the forum owner can remove forum-level moderators",
                    ));
                }
                let target = action.target_identity().to_vec();
                // Cannot remove the owner as moderator (use constant-time comparison)
                if TimingSafe::identity_equal(&target, &self.owner_identity) {
                    return Err(PqpgpError::validation(
                        "Cannot remove the forum owner as moderator",
                    ));
                }
                self.moderators.remove(&target);
            }
            ModAction::AddBoardModerator => {
                let board_hash = action.board_hash().ok_or_else(|| {
                    PqpgpError::validation("AddBoardModerator requires a board hash")
                })?;
                // Owner or forum-level moderator can add board moderators
                if !is_owner && !is_mod {
                    return Err(PqpgpError::validation(
                        "Only the forum owner or moderators can add board moderators",
                    ));
                }
                self.board_moderators
                    .entry(*board_hash)
                    .or_default()
                    .insert(action.target_identity().to_vec());
            }
            ModAction::RemoveBoardModerator => {
                let board_hash = action.board_hash().ok_or_else(|| {
                    PqpgpError::validation("RemoveBoardModerator requires a board hash")
                })?;
                // Owner or forum-level moderator can remove board moderators
                if !is_owner && !is_mod {
                    return Err(PqpgpError::validation(
                        "Only the forum owner or moderators can remove board moderators",
                    ));
                }
                if let Some(board_mods) = self.board_moderators.get_mut(board_hash) {
                    board_mods.remove(action.target_identity());
                }
            }
            ModAction::HideThread => {
                let target_hash = action.target_node_hash().ok_or_else(|| {
                    PqpgpError::validation("HideThread requires a target node hash")
                })?;
                // Owner or forum-level moderator can hide threads
                // Note: Authors can also hide their own content, but that's checked at a higher level
                if !is_owner && !is_mod {
                    return Err(PqpgpError::validation(
                        "Only the forum owner, moderators, or the author can hide threads",
                    ));
                }
                self.hidden_threads.insert(*target_hash);
            }
            ModAction::UnhideThread => {
                let target_hash = action.target_node_hash().ok_or_else(|| {
                    PqpgpError::validation("UnhideThread requires a target node hash")
                })?;
                // Owner or forum-level moderator can unhide threads
                if !is_owner && !is_mod {
                    return Err(PqpgpError::validation(
                        "Only the forum owner or moderators can unhide threads",
                    ));
                }
                self.hidden_threads.remove(target_hash);
            }
            ModAction::HidePost => {
                let target_hash = action.target_node_hash().ok_or_else(|| {
                    PqpgpError::validation("HidePost requires a target node hash")
                })?;
                // Owner or forum-level moderator can hide posts
                if !is_owner && !is_mod {
                    return Err(PqpgpError::validation(
                        "Only the forum owner, moderators, or the author can hide posts",
                    ));
                }
                self.hidden_posts.insert(*target_hash);
            }
            ModAction::UnhidePost => {
                let target_hash = action.target_node_hash().ok_or_else(|| {
                    PqpgpError::validation("UnhidePost requires a target node hash")
                })?;
                // Owner or forum-level moderator can unhide posts
                if !is_owner && !is_mod {
                    return Err(PqpgpError::validation(
                        "Only the forum owner or moderators can unhide posts",
                    ));
                }
                self.hidden_posts.remove(target_hash);
            }
            ModAction::HideBoard => {
                let board_hash = action
                    .board_hash()
                    .ok_or_else(|| PqpgpError::validation("HideBoard requires a board hash"))?;
                // Owner or forum-level moderator can hide boards
                if !is_owner && !is_mod {
                    return Err(PqpgpError::validation(
                        "Only the forum owner or moderators can hide boards",
                    ));
                }
                self.hidden_boards.insert(*board_hash);
            }
            ModAction::UnhideBoard => {
                let board_hash = action
                    .board_hash()
                    .ok_or_else(|| PqpgpError::validation("UnhideBoard requires a board hash"))?;
                // Owner or forum-level moderator can unhide boards
                if !is_owner && !is_mod {
                    return Err(PqpgpError::validation(
                        "Only the forum owner or moderators can unhide boards",
                    ));
                }
                self.hidden_boards.remove(board_hash);
            }
            ModAction::MoveThread => {
                let thread_hash = action.target_node_hash().ok_or_else(|| {
                    PqpgpError::validation("MoveThread requires a target thread hash")
                })?;
                let dest_board_hash = action.board_hash().ok_or_else(|| {
                    PqpgpError::validation("MoveThread requires a destination board hash")
                })?;
                // Owner or forum-level moderator can move threads
                if !is_owner && !is_mod {
                    return Err(PqpgpError::validation(
                        "Only the forum owner or moderators can move threads",
                    ));
                }
                self.moved_threads.insert(*thread_hash, *dest_board_hash);
            }
        }

        Ok(())
    }

    /// Returns the forum hash this permission state applies to.
    pub fn forum_hash(&self) -> &ContentHash {
        &self.forum_hash
    }

    /// Returns the forum owner's identity.
    pub fn owner_identity(&self) -> &[u8] {
        &self.owner_identity
    }

    /// Returns true if the given identity is the forum owner.
    ///
    /// SECURITY: Uses constant-time comparison to prevent timing attacks
    /// that could reveal identity information.
    pub fn is_owner(&self, identity: &[u8]) -> bool {
        TimingSafe::identity_equal(&self.owner_identity, identity)
    }

    /// Returns true if the given identity is a forum-level moderator.
    ///
    /// SECURITY: Uses constant-time comparison for each moderator check.
    /// Iterates through ALL moderators to prevent timing leaks that could
    /// reveal moderator count or position.
    pub fn is_moderator(&self, identity: &[u8]) -> bool {
        // Iterate through ALL moderators to prevent timing leaks
        // The result is accumulated without early return to ensure constant-time behavior
        let mut found = false;
        for mod_id in &self.moderators {
            if TimingSafe::identity_equal(mod_id, identity) {
                found = true;
                // Don't return early - continue checking all moderators
            }
        }
        found
    }

    /// Returns true if the given identity is a board-level moderator for the specified board.
    ///
    /// SECURITY: Uses constant-time comparison for identity checks.
    /// Iterates through ALL board moderators to prevent timing leaks.
    pub fn is_board_moderator(&self, identity: &[u8], board_hash: &ContentHash) -> bool {
        // Iterate through ALL board moderators to prevent timing leaks
        let mut found = false;
        if let Some(mods) = self.board_moderators.get(board_hash) {
            for mod_id in mods {
                if TimingSafe::identity_equal(mod_id, identity) {
                    found = true;
                    // Don't return early - continue checking all moderators
                }
            }
        }
        found
    }

    /// Returns true if the given identity can moderate the specified board.
    /// This is true if they are a forum-level moderator OR a board-level moderator for that board.
    pub fn can_moderate_board(&self, identity: &[u8], board_hash: &ContentHash) -> bool {
        self.is_moderator(identity) || self.is_board_moderator(identity, board_hash)
    }

    /// Returns the number of forum-level moderators (including owner).
    pub fn moderator_count(&self) -> usize {
        self.moderators.len()
    }

    /// Returns the number of board-level moderators for a specific board.
    pub fn board_moderator_count(&self, board_hash: &ContentHash) -> usize {
        self.board_moderators
            .get(board_hash)
            .map(|mods| mods.len())
            .unwrap_or(0)
    }

    /// Returns an iterator over all forum-level moderator identities.
    pub fn moderators(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.moderators.iter()
    }

    /// Returns an iterator over board-level moderator identities for a specific board.
    pub fn board_moderators(&self, board_hash: &ContentHash) -> impl Iterator<Item = &Vec<u8>> {
        self.board_moderators
            .get(board_hash)
            .into_iter()
            .flat_map(|mods| mods.iter())
    }

    /// Checks if an identity can create a board in this forum.
    ///
    /// Only forum-level moderators can create boards.
    pub fn can_create_board(&self, identity: &[u8]) -> bool {
        self.is_moderator(identity)
    }

    /// Checks if an identity can create a thread.
    ///
    /// Any authenticated user can create threads.
    pub fn can_create_thread(&self, _identity: &[u8]) -> bool {
        true
    }

    /// Checks if an identity can create a post.
    ///
    /// Any authenticated user can create posts.
    pub fn can_create_post(&self, _identity: &[u8]) -> bool {
        true
    }

    /// Checks if an identity can issue forum-level moderation actions.
    ///
    /// Only the forum owner can add/remove forum-level moderators.
    pub fn can_moderate(&self, identity: &[u8]) -> bool {
        self.is_owner(identity)
    }

    /// Checks if an identity can add/remove board-level moderators for a board.
    ///
    /// Forum owner and forum-level moderators can manage board moderators.
    pub fn can_manage_board_moderators(&self, identity: &[u8]) -> bool {
        self.is_owner(identity) || self.is_moderator(identity)
    }

    /// Returns true if the given board hash is hidden.
    pub fn is_board_hidden(&self, board_hash: &ContentHash) -> bool {
        self.hidden_boards.contains(board_hash)
    }

    /// Returns the number of hidden boards.
    pub fn hidden_board_count(&self) -> usize {
        self.hidden_boards.len()
    }

    /// Returns an iterator over all hidden board hashes.
    pub fn hidden_boards(&self) -> impl Iterator<Item = &ContentHash> {
        self.hidden_boards.iter()
    }

    /// Returns true if the given thread hash is hidden.
    pub fn is_thread_hidden(&self, thread_hash: &ContentHash) -> bool {
        self.hidden_threads.contains(thread_hash)
    }

    /// Returns true if the given post hash is hidden.
    pub fn is_post_hidden(&self, post_hash: &ContentHash) -> bool {
        self.hidden_posts.contains(post_hash)
    }

    /// Returns the number of hidden threads.
    pub fn hidden_thread_count(&self) -> usize {
        self.hidden_threads.len()
    }

    /// Returns the number of hidden posts.
    pub fn hidden_post_count(&self) -> usize {
        self.hidden_posts.len()
    }

    /// Returns an iterator over all hidden thread hashes.
    pub fn hidden_threads(&self) -> impl Iterator<Item = &ContentHash> {
        self.hidden_threads.iter()
    }

    /// Returns an iterator over all hidden post hashes.
    pub fn hidden_posts(&self) -> impl Iterator<Item = &ContentHash> {
        self.hidden_posts.iter()
    }

    /// Checks if an identity can hide/delete content (threads or posts).
    ///
    /// Forum owner and moderators can hide any content.
    /// Authors can also hide their own content (checked at application layer).
    pub fn can_hide_content(&self, identity: &[u8]) -> bool {
        self.is_owner(identity) || self.is_moderator(identity)
    }

    /// Returns the current board hash for a thread, considering any moves.
    ///
    /// If the thread has been moved, returns the destination board hash.
    /// If the thread has not been moved, returns None (use the original board from ThreadRoot).
    pub fn get_thread_current_board(&self, thread_hash: &ContentHash) -> Option<&ContentHash> {
        self.moved_threads.get(thread_hash)
    }

    /// Returns true if the thread has been moved from its original board.
    pub fn is_thread_moved(&self, thread_hash: &ContentHash) -> bool {
        self.moved_threads.contains_key(thread_hash)
    }

    /// Returns the number of moved threads.
    pub fn moved_thread_count(&self) -> usize {
        self.moved_threads.len()
    }

    /// Returns an iterator over all moved threads (thread_hash, destination_board_hash).
    pub fn moved_threads(&self) -> impl Iterator<Item = (&ContentHash, &ContentHash)> {
        self.moved_threads.iter()
    }
}

/// Builds forum permissions by replaying nodes from the DAG.
///
/// This struct processes nodes in order to build up the current permission state.
#[derive(Debug)]
pub struct PermissionBuilder {
    /// Permission states for each forum, keyed by forum hash.
    forums: HashMap<ContentHash, ForumPermissions>,
}

impl Default for PermissionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PermissionBuilder {
    /// Creates a new empty permission builder.
    pub fn new() -> Self {
        Self {
            forums: HashMap::new(),
        }
    }

    /// Processes a DAG node to update permission state.
    ///
    /// Nodes should be processed in topological order (parents before children).
    pub fn process_node(&mut self, node: &DagNode) -> Result<()> {
        match node {
            DagNode::ForumGenesis(forum) => {
                let permissions = ForumPermissions::from_genesis(forum);
                self.forums.insert(*forum.hash(), permissions);
            }
            DagNode::ModAction(action) => {
                let forum_hash = action.forum_hash();
                let permissions = self.forums.get_mut(forum_hash).ok_or_else(|| {
                    PqpgpError::validation("Moderation action references unknown forum")
                })?;
                permissions.apply_action(action)?;
            }
            // Other node types don't affect permissions
            DagNode::BoardGenesis(_)
            | DagNode::ThreadRoot(_)
            | DagNode::Post(_)
            | DagNode::Edit(_)
            | DagNode::EncryptionIdentity(_)
            | DagNode::SealedPrivateMessage(_) => {}
        }

        Ok(())
    }

    /// Returns the permission state for a forum, if it exists.
    pub fn get_permissions(&self, forum_hash: &ContentHash) -> Option<&ForumPermissions> {
        self.forums.get(forum_hash)
    }

    /// Returns mutable reference to permission state for a forum.
    pub fn get_permissions_mut(
        &mut self,
        forum_hash: &ContentHash,
    ) -> Option<&mut ForumPermissions> {
        self.forums.get_mut(forum_hash)
    }

    /// Consumes the builder and returns the permission states.
    pub fn into_permissions(self) -> HashMap<ContentHash, ForumPermissions> {
        self.forums
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::forum::ForumGenesis;

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
    fn test_permissions_from_genesis() {
        let keypair = create_test_keypair();
        let forum = create_test_forum(&keypair);

        let permissions = ForumPermissions::from_genesis(&forum);

        assert!(permissions.is_owner(keypair.public_key().as_bytes().as_slice()));
        assert!(permissions.is_moderator(keypair.public_key().as_bytes().as_slice()));
        assert_eq!(permissions.moderator_count(), 1);
    }

    #[test]
    fn test_add_moderator() {
        let owner_keypair = create_test_keypair();
        let mod_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let mut permissions = ForumPermissions::from_genesis(&forum);

        // Owner adds a moderator
        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            mod_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()],
        )
        .expect("Failed to create mod action");

        permissions
            .apply_action(&action)
            .expect("Failed to apply action");

        assert!(permissions.is_moderator(mod_keypair.public_key().as_bytes().as_slice()));
        assert_eq!(permissions.moderator_count(), 2);
    }

    #[test]
    fn test_remove_moderator() {
        let owner_keypair = create_test_keypair();
        let mod_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let mut permissions = ForumPermissions::from_genesis(&forum);

        // Add moderator
        let add_action = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            mod_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()],
        )
        .expect("Failed to create add action");
        permissions.apply_action(&add_action).unwrap();

        // Remove moderator
        let remove_action = ModActionNode::create(
            *forum.hash(),
            ModAction::RemoveModerator,
            mod_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*add_action.hash()],
        )
        .expect("Failed to create remove action");
        permissions.apply_action(&remove_action).unwrap();

        assert!(!permissions.is_moderator(mod_keypair.public_key().as_bytes().as_slice()));
        assert_eq!(permissions.moderator_count(), 1);
    }

    #[test]
    fn test_cannot_remove_owner() {
        let owner_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let mut permissions = ForumPermissions::from_genesis(&forum);

        // Try to remove owner
        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::RemoveModerator,
            owner_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()],
        )
        .expect("Failed to create action");

        assert!(permissions.apply_action(&action).is_err());
    }

    #[test]
    fn test_non_owner_cannot_moderate() {
        let owner_keypair = create_test_keypair();
        let other_keypair = create_test_keypair();
        let target_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let mut permissions = ForumPermissions::from_genesis(&forum);

        // Non-owner tries to add moderator
        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            target_keypair.public_key(),
            other_keypair.public_key(),
            other_keypair.private_key(),
            None,
            vec![*forum.hash()],
        )
        .expect("Failed to create action");

        assert!(permissions.apply_action(&action).is_err());
    }

    #[test]
    fn test_permission_checks() {
        let owner_keypair = create_test_keypair();
        let mod_keypair = create_test_keypair();
        let user_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let mut permissions = ForumPermissions::from_genesis(&forum);

        // Add moderator
        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            mod_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()],
        )
        .expect("Failed to create action");
        permissions.apply_action(&action).unwrap();

        let owner_id = owner_keypair.public_key().as_bytes();
        let mod_id = mod_keypair.public_key().as_bytes();
        let user_id = user_keypair.public_key().as_bytes();

        // Board creation
        assert!(permissions.can_create_board(&owner_id));
        assert!(permissions.can_create_board(&mod_id));
        assert!(!permissions.can_create_board(&user_id));

        // Thread creation - anyone can
        assert!(permissions.can_create_thread(&owner_id));
        assert!(permissions.can_create_thread(&mod_id));
        assert!(permissions.can_create_thread(&user_id));

        // Post creation - anyone can
        assert!(permissions.can_create_post(&owner_id));
        assert!(permissions.can_create_post(&mod_id));
        assert!(permissions.can_create_post(&user_id));

        // Moderation - only owner
        assert!(permissions.can_moderate(&owner_id));
        assert!(!permissions.can_moderate(&mod_id));
        assert!(!permissions.can_moderate(&user_id));
    }

    #[test]
    fn test_permission_builder() {
        let owner_keypair = create_test_keypair();
        let mod_keypair = create_test_keypair();
        let forum = create_test_forum(&owner_keypair);

        let mut builder = PermissionBuilder::new();

        // Process forum genesis
        builder
            .process_node(&DagNode::from(forum.clone()))
            .expect("Failed to process forum");

        // Process mod action
        let action = ModActionNode::create(
            *forum.hash(),
            ModAction::AddModerator,
            mod_keypair.public_key(),
            owner_keypair.public_key(),
            owner_keypair.private_key(),
            None,
            vec![*forum.hash()],
        )
        .expect("Failed to create action");

        builder
            .process_node(&DagNode::from(action))
            .expect("Failed to process action");

        let permissions = builder.get_permissions(forum.hash()).unwrap();
        assert_eq!(permissions.moderator_count(), 2);
    }

    #[test]
    fn test_permission_builder_wrong_forum() {
        let keypair1 = create_test_keypair();
        let keypair2 = create_test_keypair();
        let forum1 = create_test_forum(&keypair1);
        let forum2 = create_test_forum(&keypair2);

        let mut builder = PermissionBuilder::new();
        builder
            .process_node(&DagNode::from(forum1.clone()))
            .expect("Failed to process forum1");

        // Try to apply action for forum2 (which doesn't exist in builder)
        let action = ModActionNode::create(
            *forum2.hash(),
            ModAction::AddModerator,
            keypair2.public_key(),
            keypair2.public_key(),
            keypair2.private_key(),
            None,
            vec![*forum2.hash()],
        )
        .expect("Failed to create action");

        assert!(builder.process_node(&DagNode::from(action)).is_err());
    }

    #[test]
    fn test_multiple_forums() {
        let keypair1 = create_test_keypair();
        let keypair2 = create_test_keypair();
        let forum1 = create_test_forum(&keypair1);
        let forum2 = create_test_forum(&keypair2);

        let mut builder = PermissionBuilder::new();
        builder
            .process_node(&DagNode::from(forum1.clone()))
            .unwrap();
        builder
            .process_node(&DagNode::from(forum2.clone()))
            .unwrap();

        let permissions1 = builder.get_permissions(forum1.hash()).unwrap();
        let permissions2 = builder.get_permissions(forum2.hash()).unwrap();

        assert!(permissions1.is_owner(keypair1.public_key().as_bytes().as_slice()));
        assert!(permissions2.is_owner(keypair2.public_key().as_bytes().as_slice()));
        assert!(!permissions1.is_owner(keypair2.public_key().as_bytes().as_slice()));
    }
}
