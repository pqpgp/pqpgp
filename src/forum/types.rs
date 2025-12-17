//! Forum-specific types for the DAG system.
//!
//! This module contains types specific to the forum implementation:
//! - `NodeType`: Discriminator for different node types
//! - `ModAction`: Moderation action types
//!
//! For the generic DAG types like `ContentHash`, see the `dag` module.

use serde::{Deserialize, Serialize};
use std::fmt;

// Re-export from dag module for convenience
pub use crate::dag::{current_timestamp_millis, ContentHash};

/// Type discriminator for DAG nodes.
///
/// Each node type has a unique identifier that is included in the serialized
/// content, making nodes self-describing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeType {
    /// Forum genesis - root of the forum hierarchy.
    ForumGenesis = 1,
    /// Board genesis - creates a board within a forum.
    BoardGenesis = 2,
    /// Thread root - starts a new thread in a board.
    ThreadRoot = 3,
    /// Post - a reply within a thread.
    Post = 4,
    /// Moderation action - add/remove moderator, etc.
    ModAction = 10,
    /// Edit node - update forum/board metadata.
    Edit = 11,
    /// Encryption identity - publishes a user's encryption keys for private messaging.
    /// Contains ML-KEM-1024 prekey bundle for X3DH key agreement.
    EncryptionIdentity = 20,
    /// Sealed private message - end-to-end encrypted message with hidden metadata.
    /// Only the recipient can decrypt and discover the sender.
    SealedPrivateMessage = 21,
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeType::ForumGenesis => write!(f, "ForumGenesis"),
            NodeType::BoardGenesis => write!(f, "BoardGenesis"),
            NodeType::ThreadRoot => write!(f, "ThreadRoot"),
            NodeType::Post => write!(f, "Post"),
            NodeType::ModAction => write!(f, "ModAction"),
            NodeType::Edit => write!(f, "Edit"),
            NodeType::EncryptionIdentity => write!(f, "EncryptionIdentity"),
            NodeType::SealedPrivateMessage => write!(f, "SealedPrivateMessage"),
        }
    }
}

/// Moderation action types.
///
/// These actions are recorded in the DAG and can be replayed to determine
/// the current moderation state of a forum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ModAction {
    /// Add a user as forum-level moderator (can moderate all boards).
    AddModerator = 1,
    /// Remove a user's forum-level moderator status.
    RemoveModerator = 2,
    /// Add a user as board-level moderator (can only moderate specific board).
    AddBoardModerator = 3,
    /// Remove a user's board-level moderator status.
    RemoveBoardModerator = 4,
    /// Hide a thread (soft delete - content remains in DAG but not displayed).
    HideThread = 5,
    /// Unhide a previously hidden thread.
    UnhideThread = 6,
    /// Hide a post (soft delete - content remains in DAG but not displayed).
    HidePost = 7,
    /// Unhide a previously hidden post.
    UnhidePost = 8,
    /// Hide a board (soft delete - content remains in DAG but not displayed).
    HideBoard = 9,
    /// Unhide a previously hidden board.
    UnhideBoard = 10,
    /// Move a thread to a different board.
    MoveThread = 11,
}

impl fmt::Display for ModAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModAction::AddModerator => write!(f, "AddModerator"),
            ModAction::RemoveModerator => write!(f, "RemoveModerator"),
            ModAction::AddBoardModerator => write!(f, "AddBoardModerator"),
            ModAction::RemoveBoardModerator => write!(f, "RemoveBoardModerator"),
            ModAction::HideThread => write!(f, "HideThread"),
            ModAction::UnhideThread => write!(f, "UnhideThread"),
            ModAction::HidePost => write!(f, "HidePost"),
            ModAction::UnhidePost => write!(f, "UnhidePost"),
            ModAction::HideBoard => write!(f, "HideBoard"),
            ModAction::UnhideBoard => write!(f, "UnhideBoard"),
            ModAction::MoveThread => write!(f, "MoveThread"),
        }
    }
}

impl ModAction {
    /// Returns true if this action targets a specific board.
    pub fn is_board_action(&self) -> bool {
        matches!(
            self,
            ModAction::AddBoardModerator
                | ModAction::RemoveBoardModerator
                | ModAction::HideBoard
                | ModAction::UnhideBoard
        )
    }

    /// Returns true if this action targets a specific content node (thread or post).
    pub fn is_content_action(&self) -> bool {
        matches!(
            self,
            ModAction::HideThread
                | ModAction::UnhideThread
                | ModAction::HidePost
                | ModAction::UnhidePost
        )
    }

    /// Returns true if this is a hide action.
    pub fn is_hide_action(&self) -> bool {
        matches!(
            self,
            ModAction::HideThread | ModAction::HidePost | ModAction::HideBoard
        )
    }

    /// Returns true if this is an unhide action.
    pub fn is_unhide_action(&self) -> bool {
        matches!(
            self,
            ModAction::UnhideThread | ModAction::UnhidePost | ModAction::UnhideBoard
        )
    }

    /// Returns true if this is a move action.
    pub fn is_move_action(&self) -> bool {
        matches!(self, ModAction::MoveThread)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_type_values() {
        assert_eq!(NodeType::ForumGenesis as u8, 1);
        assert_eq!(NodeType::BoardGenesis as u8, 2);
        assert_eq!(NodeType::ThreadRoot as u8, 3);
        assert_eq!(NodeType::Post as u8, 4);
        assert_eq!(NodeType::ModAction as u8, 10);
        assert_eq!(NodeType::Edit as u8, 11);
        assert_eq!(NodeType::EncryptionIdentity as u8, 20);
        assert_eq!(NodeType::SealedPrivateMessage as u8, 21);
    }

    #[test]
    fn test_mod_action_values() {
        assert_eq!(ModAction::AddModerator as u8, 1);
        assert_eq!(ModAction::RemoveModerator as u8, 2);
    }
}
