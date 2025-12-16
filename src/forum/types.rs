//! Core types for the forum DAG system.

use crate::crypto::hash_data;
use crate::error::{PqpgpError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A 64-byte content hash using SHA3-512.
///
/// This is the content address of any DAG node. The hash is computed over
/// the bincode-serialized content, ensuring deterministic addressing.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; 64]);

impl Serialize for ContentHash {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as a byte slice, which serde handles well
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ContentHashVisitor;

        impl<'de> serde::de::Visitor<'de> for ContentHashVisitor {
            type Value = ContentHash;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array of length 64")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 64 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(ContentHash(arr))
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; 64];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(ContentHash(arr))
            }
        }

        deserializer.deserialize_bytes(ContentHashVisitor)
    }
}

impl ContentHash {
    /// Computes the content hash of serializable data.
    ///
    /// Uses bincode for deterministic serialization, then SHA3-512 for hashing.
    pub fn compute<T: Serialize>(data: &T) -> Result<Self> {
        let serialized = bincode::serialize(data).map_err(|e| {
            PqpgpError::serialization(format!("Failed to serialize for hash: {}", e))
        })?;
        Ok(Self(hash_data(&serialized)))
    }

    /// Creates a ContentHash from raw bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the raw hash bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Returns hex-encoded string representation.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a ContentHash from a hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|_| PqpgpError::validation("Invalid hex string for ContentHash"))?;
        if bytes.len() != 64 {
            return Err(PqpgpError::validation(
                "ContentHash must be exactly 64 bytes (128 hex characters)",
            ));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Returns a short form of the hash for display (first 8 bytes / 16 hex chars).
    pub fn short(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({}...)", &self.to_hex()[..16])
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

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

/// Returns the current Unix timestamp in milliseconds.
pub fn current_timestamp_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_hash_compute() {
        let data = "test data";
        let hash1 = ContentHash::compute(&data).unwrap();
        let hash2 = ContentHash::compute(&data).unwrap();
        assert_eq!(hash1, hash2, "Same data should produce same hash");

        let other_data = "other data";
        let hash3 = ContentHash::compute(&other_data).unwrap();
        assert_ne!(hash1, hash3, "Different data should produce different hash");
    }

    #[test]
    fn test_content_hash_hex_roundtrip() {
        let data = "test data";
        let hash = ContentHash::compute(&data).unwrap();
        let hex = hash.to_hex();
        let parsed = ContentHash::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_content_hash_display() {
        let data = "test data";
        let hash = ContentHash::compute(&data).unwrap();
        let short = hash.short();
        assert_eq!(short.len(), 16, "Short form should be 16 hex characters");
    }

    #[test]
    fn test_node_type_values() {
        assert_eq!(NodeType::ForumGenesis as u8, 1);
        assert_eq!(NodeType::BoardGenesis as u8, 2);
        assert_eq!(NodeType::ThreadRoot as u8, 3);
        assert_eq!(NodeType::Post as u8, 4);
        assert_eq!(NodeType::ModAction as u8, 10);
    }

    #[test]
    fn test_mod_action_values() {
        assert_eq!(ModAction::AddModerator as u8, 1);
        assert_eq!(ModAction::RemoveModerator as u8, 2);
    }
}
