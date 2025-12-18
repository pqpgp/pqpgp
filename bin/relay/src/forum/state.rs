//! Forum relay state management.
//!
//! This module re-exports the forum state types from the core library.
//! The relay stores all forum nodes and tracks DAG heads for efficient sync.

pub use pqpgp::forum::state::{ForumRelayState, ForumState};
