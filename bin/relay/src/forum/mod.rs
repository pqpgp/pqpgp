//! Forum module for the relay server.
//!
//! This module provides DAG-based forum functionality including:
//! - RocksDB-backed persistent storage
//! - In-memory state management with DAG synchronization
//!
//! The JSON-RPC 2.0 API is handled by the unified `rpc` module in the parent crate.

pub mod persistence;
pub mod state;

// Re-export commonly used types
pub use persistence::PersistentForumState;
