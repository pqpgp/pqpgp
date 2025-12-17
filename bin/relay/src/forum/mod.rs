//! Forum module for the relay server.
//!
//! This module provides DAG-based forum functionality including:
//! - HTTP handlers for forum API endpoints
//! - RocksDB-backed persistent storage
//! - In-memory state management with DAG synchronization

pub mod handlers;
pub mod persistence;
pub mod state;

// Re-export commonly used types
pub use handlers::SharedForumState;
pub use persistence::PersistentForumState;
