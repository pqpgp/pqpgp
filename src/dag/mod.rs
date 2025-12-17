//! Generic DAG (Directed Acyclic Graph) infrastructure.
//!
//! This module provides the core primitives for content-addressed DAG systems:
//!
//! - [`ContentHash`]: 64-byte SHA3-512 content address for any node
//! - [`DagNodeOps`]: Trait for types that can participate in DAG operations
//! - DAG algorithms: reachability, missing node detection, topological sorting
//!
//! These primitives are domain-agnostic and can be used by any system that
//! needs content-addressed, cryptographically-verified data structures.
//!
//! # Example
//!
//! ```ignore
//! use pqpgp::dag::{ContentHash, DagNodeOps, compute_missing};
//!
//! // Define your node type implementing DagNodeOps
//! struct MyNode { /* ... */ }
//!
//! impl DagNodeOps for MyNode {
//!     fn hash(&self) -> &ContentHash { /* ... */ }
//!     fn parent_hashes(&self) -> Vec<ContentHash> { /* ... */ }
//!     fn created_at(&self) -> u64 { /* ... */ }
//! }
//!
//! // Use generic DAG operations
//! let missing = compute_missing(&nodes, &client_heads);
//! ```

mod hash;
pub mod ops;

pub use hash::{current_timestamp_millis, ContentHash};
pub use ops::{
    compute_missing, compute_reachable, nodes_in_topological_order, topological_sort_hashes,
    DagNodeOps,
};
