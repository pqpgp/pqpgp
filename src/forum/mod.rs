//! DAG-based forum system with cryptographic integrity.
//!
//! This module implements a decentralized forum where all content forms a
//! Directed Acyclic Graph (DAG). Each node is:
//! - **Content-addressed**: Identified by SHA3-512 hash of its content
//! - **Signed**: Authenticated with ML-DSA-87 signatures
//! - **Linked**: References parent nodes by hash, forming the DAG
//!
//! ## Hierarchy
//!
//! ```text
//! ForumGenesis (root)
//!     └── BoardGenesis
//!             └── ThreadRoot
//!                     └── Post
//!                             └── Post (reply)
//! ```
//!
//! ## Rebuildability
//!
//! The DAG is completely self-describing. Given a dump of all nodes,
//! the entire forum can be rebuilt by:
//! 1. Deserializing all nodes
//! 2. Topologically sorting (parents before children)
//! 3. Validating signatures and hashes
//! 4. Storing in order
//!
//! No external data or central authority is required.

mod board;
pub mod client;
mod dag;
mod edit;
mod genesis;
mod moderation;
pub mod permissions;
mod post;
pub mod storage;
pub mod sync;
mod thread;
pub mod types;
pub mod validation;

pub use board::{BoardGenesis, BoardGenesisContent};
pub use client::ForumClient;
pub use dag::DagNode;
pub use edit::{EditNode, EditNodeContent, EditType};
pub use genesis::{ForumGenesis, ForumGenesisContent};
pub use moderation::{ModActionContent, ModActionNode};
pub use permissions::{ForumPermissions, PermissionBuilder};
pub use post::{Post, PostContent};
pub use storage::ForumStorage;
pub use sync::{
    ExportForumRequest, ExportForumResponse, FetchNodesRequest, FetchNodesResponse, SerializedNode,
    SubmitNodeRequest, SubmitNodeResponse, SyncRequest, SyncResponse,
};
pub use thread::{ThreadRoot, ThreadRootContent};
pub use types::{ContentHash, ModAction, NodeType};
pub use validation::{validate_node, ValidationContext, ValidationResult};
