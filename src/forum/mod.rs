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
pub mod constants;
mod conversation;
mod dag;
pub mod dag_ops;
mod edit;
mod encryption_identity;
mod genesis;
mod moderation;
pub mod permissions;
mod pm_scanner;
mod pm_sealed;
mod post;
pub mod rpc_client;
mod sealed_message;
pub mod signed_heads;
pub mod state;
pub mod storage;
pub mod sync;
mod thread;
pub mod types;
pub mod validation;

pub use board::{BoardGenesis, BoardGenesisContent};
pub use client::ForumClient;
pub use conversation::{
    ConversationId, ConversationManager, ConversationSession, ConversationStats,
    ConversationSummary, RatchetSendInfo, StoredMessage, CONVERSATION_ID_SIZE,
    CONVERSATION_KEY_SIZE, MAX_MESSAGES_PER_CONVERSATION,
};
pub use dag::DagNode;
pub use edit::{EditNode, EditNodeContent, EditType};
pub use encryption_identity::{
    EncryptionIdentity, EncryptionIdentityContent, EncryptionIdentityGenerator,
    EncryptionIdentityPrivate,
};
pub use genesis::{ForumGenesis, ForumGenesisContent};
pub use moderation::{ModActionContent, ModActionNode};
pub use permissions::{ForumPermissions, PermissionBuilder};
pub use pm_scanner::{
    check_prekey_status, scan_forum_for_messages, PrekeyStatus, PrivateMessageScanner, ScanResult,
    OTP_REPLENISHMENT_THRESHOLD,
};
pub use pm_sealed::{
    seal_private_message, seal_private_message_with_session, seal_with_ratchet,
    unseal_private_message, unseal_private_message_with_session, unseal_with_ratchet,
    SealedMessageResult, UnsealedMessageResult,
};
pub use post::{Post, PostContent};
pub use rpc_client::{
    RpcClient, RpcError, RpcRequest, RpcResponse, RpcServerRequest, RpcServerResponse,
};
pub use sealed_message::{
    compute_recipient_hint, derive_hint_key, InnerMessage, RatchetHeader, SealedEnvelope,
    SealedPrivateMessage, SealedPrivateMessageContent, X3DHData,
};
pub use state::{ForumRelayState, ForumState};
pub use storage::{
    BoardSummary, Cursor, ForumMetadata, ForumStorage, ForumSummary, PaginatedResult, PostSummary,
    ThreadSummary, DEFAULT_PAGE_SIZE,
};
pub use sync::{
    ExportForumRequest, ExportForumResponse, SerializedNode, SubmitNodeRequest, SubmitNodeResponse,
    SyncRequest, SyncResponse, DEFAULT_SYNC_BATCH_SIZE, MAX_SYNC_BATCH_SIZE,
};
pub use thread::{ThreadRoot, ThreadRootContent};
pub use types::{current_timestamp_millis, ContentHash, ModAction, NodeType};
pub use validation::{validate_content_limits, validate_node, ValidationContext, ValidationResult};
