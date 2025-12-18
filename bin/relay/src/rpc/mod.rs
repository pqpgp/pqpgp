//! Unified JSON-RPC 2.0 handler for the relay server.
//!
//! Provides a single `/rpc` endpoint for all relay operations:
//!
//! ## Messaging Methods
//! - `user.register` - Register user with prekey bundle
//! - `user.unregister` - Unregister a user
//! - `user.get` - Get user's prekey bundle
//! - `user.list` - List all registered users
//! - `message.send` - Send message to recipient
//! - `message.fetch` - Fetch messages for recipient
//! - `message.check` - Check pending message count
//!
//! ## Forum Methods
//! - `forum.list` - List all forums
//! - `forum.sync` - Get missing node hashes
//! - `forum.fetch` - Fetch nodes by hash
//! - `forum.submit` - Submit a new node
//! - `forum.export` - Export forum DAG (paginated)
//!
//! ## System Methods
//! - `relay.health` - Health check
//! - `relay.stats` - Server statistics

mod handlers;
mod state;

pub use handlers::handle_rpc;
pub use state::{AppState, RelayState, SharedForumState, SharedRelayState};
