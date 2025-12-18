//! System-related RPC handlers.

use crate::rpc::state::{acquire_forum_read, acquire_relay_read, AppState};
use pqpgp::rpc::RpcError;
use serde_json::Value;

pub fn handle_health() -> Result<Value, RpcError> {
    Ok(serde_json::json!({
        "status": "ok",
        "service": "pqpgp-relay",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

pub fn handle_stats(state: &AppState) -> Result<Value, RpcError> {
    let relay = acquire_relay_read(&state.relay);
    let forum = acquire_forum_read(&state.forum);

    let total_queued: usize = relay.messages.values().map(|q| q.len()).sum();

    Ok(serde_json::json!({
        "messaging": {
            "registered_users": relay.users.len(),
            "total_queued_messages": total_queued,
            "queues_active": relay.messages.len()
        },
        "forums": {
            "total_forums": forum.forums().len(),
            "total_nodes": forum.total_nodes()
        }
    }))
}
