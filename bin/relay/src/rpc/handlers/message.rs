//! Message-related RPC handlers.

use super::{parse_params, rand_id};
use crate::rpc::state::{acquire_relay_read, acquire_relay_write, QueuedMessage, SharedRelayState};
use pqpgp::forum::constants::{fingerprint_short, MAX_MESSAGE_SIZE, MAX_QUEUED_MESSAGES};
use pqpgp::forum::types::current_timestamp_millis;
use pqpgp::rpc::RpcError;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

#[derive(Debug, Deserialize)]
struct SendParams {
    recipient_fingerprint: String,
    sender_fingerprint: String,
    encrypted_data: String,
}

pub fn handle_send(state: &SharedRelayState, params: Value) -> Result<Value, RpcError> {
    let params: SendParams = parse_params(params)?;

    if params.encrypted_data.len() > MAX_MESSAGE_SIZE {
        return Err(RpcError::invalid_params("Message too large"));
    }

    if params.sender_fingerprint.is_empty() {
        return Err(RpcError::invalid_params("Sender fingerprint required"));
    }

    let now = current_timestamp_millis() / 1000;
    let message_id = format!("{}-{}", now, rand_id());

    let message = QueuedMessage {
        sender_fingerprint: params.sender_fingerprint.clone(),
        encrypted_data: params.encrypted_data,
        timestamp: now,
        message_id: message_id.clone(),
    };

    let mut relay = acquire_relay_write(state);

    let queue = relay
        .messages
        .entry(params.recipient_fingerprint.clone())
        .or_default();

    if queue.len() >= MAX_QUEUED_MESSAGES {
        return Err(RpcError::resource_exhausted("Recipient queue full"));
    }

    queue.push_back(message);

    info!(
        "message.send: {} -> {}",
        fingerprint_short(&params.sender_fingerprint),
        fingerprint_short(&params.recipient_fingerprint)
    );

    Ok(serde_json::json!({
        "sent": true,
        "message_id": message_id
    }))
}

#[derive(Debug, Deserialize)]
struct FetchParams {
    fingerprint: String,
}

pub fn handle_fetch(state: &SharedRelayState, params: Value) -> Result<Value, RpcError> {
    let params: FetchParams = parse_params(params)?;

    let mut relay = acquire_relay_write(state);

    // Update last seen
    if let Some(user) = relay.users.get_mut(&params.fingerprint) {
        user.last_seen = current_timestamp_millis() / 1000;
    }

    let messages: Vec<QueuedMessage> = relay
        .messages
        .remove(&params.fingerprint)
        .map(|q| q.into_iter().collect())
        .unwrap_or_default();

    let count = messages.len();
    if count > 0 {
        info!(
            "message.fetch: delivered {} to {}",
            count,
            fingerprint_short(&params.fingerprint)
        );
    }

    Ok(serde_json::json!({ "messages": messages }))
}

pub fn handle_check(state: &SharedRelayState, params: Value) -> Result<Value, RpcError> {
    let params: FetchParams = parse_params(params)?;

    let relay = acquire_relay_read(state);

    let count = relay
        .messages
        .get(&params.fingerprint)
        .map(|q| q.len())
        .unwrap_or(0);

    Ok(serde_json::json!({ "pending_count": count }))
}
