//! User-related RPC handlers.

use super::{parse_params, to_json};
use crate::rpc::state::{
    acquire_relay_read, acquire_relay_write, RegisteredUser, SharedRelayState,
};
use pqpgp::forum::constants::fingerprint_short;
use pqpgp::forum::types::current_timestamp_millis;
use pqpgp::rpc::RpcError;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

#[derive(Debug, Deserialize)]
struct RegisterParams {
    name: String,
    fingerprint: String,
    prekey_bundle: String,
}

pub fn handle_register(state: &SharedRelayState, params: Value) -> Result<Value, RpcError> {
    let params: RegisterParams = parse_params(params)?;

    // Validate fingerprint
    if params.fingerprint.len() < 16 || !params.fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(RpcError::invalid_params("Invalid fingerprint format"));
    }

    if params.prekey_bundle.is_empty() {
        return Err(RpcError::invalid_params("Prekey bundle required"));
    }

    let now = current_timestamp_millis() / 1000;

    let user = RegisteredUser {
        name: params.name.clone(),
        fingerprint: params.fingerprint.clone(),
        prekey_bundle: params.prekey_bundle,
        registered_at: now,
        last_seen: now,
    };

    let mut relay = acquire_relay_write(state);
    let is_update = relay.users.contains_key(&params.fingerprint);
    relay.users.insert(params.fingerprint.clone(), user);

    info!(
        "user.register: {} {} ({})",
        if is_update { "updated" } else { "registered" },
        params.name,
        fingerprint_short(&params.fingerprint)
    );

    Ok(serde_json::json!({
        "registered": true,
        "updated": is_update
    }))
}

#[derive(Debug, Deserialize)]
struct UnregisterParams {
    fingerprint: String,
}

pub fn handle_unregister(state: &SharedRelayState, params: Value) -> Result<Value, RpcError> {
    let params: UnregisterParams = parse_params(params)?;

    let mut relay = acquire_relay_write(state);

    if relay.users.remove(&params.fingerprint).is_some() {
        relay.messages.remove(&params.fingerprint);
        info!(
            "user.unregister: {}",
            fingerprint_short(&params.fingerprint)
        );
        Ok(serde_json::json!({ "unregistered": true }))
    } else {
        Err(RpcError::not_found("User not found"))
    }
}

#[derive(Debug, Deserialize)]
struct GetParams {
    fingerprint: String,
}

pub fn handle_get(state: &SharedRelayState, params: Value) -> Result<Value, RpcError> {
    let params: GetParams = parse_params(params)?;

    let relay = acquire_relay_read(state);

    relay
        .users
        .get(&params.fingerprint)
        .map(|user| serde_json::to_value(user).unwrap())
        .ok_or_else(|| RpcError::not_found("User not found"))
}

pub fn handle_list(state: &SharedRelayState) -> Result<Value, RpcError> {
    let relay = acquire_relay_read(state);
    let users: Vec<&RegisteredUser> = relay.users.values().collect();
    info!("user.list: {} users", users.len());
    to_json(users)
}
