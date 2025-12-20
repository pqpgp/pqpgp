//! RPC handler modules.

mod forum;
mod message;
mod system;
mod user;

use super::state::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use pqpgp::rpc::{RpcError, RpcServerRequest, RpcServerResponse};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use tracing::instrument;

// Re-export RpcServerRequest and RpcServerResponse as the local names.
type RpcRequest = RpcServerRequest;
type RpcResponse = RpcServerResponse;

// =============================================================================
// Helper Functions
// =============================================================================

/// Parses JSON-RPC parameters into a typed struct.
#[inline]
pub fn parse_params<T: DeserializeOwned>(params: Value) -> Result<T, RpcError> {
    serde_json::from_value(params).map_err(|e| RpcError::invalid_params(e.to_string()))
}

/// Converts a serializable value to JSON, mapping errors to RPC errors.
#[inline]
pub fn to_json<T: Serialize>(value: T) -> Result<Value, RpcError> {
    serde_json::to_value(value).map_err(|e| RpcError::internal_error(e.to_string()))
}

/// Generates a random hex ID.
pub fn rand_id() -> String {
    use rand::Rng;
    let random_bytes: [u8; 16] = rand::rng().random();
    hex::encode(random_bytes)
}

// =============================================================================
// Main RPC Handler
// =============================================================================

#[instrument(skip(state, request))]
pub async fn handle_rpc(
    State(state): State<AppState>,
    Json(request): Json<RpcRequest>,
) -> impl IntoResponse {
    if request.jsonrpc != "2.0" {
        return (
            StatusCode::OK,
            Json(RpcResponse::error(
                request.id,
                RpcError::invalid_request("Invalid JSON-RPC version"),
            )),
        );
    }

    let result = match request.method.as_str() {
        // User methods
        "user.register" => user::handle_register(&state.relay, request.params),
        "user.unregister" => user::handle_unregister(&state.relay, request.params),
        "user.get" => user::handle_get(&state.relay, request.params),
        "user.list" => user::handle_list(&state.relay),

        // Message methods
        "message.send" => message::handle_send(&state.relay, request.params),
        "message.fetch" => message::handle_fetch(&state.relay, request.params),
        "message.check" => message::handle_check(&state.relay, request.params),

        // Forum methods
        "forum.list" => forum::handle_list(&state.forum),
        "forum.sync" => forum::handle_sync(&state.forum, request.params),
        "forum.fetch" => forum::handle_fetch(&state.forum, request.params),
        "forum.submit" => forum::handle_submit(&state.forum, request.params),
        "forum.export" => forum::handle_export(&state.forum, request.params),
        "forum.heads" => forum::handle_heads(&state.forum, &state.identity, request.params),

        // System methods
        "relay.health" => system::handle_health(),
        "relay.stats" => system::handle_stats(&state),

        _ => Err(RpcError::method_not_found(&request.method)),
    };

    match result {
        Ok(value) => (
            StatusCode::OK,
            Json(RpcResponse::success(request.id, value)),
        ),
        Err(error) => (StatusCode::OK, Json(RpcResponse::error(request.id, error))),
    }
}
