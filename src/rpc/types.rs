//! Core JSON-RPC 2.0 types.
//!
//! This module provides the fundamental JSON-RPC 2.0 request and response types
//! for both client-side and server-side usage.
//!
//! ## Client Types
//!
//! - [`RpcRequest`]: For building outgoing requests
//! - [`RpcResponse`]: For parsing incoming responses
//!
//! ## Server Types
//!
//! - [`RpcServerRequest`]: For receiving incoming requests
//! - [`RpcServerResponse`]: For building outgoing responses
//!
//! ## Error Handling
//!
//! - [`RpcError`]: Standard JSON-RPC 2.0 error object with predefined error codes

use crate::error::{PqpgpError, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 protocol version.
pub const JSON_RPC_VERSION: &str = "2.0";

// =============================================================================
// Client-side Types (for building requests and parsing responses)
// =============================================================================

/// JSON-RPC 2.0 request (client-side, for building requests).
///
/// Used by clients to construct properly formatted RPC requests.
///
/// # Example
///
/// ```
/// use pqpgp::rpc::RpcRequest;
/// use serde_json::json;
///
/// let request = RpcRequest::new("method.name", json!({"param": "value"}));
/// assert_eq!(request.method, "method.name");
/// assert_eq!(request.jsonrpc, "2.0");
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct RpcRequest {
    /// Protocol version (always "2.0").
    pub jsonrpc: &'static str,
    /// Method name.
    pub method: &'static str,
    /// Method parameters.
    pub params: Value,
    /// Request ID.
    pub id: u64,
}

impl RpcRequest {
    /// Creates a new RPC request with ID 1.
    pub fn new(method: &'static str, params: impl Serialize) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION,
            method,
            params: serde_json::to_value(params).unwrap_or(Value::Null),
            id: 1,
        }
    }

    /// Creates a new RPC request with a specific ID.
    pub fn with_id(method: &'static str, params: impl Serialize, id: u64) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION,
            method,
            params: serde_json::to_value(params).unwrap_or(Value::Null),
            id,
        }
    }
}

/// JSON-RPC 2.0 response (client-side, for parsing responses).
///
/// Used by clients to parse responses from RPC servers.
#[derive(Debug, Clone, Deserialize)]
pub struct RpcResponse {
    /// Protocol version.
    pub jsonrpc: String,
    /// Result (present on success).
    pub result: Option<Value>,
    /// Error (present on failure).
    pub error: Option<RpcError>,
    /// Request ID.
    pub id: Option<Value>,
}

impl RpcResponse {
    /// Extracts the result value, returning an error if the response contains an error.
    pub fn into_result(self) -> Result<Value> {
        if let Some(err) = self.error {
            return Err(PqpgpError::Chat(format!(
                "RPC error {}: {}",
                err.code, err.message
            )));
        }

        self.result
            .ok_or_else(|| PqpgpError::Chat("Empty RPC result".to_string()))
    }

    /// Extracts and deserializes the result as a specific type.
    pub fn into_typed_result<T: DeserializeOwned>(self) -> Result<T> {
        let value = self.into_result()?;
        serde_json::from_value(value)
            .map_err(|e| PqpgpError::Serialization(format!("Failed to parse RPC result: {}", e)))
    }

    /// Creates a success response (useful for testing).
    pub fn success(id: u64, result: impl Serialize) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION.to_string(),
            result: Some(serde_json::to_value(result).unwrap_or(Value::Null)),
            error: None,
            id: Some(Value::Number(id.into())),
        }
    }

    /// Creates an error response (useful for testing).
    pub fn error(id: u64, error: RpcError) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION.to_string(),
            result: None,
            error: Some(error),
            id: Some(Value::Number(id.into())),
        }
    }
}

// =============================================================================
// Server-side Types (for receiving requests and building responses)
// =============================================================================

/// JSON-RPC 2.0 request (server-side, for receiving requests).
///
/// Used by servers to parse incoming RPC requests. The method field is a String
/// rather than &'static str since it comes from external input.
#[derive(Debug, Clone, Deserialize)]
pub struct RpcServerRequest {
    /// Protocol version.
    pub jsonrpc: String,
    /// Method name.
    pub method: String,
    /// Method parameters.
    #[serde(default)]
    pub params: Value,
    /// Request ID.
    pub id: Option<Value>,
}

impl RpcServerRequest {
    /// Validates that this is a valid JSON-RPC 2.0 request.
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.jsonrpc != JSON_RPC_VERSION {
            return Err("Invalid JSON-RPC version");
        }
        if self.method.is_empty() {
            return Err("Method name required");
        }
        Ok(())
    }

    /// Parses the params as a specific type.
    pub fn parse_params<T: DeserializeOwned>(&self) -> std::result::Result<T, String> {
        serde_json::from_value(self.params.clone()).map_err(|e| e.to_string())
    }
}

/// JSON-RPC 2.0 response (server-side, for building responses).
///
/// Used by servers to construct properly formatted RPC responses.
#[derive(Debug, Clone, Serialize)]
pub struct RpcServerResponse {
    /// Protocol version (always "2.0").
    pub jsonrpc: &'static str,
    /// Result (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error (present on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    /// Request ID.
    pub id: Option<Value>,
}

impl RpcServerResponse {
    /// Creates a success response.
    pub fn success(id: Option<Value>, result: impl Serialize) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION,
            result: Some(serde_json::to_value(result).unwrap_or(Value::Null)),
            error: None,
            id,
        }
    }

    /// Creates an error response.
    pub fn error(id: Option<Value>, error: RpcError) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION,
            result: None,
            error: Some(error),
            id,
        }
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// JSON-RPC 2.0 error object.
///
/// Contains standard error codes as defined by the JSON-RPC 2.0 specification,
/// plus application-specific error codes in the -32000 to -32099 range.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
    /// Additional error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    // -------------------------------------------------------------------------
    // Standard JSON-RPC 2.0 error codes
    // -------------------------------------------------------------------------

    /// Parse error (-32700): Invalid JSON was received by the server.
    pub const PARSE_ERROR: i32 = -32700;

    /// Invalid request (-32600): The JSON sent is not a valid Request object.
    pub const INVALID_REQUEST: i32 = -32600;

    /// Method not found (-32601): The method does not exist or is not available.
    pub const METHOD_NOT_FOUND: i32 = -32601;

    /// Invalid params (-32602): Invalid method parameter(s).
    pub const INVALID_PARAMS: i32 = -32602;

    /// Internal error (-32603): Internal JSON-RPC error.
    pub const INTERNAL_ERROR: i32 = -32603;

    // -------------------------------------------------------------------------
    // Application-specific error codes (-32000 to -32099)
    // -------------------------------------------------------------------------

    /// Resource not found (-32001).
    pub const NOT_FOUND: i32 = -32001;

    /// Validation failed (-32002).
    pub const VALIDATION_FAILED: i32 = -32002;

    /// Rate limited (-32003).
    pub const RATE_LIMITED: i32 = -32003;

    /// Resource exhausted (-32004).
    pub const RESOURCE_EXHAUSTED: i32 = -32004;

    /// Unauthorized (-32005).
    pub const UNAUTHORIZED: i32 = -32005;

    // -------------------------------------------------------------------------
    // Constructor methods
    // -------------------------------------------------------------------------

    /// Creates an error with the given code and message.
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Creates an error with additional data.
    pub fn with_data(code: i32, message: impl Into<String>, data: Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }

    /// Creates a parse error.
    pub fn parse_error(msg: impl Into<String>) -> Self {
        Self::new(Self::PARSE_ERROR, msg)
    }

    /// Creates an invalid request error.
    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new(Self::INVALID_REQUEST, msg)
    }

    /// Creates a method not found error.
    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            Self::METHOD_NOT_FOUND,
            format!("Method '{}' not found", method),
        )
    }

    /// Creates an invalid params error.
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(Self::INVALID_PARAMS, msg)
    }

    /// Creates an internal error.
    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self::new(Self::INTERNAL_ERROR, msg)
    }

    /// Creates a not found error.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(Self::NOT_FOUND, msg)
    }

    /// Creates a validation failed error with details.
    pub fn validation_failed(errors: Vec<String>) -> Self {
        Self::with_data(
            Self::VALIDATION_FAILED,
            "Validation failed",
            Value::Array(errors.into_iter().map(Value::String).collect()),
        )
    }

    /// Creates a rate limited error.
    pub fn rate_limited(msg: impl Into<String>) -> Self {
        Self::new(Self::RATE_LIMITED, msg)
    }

    /// Creates a resource exhausted error.
    pub fn resource_exhausted(msg: impl Into<String>) -> Self {
        Self::new(Self::RESOURCE_EXHAUSTED, msg)
    }

    /// Creates an unauthorized error.
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(Self::UNAUTHORIZED, msg)
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RPC error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_request_serialization() {
        let request = RpcRequest::new("test.method", serde_json::json!({"key": "value"}));
        let json = serde_json::to_string(&request).unwrap();

        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"test.method\""));
        assert!(json.contains("\"id\":1"));
    }

    #[test]
    fn test_rpc_request_with_id() {
        let request = RpcRequest::with_id("test.method", serde_json::json!({}), 42);
        assert_eq!(request.id, 42);
    }

    #[test]
    fn test_rpc_response_success() {
        let response = RpcResponse::success(1, serde_json::json!({"result": "ok"}));
        let result: serde_json::Value = response.into_typed_result().unwrap();
        assert_eq!(result["result"], "ok");
    }

    #[test]
    fn test_rpc_response_error() {
        let response = RpcResponse::error(1, RpcError::not_found("Item not found"));
        let result: Result<Value> = response.into_typed_result();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("-32001"));
        assert!(err.contains("Item not found"));
    }

    #[test]
    fn test_rpc_server_request_validation() {
        let valid = RpcServerRequest {
            jsonrpc: "2.0".to_string(),
            method: "test.method".to_string(),
            params: Value::Null,
            id: Some(Value::Number(1.into())),
        };
        assert!(valid.validate().is_ok());

        let invalid_version = RpcServerRequest {
            jsonrpc: "1.0".to_string(),
            method: "test.method".to_string(),
            params: Value::Null,
            id: None,
        };
        assert!(invalid_version.validate().is_err());

        let empty_method = RpcServerRequest {
            jsonrpc: "2.0".to_string(),
            method: "".to_string(),
            params: Value::Null,
            id: None,
        };
        assert!(empty_method.validate().is_err());
    }

    #[test]
    fn test_rpc_server_response_serialization() {
        let success = RpcServerResponse::success(Some(Value::Number(1.into())), "result");
        let json = serde_json::to_string(&success).unwrap();
        assert!(json.contains("\"result\":\"result\""));
        assert!(!json.contains("\"error\""));

        let error = RpcServerResponse::error(None, RpcError::internal_error("oops"));
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"error\""));
        assert!(!json.contains("\"result\""));
    }

    #[test]
    fn test_rpc_error_codes() {
        assert_eq!(RpcError::PARSE_ERROR, -32700);
        assert_eq!(RpcError::INVALID_REQUEST, -32600);
        assert_eq!(RpcError::METHOD_NOT_FOUND, -32601);
        assert_eq!(RpcError::INVALID_PARAMS, -32602);
        assert_eq!(RpcError::INTERNAL_ERROR, -32603);
    }

    #[test]
    fn test_rpc_error_validation_failed() {
        let error = RpcError::validation_failed(vec!["error1".to_string(), "error2".to_string()]);
        assert_eq!(error.code, RpcError::VALIDATION_FAILED);
        assert!(error.data.is_some());
        let data = error.data.unwrap();
        assert!(data.is_array());
        assert_eq!(data.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_rpc_error_display() {
        let error = RpcError::not_found("User not found");
        assert_eq!(error.to_string(), "RPC error -32001: User not found");
    }
}
