//! Generic JSON-RPC 2.0 utilities and abstractions.
//!
//! This module provides shared JSON-RPC 2.0 infrastructure that can be used
//! across different parts of the codebase (relay server, web client, CLI, etc.).
//!
//! ## Modules
//!
//! - `types`: Core JSON-RPC 2.0 request/response types and error handling
//! - `client`: Generic RPC client helper for building requests

pub mod client;
pub mod types;

pub use client::RpcClient;
pub use types::{
    RpcError, RpcRequest, RpcResponse, RpcServerRequest, RpcServerResponse, JSON_RPC_VERSION,
};
