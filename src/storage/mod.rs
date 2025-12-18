//! Storage utilities and abstractions.
//!
//! This module provides shared storage infrastructure that can be used
//! across different parts of the codebase.
//!
//! ## Modules
//!
//! - `rocksdb`: Generic RocksDB utilities (configuration, handle, iteration)

pub mod rocksdb;

pub use rocksdb::{composite_key, prefixed_key, RocksDbConfig, RocksDbHandle};
