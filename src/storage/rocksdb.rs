//! Shared RocksDB storage utilities.
//!
//! This module provides generic utilities and patterns for RocksDB-based
//! storage. It contains no domain-specific logic - just pure RocksDB helpers.
//!
//! ## Key Features
//!
//! - Configurable RocksDB setup with sensible defaults
//! - Generic key-value operations with serialization
//! - Prefix iteration patterns
//! - Batch operations

use crate::error::{PqpgpError, Result};
use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options,
};
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, trace, warn};

// =============================================================================
// RocksDB Configuration
// =============================================================================

/// Configuration for RocksDB storage.
#[derive(Debug, Clone)]
pub struct RocksDbConfig {
    /// Maximum number of open files.
    pub max_open_files: i32,
    /// Number of log files to keep.
    pub keep_log_file_num: usize,
    /// Maximum WAL size in bytes.
    pub max_wal_size: u64,
    /// Write buffer size in bytes.
    pub write_buffer_size: usize,
    /// Maximum number of write buffers.
    pub max_write_buffer_number: i32,
    /// Target file size for SST files.
    pub target_file_size_base: u64,
}

impl Default for RocksDbConfig {
    fn default() -> Self {
        Self {
            max_open_files: 128,
            keep_log_file_num: 2,
            max_wal_size: 32 * 1024 * 1024,      // 32MB
            write_buffer_size: 32 * 1024 * 1024, // 32MB
            max_write_buffer_number: 2,
            target_file_size_base: 32 * 1024 * 1024, // 32MB
        }
    }
}

impl RocksDbConfig {
    /// Creates a configuration optimized for server workloads.
    ///
    /// Uses larger buffers and more files for higher throughput.
    pub fn for_server() -> Self {
        Self {
            max_open_files: 256,
            keep_log_file_num: 3,
            max_wal_size: 64 * 1024 * 1024,      // 64MB
            write_buffer_size: 64 * 1024 * 1024, // 64MB
            max_write_buffer_number: 3,
            target_file_size_base: 64 * 1024 * 1024, // 64MB
        }
    }

    /// Builds RocksDB Options from this configuration.
    pub fn build_options(&self) -> Options {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(self.max_open_files);
        opts.set_keep_log_file_num(self.keep_log_file_num);
        opts.set_max_total_wal_size(self.max_wal_size);
        opts.increase_parallelism(num_cpus::get() as i32);
        opts.set_write_buffer_size(self.write_buffer_size);
        opts.set_max_write_buffer_number(self.max_write_buffer_number);
        opts.set_target_file_size_base(self.target_file_size_base);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts
    }
}

// =============================================================================
// Key Generation Utilities
// =============================================================================

/// Creates a prefixed key with a separator.
///
/// Format: `{prefix}{separator}{suffix}`
///
/// This is useful for creating composite keys that enable prefix iteration.
pub fn prefixed_key(prefix: &[u8], separator: u8, suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 1 + suffix.len());
    key.extend_from_slice(prefix);
    key.push(separator);
    key.extend_from_slice(suffix);
    key
}

/// Creates a composite key from two byte slices.
///
/// Format: `{part1}:{part2}` (using colon separator)
pub fn composite_key(part1: &[u8], part2: &[u8]) -> Vec<u8> {
    prefixed_key(part1, b':', part2)
}

// =============================================================================
// Database Handle Wrapper
// =============================================================================

/// A wrapper around RocksDB that provides common operations.
///
/// This is designed to be embedded in storage structs to provide
/// shared functionality while allowing storage-specific extensions.
pub struct RocksDbHandle {
    db: Arc<DBWithThreadMode<MultiThreaded>>,
}

impl RocksDbHandle {
    /// Opens a RocksDB database with the given column families.
    pub fn open(
        db_path: impl AsRef<Path>,
        config: &RocksDbConfig,
        column_families: &[&str],
    ) -> Result<Self> {
        let opts = config.build_options();
        let cf_opts = Options::default();

        let cf_descriptors: Vec<_> = column_families
            .iter()
            .map(|cf| ColumnFamilyDescriptor::new(*cf, cf_opts.clone()))
            .collect();

        let db = DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(
            &opts,
            db_path.as_ref(),
            cf_descriptors,
        )
        .map_err(|e| PqpgpError::storage(format!("Failed to open RocksDB: {}", e)))?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Gets a column family handle.
    pub fn cf(&self, name: &str) -> Result<Arc<BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| PqpgpError::storage(format!("Column family '{}' not found", name)))
    }

    /// Stores a serializable value at the given key.
    pub fn put<T: Serialize>(&self, cf_name: &str, key: &[u8], value: &T) -> Result<()> {
        let cf = self.cf(cf_name)?;
        let bytes = bincode::serialize(value)
            .map_err(|e| PqpgpError::serialization(format!("Failed to serialize: {}", e)))?;

        trace!(
            cf = cf_name,
            key_len = key.len(),
            value_bytes = bytes.len(),
            "db_put: storing serialized value"
        );

        self.db
            .put_cf(&cf, key, &bytes)
            .map_err(|e| PqpgpError::storage(format!("Failed to write: {}", e)))?;

        Ok(())
    }

    /// Stores raw bytes at the given key.
    pub fn put_raw(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;

        trace!(
            cf = cf_name,
            key_len = key.len(),
            value_bytes = value.len(),
            "db_put_raw: storing raw bytes"
        );

        self.db
            .put_cf(&cf, key, value)
            .map_err(|e| PqpgpError::storage(format!("Failed to write: {}", e)))?;
        Ok(())
    }

    /// Loads and deserializes a value from the given key.
    pub fn get<T: DeserializeOwned>(&self, cf_name: &str, key: &[u8]) -> Result<Option<T>> {
        let cf = self.cf(cf_name)?;

        match self.db.get_cf(&cf, key) {
            Ok(Some(bytes)) => {
                trace!(
                    cf = cf_name,
                    key_len = key.len(),
                    value_bytes = bytes.len(),
                    "db_get: found record"
                );
                let value: T = bincode::deserialize(&bytes).map_err(|e| {
                    PqpgpError::serialization(format!("Failed to deserialize: {}", e))
                })?;
                Ok(Some(value))
            }
            Ok(None) => {
                trace!(cf = cf_name, key_len = key.len(), "db_get: key not found");
                Ok(None)
            }
            Err(e) => Err(PqpgpError::storage(format!("Failed to read: {}", e))),
        }
    }

    /// Loads raw bytes from the given key.
    pub fn get_raw(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self.cf(cf_name)?;

        match self.db.get_cf(&cf, key) {
            Ok(Some(bytes)) => {
                trace!(
                    cf = cf_name,
                    key_len = key.len(),
                    value_bytes = bytes.len(),
                    "db_get_raw: found record"
                );
                Ok(Some(bytes.to_vec()))
            }
            Ok(None) => {
                trace!(
                    cf = cf_name,
                    key_len = key.len(),
                    "db_get_raw: key not found"
                );
                Ok(None)
            }
            Err(e) => Err(PqpgpError::storage(format!("Failed to read: {}", e))),
        }
    }

    /// Checks if a key exists.
    pub fn exists(&self, cf_name: &str, key: &[u8]) -> Result<bool> {
        let cf = self.cf(cf_name)?;
        let exists = self
            .db
            .get_cf(&cf, key)
            .map(|v| v.is_some())
            .map_err(|e| PqpgpError::storage(format!("Failed to check key: {}", e)))?;

        trace!(
            cf = cf_name,
            key_len = key.len(),
            exists = exists,
            "db_exists: checked key existence"
        );

        Ok(exists)
    }

    /// Deletes a key.
    pub fn delete(&self, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;

        trace!(cf = cf_name, key_len = key.len(), "db_delete: deleting key");

        self.db
            .delete_cf(&cf, key)
            .map_err(|e| PqpgpError::storage(format!("Failed to delete: {}", e)))?;
        Ok(())
    }

    /// Iterates over all entries with the given prefix.
    ///
    /// The callback receives (key, value) pairs and should return true to continue
    /// or false to stop iteration.
    pub fn prefix_iterate<F>(&self, cf_name: &str, prefix: &[u8], mut callback: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> bool,
    {
        let cf = self.cf(cf_name)?;
        let iter = self.db.prefix_iterator_cf(&cf, prefix);

        let mut count: usize = 0;
        for item in iter {
            match item {
                Ok((key, value)) => {
                    if !key.starts_with(prefix) {
                        break;
                    }
                    count += 1;
                    if !callback(&key, &value) {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Iterator error: {}", e);
                }
            }
        }

        debug!(
            cf = cf_name,
            prefix_len = prefix.len(),
            records_iterated = count,
            "db_prefix_iterate: completed iteration"
        );

        Ok(())
    }

    /// Iterates over entries starting from a seek position, filtering by a prefix.
    ///
    /// This is useful for cursor-based pagination where you want to seek to a specific
    /// position in the index but still only iterate over entries with a common prefix.
    ///
    /// - `seek_key`: The key to seek to (start iteration from this position)
    /// - `filter_prefix`: Only process keys that start with this prefix
    ///
    /// The callback receives (key, value) pairs and should return true to continue
    /// or false to stop iteration.
    pub fn seek_iterate<F>(
        &self,
        cf_name: &str,
        seek_key: &[u8],
        filter_prefix: &[u8],
        mut callback: F,
    ) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> bool,
    {
        let cf = self.cf(cf_name)?;
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek(seek_key);

        let mut count: usize = 0;
        while iter.valid() {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                // Stop if we've moved past the filter prefix
                if !key.starts_with(filter_prefix) {
                    break;
                }
                count += 1;
                if !callback(key, value) {
                    break;
                }
                iter.next();
            } else {
                break;
            }
        }

        debug!(
            cf = cf_name,
            seek_key_len = seek_key.len(),
            filter_prefix_len = filter_prefix.len(),
            records_iterated = count,
            "db_seek_iterate: completed seek iteration"
        );

        Ok(())
    }

    /// Collects all values with the given prefix, deserializing each.
    pub fn prefix_collect<T, F>(
        &self,
        cf_name: &str,
        prefix: &[u8],
        deserialize: F,
    ) -> Result<Vec<T>>
    where
        F: Fn(&[u8]) -> std::result::Result<T, String>,
    {
        let mut results = Vec::new();
        let mut errors: usize = 0;

        self.prefix_iterate(cf_name, prefix, |_, value| {
            match deserialize(value) {
                Ok(item) => results.push(item),
                Err(e) => {
                    errors += 1;
                    warn!("Failed to deserialize item: {}", e);
                }
            }
            true
        })?;

        debug!(
            cf = cf_name,
            prefix_len = prefix.len(),
            records_collected = results.len(),
            deserialization_errors = errors,
            "db_prefix_collect: collected records"
        );

        Ok(results)
    }

    /// Deletes all entries with the given prefix.
    ///
    /// Returns the number of deleted entries.
    pub fn prefix_delete(&self, cf_name: &str, prefix: &[u8]) -> Result<usize> {
        let cf = self.cf(cf_name)?;
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        let mut deleted = 0;

        for item in iter {
            match item {
                Ok((key, _)) => {
                    if !key.starts_with(prefix) {
                        break;
                    }
                    self.db
                        .delete_cf(&cf, &key)
                        .map_err(|e| PqpgpError::storage(format!("Failed to delete key: {}", e)))?;
                    deleted += 1;
                }
                Err(e) => {
                    warn!("Iterator error during deletion: {}", e);
                }
            }
        }

        debug!(
            cf = cf_name,
            prefix_len = prefix.len(),
            records_deleted = deleted,
            "db_prefix_delete: deleted records with prefix"
        );

        Ok(deleted)
    }

    /// Iterates over all entries in a column family.
    pub fn iterate_all<F>(&self, cf_name: &str, mut callback: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> bool,
    {
        let cf = self.cf(cf_name)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);

        let mut count: usize = 0;
        for item in iter {
            match item {
                Ok((key, value)) => {
                    count += 1;
                    if !callback(&key, &value) {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Iterator error: {}", e);
                }
            }
        }

        debug!(
            cf = cf_name,
            records_iterated = count,
            "db_iterate_all: completed full iteration"
        );

        Ok(())
    }

    /// Returns the underlying database reference for advanced operations.
    pub fn raw_db(&self) -> &DBWithThreadMode<MultiThreaded> {
        &self.db
    }

    /// Returns database statistics.
    #[allow(dead_code)]
    pub fn stats(&self) -> String {
        self.db
            .property_value("rocksdb.stats")
            .ok()
            .flatten()
            .unwrap_or_else(|| "Stats unavailable".to_string())
    }
}

impl std::fmt::Debug for RocksDbHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RocksDbHandle")
            .field("db", &"RocksDB")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestData {
        name: String,
        value: u64,
    }

    fn create_test_db() -> (RocksDbHandle, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let db_path = temp_dir.path().join("test_db");
        let config = RocksDbConfig::default();
        let db =
            RocksDbHandle::open(&db_path, &config, &["data", "meta"]).expect("Failed to open db");
        (db, temp_dir)
    }

    #[test]
    fn test_prefixed_key() {
        let key = prefixed_key(b"prefix", b':', b"suffix");
        assert_eq!(key, b"prefix:suffix");
    }

    #[test]
    fn test_composite_key() {
        let key = composite_key(b"part1", b"part2");
        assert_eq!(key, b"part1:part2");
    }

    #[test]
    fn test_put_and_get() {
        let (db, _temp) = create_test_db();

        let data = TestData {
            name: "Test".to_string(),
            value: 12345,
        };

        db.put("data", b"key1", &data).unwrap();

        let loaded: TestData = db.get("data", b"key1").unwrap().unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn test_put_and_get_raw() {
        let (db, _temp) = create_test_db();

        db.put_raw("data", b"key1", b"raw bytes").unwrap();

        let loaded = db.get_raw("data", b"key1").unwrap().unwrap();
        assert_eq!(loaded, b"raw bytes");
    }

    #[test]
    fn test_exists_and_delete() {
        let (db, _temp) = create_test_db();

        db.put_raw("meta", b"key", b"value").unwrap();
        assert!(db.exists("meta", b"key").unwrap());

        db.delete("meta", b"key").unwrap();
        assert!(!db.exists("meta", b"key").unwrap());
    }

    #[test]
    fn test_prefix_iterate() {
        let (db, _temp) = create_test_db();

        db.put_raw("data", b"prefix1:a", b"data1").unwrap();
        db.put_raw("data", b"prefix1:b", b"data2").unwrap();
        db.put_raw("data", b"prefix2:a", b"data3").unwrap();

        let mut found = Vec::new();
        db.prefix_iterate("data", b"prefix1:", |_, value| {
            found.push(value.to_vec());
            true
        })
        .unwrap();

        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_prefix_delete() {
        let (db, _temp) = create_test_db();

        db.put_raw("data", b"prefix1:a", b"data1").unwrap();
        db.put_raw("data", b"prefix1:b", b"data2").unwrap();
        db.put_raw("data", b"prefix2:a", b"data3").unwrap();

        let deleted = db.prefix_delete("data", b"prefix1:").unwrap();
        assert_eq!(deleted, 2);

        assert!(db.exists("data", b"prefix2:a").unwrap());
        assert!(!db.exists("data", b"prefix1:a").unwrap());
    }

    #[test]
    fn test_server_config() {
        let config = RocksDbConfig::for_server();
        assert_eq!(config.max_open_files, 256);
        assert_eq!(config.max_wal_size, 64 * 1024 * 1024);
    }

    #[test]
    fn test_get_missing_key() {
        let (db, _temp) = create_test_db();
        let result: Option<TestData> = db.get("data", b"nonexistent").unwrap();
        assert!(result.is_none());
    }
}
