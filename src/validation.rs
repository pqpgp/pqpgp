//! Comprehensive input validation and security limits for PQPGP
//!
//! This module provides validation functions and security limits to prevent
//! various attacks including buffer overflows, resource exhaustion, and
//! malformed input attacks.

use crate::error::{PqpgpError, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Maximum allowed message size (100MB)
///
/// This limit prevents memory exhaustion attacks and ensures reasonable memory usage.
/// For larger data, applications should implement chunking using `encrypt_messages()`.
pub const MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;

/// Maximum allowed encrypted message size (110MB to account for overhead)
pub const MAX_ENCRYPTED_SIZE: usize = 110 * 1024 * 1024;

/// Maximum allowed signature size (10KB - generous for post-quantum signatures)
pub const MAX_SIGNATURE_SIZE: usize = 10 * 1024;

/// Maximum allowed key material size (10KB - generous for post-quantum keys)
pub const MAX_KEY_SIZE: usize = 10 * 1024;

/// Maximum allowed packet size (50MB - for large encrypted messages)
pub const MAX_PACKET_SIZE: usize = 50 * 1024 * 1024;

/// Maximum allowed User ID length (1KB)
pub const MAX_USER_ID_LENGTH: usize = 1024;

/// Maximum allowed number of packets in a message
pub const MAX_PACKETS_PER_MESSAGE: usize = 1000;

/// Maximum allowed number of keys in a keyring
pub const MAX_KEYS_PER_KEYRING: usize = 10000;

/// Maximum allowed nesting depth for packets
pub const MAX_PACKET_NESTING_DEPTH: usize = 10;

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimit {
    /// Maximum operations per time window
    pub max_operations: usize,
    /// Time window for rate limiting
    pub time_window: Duration,
}

impl RateLimit {
    /// Create a new rate limit configuration
    pub fn new(max_operations: usize, time_window: Duration) -> Self {
        Self {
            max_operations,
            time_window,
        }
    }

    /// Default rate limit for key generation (5 keys per minute)
    pub fn key_generation_default() -> Self {
        Self::new(5, Duration::from_secs(60))
    }

    /// Default rate limit for encryption operations (100 per minute)
    pub fn encryption_default() -> Self {
        Self::new(100, Duration::from_secs(60))
    }

    /// Default rate limit for signature operations (100 per minute)  
    pub fn signature_default() -> Self {
        Self::new(100, Duration::from_secs(60))
    }
}

/// Rate limiter to prevent resource exhaustion attacks
#[derive(Debug)]
pub struct RateLimiter {
    operations: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    config: RateLimit,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration
    pub fn new(config: RateLimit) -> Self {
        Self {
            operations: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Check if an operation is allowed for the given identifier
    pub fn check_rate_limit(&self, identifier: &str) -> Result<()> {
        let mut operations = self.operations.lock().unwrap();
        let now = Instant::now();

        // Get or create operation history for this identifier
        let history = operations.entry(identifier.to_string()).or_default();

        // Remove old entries outside the time window
        history.retain(|&time| now.duration_since(time) < self.config.time_window);

        // Check if we've exceeded the rate limit
        if history.len() >= self.config.max_operations {
            return Err(PqpgpError::validation(format!(
                "Rate limit exceeded: {} operations in {:?}",
                self.config.max_operations, self.config.time_window
            )));
        }

        // Record this operation
        history.push(now);
        Ok(())
    }
}

/// Validation functions for input data
pub struct Validator;

impl Validator {
    /// Validate message size
    pub fn validate_message_size(data: &[u8]) -> Result<()> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(PqpgpError::validation(format!(
                "Message too large: {} bytes exceeds maximum of {} bytes",
                data.len(),
                MAX_MESSAGE_SIZE
            )));
        }
        Ok(())
    }

    /// Validate encrypted message size
    pub fn validate_encrypted_size(data: &[u8]) -> Result<()> {
        if data.len() > MAX_ENCRYPTED_SIZE {
            return Err(PqpgpError::validation(format!(
                "Encrypted message too large: {} bytes exceeds maximum of {} bytes",
                data.len(),
                MAX_ENCRYPTED_SIZE
            )));
        }
        Ok(())
    }

    /// Validate signature size
    pub fn validate_signature_size(data: &[u8]) -> Result<()> {
        if data.len() > MAX_SIGNATURE_SIZE {
            return Err(PqpgpError::validation(format!(
                "Signature too large: {} bytes exceeds maximum of {} bytes",
                data.len(),
                MAX_SIGNATURE_SIZE
            )));
        }
        Ok(())
    }

    /// Validate key material size
    pub fn validate_key_size(data: &[u8]) -> Result<()> {
        if data.len() > MAX_KEY_SIZE {
            return Err(PqpgpError::validation(format!(
                "Key material too large: {} bytes exceeds maximum of {} bytes",
                data.len(),
                MAX_KEY_SIZE
            )));
        }
        Ok(())
    }

    /// Validate packet size
    pub fn validate_packet_size(size: usize) -> Result<()> {
        if size > MAX_PACKET_SIZE {
            return Err(PqpgpError::validation(format!(
                "Packet too large: {} bytes exceeds maximum of {} bytes",
                size, MAX_PACKET_SIZE
            )));
        }
        Ok(())
    }

    /// Validate User ID string
    pub fn validate_user_id(user_id: &str) -> Result<()> {
        // Check length
        if user_id.len() > MAX_USER_ID_LENGTH {
            return Err(PqpgpError::validation(format!(
                "User ID too long: {} bytes exceeds maximum of {} bytes",
                user_id.len(),
                MAX_USER_ID_LENGTH
            )));
        }

        // Check for null bytes (security issue)
        if user_id.contains('\0') {
            return Err(PqpgpError::validation("User ID contains null bytes"));
        }

        // Check for control characters (except tab, newline, carriage return)
        if user_id
            .chars()
            .any(|c| c.is_control() && c != '\t' && c != '\n' && c != '\r')
        {
            return Err(PqpgpError::validation(
                "User ID contains invalid control characters",
            ));
        }

        // Must not be empty
        if user_id.trim().is_empty() {
            return Err(PqpgpError::validation("User ID cannot be empty"));
        }

        Ok(())
    }

    /// Validate packet count in a message
    pub fn validate_packet_count(count: usize) -> Result<()> {
        if count > MAX_PACKETS_PER_MESSAGE {
            return Err(PqpgpError::validation(format!(
                "Too many packets: {} exceeds maximum of {}",
                count, MAX_PACKETS_PER_MESSAGE
            )));
        }
        Ok(())
    }

    /// Validate keyring size
    pub fn validate_keyring_size(count: usize) -> Result<()> {
        if count > MAX_KEYS_PER_KEYRING {
            return Err(PqpgpError::validation(format!(
                "Too many keys in keyring: {} exceeds maximum of {}",
                count, MAX_KEYS_PER_KEYRING
            )));
        }
        Ok(())
    }

    /// Validate integer parsing with bounds checking
    pub fn validate_u32_from_bytes(data: &[u8], offset: usize) -> Result<u32> {
        if data.len() < offset + 4 {
            return Err(PqpgpError::validation(format!(
                "Insufficient data for u32: need {} bytes, have {} bytes",
                offset + 4,
                data.len()
            )));
        }

        let bytes = [
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ];
        Ok(u32::from_be_bytes(bytes))
    }

    /// Validate integer parsing with bounds checking
    pub fn validate_u16_from_bytes(data: &[u8], offset: usize) -> Result<u16> {
        if data.len() < offset + 2 {
            return Err(PqpgpError::validation(format!(
                "Insufficient data for u16: need {} bytes, have {} bytes",
                offset + 2,
                data.len()
            )));
        }

        let bytes = [data[offset], data[offset + 1]];
        Ok(u16::from_be_bytes(bytes))
    }

    /// Validate slice extraction with bounds checking
    pub fn validate_slice_extraction(data: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
        if data.len() < offset + length {
            return Err(PqpgpError::validation(format!(
                "Slice out of bounds: trying to extract {} bytes at offset {} from {} byte array",
                length,
                offset,
                data.len()
            )));
        }

        Ok(&data[offset..offset + length])
    }

    /// Validate that a length field is reasonable (not obviously malicious)
    pub fn validate_length_field(length: usize, max_reasonable: usize) -> Result<()> {
        if length > max_reasonable {
            return Err(PqpgpError::validation(format!(
                "Suspiciously large length field: {} exceeds reasonable maximum of {}",
                length, max_reasonable
            )));
        }
        Ok(())
    }

    /// Validate nonce/IV size for specific algorithm
    pub fn validate_nonce_size(nonce: &[u8], expected_size: usize) -> Result<()> {
        if nonce.len() != expected_size {
            return Err(PqpgpError::validation(format!(
                "Invalid nonce size: got {} bytes, expected {} bytes",
                nonce.len(),
                expected_size
            )));
        }
        Ok(())
    }

    /// Validate algorithm identifier is supported
    pub fn validate_algorithm_id(algorithm_id: u8, valid_algorithms: &[u8]) -> Result<()> {
        if !valid_algorithms.contains(&algorithm_id) {
            return Err(PqpgpError::validation(format!(
                "Unsupported algorithm ID: {}",
                algorithm_id
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_message_size_validation() {
        // Valid size should pass
        let small_message = vec![0u8; 1000];
        assert!(Validator::validate_message_size(&small_message).is_ok());

        // Oversized message should fail
        let large_message = vec![0u8; MAX_MESSAGE_SIZE + 1];
        assert!(Validator::validate_message_size(&large_message).is_err());
    }

    #[test]
    fn test_user_id_validation() {
        // Valid User ID should pass
        assert!(Validator::validate_user_id("Alice <alice@example.com>").is_ok());

        // Empty User ID should fail
        assert!(Validator::validate_user_id("").is_err());
        assert!(Validator::validate_user_id("   ").is_err());

        // User ID with null bytes should fail
        assert!(Validator::validate_user_id("Alice\0<alice@example.com>").is_err());

        // User ID with control characters should fail
        assert!(Validator::validate_user_id("Alice\x01<alice@example.com>").is_err());

        // Oversized User ID should fail
        let long_user_id = "A".repeat(MAX_USER_ID_LENGTH + 1);
        assert!(Validator::validate_user_id(&long_user_id).is_err());
    }

    #[test]
    fn test_bounds_checking() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8];

        // Valid extraction should work
        assert!(Validator::validate_u32_from_bytes(&data, 0).is_ok());
        assert!(Validator::validate_u16_from_bytes(&data, 0).is_ok());
        assert!(Validator::validate_slice_extraction(&data, 2, 3).is_ok());

        // Out-of-bounds extraction should fail
        assert!(Validator::validate_u32_from_bytes(&data, 6).is_err());
        assert!(Validator::validate_u16_from_bytes(&data, 8).is_err());
        assert!(Validator::validate_slice_extraction(&data, 5, 5).is_err());
    }

    #[test]
    fn test_rate_limiter() {
        let config = RateLimit::new(2, Duration::from_millis(100));
        let limiter = RateLimiter::new(config);

        // First two operations should succeed
        assert!(limiter.check_rate_limit("test").is_ok());
        assert!(limiter.check_rate_limit("test").is_ok());

        // Third operation should fail
        assert!(limiter.check_rate_limit("test").is_err());

        // After waiting, should work again
        thread::sleep(Duration::from_millis(150));
        assert!(limiter.check_rate_limit("test").is_ok());
    }

    #[test]
    fn test_algorithm_validation() {
        let valid_algorithms = [100, 101, 102];

        // Valid algorithm should pass
        assert!(Validator::validate_algorithm_id(100, &valid_algorithms).is_ok());

        // Invalid algorithm should fail
        assert!(Validator::validate_algorithm_id(99, &valid_algorithms).is_err());
    }
}
