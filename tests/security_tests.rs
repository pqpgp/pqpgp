//! Security-focused tests for PQPGP validation and attack prevention
//!
//! These tests verify that the validation mechanisms prevent various types
//! of attacks including buffer overflows, resource exhaustion, and malformed
//! input attacks.

use pqpgp::{
    crypto::{encrypt_message, KeyPair},
    packet::{Packet, PacketHeader, PacketType, PublicKeyPacket, UserIdPacket},
    validation::{RateLimit, RateLimiter, Validator, MAX_MESSAGE_SIZE},
    PqpgpError,
};
use rand::rngs::OsRng;
use std::time::Duration;

#[test]
fn test_oversized_message_rejected() {
    let mut rng = OsRng;
    let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();

    // Create a message that exceeds the maximum size
    let oversized_message = vec![0u8; MAX_MESSAGE_SIZE + 1];

    // This should fail with validation error
    let result = encrypt_message(keypair.public_key(), &oversized_message, &mut rng);
    assert!(result.is_err());

    match result.unwrap_err() {
        PqpgpError::Validation(msg) => {
            assert!(msg.contains("Message too large"));
        }
        _ => panic!("Expected validation error"),
    }
}

#[test]
fn test_malformed_packet_header_rejected() {
    // Test with empty data
    let result = PacketHeader::from_bytes(&[]);
    assert!(result.is_err());

    // Test with invalid header (MSB not set)
    let result = PacketHeader::from_bytes(&[0x00, 0x01]);
    assert!(result.is_err());

    // Test with incomplete header
    let result = PacketHeader::from_bytes(&[0xC6]); // New format, missing length
    assert!(result.is_err());

    // Test with malicious length field (extremely large)
    let malicious_packet = [0xC6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let result = PacketHeader::from_bytes(&malicious_packet);
    assert!(result.is_err());
}

#[test]
fn test_malformed_public_key_packet_rejected() {
    // Test with insufficient data
    let result = PublicKeyPacket::from_bytes(&[1, 2, 3]);
    assert!(result.is_err());

    // Test with invalid version
    let invalid_version = [5, 0, 0, 0, 1, 100, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
    let result = PublicKeyPacket::from_bytes(&invalid_version);
    assert!(result.is_err());

    // Test with invalid algorithm
    let invalid_algorithm = [4, 0, 0, 0, 1, 99, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
    let result = PublicKeyPacket::from_bytes(&invalid_algorithm);
    assert!(result.is_err());

    // Test with malicious key length (extremely large)
    let malicious_key_length = [4, 0, 0, 0, 1, 100, 0xFF, 0xFF]; // 65535 bit length
    let result = PublicKeyPacket::from_bytes(&malicious_key_length);
    assert!(result.is_err());
}

#[test]
fn test_malicious_user_id_rejected() {
    // Test with null bytes (security issue)
    let malicious_user_id = b"Alice\x00<alice@example.com>";
    let result = UserIdPacket::from_bytes(malicious_user_id);
    assert!(result.is_err());

    // Test with control characters
    let control_chars_user_id = b"Alice\x01<alice@example.com>";
    let result = UserIdPacket::from_bytes(control_chars_user_id);
    assert!(result.is_err());

    // Test with empty User ID
    let result = UserIdPacket::from_bytes(b"");
    assert!(result.is_err());

    // Test with whitespace-only User ID
    let result = UserIdPacket::from_bytes(b"   ");
    assert!(result.is_err());

    // Test with oversized User ID
    let oversized_user_id = vec![b'A'; 2000]; // Exceeds MAX_USER_ID_LENGTH
    let result = UserIdPacket::from_bytes(&oversized_user_id);
    assert!(result.is_err());
}

#[test]
fn test_integer_overflow_protection() {
    // Test u32 parsing with insufficient data
    let data = [1, 2, 3]; // Only 3 bytes
    let result = Validator::validate_u32_from_bytes(&data, 0);
    assert!(result.is_err());

    // Test u16 parsing with insufficient data
    let data = [1]; // Only 1 byte
    let result = Validator::validate_u16_from_bytes(&data, 0);
    assert!(result.is_err());

    // Test slice extraction with out-of-bounds access
    let data = [1, 2, 3, 4];
    let result = Validator::validate_slice_extraction(&data, 2, 5); // Would go beyond array
    assert!(result.is_err());
}

#[test]
fn test_rate_limiting_prevents_dos() {
    let config = RateLimit::new(2, Duration::from_millis(100));
    let limiter = RateLimiter::new(config);

    // First two operations should succeed
    assert!(limiter.check_rate_limit("attacker").is_ok());
    assert!(limiter.check_rate_limit("attacker").is_ok());

    // Third operation should fail (rate limited)
    let result = limiter.check_rate_limit("attacker");
    assert!(result.is_err());

    match result.unwrap_err() {
        PqpgpError::Validation(msg) => {
            assert!(msg.contains("Rate limit exceeded"));
        }
        _ => panic!("Expected validation error"),
    }

    // Different identifier should still work
    assert!(limiter.check_rate_limit("legitimate_user").is_ok());
}

#[test]
fn test_algorithm_id_validation() {
    let valid_algorithms = [100, 101]; // Only ML-KEM-1024 and ML-DSA-87

    // Valid algorithms should pass
    assert!(Validator::validate_algorithm_id(100, &valid_algorithms).is_ok());
    assert!(Validator::validate_algorithm_id(101, &valid_algorithms).is_ok());

    // Invalid algorithms should fail
    assert!(Validator::validate_algorithm_id(99, &valid_algorithms).is_err());
    assert!(Validator::validate_algorithm_id(102, &valid_algorithms).is_err());
    assert!(Validator::validate_algorithm_id(255, &valid_algorithms).is_err());
}

#[test]
fn test_nonce_size_validation() {
    // Valid nonce size should pass
    let valid_nonce = vec![0u8; 12];
    assert!(Validator::validate_nonce_size(&valid_nonce, 12).is_ok());

    // Invalid nonce sizes should fail
    let short_nonce = vec![0u8; 11];
    assert!(Validator::validate_nonce_size(&short_nonce, 12).is_err());

    let long_nonce = vec![0u8; 13];
    assert!(Validator::validate_nonce_size(&long_nonce, 12).is_err());

    let empty_nonce = vec![];
    assert!(Validator::validate_nonce_size(&empty_nonce, 12).is_err());
}

#[test]
fn test_length_field_validation() {
    // Reasonable lengths should pass
    assert!(Validator::validate_length_field(100, 1000).is_ok());
    assert!(Validator::validate_length_field(1000, 1000).is_ok());

    // Unreasonable lengths should fail
    assert!(Validator::validate_length_field(2000, 1000).is_err());
    assert!(Validator::validate_length_field(usize::MAX, 1000).is_err());
}

#[test]
fn test_packet_count_validation() {
    // Reasonable packet count should pass
    assert!(Validator::validate_packet_count(10).is_ok());
    assert!(Validator::validate_packet_count(1000).is_ok());

    // Excessive packet count should fail
    assert!(Validator::validate_packet_count(20000).is_err());
}

#[test]
fn test_keyring_size_validation() {
    // Reasonable keyring size should pass
    assert!(Validator::validate_keyring_size(100).is_ok());
    assert!(Validator::validate_keyring_size(5000).is_ok());

    // Excessive keyring size should fail
    assert!(Validator::validate_keyring_size(20000).is_err());
}

/// Test that demonstrates protection against a buffer overflow attack
#[test]
fn test_buffer_overflow_protection() {
    // Simulate malicious packet with length field claiming more data than available
    let malicious_data = [
        0xC6, // New format packet header, packet type 6 (public key)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Claims packet is 4GB long
        // But only has a few more bytes
        1, 2, 3, 4,
    ];

    // This should be rejected during header parsing
    let result = PacketHeader::from_bytes(&malicious_data);
    assert!(result.is_err());

    // Even if the header parsing passes, packet parsing should fail
    if let Ok((_header, _header_len)) = result {
        let result = Packet::from_bytes(&malicious_data);
        assert!(result.is_err());
    }
}

/// Test that demonstrates protection against resource exhaustion
#[test]
fn test_resource_exhaustion_protection() {
    // Try to create packet claiming to be extremely large
    let header = PacketHeader::new(PacketType::PublicKey, 1000000000); // 1GB

    // This should fail when trying to create the packet
    let large_body = vec![0u8; 1000]; // Much smaller than claimed
                                      // Even if we tried to create this, validation should prevent it
    let packet_bytes = header.to_bytes();
    let mut full_packet = packet_bytes;
    full_packet.extend_from_slice(&large_body);
    let result = Packet::from_bytes(&full_packet);

    // The validation should have prevented any memory allocation issues
    // by rejecting the oversized packet early
    assert!(result.is_err(), "Oversized packet should be rejected");
}

/// Test that demonstrates protection against malformed UTF-8 attacks
#[test]
fn test_utf8_validation() {
    // Invalid UTF-8 sequences should be rejected
    let invalid_utf8 = [0xFF, 0xFE, 0xFD]; // Invalid UTF-8
    let result = UserIdPacket::from_bytes(&invalid_utf8);
    assert!(result.is_err());

    // Valid UTF-8 should pass
    let valid_utf8 = "Alice <alice@example.com>".as_bytes();
    let result = UserIdPacket::from_bytes(valid_utf8);
    assert!(result.is_ok());
}
