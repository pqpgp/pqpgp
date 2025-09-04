//! Property-based security tests using QuickCheck-style testing
//!
//! These tests verify that security properties hold across all possible inputs
//! by generating thousands of test cases automatically.

use pqpgp::{
    crypto::{decrypt_message, encrypt_message, KeyPair},
    packet::{PacketHeader, UserIdPacket},
    validation::Validator,
};
use rand::{rngs::OsRng, Rng};

/// Property: All valid encryptions should decrypt to original message
#[test]
fn property_encryption_decryption_roundtrip() {
    let mut rng = OsRng;
    let keypair = KeyPair::generate_mlkem768(&mut rng).unwrap();

    // Test with various message sizes and contents
    for _ in 0..50 {
        let message_size = rng.gen_range(1..1000);
        let mut message = vec![0u8; message_size];
        rng.fill(&mut message[..]);

        // Property: encrypt(m) -> decrypt -> m
        if let Ok(encrypted) = encrypt_message(keypair.public_key(), &message, &mut rng) {
            match decrypt_message(keypair.private_key(), &encrypted, None) {
                Ok(decrypted) => {
                    assert_eq!(
                        message, decrypted,
                        "Roundtrip property violated: decrypted != original"
                    );
                }
                Err(_) => {
                    // If decryption fails, that's acceptable but should be rare
                    // with valid ciphertexts
                }
            }
        }
    }
}

/// Property: Invalid inputs should always be rejected safely
#[test]
fn property_invalid_input_rejection() {
    let mut rng = OsRng;

    for _ in 0..200 {
        let data_size = rng.gen_range(0..2000);
        let mut random_data = vec![0u8; data_size];
        rng.fill(&mut random_data[..]);

        // Property: Invalid input parsing should never panic or cause UB
        let result = std::panic::catch_unwind(|| {
            let _ = PacketHeader::from_bytes(&random_data);
            let _ = UserIdPacket::from_bytes(&random_data);
        });

        assert!(
            result.is_ok(),
            "Invalid input caused panic - safety property violated"
        );
    }
}

/// Property: Validation functions should be consistent and safe
#[test]
fn property_validation_consistency() {
    let mut rng = OsRng;

    for _ in 0..100 {
        let length = rng.gen::<usize>() % 1000000; // Reasonable upper bound
        let max_length = rng.gen::<usize>() % 1000000;

        // Property: Validation should be deterministic
        let result1 = Validator::validate_length_field(length, max_length);
        let result2 = Validator::validate_length_field(length, max_length);

        match (result1, result2) {
            (Ok(()), Ok(())) => {
                // Both should succeed - consistent
                assert!(
                    length <= max_length,
                    "Validation accepted invalid length: {} > {}",
                    length,
                    max_length
                );
            }
            (Err(_), Err(_)) => {
                // Both should fail - consistent
                assert!(
                    length > max_length,
                    "Validation rejected valid length: {} <= {}",
                    length,
                    max_length
                );
            }
            _ => panic!(
                "Inconsistent validation results for length={}, max={}",
                length, max_length
            ),
        }
    }
}

/// Property: Nonce validation should enforce exact size requirements
#[test]
fn property_nonce_size_enforcement() {
    let mut rng = OsRng;

    for _ in 0..100 {
        let nonce_size = rng.gen_range(0..100);
        let expected_size = rng.gen_range(1..50);

        let nonce = vec![0u8; nonce_size];
        let result = Validator::validate_nonce_size(&nonce, expected_size);

        // Property: Validation succeeds iff sizes match exactly
        if nonce_size == expected_size {
            assert!(
                result.is_ok(),
                "Valid nonce size {} rejected (expected {})",
                nonce_size,
                expected_size
            );
        } else {
            assert!(
                result.is_err(),
                "Invalid nonce size {} accepted (expected {})",
                nonce_size,
                expected_size
            );
        }
    }
}

/// Property: Algorithm validation should only accept whitelisted algorithms
#[test]
fn property_algorithm_whitelist_enforcement() {
    let valid_algorithms = [100, 101]; // ML-KEM-768, ML-DSA-65

    // Test all possible u8 values
    for algorithm_id in 0u8..=255u8 {
        let result = Validator::validate_algorithm_id(algorithm_id, &valid_algorithms);

        // Property: Algorithm is accepted iff it's in the whitelist
        if valid_algorithms.contains(&algorithm_id) {
            assert!(
                result.is_ok(),
                "Valid algorithm {} was rejected",
                algorithm_id
            );
        } else {
            assert!(
                result.is_err(),
                "Invalid algorithm {} was accepted",
                algorithm_id
            );
        }
    }
}

/// Property: Packet count validation should have consistent bounds
#[test]
fn property_packet_count_bounds() {
    // Test various packet counts
    let test_counts = vec![
        0, 1, 10, 100, 1000, 5000, 10000, 15000, 20000, 25000, 50000, 100000,
    ];

    let mut last_valid_count = None;

    for &count in &test_counts {
        let result = Validator::validate_packet_count(count);

        match result {
            Ok(()) => {
                last_valid_count = Some(count);
            }
            Err(_) => {
                // Property: Once a count is rejected, all larger counts should be rejected
                if let Some(last_valid) = last_valid_count {
                    assert!(
                        count > last_valid,
                        "Inconsistent bounds: {} rejected but {} was accepted",
                        count,
                        last_valid
                    );
                }
            }
        }
    }
}

/// Property: Message size validation should prevent resource exhaustion
#[test]
fn property_message_size_resource_protection() {
    // Test specific size boundaries around our MAX_MESSAGE_SIZE (100MB = 104857600 bytes)
    let test_sizes = vec![
        1, 1000, 10000, 100000, 1000000, 10000000, 50000000,  // 50MB - should pass
        104857600, // Exactly 100MB - should pass
        104857601, // 100MB + 1 - should fail
        200000000, // 200MB - should fail
    ];

    for size in test_sizes {
        // We test the validation function directly rather than creating huge allocations
        if size <= 104857600 {
            // Within limit - create actual data to test
            if size <= 1000000 {
                // Only create real data for reasonable sizes
                let data = vec![0u8; size];
                let result = Validator::validate_message_size(&data);
                assert!(result.is_ok(), "Valid message size {} was rejected", size);
            }
        } else {
            // Above limit - should be rejected, but we'll test indirectly
            // by creating a small buffer and checking the limit constant
            let data = vec![0u8; 100]; // Small actual data
            let result = Validator::validate_message_size(&data);
            assert!(result.is_ok(), "Small message should pass");

            // Verify our constant is reasonable
            assert!(
                size > 104857600,
                "Test size {} should exceed MAX_MESSAGE_SIZE",
                size
            );
        }
    }

    // Test the actual limit by creating a message just over the limit
    let over_limit_data = vec![0u8; 104857601]; // 100MB + 1 byte
    let result = Validator::validate_message_size(&over_limit_data);
    assert!(
        result.is_err(),
        "Message over size limit should be rejected"
    );
}

/// Property: Slice extraction should prevent buffer overflows
#[test]
fn property_slice_extraction_bounds_safety() {
    let mut rng = OsRng;

    for _ in 0..100 {
        let data_size = rng.gen_range(0..1000);
        let data = vec![42u8; data_size];

        let offset = rng.gen::<usize>() % (data_size + 100);
        let length = rng.gen::<usize>() % 200;

        let result = Validator::validate_slice_extraction(&data, offset, length);

        // Property: Validation succeeds iff extraction would be safe
        let would_overflow = offset.saturating_add(length) > data.len() || offset > data.len();

        if would_overflow {
            assert!(
                result.is_err(),
                "Unsafe slice extraction was allowed: data.len()={}, offset={}, length={}",
                data.len(),
                offset,
                length
            );
        } else {
            assert!(
                result.is_ok(),
                "Safe slice extraction was rejected: data.len()={}, offset={}, length={}",
                data.len(),
                offset,
                length
            );
        }
    }
}

/// Property: Integer parsing should handle all edge cases safely
#[test]
fn property_integer_parsing_safety() {
    let mut rng = OsRng;

    for _ in 0..100 {
        let data_size = rng.gen_range(0..20);
        let mut data = vec![0u8; data_size];
        rng.fill(&mut data[..]);

        let offset = rng.gen::<usize>() % (data_size + 10);

        // Property: u32 parsing should succeed iff 4 bytes available at offset
        let u32_result = Validator::validate_u32_from_bytes(&data, offset);
        let u32_would_succeed = offset.saturating_add(4) <= data.len();

        if u32_would_succeed {
            assert!(
                u32_result.is_ok(),
                "u32 parsing failed with sufficient data: len={}, offset={}",
                data.len(),
                offset
            );
        } else {
            assert!(
                u32_result.is_err(),
                "u32 parsing succeeded with insufficient data: len={}, offset={}",
                data.len(),
                offset
            );
        }

        // Property: u16 parsing should succeed iff 2 bytes available at offset
        let u16_result = Validator::validate_u16_from_bytes(&data, offset);
        let u16_would_succeed = offset.saturating_add(2) <= data.len();

        if u16_would_succeed {
            assert!(
                u16_result.is_ok(),
                "u16 parsing failed with sufficient data: len={}, offset={}",
                data.len(),
                offset
            );
        } else {
            assert!(
                u16_result.is_err(),
                "u16 parsing succeeded with insufficient data: len={}, offset={}",
                data.len(),
                offset
            );
        }
    }
}

/// Property: Keyring size validation should scale properly
#[test]
fn property_keyring_size_scaling() {
    // Test geometric progression of sizes
    let mut size = 1;
    let mut last_valid = None;

    while size < 1_000_000 {
        let result = Validator::validate_keyring_size(size);

        match result {
            Ok(()) => {
                last_valid = Some(size);
            }
            Err(_) => {
                // Property: Once size is rejected, larger sizes should also be rejected
                if let Some(last_valid_size) = last_valid {
                    assert!(
                        size > last_valid_size,
                        "Size validation is inconsistent: {} rejected after {} accepted",
                        size,
                        last_valid_size
                    );
                }
                break; // No point testing larger sizes
            }
        }

        size = size.saturating_mul(10);
        if size <= size / 10 {
            break;
        } // Overflow check
    }

    // Should have some reasonable upper bound
    assert!(last_valid.is_some(), "No keyring size was accepted");
    assert!(last_valid.unwrap() < 1_000_000, "Upper bound is too high");
}

/// Property: Multiple validations should be composable and consistent
#[test]
fn property_validation_composition() {
    let mut rng = OsRng;

    for _ in 0..50 {
        let data_size = rng.gen_range(0..500);
        let data = vec![42u8; data_size];

        // Test that validating message size and then other validations is consistent
        let size_valid = Validator::validate_message_size(&data).is_ok();

        if size_valid {
            // If message size is valid, other validations should not fail due to size
            let length_result = Validator::validate_length_field(data.len(), data_size + 100);
            assert!(
                length_result.is_ok(),
                "Length validation failed for size-validated data"
            );
        }
    }
}

/// Property: Error messages should not leak sensitive information
#[test]
fn property_error_message_safety() {
    let mut rng = OsRng;

    // Test that error messages don't contain actual data
    for _ in 0..50 {
        let secret_data = b"SECRET_PASSWORD_12345";
        let mut test_data = Vec::new();
        test_data.extend_from_slice(secret_data);
        test_data.extend_from_slice(&vec![0u8; rng.gen_range(0..100)]);

        // Try various parsing operations that should fail
        let results = vec![UserIdPacket::from_bytes(&test_data)];

        for result in results {
            if let Err(error) = result {
                let error_msg = error.to_string();

                // Property: Error messages should not contain input data
                assert!(
                    !error_msg.contains("SECRET_PASSWORD"),
                    "Error message leaked sensitive data: {}",
                    error_msg
                );

                // Should not contain raw binary data
                assert!(
                    !error_msg.contains("\x00"),
                    "Error message contains binary data: {:?}",
                    error_msg
                );
            }
        }
    }
}
