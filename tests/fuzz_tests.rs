//! Fuzzing and property-based security tests for PQPGP
//!
//! These tests use property-based testing and fuzzing techniques to discover
//! edge cases and potential vulnerabilities through automated test generation.

use pqpgp::{
    crypto::{encrypt_message, KeyPair},
    packet::{Packet, PacketHeader, PacketType, PublicKeyPacket, UserIdPacket},
    validation::Validator,
};
use rand::{rngs::OsRng, Rng};

/// Property-based test for packet parsing robustness
#[test]
fn fuzz_packet_parsing() {
    let mut rng = OsRng;

    // Test with 1000 random byte sequences
    for _ in 0..1000 {
        // Generate random data of varying sizes
        let size = rng.gen_range(0..10000);
        let mut random_data = vec![0u8; size];
        rng.fill(&mut random_data[..]);

        // Packet parsing should never panic, only return errors
        let result = std::panic::catch_unwind(|| {
            let _ = PacketHeader::from_bytes(&random_data);
            let _ = Packet::from_bytes(&random_data);
        });

        // Ensure no panics occurred
        assert!(result.is_ok(), "Packet parsing panicked on random input");
    }
}

/// Test encryption/decryption with malformed keys
#[test]
fn fuzz_key_operations() {
    let mut rng = OsRng;

    // Test with various key sizes and malformed key data
    for key_size in [0, 1, 32, 64, 128, 256, 512, 1024, 2048, 4096] {
        let mut fake_key_data = vec![0u8; key_size];
        rng.fill(&mut fake_key_data[..]);

        // Try to create keys from random data - should fail gracefully
        let result = std::panic::catch_unwind(|| {
            // This will fail but should not panic
            let _ = PublicKeyPacket::from_bytes(&fake_key_data);
        });

        assert!(result.is_ok(), "Key parsing panicked on malformed input");
    }
}

/// Test User ID parsing with various edge cases
#[test]
fn fuzz_user_id_parsing() {
    let mut rng = OsRng;

    // Test edge cases for User ID parsing
    let test_cases = vec![
        vec![],                         // Empty
        vec![0],                        // Single null byte
        vec![255; 1000],                // All 0xFF bytes
        vec![128; 500],                 // High ASCII values
        (0..=255).collect::<Vec<u8>>(), // All possible byte values
    ];

    for case in test_cases {
        let result = std::panic::catch_unwind(|| {
            let _ = UserIdPacket::from_bytes(&case);
        });
        assert!(result.is_ok(), "User ID parsing panicked");
    }

    // Additional random fuzzing
    for _ in 0..500 {
        let size = rng.gen_range(0..2000);
        let mut random_data = vec![0u8; size];
        rng.fill(&mut random_data[..]);

        let result = std::panic::catch_unwind(|| {
            let _ = UserIdPacket::from_bytes(&random_data);
        });
        assert!(result.is_ok(), "User ID parsing panicked on random input");
    }
}

/// Test encryption with extreme message sizes
#[test]
fn fuzz_message_sizes() {
    let keypair = KeyPair::generate_mlkem1024().unwrap();

    // Test various message sizes including edge cases
    let sizes = vec![
        0, 1, 15, 16, 17, 255, 256, 257, 1023, 1024, 1025, 65535, 65536, 65537,
    ];

    for size in sizes {
        let message = vec![42u8; size];

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = encrypt_message(keypair.public_key(), &message);
        }));

        assert!(
            result.is_ok(),
            "Encryption panicked with message size {}",
            size
        );
    }
}

/// Test with malformed packet headers
#[test]
fn fuzz_packet_headers() {
    let mut rng = OsRng;

    // Test various packet header formats
    for _ in 0..1000 {
        // Generate random header-like data
        let header_size = rng.gen_range(1..50);
        let mut header_data = vec![0u8; header_size];
        rng.fill(&mut header_data[..]);

        // Ensure first byte has MSB set (valid packet format requirement)
        if !header_data.is_empty() {
            header_data[0] |= 0x80;
        }

        let result = std::panic::catch_unwind(|| {
            let _ = PacketHeader::from_bytes(&header_data);
        });

        assert!(result.is_ok(), "Packet header parsing panicked");
    }
}

/// Test validation functions with extreme inputs
#[test]
fn fuzz_validation_functions() {
    let mut rng = OsRng;

    // Test length field validation with random values
    for _ in 0..500 {
        let length = rng.gen::<usize>();
        let max_length = rng.gen_range(1..usize::MAX / 2);

        let result = std::panic::catch_unwind(|| {
            let _ = Validator::validate_length_field(length, max_length);
        });

        assert!(result.is_ok(), "Length validation panicked");
    }

    // Test packet count validation
    for _ in 0..500 {
        let count = rng.gen::<usize>();

        let result = std::panic::catch_unwind(|| {
            let _ = Validator::validate_packet_count(count);
        });

        assert!(result.is_ok(), "Packet count validation panicked");
    }

    // Test keyring size validation
    for _ in 0..500 {
        let size = rng.gen::<usize>();

        let result = std::panic::catch_unwind(|| {
            let _ = Validator::validate_keyring_size(size);
        });

        assert!(result.is_ok(), "Keyring size validation panicked");
    }
}

/// Test byte parsing functions with malformed input
#[test]
fn fuzz_byte_parsing() {
    let mut rng = OsRng;

    for _ in 0..1000 {
        let data_size = rng.gen_range(0..100);
        let mut data = vec![0u8; data_size];
        rng.fill(&mut data[..]);

        let offset = rng.gen_range(0..data.len().saturating_add(10));

        // Test u32 parsing
        let result = std::panic::catch_unwind(|| {
            let _ = Validator::validate_u32_from_bytes(&data, offset);
        });
        assert!(result.is_ok(), "u32 parsing panicked");

        // Test u16 parsing
        let result = std::panic::catch_unwind(|| {
            let _ = Validator::validate_u16_from_bytes(&data, offset);
        });
        assert!(result.is_ok(), "u16 parsing panicked");

        // Test slice extraction
        let length = rng.gen_range(0..50);
        let result = std::panic::catch_unwind(|| {
            let _ = Validator::validate_slice_extraction(&data, offset, length);
        });
        assert!(result.is_ok(), "Slice extraction panicked");
    }
}

/// Test nonce validation with various sizes
#[test]
fn fuzz_nonce_validation() {
    let mut rng = OsRng;

    for _ in 0..500 {
        let nonce_size = rng.gen_range(0..100);
        let mut nonce = vec![0u8; nonce_size];
        rng.fill(&mut nonce[..]);

        let expected_size = rng.gen_range(1..50);

        let result = std::panic::catch_unwind(|| {
            let _ = Validator::validate_nonce_size(&nonce, expected_size);
        });

        assert!(result.is_ok(), "Nonce validation panicked");
    }
}

/// Test algorithm ID validation with random IDs
#[test]
fn fuzz_algorithm_validation() {
    let mut rng = OsRng;
    let valid_algorithms = [100, 101];

    for _ in 0..500 {
        let algorithm_id = rng.gen::<u8>();

        let result = std::panic::catch_unwind(|| {
            let _ = Validator::validate_algorithm_id(algorithm_id, &valid_algorithms);
        });

        assert!(result.is_ok(), "Algorithm validation panicked");
    }
}

/// Adversarial test: Try to cause integer overflows
#[test]
fn adversarial_integer_overflow_test() {
    // Test with values near integer limits
    let extreme_values = vec![
        0,
        1,
        u8::MAX as usize,
        u16::MAX as usize,
        u32::MAX as usize,
        usize::MAX,
        usize::MAX - 1,
        usize::MAX / 2,
    ];

    for &value in &extreme_values {
        let result = std::panic::catch_unwind(|| {
            let _ = Validator::validate_length_field(value, 1000);
            let _ = Validator::validate_packet_count(value);
            let _ = Validator::validate_keyring_size(value);
        });

        assert!(
            result.is_ok(),
            "Validation panicked with extreme value: {}",
            value
        );
    }
}

/// Adversarial test: Memory exhaustion attempts
#[test]
fn adversarial_memory_exhaustion_test() {
    // Try to create packets claiming extremely large sizes
    let malicious_sizes = vec![
        1_000_000,     // 1MB
        10_000_000,    // 10MB
        100_000_000,   // 100MB
        1_000_000_000, // 1GB (should be rejected)
        u32::MAX as usize,
    ];

    for &size in &malicious_sizes {
        let result = std::panic::catch_unwind(|| {
            // Try to create a packet header claiming this size
            let header = PacketHeader::new(PacketType::PublicKey, size);
            let header_bytes = header.to_bytes();

            // Try to parse it back
            let _ = PacketHeader::from_bytes(&header_bytes);

            // Try to validate the size
            let _ = Validator::validate_length_field(size, 1000);
        });

        assert!(
            result.is_ok(),
            "Memory exhaustion test panicked with size: {}",
            size
        );
    }
}

/// Test concurrent access patterns
#[test]
fn fuzz_concurrent_operations() {
    use std::sync::Arc;
    use std::thread;

    let keypair = Arc::new(KeyPair::generate_mlkem1024().unwrap());

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let keypair = keypair.clone();
            thread::spawn(move || {
                let mut local_rng = OsRng;

                // Each thread performs random operations
                for _ in 0..50 {
                    let message_size = local_rng.gen_range(0..1000);
                    let message = vec![42u8; message_size];

                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _ = encrypt_message(keypair.public_key(), &message);
                    }));

                    assert!(result.is_ok(), "Concurrent encryption panicked");
                }
            })
        })
        .collect();

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
}
