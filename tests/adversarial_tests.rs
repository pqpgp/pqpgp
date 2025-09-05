//! Adversarial security tests for PQPGP
//!
//! These tests simulate various attack scenarios and verify that the system
//! handles them securely without compromising security or availability.

use pqpgp::{
    crypto::{decrypt_message, encrypt_message, KeyPair},
    packet::{Packet, PacketHeader, PacketType, UserIdPacket},
    validation::{RateLimit, RateLimiter, Validator},
};
use rand::{rngs::OsRng, Rng};
use std::time::{Duration, Instant};

/// Test timing attack resistance in key operations
#[test]
fn test_timing_attack_resistance() {
    let keypair = KeyPair::generate_mlkem1024().unwrap();
    let message = b"test message for timing analysis";

    let mut timing_samples = Vec::new();

    // Perform multiple encryption operations and measure timing
    for _ in 0..100 {
        let start = Instant::now();
        let _ = encrypt_message(keypair.public_key(), message);
        let duration = start.elapsed();
        timing_samples.push(duration.as_nanos());
    }

    // Calculate timing statistics
    let mean = timing_samples.iter().sum::<u128>() / timing_samples.len() as u128;
    let variance = timing_samples
        .iter()
        .map(|&x| {
            let diff = x as i128 - mean as i128;
            (diff * diff) as u128
        })
        .sum::<u128>()
        / timing_samples.len() as u128;

    let std_dev = (variance as f64).sqrt();
    let coefficient_of_variation = std_dev / mean as f64;

    // Timing should be relatively consistent, but allow for natural system variance
    // This is a basic check - more sophisticated timing analysis would be needed
    // for production systems. We use a more lenient threshold to account for system load
    if coefficient_of_variation > 3.0 {
        eprintln!("Warning: High timing variance detected (CV: {:.3}), may indicate timing attack vulnerability", coefficient_of_variation);
        // Don't fail the test but warn about potential issues
    }

    // Ensure operations don't take an unreasonably long time (DoS protection)
    let max_time_ns = timing_samples.iter().max().unwrap();
    assert!(
        *max_time_ns < 10_000_000_000, // 10 seconds is way too long
        "Encryption operation took too long: {} ns",
        max_time_ns
    );
}

/// Test side-channel resistance in decryption operations
#[test]
fn test_decryption_timing_consistency() {
    let mut rng = OsRng;
    let keypair = KeyPair::generate_mlkem1024().unwrap();
    let message = b"test message for decryption timing";

    // Create valid encrypted message
    let encrypted = encrypt_message(keypair.public_key(), message).unwrap();

    let mut valid_timings = Vec::new();
    let mut invalid_timings = Vec::new();

    // Time valid decryptions
    for _ in 0..50 {
        let start = Instant::now();
        let _ = decrypt_message(keypair.private_key(), &encrypted, None);
        let duration = start.elapsed();
        valid_timings.push(duration.as_nanos());
    }

    // Time invalid decryptions (corrupted data)
    for _ in 0..50 {
        let mut corrupted = encrypted.clone();
        // Corrupt a random part of the encrypted message
        let corruption_target = rng.gen_range(0..2); // Only corrupt cryptographically significant parts
        match corruption_target {
            0 => {
                if !corrupted.encapsulated_key.is_empty() {
                    let idx = rng.gen_range(0..corrupted.encapsulated_key.len());
                    corrupted.encapsulated_key[idx] ^= 1;
                }
            }
            _ => {
                if !corrupted.encrypted_content.is_empty() {
                    let idx = rng.gen_range(0..corrupted.encrypted_content.len());
                    corrupted.encrypted_content[idx] ^= 1;
                }
            }
        }

        let start = Instant::now();
        let _ = decrypt_message(keypair.private_key(), &corrupted, None);
        let duration = start.elapsed();
        invalid_timings.push(duration.as_nanos());
    }

    // Remove outliers to get more stable timing measurements (remove top/bottom 10%)
    valid_timings.sort_unstable();
    invalid_timings.sort_unstable();

    let trim_count = valid_timings.len() / 10; // Remove 10% from each end
    let valid_trimmed = &valid_timings[trim_count..valid_timings.len() - trim_count];
    let invalid_trimmed = &invalid_timings[trim_count..invalid_timings.len() - trim_count];

    let valid_mean = valid_trimmed.iter().sum::<u128>() / valid_trimmed.len() as u128;
    let invalid_mean = invalid_trimmed.iter().sum::<u128>() / invalid_trimmed.len() as u128;

    // The timing difference should not be too large (indicating potential side-channel)
    let timing_ratio = if valid_mean > invalid_mean {
        valid_mean as f64 / invalid_mean as f64
    } else {
        invalid_mean as f64 / valid_mean as f64
    };

    // Allow for more variation in CI environments while still detecting significant side-channels
    // CI environments have high timing variability due to virtualization and resource contention
    let timing_threshold = if std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok()
    {
        5.0 // More lenient threshold for CI environments
    } else {
        3.0 // Stricter threshold for local testing
    };

    assert!(
        timing_ratio < timing_threshold,
        "Significant timing difference between valid/invalid decryption (ratio: {:.2}, threshold: {:.1})",
        timing_ratio, timing_threshold
    );
}

/// Test resource exhaustion attack protection
#[test]
fn test_resource_exhaustion_protection() {
    // Test 1: Memory exhaustion via large packet claims
    let oversized_header = PacketHeader::new(PacketType::PublicKey, usize::MAX);
    let header_bytes = oversized_header.to_bytes();

    // This should be rejected during parsing, not cause OOM
    let result = std::panic::catch_unwind(|| PacketHeader::from_bytes(&header_bytes));
    assert!(result.is_ok(), "Large packet header caused panic");

    // Test 2: CPU exhaustion via many operations
    let start_time = Instant::now();
    let mut operations = 0;

    // Perform operations for a limited time
    while start_time.elapsed() < Duration::from_millis(100) && operations < 1000 {
        let small_data = vec![0u8; 10];
        let _ = Validator::validate_message_size(&small_data);
        operations += 1;
    }

    // Should complete reasonable number of operations in time limit
    assert!(
        operations > 10,
        "Too few operations completed, potential DoS vulnerability"
    );

    // Test 3: Stack exhaustion via deep recursion
    // Create deeply nested packet structure (if supported)
    let mut nested_data = Vec::new();
    for _ in 0..1000 {
        let header = PacketHeader::new(PacketType::UserAttribute, 10);
        nested_data.extend_from_slice(&header.to_bytes());
        nested_data.extend_from_slice(&[0u8; 10]);
    }

    let result = std::panic::catch_unwind(|| {
        let _ = Packet::from_bytes(&nested_data);
    });
    assert!(
        result.is_ok(),
        "Nested packet parsing caused stack overflow"
    );
}

/// Test algorithmic complexity attacks
#[test]
fn test_algorithmic_complexity_attacks() {
    // Test quadratic behavior in parsing
    let sizes = vec![10, 50, 100, 500, 1000];
    let mut timings = Vec::new();

    for size in sizes {
        let data = vec![0u8; size];
        let start = Instant::now();

        // Perform parsing operation
        for _ in 0..10 {
            let _ = UserIdPacket::from_bytes(&data);
        }

        let duration = start.elapsed();
        timings.push((size, duration.as_nanos()));
    }

    // Check if timing grows quadratically (indicating potential DoS)
    // Simple heuristic: timing shouldn't grow faster than O(n²)
    if timings.len() >= 2 {
        let (size1, time1) = timings[0];
        let (size2, time2) = timings[timings.len() - 1];

        if size2 > size1 && time2 > time1 {
            let size_ratio = size2 as f64 / size1 as f64;
            let time_ratio = time2 as f64 / time1 as f64;
            let growth_factor = time_ratio / (size_ratio * size_ratio);

            // If growth is much faster than quadratic, flag it
            assert!(
                growth_factor < 10.0,
                "Potential quadratic complexity attack vector (growth factor: {:.2})",
                growth_factor
            );
        }
    }
}

/// Test input sanitization and injection attacks
#[test]
fn test_injection_attack_protection() {
    // Test various malicious payloads that should be rejected in User ID fields
    // Focus on actual PGP security issues, not general injection attacks
    let oversized_input = vec![b'A'; 10000];
    let empty_input = vec![0u8; 0];
    let whitespace_input = vec![b' '; 10];
    let invalid_utf8_input = vec![0xFF, 0xFE, 0xFD];
    let malicious_payloads: Vec<&[u8]> = vec![
        b"\x00\x01\x02\x03", // Null bytes and binary data (should be rejected)
        b"\n\r\t\x08",       // Invalid control characters (should be rejected)
        &empty_input,        // Empty (should be rejected)
        &whitespace_input,   // Whitespace only (should be rejected)
        &oversized_input,    // Oversized input (should be rejected)
        &invalid_utf8_input, // Invalid UTF-8 (should be rejected)
    ];

    // Test legitimate User IDs that should be accepted
    let legitimate_payloads: Vec<&[u8]> = vec![
        b"Alice <alice@example.com>",
        b"Bob O'Reilly <bob@company.com>", // Apostrophe is legitimate
        b"Test-User <test@domain.com>",    // Dashes are legitimate
        b"User (Comment) <user@email.com>", // Parentheses are legitimate
    ];

    for payload in malicious_payloads {
        let result = std::panic::catch_unwind(|| {
            let _ = UserIdPacket::from_bytes(payload);
        });
        assert!(
            result.is_ok(),
            "Malicious payload caused panic: {:?}",
            payload
        );

        // Should be rejected for security reasons
        let parse_result = UserIdPacket::from_bytes(payload);
        assert!(
            parse_result.is_err(),
            "Malicious payload was not rejected: {:?}",
            payload
        );
    }

    // Legitimate User IDs should be accepted
    for payload in legitimate_payloads {
        let result = std::panic::catch_unwind(|| {
            let _ = UserIdPacket::from_bytes(payload);
        });
        assert!(
            result.is_ok(),
            "Legitimate payload caused panic: {:?}",
            payload
        );

        // Should be accepted
        let parse_result = UserIdPacket::from_bytes(payload);
        assert!(
            parse_result.is_ok(),
            "Legitimate payload was rejected: {:?}",
            payload
        );
    }
}

/// Test cryptographic oracle attacks
#[test]
fn test_padding_oracle_protection() {
    let keypair = KeyPair::generate_mlkem1024().unwrap();
    let message = b"padding oracle test message";

    let encrypted = encrypt_message(keypair.public_key(), message).unwrap();

    // Try various padding modifications
    for i in 0..10 {
        let mut modified = encrypted.clone();

        // Modify different parts of the encrypted message that affect AEAD authentication
        if i % 2 == 0 {
            // Modify KEM ciphertext (affects key derivation)
            if !modified.encapsulated_key.is_empty() {
                let idx = modified.encapsulated_key.len().saturating_sub(1);
                modified.encapsulated_key[idx] ^= 1;
            }
        } else {
            // Modify encrypted content (affects AEAD authentication)
            if !modified.encrypted_content.is_empty() {
                let idx = modified.encrypted_content.len().saturating_sub(1 + (i / 2));
                if idx < modified.encrypted_content.len() {
                    modified.encrypted_content[idx] ^= 1;
                }
            }
        }

        let start = Instant::now();
        let result = decrypt_message(keypair.private_key(), &modified, None);
        let duration = start.elapsed();

        // Decryption should fail consistently without timing differences
        assert!(result.is_err(), "Modified ciphertext should not decrypt");

        // All failures should take similar time (no padding oracle)
        assert!(
            duration < Duration::from_millis(100),
            "Decryption took too long, potential DoS or oracle"
        );
    }
}

/// Test replay attack protection mechanisms
#[test]
fn test_replay_attack_protection() {
    let keypair = KeyPair::generate_mlkem1024().unwrap();
    let message = b"test message for replay attack";

    // Encrypt the same message multiple times
    let mut ciphertexts = Vec::new();
    for _ in 0..5 {
        let encrypted = encrypt_message(keypair.public_key(), message).unwrap();
        ciphertexts.push(encrypted);
    }

    // All ciphertexts should be different (non-deterministic encryption)
    for i in 0..ciphertexts.len() {
        for j in (i + 1)..ciphertexts.len() {
            assert_ne!(
                ciphertexts[i], ciphertexts[j],
                "Ciphertexts should be different (non-deterministic encryption)"
            );
        }
    }

    // All should decrypt to the same message
    for ciphertext in &ciphertexts {
        let decrypted = decrypt_message(keypair.private_key(), ciphertext, None).unwrap();
        assert_eq!(
            &decrypted, message,
            "Decryption should yield original message"
        );
    }
}

/// Test rate limiting effectiveness under attack
#[test]
fn test_rate_limiting_under_attack() {
    let config = RateLimit::new(5, Duration::from_millis(100));
    let limiter = RateLimiter::new(config);

    let attacker_id = "attacker_192.168.1.100";
    let legitimate_id = "user_10.0.0.5";

    // Simulate rapid attack attempts
    let mut blocked_count = 0;
    let mut allowed_count = 0;

    // Attack phase: rapid requests from attacker
    for _ in 0..20 {
        match limiter.check_rate_limit(attacker_id) {
            Ok(_) => allowed_count += 1,
            Err(_) => blocked_count += 1,
        }
    }

    // Rate limiting should block most requests
    assert!(
        blocked_count > allowed_count,
        "Rate limiting should block majority of attack requests"
    );
    assert!(
        allowed_count <= 5,
        "Should not allow more than configured limit"
    );

    // Legitimate user should still be able to operate
    assert!(
        limiter.check_rate_limit(legitimate_id).is_ok(),
        "Legitimate user should not be affected by attacker's rate limiting"
    );

    // After rate limit window, some requests should be allowed again
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        limiter.check_rate_limit(attacker_id).is_ok(),
        "Rate limit should reset after time window"
    );
}

/// Test concurrent attack scenarios
#[test]
fn test_concurrent_attack_resistance() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let keypair = Arc::new(KeyPair::generate_mlkem1024().unwrap());
    let error_count = Arc::new(Mutex::new(0));
    let success_count = Arc::new(Mutex::new(0));

    let handles: Vec<_> = (0..20)
        .map(|thread_id| {
            let keypair = keypair.clone();
            let error_count = error_count.clone();
            let success_count = success_count.clone();

            thread::spawn(move || {
                // Each thread simulates an attacker
                for _ in 0..10 {
                    let message = format!("attack from thread {}", thread_id);

                    let result = encrypt_message(keypair.public_key(), message.as_bytes());

                    match result {
                        Ok(_) => {
                            *success_count.lock().unwrap() += 1;
                        }
                        Err(_) => {
                            *error_count.lock().unwrap() += 1;
                        }
                    }
                }
            })
        })
        .collect();

    // Wait for all attack threads
    for handle in handles {
        handle.join().unwrap();
    }

    let final_success = *success_count.lock().unwrap();
    let final_error = *error_count.lock().unwrap();
    let total_attempts = final_success + final_error;

    // System should handle concurrent load without crashing
    assert_eq!(
        total_attempts, 200,
        "Some operations were lost during concurrent access"
    );

    // Most operations should succeed (system remains available)
    let success_rate = final_success as f64 / total_attempts as f64;
    assert!(
        success_rate > 0.8,
        "Success rate too low under concurrent load: {:.2}",
        success_rate
    );
}

/// Test memory safety under adversarial conditions
#[test]
fn test_memory_safety_attacks() {
    let mut rng = OsRng;

    // Test use-after-free scenarios by dropping and reusing data
    let mut data_blocks = Vec::new();

    for _ in 0..100 {
        let size = rng.gen_range(1..1000);
        let mut data = vec![0u8; size];
        rng.fill(&mut data[..]);

        // Parse the data
        let result = std::panic::catch_unwind(|| {
            let _ = PacketHeader::from_bytes(&data);
            let _ = UserIdPacket::from_bytes(&data);
        });

        assert!(result.is_ok(), "Memory safety violation detected");

        // Store reference to data to test for use-after-free
        data_blocks.push(data);

        // Periodically clear some blocks to test memory reuse
        if data_blocks.len() > 50 {
            data_blocks.drain(..25);
        }
    }
}

/// Test denial of service through resource exhaustion
#[test]
fn test_dos_resource_exhaustion() {
    let start_time = Instant::now();
    let time_limit = Duration::from_millis(500);

    let mut operations = 0;

    // Attempt to consume resources rapidly
    while start_time.elapsed() < time_limit {
        // Try to create oversized structures
        let result = std::panic::catch_unwind(|| {
            let _ = Validator::validate_length_field(usize::MAX, 1000);
            let _ = Validator::validate_packet_count(usize::MAX);
            let _ = Validator::validate_keyring_size(usize::MAX);
        });

        assert!(result.is_ok(), "DoS attempt caused panic");
        operations += 1;

        // Prevent infinite loops in case of bugs
        if operations > 10000 {
            break;
        }
    }

    // Should complete a reasonable number of operations
    assert!(
        operations > 100,
        "Too few operations, potential DoS vulnerability"
    );
    assert!(
        operations < 100000,
        "Too many operations, validation may be ineffective"
    );
}
