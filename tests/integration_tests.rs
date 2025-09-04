//! Integration tests for PQPGP
//!
//! These tests verify end-to-end functionality across all modules,
//! including key generation, encryption/decryption, signing/verification,
//! and keyring management.

use pqpgp::{
    armor::{decode, encode, ArmorType},
    crypto::{decrypt_message, encrypt_message, sign_message, verify_signature, KeyPair},
    keyring::KeyringManager,
};
use rand::rngs::OsRng;
use tempfile::TempDir;

/// Test complete end-to-end encryption and decryption workflow
#[test]
fn test_end_to_end_encryption() {
    let mut rng = OsRng;

    // Generate Bob's key pair for encryption test
    let bob_keypair =
        KeyPair::generate_mlkem768(&mut rng).expect("Failed to generate Bob's key pair");

    // Test message
    let original_message = b"This is a secret post-quantum message from Alice to Bob!";

    // Alice encrypts a message for Bob
    let encrypted = encrypt_message(bob_keypair.public_key(), original_message, &mut rng)
        .expect("Failed to encrypt message");

    // Bob decrypts the message
    let decrypted = decrypt_message(bob_keypair.private_key(), &encrypted, None)
        .expect("Failed to decrypt message");

    assert_eq!(original_message, decrypted.as_slice());
}

/// Test complete end-to-end signing and verification workflow
#[test]
fn test_end_to_end_signing() {
    let mut rng = OsRng;

    // Generate signing key pair
    let alice_keypair =
        KeyPair::generate_mldsa65(&mut rng).expect("Failed to generate Alice's signing key pair");

    // Test message
    let message = b"This document is signed by Alice with post-quantum cryptography";

    // Alice signs the message
    let signature =
        sign_message(alice_keypair.private_key(), message, None).expect("Failed to sign message");

    // Anyone can verify the signature with Alice's public key
    verify_signature(alice_keypair.public_key(), message, &signature)
        .expect("Failed to verify signature");

    // Verify that signature fails with wrong message
    let wrong_message = b"This is a different message";
    assert!(verify_signature(alice_keypair.public_key(), wrong_message, &signature).is_err());
}

/// Test hybrid cryptography workflow (different keys for encryption and signing)
#[test]
fn test_hybrid_cryptography_workflow() {
    let mut rng = OsRng;

    // Generate hybrid key pairs for Alice
    let (_alice_kem_keypair, alice_dsa_keypair) =
        KeyPair::generate_hybrid(&mut rng).expect("Failed to generate Alice's hybrid key pairs");

    // Generate hybrid key pairs for Bob
    let (bob_kem_keypair, _bob_dsa_keypair) =
        KeyPair::generate_hybrid(&mut rng).expect("Failed to generate Bob's hybrid key pairs");

    let message = b"Secret message with authentication";

    // Alice encrypts for Bob and signs with her own key
    let encrypted = encrypt_message(bob_kem_keypair.public_key(), message, &mut rng)
        .expect("Failed to encrypt message");

    let signature = sign_message(alice_dsa_keypair.private_key(), message, None)
        .expect("Failed to sign message");

    // Bob decrypts and verifies
    let decrypted = decrypt_message(bob_kem_keypair.private_key(), &encrypted, None)
        .expect("Failed to decrypt message");

    verify_signature(alice_dsa_keypair.public_key(), &decrypted, &signature)
        .expect("Failed to verify signature");

    assert_eq!(message, decrypted.as_slice());
}

/// Test ASCII armor encoding and decoding integration
#[test]
fn test_armor_integration() {
    let mut rng = OsRng;

    // Generate a key pair
    let keypair = KeyPair::generate_mlkem768(&mut rng).expect("Failed to generate key pair");

    // Test message
    let message = b"Test message for armor integration";

    // Encrypt message
    let encrypted = encrypt_message(keypair.public_key(), message, &mut rng)
        .expect("Failed to encrypt message");

    // Serialize and armor the encrypted message
    let serialized = bincode::serialize(&encrypted).expect("Failed to serialize encrypted message");

    let armored = encode(&serialized, ArmorType::Message).expect("Failed to armor message");

    // Verify it looks like PGP armor
    assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----"));
    assert!(armored.ends_with("-----END PGP MESSAGE-----\n"));

    // Decode the armored message
    let decoded = decode(&armored).expect("Failed to decode armored message");

    assert_eq!(serialized, decoded.data);

    // Deserialize and decrypt
    let deserialized: pqpgp::crypto::EncryptedMessage =
        bincode::deserialize(&decoded.data).expect("Failed to deserialize encrypted message");

    let decrypted = decrypt_message(keypair.private_key(), &deserialized, None)
        .expect("Failed to decrypt message");

    assert_eq!(message, decrypted.as_slice());
}

/// Test complete keyring management workflow
#[test]
fn test_keyring_management_workflow() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let keyring_path = temp_dir.path();

    let mut rng = OsRng;

    // Create keyring manager
    let mut keyring = KeyringManager::with_directory(keyring_path);

    // Generate key pairs
    let alice_keypair =
        KeyPair::generate_mlkem768(&mut rng).expect("Failed to generate Alice's key pair");
    let bob_keypair =
        KeyPair::generate_mldsa65(&mut rng).expect("Failed to generate Bob's key pair");

    // Add keys to keyring
    keyring
        .add_keypair(
            &alice_keypair,
            Some("Alice <alice@example.com>".to_string()),
        )
        .expect("Failed to add Alice's key pair");
    keyring
        .add_keypair(&bob_keypair, Some("Bob <bob@example.com>".to_string()))
        .expect("Failed to add Bob's key pair");

    // Save keyring
    keyring.save().expect("Failed to save keyring");

    // Create a new keyring manager and load from disk
    let mut keyring2 = KeyringManager::with_directory(keyring_path);
    keyring2.load().expect("Failed to load keyring");

    // Verify keys are present
    let all_keys = keyring2.list_all_keys();
    assert_eq!(all_keys.len(), 2);

    // Test key retrieval
    let alice_key = keyring2
        .get_key(alice_keypair.key_id())
        .expect("Alice's key not found");
    assert_eq!(alice_key.user_ids, vec!["Alice <alice@example.com>"]);

    let bob_key = keyring2
        .get_key(bob_keypair.key_id())
        .expect("Bob's key not found");
    assert_eq!(bob_key.user_ids, vec!["Bob <bob@example.com>"]);

    // Test private key access
    assert!(keyring2.has_private_key(alice_keypair.key_id()));
    assert!(keyring2.has_private_key(bob_keypair.key_id()));
}

/// Test complete secure communication scenario
#[test]
fn test_secure_communication_scenario() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let keyring_path = temp_dir.path();

    let mut rng = OsRng;

    // Setup: Alice and Bob generate hybrid key pairs
    let (alice_enc_keypair, alice_sign_keypair) =
        KeyPair::generate_hybrid(&mut rng).expect("Failed to generate Alice's hybrid keys");
    let (bob_enc_keypair, bob_sign_keypair) =
        KeyPair::generate_hybrid(&mut rng).expect("Failed to generate Bob's hybrid keys");

    // Both add their keys to keyrings
    let mut alice_keyring = KeyringManager::with_directory(keyring_path.join("alice"));
    let mut bob_keyring = KeyringManager::with_directory(keyring_path.join("bob"));

    // Alice adds her keys and Bob's public keys
    alice_keyring
        .add_keypair(
            &alice_enc_keypair,
            Some("Alice Enc <alice@example.com>".to_string()),
        )
        .expect("Failed to add Alice's encryption key");
    alice_keyring
        .add_keypair(
            &alice_sign_keypair,
            Some("Alice Sign <alice@example.com>".to_string()),
        )
        .expect("Failed to add Alice's signing key");
    alice_keyring
        .add_public_key(
            bob_enc_keypair.public_key(),
            Some("Bob Enc <bob@example.com>".to_string()),
        )
        .expect("Failed to add Bob's public encryption key");
    alice_keyring
        .add_public_key(
            bob_sign_keypair.public_key(),
            Some("Bob Sign <bob@example.com>".to_string()),
        )
        .expect("Failed to add Bob's public signing key");

    // Bob adds his keys and Alice's public keys
    bob_keyring
        .add_keypair(
            &bob_enc_keypair,
            Some("Bob Enc <bob@example.com>".to_string()),
        )
        .expect("Failed to add Bob's encryption key");
    bob_keyring
        .add_keypair(
            &bob_sign_keypair,
            Some("Bob Sign <bob@example.com>".to_string()),
        )
        .expect("Failed to add Bob's signing key");
    bob_keyring
        .add_public_key(
            alice_enc_keypair.public_key(),
            Some("Alice Enc <alice@example.com>".to_string()),
        )
        .expect("Failed to add Alice's public encryption key");
    bob_keyring
        .add_public_key(
            alice_sign_keypair.public_key(),
            Some("Alice Sign <alice@example.com>".to_string()),
        )
        .expect("Failed to add Alice's public signing key");

    // Save keyrings
    alice_keyring
        .save()
        .expect("Failed to save Alice's keyring");
    bob_keyring.save().expect("Failed to save Bob's keyring");

    // Scenario: Alice sends a signed and encrypted message to Bob
    let message = b"Hi Bob, this is Alice. This message is both encrypted and signed with post-quantum cryptography!";

    // Alice signs the message
    let signature = sign_message(alice_sign_keypair.private_key(), message, None)
        .expect("Failed to sign message");

    // Alice encrypts the message for Bob
    let encrypted = encrypt_message(bob_enc_keypair.public_key(), message, &mut rng)
        .expect("Failed to encrypt message");

    // Simulate transmission (serialize and armor both)
    let encrypted_serialized =
        bincode::serialize(&encrypted).expect("Failed to serialize encrypted message");
    let encrypted_armored = encode(&encrypted_serialized, ArmorType::Message)
        .expect("Failed to armor encrypted message");

    let signature_serialized =
        bincode::serialize(&signature).expect("Failed to serialize signature");
    let signature_armored =
        encode(&signature_serialized, ArmorType::Signature).expect("Failed to armor signature");

    // Bob receives and processes the message

    // Decode armored data
    let encrypted_decoded = decode(&encrypted_armored).expect("Failed to decode encrypted message");
    let signature_decoded = decode(&signature_armored).expect("Failed to decode signature");

    // Deserialize
    let received_encrypted: pqpgp::crypto::EncryptedMessage =
        bincode::deserialize(&encrypted_decoded.data)
            .expect("Failed to deserialize encrypted message");
    let received_signature: pqpgp::crypto::Signature =
        bincode::deserialize(&signature_decoded.data).expect("Failed to deserialize signature");

    // Bob decrypts the message
    let decrypted = decrypt_message(bob_enc_keypair.private_key(), &received_encrypted, None)
        .expect("Failed to decrypt message");

    // Bob verifies the signature
    verify_signature(
        alice_sign_keypair.public_key(),
        &decrypted,
        &received_signature,
    )
    .expect("Failed to verify signature");

    // Verify the message content
    assert_eq!(message, decrypted.as_slice());

    println!("✅ Secure communication test passed!");
    println!("   Message length: {} bytes", message.len());
    println!("   Encrypted size: {} bytes", encrypted_serialized.len());
    println!("   Signature size: {} bytes", signature_serialized.len());
    println!("   Armored message: {} chars", encrypted_armored.len());
    println!("   Armored signature: {} chars", signature_armored.len());
}

/// Test large message handling
#[test]
fn test_large_message_handling() {
    let mut rng = OsRng;

    // Generate key pair
    let keypair = KeyPair::generate_mlkem768(&mut rng).expect("Failed to generate key pair");

    // Create a large message (1MB)
    let large_message: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    // Encrypt large message
    let encrypted = encrypt_message(keypair.public_key(), &large_message, &mut rng)
        .expect("Failed to encrypt large message");

    // Decrypt large message
    let decrypted = decrypt_message(keypair.private_key(), &encrypted, None)
        .expect("Failed to decrypt large message");

    assert_eq!(large_message, decrypted);

    println!("✅ Large message test passed!");
    println!("   Original size: {} bytes", large_message.len());
    println!(
        "   Encrypted size: {} bytes ({}% overhead)",
        bincode::serialize(&encrypted).unwrap().len(),
        (bincode::serialize(&encrypted).unwrap().len() as f64 / large_message.len() as f64 * 100.0
            - 100.0) as i32
    );
}

/// Test key export and import workflow
#[test]
fn test_key_export_import_workflow() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let keyring1_path = temp_dir.path().join("keyring1");
    let keyring2_path = temp_dir.path().join("keyring2");

    let mut rng = OsRng;

    // Create first keyring with a key
    let mut keyring1 = KeyringManager::with_directory(&keyring1_path);
    let keypair = KeyPair::generate_mlkem768(&mut rng).expect("Failed to generate key pair");

    keyring1
        .add_keypair(&keypair, Some("Test User <test@example.com>".to_string()))
        .expect("Failed to add key pair");
    keyring1.save().expect("Failed to save keyring1");

    // Export the public key
    let exported_key = keyring1
        .public_keyring
        .export_key(keypair.key_id())
        .expect("Failed to export key");

    // Create second keyring and import the key
    let mut keyring2 = KeyringManager::with_directory(&keyring2_path);
    let imported_key_id = keyring2
        .public_keyring
        .import_key(&exported_key)
        .expect("Failed to import key");
    keyring2.save().expect("Failed to save keyring2");

    // Verify the key was imported correctly
    let imported_key = keyring2
        .get_key(imported_key_id)
        .expect("Imported key not found");

    // The key ID might be different due to how import works, but algorithm should match
    assert_eq!(imported_key.public_key.algorithm(), keypair.algorithm());

    // More importantly, verify we can use the imported key for encryption

    // Verify we can encrypt with the imported key and decrypt with the original
    let message = b"Test message for import/export";
    let encrypted = encrypt_message(&imported_key.public_key, message, &mut rng)
        .expect("Failed to encrypt with imported key");
    let decrypted = decrypt_message(keypair.private_key(), &encrypted, None)
        .expect("Failed to decrypt with original key");

    assert_eq!(message, decrypted.as_slice());
}
