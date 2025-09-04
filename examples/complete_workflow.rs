//! Complete PQPGP Workflow Example
//!
//! This example demonstrates a complete post-quantum PGP workflow including:
//! - Key generation (both encryption and signing keys)
//! - Keyring management
//! - Sign-then-encrypt workflow (sign message → create signed message armor → encrypt)
//! - Decrypt-then-verify workflow (decrypt → parse signed message → verify signature)
//! - ASCII armor encoding/decoding
//! - Key import/export
//!
//! Run with: cargo run --example complete_workflow

use pqpgp::{
    armor::{create_signed_message, decode, encode, parse_signed_message, ArmorType},
    crypto::{decrypt_message, encrypt_message, sign_message, verify_signature, KeyPair},
    keyring::KeyringManager,
};
use rand::rngs::OsRng;
use std::fs;
use tempfile::TempDir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 PQPGP - Post-Quantum Pretty Good Privacy Example");
    println!("==================================================");
    println!();

    // Setup temporary directory for this example
    let temp_dir = TempDir::new()?;
    let keyring_path = temp_dir.path();

    let mut rng = OsRng;

    // Step 1: Generate hybrid key pairs for Alice and Bob
    println!("📊 Step 1: Generating post-quantum key pairs...");

    let (alice_enc_key, alice_sign_key) = KeyPair::generate_hybrid(&mut rng)?;
    println!("✅ Generated Alice's hybrid key pairs:");
    println!(
        "   Encryption key ({}): {:016X}",
        alice_enc_key.algorithm(),
        alice_enc_key.key_id()
    );
    println!(
        "   Signing key ({}): {:016X}",
        alice_sign_key.algorithm(),
        alice_sign_key.key_id()
    );

    let (bob_enc_key, bob_sign_key) = KeyPair::generate_hybrid(&mut rng)?;
    println!("✅ Generated Bob's hybrid key pairs:");
    println!(
        "   Encryption key ({}): {:016X}",
        bob_enc_key.algorithm(),
        bob_enc_key.key_id()
    );
    println!(
        "   Signing key ({}): {:016X}",
        bob_sign_key.algorithm(),
        bob_sign_key.key_id()
    );
    println!();

    // Step 2: Setup keyrings
    println!("🔑 Step 2: Setting up keyrings...");

    let mut alice_keyring = KeyringManager::with_directory(keyring_path.join("alice"));
    let mut bob_keyring = KeyringManager::with_directory(keyring_path.join("bob"));

    // Alice adds her keys
    alice_keyring.add_keypair(
        &alice_enc_key,
        Some("Alice Encryption <alice@example.com>".to_string()),
    )?;
    alice_keyring.add_keypair(
        &alice_sign_key,
        Some("Alice Signing <alice@example.com>".to_string()),
    )?;

    // Bob adds his keys
    bob_keyring.add_keypair(
        &bob_enc_key,
        Some("Bob Encryption <bob@example.com>".to_string()),
    )?;
    bob_keyring.add_keypair(
        &bob_sign_key,
        Some("Bob Signing <bob@example.com>".to_string()),
    )?;

    // Exchange public keys (in real world, this would be done securely)
    alice_keyring.add_public_key(
        bob_enc_key.public_key(),
        Some("Bob Encryption <bob@example.com>".to_string()),
    )?;
    alice_keyring.add_public_key(
        bob_sign_key.public_key(),
        Some("Bob Signing <bob@example.com>".to_string()),
    )?;

    bob_keyring.add_public_key(
        alice_enc_key.public_key(),
        Some("Alice Encryption <alice@example.com>".to_string()),
    )?;
    bob_keyring.add_public_key(
        alice_sign_key.public_key(),
        Some("Alice Signing <alice@example.com>".to_string()),
    )?;

    // Save keyrings
    alice_keyring.save()?;
    bob_keyring.save()?;

    println!("✅ Keyrings setup complete");
    println!(
        "   Alice's keyring: {} keys",
        alice_keyring.list_all_keys().len()
    );
    println!(
        "   Bob's keyring: {} keys",
        bob_keyring.list_all_keys().len()
    );
    println!();

    // Step 3: Alice composes and signs her message
    println!("✍️ Step 3: Alice signs her message...");

    let secret_message = "Hi Bob! This is Alice. This message demonstrates post-quantum PGP signing and encryption. \
                          The security of this message relies on lattice-based cryptography which is believed to be \
                          secure against quantum computer attacks. Pretty cool, right?";

    println!("📝 Original message ({} bytes):", secret_message.len());
    println!("   \"{}\"", secret_message);

    // Sign the message first (like our web UI)
    let signature = sign_message(
        alice_sign_key.private_key(),
        secret_message.as_bytes(),
        None,
    )?;
    println!("✅ Message signed using ML-DSA-87");
    println!("   Signature key ID: {:016X}", signature.key_id);

    // Serialize the signature for the signed message armor
    let signature_serialized = bincode::serialize(&signature)?;

    // Create the signed message armor (like PGP does)
    let signed_message_armor = create_signed_message(secret_message, &signature_serialized)?;
    println!("📝 Created PGP signed message armor");

    println!("📦 Signed message preview:");
    let lines: Vec<&str> = signed_message_armor.lines().take(8).collect();
    for line in &lines {
        println!("   {}", line);
    }
    if signed_message_armor.lines().count() > 8 {
        println!(
            "   ... ({} more lines)",
            signed_message_armor.lines().count() - 8
        );
    }
    println!();

    // Step 4: Alice encrypts the signed message for Bob
    println!("🔒 Step 4: Alice encrypts the signed message for Bob...");

    // Encrypt the signed message armor (this is what gets transmitted)
    let encrypted_message = encrypt_message(
        bob_enc_key.public_key(),
        signed_message_armor.as_bytes(),
        &mut rng,
    )?;
    println!("✅ Signed message encrypted using ML-KEM-1024");

    // Serialize and armor the encrypted message
    let encrypted_serialized = bincode::serialize(&encrypted_message)?;
    let encrypted_armored = encode(&encrypted_serialized, ArmorType::Message)?;

    println!("📦 Final encrypted message stats:");
    println!("   Original message size: {} bytes", secret_message.len());
    println!(
        "   Signed message size: {} bytes",
        signed_message_armor.len()
    );
    println!("   Encrypted size: {} bytes", encrypted_serialized.len());
    println!("   Armored size: {} characters", encrypted_armored.len());
    println!(
        "   Total overhead: {:.1}% ({:.2}x original)",
        (encrypted_serialized.len() as f64 / secret_message.len() as f64 * 100.0 - 100.0),
        encrypted_serialized.len() as f64 / secret_message.len() as f64
    );
    println!();

    // Step 5: Simulate transmission and storage
    println!("📡 Step 5: Simulating message transmission...");

    // Write the encrypted signed message to file (only one file needed now)
    let message_file = keyring_path.join("encrypted_signed_message.asc");

    fs::write(&message_file, &encrypted_armored)?;

    println!("✅ Encrypted signed message saved to:");
    println!("   File: {}", message_file.display());
    println!();

    // Display the armored message (first few lines)
    let armored_content = fs::read_to_string(&message_file)?;
    let lines: Vec<&str> = armored_content.lines().collect();
    println!("📄 Armored message preview:");
    for (i, line) in lines.iter().take(5).enumerate() {
        println!("   {}", line);
        if i == 4 && lines.len() > 5 {
            println!("   ... ({} more lines)", lines.len() - 5);
        }
    }
    println!();

    // Step 6: Bob receives and decrypts the message
    println!("🔓 Step 6: Bob decrypts the signed message...");

    // Read and decode the armored encrypted message
    let received_armored = fs::read_to_string(&message_file)?;
    let received_decoded = decode(&received_armored)?;

    // Deserialize the encrypted message
    let received_encrypted: pqpgp::crypto::EncryptedMessage =
        bincode::deserialize(&received_decoded.data)?;

    // Decrypt with Bob's private key - this gives us back the signed message armor
    let decrypted_signed_message =
        decrypt_message(bob_enc_key.private_key(), &received_encrypted, None)?;
    let decrypted_signed_message_str = String::from_utf8(decrypted_signed_message)?;

    println!("🔓 Encrypted message decrypted successfully!");
    println!("📝 Decrypted content is a PGP signed message:");
    let preview_lines: Vec<&str> = decrypted_signed_message_str.lines().take(6).collect();
    for line in &preview_lines {
        println!("   {}", line);
    }
    if decrypted_signed_message_str.lines().count() > 6 {
        println!(
            "   ... ({} more lines)",
            decrypted_signed_message_str.lines().count() - 6
        );
    }
    println!();

    // Step 7: Bob parses and verifies Alice's signature from the signed message
    println!("🔍 Step 7: Bob parses and verifies the signature...");

    // Use the official parse function to extract the message and signature data
    let (original_message, signature_data) = parse_signed_message(&decrypted_signed_message_str)?;

    println!("📝 Extracted original message:");
    println!("   \"{}\"", original_message);

    // Verify the original message matches what Alice sent
    assert_eq!(secret_message, original_message);
    println!("✅ Original message integrity verified!");

    // Deserialize the signature from the extracted data
    let received_signature: pqpgp::crypto::Signature = bincode::deserialize(&signature_data)?;

    // Verify the signature using Alice's public key against the original message
    verify_signature(
        alice_sign_key.public_key(),
        original_message.as_bytes(),
        &received_signature,
    )?;

    println!("✅ Signature verification successful!");
    println!("   Signed by key: {:016X}", received_signature.key_id);
    println!("   Signature algorithm: ML-DSA-87");
    println!("   Message authenticity and integrity confirmed!");
    println!("   Sign-then-encrypt workflow completed successfully!");
    println!();

    // Step 8: Demonstrate key export/import
    println!("🔄 Step 8: Demonstrating key export/import...");

    // Export Alice's public encryption key
    let exported_key = alice_keyring
        .public_keyring
        .export_key(alice_enc_key.key_id())?;
    let exported_armored = encode(&exported_key, ArmorType::PublicKey)?;

    // Save to file
    let key_file = keyring_path.join("alice_public_key.asc");
    fs::write(&key_file, exported_armored)?;

    println!("📤 Alice's public key exported to: {}", key_file.display());

    // Create a new keyring and import the key
    let mut charlie_keyring = KeyringManager::with_directory(keyring_path.join("charlie"));
    let imported_key_data = fs::read_to_string(&key_file)?;
    let imported_decoded = decode(&imported_key_data)?;

    charlie_keyring
        .public_keyring
        .import_key(&imported_decoded.data)?;
    charlie_keyring.save()?;

    println!("📥 Key successfully imported to Charlie's keyring");

    // Verify Charlie can encrypt messages for Alice
    let test_message = b"Hi Alice, this is a test from Charlie!";
    let charlie_encrypted = {
        // Load Charlie's keyring and find Alice's key
        charlie_keyring.load()?;
        let alice_entry = charlie_keyring
            .get_key(alice_enc_key.key_id())
            .expect("Alice's key not found in Charlie's keyring");

        encrypt_message(&alice_entry.public_key, test_message, &mut rng)?
    };

    // Alice can decrypt Charlie's message
    let charlie_decrypted = decrypt_message(alice_enc_key.private_key(), &charlie_encrypted, None)?;
    assert_eq!(test_message, charlie_decrypted.as_slice());

    println!("✅ Key import verification successful!");
    println!(
        "   Charlie encrypted: \"{}\"",
        String::from_utf8_lossy(test_message)
    );
    println!(
        "   Alice decrypted: \"{}\"",
        String::from_utf8_lossy(&charlie_decrypted)
    );
    println!();

    // Step 9: Performance and security summary
    println!("📊 Step 9: Performance and Security Summary");
    println!("===========================================");

    println!("🔐 Cryptographic Algorithms Used:");
    println!("   • Encryption: ML-KEM-1024 (NIST FIPS 203)");
    println!("   • Signatures: ML-DSA-87 (NIST FIPS 204)");
    println!("   • Symmetric: AES-256-GCM");
    println!("   • Hashing: SHA3-256");
    println!();

    println!("📏 Key Sizes:");
    println!(
        "   • ML-KEM-1024 public key: {} bytes",
        alice_enc_key.public_key().as_bytes().len()
    );
    println!(
        "   • ML-DSA-87 public key: {} bytes",
        alice_sign_key.public_key().as_bytes().len()
    );
    println!();

    println!("📦 Message Overhead:");
    let overhead_ratio = encrypted_serialized.len() as f64 / secret_message.len() as f64;
    println!("   • Original message: {} bytes", secret_message.len());
    println!(
        "   • Encrypted message: {} bytes",
        encrypted_serialized.len()
    );
    println!(
        "   • Encryption overhead: {:.1}% ({:.2}x)",
        (overhead_ratio - 1.0) * 100.0,
        overhead_ratio
    );
    println!("   • Signature size: {} bytes", signature_serialized.len());
    println!();

    println!("🛡️ Security Properties:");
    println!("   • Quantum-resistant encryption and signatures");
    println!("   • Forward secrecy for each encrypted message");
    println!("   • Message authentication and integrity");
    println!("   • Non-repudiation through digital signatures");
    println!("   • Key distribution via secure export/import");
    println!();

    println!("🎉 Complete PQPGP workflow demonstration finished!");
    println!("    All operations completed successfully with post-quantum security.");

    // Cleanup notification
    println!();
    println!("📝 Note: This example used temporary files that will be automatically cleaned up.");
    println!("    In a real application, you would manage keyring persistence appropriately.");

    Ok(())
}
