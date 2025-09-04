//! Basic PQPGP Usage Example
//!
//! This example shows the basic usage of PQPGP for simple encryption/decryption
//! and signing/verification operations.
//!
//! Run with: cargo run --example basic_usage

use pqpgp::crypto::{decrypt_message, encrypt_message, sign_message, verify_signature, KeyPair};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Basic PQPGP Usage Example");
    println!("============================");
    println!();

    let mut rng = OsRng;

    // Generate key pairs
    println!("1️⃣ Generating post-quantum key pairs...");
    let encryption_keypair = KeyPair::generate_mlkem768(&mut rng)?;
    let signing_keypair = KeyPair::generate_mldsa65(&mut rng)?;

    println!("✅ Generated keys:");
    println!("   Encryption key ID: {:016X}", encryption_keypair.key_id());
    println!("   Signing key ID: {:016X}", signing_keypair.key_id());
    println!();

    // Basic encryption/decryption
    println!("2️⃣ Basic encryption and decryption...");
    let message = b"Hello, post-quantum world!";
    println!(
        "📝 Original message: \"{}\"",
        String::from_utf8_lossy(message)
    );

    // Encrypt
    let encrypted = encrypt_message(encryption_keypair.public_key(), message, &mut rng)?;
    println!("🔒 Message encrypted with ML-KEM-768");

    // Decrypt
    let decrypted = decrypt_message(encryption_keypair.private_key(), &encrypted, None)?;
    println!(
        "🔓 Message decrypted: \"{}\"",
        String::from_utf8_lossy(&decrypted)
    );

    // Verify messages match
    assert_eq!(message, decrypted.as_slice());
    println!("✅ Encryption/decryption successful!");
    println!();

    // Basic signing/verification
    println!("3️⃣ Basic signing and verification...");
    let document = b"This document is signed with post-quantum cryptography.";
    println!("📄 Document: \"{}\"", String::from_utf8_lossy(document));

    // Sign
    let signature = sign_message(signing_keypair.private_key(), document, None)?;
    println!("✍️ Document signed with ML-DSA-65");

    // Verify
    verify_signature(signing_keypair.public_key(), document, &signature)?;
    println!("✅ Signature verification successful!");
    println!();

    // Security information
    println!("🛡️ Security Information:");
    println!("   • Encryption: ML-KEM-768 (quantum-resistant)");
    println!("   • Signatures: ML-DSA-65 (quantum-resistant)");
    println!("   • All algorithms are NIST-standardized");
    println!("   • Secure against quantum computer attacks");

    println!();
    println!("🎉 Basic usage example completed successfully!");

    Ok(())
}
