# PQPGP - Post-Quantum Pretty Good Privacy

A post-quantum secure implementation of PGP (Pretty Good Privacy) in Rust, providing quantum-resistant cryptographic operations while maintaining compatibility with standard PGP workflows and packet formats.

## 🔒 Security Features

- **Post-Quantum Cryptography**: Uses NIST-standardized ML-KEM-1024 and ML-DSA-87 algorithms
- **Hybrid Approach**: Combines classical and post-quantum algorithms for maximum security
- **Password Protection**: Optional Argon2id-based password encryption for private keys
- **PGP Compatible**: Standard PGP packet formats (RFC 4880) with new algorithm identifiers
- **Production Security**: Comprehensive input validation, rate limiting, and attack prevention

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/dihmeetree/pqpgp
cd pqpgp
cargo build --release
```

### Basic Usage

```rust
use pqpgp::crypto::{KeyPair, encrypt_message, decrypt_message, sign_message, verify_signature, Password};
use pqpgp::armor::{create_signed_message, parse_signed_message};
use rand::rngs::OsRng;

// Generate hybrid key pairs (encryption + signing)
let mut rng = OsRng;
let (enc_keypair, sign_keypair) = KeyPair::generate_hybrid()?

// Optionally protect private keys with password
let password = Password::new("secure_password123".to_string());
enc_keypair.private_key_mut().encrypt_with_password(&password)?;
sign_keypair.private_key_mut().encrypt_with_password(&password)?;

// Sign-then-encrypt workflow (like traditional PGP)
let message = "Secret post-quantum message";

// 1. Sign the message
let signature = sign_message(sign_keypair.private_key(), message.as_bytes(), Some(&password))?;
let signature_data = bincode::serialize(&signature)?;

// 2. Create signed message armor
let signed_message = create_signed_message(message, &signature_data)?;

// 3. Encrypt the signed message
let encrypted = encrypt_message(enc_keypair.public_key(), signed_message.as_bytes(), &mut rng)?;

// Decrypt-then-verify workflow
// 1. Decrypt to get signed message
let decrypted_signed = decrypt_message(enc_keypair.private_key(), &encrypted, Some(&password))?;
let decrypted_signed_str = String::from_utf8(decrypted_signed)?;

// 2. Parse signed message to extract original message and signature
let (original_message, signature_data) = parse_signed_message(&decrypted_signed_str)?;
let signature: pqpgp::crypto::Signature = bincode::deserialize(&signature_data)?;

// 3. Verify the signature
verify_signature(sign_keypair.public_key(), original_message.as_bytes(), &signature)?;
assert_eq!(message, original_message);
```

### Command Line Interface

```bash
# Generate a new key pair (optionally with password protection)
./target/release/pqpgp generate-key mlkem1024 "Alice <alice@example.com>"
./target/release/pqpgp generate-key mldsa87 "Bob <bob@example.com>" --password

# List all keys in keyring
./target/release/pqpgp list-keys

# Encrypt a message for a recipient
./target/release/pqpgp encrypt alice@example.com message.txt message.pgp

# Decrypt a message (password prompt for encrypted keys)
./target/release/pqpgp decrypt message.pgp decrypted.txt

# Sign a document (password prompt for encrypted signing keys)
./target/release/pqpgp sign A1B2C3D4E5F60708 document.txt document.sig

# Verify a signature
./target/release/pqpgp verify document.txt document.sig

# Import/Export keys
./target/release/pqpgp import keys.asc
./target/release/pqpgp export alice@example.com alice_public.asc
```

### Web Interface

PQPGP also provides a web interface for easy key management and cryptographic operations:

```bash
# Start the web server
./target/release/pqpgp-web

# The interface will be available at http://localhost:3000
```

The web interface provides:
- Key generation and management
- Sign-then-encrypt workflow (traditional PGP compatibility)
- Decrypt-then-verify workflow with signed message parsing
- Key import/export functionality
- User-friendly forms with CSRF protection
- Session-based security for web operations

## 🔑 Password Protection

PQPGP supports optional password-based encryption of private keys using industry-standard Argon2id key derivation and AES-256-GCM encryption:

### Features

- **Argon2id Key Derivation**: Memory-hard password hashing resistant to GPU/ASIC attacks
- **AES-256-GCM Encryption**: Authenticated encryption of private key material
- **Secure Parameters**: 19MB memory cost, 2 iterations for strong protection
- **Zero-Knowledge**: Passwords are never stored, only used for key derivation
- **Selective Protection**: Choose which keys to protect with passwords

### Usage Examples

```rust
use pqpgp::crypto::{KeyPair, Password};

// Generate key pair
let mut keypair = KeyPair::generate_mlkem1024()?;

// Protect with password
let password = Password::new("my_secure_password".to_string());
keypair.private_key_mut().encrypt_with_password(&password)?;

// Use encrypted key (password required)
let signature = sign_message(keypair.private_key(), message, Some(&password))?;
```

### Security Properties

- **Brute Force Resistant**: Argon2id makes password cracking computationally expensive
- **Salt-Based**: Each encrypted key uses unique random salt
- **Forward Secure**: Changing password doesn't reveal previous keys
- **Timing Attack Resistant**: Constant-time operations prevent information leakage

## 🔐 Cryptographic Algorithms

| Operation | Algorithm | NIST Standard | Key Size |
|-----------|-----------|---------------|----------|
| Key Encapsulation | ML-KEM-1024 | FIPS 203 | 1,568 bytes |
| Digital Signatures | ML-DSA-87 | FIPS 204 | 2,592 bytes |
| Symmetric Encryption | AES-256-GCM | FIPS 197 | 32 bytes |
| Hashing | SHA3-512 | FIPS 202 | 64 bytes |
| Password Hashing | Argon2id | RFC 9106 | 32 bytes |

## 🛡️ Security Testing

PQPGP includes a comprehensive security testing framework with **123 tests** covering:

- **Input Validation**: Buffer overflow protection, bounds checking
- **Attack Resistance**: Timing attacks, padding oracles, injection attacks
- **Resource Protection**: DoS prevention, rate limiting, memory exhaustion
- **Fuzzing**: Property-based testing with random input generation
- **Adversarial Testing**: Real attack scenario simulation

Run the security test suite:

```bash
cargo test --release
```

## 📦 Architecture

```
src/
├── crypto/           # Post-quantum cryptographic operations
│   ├── encryption.rs # ML-KEM-1024 hybrid encryption
│   ├── signature.rs  # ML-DSA-87 digital signatures
│   ├── password.rs   # Argon2id password-based key protection
│   └── keys.rs       # Key generation and management
├── packet/           # PGP packet format implementation
├── validation/       # Security validation and rate limiting
├── keyring/          # Key storage and management
├── armor/            # ASCII armor encoding/decoding + signed message parsing
├── cli/              # Command-line interface
└── web/              # Web interface for browser-based operations
examples/             # Usage examples and demonstrations
tests/                # Comprehensive test suite
├── security_tests.rs # Security validation tests
├── adversarial_tests.rs # Attack simulation tests
├── fuzz_tests.rs     # Fuzzing and property-based tests
├── property_tests.rs # Mathematical property verification
└── integration_tests.rs # End-to-end workflow tests
```

## 📚 Documentation

For comprehensive technical analysis, examples, and comparison with traditional PGP:

- **[PQPGP vs Traditional PGP](./docs/PQPGP-vs-Traditional-PGP.md)** - Detailed comparison covering security, performance, and migration guidance
- **[Documentation Index](./docs/README.md)** - Navigation guide for all documentation
- **[Usage Examples](./examples/)** - Practical code examples demonstrating PQPGP functionality

## 🔧 Development

### Prerequisites

- Rust 1.75+ 
- Cargo

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test --release

# Run security tests
cargo test --release security
cargo test --release adversarial
cargo test --release fuzz

# Check code quality
cargo clippy -- -D warnings
```

### Performance Benchmarks

```bash
cargo bench
```

## 📋 Standards Compliance

- **RFC 4880**: OpenPGP Message Format
- **RFC 9106**: The Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
- **NIST FIPS 203**: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- **NIST FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)  
- **NIST FIPS 197**: Advanced Encryption Standard (AES)
- **NIST FIPS 202**: SHA-3 Standard

## 🚨 Security Considerations

### Quantum Threat Timeline

Current estimates suggest large-scale quantum computers capable of breaking RSA and ECDSA may emerge within 10-30 years. PQPGP provides:

- **Immediate Protection**: Deploy quantum-resistant cryptography today
- **Hybrid Security**: Classical algorithms provide current security, post-quantum algorithms provide future protection
- **Smooth Migration**: PGP-compatible format allows gradual ecosystem transition

### Algorithm Selection

- **ML-KEM-1024**: Provides security equivalent to AES-256 against quantum attacks
- **ML-DSA-87**: Provides security equivalent to SHA3-512 against quantum attacks
- **Conservative Parameters**: Chosen for long-term security rather than minimal size

### Password Security

- **Strong Password Policies**: Use passwords with high entropy (≥128 bits recommended)
- **Argon2id Protection**: Memory-hard function prevents efficient GPU/ASIC attacks
- **No Password Storage**: Passwords are never stored, only used for key derivation
- **Secure Prompting**: CLI uses secure password input (no echo, memory clearing)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`cargo test --release`)
4. Run security tests (`cargo test --release security`)
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

This project is dual-licensed under either:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

## ⚠️ Disclaimer

While PQPGP implements cryptographic algorithms standardized by NIST, this software has not undergone formal security auditing. For production use in high-security environments, consider professional cryptographic review.

## 🔗 References

- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization)
- [RFC 4880: OpenPGP Message Format](https://tools.ietf.org/html/rfc4880)
- [Quantum Computing Threat Timeline](https://globalriskinstitute.org/publications/quantum-threat-timeline/)

---

**Made with ❤️ and quantum-resistant cryptography**