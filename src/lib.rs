//! # PQPGP - Post-Quantum Pretty Good Privacy
//!
//! A post-quantum secure implementation of PGP (Pretty Good Privacy) in Rust.
//! This library provides quantum-resistant cryptographic operations while maintaining
//! compatibility with standard PGP workflows and packet formats.
//!
//! ## Features
//!
//! - **Post-Quantum Security**: Uses NIST-standardized ML-KEM and ML-DSA algorithms
//! - **Hybrid Cryptography**: Combines classical and post-quantum algorithms for maximum security
//! - **PGP Compatibility**: Standard PGP packet formats with new algorithm identifiers
//! - **Performance Optimized**: Efficient Rust implementations with minimal allocations
//!
//! ## Cryptographic Algorithms
//!
//! - **Key Encapsulation**: ML-KEM-768 (NIST FIPS 203)
//! - **Digital Signatures**: ML-DSA-65 (NIST FIPS 204)
//! - **Symmetric Encryption**: AES-256-GCM
//! - **Hashing**: SHA3-256 (quantum-resistant)
//!
//! ## Examples
//!
//! ### Key Generation
//!
//! ```rust,no_run
//! use pqpgp::crypto::KeyPair;
//! use rand::rngs::OsRng;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut rng = OsRng;
//! let keypair = KeyPair::generate_mlkem768(&mut rng)?;
//! println!("Generated post-quantum key pair with {} byte public key",
//!          keypair.public_key().as_bytes().len());
//! # Ok(())
//! # }
//! ```
//!
//! ### Encryption and Decryption
//!
//! ```rust,no_run
//! use pqpgp::crypto::{KeyPair, encrypt_message, decrypt_message};
//! use rand::rngs::OsRng;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut rng = OsRng;
//! let keypair = KeyPair::generate_mlkem768(&mut rng)?;
//! let message = b"Secret post-quantum message";
//! let encrypted = encrypt_message(keypair.public_key(), message, &mut rng)?;
//! let decrypted = decrypt_message(keypair.private_key(), &encrypted, None)?;
//! assert_eq!(message, &decrypted[..]);
//! # Ok(())
//! # }
//! ```

pub mod armor;
pub mod cli;
pub mod crypto;
pub mod error;
pub mod keyring;
pub mod packet;
pub mod validation;

pub use error::{PqpgpError, Result};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Supported PGP version
pub const PGP_VERSION: u8 = 4;

/// Default key expiration time in seconds (1 year)
pub const DEFAULT_KEY_EXPIRATION: u32 = 365 * 24 * 60 * 60;
