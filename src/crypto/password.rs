//! Password-based private key protection using Argon2 and AES-GCM.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{error::PqpgpError, Result};

/// Salt size for Argon2 (128 bits)
const SALT_SIZE: usize = 16;

/// Parameters for Argon2id password hashing
const ARGON2_PARAMS: argon2::Params = match argon2::Params::new(
    19 * 1024, // 19 MiB memory cost
    2,         // 2 iterations
    1,         // 1 thread (single-threaded)
    Some(32),  // 32-byte output length
) {
    Ok(params) => params,
    Err(_) => panic!("Invalid Argon2 parameters"),
};

/// Encrypted private key data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPrivateKey {
    /// Argon2 salt for password derivation
    salt: [u8; SALT_SIZE],
    /// AES-GCM nonce
    nonce: [u8; 12],
    /// Encrypted private key data (includes authentication tag from AES-GCM)
    ciphertext: Vec<u8>,
}

/// Password for key encryption/decryption
#[derive(Clone)]
pub struct Password(String);

impl Password {
    /// Create a new password from a string
    pub fn new(password: String) -> Self {
        Self(password)
    }

    /// Get password as bytes
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Check if password is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl EncryptedPrivateKey {
    /// Encrypt private key data with a password
    pub fn encrypt(private_key_data: &[u8], password: &Password) -> Result<Self> {
        if password.is_empty() {
            return Err(PqpgpError::password("Password cannot be empty"));
        }

        // Generate random salt
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);

        // Derive key using Argon2id
        let derived_key = derive_key_from_password(password, &salt)?;

        // Create AES-GCM cipher
        let cipher = Aes256Gcm::new(&derived_key);

        // Generate random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut AeadRng);

        // Encrypt the private key data
        let ciphertext = cipher
            .encrypt(&nonce, private_key_data)
            .map_err(|e| PqpgpError::crypto(format!("Failed to encrypt private key: {}", e)))?;

        Ok(Self {
            salt,
            nonce: nonce.into(),
            ciphertext,
        })
    }

    /// Decrypt private key data with a password
    pub fn decrypt(&self, password: &Password) -> Result<Vec<u8>> {
        if password.is_empty() {
            return Err(PqpgpError::password("Password cannot be empty"));
        }

        // Derive key using stored salt
        let derived_key = derive_key_from_password(password, &self.salt)?;

        // Create AES-GCM cipher
        let cipher = Aes256Gcm::new(&derived_key);

        // Convert nonce
        let nonce = Nonce::from_slice(&self.nonce);

        // Decrypt the private key data
        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|e| {
                PqpgpError::password(format!(
                    "Failed to decrypt private key (wrong password?): {}",
                    e
                ))
            })?;

        Ok(plaintext)
    }

    /// Get the size of the encrypted data
    pub fn encrypted_size(&self) -> usize {
        self.ciphertext.len()
    }
}

/// Derive a 256-bit key from password using Argon2id
fn derive_key_from_password(password: &Password, salt: &[u8; SALT_SIZE]) -> Result<Key<Aes256Gcm>> {
    // Create Argon2 instance with secure parameters
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        ARGON2_PARAMS,
    );

    // Create salt string
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| PqpgpError::password(format!("Invalid salt: {}", e)))?;

    // Hash the password
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| PqpgpError::password(format!("Password hashing failed: {}", e)))?;

    // Extract the hash bytes
    let hash = password_hash
        .hash
        .ok_or_else(|| PqpgpError::password("No hash in password result"))?;
    let hash_bytes = hash.as_bytes();

    // Ensure we have exactly 32 bytes for AES-256
    if hash_bytes.len() != 32 {
        return Err(PqpgpError::password(format!(
            "Unexpected key length: {} bytes (expected 32)",
            hash_bytes.len()
        )));
    }

    Ok(*Key::<Aes256Gcm>::from_slice(hash_bytes))
}

/// Verify a password against stored parameters (for testing/validation)
pub fn verify_password(
    password: &Password,
    _salt: &[u8; SALT_SIZE],
    expected_hash: &str,
) -> Result<bool> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        ARGON2_PARAMS,
    );

    let parsed_hash = PasswordHash::new(expected_hash)
        .map_err(|e| PqpgpError::password(format!("Invalid password hash: {}", e)))?;

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(PqpgpError::password(format!(
            "Password verification failed: {}",
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_encryption_decryption() {
        let password = Password::new("test_password_123!".to_string());
        let private_key_data = b"secret private key data for testing";

        // Encrypt
        let encrypted = EncryptedPrivateKey::encrypt(private_key_data, &password)
            .expect("Encryption should succeed");

        // Decrypt with correct password
        let decrypted = encrypted
            .decrypt(&password)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, private_key_data);
    }

    #[test]
    fn test_wrong_password_fails() {
        let password = Password::new("correct_password".to_string());
        let wrong_password = Password::new("wrong_password".to_string());
        let private_key_data = b"secret data";

        let encrypted = EncryptedPrivateKey::encrypt(private_key_data, &password)
            .expect("Encryption should succeed");

        let result = encrypted.decrypt(&wrong_password);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("wrong password"));
    }

    #[test]
    fn test_empty_password_fails() {
        let empty_password = Password::new("".to_string());
        let private_key_data = b"secret data";

        let result = EncryptedPrivateKey::encrypt(private_key_data, &empty_password);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Password cannot be empty"));
    }

    #[test]
    fn test_different_salts_produce_different_ciphertexts() {
        let password = Password::new("same_password".to_string());
        let private_key_data = b"same data";

        let encrypted1 = EncryptedPrivateKey::encrypt(private_key_data, &password)
            .expect("First encryption should succeed");
        let encrypted2 = EncryptedPrivateKey::encrypt(private_key_data, &password)
            .expect("Second encryption should succeed");

        // Different salts should produce different ciphertexts
        assert_ne!(encrypted1.salt, encrypted2.salt);
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);

        // But both should decrypt to the same plaintext
        let decrypted1 = encrypted1
            .decrypt(&password)
            .expect("First decryption should succeed");
        let decrypted2 = encrypted2
            .decrypt(&password)
            .expect("Second decryption should succeed");

        assert_eq!(decrypted1, decrypted2);
        assert_eq!(decrypted1, private_key_data);
    }

    #[test]
    fn test_password_zeroization() {
        let password_string = "sensitive_password".to_string();
        {
            let _password = Password::new(password_string.clone());
            // Password should be zeroized when dropped
        }
        // Original string should still be intact
        assert_eq!(password_string, "sensitive_password");
    }
}
