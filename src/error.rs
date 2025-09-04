//! Error types for PQPGP operations.

use thiserror::Error;

/// Result type alias for PQPGP operations.
pub type Result<T> = std::result::Result<T, PqpgpError>;

/// Main error type for PQPGP operations.
#[derive(Error, Debug)]
pub enum PqpgpError {
    /// Cryptographic operation errors
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Key generation or validation errors
    #[error("Key error: {0}")]
    Key(String),

    /// Packet parsing or construction errors
    #[error("Packet error: {0}")]
    Packet(String),

    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization/deserialization errors
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid input or arguments
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Keyring management errors
    #[error("Keyring error: {0}")]
    Keyring(String),

    /// Armor encoding/decoding errors
    #[error("Armor error: {0}")]
    Armor(String),

    /// Message encryption/decryption errors
    #[error("Message error: {0}")]
    Message(String),

    /// Signature verification errors
    #[error("Signature error: {0}")]
    Signature(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Input validation errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// Password-related errors
    #[error("Password error: {0}")]
    Password(String),
}

impl PqpgpError {
    /// Creates a new cryptographic error.
    pub fn crypto<T: ToString>(msg: T) -> Self {
        Self::Crypto(msg.to_string())
    }

    /// Creates a new key error.
    pub fn key<T: ToString>(msg: T) -> Self {
        Self::Key(msg.to_string())
    }

    /// Creates a new packet error.
    pub fn packet<T: ToString>(msg: T) -> Self {
        Self::Packet(msg.to_string())
    }

    /// Creates a new serialization error.
    pub fn serialization<T: ToString>(msg: T) -> Self {
        Self::Serialization(msg.to_string())
    }

    /// Creates a new invalid input error.
    pub fn invalid_input<T: ToString>(msg: T) -> Self {
        Self::InvalidInput(msg.to_string())
    }

    /// Creates a new keyring error.
    pub fn keyring<T: ToString>(msg: T) -> Self {
        Self::Keyring(msg.to_string())
    }

    /// Creates a new armor error.
    pub fn armor<T: ToString>(msg: T) -> Self {
        Self::Armor(msg.to_string())
    }

    /// Creates a new message error.
    pub fn message<T: ToString>(msg: T) -> Self {
        Self::Message(msg.to_string())
    }

    /// Creates a new signature error.
    pub fn signature<T: ToString>(msg: T) -> Self {
        Self::Signature(msg.to_string())
    }

    /// Creates a new configuration error.
    pub fn config<T: ToString>(msg: T) -> Self {
        Self::Config(msg.to_string())
    }

    /// Creates a new validation error.
    pub fn validation<T: ToString>(msg: T) -> Self {
        Self::Validation(msg.to_string())
    }

    /// Creates a new password error.
    pub fn password<T: ToString>(msg: T) -> Self {
        Self::Password(msg.to_string())
    }
}
