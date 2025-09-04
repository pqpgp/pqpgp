//! Utility functions for CLI operations.

use crate::{crypto::Password, keyring::KeyringManager, Result};
use rpassword::prompt_password;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

/// Get the default keyring directory
pub fn get_keyring_dir() -> Result<PathBuf> {
    let home = env::var("HOME")
        .map_err(|_| crate::error::PqpgpError::keyring("HOME environment variable not set"))?;

    let keyring_dir = Path::new(&home).join(".pqpgp");

    // Create directory if it doesn't exist
    if !keyring_dir.exists() {
        fs::create_dir_all(&keyring_dir)?;
    }

    Ok(keyring_dir)
}

/// Create a keyring manager with the default directory and load existing data
pub fn create_keyring_manager() -> Result<KeyringManager> {
    let keyring_dir = get_keyring_dir()?;
    let mut keyring = KeyringManager::with_directory(&keyring_dir);
    keyring.load()?;
    Ok(keyring)
}

/// Read file contents
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

/// Write file contents
pub fn write_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(contents)?;
    Ok(())
}

/// Format Unix timestamp as human-readable string
pub fn format_timestamp(timestamp: u64) -> String {
    let datetime = UNIX_EPOCH + Duration::from_secs(timestamp);

    // Basic timestamp formatting for CLI display
    format!("{:?}", datetime)
}

/// Prompt for a password securely (no echo to terminal)
pub fn prompt_for_password(prompt: &str) -> Result<Password> {
    let password_str = prompt_password(format!("{}: ", prompt))
        .map_err(|e| crate::error::PqpgpError::crypto(format!("Failed to read password: {}", e)))?;

    if password_str.is_empty() {
        return Err(crate::error::PqpgpError::crypto("Password cannot be empty"));
    }

    Ok(Password::new(password_str))
}
