//! Encrypted file-based storage for chat state.
//!
//! This module provides persistent storage for chat identities, contacts,
//! sessions, and messages. Each user's data is encrypted with their password
//! using Argon2 key derivation and AES-256-GCM encryption.

use crate::chat_state::{ChatState, StoredContact, StoredMessage};
use pqpgp::crypto::password::{EncryptedPrivateKey, Password};
use pqpgp::error::{PqpgpError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info};

/// Directory name for storing chat data
const STORAGE_DIR: &str = "pqpgp_chat_data";

/// Serializable version of chat state for storage
#[derive(Clone, Serialize, Deserialize)]
struct SerializableChatState {
    /// Serialized identity key pair
    identity: Option<Vec<u8>>,
    /// Serialized prekey generator
    prekey_generator: Option<Vec<u8>>,
    /// Serialized sessions by contact fingerprint
    sessions: HashMap<String, Vec<u8>>,
    /// Contacts (already serializable)
    contacts: HashMap<String, StoredContact>,
    /// Message history
    messages: HashMap<String, Vec<StoredMessage>>,
}

/// Stored encrypted user data on disk
#[derive(Serialize, Deserialize)]
struct EncryptedUserData {
    /// The encrypted chat state
    encrypted_state: EncryptedPrivateKey,
    /// User's fingerprint (for identification, not secret)
    fingerprint: String,
}

/// Storage manager for persisting chat state
pub struct ChatStorage {
    /// Base directory for storage
    base_dir: PathBuf,
}

impl ChatStorage {
    /// Creates a new storage manager
    pub fn new() -> Result<Self> {
        let base_dir = Self::get_storage_dir()?;

        // Create directory if it doesn't exist
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir).map_err(|e| {
                PqpgpError::config(format!("Failed to create storage directory: {}", e))
            })?;
            info!("Created storage directory: {:?}", base_dir);
        }

        Ok(Self { base_dir })
    }

    /// Gets the storage directory path
    fn get_storage_dir() -> Result<PathBuf> {
        // Use current directory + storage subdirectory
        let current_dir = std::env::current_dir()
            .map_err(|e| PqpgpError::config(format!("Failed to get current directory: {}", e)))?;
        Ok(current_dir.join(STORAGE_DIR))
    }

    /// Gets the file path for a user's data based on their fingerprint
    fn user_file_path(&self, fingerprint: &str) -> PathBuf {
        // Use first 16 chars of fingerprint as filename (still unique enough)
        let filename = format!("{}.pqchat", &fingerprint[..16.min(fingerprint.len())]);
        self.base_dir.join(filename)
    }

    /// Saves a chat state to disk, encrypted with the user's password
    pub fn save_state(&self, state: &ChatState, password: &Password) -> Result<()> {
        let fingerprint = match state.our_fingerprint() {
            Some(fp) => fp,
            None => return Ok(()), // Nothing to save if no identity
        };

        // Serialize the state
        let serializable = self.state_to_serializable(state)?;
        let state_bytes = bincode::serialize(&serializable)
            .map_err(|e| PqpgpError::config(format!("Failed to serialize state: {}", e)))?;

        // Encrypt with password
        let encrypted = EncryptedPrivateKey::encrypt(&state_bytes, password)?;

        // Create the stored data structure
        let user_data = EncryptedUserData {
            encrypted_state: encrypted,
            fingerprint: fingerprint.clone(),
        };

        // Serialize and write to file
        let file_bytes = bincode::serialize(&user_data)
            .map_err(|e| PqpgpError::config(format!("Failed to serialize user data: {}", e)))?;

        let file_path = self.user_file_path(&fingerprint);
        fs::write(&file_path, &file_bytes)
            .map_err(|e| PqpgpError::config(format!("Failed to write state file: {}", e)))?;

        debug!(
            fingerprint = %&fingerprint[..16],
            contacts = serializable.contacts.len(),
            sessions = serializable.sessions.len(),
            messages_threads = serializable.messages.len(),
            file_bytes = file_bytes.len(),
            "save_state: saved encrypted chat state"
        );
        info!("Saved chat state for {}", &fingerprint[..16]);
        Ok(())
    }

    /// Loads a chat state from disk using the user's password
    pub fn load_state(&self, fingerprint: &str, password: &Password) -> Result<ChatState> {
        let file_path = self.user_file_path(fingerprint);

        if !file_path.exists() {
            return Err(PqpgpError::config("No saved state found"));
        }

        // Read file
        let file_bytes = fs::read(&file_path)
            .map_err(|e| PqpgpError::config(format!("Failed to read state file: {}", e)))?;

        // Deserialize encrypted data
        let user_data: EncryptedUserData = bincode::deserialize(&file_bytes)
            .map_err(|e| PqpgpError::config(format!("Failed to deserialize user data: {}", e)))?;

        // Decrypt with password
        let state_bytes = user_data.encrypted_state.decrypt(password)?;

        // Deserialize state
        let serializable: SerializableChatState = bincode::deserialize(&state_bytes)
            .map_err(|e| PqpgpError::config(format!("Failed to deserialize state: {}", e)))?;

        // Convert back to ChatState
        let state = self.serializable_to_state(serializable.clone())?;

        debug!(
            fingerprint = %&fingerprint[..16],
            contacts = serializable.contacts.len(),
            sessions = serializable.sessions.len(),
            messages_threads = serializable.messages.len(),
            file_bytes = file_bytes.len(),
            "load_state: loaded encrypted chat state"
        );
        info!("Loaded chat state for {}", &fingerprint[..16]);
        Ok(state)
    }

    /// Lists all stored user fingerprints
    pub fn list_users(&self) -> Result<Vec<String>> {
        let mut fingerprints = Vec::new();

        if !self.base_dir.exists() {
            return Ok(fingerprints);
        }

        let entries = fs::read_dir(&self.base_dir)
            .map_err(|e| PqpgpError::config(format!("Failed to read storage directory: {}", e)))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "pqchat").unwrap_or(false) {
                // Try to read the fingerprint from the file
                if let Ok(file_bytes) = fs::read(&path) {
                    if let Ok(user_data) = bincode::deserialize::<EncryptedUserData>(&file_bytes) {
                        // Only include non-empty fingerprints
                        if !user_data.fingerprint.is_empty() {
                            fingerprints.push(user_data.fingerprint);
                        }
                    }
                }
            }
        }

        debug!(
            users_found = fingerprints.len(),
            "list_users: listed stored user fingerprints"
        );

        Ok(fingerprints)
    }

    /// Checks if a user has saved data
    #[allow(dead_code)]
    pub fn has_saved_state(&self, fingerprint: &str) -> bool {
        self.user_file_path(fingerprint).exists()
    }

    /// Deletes a user's saved state
    #[allow(dead_code)]
    pub fn delete_state(&self, fingerprint: &str) -> Result<()> {
        let file_path = self.user_file_path(fingerprint);
        if file_path.exists() {
            fs::remove_file(&file_path)
                .map_err(|e| PqpgpError::config(format!("Failed to delete state file: {}", e)))?;
            info!("Deleted chat state for {}", &fingerprint[..16]);
        }
        Ok(())
    }

    /// Converts ChatState to serializable form
    fn state_to_serializable(&self, state: &ChatState) -> Result<SerializableChatState> {
        // Serialize identity
        let identity = state.identity_bytes()?;

        // Serialize prekey generator
        let prekey_generator = state.prekey_generator_bytes()?;

        // Serialize sessions
        let sessions = state.sessions_bytes()?;

        // Get contacts and messages (already cloneable)
        let contacts = state.contacts_map().clone();
        let messages = state.messages_map().clone();

        Ok(SerializableChatState {
            identity,
            prekey_generator,
            sessions,
            contacts,
            messages,
        })
    }

    /// Converts serializable form back to ChatState
    fn serializable_to_state(&self, data: SerializableChatState) -> Result<ChatState> {
        ChatState::from_serializable(
            data.identity,
            data.prekey_generator,
            data.sessions,
            data.contacts,
            data.messages,
        )
    }
}

impl Default for ChatStorage {
    fn default() -> Self {
        Self::new().expect("Failed to initialize storage")
    }
}
