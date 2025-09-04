//! Key management and keyring functionality for PQPGP.
//!
//! This module provides keyring management similar to GnuPG, allowing users
//! to store, retrieve, and manage collections of public and private keys
//! with their associated metadata and User IDs.

use crate::crypto::{KeyPair, PrivateKey, PublicKey};
use crate::error::{PqpgpError, Result};
use crate::packet::{Packet, PacketType, PublicKeyPacket, UserIdPacket};
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::PublicKey as SignTraitPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// A complete key entry in the keyring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// The public key
    pub public_key: PublicKey,
    /// Optional private key (if available)
    pub private_key: Option<PrivateKey>,
    /// Associated User IDs
    pub user_ids: Vec<String>,
    /// Key creation time
    pub created: u64,
    /// Key expiration time (None for no expiration)
    pub expires: Option<u64>,
    /// Whether this key is trusted
    pub trusted: bool,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Public keyring for storing public keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyring {
    /// Keys indexed by key ID
    keys: HashMap<u64, KeyEntry>,
    /// Alternative lookup by User ID
    user_id_index: HashMap<String, u64>,
    /// Keyring metadata
    metadata: HashMap<String, String>,
}

/// Private keyring for storing private keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKeyring {
    /// Private key entries indexed by key ID
    keys: HashMap<u64, KeyEntry>,
    /// Keyring metadata
    metadata: HashMap<String, String>,
}

/// Combined keyring manager for both public and private keys
#[derive(Debug)]
pub struct KeyringManager {
    /// Public keyring
    pub public_keyring: PublicKeyring,
    /// Private keyring  
    pub private_keyring: PrivateKeyring,
    /// Base directory for keyring files
    keyring_dir: Option<std::path::PathBuf>,
}

impl KeyEntry {
    /// Create a new key entry from a key pair
    pub fn from_keypair(keypair: &KeyPair, user_id: Option<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let user_ids = user_id.map(|id| vec![id]).unwrap_or_default();

        Self {
            public_key: keypair.public_key().clone(),
            private_key: Some(keypair.private_key().clone()),
            user_ids,
            created: now,
            expires: None,
            trusted: false,
            metadata: HashMap::new(),
        }
    }

    /// Create a new key entry from just a public key
    pub fn from_public_key(public_key: &PublicKey, user_id: Option<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let user_ids = user_id.map(|id| vec![id]).unwrap_or_default();

        Self {
            public_key: public_key.clone(),
            private_key: None,
            user_ids,
            created: now,
            expires: None,
            trusted: false,
            metadata: HashMap::new(),
        }
    }

    /// Get the key ID
    pub fn key_id(&self) -> u64 {
        self.public_key.key_id()
    }

    /// Check if this key entry has a private key
    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }

    /// Check if the key is expired
    pub fn is_expired(&self) -> bool {
        self.expires.is_some_and(|exp| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now > exp
        })
    }

    /// Add a User ID to this key entry
    pub fn add_user_id(&mut self, user_id: String) {
        if !self.user_ids.contains(&user_id) {
            self.user_ids.push(user_id);
        }
    }

    /// Set key expiration time
    pub fn set_expiration(&mut self, expires: Option<u64>) {
        self.expires = expires;
    }

    /// Set trust level for this key
    pub fn set_trusted(&mut self, trusted: bool) {
        self.trusted = trusted;
    }
}

impl PublicKeyring {
    /// Create a new empty public keyring
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            user_id_index: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a key entry to the keyring
    pub fn add_key(&mut self, entry: KeyEntry) -> Result<()> {
        let key_id = entry.key_id();

        // Check if key already exists
        if self.keys.contains_key(&key_id) {
            return Err(PqpgpError::keyring(format!(
                "Key {} already exists in keyring",
                key_id
            )));
        }

        // Add to user ID index
        for user_id in &entry.user_ids {
            self.user_id_index.insert(user_id.clone(), key_id);
        }

        // Add key
        self.keys.insert(key_id, entry);

        Ok(())
    }

    /// Get a key by key ID
    pub fn get_key(&self, key_id: u64) -> Option<&KeyEntry> {
        self.keys.get(&key_id)
    }

    /// Get a key by User ID
    pub fn get_key_by_user_id(&self, user_id: &str) -> Option<&KeyEntry> {
        self.user_id_index
            .get(user_id)
            .and_then(|key_id| self.keys.get(key_id))
    }

    /// Remove a key from the keyring
    pub fn remove_key(&mut self, key_id: u64) -> Result<KeyEntry> {
        let entry = self
            .keys
            .remove(&key_id)
            .ok_or_else(|| PqpgpError::keyring(format!("Key {} not found", key_id)))?;

        // Remove from user ID index
        for user_id in &entry.user_ids {
            self.user_id_index.remove(user_id);
        }

        Ok(entry)
    }

    /// List all key IDs in the keyring
    pub fn list_keys(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }

    /// Search for keys by User ID pattern
    pub fn search_keys(&self, pattern: &str) -> Vec<&KeyEntry> {
        self.keys
            .values()
            .filter(|entry| entry.user_ids.iter().any(|uid| uid.contains(pattern)))
            .collect()
    }

    /// Get the number of keys in the keyring
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Check if the keyring is empty
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Export key to PGP packet format
    pub fn export_key(&self, key_id: u64) -> Result<Vec<u8>> {
        let entry = self
            .get_key(key_id)
            .ok_or_else(|| PqpgpError::keyring(format!("Key {} not found", key_id)))?;

        let mut packets = Vec::new();

        // Public key packet
        let pk_packet = PublicKeyPacket::from_public_key(&entry.public_key);
        let pk_packet_data = Packet::new(PacketType::PublicKey, pk_packet.to_bytes());
        packets.extend_from_slice(&pk_packet_data.to_bytes());

        // User ID packets
        for user_id in &entry.user_ids {
            let uid_packet = UserIdPacket::new(user_id.clone());
            let uid_packet_data = Packet::new(PacketType::UserId, uid_packet.to_bytes());
            packets.extend_from_slice(&uid_packet_data.to_bytes());
        }

        Ok(packets)
    }

    /// Import key from PGP packet data
    pub fn import_key(&mut self, packet_data: &[u8]) -> Result<u64> {
        let mut offset = 0;
        let mut public_key: Option<PublicKey> = None;
        let mut user_ids = Vec::new();

        // Parse packets
        while offset < packet_data.len() {
            let remaining = &packet_data[offset..];
            let packet = Packet::from_bytes(remaining)?;
            offset += packet.header.to_bytes().len() + packet.body.len();

            match packet.header.packet_type {
                PacketType::PublicKey => {
                    let pk_packet = PublicKeyPacket::from_bytes(&packet.body)?;

                    // Generate deterministic key ID from the packet data
                    let key_id = crate::crypto::generate_key_id(
                        &pk_packet.key_material,
                        pk_packet.algorithm,
                        pk_packet.created as u64,
                    );

                    // Validate key material before import
                    Self::validate_key_material(&pk_packet)?;

                    // Convert packet back to our PublicKey format based on algorithm
                    public_key = match pk_packet.algorithm {
                        crate::crypto::Algorithm::Mlkem1024 => Some(PublicKey::new_mlkem1024(
                            KemPublicKey::from_bytes(&pk_packet.key_material).map_err(|_| {
                                PqpgpError::keyring("Invalid ML-KEM-1024 key material")
                            })?,
                            key_id,
                            crate::crypto::KeyUsage::encrypt_only(),
                        )),
                        crate::crypto::Algorithm::Mldsa87 => Some(PublicKey::new_mldsa87(
                            SignTraitPublicKey::from_bytes(&pk_packet.key_material).map_err(
                                |_| PqpgpError::keyring("Invalid ML-DSA-87 key material"),
                            )?,
                            key_id,
                            crate::crypto::KeyUsage::sign_only(),
                        )),
                        _ => {
                            return Err(PqpgpError::keyring(format!(
                                "Unsupported algorithm for import: {}",
                                pk_packet.algorithm
                            )))
                        }
                    };
                }
                PacketType::UserId => {
                    let uid_packet = UserIdPacket::from_bytes(&packet.body)?;
                    user_ids.push(uid_packet.user_id);
                }
                _ => {
                    // Skip unknown packets
                }
            }
        }

        let public_key =
            public_key.ok_or_else(|| PqpgpError::keyring("No public key found in packet data"))?;

        let key_id = public_key.key_id();
        let mut entry = KeyEntry::from_public_key(&public_key, None);
        entry.user_ids = user_ids;

        self.add_key(entry)?;
        Ok(key_id)
    }

    /// Validate key material before import to prevent malicious keys
    fn validate_key_material(pk_packet: &crate::packet::PublicKeyPacket) -> Result<()> {
        // Check packet version
        if pk_packet.version != 4 {
            return Err(PqpgpError::keyring(format!(
                "Unsupported key version: {}. Only version 4 is supported.",
                pk_packet.version
            )));
        }

        // Check key material size for known algorithms
        match pk_packet.algorithm {
            crate::crypto::Algorithm::Mlkem1024 => {
                const EXPECTED_SIZE: usize = 1568; // ML-KEM-1024 public key size
                if pk_packet.key_material.len() != EXPECTED_SIZE {
                    return Err(PqpgpError::keyring(format!(
                        "Invalid ML-KEM-1024 key material size: got {} bytes, expected {} bytes",
                        pk_packet.key_material.len(),
                        EXPECTED_SIZE
                    )));
                }
            }
            crate::crypto::Algorithm::Mldsa87 => {
                const EXPECTED_SIZE: usize = 2592; // ML-DSA-87 public key size
                if pk_packet.key_material.len() != EXPECTED_SIZE {
                    return Err(PqpgpError::keyring(format!(
                        "Invalid ML-DSA-87 key material size: got {} bytes, expected {} bytes",
                        pk_packet.key_material.len(),
                        EXPECTED_SIZE
                    )));
                }
            }
            _ => {
                return Err(PqpgpError::keyring(format!(
                    "Unsupported algorithm for validation: {}",
                    pk_packet.algorithm
                )));
            }
        }

        // Check creation time is reasonable (not in the future, not before 2000)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let year_2000 = 946684800; // Unix timestamp for 2000-01-01

        if pk_packet.created as u64 > now + 86400 {
            // Allow 1 day future for clock skew
            return Err(PqpgpError::keyring(
                "Key creation time is too far in the future",
            ));
        }

        if (pk_packet.created as u64) < year_2000 {
            return Err(PqpgpError::keyring(
                "Key creation time is unreasonably old (before 2000)",
            ));
        }

        Ok(())
    }
}

impl PrivateKeyring {
    /// Create a new empty private keyring
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a key entry with private key to the keyring
    pub fn add_key(&mut self, entry: KeyEntry) -> Result<()> {
        if entry.private_key.is_none() {
            return Err(PqpgpError::keyring(
                "Cannot add key entry without private key to private keyring",
            ));
        }

        let key_id = entry.key_id();

        if self.keys.contains_key(&key_id) {
            return Err(PqpgpError::keyring(format!(
                "Private key {} already exists in keyring",
                key_id
            )));
        }

        self.keys.insert(key_id, entry);
        Ok(())
    }

    /// Get a private key by key ID
    pub fn get_key(&self, key_id: u64) -> Option<&KeyEntry> {
        self.keys.get(&key_id)
    }

    /// Get private key component by key ID
    pub fn get_private_key(&self, key_id: u64) -> Option<&PrivateKey> {
        self.keys.get(&key_id)?.private_key.as_ref()
    }

    /// Remove a private key from the keyring
    pub fn remove_key(&mut self, key_id: u64) -> Result<KeyEntry> {
        self.keys
            .remove(&key_id)
            .ok_or_else(|| PqpgpError::keyring(format!("Private key {} not found", key_id)))
    }

    /// List all private key IDs
    pub fn list_keys(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }

    /// Get the number of private keys
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Check if the private keyring is empty
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl KeyringManager {
    /// Create a new keyring manager
    pub fn new() -> Self {
        Self {
            public_keyring: PublicKeyring::new(),
            private_keyring: PrivateKeyring::new(),
            keyring_dir: None,
        }
    }

    /// Create a keyring manager with a specific directory
    pub fn with_directory<P: AsRef<Path>>(path: P) -> Self {
        Self {
            public_keyring: PublicKeyring::new(),
            private_keyring: PrivateKeyring::new(),
            keyring_dir: Some(path.as_ref().to_path_buf()),
        }
    }

    /// Add a complete key pair to both keyrings
    pub fn add_keypair(&mut self, keypair: &KeyPair, user_id: Option<String>) -> Result<()> {
        let entry = KeyEntry::from_keypair(keypair, user_id);

        // Add to public keyring
        let mut public_entry = entry.clone();
        public_entry.private_key = None; // Remove private key for public keyring
        self.public_keyring.add_key(public_entry)?;

        // Add to private keyring
        self.private_keyring.add_key(entry)?;

        Ok(())
    }

    /// Add only a public key
    pub fn add_public_key(
        &mut self,
        public_key: &PublicKey,
        user_id: Option<String>,
    ) -> Result<()> {
        let entry = KeyEntry::from_public_key(public_key, user_id);
        self.public_keyring.add_key(entry)
    }

    /// Get a key entry by key ID (checks public keyring)
    pub fn get_key(&self, key_id: u64) -> Option<&KeyEntry> {
        self.public_keyring.get_key(key_id)
    }

    /// Get a private key by key ID
    pub fn get_private_key(&self, key_id: u64) -> Option<&PrivateKey> {
        self.private_keyring.get_private_key(key_id)
    }

    /// Check if we have the private key for a given key ID
    pub fn has_private_key(&self, key_id: u64) -> bool {
        self.private_keyring.get_key(key_id).is_some()
    }

    /// Save keyrings to files
    pub fn save(&self) -> Result<()> {
        let keyring_dir = self
            .keyring_dir
            .as_ref()
            .ok_or_else(|| PqpgpError::keyring("No keyring directory specified"))?;

        // Create directory if it doesn't exist
        if !keyring_dir.exists() {
            fs::create_dir_all(keyring_dir).map_err(|e| {
                PqpgpError::keyring(format!("Failed to create keyring directory: {}", e))
            })?;
        }

        // Save public keyring
        let public_path = keyring_dir.join("pubring.pgp");
        let public_data = bincode::serialize(&self.public_keyring).map_err(|e| {
            PqpgpError::serialization(format!("Failed to serialize public keyring: {}", e))
        })?;
        fs::write(&public_path, public_data)
            .map_err(|e| PqpgpError::keyring(format!("Failed to write public keyring: {}", e)))?;

        // Save private keyring
        let private_path = keyring_dir.join("secring.pgp");
        let private_data = bincode::serialize(&self.private_keyring).map_err(|e| {
            PqpgpError::serialization(format!("Failed to serialize private keyring: {}", e))
        })?;
        fs::write(&private_path, private_data)
            .map_err(|e| PqpgpError::keyring(format!("Failed to write private keyring: {}", e)))?;

        Ok(())
    }

    /// Load keyrings from files
    pub fn load(&mut self) -> Result<()> {
        let keyring_dir = self
            .keyring_dir
            .as_ref()
            .ok_or_else(|| PqpgpError::keyring("No keyring directory specified"))?;

        // Load public keyring
        let public_path = keyring_dir.join("pubring.pgp");
        if public_path.exists() {
            let public_data = fs::read(&public_path).map_err(|e| {
                PqpgpError::keyring(format!("Failed to read public keyring: {}", e))
            })?;
            self.public_keyring = bincode::deserialize(&public_data).map_err(|e| {
                PqpgpError::serialization(format!("Failed to deserialize public keyring: {}", e))
            })?;
        }

        // Load private keyring
        let private_path = keyring_dir.join("secring.pgp");
        if private_path.exists() {
            let private_data = fs::read(&private_path).map_err(|e| {
                PqpgpError::keyring(format!("Failed to read private keyring: {}", e))
            })?;
            self.private_keyring = bincode::deserialize(&private_data).map_err(|e| {
                PqpgpError::serialization(format!("Failed to deserialize private keyring: {}", e))
            })?;
        }

        Ok(())
    }

    /// List all keys with their information
    pub fn list_all_keys(&self) -> Vec<(u64, &KeyEntry, bool)> {
        self.public_keyring
            .keys
            .iter()
            .map(|(&key_id, entry)| {
                let has_private = self.has_private_key(key_id);
                (key_id, entry, has_private)
            })
            .collect()
    }
}

impl Default for PublicKeyring {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PrivateKeyring {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for KeyringManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    #[test]
    fn test_key_entry_creation() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();

        let entry = KeyEntry::from_keypair(&keypair, Some("test@example.com".to_string()));

        assert_eq!(entry.key_id(), keypair.key_id());
        assert!(entry.has_private_key());
        assert_eq!(entry.user_ids, vec!["test@example.com"]);
        assert!(!entry.is_expired());
        assert!(!entry.trusted);
    }

    #[test]
    fn test_public_keyring_operations() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();
        let mut keyring = PublicKeyring::new();

        let entry =
            KeyEntry::from_public_key(keypair.public_key(), Some("alice@example.com".to_string()));
        let key_id = entry.key_id();

        // Add key
        keyring.add_key(entry).unwrap();
        assert_eq!(keyring.len(), 1);
        assert!(!keyring.is_empty());

        // Get key
        let retrieved = keyring.get_key(key_id).unwrap();
        assert_eq!(retrieved.key_id(), key_id);

        // Get key by user ID
        let by_user_id = keyring.get_key_by_user_id("alice@example.com").unwrap();
        assert_eq!(by_user_id.key_id(), key_id);

        // Search keys
        let search_results = keyring.search_keys("alice");
        assert_eq!(search_results.len(), 1);

        // List keys
        let key_list = keyring.list_keys();
        assert_eq!(key_list, vec![key_id]);

        // Remove key
        let removed = keyring.remove_key(key_id).unwrap();
        assert_eq!(removed.key_id(), key_id);
        assert!(keyring.is_empty());
    }

    #[test]
    fn test_private_keyring_operations() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mldsa87(&mut rng).unwrap();
        let mut keyring = PrivateKeyring::new();

        let entry = KeyEntry::from_keypair(&keypair, Some("bob@example.com".to_string()));
        let key_id = entry.key_id();

        // Add key
        keyring.add_key(entry).unwrap();
        assert_eq!(keyring.len(), 1);

        // Get key
        let retrieved = keyring.get_key(key_id).unwrap();
        assert!(retrieved.has_private_key());

        // Get private key
        let private_key = keyring.get_private_key(key_id).unwrap();
        assert_eq!(private_key.key_id(), key_id);

        // Remove key
        let removed = keyring.remove_key(key_id).unwrap();
        assert_eq!(removed.key_id(), key_id);
        assert!(keyring.is_empty());
    }

    #[test]
    fn test_keyring_manager() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();
        let mut manager = KeyringManager::new();

        let key_id = keypair.key_id();

        // Add keypair
        manager
            .add_keypair(&keypair, Some("charlie@example.com".to_string()))
            .unwrap();

        // Check public key exists
        let public_entry = manager.get_key(key_id).unwrap();
        assert_eq!(public_entry.key_id(), key_id);
        assert!(!public_entry.has_private_key()); // Should not have private key in public keyring

        // Check private key exists
        assert!(manager.has_private_key(key_id));
        let private_key = manager.get_private_key(key_id).unwrap();
        assert_eq!(private_key.key_id(), key_id);

        // List all keys
        let all_keys = manager.list_all_keys();
        assert_eq!(all_keys.len(), 1);
        let (listed_key_id, _entry, has_private) = all_keys[0];
        assert_eq!(listed_key_id, key_id);
        assert!(has_private);
    }

    #[test]
    fn test_keyring_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let keyring_path = temp_dir.path().to_path_buf();

        let mut rng = OsRng;
        let keypair = KeyPair::generate_mldsa87(&mut rng).unwrap();
        let key_id = keypair.key_id();

        // Create and save keyring
        {
            let mut manager = KeyringManager::with_directory(&keyring_path);
            manager
                .add_keypair(&keypair, Some("dave@example.com".to_string()))
                .unwrap();
            manager.save().unwrap();
        }

        // Load keyring and verify
        {
            let mut manager = KeyringManager::with_directory(&keyring_path);
            manager.load().unwrap();

            assert!(manager.has_private_key(key_id));
            let entry = manager.get_key(key_id).unwrap();
            assert_eq!(entry.user_ids, vec!["dave@example.com"]);
        }
    }

    #[test]
    fn test_key_expiration() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();

        let mut entry = KeyEntry::from_keypair(&keypair, None);
        assert!(!entry.is_expired());

        // Set expiration in the past
        let past_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600; // 1 hour ago
        entry.set_expiration(Some(past_time));
        assert!(entry.is_expired());

        // Set expiration in the future
        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // 1 hour from now
        entry.set_expiration(Some(future_time));
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_key_trust() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem1024(&mut rng).unwrap();

        let mut entry = KeyEntry::from_keypair(&keypair, None);
        assert!(!entry.trusted);

        entry.set_trusted(true);
        assert!(entry.trusted);
    }

    #[test]
    fn test_multiple_user_ids() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mldsa87(&mut rng).unwrap();

        let mut entry = KeyEntry::from_keypair(&keypair, Some("primary@example.com".to_string()));
        entry.add_user_id("secondary@example.com".to_string());
        entry.add_user_id("alias@example.com".to_string());

        assert_eq!(entry.user_ids.len(), 3);
        assert!(entry.user_ids.contains(&"primary@example.com".to_string()));
        assert!(entry
            .user_ids
            .contains(&"secondary@example.com".to_string()));
        assert!(entry.user_ids.contains(&"alias@example.com".to_string()));

        // Adding duplicate should not increase count
        entry.add_user_id("primary@example.com".to_string());
        assert_eq!(entry.user_ids.len(), 3);
    }
}
