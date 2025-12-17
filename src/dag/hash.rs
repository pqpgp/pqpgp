//! Content-addressed hashing for DAG nodes.
//!
//! This module provides the `ContentHash` type, a 64-byte SHA3-512 hash used
//! as the content address for any DAG node. The hash is computed over bincode-
//! serialized data, ensuring deterministic addressing.

use crate::crypto::hash_data;
use crate::error::{PqpgpError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// A 64-byte content hash using SHA3-512.
///
/// This is the content address of any DAG node. The hash is computed over
/// the bincode-serialized content, ensuring deterministic addressing.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; 64]);

impl Serialize for ContentHash {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as a byte slice, which serde handles well
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ContentHashVisitor;

        impl<'de> serde::de::Visitor<'de> for ContentHashVisitor {
            type Value = ContentHash;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array of length 64")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 64 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(ContentHash(arr))
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; 64];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(ContentHash(arr))
            }
        }

        deserializer.deserialize_bytes(ContentHashVisitor)
    }
}

impl ContentHash {
    /// Computes the content hash of serializable data.
    ///
    /// Uses bincode for deterministic serialization, then SHA3-512 for hashing.
    pub fn compute<T: Serialize>(data: &T) -> Result<Self> {
        let serialized = bincode::serialize(data).map_err(|e| {
            PqpgpError::serialization(format!("Failed to serialize for hash: {}", e))
        })?;
        Ok(Self(hash_data(&serialized)))
    }

    /// Creates a ContentHash from raw bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the raw hash bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Returns hex-encoded string representation.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a ContentHash from a hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|_| PqpgpError::validation("Invalid hex string for ContentHash"))?;
        if bytes.len() != 64 {
            return Err(PqpgpError::validation(
                "ContentHash must be exactly 64 bytes (128 hex characters)",
            ));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Returns a short form of the hash for display (first 8 bytes / 16 hex chars).
    pub fn short(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({}...)", &self.to_hex()[..16])
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

/// Returns the current Unix timestamp in milliseconds.
pub fn current_timestamp_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_hash_compute() {
        let data = "test data";
        let hash1 = ContentHash::compute(&data).unwrap();
        let hash2 = ContentHash::compute(&data).unwrap();
        assert_eq!(hash1, hash2, "Same data should produce same hash");

        let other_data = "other data";
        let hash3 = ContentHash::compute(&other_data).unwrap();
        assert_ne!(hash1, hash3, "Different data should produce different hash");
    }

    #[test]
    fn test_content_hash_hex_roundtrip() {
        let data = "test data";
        let hash = ContentHash::compute(&data).unwrap();
        let hex = hash.to_hex();
        let parsed = ContentHash::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_content_hash_display() {
        let data = "test data";
        let hash = ContentHash::compute(&data).unwrap();
        let short = hash.short();
        assert_eq!(short.len(), 16, "Short form should be 16 hex characters");
    }
}
