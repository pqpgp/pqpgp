//! PGP packet format implementation for post-quantum cryptography.
//!
//! This module provides PGP-compatible packet structures and serialization
//! for post-quantum algorithms, following RFC 4880 with extensions for
//! new algorithm identifiers.

use crate::crypto::Algorithm;
use crate::error::{PqpgpError, Result};
use crate::validation::{Validator, MAX_PACKET_SIZE};
use serde::{Deserialize, Serialize};

/// PGP packet types defined in RFC 4880
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Public-Key Encrypted Session Key Packet
    PublicKeyEncryptedSessionKey = 1,
    /// Signature Packet  
    Signature = 2,
    /// Symmetric-Key Encrypted Session Key Packet
    SymmetricKeyEncryptedSessionKey = 3,
    /// One-Pass Signature Packet
    OnePassSignature = 4,
    /// Secret-Key Packet
    SecretKey = 5,
    /// Public-Key Packet
    PublicKey = 6,
    /// Secret-Subkey Packet
    SecretSubkey = 7,
    /// Compressed Data Packet
    CompressedData = 8,
    /// Symmetrically Encrypted Data Packet
    SymmetricallyEncryptedData = 9,
    /// Marker Packet
    Marker = 10,
    /// Literal Data Packet
    LiteralData = 11,
    /// Trust Packet
    Trust = 12,
    /// User ID Packet
    UserId = 13,
    /// Public-Subkey Packet
    PublicSubkey = 14,
    /// User Attribute Packet
    UserAttribute = 17,
    /// Sym. Encrypted and Integrity Protected Data Packet
    SymEncryptedIntegrityProtectedData = 18,
    /// Modification Detection Code Packet
    ModificationDetectionCode = 19,
}

/// PGP packet header format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// Packet type
    pub packet_type: PacketType,
    /// Packet body length
    pub length: usize,
    /// Whether this uses new packet format
    pub new_format: bool,
}

/// A complete PGP packet with header and body
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet header
    pub header: PacketHeader,
    /// Packet body data
    pub body: Vec<u8>,
}

/// Public key packet for post-quantum algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyPacket {
    /// Version (always 4 for our implementation)
    pub version: u8,
    /// Key creation time (Unix timestamp)
    pub created: u32,
    /// Public key algorithm
    pub algorithm: Algorithm,
    /// Public key material
    pub key_material: Vec<u8>,
}

/// Secret key packet for post-quantum algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKeyPacket {
    /// Version (always 4 for our implementation)
    pub version: u8,
    /// Key creation time (Unix timestamp)  
    pub created: u32,
    /// Public key algorithm
    pub algorithm: Algorithm,
    /// Public key material
    pub public_key_material: Vec<u8>,
    /// String-to-key usage (0 = unencrypted)
    pub s2k_usage: u8,
    /// Secret key material
    pub secret_key_material: Vec<u8>,
    /// Checksum of secret key material
    pub checksum: u16,
}

/// Signature packet for post-quantum digital signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturePacket {
    /// Version (always 4 for our implementation)
    pub version: u8,
    /// Signature type (e.g., 0x00 for binary document)
    pub signature_type: u8,
    /// Public key algorithm used for signature
    pub public_key_algorithm: Algorithm,
    /// Hash algorithm used
    pub hash_algorithm: Algorithm,
    /// Hashed subpackets length
    pub hashed_subpackets_len: u16,
    /// Hashed subpackets data
    pub hashed_subpackets: Vec<u8>,
    /// Unhashed subpackets length
    pub unhashed_subpackets_len: u16,
    /// Unhashed subpackets data
    pub unhashed_subpackets: Vec<u8>,
    /// Hash prefix (first 2 bytes of hash)
    pub hash_prefix: [u8; 2],
    /// Signature material
    pub signature_material: Vec<u8>,
}

/// User ID packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdPacket {
    /// User ID string (typically email or name)
    pub user_id: String,
}

impl PacketType {
    /// Convert packet type to byte value
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Convert byte value to packet type
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::PublicKeyEncryptedSessionKey),
            2 => Some(Self::Signature),
            3 => Some(Self::SymmetricKeyEncryptedSessionKey),
            4 => Some(Self::OnePassSignature),
            5 => Some(Self::SecretKey),
            6 => Some(Self::PublicKey),
            7 => Some(Self::SecretSubkey),
            8 => Some(Self::CompressedData),
            9 => Some(Self::SymmetricallyEncryptedData),
            10 => Some(Self::Marker),
            11 => Some(Self::LiteralData),
            12 => Some(Self::Trust),
            13 => Some(Self::UserId),
            14 => Some(Self::PublicSubkey),
            17 => Some(Self::UserAttribute),
            18 => Some(Self::SymEncryptedIntegrityProtectedData),
            19 => Some(Self::ModificationDetectionCode),
            _ => None,
        }
    }
}

impl PacketHeader {
    /// Create a new packet header
    pub fn new(packet_type: PacketType, length: usize) -> Self {
        Self {
            packet_type,
            length,
            new_format: true, // Always use new format for simplicity
        }
    }

    /// Serialize packet header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        if self.new_format {
            // New packet format: first byte is 0xC0 + packet type
            bytes.push(0xC0 | self.packet_type.to_byte());

            // Length encoding for new format
            if self.length < 192 {
                bytes.push(self.length as u8);
            } else if self.length < 8384 {
                let encoded = self.length - 192;
                bytes.push(192 + (encoded >> 8) as u8);
                bytes.push((encoded & 0xFF) as u8);
            } else {
                // 5-byte length
                bytes.push(0xFF);
                bytes.extend_from_slice(&(self.length as u32).to_be_bytes());
            }
        } else {
            // Old packet format (not implemented for simplicity)
            unimplemented!("Old packet format not supported");
        }

        bytes
    }

    /// Parse packet header from bytes with comprehensive validation
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        // Basic input validation
        if data.is_empty() {
            return Err(PqpgpError::validation("Empty packet header"));
        }

        // Validate minimum reasonable input size
        if data.len() > MAX_PACKET_SIZE + 10 {
            // Allow some overhead for header
            return Err(PqpgpError::validation(format!(
                "Input data too large: {} bytes exceeds maximum packet size",
                data.len()
            )));
        }

        let first_byte = data[0];
        let mut consumed = 1;

        // Validate PGP packet format
        if (first_byte & 0x80) == 0 {
            return Err(PqpgpError::validation("Invalid packet header: MSB not set"));
        }

        if (first_byte & 0x40) != 0 {
            // New packet format
            let packet_type_byte = first_byte & 0x3F;
            let packet_type = PacketType::from_byte(packet_type_byte).ok_or_else(|| {
                PqpgpError::packet(format!("Unknown packet type: {}", packet_type_byte))
            })?;

            if data.len() < 2 {
                return Err(PqpgpError::validation("Incomplete packet header"));
            }

            let (length, length_bytes) = if data[1] < 192 {
                (data[1] as usize, 1)
            } else if data[1] < 224 {
                if data.len() < 3 {
                    return Err(PqpgpError::validation("Incomplete two-byte length"));
                }
                let len = ((data[1] as usize - 192) << 8) + data[2] as usize + 192;
                (len, 2)
            } else if data[1] == 255 {
                if data.len() < 6 {
                    return Err(PqpgpError::validation("Incomplete five-byte length"));
                }
                // Use safe integer parsing with validation
                let len_u32 = Validator::validate_u32_from_bytes(data, 2)?;
                let len = len_u32 as usize;

                // Validate length is reasonable
                Validator::validate_packet_size(len)?;

                (len, 5)
            } else {
                return Err(PqpgpError::validation("Partial body length not supported"));
            };

            consumed += length_bytes;

            Ok((
                Self {
                    packet_type,
                    length,
                    new_format: true,
                },
                consumed,
            ))
        } else {
            Err(PqpgpError::validation("Old packet format not supported"))
        }
    }
}

impl Packet {
    /// Create a new packet
    pub fn new(packet_type: PacketType, body: Vec<u8>) -> Self {
        let header = PacketHeader::new(packet_type, body.len());
        Self { header, body }
    }

    /// Serialize packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// Parse packet from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let (header, header_len) = PacketHeader::from_bytes(data)?;

        if data.len() < header_len + header.length {
            return Err(PqpgpError::packet("Incomplete packet body"));
        }

        let body = data[header_len..header_len + header.length].to_vec();

        Ok(Self { header, body })
    }
}

impl PublicKeyPacket {
    /// Create a new public key packet from post-quantum key
    pub fn from_public_key(public_key: &crate::crypto::PublicKey) -> Self {
        Self {
            version: 4,
            created: public_key.metadata().created as u32,
            algorithm: public_key.algorithm(),
            key_material: public_key.as_bytes(),
        }
    }

    /// Serialize to packet body bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.extend_from_slice(&self.created.to_be_bytes());
        bytes.push(self.algorithm as u8);

        // Key material with MPI encoding
        let key_len = self.key_material.len();
        bytes.extend_from_slice(&((key_len * 8) as u16).to_be_bytes()); // bit length
        bytes.extend_from_slice(&self.key_material);

        bytes
    }

    /// Parse from packet body bytes with comprehensive validation
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Basic input validation
        if data.len() < 6 {
            return Err(PqpgpError::validation("Public key packet too short"));
        }

        // Validate total packet size
        Validator::validate_key_size(data)?;

        let version = data[0];
        if version != 4 {
            return Err(PqpgpError::validation(format!(
                "Unsupported key version: {}",
                version
            )));
        }

        // Use safe integer parsing with validation
        let created = Validator::validate_u32_from_bytes(data, 1)?;
        let algorithm_byte = data[5];

        // Validate algorithm ID
        let valid_algorithms = [100, 101]; // Mlkem768, Mldsa65
        Validator::validate_algorithm_id(algorithm_byte, &valid_algorithms)?;

        let algorithm = match algorithm_byte {
            100 => Algorithm::Mlkem768,
            101 => Algorithm::Mldsa65,
            _ => {
                return Err(PqpgpError::validation(format!(
                    "Unsupported algorithm: {}",
                    algorithm_byte
                )))
            }
        };

        // Parse MPI-encoded key material with validation
        if data.len() < 8 {
            return Err(PqpgpError::validation("Missing key material length"));
        }

        let key_bit_len = Validator::validate_u16_from_bytes(data, 6)? as usize;
        let key_byte_len = key_bit_len.div_ceil(8); // Round up to nearest byte

        // Validate key material length is reasonable
        if key_byte_len > 10240 {
            // 10KB max for post-quantum keys
            return Err(PqpgpError::validation(format!(
                "Key material too large: {} bytes",
                key_byte_len
            )));
        }

        if data.len() < 8 + key_byte_len {
            return Err(PqpgpError::validation("Incomplete key material"));
        }

        let key_material = Validator::validate_slice_extraction(data, 8, key_byte_len)?.to_vec();

        Ok(Self {
            version,
            created,
            algorithm,
            key_material,
        })
    }
}

impl UserIdPacket {
    /// Create a new User ID packet
    pub fn new(user_id: String) -> Self {
        Self { user_id }
    }

    /// Serialize to packet body bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.user_id.as_bytes().to_vec()
    }

    /// Parse from packet body bytes with validation
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Basic size validation
        if data.is_empty() {
            return Err(PqpgpError::validation("Empty User ID packet"));
        }

        // Convert to string with validation
        let user_id = String::from_utf8(data.to_vec())
            .map_err(|_| PqpgpError::validation("Invalid UTF-8 in User ID"))?;

        // Validate User ID content
        Validator::validate_user_id(&user_id)?;

        Ok(Self { user_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use rand::rngs::OsRng;

    #[test]
    fn test_packet_type_conversion() {
        assert_eq!(PacketType::PublicKey.to_byte(), 6);
        assert_eq!(PacketType::from_byte(6), Some(PacketType::PublicKey));
        assert_eq!(PacketType::from_byte(255), None);
    }

    #[test]
    fn test_packet_header_serialization() {
        let header = PacketHeader::new(PacketType::PublicKey, 100);
        let bytes = header.to_bytes();

        let (parsed_header, consumed) = PacketHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed_header.packet_type, PacketType::PublicKey);
        assert_eq!(parsed_header.length, 100);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_packet_serialization() {
        let body = vec![1, 2, 3, 4, 5];
        let packet = Packet::new(PacketType::UserId, body.clone());
        let bytes = packet.to_bytes();

        let parsed_packet = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed_packet.header.packet_type, PacketType::UserId);
        assert_eq!(parsed_packet.body, body);
    }

    #[test]
    fn test_public_key_packet() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_mlkem768(&mut rng).unwrap();

        let pk_packet = PublicKeyPacket::from_public_key(keypair.public_key());
        let bytes = pk_packet.to_bytes();

        let parsed = PublicKeyPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.algorithm, Algorithm::Mlkem768);
        assert_eq!(parsed.key_material, keypair.public_key().as_bytes());
    }

    #[test]
    fn test_user_id_packet() {
        let user_id = "Alice <alice@example.com>".to_string();
        let packet = UserIdPacket::new(user_id.clone());
        let bytes = packet.to_bytes();

        let parsed = UserIdPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.user_id, user_id);
    }

    #[test]
    fn test_packet_header_length_encoding() {
        // Test different length encodings
        let test_cases = vec![
            (50, vec![0xC0 | PacketType::PublicKey.to_byte(), 50]),
            (
                200,
                vec![0xC0 | PacketType::PublicKey.to_byte(), 192 + 0, 8],
            ), // 200 = 192 + 8
            (
                10000,
                vec![0xC0 | PacketType::PublicKey.to_byte(), 255, 0, 0, 39, 16],
            ), // 10000 in big-endian
        ];

        for (length, expected_bytes) in test_cases {
            let header = PacketHeader::new(PacketType::PublicKey, length);
            let bytes = header.to_bytes();
            assert_eq!(bytes, expected_bytes);

            let (parsed, _) = PacketHeader::from_bytes(&bytes).unwrap();
            assert_eq!(parsed.length, length);
        }
    }
}
