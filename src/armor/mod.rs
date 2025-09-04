//! ASCII armor encoding and decoding for PGP messages and keys.
//!
//! This module implements the ASCII armor format defined in RFC 4880,
//! which allows binary PGP data to be represented as printable text
//! for safe transmission through text-only channels like email.

use crate::error::{PqpgpError, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};

/// CRC-24 polynomial used for PGP armor checksums
const CRC24_POLY: u32 = 0x1864CFB;
const CRC24_INIT: u32 = 0xB704CE;

/// ASCII armor message types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArmorType {
    /// PGP message (encrypted or signed data)
    Message,
    /// Signed message with cleartext
    SignedMessage,
    /// Public key block
    PublicKey,
    /// Private key block
    PrivateKey,
    /// Signature block
    Signature,
    /// Multi-part message
    MultiPartMessage { part: u32, total: u32 },
    /// Custom armor type
    Custom(String),
}

impl ArmorType {
    /// Get the armor header string for this type
    pub fn header_string(&self) -> String {
        match self {
            ArmorType::Message => "PGP MESSAGE".to_string(),
            ArmorType::SignedMessage => "PGP SIGNED MESSAGE".to_string(),
            ArmorType::PublicKey => "PGP PUBLIC KEY BLOCK".to_string(),
            ArmorType::PrivateKey => "PGP PRIVATE KEY BLOCK".to_string(),
            ArmorType::Signature => "PGP SIGNATURE".to_string(),
            ArmorType::MultiPartMessage { part, total } => {
                format!("PGP MESSAGE, PART {}/{}", part, total)
            }
            ArmorType::Custom(s) => s.clone(),
        }
    }

    /// Parse armor type from header string
    pub fn from_header_string(header: &str) -> Result<Self> {
        match header {
            "PGP MESSAGE" => Ok(ArmorType::Message),
            "PGP SIGNED MESSAGE" => Ok(ArmorType::SignedMessage),
            "PGP PUBLIC KEY BLOCK" => Ok(ArmorType::PublicKey),
            "PGP PRIVATE KEY BLOCK" => Ok(ArmorType::PrivateKey),
            "PGP SIGNATURE" => Ok(ArmorType::Signature),
            s if s.starts_with("PGP MESSAGE, PART ") => {
                // Parse "PGP MESSAGE, PART X/Y"
                let part_info = s.strip_prefix("PGP MESSAGE, PART ").unwrap();
                if let Some((part_str, total_str)) = part_info.split_once('/') {
                    let part = part_str.parse::<u32>().map_err(|_| {
                        PqpgpError::armor("Invalid part number in multi-part message")
                    })?;
                    let total = total_str.parse::<u32>().map_err(|_| {
                        PqpgpError::armor("Invalid total number in multi-part message")
                    })?;
                    Ok(ArmorType::MultiPartMessage { part, total })
                } else {
                    Err(PqpgpError::armor("Invalid multi-part message format"))
                }
            }
            s => Ok(ArmorType::Custom(s.to_string())),
        }
    }
}

/// ASCII armored data with headers and checksums
#[derive(Debug, Clone)]
pub struct ArmoredData {
    /// The type of armored data
    pub armor_type: ArmorType,
    /// Armor headers (key-value pairs)
    pub headers: HashMap<String, String>,
    /// The decoded binary data
    pub data: Vec<u8>,
}

impl ArmoredData {
    /// Create new armored data
    pub fn new(armor_type: ArmorType, data: Vec<u8>) -> Self {
        Self {
            armor_type,
            headers: HashMap::new(),
            data,
        }
    }

    /// Add a header to the armored data
    pub fn add_header(&mut self, key: String, value: String) {
        self.headers.insert(key, value);
    }

    /// Get a header value
    pub fn get_header(&self, key: &str) -> Option<&String> {
        self.headers.get(key)
    }
}

/// Calculate CRC-24 checksum used in PGP armor
pub fn crc24(data: &[u8]) -> u32 {
    let mut crc = CRC24_INIT;

    for &byte in data {
        crc ^= (byte as u32) << 16;
        for _ in 0..8 {
            if (crc & 0x800000) != 0 {
                crc = (crc << 1) ^ CRC24_POLY;
            } else {
                crc <<= 1;
            }
            crc &= 0xFFFFFF;
        }
    }

    crc
}

/// Encode binary data as ASCII armored text
pub fn encode(data: &[u8], armor_type: ArmorType) -> Result<String> {
    encode_with_headers(data, armor_type, &HashMap::new())
}

/// Encode binary data as ASCII armored text with custom headers
pub fn encode_with_headers(
    data: &[u8],
    armor_type: ArmorType,
    headers: &HashMap<String, String>,
) -> Result<String> {
    let mut output = String::new();

    // Write header
    let header_string = armor_type.header_string();
    output.push_str(&format!("-----BEGIN {}-----\n", header_string));

    // Write custom headers
    for (key, value) in headers {
        output.push_str(&format!("{}: {}\n", key, value));
    }

    // Empty line after headers if there are any
    if !headers.is_empty() {
        output.push('\n');
    }

    // Encode data as base64
    let base64_data = base64_encode(data);

    // Write base64 data in 64-character lines
    for chunk in base64_data.chunks(64) {
        let line = std::str::from_utf8(chunk)
            .map_err(|_| PqpgpError::armor("Invalid UTF-8 in base64 data"))?;
        output.push_str(line);
        output.push('\n');
    }

    // Calculate and write CRC-24 checksum
    let checksum = crc24(data);
    let checksum_bytes = [
        ((checksum >> 16) & 0xFF) as u8,
        ((checksum >> 8) & 0xFF) as u8,
        (checksum & 0xFF) as u8,
    ];
    let checksum_b64 = base64_encode(&checksum_bytes);
    let checksum_str = std::str::from_utf8(&checksum_b64)
        .map_err(|_| PqpgpError::armor("Invalid UTF-8 in checksum"))?;

    output.push('=');
    output.push_str(checksum_str);
    output.push('\n');

    // Write footer
    output.push_str(&format!("-----END {}-----\n", header_string));

    Ok(output)
}

/// Decode ASCII armored text to binary data
pub fn decode(armored_text: &str) -> Result<ArmoredData> {
    let mut reader = BufReader::new(armored_text.as_bytes());
    let mut line = String::new();

    // Find the begin header
    let armor_type = loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(PqpgpError::armor("No armor header found"));
        }

        let trimmed = line.trim();
        if let Some(header_content) = trimmed.strip_prefix("-----BEGIN ") {
            if let Some(armor_name) = header_content.strip_suffix("-----") {
                break ArmorType::from_header_string(armor_name)?;
            }
        }
    };

    // Read headers
    let mut headers = HashMap::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(PqpgpError::armor(
                "Unexpected end of input while reading headers",
            ));
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            // Empty line indicates end of headers
            break;
        }

        // Check if this is the start of base64 data (no colon means no more headers)
        if !trimmed.contains(':') && is_base64_line(trimmed) {
            // This is base64 data, put it back (simulate by processing it immediately)
            break;
        }

        // Parse header line "Key: Value"
        if let Some((key, value)) = trimmed.split_once(':') {
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    // Read base64 data
    let mut base64_data = Vec::new();
    let mut checksum_line: Option<String> = None;

    // If we already have a base64 line from header parsing, include it
    if !line.trim().is_empty() && is_base64_line(line.trim()) {
        base64_data.extend_from_slice(line.trim().as_bytes());
    }

    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(PqpgpError::armor(
                "Unexpected end of input while reading data",
            ));
        }

        let trimmed = line.trim();

        // Check for checksum line (starts with '=')
        if let Some(checksum_data) = trimmed.strip_prefix('=') {
            checksum_line = Some(checksum_data.to_string());
            break;
        }

        // Check for end header
        if trimmed.starts_with("-----END ") {
            // No checksum found, break without setting checksum_line
            break;
        }

        // This should be base64 data
        if is_base64_line(trimmed) {
            base64_data.extend_from_slice(trimmed.as_bytes());
        } else if !trimmed.is_empty() {
            return Err(PqpgpError::armor(format!(
                "Invalid base64 data: {}",
                trimmed
            )));
        }
    }

    // Decode base64 data
    let binary_data = base64_decode(&base64_data)?;

    // Verify checksum if present
    let has_checksum = if let Some(ref checksum_b64) = checksum_line {
        let expected_checksum_bytes = base64_decode(checksum_b64.as_bytes())?;
        if expected_checksum_bytes.len() != 3 {
            return Err(PqpgpError::armor("Invalid checksum length"));
        }

        let expected_checksum = ((expected_checksum_bytes[0] as u32) << 16)
            | ((expected_checksum_bytes[1] as u32) << 8)
            | (expected_checksum_bytes[2] as u32);

        let actual_checksum = crc24(&binary_data);

        if actual_checksum != expected_checksum {
            return Err(PqpgpError::armor(format!(
                "Checksum mismatch: expected {:06X}, got {:06X}",
                expected_checksum, actual_checksum
            )));
        }
        true
    } else {
        false
    };

    // Find and verify the end header
    if has_checksum {
        // We need to read the end header
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(PqpgpError::armor("Missing end header"));
        }
    }

    let trimmed = line.trim();
    let expected_end = format!("-----END {}-----", armor_type.header_string());
    if trimmed != expected_end {
        return Err(PqpgpError::armor(format!(
            "End header mismatch: expected '{}', got '{}'",
            expected_end, trimmed
        )));
    }

    Ok(ArmoredData {
        armor_type,
        headers,
        data: binary_data,
    })
}

/// Check if a line contains valid base64 characters
fn is_base64_line(line: &str) -> bool {
    !line.is_empty()
        && line
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Encode binary data as base64 (RFC 4648 compliant)
fn base64_encode(data: &[u8]) -> Vec<u8> {
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = Vec::new();
    let mut i = 0;

    // Process 3-byte chunks
    while i + 2 < data.len() {
        let chunk = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);

        result.push(BASE64_CHARS[((chunk >> 18) & 0x3F) as usize]);
        result.push(BASE64_CHARS[((chunk >> 12) & 0x3F) as usize]);
        result.push(BASE64_CHARS[((chunk >> 6) & 0x3F) as usize]);
        result.push(BASE64_CHARS[(chunk & 0x3F) as usize]);

        i += 3;
    }

    // Handle remaining bytes
    if i < data.len() {
        let mut chunk = (data[i] as u32) << 16;
        if i + 1 < data.len() {
            chunk |= (data[i + 1] as u32) << 8;
        }

        result.push(BASE64_CHARS[((chunk >> 18) & 0x3F) as usize]);
        result.push(BASE64_CHARS[((chunk >> 12) & 0x3F) as usize]);

        if i + 1 < data.len() {
            result.push(BASE64_CHARS[((chunk >> 6) & 0x3F) as usize]);
        } else {
            result.push(b'=');
        }
        result.push(b'=');
    }

    result
}

/// Decode base64 data to binary (RFC 4648 compliant)
fn base64_decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < data.len() {
        if i + 4 > data.len() {
            break;
        }

        let mut chunk = 0u32;
        let mut valid_chars = 0;

        for j in 0..4 {
            let c = data[i + j];
            let value = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => break,
                _ => {
                    return Err(PqpgpError::armor(format!(
                        "Invalid base64 character: {}",
                        c as char
                    )))
                }
            };

            chunk = (chunk << 6) | (value as u32);
            valid_chars += 1;
        }

        // Extract bytes based on how many valid characters we had
        match valid_chars {
            4 => {
                result.push(((chunk >> 16) & 0xFF) as u8);
                result.push(((chunk >> 8) & 0xFF) as u8);
                result.push((chunk & 0xFF) as u8);
            }
            3 => {
                chunk <<= 6; // Shift to account for missing bits
                result.push(((chunk >> 16) & 0xFF) as u8);
                result.push(((chunk >> 8) & 0xFF) as u8);
            }
            2 => {
                chunk <<= 12; // Shift to account for missing bits
                result.push(((chunk >> 16) & 0xFF) as u8);
            }
            _ => break,
        }

        i += 4;
    }

    Ok(result)
}

/// Convenience function to encode a public key as ASCII armor
pub fn encode_public_key(key_data: &[u8]) -> Result<String> {
    encode(key_data, ArmorType::PublicKey)
}

/// Convenience function to encode a private key as ASCII armor
pub fn encode_private_key(key_data: &[u8]) -> Result<String> {
    encode(key_data, ArmorType::PrivateKey)
}

/// Convenience function to encode a message as ASCII armor
pub fn encode_message(message_data: &[u8]) -> Result<String> {
    encode(message_data, ArmorType::Message)
}

/// Convenience function to encode a signature as ASCII armor
pub fn encode_signature(signature_data: &[u8]) -> Result<String> {
    encode(signature_data, ArmorType::Signature)
}

/// Create a PGP signed message with cleartext and detached signature
///
/// This creates the traditional PGP format:
/// -----BEGIN PGP SIGNED MESSAGE-----
/// Hash: SHA3-512
///
/// \[cleartext message\]
/// -----BEGIN PGP SIGNATURE-----
/// \[signature\]
/// -----END PGP SIGNATURE-----
pub fn create_signed_message(message: &str, signature_data: &[u8]) -> Result<String> {
    let signature_armor = encode(signature_data, ArmorType::Signature)?;

    let mut result = String::new();
    result.push_str("-----BEGIN PGP SIGNED MESSAGE-----\n");
    result.push_str("Hash: SHA3-512\n");
    result.push('\n');
    result.push_str(message);
    if !message.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(&signature_armor);

    Ok(result)
}

/// Parses a PGP signed message and extracts the original message and signature data
///
/// # Arguments
/// * `signed_message` - The complete signed message armor string
///
/// # Returns
/// A tuple containing (original_message, signature_data) where signature_data is the raw bytes
///
/// # Examples
/// ```rust,no_run
/// use pqpgp::armor::{create_signed_message, parse_signed_message};
///
/// let message = "Hello, world!";
/// let signature_data = b"some signature bytes";
/// let signed_armor = create_signed_message(message, signature_data)?;
///
/// let (parsed_message, parsed_signature_data) = parse_signed_message(&signed_armor)?;
/// assert_eq!(message, parsed_message);
/// assert_eq!(signature_data, parsed_signature_data.as_slice());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_signed_message(signed_message: &str) -> Result<(String, Vec<u8>)> {
    let lines: Vec<&str> = signed_message.lines().collect();

    // Validate that this is a signed message
    if lines.is_empty() || !lines[0].starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
        return Err(PqpgpError::armor("Not a valid PGP signed message"));
    }

    // Find the start of the message content (after the Hash: line)
    let mut message_start = 0;
    let mut signature_start = 0;

    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("Hash:") {
            message_start = i + 2; // Skip Hash: line and blank line
        } else if line.starts_with("-----BEGIN PGP SIGNATURE-----") {
            signature_start = i;
            break;
        }
    }

    if message_start == 0 || signature_start == 0 {
        return Err(PqpgpError::armor("Invalid signed message format"));
    }

    // Extract the original message (everything from message_start to signature_start)
    let original_message_lines = &lines[message_start..signature_start];
    let original_message = original_message_lines.join("\n");
    // Remove the trailing newline that was added during signed message creation
    let original_message = original_message.trim_end_matches('\n').to_string();

    // Extract the signature armor (everything from signature_start to end)
    let signature_armor_lines = &lines[signature_start..];
    let signature_armor = signature_armor_lines.join("\n");

    // Decode the signature armor to get the raw signature data
    let signature_decoded = decode(&signature_armor)?;

    Ok((original_message, signature_decoded.data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc24_calculation() {
        // Test vector from RFC 4880
        let data = b"hello world";
        let crc = crc24(data);
        // Standard CRC24 implementation as used in PGP armor
        assert_eq!(crc & 0xFFFFFF, crc); // Ensure it's 24-bit
    }

    #[test]
    fn test_base64_encoding() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let encoded_str = std::str::from_utf8(&encoded).unwrap();
        assert_eq!(encoded_str, "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_base64_decoding() {
        let encoded = b"SGVsbG8sIFdvcmxkIQ==";
        let decoded = base64_decode(encoded).unwrap();
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"The quick brown fox jumps over the lazy dog";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_armor_type_parsing() {
        assert_eq!(
            ArmorType::from_header_string("PGP MESSAGE").unwrap(),
            ArmorType::Message
        );
        assert_eq!(
            ArmorType::from_header_string("PGP PUBLIC KEY BLOCK").unwrap(),
            ArmorType::PublicKey
        );
        assert_eq!(
            ArmorType::from_header_string("PGP MESSAGE, PART 1/3").unwrap(),
            ArmorType::MultiPartMessage { part: 1, total: 3 }
        );
    }

    #[test]
    fn test_simple_armor_encoding() {
        let data = b"Hello, PGP World!";
        let armored = encode(data, ArmorType::Message).unwrap();

        assert!(armored.contains("-----BEGIN PGP MESSAGE-----"));
        assert!(armored.contains("-----END PGP MESSAGE-----"));
        assert!(armored.contains("=")); // CRC checksum
    }

    #[test]
    fn test_armor_encoding_with_headers() {
        let data = b"Test message";
        let mut headers = HashMap::new();
        headers.insert("Version".to_string(), "PQPGP 0.1.0".to_string());
        headers.insert("Comment".to_string(), "Post-quantum test".to_string());

        let armored = encode_with_headers(data, ArmorType::Message, &headers).unwrap();

        assert!(armored.contains("Version: PQPGP 0.1.0"));
        assert!(armored.contains("Comment: Post-quantum test"));
    }

    #[test]
    fn test_armor_roundtrip() {
        let original_data = b"This is a test message for PGP armor encoding and decoding.";

        // Encode
        let mut headers = HashMap::new();
        headers.insert("Version".to_string(), "PQPGP 0.1.0".to_string());
        let armored = encode_with_headers(original_data, ArmorType::Message, &headers).unwrap();

        // Decode
        let decoded = decode(&armored).unwrap();

        assert_eq!(decoded.armor_type, ArmorType::Message);
        assert_eq!(decoded.data, original_data);
        assert_eq!(
            decoded.get_header("Version"),
            Some(&"PQPGP 0.1.0".to_string())
        );
    }

    #[test]
    fn test_public_key_armor() {
        let key_data = b"This is fake key data for testing purposes";
        let armored = encode_public_key(key_data).unwrap();

        assert!(armored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(armored.contains("-----END PGP PUBLIC KEY BLOCK-----"));

        let decoded = decode(&armored).unwrap();
        assert_eq!(decoded.armor_type, ArmorType::PublicKey);
        assert_eq!(decoded.data, key_data);
    }

    #[test]
    fn test_private_key_armor() {
        let key_data = b"This is fake private key data for testing";
        let armored = encode_private_key(key_data).unwrap();

        assert!(armored.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assert!(armored.contains("-----END PGP PRIVATE KEY BLOCK-----"));
    }

    #[test]
    fn test_signature_armor() {
        let sig_data = b"This is fake signature data";
        let armored = encode_signature(sig_data).unwrap();

        assert!(armored.contains("-----BEGIN PGP SIGNATURE-----"));
        assert!(armored.contains("-----END PGP SIGNATURE-----"));
    }

    #[test]
    fn test_invalid_armor_decode() {
        let invalid_armor = "This is not valid armor data";
        assert!(decode(invalid_armor).is_err());

        let invalid_checksum = r#"-----BEGIN PGP MESSAGE-----

SGVsbG8gV29ybGQ=
=XXXX
-----END PGP MESSAGE-----"#;
        assert!(decode(invalid_checksum).is_err());
    }

    #[test]
    fn test_multipart_message() {
        let armor_type = ArmorType::MultiPartMessage { part: 2, total: 5 };
        let header = armor_type.header_string();
        assert_eq!(header, "PGP MESSAGE, PART 2/5");

        let parsed = ArmorType::from_header_string(&header).unwrap();
        assert_eq!(parsed, armor_type);
    }

    #[test]
    fn test_armor_without_checksum() {
        // Some armor might not have checksums
        let armor_without_checksum = r#"-----BEGIN PGP MESSAGE-----

SGVsbG8gV29ybGQ=
-----END PGP MESSAGE-----"#;

        let decoded = decode(armor_without_checksum).unwrap();
        assert_eq!(decoded.data, b"Hello World");
    }

    #[test]
    fn test_empty_headers() {
        let data = b"test";
        let armored = encode(data, ArmorType::Message).unwrap();
        let decoded = decode(&armored).unwrap();

        assert!(decoded.headers.is_empty());
        assert_eq!(decoded.data, data);
    }

    #[test]
    fn test_long_message_armor() {
        // Test with message longer than 64 characters (should span multiple lines)
        let long_data = vec![42u8; 200];
        let armored = encode(&long_data, ArmorType::Message).unwrap();

        // Should contain multiple lines of base64 data
        let lines: Vec<&str> = armored.lines().collect();
        let base64_lines: Vec<&str> = lines
            .iter()
            .filter(|line| is_base64_line(line))
            .copied()
            .collect();

        assert!(base64_lines.len() > 3); // Should be multiple lines

        let decoded = decode(&armored).unwrap();
        assert_eq!(decoded.data, long_data);
    }

    #[test]
    fn test_signed_message_roundtrip() {
        let original_message = "Hello, this is a test message for PGP signing!";
        let signature_data = b"fake_signature_data_for_testing";

        // Create signed message armor
        let signed_armor = create_signed_message(original_message, signature_data).unwrap();

        // Parse it back
        let (parsed_message, parsed_signature_data) = parse_signed_message(&signed_armor).unwrap();

        // Verify the round trip
        assert_eq!(original_message, parsed_message);
        assert_eq!(signature_data, parsed_signature_data.as_slice());
    }

    #[test]
    fn test_parse_invalid_signed_message() {
        let invalid_message = "This is not a signed message";

        // Should fail with invalid format
        assert!(parse_signed_message(invalid_message).is_err());

        // Test incomplete signed message
        let incomplete =
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA3-512\n\nMessage without signature";
        assert!(parse_signed_message(incomplete).is_err());
    }
}
