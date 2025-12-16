//! Chat message types and content handling.
//!
//! This module defines the message format for the chat protocol, including:
//! - Message payloads with various content types
//! - Attachments and media handling
//! - Message metadata (timestamps, IDs, replies)
//!
//! ## Message Structure
//!
//! Each message contains:
//! - Unique message ID (for deduplication and replies)
//! - Timestamp (sender's local time)
//! - Content type and data
//! - Optional reply-to reference
//! - Optional attachments

use crate::error::{PqpgpError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum message content size (10 MB).
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum attachment size (100 MB).
pub const MAX_ATTACHMENT_SIZE: usize = 100 * 1024 * 1024;

/// Maximum number of attachments per message.
pub const MAX_ATTACHMENTS: usize = 10;

/// Type of content in a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentType {
    /// Plain text message
    Text = 1,
    /// Image (JPEG, PNG, GIF, WebP)
    Image = 2,
    /// Audio message
    Audio = 3,
    /// Video message
    Video = 4,
    /// Generic file attachment
    File = 5,
    /// Location sharing
    Location = 6,
    /// Contact card
    Contact = 7,
    /// Reaction to another message
    Reaction = 8,
    /// Message edit
    Edit = 9,
    /// Message deletion
    Delete = 10,
    /// Read receipt
    ReadReceipt = 11,
    /// Typing indicator
    Typing = 12,
    /// Key update notification
    KeyUpdate = 13,
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentType::Text => write!(f, "Text"),
            ContentType::Image => write!(f, "Image"),
            ContentType::Audio => write!(f, "Audio"),
            ContentType::Video => write!(f, "Video"),
            ContentType::File => write!(f, "File"),
            ContentType::Location => write!(f, "Location"),
            ContentType::Contact => write!(f, "Contact"),
            ContentType::Reaction => write!(f, "Reaction"),
            ContentType::Edit => write!(f, "Edit"),
            ContentType::Delete => write!(f, "Delete"),
            ContentType::ReadReceipt => write!(f, "ReadReceipt"),
            ContentType::Typing => write!(f, "Typing"),
            ContentType::KeyUpdate => write!(f, "KeyUpdate"),
        }
    }
}

/// A unique message identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId([u8; 16]);

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl MessageId {
    /// Generates a new random message ID.
    pub fn generate() -> Result<Self> {
        let mut id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        Ok(Self(id))
    }

    /// Creates a message ID from bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the ID as bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// File attachment metadata and content.
#[derive(Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Unique attachment ID
    pub id: MessageId,
    /// Original filename
    pub filename: String,
    /// MIME type
    pub mime_type: String,
    /// File size in bytes
    pub size: u64,
    /// Encrypted file content (or reference for large files)
    pub data: AttachmentData,
    /// Optional thumbnail for images/videos
    pub thumbnail: Option<Vec<u8>>,
}

impl fmt::Debug for Attachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attachment")
            .field("id", &self.id)
            .field("filename", &self.filename)
            .field("mime_type", &self.mime_type)
            .field("size", &self.size)
            .finish()
    }
}

/// Attachment data - either inline or a reference.
#[derive(Clone, Serialize, Deserialize)]
pub enum AttachmentData {
    /// Inline data (for small attachments)
    Inline(Vec<u8>),
    /// Reference to external storage (for large attachments)
    Reference {
        /// Storage location/URL
        location: String,
        /// Encryption key for the attachment
        key: Vec<u8>,
        /// SHA3-512 hash of the encrypted data (as Vec for serde compatibility)
        hash: Vec<u8>,
    },
}

impl fmt::Debug for AttachmentData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttachmentData::Inline(data) => write!(f, "Inline({} bytes)", data.len()),
            AttachmentData::Reference { location, .. } => {
                write!(f, "Reference({})", location)
            }
        }
    }
}

/// Location data for location sharing.
#[derive(Clone, Serialize, Deserialize)]
pub struct Location {
    /// Latitude
    pub latitude: f64,
    /// Longitude
    pub longitude: f64,
    /// Optional accuracy in meters
    pub accuracy: Option<f32>,
    /// Optional place name
    pub name: Option<String>,
    /// Optional address
    pub address: Option<String>,
}

impl fmt::Debug for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Location")
            .field("lat", &self.latitude)
            .field("lon", &self.longitude)
            .field("name", &self.name)
            .finish()
    }
}

/// Reaction to a message.
#[derive(Clone, Serialize, Deserialize)]
pub struct Reaction {
    /// The message being reacted to
    pub target_message_id: MessageId,
    /// The reaction emoji or identifier
    pub reaction: String,
    /// Whether this removes a previous reaction
    pub remove: bool,
}

impl fmt::Debug for Reaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reaction")
            .field("target", &self.target_message_id)
            .field("reaction", &self.reaction)
            .field("remove", &self.remove)
            .finish()
    }
}

/// The payload of a chat message.
#[derive(Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    /// Unique message identifier
    pub message_id: MessageId,
    /// Timestamp when the message was created (Unix timestamp in milliseconds)
    pub timestamp: u64,
    /// Type of content
    pub content_type: ContentType,
    /// The actual content (interpretation depends on content_type)
    pub content: Vec<u8>,
    /// Optional: Message this is replying to
    pub reply_to: Option<MessageId>,
    /// Optional: Attachments
    pub attachments: Vec<Attachment>,
    /// Optional: Expiration time (for disappearing messages)
    pub expires_at: Option<u64>,
}

impl fmt::Debug for MessagePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessagePayload")
            .field("message_id", &self.message_id)
            .field("timestamp", &self.timestamp)
            .field("content_type", &self.content_type)
            .field("content_len", &self.content.len())
            .field("reply_to", &self.reply_to)
            .field("attachments", &self.attachments.len())
            .finish()
    }
}

impl MessagePayload {
    /// Creates a new text message.
    pub fn text(text: &str) -> Result<Self> {
        if text.len() > MAX_MESSAGE_SIZE {
            return Err(PqpgpError::validation("Message too large"));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Ok(Self {
            message_id: MessageId::generate()?,
            timestamp: now,
            content_type: ContentType::Text,
            content: text.as_bytes().to_vec(),
            reply_to: None,
            attachments: Vec::new(),
            expires_at: None,
        })
    }

    /// Creates a new text message as a reply.
    pub fn text_reply(text: &str, reply_to: MessageId) -> Result<Self> {
        let mut msg = Self::text(text)?;
        msg.reply_to = Some(reply_to);
        Ok(msg)
    }

    /// Creates a reaction message.
    pub fn reaction(target: MessageId, reaction: &str) -> Result<Self> {
        let reaction_data = Reaction {
            target_message_id: target,
            reaction: reaction.to_string(),
            remove: false,
        };

        let content = bincode::serialize(&reaction_data)
            .map_err(|e| PqpgpError::serialization(e.to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Ok(Self {
            message_id: MessageId::generate()?,
            timestamp: now,
            content_type: ContentType::Reaction,
            content,
            reply_to: None,
            attachments: Vec::new(),
            expires_at: None,
        })
    }

    /// Creates a read receipt.
    pub fn read_receipt(message_ids: &[MessageId]) -> Result<Self> {
        let content = bincode::serialize(message_ids)
            .map_err(|e| PqpgpError::serialization(e.to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Ok(Self {
            message_id: MessageId::generate()?,
            timestamp: now,
            content_type: ContentType::ReadReceipt,
            content,
            reply_to: None,
            attachments: Vec::new(),
            expires_at: None,
        })
    }

    /// Creates a typing indicator.
    pub fn typing(is_typing: bool) -> Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Ok(Self {
            message_id: MessageId::generate()?,
            timestamp: now,
            content_type: ContentType::Typing,
            content: vec![if is_typing { 1 } else { 0 }],
            reply_to: None,
            attachments: Vec::new(),
            expires_at: None,
        })
    }

    /// Creates a message with an inline attachment.
    pub fn with_attachment(
        text: Option<&str>,
        filename: &str,
        mime_type: &str,
        data: Vec<u8>,
    ) -> Result<Self> {
        if data.len() > MAX_ATTACHMENT_SIZE {
            return Err(PqpgpError::validation("Attachment too large"));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let attachment = Attachment {
            id: MessageId::generate()?,
            filename: filename.to_string(),
            mime_type: mime_type.to_string(),
            size: data.len() as u64,
            data: AttachmentData::Inline(data),
            thumbnail: None,
        };

        let content_type = match mime_type.split('/').next() {
            Some("image") => ContentType::Image,
            Some("audio") => ContentType::Audio,
            Some("video") => ContentType::Video,
            _ => ContentType::File,
        };

        Ok(Self {
            message_id: MessageId::generate()?,
            timestamp: now,
            content_type,
            content: text.map(|t| t.as_bytes().to_vec()).unwrap_or_default(),
            reply_to: None,
            attachments: vec![attachment],
            expires_at: None,
        })
    }

    /// Creates a location sharing message.
    pub fn location(lat: f64, lon: f64, name: Option<&str>) -> Result<Self> {
        let location = Location {
            latitude: lat,
            longitude: lon,
            accuracy: None,
            name: name.map(String::from),
            address: None,
        };

        let content =
            bincode::serialize(&location).map_err(|e| PqpgpError::serialization(e.to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Ok(Self {
            message_id: MessageId::generate()?,
            timestamp: now,
            content_type: ContentType::Location,
            content,
            reply_to: None,
            attachments: Vec::new(),
            expires_at: None,
        })
    }

    /// Sets the expiration time for a disappearing message.
    pub fn with_expiration(mut self, seconds: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.expires_at = Some(now + seconds);
        self
    }

    /// Returns the text content if this is a text message.
    pub fn as_text(&self) -> Option<&str> {
        if self.content_type == ContentType::Text {
            std::str::from_utf8(&self.content).ok()
        } else {
            None
        }
    }

    /// Returns the reaction data if this is a reaction.
    pub fn as_reaction(&self) -> Option<Reaction> {
        if self.content_type == ContentType::Reaction {
            bincode::deserialize(&self.content).ok()
        } else {
            None
        }
    }

    /// Returns the location data if this is a location message.
    pub fn as_location(&self) -> Option<Location> {
        if self.content_type == ContentType::Location {
            bincode::deserialize(&self.content).ok()
        } else {
            None
        }
    }

    /// Returns whether this message has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now >= expires
        } else {
            false
        }
    }

    /// Serializes the payload for encryption.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| PqpgpError::serialization(format!("Payload serialization failed: {}", e)))
    }

    /// Deserializes a payload from bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| {
            PqpgpError::serialization(format!("Payload deserialization failed: {}", e))
        })
    }
}

/// A complete chat message combining header and encrypted payload.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Protocol version
    pub version: u8,
    /// Whether this is an initial message (contains X3DH data)
    pub is_initial: bool,
    /// Encrypted header
    pub header: Vec<u8>,
    /// Encrypted payload
    pub payload: Vec<u8>,
}

impl fmt::Debug for ChatMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatMessage")
            .field("version", &self.version)
            .field("is_initial", &self.is_initial)
            .field("header_len", &self.header.len())
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl ChatMessage {
    /// Creates a new chat message.
    pub fn new(version: u8, is_initial: bool, header: Vec<u8>, payload: Vec<u8>) -> Self {
        Self {
            version,
            is_initial,
            header,
            payload,
        }
    }

    /// Returns the total size of the message.
    pub fn size(&self) -> usize {
        2 + self.header.len() + self.payload.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_id_generation() {
        let id1 = MessageId::generate().unwrap();
        let id2 = MessageId::generate().unwrap();

        // IDs should be unique
        assert_ne!(id1.as_bytes(), id2.as_bytes());
    }

    #[test]
    fn test_text_message() {
        let msg = MessagePayload::text("Hello, World!").unwrap();

        assert_eq!(msg.content_type, ContentType::Text);
        assert_eq!(msg.as_text(), Some("Hello, World!"));
        assert!(msg.reply_to.is_none());
        assert!(msg.attachments.is_empty());
    }

    #[test]
    fn test_text_reply() {
        let original = MessagePayload::text("Original").unwrap();
        let reply = MessagePayload::text_reply("Reply", original.message_id).unwrap();

        assert_eq!(reply.reply_to, Some(original.message_id));
    }

    #[test]
    fn test_reaction_message() {
        let target = MessageId::generate().unwrap();
        let msg = MessagePayload::reaction(target, "👍").unwrap();

        assert_eq!(msg.content_type, ContentType::Reaction);

        let reaction = msg.as_reaction().unwrap();
        assert_eq!(reaction.target_message_id, target);
        assert_eq!(reaction.reaction, "👍");
        assert!(!reaction.remove);
    }

    #[test]
    fn test_location_message() {
        let msg = MessagePayload::location(37.7749, -122.4194, Some("San Francisco")).unwrap();

        assert_eq!(msg.content_type, ContentType::Location);

        let location = msg.as_location().unwrap();
        assert!((location.latitude - 37.7749).abs() < 0.0001);
        assert!((location.longitude - (-122.4194)).abs() < 0.0001);
        assert_eq!(location.name, Some("San Francisco".to_string()));
    }

    #[test]
    fn test_disappearing_message() {
        let msg = MessagePayload::text("Secret").unwrap().with_expiration(0);

        // Should be expired immediately (0 seconds)
        assert!(msg.is_expired());

        let msg2 = MessagePayload::text("Not secret")
            .unwrap()
            .with_expiration(3600);
        assert!(!msg2.is_expired());
    }

    #[test]
    fn test_message_serialization() {
        let msg = MessagePayload::text("Test message").unwrap();

        let serialized = msg.serialize().unwrap();
        let deserialized = MessagePayload::deserialize(&serialized).unwrap();

        assert_eq!(msg.message_id, deserialized.message_id);
        assert_eq!(msg.content_type, deserialized.content_type);
        assert_eq!(msg.content, deserialized.content);
    }

    #[test]
    fn test_attachment_message() {
        let data = vec![0u8; 1024]; // 1KB of data
        let msg = MessagePayload::with_attachment(
            Some("Check out this file"),
            "test.png",
            "image/png",
            data.clone(),
        )
        .unwrap();

        assert_eq!(msg.content_type, ContentType::Image);
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].filename, "test.png");
        assert_eq!(msg.attachments[0].mime_type, "image/png");

        if let AttachmentData::Inline(ref inline_data) = msg.attachments[0].data {
            assert_eq!(inline_data.len(), 1024);
        } else {
            panic!("Expected inline data");
        }
    }

    #[test]
    fn test_read_receipt() {
        let id1 = MessageId::generate().unwrap();
        let id2 = MessageId::generate().unwrap();

        let receipt = MessagePayload::read_receipt(&[id1, id2]).unwrap();

        assert_eq!(receipt.content_type, ContentType::ReadReceipt);
    }

    #[test]
    fn test_typing_indicator() {
        let typing = MessagePayload::typing(true).unwrap();

        assert_eq!(typing.content_type, ContentType::Typing);
        assert_eq!(typing.content, vec![1]);

        let not_typing = MessagePayload::typing(false).unwrap();
        assert_eq!(not_typing.content, vec![0]);
    }

    #[test]
    fn test_content_type_display() {
        assert_eq!(format!("{}", ContentType::Text), "Text");
        assert_eq!(format!("{}", ContentType::Image), "Image");
        assert_eq!(format!("{}", ContentType::Reaction), "Reaction");
    }

    #[test]
    fn test_message_too_large() {
        let large_text = "x".repeat(MAX_MESSAGE_SIZE + 1);
        let result = MessagePayload::text(&large_text);

        assert!(result.is_err());
    }

    #[test]
    fn test_attachment_too_large() {
        let large_data = vec![0u8; MAX_ATTACHMENT_SIZE + 1];
        let result = MessagePayload::with_attachment(
            None,
            "large.bin",
            "application/octet-stream",
            large_data,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_chat_message() {
        let msg = ChatMessage::new(1, false, vec![1, 2, 3], vec![4, 5, 6, 7]);

        assert_eq!(msg.version, 1);
        assert!(!msg.is_initial);
        assert_eq!(msg.size(), 2 + 3 + 4);
    }
}
