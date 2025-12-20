//! Thread root node for the DAG-based forum system.
//!
//! A ThreadRoot starts a new discussion thread within a board. It contains
//! the thread title and initial post body. Any authenticated user can create
//! threads.
//!
//! Threads are where discussions happen. Users reply to threads by creating
//! Post nodes that reference the thread root.

use crate::crypto::{sign_data, verify_data_signature, PublicKey, Signature};
use crate::error::{PqpgpError, Result};
use crate::forum::types::{current_timestamp_millis, ContentHash, NodeType};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum length for thread title in characters.
pub const MAX_THREAD_TITLE_LENGTH: usize = 200;

/// Maximum length for thread body in bytes (100 KB).
pub const MAX_THREAD_BODY_SIZE: usize = 100 * 1024;

/// The content of a thread root node that gets signed and hashed.
///
/// This structure is serialized with bincode for deterministic hashing and signing.
/// The content hash of this struct becomes the thread's unique identifier.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreadRootContent {
    /// Node type discriminator (always ThreadRoot).
    pub node_type: NodeType,
    /// Hash of the parent board genesis.
    pub board_hash: ContentHash,
    /// Thread title.
    pub title: String,
    /// Initial post body content.
    pub body: String,
    /// Public key bytes of the thread author.
    pub author_identity: Vec<u8>,
    /// Creation timestamp in milliseconds since Unix epoch.
    pub created_at: u64,
}

impl fmt::Debug for ThreadRootContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreadRootContent")
            .field("node_type", &self.node_type)
            .field("board_hash", &self.board_hash)
            .field("title", &self.title)
            .field("body_len", &self.body.len())
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl ThreadRootContent {
    /// Creates new thread root content.
    ///
    /// # Arguments
    /// * `board_hash` - Hash of the parent board genesis
    /// * `title` - Thread title (1-200 characters)
    /// * `body` - Initial post body (up to 100 KB)
    /// * `author_public_key` - Public key of the thread author
    ///
    /// # Errors
    /// Returns an error if:
    /// - Title is empty or exceeds 200 characters
    /// - Body exceeds 100 KB
    pub fn new(
        board_hash: ContentHash,
        title: String,
        body: String,
        author_public_key: &PublicKey,
    ) -> Result<Self> {
        // Validate title
        if title.is_empty() {
            return Err(PqpgpError::validation("Thread title cannot be empty"));
        }
        if title.len() > MAX_THREAD_TITLE_LENGTH {
            return Err(PqpgpError::validation(format!(
                "Thread title exceeds maximum length of {} characters",
                MAX_THREAD_TITLE_LENGTH
            )));
        }

        // Validate body
        if body.len() > MAX_THREAD_BODY_SIZE {
            return Err(PqpgpError::validation(format!(
                "Thread body exceeds maximum size of {} bytes",
                MAX_THREAD_BODY_SIZE
            )));
        }

        Ok(Self {
            node_type: NodeType::ThreadRoot,
            board_hash,
            title,
            body,
            author_identity: author_public_key.as_bytes(),
            created_at: current_timestamp_millis(),
        })
    }

    /// Computes the content hash of this thread root content.
    pub fn content_hash(&self) -> Result<ContentHash> {
        ContentHash::compute(self)
    }
}

/// A complete thread root node with content, signature, and content hash.
///
/// This starts a new discussion thread within a board.
#[derive(Clone, Serialize, Deserialize)]
pub struct ThreadRoot {
    /// The signed content of this node.
    pub content: ThreadRootContent,
    /// ML-DSA-87 signature over the content.
    pub signature: Signature,
    /// Content hash - the unique identifier of this node.
    pub content_hash: ContentHash,
}

impl fmt::Debug for ThreadRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreadRoot")
            .field("title", &self.content.title)
            .field("board_hash", &self.content.board_hash)
            .field("content_hash", &self.content_hash)
            .finish()
    }
}

impl ThreadRoot {
    /// Creates and signs a new thread root node.
    ///
    /// # Arguments
    /// * `board_hash` - Hash of the parent board genesis
    /// * `title` - Thread title
    /// * `body` - Initial post body
    /// * `author_public_key` - Public key of the thread author
    /// * `author_private_key` - Private key to sign with
    /// * `password` - Optional password if the private key is encrypted
    ///
    /// # Errors
    /// Returns an error if validation fails or signing fails.
    pub fn create(
        board_hash: ContentHash,
        title: String,
        body: String,
        author_public_key: &PublicKey,
        author_private_key: &crate::crypto::PrivateKey,
        password: Option<&crate::crypto::Password>,
    ) -> Result<Self> {
        let content = ThreadRootContent::new(board_hash, title, body, author_public_key)?;
        let content_hash = content.content_hash()?;
        let signature = sign_data(author_private_key, &content, password)?;

        Ok(Self {
            content,
            signature,
            content_hash,
        })
    }

    /// Verifies the signature and content hash of this node.
    ///
    /// # Arguments
    /// * `author_public_key` - Public key to verify the signature against
    ///
    /// # Errors
    /// Returns an error if:
    /// - The content hash doesn't match the computed hash
    /// - The signature is invalid
    pub fn verify(&self, author_public_key: &PublicKey) -> Result<()> {
        // Verify content hash
        let computed_hash = self.content.content_hash()?;
        if computed_hash != self.content_hash {
            return Err(PqpgpError::validation("Thread root content hash mismatch"));
        }

        // Verify signature
        verify_data_signature(author_public_key, &self.content, &self.signature)?;

        Ok(())
    }

    /// Returns the thread title.
    pub fn title(&self) -> &str {
        &self.content.title
    }

    /// Returns the thread body.
    pub fn body(&self) -> &str {
        &self.content.body
    }

    /// Returns the parent board hash.
    pub fn board_hash(&self) -> &ContentHash {
        &self.content.board_hash
    }

    /// Returns the author identity bytes.
    pub fn author_identity(&self) -> &[u8] {
        &self.content.author_identity
    }

    /// Returns the creation timestamp in milliseconds.
    pub fn created_at(&self) -> u64 {
        self.content.created_at
    }

    /// Returns the content hash (unique identifier).
    pub fn hash(&self) -> &ContentHash {
        &self.content_hash
    }

    /// Returns the node type.
    pub fn node_type(&self) -> NodeType {
        self.content.node_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::forum::{BoardGenesis, ForumGenesis};

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
    }

    fn create_test_board(keypair: &KeyPair) -> BoardGenesis {
        let forum = ForumGenesis::create(
            "Test Forum".to_string(),
            "A test forum".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create forum");

        BoardGenesis::create(
            *forum.hash(),
            "Test Board".to_string(),
            "A test board".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board")
    }

    #[test]
    fn test_thread_root_creation() {
        let keypair = create_test_keypair();
        let board = create_test_board(&keypair);

        let thread = ThreadRoot::create(
            *board.hash(),
            "Test Thread Title".to_string(),
            "This is the body of the first post in the thread.".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create thread root");

        assert_eq!(thread.title(), "Test Thread Title");
        assert_eq!(
            thread.body(),
            "This is the body of the first post in the thread."
        );
        assert_eq!(thread.board_hash(), board.hash());
        assert_eq!(thread.node_type(), NodeType::ThreadRoot);
    }

    #[test]
    fn test_thread_root_verification() {
        let keypair = create_test_keypair();
        let board = create_test_board(&keypair);

        let thread = ThreadRoot::create(
            *board.hash(),
            "Verified Thread".to_string(),
            "Testing verification".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create thread root");

        thread
            .verify(keypair.public_key())
            .expect("Verification failed");
    }

    #[test]
    fn test_thread_root_verification_wrong_key() {
        let author_keypair = create_test_keypair();
        let other_keypair = create_test_keypair();
        let board = create_test_board(&author_keypair);

        let thread = ThreadRoot::create(
            *board.hash(),
            "Thread".to_string(),
            "Body".to_string(),
            author_keypair.public_key(),
            author_keypair.private_key(),
            None,
        )
        .expect("Failed to create thread root");

        assert!(thread.verify(other_keypair.public_key()).is_err());
    }

    #[test]
    fn test_thread_root_empty_title_rejected() {
        let keypair = create_test_keypair();
        let board_hash = ContentHash::from_bytes([0u8; 64]);

        let result = ThreadRootContent::new(
            board_hash,
            "".to_string(),
            "Body".to_string(),
            keypair.public_key(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_thread_root_title_too_long() {
        let keypair = create_test_keypair();
        let board_hash = ContentHash::from_bytes([0u8; 64]);

        let long_title = "x".repeat(MAX_THREAD_TITLE_LENGTH + 1);
        let result = ThreadRootContent::new(
            board_hash,
            long_title,
            "Body".to_string(),
            keypair.public_key(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_thread_root_body_too_large() {
        let keypair = create_test_keypair();
        let board_hash = ContentHash::from_bytes([0u8; 64]);

        let large_body = "x".repeat(MAX_THREAD_BODY_SIZE + 1);
        let result = ThreadRootContent::new(
            board_hash,
            "Title".to_string(),
            large_body,
            keypair.public_key(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_thread_root_empty_body_allowed() {
        let keypair = create_test_keypair();
        let board = create_test_board(&keypair);

        // Empty body should be allowed (thread with just a title)
        let thread = ThreadRoot::create(
            *board.hash(),
            "Title Only Thread".to_string(),
            "".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create thread root with empty body");

        assert!(thread.body().is_empty());
    }

    #[test]
    fn test_thread_root_max_valid_title() {
        let keypair = create_test_keypair();
        let board_hash = ContentHash::from_bytes([0u8; 64]);

        let max_title = "x".repeat(MAX_THREAD_TITLE_LENGTH);
        let result = ThreadRootContent::new(
            board_hash,
            max_title,
            "Body".to_string(),
            keypair.public_key(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_thread_root_serialization_roundtrip() {
        let keypair = create_test_keypair();
        let board = create_test_board(&keypair);

        let thread = ThreadRoot::create(
            *board.hash(),
            "Serialization Test".to_string(),
            "Testing serialization roundtrip".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create thread root");

        let serialized = bincode::serialize(&thread).expect("Failed to serialize");
        let deserialized: ThreadRoot =
            bincode::deserialize(&serialized).expect("Failed to deserialize");

        assert_eq!(thread.title(), deserialized.title());
        assert_eq!(thread.body(), deserialized.body());
        assert_eq!(thread.content_hash, deserialized.content_hash);

        deserialized
            .verify(keypair.public_key())
            .expect("Verification failed after deserialization");
    }

    #[test]
    fn test_thread_root_different_authors() {
        let author1 = create_test_keypair();
        let author2 = create_test_keypair();
        let board = create_test_board(&author1);

        // Both users can create threads in the same board
        let thread1 = ThreadRoot::create(
            *board.hash(),
            "Thread by Author 1".to_string(),
            "Content from author 1".to_string(),
            author1.public_key(),
            author1.private_key(),
            None,
        )
        .expect("Failed to create thread 1");

        let thread2 = ThreadRoot::create(
            *board.hash(),
            "Thread by Author 2".to_string(),
            "Content from author 2".to_string(),
            author2.public_key(),
            author2.private_key(),
            None,
        )
        .expect("Failed to create thread 2");

        // Each verifies with their own key
        thread1
            .verify(author1.public_key())
            .expect("Thread 1 verification failed");
        thread2
            .verify(author2.public_key())
            .expect("Thread 2 verification failed");

        // Cross-verification should fail
        assert!(thread1.verify(author2.public_key()).is_err());
        assert!(thread2.verify(author1.public_key()).is_err());
    }
}
