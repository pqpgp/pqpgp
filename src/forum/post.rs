//! Post node for the DAG-based forum system.
//!
//! A Post is a reply within a thread. Posts can reference:
//! - The thread root (required)
//! - Parent posts within the same thread (for threaded replies)
//! - A quoted post (optional, for explicit quoting)
//!
//! Posts form the actual discussion content within threads. Any authenticated
//! user can create posts in any thread.

use crate::crypto::{sign_data, verify_data_signature, PublicKey, Signature};
use crate::error::{PqpgpError, Result};
use crate::forum::constants::{MAX_PARENT_HASHES, MAX_POST_BODY_SIZE};
use crate::forum::types::{current_timestamp_millis, ContentHash, NodeType};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The content of a post node that gets signed and hashed.
///
/// This structure is serialized with bincode for deterministic hashing and signing.
/// The content hash of this struct becomes the post's unique identifier.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostContent {
    /// Node type discriminator (always Post).
    pub node_type: NodeType,
    /// Hash of the thread root this post belongs to.
    pub thread_hash: ContentHash,
    /// Hashes of parent nodes (for DAG ordering).
    /// At minimum, should include the most recent post(s) the author has seen.
    pub parent_hashes: Vec<ContentHash>,
    /// Post body content.
    pub body: String,
    /// Optional hash of a post being quoted.
    pub quote_hash: Option<ContentHash>,
    /// Public key bytes of the post author.
    pub author_identity: Vec<u8>,
    /// Creation timestamp in milliseconds since Unix epoch.
    pub created_at: u64,
}

impl fmt::Debug for PostContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostContent")
            .field("node_type", &self.node_type)
            .field("thread_hash", &self.thread_hash)
            .field("parent_count", &self.parent_hashes.len())
            .field("body_len", &self.body.len())
            .field("has_quote", &self.quote_hash.is_some())
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl PostContent {
    /// Creates new post content.
    ///
    /// # Arguments
    /// * `thread_hash` - Hash of the thread root this post belongs to
    /// * `parent_hashes` - Hashes of parent nodes for DAG ordering
    /// * `body` - Post body content (up to 100 KB)
    /// * `quote_hash` - Optional hash of a post being quoted
    /// * `author_public_key` - Public key of the post author
    ///
    /// # Errors
    /// Returns an error if:
    /// - Body is empty or exceeds 100 KB
    /// - More than 10 parent hashes provided
    pub fn new(
        thread_hash: ContentHash,
        parent_hashes: Vec<ContentHash>,
        body: String,
        quote_hash: Option<ContentHash>,
        author_public_key: &PublicKey,
    ) -> Result<Self> {
        // Validate body
        if body.is_empty() {
            return Err(PqpgpError::validation("Post body cannot be empty"));
        }
        if body.len() > MAX_POST_BODY_SIZE {
            return Err(PqpgpError::validation(format!(
                "Post body exceeds maximum size of {} bytes",
                MAX_POST_BODY_SIZE
            )));
        }

        // Validate parent hashes
        if parent_hashes.len() > MAX_PARENT_HASHES {
            return Err(PqpgpError::validation(format!(
                "Post cannot have more than {} parent references",
                MAX_PARENT_HASHES
            )));
        }

        Ok(Self {
            node_type: NodeType::Post,
            thread_hash,
            parent_hashes,
            body,
            quote_hash,
            author_identity: author_public_key.as_bytes(),
            created_at: current_timestamp_millis(),
        })
    }

    /// Computes the content hash of this post content.
    pub fn content_hash(&self) -> Result<ContentHash> {
        ContentHash::compute(self)
    }
}

/// A complete post node with content, signature, and content hash.
///
/// Posts are replies within a thread. They form a DAG within the thread,
/// allowing for proper ordering even in distributed scenarios.
#[derive(Clone, Serialize, Deserialize)]
pub struct Post {
    /// The signed content of this node.
    pub content: PostContent,
    /// ML-DSA-87 signature over the content.
    pub signature: Signature,
    /// Content hash - the unique identifier of this node.
    pub content_hash: ContentHash,
}

impl fmt::Debug for Post {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Post")
            .field("thread_hash", &self.content.thread_hash)
            .field("content_hash", &self.content_hash)
            .field("body_len", &self.content.body.len())
            .finish()
    }
}

impl Post {
    /// Creates and signs a new post node.
    ///
    /// # Arguments
    /// * `thread_hash` - Hash of the thread root
    /// * `parent_hashes` - Hashes of parent nodes for DAG ordering
    /// * `body` - Post body content
    /// * `quote_hash` - Optional hash of a post being quoted
    /// * `author_public_key` - Public key of the post author
    /// * `author_private_key` - Private key to sign with
    /// * `password` - Optional password if the private key is encrypted
    ///
    /// # Errors
    /// Returns an error if validation fails or signing fails.
    pub fn create(
        thread_hash: ContentHash,
        parent_hashes: Vec<ContentHash>,
        body: String,
        quote_hash: Option<ContentHash>,
        author_public_key: &PublicKey,
        author_private_key: &crate::crypto::PrivateKey,
        password: Option<&crate::crypto::Password>,
    ) -> Result<Self> {
        let content = PostContent::new(
            thread_hash,
            parent_hashes,
            body,
            quote_hash,
            author_public_key,
        )?;
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
            return Err(PqpgpError::validation("Post content hash mismatch"));
        }

        // Verify signature
        verify_data_signature(author_public_key, &self.content, &self.signature)?;

        Ok(())
    }

    /// Returns the post body.
    pub fn body(&self) -> &str {
        &self.content.body
    }

    /// Returns the thread hash this post belongs to.
    pub fn thread_hash(&self) -> &ContentHash {
        &self.content.thread_hash
    }

    /// Returns the parent hashes for DAG ordering.
    pub fn parent_hashes(&self) -> &[ContentHash] {
        &self.content.parent_hashes
    }

    /// Returns the optional quote hash.
    pub fn quote_hash(&self) -> Option<&ContentHash> {
        self.content.quote_hash.as_ref()
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
    use crate::forum::{BoardGenesis, ForumGenesis, ThreadRoot};

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
    }

    fn create_test_thread(keypair: &KeyPair) -> ThreadRoot {
        let forum = ForumGenesis::create(
            "Test Forum".to_string(),
            "A test forum".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create forum");

        let board = BoardGenesis::create(
            *forum.hash(),
            "Test Board".to_string(),
            "A test board".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create board");

        ThreadRoot::create(
            *board.hash(),
            "Test Thread".to_string(),
            "Thread body".to_string(),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create thread")
    }

    #[test]
    fn test_post_creation() {
        let keypair = create_test_keypair();
        let thread = create_test_thread(&keypair);

        let post = Post::create(
            *thread.hash(),
            vec![*thread.hash()], // Parent is the thread root
            "This is a reply to the thread.".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create post");

        assert_eq!(post.body(), "This is a reply to the thread.");
        assert_eq!(post.thread_hash(), thread.hash());
        assert_eq!(post.parent_hashes(), &[*thread.hash()]);
        assert!(post.quote_hash().is_none());
        assert_eq!(post.node_type(), NodeType::Post);
    }

    #[test]
    fn test_post_verification() {
        let keypair = create_test_keypair();
        let thread = create_test_thread(&keypair);

        let post = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Verified post".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create post");

        post.verify(keypair.public_key())
            .expect("Verification failed");
    }

    #[test]
    fn test_post_verification_wrong_key() {
        let author_keypair = create_test_keypair();
        let other_keypair = create_test_keypair();
        let thread = create_test_thread(&author_keypair);

        let post = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Post body".to_string(),
            None,
            author_keypair.public_key(),
            author_keypair.private_key(),
            None,
        )
        .expect("Failed to create post");

        assert!(post.verify(other_keypair.public_key()).is_err());
    }

    #[test]
    fn test_post_with_quote() {
        let keypair = create_test_keypair();
        let thread = create_test_thread(&keypair);

        let first_post = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "First post".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create first post");

        // Second post quotes the first
        let reply = Post::create(
            *thread.hash(),
            vec![*first_post.hash()],
            "This is a reply quoting the first post".to_string(),
            Some(*first_post.hash()),
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create reply");

        assert_eq!(reply.quote_hash(), Some(first_post.hash()));
    }

    #[test]
    fn test_post_multiple_parents() {
        let keypair = create_test_keypair();
        let thread = create_test_thread(&keypair);

        // Create two posts
        let post1 = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Post 1".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create post 1");

        let post2 = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Post 2".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create post 2");

        // Create a post that has both as parents (merging branches)
        let merge_post = Post::create(
            *thread.hash(),
            vec![*post1.hash(), *post2.hash()],
            "Merge post".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create merge post");

        assert_eq!(merge_post.parent_hashes().len(), 2);
    }

    #[test]
    fn test_post_empty_body_rejected() {
        let keypair = create_test_keypair();
        let thread_hash = ContentHash::from_bytes([0u8; 64]);

        let result = PostContent::new(
            thread_hash,
            vec![],
            "".to_string(),
            None,
            keypair.public_key(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_post_body_too_large() {
        let keypair = create_test_keypair();
        let thread_hash = ContentHash::from_bytes([0u8; 64]);

        let large_body = "x".repeat(MAX_POST_BODY_SIZE + 1);
        let result = PostContent::new(thread_hash, vec![], large_body, None, keypair.public_key());

        assert!(result.is_err());
    }

    #[test]
    fn test_post_too_many_parents() {
        let keypair = create_test_keypair();
        let thread_hash = ContentHash::from_bytes([0u8; 64]);

        let too_many_parents: Vec<ContentHash> = (0..MAX_PARENT_HASHES + 1)
            .map(|i| ContentHash::from_bytes([i as u8; 64]))
            .collect();

        let result = PostContent::new(
            thread_hash,
            too_many_parents,
            "Body".to_string(),
            None,
            keypair.public_key(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_post_struct_allows_empty_parents() {
        // NOTE: While Post::create allows empty parent_hashes at the struct level,
        // the validation layer (validate_post) now requires at least one parent
        // to prevent orphaned subtrees in the DAG. This test verifies the struct
        // creation behavior; the validation behavior is tested in validation.rs.
        let keypair = create_test_keypair();
        let thread = create_test_thread(&keypair);

        // A post with no parent hashes (struct creation succeeds)
        let post = Post::create(
            *thread.hash(),
            vec![], // No parents - struct creation works
            "Post without parents".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Post struct creation should succeed even with empty parents");

        assert!(post.parent_hashes().is_empty());
        // NOTE: This post would fail validate_post() because it has no parent hashes
    }

    #[test]
    fn test_post_serialization_roundtrip() {
        let keypair = create_test_keypair();
        let thread = create_test_thread(&keypair);

        let post = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "Serialization test post".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create post");

        let serialized = bincode::serialize(&post).expect("Failed to serialize");
        let deserialized: Post = bincode::deserialize(&serialized).expect("Failed to deserialize");

        assert_eq!(post.body(), deserialized.body());
        assert_eq!(post.content_hash, deserialized.content_hash);

        deserialized
            .verify(keypair.public_key())
            .expect("Verification failed after deserialization");
    }

    #[test]
    fn test_post_chain() {
        let keypair = create_test_keypair();
        let thread = create_test_thread(&keypair);

        // Create a chain of posts
        let post1 = Post::create(
            *thread.hash(),
            vec![*thread.hash()],
            "First reply".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create post 1");

        let post2 = Post::create(
            *thread.hash(),
            vec![*post1.hash()],
            "Second reply".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create post 2");

        let post3 = Post::create(
            *thread.hash(),
            vec![*post2.hash()],
            "Third reply".to_string(),
            None,
            keypair.public_key(),
            keypair.private_key(),
            None,
        )
        .expect("Failed to create post 3");

        // All posts reference the same thread
        assert_eq!(post1.thread_hash(), thread.hash());
        assert_eq!(post2.thread_hash(), thread.hash());
        assert_eq!(post3.thread_hash(), thread.hash());

        // Chain is formed through parent hashes
        assert_eq!(post2.parent_hashes(), &[*post1.hash()]);
        assert_eq!(post3.parent_hashes(), &[*post2.hash()]);
    }
}
