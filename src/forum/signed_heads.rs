//! Signed heads for relay transparency and withholding detection.
//!
//! This module provides cryptographically signed statements of a relay's view
//! of a forum's DAG state. Clients can compare statements from multiple relays
//! to detect potential node withholding.
//!
//! ## Overview
//!
//! Each relay maintains an ML-DSA-87 signing keypair and can generate signed
//! statements about the current state of each forum it hosts:
//!
//! ```text
//! HeadsStatement {
//!     forum_hash,           // Which forum
//!     head_hashes,          // Current DAG tips (sorted)
//!     node_count,           // Total nodes in forum
//!     timestamp,            // When statement was generated
//!     relay_fingerprint,    // Relay's public key fingerprint
//! }
//! ```
//!
//! ## Usage
//!
//! ```ignore
//! // Query multiple relays
//! let stmt_a = relay_a.forum_heads(&forum_hash)?;
//! let stmt_b = relay_b.forum_heads(&forum_hash)?;
//!
//! // Verify signatures
//! stmt_a.verify()?;
//! stmt_b.verify()?;
//!
//! // Compare heads
//! let comparison = HeadsComparison::compare(&[stmt_a, stmt_b])?;
//! if !comparison.is_consistent() {
//!     // Relays disagree - fetch missing nodes from the one with more heads
//! }
//! ```
//!
//! ## Security Properties
//!
//! - **Authenticity**: Statements are signed with ML-DSA-87 (post-quantum secure)
//! - **Non-repudiation**: Relay cannot deny having signed a statement
//! - **Freshness**: Timestamps allow detecting stale statements
//! - **Transparency**: Comparing statements reveals withholding

use crate::crypto::{sign_data, verify_data_signature, PrivateKey, PublicKey, Signature};
use crate::error::{PqpgpError, Result};
use crate::forum::ContentHash;
use serde::{Deserialize, Serialize};

/// Maximum age of a heads statement before it's considered stale (5 minutes).
pub const MAX_STATEMENT_AGE_MS: u64 = 5 * 60 * 1000;

/// Statement of a relay's current view of a forum's DAG state.
///
/// This is the data that gets signed by the relay. The head hashes must be
/// sorted to ensure deterministic serialization for signature verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeadsStatement {
    /// Forum hash (identifies which forum this statement is for).
    pub forum_hash: ContentHash,
    /// Current DAG heads (nodes with no children), sorted for deterministic signing.
    pub head_hashes: Vec<ContentHash>,
    /// Total node count in the forum.
    pub node_count: usize,
    /// Timestamp when this statement was generated (Unix millis).
    pub timestamp: u64,
    /// Relay's public key fingerprint (SHA3-512 of public key bytes).
    /// Stored as Vec for serde compatibility with large arrays.
    pub relay_fingerprint: Vec<u8>,
    /// Statement version for future compatibility.
    pub version: u8,
}

impl HeadsStatement {
    /// Current statement version.
    pub const VERSION: u8 = 1;

    /// Creates a new heads statement.
    ///
    /// The head hashes are automatically sorted for deterministic serialization.
    pub fn new(
        forum_hash: ContentHash,
        mut head_hashes: Vec<ContentHash>,
        node_count: usize,
        timestamp: u64,
        relay_fingerprint: &[u8; 64],
    ) -> Self {
        // Sort heads for deterministic serialization
        head_hashes.sort();

        Self {
            forum_hash,
            head_hashes,
            node_count,
            timestamp,
            relay_fingerprint: relay_fingerprint.to_vec(),
            version: Self::VERSION,
        }
    }

    /// Returns the age of this statement in milliseconds.
    pub fn age_ms(&self, current_time: u64) -> u64 {
        current_time.saturating_sub(self.timestamp)
    }

    /// Returns true if this statement is stale (older than MAX_STATEMENT_AGE_MS).
    pub fn is_stale(&self, current_time: u64) -> bool {
        self.age_ms(current_time) > MAX_STATEMENT_AGE_MS
    }
}

/// A signed heads statement that can be verified by clients.
///
/// Contains the statement data, ML-DSA-87 signature, and the relay's public key
/// for verification without requiring prior knowledge of the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHeadsStatement {
    /// The statement data.
    pub statement: HeadsStatement,
    /// ML-DSA-87 signature over the statement.
    pub signature: Signature,
    /// Relay's public key (for verification).
    pub relay_public_key: Vec<u8>,
}

impl SignedHeadsStatement {
    /// Creates a new signed heads statement.
    ///
    /// # Arguments
    /// * `statement` - The heads statement to sign
    /// * `private_key` - The relay's signing private key
    /// * `public_key` - The relay's public key (for inclusion in the statement)
    ///
    /// # Returns
    /// A signed statement that can be verified by any client.
    pub fn sign(
        statement: HeadsStatement,
        private_key: &PrivateKey,
        public_key: &PublicKey,
    ) -> Result<Self> {
        let signature = sign_data(private_key, &statement, None)?;

        Ok(Self {
            statement,
            signature,
            relay_public_key: public_key.as_bytes(),
        })
    }

    /// Verifies the signature on this statement.
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, `Err` otherwise.
    pub fn verify(&self) -> Result<()> {
        let public_key = self.public_key()?;
        verify_data_signature(&public_key, &self.statement, &self.signature)
    }

    /// Reconstructs the public key from the stored bytes.
    pub fn public_key(&self) -> Result<PublicKey> {
        // Use the key_id from the signature to reconstruct the public key
        PublicKey::from_mldsa87_bytes_with_id(&self.relay_public_key, self.signature.key_id())
    }

    /// Returns the relay's fingerprint from the statement.
    pub fn relay_fingerprint(&self) -> &[u8] {
        &self.statement.relay_fingerprint
    }

    /// Returns a short hex representation of the relay fingerprint (first 8 bytes).
    pub fn relay_fingerprint_short(&self) -> String {
        hex::encode(&self.statement.relay_fingerprint[..8])
    }
}

/// Discrepancy detected when comparing heads statements from multiple relays.
#[derive(Debug, Clone)]
pub enum HeadsDiscrepancy {
    /// Relays have different head hashes for the same forum.
    DifferentHeads {
        /// First relay's fingerprint.
        relay_a: Vec<u8>,
        /// Second relay's fingerprint.
        relay_b: Vec<u8>,
        /// First relay's heads.
        heads_a: Vec<ContentHash>,
        /// Second relay's heads.
        heads_b: Vec<ContentHash>,
    },
    /// Relays have different node counts (shouldn't happen with same heads).
    NodeCountMismatch {
        /// First relay's fingerprint.
        relay_a: Vec<u8>,
        /// Second relay's fingerprint.
        relay_b: Vec<u8>,
        /// First relay's node count.
        count_a: usize,
        /// Second relay's node count.
        count_b: usize,
    },
    /// Statement timestamp is too old (possible stale data).
    StaleStatement {
        /// Relay's fingerprint.
        relay: Vec<u8>,
        /// Age in milliseconds.
        age_ms: u64,
    },
    /// Signature verification failed.
    InvalidSignature {
        /// Relay's fingerprint.
        relay: Vec<u8>,
        /// Error message.
        error: String,
    },
}

/// Result of comparing heads statements from multiple relays.
#[derive(Debug, Clone)]
pub struct HeadsComparison {
    /// Forum hash being compared.
    pub forum_hash: ContentHash,
    /// Number of statements compared.
    pub statement_count: usize,
    /// All unique head sets observed (sorted).
    pub unique_head_sets: Vec<Vec<ContentHash>>,
    /// Detected discrepancies.
    pub discrepancies: Vec<HeadsDiscrepancy>,
}

impl HeadsComparison {
    /// Compares signed heads statements from multiple relays.
    ///
    /// This function:
    /// 1. Verifies all signatures
    /// 2. Checks for stale statements
    /// 3. Compares head hashes across all statements
    /// 4. Reports any discrepancies
    ///
    /// # Arguments
    /// * `statements` - Signed statements to compare (should all be for the same forum)
    /// * `current_time` - Current timestamp in milliseconds
    ///
    /// # Returns
    /// A comparison result with any detected discrepancies.
    pub fn compare(statements: &[SignedHeadsStatement], current_time: u64) -> Result<Self> {
        if statements.is_empty() {
            return Err(PqpgpError::validation("No statements to compare"));
        }

        let forum_hash = statements[0].statement.forum_hash;

        // Verify all statements are for the same forum
        for stmt in statements {
            if stmt.statement.forum_hash != forum_hash {
                return Err(PqpgpError::validation(
                    "All statements must be for the same forum",
                ));
            }
        }

        let mut discrepancies = Vec::new();
        let mut unique_head_sets: Vec<Vec<ContentHash>> = Vec::new();

        // Verify signatures and check for stale statements
        for stmt in statements {
            // Verify signature
            if let Err(e) = stmt.verify() {
                discrepancies.push(HeadsDiscrepancy::InvalidSignature {
                    relay: stmt.statement.relay_fingerprint.clone(),
                    error: e.to_string(),
                });
                continue;
            }

            // Check for stale statements
            if stmt.statement.is_stale(current_time) {
                discrepancies.push(HeadsDiscrepancy::StaleStatement {
                    relay: stmt.statement.relay_fingerprint.clone(),
                    age_ms: stmt.statement.age_ms(current_time),
                });
            }

            // Collect unique head sets
            let heads = stmt.statement.head_hashes.clone();
            if !unique_head_sets.contains(&heads) {
                unique_head_sets.push(heads);
            }
        }

        // Compare head hashes between all pairs of statements
        for i in 0..statements.len() {
            for j in (i + 1)..statements.len() {
                let stmt_a = &statements[i];
                let stmt_b = &statements[j];

                // Skip if either signature was invalid
                if discrepancies.iter().any(|d| {
                    matches!(d, HeadsDiscrepancy::InvalidSignature { relay, .. }
                        if relay == &stmt_a.statement.relay_fingerprint
                            || relay == &stmt_b.statement.relay_fingerprint)
                }) {
                    continue;
                }

                // Compare heads
                if stmt_a.statement.head_hashes != stmt_b.statement.head_hashes {
                    discrepancies.push(HeadsDiscrepancy::DifferentHeads {
                        relay_a: stmt_a.statement.relay_fingerprint.clone(),
                        relay_b: stmt_b.statement.relay_fingerprint.clone(),
                        heads_a: stmt_a.statement.head_hashes.clone(),
                        heads_b: stmt_b.statement.head_hashes.clone(),
                    });
                } else if stmt_a.statement.node_count != stmt_b.statement.node_count {
                    // Same heads but different node count - this shouldn't happen
                    discrepancies.push(HeadsDiscrepancy::NodeCountMismatch {
                        relay_a: stmt_a.statement.relay_fingerprint.clone(),
                        relay_b: stmt_b.statement.relay_fingerprint.clone(),
                        count_a: stmt_a.statement.node_count,
                        count_b: stmt_b.statement.node_count,
                    });
                }
            }
        }

        Ok(Self {
            forum_hash,
            statement_count: statements.len(),
            unique_head_sets,
            discrepancies,
        })
    }

    /// Returns true if all relays agree on the DAG state.
    pub fn is_consistent(&self) -> bool {
        self.discrepancies.is_empty()
    }

    /// Returns true if there are any head differences (ignoring stale/signature issues).
    pub fn has_head_differences(&self) -> bool {
        self.discrepancies
            .iter()
            .any(|d| matches!(d, HeadsDiscrepancy::DifferentHeads { .. }))
    }

    /// Returns the union of all heads across all statements.
    ///
    /// Useful for determining which nodes to fetch to reconcile differences.
    pub fn all_heads(&self) -> Vec<ContentHash> {
        let mut all: Vec<ContentHash> = self.unique_head_sets.iter().flatten().cloned().collect();
        all.sort();
        all.dedup();
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::forum::current_timestamp_millis;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
    }

    fn create_test_fingerprint(keypair: &KeyPair) -> [u8; 64] {
        let bytes = keypair.public_key().as_bytes();
        let hash = crate::crypto::hash_data(&bytes);
        let mut fingerprint = [0u8; 64];
        fingerprint.copy_from_slice(&hash);
        fingerprint
    }

    #[test]
    fn test_heads_statement_creation() {
        let forum_hash = ContentHash::from_bytes([1u8; 64]);
        let head1 = ContentHash::from_bytes([3u8; 64]);
        let head2 = ContentHash::from_bytes([2u8; 64]);
        let fingerprint = [0u8; 64];
        let timestamp = current_timestamp_millis();

        // Heads should be sorted after creation
        let statement = HeadsStatement::new(
            forum_hash,
            vec![head1, head2], // Unsorted
            100,
            timestamp,
            &fingerprint,
        );

        assert_eq!(statement.head_hashes.len(), 2);
        // head2 ([2u8; 64]) should come before head1 ([3u8; 64])
        assert!(statement.head_hashes[0] < statement.head_hashes[1]);
        assert_eq!(statement.node_count, 100);
        assert_eq!(statement.version, HeadsStatement::VERSION);
    }

    #[test]
    fn test_statement_staleness() {
        let statement = HeadsStatement::new(
            ContentHash::from_bytes([1u8; 64]),
            vec![],
            0,
            1000,
            &[0u8; 64],
        );

        // Statement at time 1000, current time 1000 + MAX + 1 = stale
        let current = 1000 + MAX_STATEMENT_AGE_MS + 1;
        assert!(statement.is_stale(current));

        // Statement at time 1000, current time 1000 + MAX - 1 = not stale
        let current = 1000 + MAX_STATEMENT_AGE_MS - 1;
        assert!(!statement.is_stale(current));
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = create_test_keypair();
        let fingerprint = create_test_fingerprint(&keypair);

        let statement = HeadsStatement::new(
            ContentHash::from_bytes([1u8; 64]),
            vec![ContentHash::from_bytes([2u8; 64])],
            42,
            current_timestamp_millis(),
            &fingerprint,
        );

        let signed = SignedHeadsStatement::sign(
            statement.clone(),
            keypair.private_key(),
            keypair.public_key(),
        )
        .expect("Signing failed");

        // Verification should succeed
        signed.verify().expect("Verification failed");

        // Statement data should be preserved
        assert_eq!(signed.statement, statement);
    }

    #[test]
    fn test_verify_fails_with_tampered_data() {
        let keypair = create_test_keypair();
        let fingerprint = create_test_fingerprint(&keypair);

        let statement = HeadsStatement::new(
            ContentHash::from_bytes([1u8; 64]),
            vec![ContentHash::from_bytes([2u8; 64])],
            42,
            current_timestamp_millis(),
            &fingerprint,
        );

        let mut signed =
            SignedHeadsStatement::sign(statement, keypair.private_key(), keypair.public_key())
                .expect("Signing failed");

        // Tamper with the node count
        signed.statement.node_count = 999;

        // Verification should fail
        assert!(signed.verify().is_err());
    }

    #[test]
    fn test_comparison_consistent() {
        let keypair_a = create_test_keypair();
        let keypair_b = create_test_keypair();
        let fingerprint_a = create_test_fingerprint(&keypair_a);
        let fingerprint_b = create_test_fingerprint(&keypair_b);

        let forum_hash = ContentHash::from_bytes([1u8; 64]);
        let heads = vec![ContentHash::from_bytes([2u8; 64])];
        let timestamp = current_timestamp_millis();

        let stmt_a = HeadsStatement::new(forum_hash, heads.clone(), 100, timestamp, &fingerprint_a);
        let stmt_b = HeadsStatement::new(forum_hash, heads.clone(), 100, timestamp, &fingerprint_b);

        let signed_a =
            SignedHeadsStatement::sign(stmt_a, keypair_a.private_key(), keypair_a.public_key())
                .expect("Signing failed");
        let signed_b =
            SignedHeadsStatement::sign(stmt_b, keypair_b.private_key(), keypair_b.public_key())
                .expect("Signing failed");

        let comparison =
            HeadsComparison::compare(&[signed_a, signed_b], timestamp).expect("Comparison failed");

        assert!(comparison.is_consistent());
        assert!(!comparison.has_head_differences());
        assert_eq!(comparison.unique_head_sets.len(), 1);
    }

    #[test]
    fn test_comparison_different_heads() {
        let keypair_a = create_test_keypair();
        let keypair_b = create_test_keypair();
        let fingerprint_a = create_test_fingerprint(&keypair_a);
        let fingerprint_b = create_test_fingerprint(&keypair_b);

        let forum_hash = ContentHash::from_bytes([1u8; 64]);
        let timestamp = current_timestamp_millis();

        // Relay A has one head
        let heads_a = vec![ContentHash::from_bytes([2u8; 64])];
        let stmt_a = HeadsStatement::new(forum_hash, heads_a, 100, timestamp, &fingerprint_a);

        // Relay B has a different head (maybe it has more nodes)
        let heads_b = vec![
            ContentHash::from_bytes([2u8; 64]),
            ContentHash::from_bytes([3u8; 64]),
        ];
        let stmt_b = HeadsStatement::new(forum_hash, heads_b, 150, timestamp, &fingerprint_b);

        let signed_a =
            SignedHeadsStatement::sign(stmt_a, keypair_a.private_key(), keypair_a.public_key())
                .expect("Signing failed");
        let signed_b =
            SignedHeadsStatement::sign(stmt_b, keypair_b.private_key(), keypair_b.public_key())
                .expect("Signing failed");

        let comparison =
            HeadsComparison::compare(&[signed_a, signed_b], timestamp).expect("Comparison failed");

        assert!(!comparison.is_consistent());
        assert!(comparison.has_head_differences());
        assert_eq!(comparison.unique_head_sets.len(), 2);

        // All heads should include both sets
        let all_heads = comparison.all_heads();
        assert_eq!(all_heads.len(), 2);
    }

    #[test]
    fn test_comparison_detects_stale() {
        let keypair = create_test_keypair();
        let fingerprint = create_test_fingerprint(&keypair);

        let forum_hash = ContentHash::from_bytes([1u8; 64]);
        let old_timestamp = 1000; // Very old

        let stmt = HeadsStatement::new(forum_hash, vec![], 0, old_timestamp, &fingerprint);

        let signed = SignedHeadsStatement::sign(stmt, keypair.private_key(), keypair.public_key())
            .expect("Signing failed");

        let current = old_timestamp + MAX_STATEMENT_AGE_MS + 1000;
        let comparison = HeadsComparison::compare(&[signed], current).expect("Comparison failed");

        assert!(!comparison.is_consistent());
        assert!(comparison
            .discrepancies
            .iter()
            .any(|d| matches!(d, HeadsDiscrepancy::StaleStatement { .. })));
    }

    #[test]
    fn test_relay_fingerprint_short() {
        let keypair = create_test_keypair();
        let mut fingerprint = [0u8; 64];
        fingerprint[0] = 0xAB;
        fingerprint[1] = 0xCD;

        let stmt = HeadsStatement::new(
            ContentHash::from_bytes([1u8; 64]),
            vec![],
            0,
            current_timestamp_millis(),
            &fingerprint,
        );

        let signed = SignedHeadsStatement::sign(stmt, keypair.private_key(), keypair.public_key())
            .expect("Signing failed");

        let short = signed.relay_fingerprint_short();
        assert_eq!(short.len(), 16); // 8 bytes = 16 hex chars
        assert!(short.starts_with("abcd"));
    }
}
