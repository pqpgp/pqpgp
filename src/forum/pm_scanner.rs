//! Private message scanning and discovery.
//!
//! This module handles scanning the DAG for private messages addressed to the user
//! and managing the discovery of new conversations.
//!
//! ## Scanning Strategy
//!
//! Since sealed messages don't reveal their recipients, we use recipient hints
//! for efficient filtering:
//!
//! 1. Compute hint key from our encryption identity's signed prekey
//! 2. For each sealed message, verify HMAC hint
//! 3. Only attempt full decryption if hint matches
//!
//! This reduces the cost from O(n * decrypt) to O(n * HMAC) + O(m * decrypt)
//! where m is the number of messages actually for us.
//!
//! ## Usage Flow
//!
//! ```text
//! 1. Load our encryption identity private keys
//! 2. Scan new sealed messages since last sync
//! 3. Filter by recipient hint
//! 4. Attempt to unseal matching messages
//! 5. Create/update conversation sessions
//! 6. Store decrypted messages locally
//! ```

use crate::error::{PqpgpError, Result};
use crate::forum::conversation::{
    ConversationManager, ConversationSession, StoredMessage, CONVERSATION_ID_SIZE,
};
use crate::forum::encryption_identity::EncryptionIdentityPrivate;
use crate::forum::pm_sealed::{unseal_private_message, UnsealedMessageResult};
use crate::forum::sealed_message::{derive_hint_key, SealedPrivateMessage};
use crate::forum::storage::ForumStorage;
use crate::forum::types::ContentHash;
use std::collections::HashSet;
use tracing::warn;

/// Categorized decryption failure for better error diagnosis.
#[derive(Debug, Clone)]
pub enum DecryptionFailure {
    /// Authentication failed - message was corrupted or tampered with.
    /// The recipient should be alerted about this.
    AuthenticationFailed(ContentHash, String),
    /// Envelope parsing failed - malformed message structure.
    EnvelopeParseFailed(ContentHash, String),
    /// Key derivation or decryption failed.
    DecryptionError(ContentHash, String),
    /// Hint matched but was a false positive (extremely rare).
    HintFalsePositive(ContentHash),
}

impl DecryptionFailure {
    /// Returns the content hash of the failed message.
    pub fn hash(&self) -> &ContentHash {
        match self {
            DecryptionFailure::AuthenticationFailed(h, _) => h,
            DecryptionFailure::EnvelopeParseFailed(h, _) => h,
            DecryptionFailure::DecryptionError(h, _) => h,
            DecryptionFailure::HintFalsePositive(h) => h,
        }
    }

    /// Returns true if this failure indicates potential tampering.
    pub fn is_potential_attack(&self) -> bool {
        matches!(self, DecryptionFailure::AuthenticationFailed(_, _))
    }
}

/// Result of scanning for private messages.
#[derive(Debug, Default)]
pub struct ScanResult {
    /// Number of sealed messages scanned.
    pub messages_scanned: usize,
    /// Number of messages that matched our hint (potential matches).
    pub hint_matches: usize,
    /// Number of messages successfully decrypted.
    pub messages_decrypted: usize,
    /// Number of new conversations discovered.
    pub new_conversations: usize,
    /// Hashes of messages that failed to decrypt despite hint match (legacy field).
    pub failed_decryptions: Vec<ContentHash>,
    /// Categorized decryption failures for better diagnosis.
    pub decryption_failures: Vec<DecryptionFailure>,
    /// Newly decrypted messages with their conversation IDs.
    pub new_messages: Vec<(ContentHash, [u8; CONVERSATION_ID_SIZE], StoredMessage)>,
    /// Messages rejected due to consumed OTP (replay attack prevention).
    pub rejected_replay_attempts: usize,
    /// Consumed OTPs that should be recorded (identity_hash, otp_id).
    pub consumed_otps: Vec<(ContentHash, u32)>,
}

/// Scanner for discovering private messages in the DAG.
pub struct PrivateMessageScanner<'a> {
    /// Our encryption identity private keys.
    encryption_privates: Vec<&'a EncryptionIdentityPrivate>,
    /// Precomputed hint keys for our identities.
    hint_keys: Vec<[u8; 32]>,
    /// Set of message hashes we've already processed.
    processed_messages: HashSet<ContentHash>,
}

impl<'a> PrivateMessageScanner<'a> {
    /// Creates a new scanner with the given encryption identity private keys.
    ///
    /// # Arguments
    /// * `encryption_privates` - Our encryption identity private keys
    pub fn new(encryption_privates: Vec<&'a EncryptionIdentityPrivate>) -> Self {
        // Precompute hint keys for efficient filtering using HKDF
        // SECURITY: Uses same derivation as sender for consistent hint verification
        let hint_keys: Vec<[u8; 32]> = encryption_privates
            .iter()
            .map(|p| {
                let spk_public = p.signed_prekey_public();
                // Use unified HKDF-based derivation (same as pm_sealed.rs)
                derive_hint_key(spk_public)
            })
            .collect();

        Self {
            encryption_privates,
            hint_keys,
            processed_messages: HashSet::new(),
        }
    }

    /// Adds already-processed message hashes to avoid re-processing.
    pub fn set_processed(&mut self, processed: HashSet<ContentHash>) {
        self.processed_messages = processed;
    }

    /// Marks a message as processed.
    pub fn mark_processed(&mut self, hash: ContentHash) {
        self.processed_messages.insert(hash);
    }

    /// Checks if a message has already been processed.
    pub fn is_processed(&self, hash: &ContentHash) -> bool {
        self.processed_messages.contains(hash)
    }

    /// Checks if a sealed message might be for us by verifying the recipient hint.
    ///
    /// Returns the index of the matching encryption identity, or None if no match.
    ///
    /// **Security note**: This function scans ALL identities in constant time to avoid
    /// leaking which identity matched through timing side-channels. Additionally,
    /// when multiple identities match, one is selected randomly to prevent pattern leakage.
    pub fn check_hint(&self, message: &SealedPrivateMessage) -> Option<usize> {
        use rand::Rng;

        // SECURITY FIX: Scan all identities to avoid timing side-channel that
        // could reveal which identity index matched.
        // SECURITY FIX #2: Collect all matches and randomly select one to prevent
        // leaking which identity index matched through return value patterns.
        let mut matching_indices: Vec<usize> = Vec::new();

        for (idx, hint_key) in self.hint_keys.iter().enumerate() {
            // Always check all hints regardless of previous matches
            if message.check_recipient_hint(hint_key) {
                matching_indices.push(idx);
            }
        }

        // SECURITY: Randomly select among matches to prevent timing pattern analysis
        // that could reveal which identity index typically matches first.
        match matching_indices.len() {
            0 => None,
            1 => Some(matching_indices[0]),
            n => {
                // Multiple matches - randomly select one
                let random_idx = rand::rng().random_range(0..n);
                Some(matching_indices[random_idx])
            }
        }
    }

    /// Attempts to unseal a message using the specified encryption identity.
    ///
    /// # Arguments
    /// * `message` - The sealed message to unseal
    /// * `identity_idx` - Index of the encryption identity to use
    ///
    /// # Returns
    /// The unsealed result if successful, or an error.
    pub fn try_unseal(
        &self,
        message: &SealedPrivateMessage,
        identity_idx: usize,
    ) -> Result<UnsealedMessageResult> {
        let private = self
            .encryption_privates
            .get(identity_idx)
            .ok_or_else(|| PqpgpError::crypto("Invalid encryption identity index"))?;

        unseal_private_message(message, private)
    }

    /// Scans a batch of sealed messages and returns results.
    ///
    /// # Arguments
    /// * `messages` - Iterator of (hash, message) pairs to scan
    /// * `conversation_manager` - Manager to check for existing conversations
    ///
    /// # Returns
    /// Scan results including decrypted messages and statistics.
    ///
    /// # Security
    /// This function tracks consumed OTPs in the result. The caller MUST record
    /// these consumed OTPs to storage before processing more messages to prevent
    /// replay attacks.
    pub fn scan_messages<'b, I>(
        &mut self,
        messages: I,
        conversation_manager: &ConversationManager,
    ) -> ScanResult
    where
        I: Iterator<Item = (&'b ContentHash, &'b SealedPrivateMessage)>,
    {
        self.scan_messages_with_otp_check(messages, conversation_manager, &HashSet::new())
    }

    /// Scans messages with OTP replay protection.
    ///
    /// # Arguments
    /// * `messages` - Iterator of (hash, message) pairs to scan
    /// * `conversation_manager` - Manager to check for existing conversations
    /// * `consumed_otps` - Set of (identity_hash, otp_id) pairs that have been consumed
    ///
    /// # Returns
    /// Scan results including decrypted messages, statistics, and newly consumed OTPs.
    pub fn scan_messages_with_otp_check<'b, I>(
        &mut self,
        messages: I,
        conversation_manager: &ConversationManager,
        consumed_otps: &HashSet<(ContentHash, u32)>,
    ) -> ScanResult
    where
        I: Iterator<Item = (&'b ContentHash, &'b SealedPrivateMessage)>,
    {
        let mut result = ScanResult::default();

        for (hash, message) in messages {
            // Skip already processed
            if self.is_processed(hash) {
                continue;
            }

            result.messages_scanned += 1;

            // Check hint
            let identity_idx = match self.check_hint(message) {
                Some(idx) => idx,
                None => continue, // Not for us
            };

            result.hint_matches += 1;

            // Try to unseal
            match self.try_unseal(message, identity_idx) {
                Ok(unsealed) => {
                    // SECURITY: Check if this OTP has already been consumed (replay attack)
                    if let Some(otp_id) = unsealed.used_one_time_prekey_id {
                        let identity_hash = self.encryption_privates[identity_idx].identity_hash;
                        if consumed_otps.contains(&(identity_hash, otp_id)) {
                            warn!(
                                "Rejecting message {} - OTP {} already consumed (potential replay attack)",
                                hash.short(), otp_id
                            );
                            result.rejected_replay_attempts += 1;
                            continue;
                        }
                        // Track this OTP consumption for the caller to record
                        result.consumed_otps.push((identity_hash, otp_id));
                    }

                    result.messages_decrypted += 1;

                    // Check if this is a new conversation
                    let is_new_conversation = conversation_manager
                        .get_session(&unsealed.conversation_id)
                        .is_none();

                    if is_new_conversation {
                        result.new_conversations += 1;
                    }

                    // Create stored message
                    let stored = StoredMessage {
                        inner: unsealed.inner_message,
                        dag_hash: *hash,
                        is_outgoing: false,
                        processed_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                    };

                    result
                        .new_messages
                        .push((*hash, unsealed.conversation_id, stored));
                    self.mark_processed(*hash);
                }
                Err(e) => {
                    // Hint matched but decryption failed - categorize the failure
                    let error_msg = e.to_string();
                    result.failed_decryptions.push(*hash);

                    // SECURITY: Categorize failure for better diagnosis
                    let failure = if error_msg.contains("authentication") {
                        // Message was for us but corrupted/tampered
                        DecryptionFailure::AuthenticationFailed(*hash, error_msg.clone())
                    } else if error_msg.contains("envelope")
                        || error_msg.contains("deserialize")
                        || error_msg.contains("Invalid")
                    {
                        // Malformed message structure
                        DecryptionFailure::EnvelopeParseFailed(*hash, error_msg.clone())
                    } else if error_msg.contains("hint") {
                        // Extremely unlikely false positive
                        DecryptionFailure::HintFalsePositive(*hash)
                    } else {
                        // Generic decryption error
                        DecryptionFailure::DecryptionError(*hash, error_msg.clone())
                    };

                    // Log potential attacks
                    if failure.is_potential_attack() {
                        warn!(
                            "Potential tampering detected for message {}: {}",
                            hash.short(),
                            error_msg
                        );
                    }

                    result.decryption_failures.push(failure);
                }
            }
        }

        result
    }
}

/// High-level function to scan a forum for new private messages.
///
/// This is a convenience function that:
/// 1. Loads encryption identity private keys from storage
/// 2. Loads sealed messages from storage
/// 3. Scans for messages addressed to us (with OTP replay protection)
/// 4. Updates conversation manager with new sessions and messages
/// 5. Records consumed OTPs to prevent replay attacks
///
/// # Arguments
/// * `storage` - Forum storage
/// * `forum_hash` - The forum to scan
/// * `conversation_manager` - Manager to update with results
///
/// # Returns
/// Scan results including statistics and new messages.
///
/// # Security
/// This function checks consumed OTPs from storage to prevent replay attacks
/// where an attacker re-submits a message with the same one-time prekey.
pub fn scan_forum_for_messages(
    storage: &ForumStorage,
    forum_hash: &ContentHash,
    conversation_manager: &mut ConversationManager,
) -> Result<ScanResult> {
    // Load our encryption identity private keys
    let private_hashes = storage.list_encryption_privates()?;
    let mut privates: Vec<EncryptionIdentityPrivate> = Vec::new();

    for hash in &private_hashes {
        if let Some(private) = storage.load_encryption_private(hash)? {
            privates.push(private);
        }
    }

    if privates.is_empty() {
        // No encryption identities, nothing to scan for
        return Ok(ScanResult::default());
    }

    // SECURITY: Load already consumed OTPs to prevent replay attacks
    let mut consumed_otps: HashSet<(ContentHash, u32)> = HashSet::new();
    for private in &privates {
        let identity_hash = private.identity_hash;
        if let Ok(consumed) = storage.list_consumed_otps(&identity_hash) {
            for otp_id in consumed {
                consumed_otps.insert((identity_hash, otp_id));
            }
        }
    }

    // Create scanner with references to our private keys
    let private_refs: Vec<&EncryptionIdentityPrivate> = privates.iter().collect();
    let mut scanner = PrivateMessageScanner::new(private_refs);

    // Get already processed messages from existing conversation histories
    let mut processed = HashSet::new();
    for session in conversation_manager.all_sessions() {
        if let Some(messages) =
            conversation_manager.get_messages(session.conversation_id().as_bytes())
        {
            for msg in messages {
                processed.insert(msg.dag_hash);
            }
        }
    }
    scanner.set_processed(processed);

    // Load sealed messages from the forum
    // Note: In a real implementation, this would use an index of sealed messages
    // For now, we scan all nodes and filter
    let nodes = storage.load_all_nodes()?;
    let sealed_messages: Vec<(&ContentHash, &SealedPrivateMessage)> = nodes
        .iter()
        .filter_map(|(hash, node)| {
            node.as_sealed_private_message()
                .filter(|m| m.forum_hash() == forum_hash)
                .map(|m| (hash, m))
        })
        .collect();

    // Scan messages with OTP replay protection
    let scan_result = scanner.scan_messages_with_otp_check(
        sealed_messages.into_iter(),
        conversation_manager,
        &consumed_otps,
    );

    // SECURITY: Record newly consumed OTPs to storage BEFORE processing messages
    // This prevents a race condition where a message could be replayed
    for (identity_hash, otp_id) in &scan_result.consumed_otps {
        if let Err(e) = storage.record_consumed_otp(identity_hash, *otp_id) {
            warn!("Failed to record consumed OTP: {}", e);
        }
    }

    // Process results - create sessions and store messages
    for (dag_hash, conversation_id, stored_message) in &scan_result.new_messages {
        // Check if we need to create a new session
        if conversation_manager.get_session(conversation_id).is_none() {
            // We need the sender's identity hash and conversation key to create a session
            // Re-unseal to get this information (we could cache it in scan_messages)
            // For now, we'll need to get it from the stored message's context

            // Find the private key that successfully decrypted this
            let private_refs: Vec<&EncryptionIdentityPrivate> = privates.iter().collect();
            let temp_scanner = PrivateMessageScanner::new(private_refs);

            // Find the sealed message
            if let Some(node) = nodes.get(dag_hash) {
                if let Some(sealed) = node.as_sealed_private_message() {
                    if let Some(idx) = temp_scanner.check_hint(sealed) {
                        if let Ok(unsealed) = temp_scanner.try_unseal(sealed, idx) {
                            // Get the signed prekey keypair for Double Ratchet initialization
                            // The responder uses their signed prekey as the initial ratchet keypair
                            let ratchet_keypair = Some((
                                privates[idx].signed_prekey_public().to_vec(),
                                privates[idx].signed_prekey_secret().to_vec(),
                            ));

                            // Create new session as responder with ratchet keypair
                            let session = ConversationSession::new_responder(
                                *conversation_id,
                                *unsealed.conversation_key,
                                privates[idx].identity_hash,
                                unsealed.sender_identity_hash,
                                unsealed.used_one_time_prekey_id,
                                ratchet_keypair,
                            );

                            // Add session (ignore error if already exists from race)
                            let _ = conversation_manager.add_session(session);
                        }
                    }
                }
            }
        }

        // Store the message and record receipt
        let _ = conversation_manager.store_message(conversation_id, stored_message.clone());

        // Update session's received message counter
        if let Some(session) = conversation_manager.get_session_mut(conversation_id) {
            session.record_received();
        }
    }

    Ok(scan_result)
}

/// Tracks one-time prekey consumption and generates replenishment alerts.
#[derive(Debug, Default)]
pub struct PrekeyStatus {
    /// Identity hash -> remaining OTP count
    pub remaining_otps: Vec<(ContentHash, usize)>,
    /// Identities that need OTP replenishment (below threshold)
    pub needs_replenishment: Vec<ContentHash>,
}

/// Threshold below which we recommend generating more OTPs.
pub const OTP_REPLENISHMENT_THRESHOLD: usize = 5;

/// Checks the status of one-time prekeys for all encryption identities.
///
/// # Arguments
/// * `storage` - Forum storage to load identities from
///
/// # Returns
/// Status of all encryption identity prekeys.
pub fn check_prekey_status(storage: &ForumStorage) -> Result<PrekeyStatus> {
    let mut status = PrekeyStatus::default();

    let private_hashes = storage.list_encryption_privates()?;

    for hash in private_hashes {
        if let Some(private) = storage.load_encryption_private(&hash)? {
            // Count remaining OTPs by checking which IDs still have secrets
            // This is a simplification - in practice we'd track consumed OTPs separately
            let remaining = count_remaining_otps(&private);

            status.remaining_otps.push((hash, remaining));

            if remaining < OTP_REPLENISHMENT_THRESHOLD {
                status.needs_replenishment.push(hash);
            }
        }
    }

    Ok(status)
}

/// Counts remaining one-time prekeys in a private identity.
fn count_remaining_otps(private: &EncryptionIdentityPrivate) -> usize {
    // Count OTPs by iterating through possible IDs
    // This is a heuristic - we check IDs 2-102 (typical range)
    let mut count = 0;
    for id in 2..102u32 {
        if private.get_one_time_secret(id).is_some() {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::forum::conversation::ConversationSession;
    use crate::forum::encryption_identity::EncryptionIdentityGenerator;
    use crate::forum::pm_sealed::seal_private_message;
    use crate::forum::sealed_message::InnerMessage;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_mldsa87().expect("Failed to generate keypair")
    }

    fn create_test_forum_hash() -> ContentHash {
        ContentHash::from_bytes([42u8; 64])
    }

    #[test]
    fn test_scanner_hint_matching() {
        let forum_hash = create_test_forum_hash();

        // Create recipient identity
        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        // Create sender identity
        let sender_keypair = create_test_keypair();
        let (sender_identity, _sender_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        // Seal a message
        let inner = InnerMessage::new([0u8; 32], "Test message".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            true, // Use OTP
        )
        .expect("Failed to seal message");

        // Create scanner with recipient's private key
        let scanner = PrivateMessageScanner::new(vec![&recipient_private]);

        // Should match hint
        let match_idx = scanner.check_hint(&sealed_result.message);
        assert!(match_idx.is_some());
        assert_eq!(match_idx.unwrap(), 0);
    }

    #[test]
    fn test_scanner_no_false_positives() {
        let forum_hash = create_test_forum_hash();

        // Create two different recipients
        let recipient1_keypair = create_test_keypair();
        let (recipient1_identity, _recipient1_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient1_keypair.public_key(),
            recipient1_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient1 identity");

        let recipient2_keypair = create_test_keypair();
        let (_recipient2_identity, recipient2_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient2_keypair.public_key(),
            recipient2_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient2 identity");

        // Create sender
        let sender_keypair = create_test_keypair();
        let (sender_identity, _sender_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        // Seal message to recipient1
        let inner = InnerMessage::new([0u8; 32], "For recipient 1".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient1_identity,
            inner,
            true,
        )
        .expect("Failed to seal message");

        // Scanner for recipient2 should NOT match
        let scanner = PrivateMessageScanner::new(vec![&recipient2_private]);
        let match_idx = scanner.check_hint(&sealed_result.message);
        assert!(match_idx.is_none());
    }

    #[test]
    fn test_scanner_full_unseal() {
        let forum_hash = create_test_forum_hash();

        // Create recipient
        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        // Create sender
        let sender_keypair = create_test_keypair();
        let (sender_identity, _sender_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        // Seal message
        let inner = InnerMessage::new([0u8; 32], "Secret message".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            true,
        )
        .expect("Failed to seal message");

        // Create scanner and unseal
        let scanner = PrivateMessageScanner::new(vec![&recipient_private]);
        let match_idx = scanner
            .check_hint(&sealed_result.message)
            .expect("Should match hint");

        let unsealed = scanner
            .try_unseal(&sealed_result.message, match_idx)
            .expect("Should unseal");

        assert_eq!(unsealed.inner_message.body, "Secret message");
        assert_eq!(unsealed.sender_identity_hash, *sender_identity.hash());
    }

    #[test]
    fn test_scan_messages_batch() {
        let forum_hash = create_test_forum_hash();

        // Create recipient
        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        // Create sender
        let sender_keypair = create_test_keypair();
        let (sender_identity, _sender_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        // Seal multiple messages
        let mut messages = Vec::new();
        for i in 0..3 {
            let inner = InnerMessage::new([0u8; 32], format!("Message {}", i));
            let sealed_result = seal_private_message(
                forum_hash,
                &sender_identity,
                &recipient_identity,
                inner,
                true, // Use OTP
            )
            .expect("Failed to seal message");
            messages.push((*sealed_result.message.hash(), sealed_result.message));
        }

        // Scan
        let mut scanner = PrivateMessageScanner::new(vec![&recipient_private]);
        let manager = ConversationManager::new();

        let message_refs: Vec<(&ContentHash, &SealedPrivateMessage)> =
            messages.iter().map(|(h, m)| (h, m)).collect();

        let result = scanner.scan_messages(message_refs.into_iter(), &manager);

        assert_eq!(result.messages_scanned, 3);
        assert_eq!(result.hint_matches, 3);
        assert_eq!(result.messages_decrypted, 3);
        assert_eq!(result.new_messages.len(), 3);
    }

    #[test]
    fn test_processed_messages_skipped() {
        let forum_hash = create_test_forum_hash();

        // Create recipient
        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        // Create sender
        let sender_keypair = create_test_keypair();
        let (sender_identity, _sender_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        // Seal a message
        let inner = InnerMessage::new([0u8; 32], "Test".to_string());
        let sealed_result = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity,
            inner,
            true,
        )
        .expect("Failed to seal message");

        let hash = *sealed_result.message.hash();

        // First scan
        let mut scanner = PrivateMessageScanner::new(vec![&recipient_private]);
        let manager = ConversationManager::new();

        let messages = vec![(&hash, &sealed_result.message)];
        let result1 = scanner.scan_messages(messages.clone().into_iter(), &manager);
        assert_eq!(result1.messages_decrypted, 1);

        // Second scan - should skip processed
        let result2 = scanner.scan_messages(messages.into_iter(), &manager);
        assert_eq!(result2.messages_scanned, 0); // Skipped
        assert_eq!(result2.messages_decrypted, 0);
    }

    // =========================================================================
    // Integration tests - Full Conversation Flow
    // =========================================================================

    #[test]
    fn test_full_conversation_flow() {
        // This test simulates a complete PM conversation:
        // 1. Alice creates encryption identity
        // 2. Bob creates encryption identity
        // 3. Alice sends message to Bob
        // 4. Bob scans and receives message
        // 5. Bob sends reply to Alice
        // 6. Alice scans and receives reply

        let forum_hash = create_test_forum_hash();

        // Step 1 & 2: Create identities for Alice and Bob
        let alice_keypair = create_test_keypair();
        let (alice_identity, alice_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            alice_keypair.public_key(),
            alice_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate Alice identity");

        let bob_keypair = create_test_keypair();
        let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            bob_keypair.public_key(),
            bob_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate Bob identity");

        // Step 3: Alice sends message to Bob
        let alice_message = InnerMessage::new([1u8; 32], "Hello Bob! This is Alice.".to_string());
        let sealed_to_bob = seal_private_message(
            forum_hash,
            &alice_identity,
            &bob_identity,
            alice_message,
            true,
        )
        .expect("Failed to seal Alice's message");

        // Step 4: Bob scans and receives message
        let mut bob_scanner = PrivateMessageScanner::new(vec![&bob_private]);
        let bob_manager = ConversationManager::new();

        let messages_for_bob = vec![(sealed_to_bob.message.hash(), &sealed_to_bob.message)];

        let bob_scan_result = bob_scanner.scan_messages(messages_for_bob.into_iter(), &bob_manager);
        assert_eq!(bob_scan_result.messages_decrypted, 1);
        assert_eq!(bob_scan_result.new_messages.len(), 1);

        let (_, bob_conv_id, bob_received) = &bob_scan_result.new_messages[0];
        assert_eq!(bob_received.inner.body, "Hello Bob! This is Alice.");

        // Step 5: Bob sends reply to Alice (using same conversation)
        let bob_reply = InnerMessage::new(*bob_conv_id, "Hi Alice! Got your message.".to_string())
            .with_reply_to(bob_received.inner.message_id);

        let sealed_to_alice =
            seal_private_message(forum_hash, &bob_identity, &alice_identity, bob_reply, true)
                .expect("Failed to seal Bob's reply");

        // Step 6: Alice scans and receives reply
        let mut alice_scanner = PrivateMessageScanner::new(vec![&alice_private]);
        let alice_manager = ConversationManager::new();

        let messages_for_alice = vec![(sealed_to_alice.message.hash(), &sealed_to_alice.message)];

        let alice_scan_result =
            alice_scanner.scan_messages(messages_for_alice.into_iter(), &alice_manager);
        assert_eq!(alice_scan_result.messages_decrypted, 1);
        assert_eq!(alice_scan_result.new_messages.len(), 1);

        let (_, _, alice_received) = &alice_scan_result.new_messages[0];
        assert_eq!(alice_received.inner.body, "Hi Alice! Got your message.");
        assert_eq!(
            alice_received.inner.reply_to,
            Some(bob_received.inner.message_id)
        );
    }

    #[test]
    fn test_multi_party_privacy() {
        // Test that messages between two parties are invisible to third parties
        // Even if the third party has access to the DAG

        let forum_hash = create_test_forum_hash();

        // Create three users
        let alice_keypair = create_test_keypair();
        let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            alice_keypair.public_key(),
            alice_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate Alice identity");

        let bob_keypair = create_test_keypair();
        let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            bob_keypair.public_key(),
            bob_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate Bob identity");

        let eve_keypair = create_test_keypair();
        let (_eve_identity, eve_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            eve_keypair.public_key(),
            eve_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate Eve identity");

        // Alice sends private message to Bob
        let private_message =
            InnerMessage::new([0u8; 32], "Secret message for Bob only".to_string());
        let sealed = seal_private_message(
            forum_hash,
            &alice_identity,
            &bob_identity,
            private_message,
            true,
        )
        .expect("Failed to seal message");

        // Eve tries to scan the message - should find nothing
        let mut eve_scanner = PrivateMessageScanner::new(vec![&eve_private]);
        let eve_manager = ConversationManager::new();

        let all_messages = vec![(sealed.message.hash(), &sealed.message)];

        let eve_result = eve_scanner.scan_messages(all_messages.clone().into_iter(), &eve_manager);
        assert_eq!(
            eve_result.messages_decrypted, 0,
            "Eve should not be able to decrypt Bob's message"
        );
        assert_eq!(eve_result.new_messages.len(), 0);

        // Bob scans the same messages - should find his message
        let mut bob_scanner = PrivateMessageScanner::new(vec![&bob_private]);
        let bob_manager = ConversationManager::new();

        let bob_result = bob_scanner.scan_messages(all_messages.into_iter(), &bob_manager);
        assert_eq!(
            bob_result.messages_decrypted, 1,
            "Bob should decrypt his message"
        );
        assert_eq!(
            bob_result.new_messages[0].2.inner.body,
            "Secret message for Bob only"
        );
    }

    #[test]
    fn test_multiple_identities_scanning() {
        // Test that a user with multiple encryption identities can scan with all of them

        let forum_hash = create_test_forum_hash();

        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        // Recipient has two encryption identities (e.g., rotated keys)
        let recipient_keypair = create_test_keypair();
        let (recipient_identity1, recipient_private1) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity 1");

        let (recipient_identity2, recipient_private2) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity 2");

        // Send message to identity 1
        let msg1 = InnerMessage::new([1u8; 32], "Message to identity 1".to_string());
        let sealed1 = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity1,
            msg1,
            true,
        )
        .expect("Failed to seal message 1");

        // Send message to identity 2
        let msg2 = InnerMessage::new([2u8; 32], "Message to identity 2".to_string());
        let sealed2 = seal_private_message(
            forum_hash,
            &sender_identity,
            &recipient_identity2,
            msg2,
            true,
        )
        .expect("Failed to seal message 2");

        // Scan with both identities
        let mut scanner =
            PrivateMessageScanner::new(vec![&recipient_private1, &recipient_private2]);
        let manager = ConversationManager::new();

        let all_messages = vec![
            (sealed1.message.hash(), &sealed1.message),
            (sealed2.message.hash(), &sealed2.message),
        ];

        let result = scanner.scan_messages(all_messages.into_iter(), &manager);
        assert_eq!(result.messages_decrypted, 2);
        assert_eq!(result.new_messages.len(), 2);

        // Verify both messages were decrypted
        let bodies: Vec<&str> = result
            .new_messages
            .iter()
            .map(|(_, _, msg)| msg.inner.body.as_str())
            .collect();
        assert!(bodies.contains(&"Message to identity 1"));
        assert!(bodies.contains(&"Message to identity 2"));
    }

    #[test]
    fn test_conversation_session_creation() {
        // Test that conversation sessions are properly created when receiving initial messages

        let forum_hash = create_test_forum_hash();

        let alice_keypair = create_test_keypair();
        let (alice_identity, _alice_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            alice_keypair.public_key(),
            alice_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate Alice identity");

        let bob_keypair = create_test_keypair();
        let (bob_identity, bob_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            bob_keypair.public_key(),
            bob_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate Bob identity");

        // Alice initiates conversation with Bob
        let msg = InnerMessage::new([0u8; 32], "Starting conversation".to_string());
        let sealed = seal_private_message(forum_hash, &alice_identity, &bob_identity, msg, true)
            .expect("Failed to seal message");

        // Bob receives and creates session
        let mut bob_scanner = PrivateMessageScanner::new(vec![&bob_private]);
        let mut bob_manager = ConversationManager::new();

        let messages = vec![(sealed.message.hash(), &sealed.message)];

        let result = bob_scanner.scan_messages(messages.into_iter(), &bob_manager);
        assert_eq!(result.messages_decrypted, 1);

        // Create session for Bob from the received message
        let (_, conversation_id, stored_msg) = &result.new_messages[0];

        // Verify conversation ID is valid (32 bytes)
        assert_eq!(conversation_id.len(), 32);

        // Verify we can create a session (even though we're not fully implementing it here)
        // ConversationSession::new_responder args:
        // (conversation_id, conversation_key, our_identity_hash, peer_identity_hash, consumed_otp_id, ratchet_keypair)
        let session = ConversationSession::new_responder(
            *conversation_id,
            *sealed.conversation_key,
            *bob_identity.hash(),   // our identity (Bob)
            *alice_identity.hash(), // peer identity (Alice)
            None,                   // consumed OTP (not tracked in this test)
            None,                   // ratchet keypair (not needed for basic test)
        );

        bob_manager
            .add_session(session)
            .expect("Failed to add session");

        // Verify session was stored
        assert!(bob_manager.get_session(conversation_id).is_some());

        // Store the message in the session
        bob_manager
            .store_message(conversation_id, stored_msg.clone())
            .expect("Failed to store message");

        // Verify message was stored via ConversationManager::get_messages
        let messages = bob_manager.get_messages(conversation_id).unwrap();
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn test_performance_hint_checking() {
        // Test that hint checking is fast compared to full decryption
        // This validates our optimization strategy

        let forum_hash = create_test_forum_hash();

        // Create sender
        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        // Create recipient
        let recipient_keypair = create_test_keypair();
        let (recipient_identity, recipient_private) = EncryptionIdentityGenerator::generate(
            forum_hash,
            recipient_keypair.public_key(),
            recipient_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate recipient identity");

        // Create a batch of messages to recipient
        let mut sealed_messages: Vec<SealedPrivateMessage> = Vec::new();
        for i in 0..10 {
            let msg = InnerMessage::new([i as u8; 32], format!("Message {}", i));
            let sealed =
                seal_private_message(forum_hash, &sender_identity, &recipient_identity, msg, true)
                    .expect("Failed to seal message");
            sealed_messages.push(sealed.message);
        }

        // Create scanner
        let scanner = PrivateMessageScanner::new(vec![&recipient_private]);

        // Time hint checking
        let start_hints = std::time::Instant::now();
        let mut hint_matches = 0;
        for msg in &sealed_messages {
            if scanner.check_hint(msg).is_some() {
                hint_matches += 1;
            }
        }
        let hint_duration = start_hints.elapsed();

        // Time full decryption
        let start_decrypt = std::time::Instant::now();
        let mut decrypt_success = 0;
        for msg in &sealed_messages {
            if let Some(idx) = scanner.check_hint(msg) {
                if scanner.try_unseal(msg, idx).is_ok() {
                    decrypt_success += 1;
                }
            }
        }
        let decrypt_duration = start_decrypt.elapsed();

        // All messages should match (they were all for our recipient)
        assert_eq!(hint_matches, 10);
        assert_eq!(decrypt_success, 10);

        // Hint checking should be faster than full decryption
        // (This is more of a sanity check than a strict requirement)
        println!(
            "Performance: Hint checking took {:?}, Full decryption took {:?}",
            hint_duration, decrypt_duration
        );
    }

    #[test]
    fn test_performance_batch_scanning() {
        // Test scanning a batch of messages where most are not for us
        // This simulates real-world usage where we need to filter efficiently

        let forum_hash = create_test_forum_hash();

        // Create multiple users
        let mut identities = Vec::new();
        let mut privates = Vec::new();
        for _ in 0..3 {
            let kp = create_test_keypair();
            let (identity, private) = EncryptionIdentityGenerator::generate(
                forum_hash,
                kp.public_key(),
                kp.private_key(),
                5,
                None,
            )
            .expect("Failed to generate identity");
            identities.push(identity);
            privates.push(private);
        }

        // Create messages between different users
        // User 0 -> User 1: 2 messages
        // User 0 -> User 2: 2 messages
        // User 1 -> User 2: 2 messages
        let mut all_sealed: Vec<SealedPrivateMessage> = Vec::new();

        // Messages for User 1
        for i in 0..2 {
            let msg = InnerMessage::new([i as u8; 32], format!("To User1 #{}", i));
            let sealed =
                seal_private_message(forum_hash, &identities[0], &identities[1], msg, true)
                    .expect("Failed to seal");
            all_sealed.push(sealed.message);
        }

        // Messages for User 2 from User 0
        for i in 0..2 {
            let msg = InnerMessage::new([(i + 10) as u8; 32], format!("To User2 from 0 #{}", i));
            let sealed =
                seal_private_message(forum_hash, &identities[0], &identities[2], msg, true)
                    .expect("Failed to seal");
            all_sealed.push(sealed.message);
        }

        // Messages for User 2 from User 1
        for i in 0..2 {
            let msg = InnerMessage::new([(i + 20) as u8; 32], format!("To User2 from 1 #{}", i));
            let sealed =
                seal_private_message(forum_hash, &identities[1], &identities[2], msg, true)
                    .expect("Failed to seal");
            all_sealed.push(sealed.message);
        }

        // User 1 scans - should find 2 messages
        let mut scanner1 = PrivateMessageScanner::new(vec![&privates[1]]);
        let manager1 = ConversationManager::new();

        let messages_with_hashes: Vec<_> = all_sealed.iter().map(|m| (m.hash(), m)).collect();

        let result1 = scanner1.scan_messages(messages_with_hashes.clone().into_iter(), &manager1);
        assert_eq!(result1.messages_scanned, 6);
        assert_eq!(result1.messages_decrypted, 2);

        // User 2 scans - should find 4 messages
        let mut scanner2 = PrivateMessageScanner::new(vec![&privates[2]]);
        let manager2 = ConversationManager::new();

        let result2 = scanner2.scan_messages(messages_with_hashes.into_iter(), &manager2);
        assert_eq!(result2.messages_scanned, 6);
        assert_eq!(result2.messages_decrypted, 4);
    }

    #[test]
    fn test_performance_large_batch_hint_filtering() {
        // Test that hint filtering scales well with large message counts
        // Creates messages for different recipients and verifies efficient filtering

        let forum_hash = create_test_forum_hash();

        // Create sender
        let sender_keypair = create_test_keypair();
        let (sender_identity, _) = EncryptionIdentityGenerator::generate(
            forum_hash,
            sender_keypair.public_key(),
            sender_keypair.private_key(),
            5,
            None,
        )
        .expect("Failed to generate sender identity");

        // Create multiple recipients
        let mut recipient_identities = Vec::new();
        let mut recipient_privates = Vec::new();
        for _ in 0..5 {
            let kp = create_test_keypair();
            let (identity, private) = EncryptionIdentityGenerator::generate(
                forum_hash,
                kp.public_key(),
                kp.private_key(),
                5,
                None,
            )
            .expect("Failed to generate recipient identity");
            recipient_identities.push(identity);
            recipient_privates.push(private);
        }

        // Create messages: 3 messages per recipient = 15 total
        let mut all_messages: Vec<SealedPrivateMessage> = Vec::new();
        for (r_idx, recipient) in recipient_identities.iter().enumerate() {
            for m_idx in 0..3 {
                let msg = InnerMessage::new(
                    [(r_idx * 10 + m_idx) as u8; 32],
                    format!("Message {} to recipient {}", m_idx, r_idx),
                );
                let sealed =
                    seal_private_message(forum_hash, &sender_identity, recipient, msg, true)
                        .expect("Failed to seal message");
                all_messages.push(sealed.message);
            }
        }

        // Each recipient should find exactly 3 messages
        for (idx, private) in recipient_privates.iter().enumerate() {
            let mut scanner = PrivateMessageScanner::new(vec![private]);
            let manager = ConversationManager::new();

            let messages_with_hashes: Vec<_> = all_messages.iter().map(|m| (m.hash(), m)).collect();

            let result = scanner.scan_messages(messages_with_hashes.into_iter(), &manager);
            assert_eq!(
                result.messages_decrypted, 3,
                "Recipient {} should have received 3 messages",
                idx
            );
            assert_eq!(
                result.messages_scanned, 15,
                "Scanner should have scanned all 15 messages"
            );
        }
    }
}
