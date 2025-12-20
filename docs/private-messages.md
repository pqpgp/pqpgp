# Private Messages

PQPGP forums support end-to-end encrypted private messages using a Signal-inspired sealed sender protocol. Messages are stored in the forum DAG but only the recipient can decrypt them - the relay learns nothing about sender, recipient, or content.

## Security Goals

1. **Content privacy** - Only recipient can read the message
2. **Sender privacy** - Relay cannot determine who sent it
3. **Recipient privacy** - Relay cannot determine who it's for
4. **Forward secrecy** - Past messages safe if keys compromised
5. **Post-compromise security** - Future messages safe after key rotation
6. **Quantum resistance** - Safe against quantum computers

## Protocol Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                  Sealed Sender Protocol                          │
├──────────────────────────────────────────────────────────────────┤
│  1. EncryptionIdentity: Users publish X3DH prekey bundles        │
│     • ML-KEM-1024 identity key + signed prekey + one-time keys   │
│     • Bound to forum identity via ML-DSA-87 signature            │
│                                                                  │
│  2. Sealed Messages: Doubly-encrypted for maximum privacy        │
│     • Outer layer: Encrypted to recipient's prekey               │
│     • Inner layer: Double Ratchet encrypted content              │
│     • Recipient hint: HMAC-based filtering (no metadata leak)    │
│                                                                  │
│  3. Trial Decryption: Only recipient can identify their messages │
│     • Server sees: opaque blobs with random-looking hints        │
│     • Server cannot: link sender, recipient, or content          │
└──────────────────────────────────────────────────────────────────┘
```

## Encryption Identity

Before sending or receiving PMs, users publish an `EncryptionIdentity` node to the DAG:

```rust
EncryptionIdentityContent {
    node_type: NodeType::EncryptionIdentity,
    forum_hash: ContentHash,

    // Identity binding
    owner_signing_key: Vec<u8>,           // ML-DSA-87 public key

    // X3DH Prekey Bundle
    signed_prekey: SignedPreKey,          // ML-KEM-1024, rotatable
    one_time_prekeys: Vec<OneTimePrekey>, // ML-KEM-1024, consumed per conversation

    created_at: u64,
}
// Signed by owner_signing_key
```

The signature binds the encryption identity to the user's forum identity.

## X3DH Key Exchange

When Alice initiates a conversation with Bob:

```
Alice                                               Bob
  │                                                  │
  │  1. Fetch Bob's EncryptionIdentity               │
  │<─────────────────────────────────────────────────│
  │                                                  │
  │  2. Generate ephemeral ML-KEM keys               │
  │  3. Encapsulate to Bob's signed prekey → ss1     │
  │  4. Encapsulate to Bob's one-time prekey → ss2   │
  │  5. Derive: conversation_key = HKDF(ss1 || ss2)  │
  │                                                  │
  │  6. Send sealed message + KEM ciphertexts        │
  │─────────────────────────────────────────────────>│
  │                                                  │
  │     Bob decapsulates, derives same key           │
```

The one-time prekey is consumed after use, providing forward secrecy for the initial message.

## Double Encryption (Sealed Sender)

Messages have two encryption layers:

```
┌─────────────────────────────────────────────────────┐
│ Outer Layer (ML-KEM to recipient's identity key)    │
│  ┌───────────────────────────────────────────────┐  │
│  │ SealedEnvelope                                │  │
│  │  • sender_identity_hash                       │  │
│  │  • x3dh_ciphertexts                           │  │
│  │  • ratchet_header                             │  │
│  │  ┌─────────────────────────────────────────┐  │  │
│  │  │ Inner Layer (Double Ratchet AES-256)    │  │  │
│  │  │  • message_id                           │  │  │
│  │  │  • subject (optional)                   │  │  │
│  │  │  • body                                 │  │  │
│  │  │  • reply_to (optional)                  │  │  │
│  │  │  • timestamp                            │  │  │
│  │  └─────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

**What the relay sees**: An opaque `sealed_payload` blob + a random-looking `recipient_hint`

**What the relay cannot determine**:

- Who sent it (sender identity is encrypted inside)
- Who it's for (must have private key to decrypt)
- What it says (AES-256-GCM encrypted)

## Recipient Hint

To avoid O(n) trial decryption of every message, each message includes a hint:

```rust
recipient_hint = HMAC-SHA3(hint_key, hint_nonce)
where hint_key = HKDF(recipient_encryption_private_key, "pm-hint-v1")
```

**Properties**:

- Only the recipient can compute the expected hint
- Hints look random to everyone else
- Different nonce per message - can't correlate messages to same recipient
- Checking a hint is ~1000x faster than full decryption

**Scanning flow**:

```
for each SealedPrivateMessage in forum:
    expected = HMAC(my_hint_key, message.hint_nonce)
    if message.recipient_hint == expected:
        try full decryption  // This is for me
    else:
        skip  // Not for me
```

## Double Ratchet

After the initial X3DH, ongoing messages use the Double Ratchet algorithm:

### Symmetric Ratchet

Each message advances the chain key:

```
chain_key_0 → chain_key_1 → chain_key_2 → ...
     │              │              │
     ▼              ▼              ▼
message_key_0  message_key_1  message_key_2
```

Each message gets a unique key. Compromising one key reveals only that message.

### DH Ratchet

Periodically, new ML-KEM key exchanges rotate the root key:

```
root_key_0 ──[ML-KEM exchange]──> root_key_1 ──[ML-KEM exchange]──> root_key_2
```

This provides **post-compromise security**: even if current keys are compromised, future messages (after a ratchet step) are secure.

## Message Structure

### SealedPrivateMessage (DAG Node)

```rust
SealedPrivateMessageContent {
    node_type: NodeType::SealedPrivateMessage,
    forum_hash: ContentHash,

    sealed_payload: Vec<u8>,     // Encrypted envelope
    recipient_hint: [u8; 32],    // HMAC for efficient filtering
    hint_nonce: [u8; 16],        // Random per message

    created_at: u64,
}
// NOT signed (or signed with ephemeral key) - preserves sender deniability
```

### InnerMessage (Decrypted Content)

```rust
InnerMessage {
    message_id: [u8; 32],        // Random unique ID
    subject: Option<String>,     // Optional subject line
    body: String,                // Message content
    reply_to: Option<[u8; 32]>,  // Reply to another message
    timestamp: u64,
}
```

## Security Properties

| Property                 | How Achieved                                    |
| ------------------------ | ----------------------------------------------- |
| Content hidden           | AES-256-GCM encryption with conversation ID AAD |
| Sender hidden            | Identity inside sealed envelope                 |
| Recipient hidden         | Trial decryption + opaque hints                 |
| Forward secrecy          | One-time prekeys + symmetric ratchet            |
| Post-compromise security | DH ratchet with ML-KEM                          |
| Quantum resistance       | ML-KEM-1024 for all key exchanges               |
| Deniability              | No signatures on message content                |
| Length hiding            | Mandatory bucket-based message padding          |
| Conversation binding     | Conversation ID as authenticated data (AAD)     |

## Prekey Management

### Signed Prekey Rotation

The signed prekey should be rotated periodically (e.g., weekly):

```rust
EncryptionIdentityGenerator::rotate_signed_prekey(
    forum_hash,
    owner_keypair,
    existing_private,
    password,
)
```

Old signed prekeys remain valid for a grace period to handle in-flight messages.

### One-Time Prekey Replenishment

When OTPs run low, publish new ones:

```rust
EncryptionIdentityGenerator::replenish_one_time_prekeys(
    forum_hash,
    owner_keypair,
    existing_private,
    count,
    starting_id,
    password,
)
```

### Consumed OTP Tracking

The client tracks which OTPs have been consumed to prevent replay:

```rust
conversation_manager.mark_otp_consumed(identity_hash, otp_id);
conversation_manager.is_otp_consumed(identity_hash, otp_id);
```

## Conversation Sessions

Each conversation maintains state:

```rust
ConversationSession {
    conversation_id: [u8; 32],     // Derived from X3DH
    peer_identity_hash: ContentHash,
    conversation_key: [u8; 32],    // Root key

    // Double Ratchet state
    double_ratchet: Option<DoubleRatchet>,
    ratchet_initialized: bool,

    // Metadata
    messages_sent: u64,
    messages_received: u64,
    last_activity: u64,
}
```

Sessions are stored locally and persist across restarts.

## Threat Model

### What's Protected

- Message content (encrypted)
- Sender identity (sealed)
- Recipient identity (trial decryption)
- Conversation history (forward secrecy)
- Future messages (post-compromise security)

### What's NOT Protected

- **Timing analysis**: Relay sees when messages are posted
- **Endpoint compromise**: If your device is owned, keys are exposed
- **Traffic analysis**: Relay sees access patterns

### Mitigated Threats

- **Size analysis**: Messages are padded to fixed bucket sizes (256B to 128KB) to hide true length

### Trust Assumptions

- Your device is secure
- ML-KEM-1024 and ML-DSA-87 are quantum-resistant
- AES-256-GCM is secure
- Random number generator is unpredictable

## Security Mechanisms

### Message Padding

All messages are padded to fixed bucket sizes before encryption to prevent size-based analysis:

| Bucket Size | Use Case                   |
| ----------- | -------------------------- |
| 256 bytes   | Acknowledgments, reactions |
| 512 bytes   | Short messages             |
| 1 KB        | Medium messages            |
| 2 KB        | Longer messages            |
| 4 KB        | Large messages             |
| 8 KB        | Very large messages        |
| 16-128 KB   | Extended content           |

Padding format: `[original_data][random_padding][4-byte length]`

### Conversation Binding

Messages are cryptographically bound to their conversation using AES-GCM's Additional Authenticated Data (AAD):

```
encrypted_inner = AES-256-GCM(
    key = conversation_key,
    plaintext = padded_inner_message,
    aad = conversation_id  // Binds message to this conversation
)
```

This prevents:

- Message reassignment attacks (moving a message to a different conversation)
- Conversation confusion attacks

### Envelope Validation

Sealed envelopes are validated to prevent message type confusion:

- Envelopes cannot contain both X3DH data AND ratchet headers
- Malformed envelopes are rejected before processing

### Timing-Safe Hint Checking

When scanning messages, identity selection is randomized to prevent timing side-channels:

- All hint keys are checked regardless of early matches
- When multiple identities match, one is selected randomly
- Prevents leaking which identity index matched

### Decryption Failure Classification

Decryption failures are categorized to detect potential attacks:

| Failure Type         | Meaning                         | Action                     |
| -------------------- | ------------------------------- | -------------------------- |
| AuthenticationFailed | Message corrupted or tampered   | Alert user, log for review |
| EnvelopeParseFailed  | Malformed message structure     | Reject silently            |
| HintFalsePositive    | Hint matched incorrectly (rare) | Reject silently            |
| DecryptionError      | Generic crypto failure          | Log for debugging          |

### Ratchet Initialization Guard

Double Ratchet initialization is protected against race conditions:

- Guard flag prevents concurrent initialization attempts
- Initialization is atomic - completes fully or rolls back

### Skipped Message Key Limits

To prevent DoS attacks via out-of-order messages:

- Maximum 1000 skipped message keys stored per session
- Skipped keys expire after 24 hours
- Requests exceeding limits are rejected

## Module Structure

```
src/forum/
├── encryption_identity.rs  # EncryptionIdentity node, prekey bundles
├── sealed_message.rs       # SealedPrivateMessage node type, padding utilities
├── pm_sealed.rs            # Seal/unseal functions, X3DH integration
├── pm_scanner.rs           # Efficient message scanning with hints
└── conversation.rs         # ConversationSession, Double Ratchet state
```

## Usage Flow

### Creating a PM Identity

```
1. User selects signing key
2. System generates ML-KEM keypairs for:
   - Signed prekey
   - One-time prekeys (default: 10)
3. EncryptionIdentity node created and signed
4. Node submitted to forum DAG
5. Private keys stored locally (encrypted)
```

### Sending a Message

```
1. Fetch recipient's EncryptionIdentity from DAG
2. Perform X3DH (or use existing session)
3. Encrypt message with Double Ratchet
4. Create sealed envelope with sender identity
5. Encrypt envelope to recipient's identity key
6. Compute recipient hint
7. Create SealedPrivateMessage node
8. Submit to forum DAG
```

### Receiving Messages

```
1. Scan forum for SealedPrivateMessage nodes
2. For each, check recipient_hint against our hint_key
3. If hint matches, attempt full decryption:
   a. Decrypt outer layer with our identity key
   b. Extract sender identity, verify it exists
   c. Perform X3DH (or use existing session)
   d. Decrypt inner message with Double Ratchet
4. Store decrypted message locally
5. Update conversation session state
```
