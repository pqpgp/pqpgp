<p align="center">
  <img src="https://i.imgur.com/3Bbddk7.png" alt="PQPGP" width="850">
</p>

A post-quantum secure implementation of PGP (Pretty Good Privacy) in Rust, providing quantum-resistant cryptographic operations while maintaining compatibility with standard PGP workflows and packet formats.

> [!WARNING]
> While PQPGP implements cryptographic algorithms standardized by NIST, this software has not undergone a formal security audit. A formal audit is planned once the design and APIs have stabilized.
> This project is under active development and is considered experimental. Features may change, and not all functionality is production-ready.
> If you discover bugs, security vulnerabilities, or have feature requests, please open an issue on [GitHub](https://github.com/pqpgp/pqpgp/issues).

## Documentation

- **[Cryptography](docs/cryptography.md)** - Encryption, signatures, key management, ASCII armor
- **[Forums](docs/forums.md)** - DAG structure, moderation, sync protocol
- **[Indexes](docs/indexes.md)** - Storage indexes across client, relay, and web server
- **[Private Messages](docs/private-messages.md)** - Sealed sender, X3DH, Double Ratchet
- **[Relay Server](docs/relay.md)** - Message routing, forum hosting, peer sync
- **[Simulator](docs/simulator.md)** - Multi-user testing environment, security attack simulation

## Security Features

- **Post-Quantum Cryptography**: Uses NIST-standardized ML-KEM-1024 and ML-DSA-87 algorithms
- **Hybrid Approach**: Combines classical and post-quantum algorithms for maximum security
- **Signal Protocol Inspired Chat**: X3DH key exchange + Double Ratchet with post-quantum primitives
- **Perfect Forward Secrecy**: Each message gets unique keys; one-time prekeys and ratcheting provide break-in recovery
- **Random Nonces**: Cryptographically random nonces for every encryption operation
- **Password Protection**: Optional Argon2id-based password encryption for private keys
- **PGP Compatible**: Standard PGP packet formats (RFC 4880) with new algorithm identifiers
- **Production Security**: Comprehensive input validation, rate limiting, and attack prevention

## Quick Start

### Installation

```bash
git clone https://github.com/pqpgp/pqpgp
cd pqpgp
cargo build --release
```

### Basic Usage

```rust
use pqpgp::crypto::{KeyPair, encrypt_message, decrypt_message, sign_message, verify_signature, Password};
use pqpgp::armor::{create_signed_message, parse_signed_message};

// Generate hybrid key pairs (encryption + signing)
let (enc_keypair, sign_keypair) = KeyPair::generate_hybrid()?

// Optionally protect private keys with password
let password = Password::new("secure_password123".to_string());
enc_keypair.private_key_mut().encrypt_with_password(&password)?;
sign_keypair.private_key_mut().encrypt_with_password(&password)?;

// Sign-then-encrypt workflow (like traditional PGP)
let message = "Secret post-quantum message";

// 1. Sign the message
let signature = sign_message(sign_keypair.private_key(), message.as_bytes(), Some(&password))?;
let signature_data = bincode::serialize(&signature)?;

// 2. Create signed message armor
let signed_message = create_signed_message(message, &signature_data)?;

// 3. Encrypt the signed message
let encrypted = encrypt_message(enc_keypair.public_key(), signed_message.as_bytes())?;

// Decrypt-then-verify workflow
// 1. Decrypt to get signed message
let decrypted_signed = decrypt_message(enc_keypair.private_key(), &encrypted, Some(&password))?;
let decrypted_signed_str = String::from_utf8(decrypted_signed)?;

// 2. Parse signed message to extract original message and signature
let (original_message, signature_data) = parse_signed_message(&decrypted_signed_str)?;
let signature: pqpgp::crypto::Signature = bincode::deserialize(&signature_data)?;

// 3. Verify the signature
verify_signature(sign_keypair.public_key(), original_message.as_bytes(), &signature)?;
assert_eq!(message, original_message);
```

### Command Line Interface

```bash
# Generate a new key pair (optionally with password protection)
./target/release/pqpgp generate-key mlkem1024 "Alice <alice@example.com>"
./target/release/pqpgp generate-key mldsa87 "Bob <bob@example.com>" --password

# List all keys in keyring
./target/release/pqpgp list-keys

# Encrypt a message for a recipient
./target/release/pqpgp encrypt alice@example.com message.txt message.pgp

# Decrypt a message (password prompt for encrypted keys)
./target/release/pqpgp decrypt message.pgp decrypted.txt

# Sign a document (password prompt for encrypted signing keys)
./target/release/pqpgp sign A1B2C3D4E5F60708 document.txt document.sig

# Verify a signature
./target/release/pqpgp verify document.txt document.sig

# Import/Export keys
./target/release/pqpgp import keys.asc
./target/release/pqpgp export alice@example.com alice_public.asc
```

### Web Interface

PQPGP provides a web interface for easy key management, cryptographic operations, and **end-to-end encrypted chat**:

```bash
# Build everything
cargo build --release --workspace

# Start the relay server (for multi-user chat and forum)
./target/release/pqpgp-relay
# Relay runs on http://localhost:3001

# Start the web server
./target/release/pqpgp-web
# Web UI available at http://localhost:3000
```

**Web Interface Features:**

- Key generation and management
- Sign-then-encrypt workflow (traditional PGP compatibility)
- Decrypt-then-verify workflow with signed message parsing
- Key import/export functionality
- **Post-quantum encrypted chat** with Signal Protocol-inspired design
- **DAG-based forums** with cryptographic integrity and hierarchical moderation
- User-friendly forms with CSRF protection
- Session-based security with HTTP-only cookies
- **Security headers**: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy
- Input validation with size limits to prevent DoS attacks

### Relay Server

PQPGP includes a dedicated relay server for message routing, forum hosting, and peer-to-peer synchronization:

```bash
# Run with default settings (localhost:3001)
./target/release/pqpgp-relay

# Run on custom address (for production deployment)
./target/release/pqpgp-relay --bind 0.0.0.0:8080

# Configure web server to use custom relay
PQPGP_RELAY_URL=http://your-relay:8080 ./target/release/pqpgp-web

# Sync from peer relays (for federation/redundancy)
./target/release/pqpgp-relay --peers http://relay1.example.com,http://relay2.example.com

# Sync only specific forums from peers
./target/release/pqpgp-relay --peers http://relay1.example.com --sync-forums <hash1>,<hash2>

# Set custom sync interval (default: 60 seconds)
./target/release/pqpgp-relay --peers http://relay1.example.com --sync-interval 120
```

**Relay Server Features:**

- User registration with prekey bundles
- Message queuing for offline recipients
- User discovery endpoint
- Stateless design (messages deleted after delivery)
- Cryptographically random message IDs
- **Forum hosting** with RocksDB-backed persistence
- **Peer-to-peer sync** for relay federation and redundancy
- **IP-based rate limiting** with token bucket algorithm (separate limits for reads/writes)
- **Graceful error recovery** for lock poisoning

### DAG-Based Forums

PQPGP includes a cryptographically-secured forum system built on a Directed Acyclic Graph (DAG) structure:

```
┌─────────────────────────────────────────────────────────────┐
│                       DAG STRUCTURE                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ForumGenesis ──┬──> BoardGenesis ──┬──> ThreadRoot        │
│   (root)         │    (board A)      │    (thread 1)        │
│                  │                   │         │            │
│                  │                   │    ┌────┴────┐       │
│                  │                   │    ▼         ▼       │
│                  │                   │  Post      Post      │
│                  │                   │    │                 │
│                  │                   │    ▼                 │
│                  │                   │  Post (reply)        │
│                  │                   │                      │
│                  └──> BoardGenesis ──┴──> ...               │
│                       (board B)                             │
│                                                             │
│   Each node:                                                │
│   • content_hash = SHA3-512(bincode::serialize(content))    │
│   • signature = ML-DSA-87(content, author_private_key)      │
│   • References parent(s) by content_hash                    │
└─────────────────────────────────────────────────────────────┘
```

**Forum Features:**

- **Content Addressing**: Every node is identified by its SHA3-512 hash
- **Cryptographic Signatures**: All posts signed with ML-DSA-87 for authenticity
- **Hierarchical Structure**: Forum → Board → Thread → Post
- **Moderation System**: Forum owners, forum moderators, and board-specific moderators
- **Self-Describing Data**: DAG can be rebuilt from any backup without external data
- **Sync Protocol**: Efficient cursor-based synchronization with batching
- **Client-Side Storage**: Web client maintains local DAG copy for offline access
- **Causal Ordering**: Moderation actions reference DAG heads to prevent race conditions
- **RocksDB Storage**: High-performance relay persistence that scales to millions of posts

**Moderation Hierarchy:**

| Role                | Permissions                                                                 |
| ------------------- | --------------------------------------------------------------------------- |
| **Forum Owner**     | Create boards, add/remove forum moderators, edit forum, full control        |
| **Forum Moderator** | Create boards, add/remove board moderators, hide/unhide boards, edit boards |
| **Board Moderator** | Hide/unhide threads and posts within assigned board only                    |
| **Member**          | Create threads and posts                                                    |

**Moderation Actions:**

- `AddModerator` / `RemoveModerator` - Forum-level moderator management (owner only)
- `AddBoardModerator` / `RemoveBoardModerator` - Board-level moderator management
- `HideThread` / `UnhideThread` - Hide or restore threads (content remains in DAG)
- `HidePost` / `UnhidePost` - Hide or restore individual posts
- `HideBoard` / `UnhideBoard` - Hide or restore entire boards
- `MoveThread` - Move a thread to a different board within the same forum

### Private Messaging (Sealed Sender Protocol)

Forums support end-to-end encrypted private messages using a Signal-inspired sealed sender protocol:

```
┌──────────────────────────────────────────────────────────────────┐
│                       Sealed Sender Protocol                     │
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

**Privacy Properties:**

| Property                 | How Achieved                                         |
| ------------------------ | ---------------------------------------------------- |
| Content hidden           | AES-256-GCM encryption                               |
| Sender hidden            | Sealed sender - only recipient knows                 |
| Recipient hidden         | Trial decryption - server can't tell who can decrypt |
| Forward secrecy          | X3DH + Double Ratchet                                |
| Post-compromise security | Double Ratchet key rotation                          |
| Deniability              | No signatures on message content                     |

**DAG Sync Protocol:**

The sync protocol uses cursor-based pagination with `(timestamp, hash)` cursors for efficient incremental sync:

```
1. Client → Relay:  SyncRequest { forum_hash, cursor_timestamp: 0, cursor_hash: null, batch_size: 100 }
2. Relay → Client:  SyncResponse { nodes: [...], next_cursor_timestamp, next_cursor_hash, has_more }
3. Client validates and stores nodes
4. Repeat with next cursor until has_more = false
```

**Benefits:**

- O(log n) relay lookup using timestamp index
- Fixed-size requests regardless of DAG complexity
- Nodes returned directly in sync response (no separate fetch step)
- Cursor handles ties when multiple nodes share a timestamp

Concurrent posts from different users create valid DAG branches that merge on sync.

**Relay JSON-RPC 2.0 API:**

All relay operations use a single `/rpc` endpoint with JSON-RPC 2.0:

```
POST /rpc - JSON-RPC 2.0 endpoint

Methods:
  user.register    - Register user with prekey bundle
  user.list        - List all registered users
  message.send     - Send message to recipient
  message.fetch    - Fetch messages for recipient
  forum.list       - List all forums
  forum.sync       - Cursor-based sync with batched nodes
  forum.fetch      - Fetch nodes by hash
  forum.submit     - Submit a new node
  forum.export     - Export entire forum DAG (paginated)
  relay.health     - Health check
  relay.stats      - Server statistics
```

## Password Protection

PQPGP supports optional password-based encryption of private keys using industry-standard Argon2id key derivation and AES-256-GCM encryption:

### Features

- **Argon2id Key Derivation**: Memory-hard password hashing resistant to GPU/ASIC attacks
- **AES-256-GCM Encryption**: Authenticated encryption of private key material
- **Secure Parameters**: 19MB memory cost, 2 iterations for strong protection
- **Zero-Knowledge**: Passwords are never stored, only used for key derivation
- **Selective Protection**: Choose which keys to protect with passwords

### Usage Examples

```rust
use pqpgp::crypto::{KeyPair, Password};

// Generate key pair
let mut keypair = KeyPair::generate_mlkem1024()?;

// Protect with password
let password = Password::new("my_secure_password".to_string());
keypair.private_key_mut().encrypt_with_password(&password)?;

// Use encrypted key (password required)
let signature = sign_message(keypair.private_key(), message, Some(&password))?;
```

### Security Properties

- **Brute Force Resistant**: Argon2id makes password cracking computationally expensive
- **Salt-Based**: Each encrypted key uses unique random salt
- **Forward Secure**: Changing password doesn't reveal previous keys
- **Timing Attack Resistant**: Constant-time operations prevent information leakage

## Post-Quantum Chat Protocol

PQPGP implements an end-to-end encrypted chat system inspired by the Signal Protocol, but using post-quantum cryptographic primitives:

### Protocol Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     X3DH Key Exchange                           │
├─────────────────────────────────────────────────────────────────┤
│  Alice                                              Bob         │
│    │                                                  │         │
│    │  1. Fetch Bob's prekey bundle                    │         │
│    │<─────────────────────────────────────────────────│         │
│    │                                                  │         │
│    │  2. Generate ephemeral ML-KEM keys               │         │
│    │  3. Encapsulate to signed prekey (ML-KEM-1024)   │         │
│    │  4. Encapsulate to one-time prekey               │         │
│    │  5. Derive shared secret (HKDF-SHA3-512)         │         │
│    │                                                  │         │
│    │  6. Send initial message + KEM ciphertexts       │         │
│    │─────────────────────────────────────────────────>│         │
│    │                                                  │         │
│    │     Bob decapsulates, derives same secret        │         │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Double Ratchet                               │
├─────────────────────────────────────────────────────────────────┤
│  • Symmetric ratchet: Each message advances chain key           │
│  • DH ratchet: Periodic ML-KEM exchanges for forward secrecy    │
│  • Message encryption: AES-256-GCM with random nonces           │
└─────────────────────────────────────────────────────────────────┘
```

### Security Properties

| Property                  | Implementation                                         |
| ------------------------- | ------------------------------------------------------ |
| **Post-Quantum Security** | ML-KEM-1024 for key exchange, ML-DSA-87 for signatures |
| **Forward Secrecy**       | One-time prekeys + Double Ratchet DH steps             |
| **Break-in Recovery**     | DH ratchet heals session after key compromise          |
| **Authentication**        | Identity keys sign prekey bundles                      |
| **Replay Protection**     | Message numbers + unique nonces per message            |
| **Identity Verification** | Fingerprint comparison for out-of-band verification    |

### Chat Module Structure

```
src/chat/
├── identity.rs    # ML-DSA-87 identity key pairs
├── prekey.rs      # Signed prekeys + one-time prekeys (ML-KEM-1024)
├── x3dh.rs        # Extended Triple Diffie-Hellman key exchange
├── ratchet.rs     # Double Ratchet with ML-KEM
├── session.rs     # Session management and message encryption
├── message.rs     # Chat message types and serialization
└── header.rs      # Encrypted message headers
```

## Advanced Key Derivation (HKDF)

PQPGP implements state-of-the-art key derivation using HKDF-SHA3-512:

### Security Features

- **Random Nonces**: Each encryption operation uses a fresh cryptographically random nonce (12 bytes from OsRng)
- **Perfect Forward Secrecy**: Unique AES-256 keys derived for each message via the ratchet
- **Domain Separation**: Different HKDF info strings for different key types prevent cross-protocol attacks
- **Cryptographic Binding**: Keys are bound to both party identities via associated data

### Technical Implementation

```rust
// Message key derivation from ratchet chain
let aes_key = message_key.derive_aes_key()?;  // HKDF-SHA3-512

// Random nonce for each encryption (prepended to ciphertext)
let mut nonce = [0u8; 12];
OsRng.fill_bytes(&mut nonce);

// AES-256-GCM encryption with associated data
let ciphertext = aes_gcm.encrypt(nonce, Payload { msg, aad })?;
```

### Security Benefits

- **No nonce reuse**: Random nonces eliminate deterministic nonce vulnerabilities
- **Quantum-resistant key expansion**: Based on quantum-resistant ML-KEM shared secrets
- **Cryptographically secure**: HKDF is proven secure in the random oracle model
- **Standards-based**: Implements RFC 5869 with SHA3-512 for quantum resistance

## Cryptographic Algorithms

| Operation            | Algorithm     | NIST Standard | Key Size    |
| -------------------- | ------------- | ------------- | ----------- |
| Key Encapsulation    | ML-KEM-1024   | FIPS 203      | 1,568 bytes |
| Digital Signatures   | ML-DSA-87     | FIPS 204      | 2,592 bytes |
| Symmetric Encryption | AES-256-GCM   | FIPS 197      | 32 bytes    |
| Key Derivation       | HKDF-SHA3-512 | RFC 5869      | Variable    |
| Hashing              | SHA3-512      | FIPS 202      | 64 bytes    |
| Password Hashing     | Argon2id      | RFC 9106      | 32 bytes    |

## Security Testing

PQPGP includes a comprehensive security testing framework with **430+ tests** covering:

- **Input Validation**: Buffer overflow protection, bounds checking
- **Attack Resistance**: Timing attacks, padding oracles, injection attacks
- **Resource Protection**: DoS prevention, rate limiting, memory exhaustion
- **Fuzzing**: Property-based testing with random input generation
- **Adversarial Testing**: Real attack scenario simulation

Run the security test suite:

```bash
cargo test --release
```

## Architecture

### Core Library Structure

```
src/
├── crypto/           # Post-quantum cryptographic operations
│   ├── encryption.rs # ML-KEM-1024 hybrid encryption with HKDF key derivation
│   ├── signature.rs  # ML-DSA-87 digital signatures
│   ├── password.rs   # Argon2id password-based key protection
│   └── keys.rs       # Key generation and management
├── chat/             # End-to-end encrypted chat protocol
│   ├── identity.rs   # ML-DSA-87 identity key pairs
│   ├── prekey.rs     # Signed & one-time prekeys (ML-KEM-1024)
│   ├── x3dh.rs       # X3DH key exchange
│   ├── ratchet.rs    # Double Ratchet algorithm
│   ├── session.rs    # Session management
│   └── message.rs    # Chat message types
├── packet/           # PGP packet format implementation
├── validation/       # Security validation and rate limiting
├── keyring/          # Key storage and management
├── armor/            # ASCII armor encoding/decoding + signed message parsing
├── dag/              # Generic DAG operations (extracted from forum)
├── rpc/              # Generic JSON-RPC 2.0 types and client
├── storage/          # Generic RocksDB storage abstraction
├── forum/            # DAG-based forum system
│   ├── types.rs      # ContentHash, NodeType, ModAction
│   ├── constants.rs  # Validation limits and shared constants
│   ├── genesis.rs    # ForumGenesis node
│   ├── board.rs      # BoardGenesis node
│   ├── thread.rs     # ThreadRoot node
│   ├── post.rs       # Post node
│   ├── edit.rs       # EditNode for forum/board metadata updates
│   ├── moderation.rs # ModActionNode for moderator management
│   ├── permissions.rs# Permission checking and moderator resolution
│   ├── dag.rs        # DagNode enum wrapper
│   ├── dag_ops.rs    # DAG operations (compute_missing, topological sort)
│   ├── sync.rs       # Sync protocol types (SyncRequest, FetchNodes, etc.)
│   ├── storage.rs    # Client-side file-based DAG storage
│   ├── state.rs      # Forum state management
│   ├── client.rs     # ForumClient with sync orchestration
│   ├── rpc_client.rs # JSON-RPC client for relay communication
│   ├── validation.rs # Node validation rules
│   ├── encryption_identity.rs  # X3DH prekey bundles for PM
│   ├── sealed_message.rs       # SealedPrivateMessage node type
│   ├── pm_sealed.rs            # Sealed sender encrypt/decrypt
│   ├── pm_scanner.rs           # Efficient message scanning with hints
│   └── conversation.rs         # Double Ratchet session management
└── cli/              # Command-line interface
```

### Web Interface (bin/web)

```
bin/web/
├── Cargo.toml        # Web-specific dependencies (axum, askama, reqwest, rocksdb)
└── src/
    ├── main.rs       # Web server, HTTP handlers, chat endpoints, background sync task
    ├── chat_state.rs # Chat session state management
    ├── relay_client.rs # HTTP client for relay server
    ├── storage.rs    # Encrypted persistent storage for chat
    ├── csrf.rs       # CSRF protection
    ├── rate_limiter.rs # Request rate limiting
    ├── handlers/     # HTTP handlers
    │   └── forum.rs  # Forum web handlers with sync and validation logic
    ├── templates.rs  # Askama template definitions
    └── templates/    # HTML templates (forum, chat, keys, etc.)
```

**Web Client Forum Storage (RocksDB):**

```
pqpgp_forum_data/
└── forum_db/                    # RocksDB database
    ├── Column: nodes              # {forum_hash}:{node_hash} → DagNode
    ├── Column: forums             # {forum_hash} → ForumMetadata
    ├── Column: heads              # {forum_hash} → Vec<ContentHash>
    ├── Column: meta               # forum_list → [forum_hashes]
    ├── Column: private            # Private data (conversation sessions, etc.)
    ├── Column: idx_forums         # Sorted index for forum listing
    ├── Column: idx_boards         # Sorted index for board listing
    ├── Column: idx_threads        # Sorted index for thread listing
    ├── Column: idx_posts          # Sorted index for post listing
    ├── Column: idx_post_counts    # Reply count cache per thread
    ├── Column: idx_mod_actions    # Index for moderation actions
    ├── Column: idx_edits          # Index for edit nodes
    ├── Column: idx_encryption_ids # Index for PM encryption identities
    └── Column: idx_sealed_msgs    # Index for sealed private messages
```

**Query Indexes:**

Indexes embed timestamps in keys for efficient sorted iteration and cursor-based pagination:

| Index                | Key Structure                                      | Sort Order   |
| -------------------- | -------------------------------------------------- | ------------ |
| `idx_forums`         | `inverted_ts + forum` (72 bytes)                   | Newest first |
| `idx_boards`         | `forum + inverted_ts + board` (136 bytes)          | Newest first |
| `idx_threads`        | `forum + board + inverted_ts + thread` (200 bytes) | Newest first |
| `idx_posts`          | `forum + thread + timestamp + post` (200 bytes)    | Oldest first |
| `idx_post_counts`    | `forum + thread` (128 bytes)                       | N/A          |
| `idx_mod_actions`    | `forum + mod_action` (128 bytes)                   | N/A          |
| `idx_edits`          | `forum + target + edit` (192 bytes)                | N/A          |
| `idx_encryption_ids` | `forum + identity` (128 bytes)                     | N/A          |
| `idx_sealed_msgs`    | `forum + timestamp + msg` (136 bytes)              | Oldest first |

This enables O(page_size) queries with early termination instead of O(all_nodes), reducing page loads from 300ms to 2-10ms.

**Background Sync:**

The web client uses background polling to keep forums synchronized:

- Default sync interval: 30 seconds (configurable via `PQPGP_FORUM_SYNC_INTERVAL`)
- All locally-tracked forums are synced automatically
- UI reads from local storage for fast, offline-capable access
- New content is stored locally first, then submitted to relay

**Node Validation:**

Both the relay server and web client validate nodes using shared validation logic:

- Signature verification (ML-DSA-87)
- Content hash verification (SHA3-512)
- Parent existence checks (DAG integrity)
- Parent type validation (posts can only reference posts or thread roots)
- Thread isolation (parent posts must belong to the same thread)
- Permission checks (moderator actions)
- Target validation (hide/unhide actions verify target exists and has correct type)
- Timestamp sanity checks (±5 minute clock skew, minimum timestamp validation)
- Content size limits (DoS prevention)

Invalid nodes are rejected and not stored, protecting against malicious relays.

### Relay Server (bin/relay)

```
bin/relay/
├── Cargo.toml               # Relay server dependencies (axum, rocksdb, reqwest)
└── src/
    ├── main.rs              # Server entry point, routing
    ├── rpc/                 # Unified JSON-RPC 2.0 handler
    │   ├── mod.rs           # Module exports
    │   ├── state.rs         # Relay state types and RwLock helpers
    │   └── handlers/        # Domain-specific handlers
    │       ├── mod.rs       # Main dispatcher, helper functions
    │       ├── user.rs      # user.* methods
    │       ├── message.rs   # message.* methods
    │       ├── forum.rs     # forum.* methods
    │       └── system.rs    # relay.* methods
    ├── forum/               # Forum module
    │   ├── mod.rs           # Module exports
    │   ├── state.rs         # Forum DAG state management
    │   └── persistence.rs   # RocksDB-backed persistence
    ├── peer_sync.rs         # Relay-to-relay synchronization (uses RPC)
    └── rate_limit.rs        # IP-based rate limiting middleware

# Single JSON-RPC 2.0 endpoint:
# POST /rpc - All operations (user, message, forum, system)
```

**Forum Storage Layout (RocksDB):**

```
pqpgp_relay_data/
└── forum_db/                    # RocksDB database
    ├── Column: nodes            # {forum_hash}:{node_hash} → DagNode
    ├── Column: forums           # {forum_hash} → metadata
    └── Column: meta             # forum_list → [forum_hashes]
```

- **Write-optimized**: LSM tree with 64MB write buffers for fast appends
- **Compressed**: LZ4 compression reduces storage by ~60%
- **Scalable**: Handles millions of nodes with O(1) writes
- **Crash-safe**: WAL ensures durability even on power failure

### Simulator (bin/simulator)

```
bin/simulator/
├── Cargo.toml           # Simulator dependencies
└── src/
    ├── main.rs          # Entry point, spawns users and attack loop
    ├── user.rs          # SimulatedUser with keypair
    ├── relay.rs         # SimulatorRelay wrapper for RPC
    ├── simulation.rs    # Forum operations (create boards, threads, posts)
    └── malicious.rs     # 13 attack scenarios (signature forge, replay, etc.)
```

**Features:**

- Two relay instances (Alice on 4001, Bob on 4002) with peer sync
- Legitimate activity simulation (Alice creates content, Bob participates)
- Malicious user (Eve) continuously tests security controls
- Panics on successful attack to flag vulnerabilities

```bash
# Run the simulator
cargo run --release -p pqpgp-simulator

# Connect external clients to test sync
PQPGP_RELAY_URL=http://127.0.0.1:4001 pqpgp-web
```

### Testing & Examples

```
examples/             # Usage examples and demonstrations
tests/                # Comprehensive test suite
├── security_tests.rs           # Security validation tests
├── adversarial_tests.rs        # Attack simulation tests
├── fuzz_tests.rs               # Fuzzing and property-based tests
├── property_tests.rs           # Mathematical property verification
├── integration_tests.rs        # End-to-end workflow tests
├── forum_e2e_tests.rs          # Forum and PM end-to-end tests
├── timing_analysis_tests.rs    # Timing side-channel analysis
└── timing_safe_crypto_tests.rs # Constant-time operation verification
```

## Development

### Prerequisites

- Rust 1.75+
- Cargo

### Building

```bash
# Build core library and CLI
cargo build --release

# Build web interface (separate binary)
cargo build -p pqpgp-web --release

# Build everything in the workspace
cargo build --release --workspace

# Run tests (core library)
cargo test --release

# Run security tests
cargo test --release security
cargo test --release adversarial
cargo test --release fuzz

# Check code quality
cargo clippy --workspace -- -D warnings
```

### Performance Benchmarks

```bash
cargo bench
```

## Standards Compliance

- **RFC 4880**: OpenPGP Message Format
- **RFC 5869**: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- **RFC 9106**: The Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
- **NIST FIPS 203**: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- **NIST FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- **NIST FIPS 197**: Advanced Encryption Standard (AES)
- **NIST FIPS 202**: SHA-3 Standard

## Security Considerations

### Quantum Threat Timeline

Current estimates suggest large-scale quantum computers capable of breaking RSA and ECDSA may emerge within 10-30 years. PQPGP provides:

- **Immediate Protection**: Deploy quantum-resistant cryptography today
- **Hybrid Security**: Classical algorithms provide current security, post-quantum algorithms provide future protection
- **Smooth Migration**: PGP-compatible format allows gradual ecosystem transition

### Algorithm Selection

- **ML-KEM-1024**: Provides security equivalent to AES-256 against quantum attacks
- **ML-DSA-87**: Provides security equivalent to SHA3-512 against quantum attacks
- **Conservative Parameters**: Chosen for long-term security rather than minimal size

### Password Security

- **Strong Password Policies**: Use passwords with high entropy (≥128 bits recommended)
- **Argon2id Protection**: Memory-hard function prevents efficient GPU/ASIC attacks
- **No Password Storage**: Passwords are never stored, only used for key derivation
- **Secure Prompting**: CLI uses secure password input (no echo, memory clearing)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`cargo test --release`)
4. Run security tests (`cargo test --release security`)
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## References

- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization)
- [RFC 4880: OpenPGP Message Format](https://tools.ietf.org/html/rfc4880)
- [Quantum Computing Threat Timeline](https://globalriskinstitute.org/publications/quantum-threat-timeline/)

---

**Made with ❤️ and quantum-resistant cryptography**
