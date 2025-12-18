# Forum System

PQPGP includes a cryptographically-secured forum system built on a Directed Acyclic Graph (DAG) structure. Every piece of content is signed and hash-linked, providing tamper-evident, self-verifying data.

## DAG Structure

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

## Node Types

| Type                   | Description                               | Parent             |
| ---------------------- | ----------------------------------------- | ------------------ |
| `ForumGenesis`         | Root node, defines forum name/description | None               |
| `BoardGenesis`         | Creates a board within the forum          | ForumGenesis       |
| `ThreadRoot`           | Starts a new thread in a board            | BoardGenesis       |
| `Post`                 | Reply within a thread                     | ThreadRoot or Post |
| `ModAction`            | Moderation action (hide, move, etc.)      | DAG heads          |
| `EditNode`             | Edits forum or board metadata             | Target node        |
| `EncryptionIdentity`   | PM prekey bundle                          | ForumGenesis       |
| `SealedPrivateMessage` | Encrypted private message                 | ForumGenesis       |

## Content Addressing

Every node is identified by its content hash:

```rust
content_hash = SHA3-512(bincode::serialize(content))
```

This provides:

- **Immutability**: Changing content changes the hash
- **Tamper evidence**: Any modification is detectable
- **Self-verification**: Hash can be recomputed from content

## Cryptographic Signatures

Every node is signed by its author:

```rust
signature = ML-DSA-87.sign(private_key, content_bytes)
```

This proves:

- **Authenticity**: Node was created by the claimed author
- **Non-repudiation**: Author cannot deny creating it
- **Integrity**: Content has not been modified

## Validation Rules

When receiving a node, the system validates:

1. **Signature verification** - Valid ML-DSA-87 signature
2. **Content hash verification** - Hash matches content
3. **Parent existence** - All referenced parents exist
4. **Parent type validation** - Parents are correct type
5. **Thread isolation** - Posts stay within their thread
6. **Permission checks** - Author has required permissions
7. **Timestamp sanity** - Within ±5 minutes of current time
8. **Size limits** - Content within allowed bounds

Invalid nodes are rejected and never stored.

## Moderation System

### Hierarchy

| Role                | Permissions                                                       |
| ------------------- | ----------------------------------------------------------------- |
| **Forum Owner**     | Create boards, manage forum mods, edit forum, full control        |
| **Forum Moderator** | Create boards, manage board mods, hide/unhide boards, edit boards |
| **Board Moderator** | Hide/unhide threads and posts within assigned board               |
| **Member**          | Create threads and posts                                          |

### Moderation Actions

All moderation actions are recorded in the DAG as signed `ModAction` nodes:

- `AddModerator` / `RemoveModerator` - Forum-level mod management
- `AddBoardModerator` / `RemoveBoardModerator` - Board-level mod management
- `HideThread` / `UnhideThread` - Hide or restore threads
- `HidePost` / `UnhidePost` - Hide or restore posts
- `HideBoard` / `UnhideBoard` - Hide or restore boards
- `MoveThread` - Move thread to different board

Hidden content remains in the DAG (for auditability) but is not displayed.

### Causal Ordering

Moderation actions reference current DAG heads, establishing causal order:

```
Posts A, B, C exist
         │
         ▼
ModAction(HidePost(B), parents=[A,B,C])
         │
         ▼
Anyone syncing sees: A created before hide action
```

This prevents race conditions and makes moderation history auditable.

## Sync Protocol

The sync protocol efficiently transfers only missing nodes:

```
1. Client → Relay:  SyncRequest { forum_hash, known_heads: [...] }
2. Relay → Client:  SyncResponse { missing_hashes: [...], server_heads: [...] }
3. Client → Relay:  FetchNodesRequest { hashes: [...] }
4. Relay → Client:  FetchNodesResponse { nodes: [...] }
5. Client validates and stores nodes, updates heads
```

**Heads** are nodes with no children - the "tips" of the DAG. By comparing heads, client and relay can determine what's missing.

## Trust Model

The DAG is **trustless** - you don't need to trust the relay:

| What relay CAN do           | What relay CANNOT do       |
| --------------------------- | -------------------------- |
| Store/forward nodes         | Forge signatures           |
| Withhold nodes (censorship) | Modify content             |
| See public content          | Create fake nodes          |
| Rate limit                  | Break cryptographic proofs |

All security comes from client-side cryptographic verification.

## Security Properties

| Attack                  | Prevention                         |
| ----------------------- | ---------------------------------- |
| Content modification    | Hash changes, signature invalid    |
| Fake authorship         | Signature verification fails       |
| Backdating nodes        | Parent references must exist       |
| History rewriting       | Descendants have broken references |
| Unauthorized moderation | Permission checks                  |
| Replay attacks          | Content hash uniqueness            |

## API Endpoints

```
GET    /forums                    - List all forums
POST   /forums                    - Create a new forum
GET    /forums/:hash              - Get forum details
GET    /forums/:hash/boards       - List boards in forum
GET    /forums/:hash/moderators   - List forum moderators
GET    /forums/:fh/boards/:bh/moderators - List board moderators
GET    /forums/:fh/boards/:bh/threads    - List threads in board
GET    /forums/:fh/threads/:th/posts     - List posts in thread
POST   /forums/sync               - Sync request
POST   /forums/nodes/fetch        - Fetch nodes by hash
POST   /forums/nodes/submit       - Submit a new node
GET    /forums/:hash/export       - Export entire forum DAG
```

## Storage

### Relay (RocksDB)

```
pqpgp_relay_data/
└── forum_db/
    ├── Column: nodes   # {forum_hash}:{node_hash} → DagNode
    ├── Column: forums  # {forum_hash} → metadata
    └── Column: meta    # forum_list → [forum_hashes]
```

### Client (RocksDB)

```
pqpgp_forum_data/
└── forum_db/
    ├── Column: nodes             # {forum_hash}:{node_hash} → DagNode
    ├── Column: forums            # {forum_hash} → ForumMetadata
    ├── Column: heads             # {forum_hash} → Vec<ContentHash>
    ├── Column: meta              # forum_list → [forum_hashes]
    ├── Column: private           # Private data (conversation sessions, etc.)
    ├── Column: idx_forums        # Sorted index for forum listing
    ├── Column: idx_boards        # Sorted index for board listing
    ├── Column: idx_threads       # Sorted index for thread listing
    ├── Column: idx_posts         # Sorted index for post listing
    ├── Column: idx_post_counts   # Reply count cache per thread
    ├── Column: idx_mod_actions   # Index for moderation actions
    ├── Column: idx_edits         # Index for edit nodes
    ├── Column: idx_encryption_ids # Index for PM encryption identities
    └── Column: idx_sealed_msgs   # Index for sealed private messages
```

### Query Indexes

The client storage maintains indexes for fast queries. Without indexes, every query would need to scan and deserialize all nodes in a forum (O(n) where n = total nodes).

**Index Key Structure:**

Indexes embed timestamps directly in keys to enable sorted iteration without post-processing. This allows cursor-based pagination with early termination.

| Index                | Key Structure                                                | Size      | Sort Order    |
| -------------------- | ------------------------------------------------------------ | --------- | ------------- |
| `idx_forums`         | `inverted_timestamp + forum_hash`                            | 72 bytes  | Newest first  |
| `idx_boards`         | `forum_hash + inverted_timestamp + board_hash`               | 136 bytes | Newest first  |
| `idx_threads`        | `forum_hash + board_hash + inverted_timestamp + thread_hash` | 200 bytes | Newest first  |
| `idx_posts`          | `forum_hash + thread_hash + timestamp + post_hash`           | 200 bytes | Oldest first  |
| `idx_post_counts`    | `forum_hash + thread_hash`                                   | 128 bytes | N/A (counter) |
| `idx_mod_actions`    | `forum_hash + mod_action_hash`                               | 128 bytes | N/A           |
| `idx_edits`          | `forum_hash + target_hash + edit_hash`                       | 192 bytes | N/A           |
| `idx_encryption_ids` | `forum_hash + identity_hash`                                 | 128 bytes | N/A           |
| `idx_sealed_msgs`    | `forum_hash + timestamp + msg_hash`                          | 136 bytes | Oldest first  |

**Timestamp Encoding:**

- **Inverted timestamps** (`u64::MAX - timestamp`) sort newest-first in byte order (boards, threads)
- **Non-inverted timestamps** sort oldest-first for chronological reading (posts)
- Timestamps are stored as big-endian 8-byte values for correct byte ordering

**Cursor-Based Pagination:**

Cursors encode `(timestamp, hash)` pairs for stable pagination:

```rust
struct Cursor {
    timestamp: u64,
    hash: ContentHash,
}
```

The pagination algorithm:

1. Seek to cursor position in index using prefix + timestamp
2. Iterate forward, collecting items until limit reached
3. Stop iteration early (no need to scan remaining items)
4. Return next cursor from last item for continuation

**Performance:**

| Query               | Without Indexes | With Indexes                 |
| ------------------- | --------------- | ---------------------------- |
| List boards         | O(all nodes)    | O(page_size)                 |
| List threads        | O(all nodes)    | O(page_size)                 |
| List posts          | O(all nodes)    | O(page_size)                 |
| Get post count      | O(all nodes)    | O(1)                         |
| Paginate 10 of 1000 | O(1000)         | O(10) with early termination |

For forums with 1000+ nodes, this reduces page load times from 300-400ms to 2-10ms.

**Summary Types (N+1 Query Elimination):**

Paginated queries return summary structs that include related data, eliminating N+1 query patterns:

| Query                    | Return Type           | Included Data                          |
| ------------------------ | --------------------- | -------------------------------------- |
| `get_boards_paginated`   | `BoardSummary`        | Board + effective name/description     |
| `get_threads_paginated`  | `ThreadSummary`       | Thread + post count                    |
| `get_posts_paginated`    | `PostSummary`         | Post + quote preview (if quoting)      |
| `all_sessions_paginated` | `ConversationSummary` | Session + last message + message count |

This eliminates per-item queries:

- **Boards**: Edits are batch-loaded in a single pass over the edit index
- **Threads**: Post counts are fetched from `idx_post_counts` (O(1) per thread)
- **Posts**: Only quoted posts are loaded (not all posts in thread)
- **Conversations**: Messages are counted and last message fetched in a single pass

**Automatic migration:** When opening a database with old-format indexes (128-byte board keys instead of 136-byte), indexes are automatically rebuilt on startup:

```
Indexes have old format (128-byte board keys), rebuilding with sorted keys...
Rebuilt indexes: X boards, Y threads, Z posts
```

**Manual rebuild:** If indexes become corrupted, call `storage.rebuild_all_indexes()` to regenerate them from the node data.

## Module Structure

```
src/forum/
├── types.rs              # ContentHash, NodeType, ModAction
├── constants.rs          # Validation limits and shared constants
├── genesis.rs            # ForumGenesis node
├── board.rs              # BoardGenesis node
├── thread.rs             # ThreadRoot node
├── post.rs               # Post node
├── edit.rs               # EditNode for metadata updates
├── moderation.rs         # ModActionNode
├── permissions.rs        # Permission checking
├── dag.rs                # DagNode enum wrapper
├── dag_ops.rs            # DAG operations (compute_missing, topological sort)
├── sync.rs               # Sync protocol types
├── storage.rs            # Client-side storage
├── state.rs              # Forum state management
├── client.rs             # ForumClient with sync
├── rpc_client.rs         # JSON-RPC client for relay communication
├── validation.rs         # Node validation rules
├── encryption_identity.rs # PM prekey bundles
├── sealed_message.rs     # Encrypted private message nodes
├── pm_sealed.rs          # Seal/unseal functions
├── pm_scanner.rs         # Efficient message scanning
└── conversation.rs       # Double Ratchet session management
```
