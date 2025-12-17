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
pqpgp_web_forum_data/
└── forum_db/
    ├── Column: nodes   # {forum_hash}:{node_hash} → DagNode
    ├── Column: forums  # {forum_hash} → ForumMetadata
    ├── Column: heads   # {forum_hash} → Vec<ContentHash>
    └── Column: meta    # forum_list → [forum_hashes]
```

## Module Structure

```
src/forum/
├── types.rs              # ContentHash, NodeType, ModAction
├── genesis.rs            # ForumGenesis node
├── board.rs              # BoardGenesis node
├── thread.rs             # ThreadRoot node
├── post.rs               # Post node
├── edit.rs               # EditNode for metadata updates
├── moderation.rs         # ModActionNode
├── permissions.rs        # Permission checking
├── dag.rs                # DagNode enum wrapper
├── sync.rs               # Sync protocol types
├── storage.rs            # Client-side storage
├── client.rs             # ForumClient with sync
└── validation.rs         # Node validation rules
```
