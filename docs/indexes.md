# Index Reference

This document provides a comprehensive overview of all indexes used across the pqpgp codebase, including the client library, relay server, and web server.

## Overview

The system uses three storage approaches:

1. **Client Library** (`src/forum/storage.rs`) - Full RocksDB with 23 column families for comprehensive indexing
2. **Relay Server** (`bin/relay/`) - Minimal RocksDB (3 column families) + in-memory indexes for messaging
3. **Web Server** (`bin/web/`) - Encrypted file storage + in-memory session state

---

## Client Library Indexes

### Core Storage Column Families

| Column Family | Key                         | Value                | Purpose                     |
| ------------- | --------------------------- | -------------------- | --------------------------- |
| `nodes`       | `{forum_hash}:{node_hash}`  | Serialized `DagNode` | Primary node storage        |
| `forums`      | `{forum_hash}`              | `ForumMetadata`      | Forum metadata              |
| `heads`       | `{forum_hash}`              | `Vec<ContentHash>`   | DAG heads for sync          |
| `meta`        | `forum_list`, `forum_count` | Various              | Global metadata             |
| `private`     | Prefixed keys               | Various              | Local-only data (keys, etc) |

### Content Listing Indexes

Sorted indexes for efficient paginated queries using cursor-based pagination.

| Column Family | Key Format (bytes)                                          | Value         | Sort Order   |
| ------------- | ----------------------------------------------------------- | ------------- | ------------ |
| `idx_forums`  | `inverted_ts(8) + forum_hash(64)` = 72                      | `forum_hash`  | Newest first |
| `idx_boards`  | `forum(64) + inverted_ts(8) + board_hash(64)` = 136         | `board_hash`  | Newest first |
| `idx_threads` | `forum(64) + board(64) + inverted_ts(8) + thread(64)` = 200 | `thread_hash` | Newest first |
| `idx_posts`   | `forum(64) + thread(64) + ts(8) + post(64)` = 200           | `post_hash`   | Oldest first |

**Note:** Posts use non-inverted timestamps for chronological reading order.

### Count Cache Indexes

O(1) access to totals without scanning.

| Column Family       | Key Format (bytes)             | Value | Purpose               |
| ------------------- | ------------------------------ | ----- | --------------------- |
| `idx_board_counts`  | `forum_hash(64)` = 64          | `u64` | Total boards in forum |
| `idx_thread_counts` | `forum(64) + board(64)` = 128  | `u64` | Threads per board     |
| `idx_post_counts`   | `forum(64) + thread(64)` = 128 | `u64` | Posts per thread      |

### Metadata Indexes

| Column Family        | Key Format (bytes)                        | Value          | Purpose                  |
| -------------------- | ----------------------------------------- | -------------- | ------------------------ |
| `idx_mod_actions`    | `forum(64) + action(64)` = 128            | `timestamp(8)` | Mod actions per forum    |
| `idx_edits`          | `forum(64) + target(64) + edit(64)` = 192 | `timestamp(8)` | Edits per target         |
| `idx_encryption_ids` | `forum(64) + identity(64)` = 128          | `timestamp(8)` | Encryption identities    |
| `idx_sealed_msgs`    | `forum(64) + ts(8) + msg(64)` = 136       | `msg_hash`     | Sealed messages (sorted) |

### Moderation-Derived State Indexes

Derived from mod actions for O(1) state lookups without replaying history.

| Column Family          | Key Format (bytes)                                          | Value            | Purpose                           |
| ---------------------- | ----------------------------------------------------------- | ---------------- | --------------------------------- |
| `idx_hidden_threads`   | `forum(64) + thread(64)` = 128                              | `()`             | Hidden thread set                 |
| `idx_hidden_posts`     | `forum(64) + post(64)` = 128                                | `()`             | Hidden post set                   |
| `idx_hidden_boards`    | `forum(64) + board(64)` = 128                               | `()`             | Hidden board set                  |
| `idx_moved_threads`    | `forum(64) + thread(64)` = 128                              | `board_hash(64)` | Thread's current board            |
| `idx_moved_in_threads` | `forum(64) + board(64) + inverted_ts(8) + thread(64)` = 200 | `()`             | Threads moved into board (sorted) |
| `idx_forum_mods`       | `forum(64) + fingerprint` = 64+                             | `role(1)`        | Forum moderators (1=owner, 2=mod) |
| `idx_board_mods`       | `forum(64) + board(64) + fingerprint` = 128+                | `()`             | Board moderators                  |

### Query Methods

| Operation                | Method                       | Complexity | Index Used                             |
| ------------------------ | ---------------------------- | ---------- | -------------------------------------- |
| List forums (paginated)  | `get_forums_paginated()`     | O(limit)   | `idx_forums`                           |
| List boards (paginated)  | `get_boards_paginated()`     | O(limit)   | `idx_boards`                           |
| List threads (paginated) | `get_threads_paginated()`    | O(limit)   | `idx_threads` + `idx_moved_in_threads` |
| List posts (paginated)   | `get_posts_paginated()`      | O(limit)   | `idx_posts`                            |
| Get board count          | `get_board_count()`          | O(1)       | `idx_board_counts`                     |
| Get thread count         | (cached)                     | O(1)       | `idx_thread_counts`                    |
| Get post count           | `get_post_count()`           | O(1)       | `idx_post_counts`                      |
| Check thread hidden      | `is_thread_hidden()`         | O(1)       | `idx_hidden_threads`                   |
| Check post hidden        | `is_post_hidden()`           | O(1)       | `idx_hidden_posts`                     |
| Check board hidden       | `is_board_hidden()`          | O(1)       | `idx_hidden_boards`                    |
| Get thread current board | `get_thread_current_board()` | O(1)       | `idx_moved_threads`                    |
| Get all hidden threads   | `get_hidden_threads()`       | O(hidden)  | `idx_hidden_threads`                   |
| Get forum moderators     | `get_forum_moderators()`     | O(mods)    | `idx_forum_mods`                       |

---

## Relay Server Indexes

### RocksDB Storage (`bin/relay/src/forum/persistence.rs`)

Minimal disk storage with in-memory secondary indexes.

| Column Family | Key                        | Value                                                  |
| ------------- | -------------------------- | ------------------------------------------------------ |
| `nodes`       | `{forum_hash}:{node_hash}` | Serialized `DagNode`                                   |
| `forums`      | `{forum_hash}`             | `ForumMetadata` (name, description, created_at, owner) |
| `meta`        | `forum_list`               | `Vec<ContentHash>` of all forum hashes                 |

### In-Memory Indexes (`ForumState`)

Each forum maintains in-memory secondary indexes rebuilt on load:

```rust
pub struct ForumState {
    // Primary storage
    pub nodes: HashMap<ContentHash, DagNode>,
    pub heads: HashSet<ContentHash>,

    // Secondary indexes
    boards: Vec<ContentHash>,                              // O(1) board listing
    board_threads: HashMap<ContentHash, Vec<ContentHash>>, // O(1) threads per board
    thread_posts: HashMap<ContentHash, Vec<ContentHash>>,  // O(1) posts per thread
    topological_cache: Option<Vec<ContentHash>>,           // Lazy topological order
}
```

| Index           | Key Type      | Value Type             | Purpose             |
| --------------- | ------------- | ---------------------- | ------------------- |
| `nodes`         | `ContentHash` | `DagNode`              | Primary node lookup |
| `heads`         | -             | `HashSet<ContentHash>` | DAG head tracking   |
| `boards`        | -             | `Vec<ContentHash>`     | Ordered board list  |
| `board_threads` | `ContentHash` | `Vec<ContentHash>`     | Threads per board   |
| `thread_posts`  | `ContentHash` | `Vec<ContentHash>`     | Posts per thread    |

### Messaging State (`bin/relay/src/rpc/state.rs`)

In-memory indexes for the relay messaging system:

```rust
pub struct RelayState {
    pub users: HashMap<String, RegisteredUser>,
    pub messages: HashMap<String, VecDeque<QueuedMessage>>,
}
```

| Index      | Key Type               | Value Type                | Purpose                       |
| ---------- | ---------------------- | ------------------------- | ----------------------------- |
| `users`    | fingerprint (`String`) | `RegisteredUser`          | User registration lookup      |
| `messages` | fingerprint (`String`) | `VecDeque<QueuedMessage>` | Per-user message queue (FIFO) |

**RegisteredUser:**

- `name`: Display name
- `fingerprint`: Public key fingerprint
- `prekey_bundle`: Base64-encoded prekey bundle
- `registered_at`: Registration timestamp
- `last_seen`: Last activity timestamp

**QueuedMessage:**

- `sender_fingerprint`: Sender's fingerprint
- `encrypted_data`: Encrypted message payload
- `timestamp`: Message timestamp
- `message_id`: Unique message ID

---

## Web Server Indexes

### Chat Storage (`bin/web/src/storage.rs`)

File-based encrypted storage with in-memory indexes during runtime.

**Serialized State Structure:**

```rust
struct SerializableChatState {
    sessions: HashMap<String, Vec<u8>>,    // fingerprint -> serialized Session
    contacts: HashMap<String, StoredContact>,
    messages: HashMap<String, Vec<StoredMessage>>,
}
```

| Index      | Key Type               | Value Type           | Purpose                     |
| ---------- | ---------------------- | -------------------- | --------------------------- |
| `sessions` | fingerprint (`String`) | `Vec<u8>`            | Encrypted chat sessions     |
| `contacts` | fingerprint (`String`) | `StoredContact`      | Contact information         |
| `messages` | fingerprint (`String`) | `Vec<StoredMessage>` | Message history per contact |

**StoredContact:**

- `fingerprint`: Contact's public key fingerprint
- `name`: Display name
- `prekey_bundle`: Optional prekey bundle bytes
- `has_session`: Whether an active session exists

**StoredMessage:**

- `content`: Message text
- `timestamp`: ISO 8601 timestamp string
- `is_outgoing`: Direction flag

---

## Design Patterns

### Inverted Timestamps

RocksDB sorts keys lexicographically. To get newest-first ordering:

```rust
fn invert_timestamp(timestamp: u64) -> [u8; 8] {
    (u64::MAX - timestamp).to_be_bytes()
}
```

Used in: `idx_forums`, `idx_boards`, `idx_threads`, `idx_moved_in_threads`

### Composite Keys

Keys are concatenated byte sequences enabling prefix iteration:

```rust
// All boards in a forum: prefix = forum_hash (64 bytes)
// All threads in a board: prefix = forum_hash (64) + board_hash (64) = 128 bytes
// All posts in a thread: prefix = forum_hash (64) + thread_hash (64) = 128 bytes
```

### Presence-Based Indexes

Empty values indicate set membership. Enables O(1) existence checks:

```rust
// Check if thread is hidden
let key = hidden_content_key(forum_hash, thread_hash);
db.exists(CF_IDX_HIDDEN_THREADS, &key)?
```

Used in: `idx_hidden_*`, `idx_board_mods`

### Cursor-Based Pagination

Stable pagination using timestamp + hash for tie-breaking:

```rust
pub struct Cursor {
    pub timestamp: u64,
    pub hash: ContentHash,
}
```

### Count Caches

Maintained atomically with node storage:

- Incremented when nodes are added
- Decremented when threads are moved (from source board)
- Incremented when threads are moved (to destination board)

---

## Index Key Size Reference

| Index Type      | Key Size (bytes) | Components                                        |
| --------------- | ---------------- | ------------------------------------------------- |
| Forum           | 72               | inverted_ts(8) + hash(64)                         |
| Board           | 136              | forum(64) + inverted_ts(8) + hash(64)             |
| Thread          | 200              | forum(64) + board(64) + inverted_ts(8) + hash(64) |
| Moved-in thread | 200              | forum(64) + board(64) + inverted_ts(8) + hash(64) |
| Post            | 200              | forum(64) + thread(64) + ts(8) + hash(64)         |
| Post count      | 128              | forum(64) + thread(64)                            |
| Hidden content  | 128              | forum(64) + content(64)                           |
| Moved thread    | 128              | forum(64) + thread(64)                            |
| Edit            | 192              | forum(64) + target(64) + edit(64)                 |

All hashes are 64 bytes (SHA-512/Blake2b-512 content hashes).

---

## Memory vs Disk Trade-offs

### Client Library

- **Approach:** Full disk-based indexes
- **Pro:** Constant memory regardless of data size
- **Con:** Disk I/O for queries
- **Suitable for:** Large local archives, resource-constrained devices

### Relay Server

- **Approach:** Minimal disk + in-memory indexes
- **Pro:** Simple, fast in-memory lookups
- **Con:** Memory scales with total forum size
- **Suitable for:** Typical relay deployments

### Web Server

- **Approach:** Encrypted file storage
- **Pro:** Simple persistence, portable state
- **Con:** Full reload on startup
- **Suitable for:** Single-user web clients
