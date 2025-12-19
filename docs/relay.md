# Relay Server

The PQPGP relay server is a content-addressed DAG storage node that provides message routing and forum data synchronization via a unified JSON-RPC 2.0 API.

## Design Philosophy

The relay is intentionally minimal - a "dumb pipe" for DAG data:

- **No application logic**: Clients build their own views (threads, boards, posts) from the raw DAG
- **Content-addressed**: All data identified by cryptographic hash
- **Trustless**: All nodes validated locally before storage
- **Federated**: Relays can sync from each other

## Features

- **Message Relay**: Routes encrypted messages between users
- **DAG Storage**: Stores forum nodes with cryptographic validation
- **Peer Sync**: Synchronizes data from other relays
- **Rate Limiting**: Protects against DoS attacks
- **Persistent Storage**: RocksDB-based durable storage

## Quick Start

```bash
# Run with default settings (localhost:3001)
pqpgp-relay

# Run on custom address
pqpgp-relay --bind 0.0.0.0:8080

# Enable debug logging
RUST_LOG=debug pqpgp-relay
```

## Peer-to-Peer Sync

Relays can synchronize forum data from other relays, enabling decentralization and redundancy.

### Configuration

```bash
# Sync from peer relays
pqpgp-relay --peers http://relay1.example.com,http://relay2.example.com

# Sync only specific forums
pqpgp-relay --peers http://relay1.example.com --sync-forums <hash1>,<hash2>

# Set sync interval (default: 60 seconds)
pqpgp-relay --peers http://relay1.example.com --sync-interval 120
```

### How It Works

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Relay A   │ <────── │   Relay B   │ <────── │   Relay C   │
│  (primary)  │  pull   │  (mirror)   │  pull   │    (new)    │
└─────────────┘         └─────────────┘         └─────────────┘
       ▲                       ▲                       ▲
       │                       │                       │
    clients                 clients                 clients
```

1. **Bootstrap**: New relay fetches forum list from peers
2. **Sync**: For each forum, request missing nodes using the DAG sync protocol
3. **Validate**: All received nodes are cryptographically validated before storage
4. **Periodic**: Sync repeats at configured interval

### Security Model

- **Trustless**: All nodes are validated locally (signatures, hashes, permissions)
- **No Auth Required**: Pull-only sync doesn't require authentication
- **Tamper-Proof**: Invalid or modified nodes are rejected
- **Censorship-Resistant**: Multiple relays provide redundancy

## HTTP Endpoints

| Endpoint  | Method | Description                              |
| --------- | ------ | ---------------------------------------- |
| `/rpc`    | POST   | JSON-RPC 2.0 endpoint                    |
| `/health` | GET    | Health check for load balancers/monitors |

### Health Check

Simple endpoint for load balancers and monitoring tools:

```bash
curl http://localhost:3001/health
# {"status":"ok"}
```

## JSON-RPC 2.0 API

All RPC operations use the `/rpc` endpoint:

### Available Methods

#### User Methods

| Method            | Description                      |
| ----------------- | -------------------------------- |
| `user.register`   | Register user with prekey bundle |
| `user.unregister` | Unregister a user                |
| `user.get`        | Get user's prekey bundle         |
| `user.list`       | List all registered users        |

#### Message Methods

| Method          | Description                  |
| --------------- | ---------------------------- |
| `message.send`  | Send message to recipient    |
| `message.fetch` | Fetch messages for recipient |
| `message.check` | Check pending message count  |

#### Forum Methods

| Method         | Description                                |
| -------------- | ------------------------------------------ |
| `forum.list`   | List all forums (minimal info)             |
| `forum.sync`   | Cursor-based sync with batched nodes       |
| `forum.fetch`  | Fetch nodes by hash                        |
| `forum.submit` | Submit a new node (including ForumGenesis) |
| `forum.export` | Export entire forum DAG (paginated)        |

#### System Methods

| Method         | Description       |
| -------------- | ----------------- |
| `relay.health` | Health check      |
| `relay.stats`  | Server statistics |

## JSON-RPC 2.0 Protocol

All requests use JSON-RPC 2.0 format:

```json
{
  "jsonrpc": "2.0",
  "method": "method.name",
  "params": {},
  "id": 1
}
```

### Method Examples

#### Register User

```json
// Request
{
  "jsonrpc": "2.0",
  "method": "user.register",
  "params": {
    "name": "Alice",
    "fingerprint": "abc123...",
    "prekey_bundle": "<base64-encoded-bundle>"
  },
  "id": 1
}

// Response
{
  "jsonrpc": "2.0",
  "result": {"success": true},
  "id": 1
}
```

#### List Users

```json
// Request
{"jsonrpc": "2.0", "method": "user.list", "params": {}, "id": 1}

// Response
{
  "jsonrpc": "2.0",
  "result": [
    {
      "name": "Alice",
      "fingerprint": "abc123...",
      "prekey_bundle": "<base64>",
      "registered_at": 1700000000000,
      "last_seen": 1700000000000
    }
  ],
  "id": 1
}
```

#### Send Message

```json
// Request
{
  "jsonrpc": "2.0",
  "method": "message.send",
  "params": {
    "recipient_fingerprint": "def456...",
    "sender_fingerprint": "abc123...",
    "encrypted_data": "<base64-encoded-message>"
  },
  "id": 1
}

// Response
{
  "jsonrpc": "2.0",
  "result": {"success": true},
  "id": 1
}
```

#### Fetch Messages

```json
// Request
{
  "jsonrpc": "2.0",
  "method": "message.fetch",
  "params": {"fingerprint": "abc123..."},
  "id": 1
}

// Response
{
  "jsonrpc": "2.0",
  "result": {
    "messages": [
      {
        "sender_fingerprint": "def456...",
        "encrypted_data": "<base64>",
        "timestamp": 1700000000000,
        "message_id": "msg123..."
      }
    ]
  },
  "id": 1
}
```

#### List Forums

```json
// Request
{"jsonrpc": "2.0", "method": "forum.list", "params": {}, "id": 1}

// Response
{
  "jsonrpc": "2.0",
  "result": [
    {
      "hash": "abc123...",
      "name": "My Forum",
      "description": "A test forum",
      "node_count": 42,
      "created_at": 1700000000000
    }
  ],
  "id": 1
}
```

#### Sync Forum

Uses cursor-based pagination with `(timestamp, hash)` cursor for efficient incremental sync.
Nodes are returned directly in the response, eliminating the need for separate fetch calls.

```json
// Initial sync request (cursor_timestamp=0 to get all nodes)
{
  "jsonrpc": "2.0",
  "method": "forum.sync",
  "params": {
    "forum_hash": "abc123...",
    "cursor_timestamp": 0,
    "cursor_hash": null,
    "batch_size": 100
  },
  "id": 2
}

// Response with nodes and next cursor
{
  "jsonrpc": "2.0",
  "result": {
    "forum_hash": "abc123...",
    "nodes": [
      {"hash": "jkl012...", "data": "<base64-encoded-node>"},
      {"hash": "mno345...", "data": "<base64-encoded-node>"}
    ],
    "next_cursor_timestamp": 1700000000000,
    "next_cursor_hash": "mno345...",
    "has_more": true,
    "total_nodes": 150
  },
  "id": 2
}

// Continue sync with cursor from previous response
{
  "jsonrpc": "2.0",
  "method": "forum.sync",
  "params": {
    "forum_hash": "abc123...",
    "cursor_timestamp": 1700000000000,
    "cursor_hash": "mno345...",
    "batch_size": 100
  },
  "id": 3
}
```

**Sync Protocol:**

1. Client sends request with `cursor_timestamp=0` for initial sync
2. Server returns batch of nodes ordered by `(timestamp, hash)`
3. Client stores nodes, uses `next_cursor_*` fields for next request
4. Repeat until `has_more=false`

#### Fetch Nodes

```json
// Request
{
  "jsonrpc": "2.0",
  "method": "forum.fetch",
  "params": {
    "hashes": ["jkl012...", "mno345..."]
  },
  "id": 3
}

// Response
{
  "jsonrpc": "2.0",
  "result": {
    "nodes": [
      {"hash": "jkl012...", "data": "<base64-encoded-node>"},
      {"hash": "mno345...", "data": "<base64-encoded-node>"}
    ],
    "not_found": []
  },
  "id": 3
}
```

#### Submit Node

```json
// Request
{
  "jsonrpc": "2.0",
  "method": "forum.submit",
  "params": {
    "forum_hash": "abc123...",
    "node_data": "<base64-encoded-node>"
  },
  "id": 4
}

// Response
{
  "jsonrpc": "2.0",
  "result": {
    "accepted": true,
    "hash": "stu901..."
  },
  "id": 4
}
```

#### Export Forum

```json
// Request
{
  "jsonrpc": "2.0",
  "method": "forum.export",
  "params": {
    "forum_hash": "abc123...",
    "page": 0,
    "page_size": 100
  },
  "id": 5
}

// Response
{
  "jsonrpc": "2.0",
  "result": {
    "forum_hash": "abc123...",
    "nodes": [{"hash": "...", "data": "..."}],
    "total_nodes": 150,
    "has_more": true
  },
  "id": 5
}
```

#### Health Check

```json
// Request
{"jsonrpc": "2.0", "method": "relay.health", "params": {}, "id": 1}

// Response
{
  "jsonrpc": "2.0",
  "result": {"status": "ok"},
  "id": 1
}
```

#### Server Stats

```json
// Request
{"jsonrpc": "2.0", "method": "relay.stats", "params": {}, "id": 1}

// Response
{
  "jsonrpc": "2.0",
  "result": {
    "registered_users": 10,
    "pending_messages": 5,
    "total_forums": 3,
    "total_nodes": 150
  },
  "id": 1
}
```

### Error Codes

| Code   | Meaning            |
| ------ | ------------------ |
| -32700 | Parse error        |
| -32600 | Invalid request    |
| -32601 | Method not found   |
| -32602 | Invalid params     |
| -32603 | Internal error     |
| -32001 | Not found          |
| -32002 | Validation failed  |
| -32003 | Rate limited       |
| -32004 | Resource exhausted |

### Batching

- Sync responses limited to 500 nodes per batch (configurable, default 100)
- Fetch requests limited to 1,000 nodes per batch
- `has_more` flag indicates additional data available

## Storage

```
pqpgp_relay_data/
└── forum_db/                    # RocksDB database
    ├── Column: nodes            # {forum_hash}:{node_hash} → DagNode
    ├── Column: forums           # {forum_hash} → ForumMetadata
    └── Column: meta             # forum_list → [forum_hashes]
```

## Resource Limits

| Resource                         | Limit                   |
| -------------------------------- | ----------------------- |
| Maximum forums                   | 10,000                  |
| Maximum nodes per forum          | 1,000,000               |
| Maximum message size             | 1 MB                    |
| Maximum queued messages per user | 1,000                   |
| Sync batch size                  | 500 nodes (default 100) |
| Fetch batch size                 | 1,000 nodes             |

## Rate Limiting

The relay implements token bucket rate limiting:

| Operation Type | Limit              |
| -------------- | ------------------ |
| All operations | 20 requests/second |

Rate limits are per-IP address.

## Running Multiple Relays

### Primary Relay

```bash
# Start primary relay
pqpgp-relay --bind 0.0.0.0:3001
```

### Mirror Relay

```bash
# Start mirror that syncs from primary
pqpgp-relay --bind 0.0.0.0:3002 --peers http://primary:3001
```

### Selective Sync

```bash
# Sync only specific forums
pqpgp-relay --bind 0.0.0.0:3002 \
  --peers http://primary:3001 \
  --sync-forums abc123...,def456...
```

## Environment Variables

| Variable           | Description    | Default            |
| ------------------ | -------------- | ------------------ |
| `RUST_LOG`         | Logging level  | `pqpgp_relay=info` |
| `PQPGP_RELAY_DATA` | Data directory | `pqpgp_relay_data` |

## Module Structure

```
bin/relay/src/
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
├── forum/               # Forum DAG storage module
│   ├── mod.rs           # Module exports
│   ├── state.rs         # In-memory forum state
│   └── persistence.rs   # RocksDB storage layer
├── peer_sync.rs         # Relay-to-relay synchronization (uses RPC)
└── rate_limit.rs        # Token bucket rate limiting
```
