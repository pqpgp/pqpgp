# Relay Server

The PQPGP relay server provides message routing, forum hosting, and peer-to-peer synchronization for decentralized communication.

## Features

- **Message Relay**: Routes encrypted messages between users
- **Forum Hosting**: Stores and serves DAG-based forum data
- **Peer Sync**: Synchronizes forum data from other relays
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
│  Relay A    │ <────── │  Relay B    │ <────── │  Relay C    │
│ (primary)   │  pull   │ (mirror)    │  pull   │ (new)       │
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

## API Endpoints

### Messaging

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/register` | POST | Register user with prekey bundle |
| `/register/:fingerprint` | DELETE | Unregister user |
| `/users` | GET | List all registered users |
| `/users/:fingerprint` | GET | Get user's prekey bundle |
| `/messages/:fingerprint` | POST | Send message to recipient |
| `/messages/:fingerprint` | GET | Fetch messages for recipient |
| `/messages/:fingerprint/check` | GET | Check pending message count |
| `/health` | GET | Health check |
| `/stats` | GET | Server statistics |

### Forums

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/forums` | GET | List all forums |
| `/forums` | POST | Create a new forum |
| `/forums/stats` | GET | Forum statistics |
| `/forums/sync` | POST | Sync request (get missing hashes) |
| `/forums/nodes/fetch` | POST | Fetch nodes by hash |
| `/forums/nodes/submit` | POST | Submit a new node |
| `/forums/:hash` | GET | Get forum details |
| `/forums/:hash/export` | GET | Export entire forum DAG |
| `/forums/:hash/boards` | GET | List boards in forum |
| `/forums/:hash/moderators` | GET | List forum moderators |
| `/forums/:fh/boards/:bh/moderators` | GET | List board moderators |
| `/forums/:fh/boards/:bh/threads` | GET | List threads in board |
| `/forums/:fh/threads/:th/posts` | GET | List posts in thread |

## Sync Protocol

The relay uses the same sync protocol as clients:

```
1. Requester → Relay:  SyncRequest { forum_hash, known_heads: [...] }
2. Relay → Requester:  SyncResponse { missing_hashes: [...], server_heads: [...] }
3. Requester → Relay:  FetchNodesRequest { hashes: [...] }
4. Relay → Requester:  FetchNodesResponse { nodes: [...] }
```

### Batching

- Sync responses limited to 10,000 missing hashes
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

| Resource | Limit |
|----------|-------|
| Maximum forums | 10,000 |
| Maximum nodes per forum | 1,000,000 |
| Maximum message size | 1 MB |
| Maximum queued messages per user | 1,000 |
| Sync batch size | 10,000 hashes |
| Fetch batch size | 1,000 nodes |

## Rate Limiting

The relay implements token bucket rate limiting:

| Operation Type | Limit |
|----------------|-------|
| Read operations | 100 requests/second |
| Write operations | 20 requests/second |

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

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Logging level | `pqpgp_relay=info` |
| `PQPGP_RELAY_DATA` | Data directory | `pqpgp_relay_data` |

## Module Structure

```
bin/relay/src/
├── main.rs              # Server entry point, routing
├── forum_handlers.rs    # Forum API handlers
├── forum_persistence.rs # RocksDB storage layer
├── forum_state.rs       # In-memory forum state
├── peer_sync.rs         # Relay-to-relay synchronization
└── rate_limit.rs        # Token bucket rate limiting
```
