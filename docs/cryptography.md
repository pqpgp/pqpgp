# Post-Quantum PGP

PQPGP is a post-quantum secure implementation of PGP (Pretty Good Privacy) in Rust. It provides quantum-resistant cryptographic operations while maintaining compatibility with standard PGP workflows and packet formats.

## Cryptographic Algorithms

| Operation            | Algorithm     | NIST Standard | Key Size    |
| -------------------- | ------------- | ------------- | ----------- |
| Key Encapsulation    | ML-KEM-1024   | FIPS 203      | 1,568 bytes |
| Digital Signatures   | ML-DSA-87     | FIPS 204      | 2,592 bytes |
| Symmetric Encryption | AES-256-GCM   | FIPS 197      | 32 bytes    |
| Key Derivation       | HKDF-SHA3-512 | RFC 5869      | Variable    |
| Hashing              | SHA3-512      | FIPS 202      | 64 bytes    |
| Password Hashing     | Argon2id      | RFC 9106      | 32 bytes    |

### Why These Algorithms?

**ML-KEM-1024** (formerly Kyber): NIST's primary post-quantum key encapsulation mechanism. The 1024 variant provides security equivalent to AES-256 against quantum attacks.

**ML-DSA-87** (formerly Dilithium): NIST's primary post-quantum signature scheme. The 87 variant provides security equivalent to SHA3-512 against quantum attacks.

**AES-256-GCM**: Battle-tested symmetric encryption with authentication. Quantum computers only halve the effective security (Grover's algorithm), so 256-bit remains secure.

**SHA3-512**: Quantum-resistant hash function. Part of the SHA-3 family, resistant to length extension attacks.

## Key Generation

### Encryption Keys (ML-KEM-1024)

```rust
use pqpgp::crypto::KeyPair;

// Generate encryption keypair
let keypair = KeyPair::generate_mlkem1024()?;

// Access keys
let public_key = keypair.public_key();   // 1,568 bytes
let private_key = keypair.private_key(); // 3,168 bytes
```

### Signing Keys (ML-DSA-87)

```rust
// Generate signing keypair
let keypair = KeyPair::generate_mldsa87()?;

// Access keys
let public_key = keypair.public_key();   // 2,592 bytes
let private_key = keypair.private_key(); // 4,896 bytes
```

### Hybrid Keys

For typical PGP usage, generate both:

```rust
let (enc_keypair, sign_keypair) = KeyPair::generate_hybrid()?;
```

## Encryption

PQPGP uses ML-KEM for key encapsulation combined with AES-256-GCM for symmetric encryption:

```
┌─────────────────────────────────────────────────────────────┐
│                    Encryption Flow                          │
├─────────────────────────────────────────────────────────────┤
│  1. Generate random shared secret via ML-KEM encapsulation  │
│  2. Derive AES-256 key using HKDF-SHA3-512                  │
│  3. Generate random 12-byte nonce                           │
│  4. Encrypt plaintext with AES-256-GCM                      │
│  5. Output: KEM ciphertext + nonce + AES ciphertext + tag   │
└─────────────────────────────────────────────────────────────┘
```

### Usage

```rust
use pqpgp::crypto::{encrypt_message, decrypt_message};

// Encrypt
let ciphertext = encrypt_message(recipient_public_key, plaintext.as_bytes())?;

// Decrypt
let plaintext = decrypt_message(recipient_private_key, &ciphertext, password)?;
```

### Security Properties

- **Random nonces**: Fresh 12-byte nonce per encryption (no nonce reuse)
- **Authenticated encryption**: AES-GCM provides integrity and authenticity
- **Key encapsulation**: Each message uses a unique symmetric key
- **Forward secrecy**: Compromising long-term keys doesn't reveal past messages (when used with ephemeral keys)

## Digital Signatures

PQPGP uses ML-DSA-87 for post-quantum signatures:

```
┌─────────────────────────────────────────────────────────────┐
│                    Signature Flow                           │
├─────────────────────────────────────────────────────────────┤
│  1. Hash message with SHA3-512                              │
│  2. Sign hash with ML-DSA-87 private key                    │
│  3. Output: 4,627-byte signature                            │
│                                                             │
│  Verification:                                              │
│  1. Hash message with SHA3-512                              │
│  2. Verify signature against hash using public key          │
└─────────────────────────────────────────────────────────────┘
```

### Usage

```rust
use pqpgp::crypto::{sign_message, verify_signature};

// Sign
let signature = sign_message(private_key, message.as_bytes(), password)?;

// Verify
verify_signature(public_key, message.as_bytes(), &signature)?;
```

## Password Protection

Private keys can be encrypted with a password using Argon2id + AES-256-GCM:

```
┌─────────────────────────────────────────────────────────────┐
│                Password Protection Flow                     │
├─────────────────────────────────────────────────────────────┤
│  1. Generate random 16-byte salt                            │
│  2. Derive 32-byte key using Argon2id:                      │
│     • Memory: 19 MB                                         │
│     • Iterations: 2                                         │
│     • Parallelism: 1                                        │
│  3. Generate random 12-byte nonce                           │
│  4. Encrypt private key with AES-256-GCM                    │
│  5. Store: salt + nonce + ciphertext + tag                  │
└─────────────────────────────────────────────────────────────┘
```

### Usage

```rust
use pqpgp::crypto::Password;

let password = Password::new("secure_password".to_string());

// Encrypt private key
keypair.private_key_mut().encrypt_with_password(&password)?;

// Use encrypted key (password required for operations)
let signature = sign_message(keypair.private_key(), message, Some(&password))?;
```

### Security Properties

- **Memory-hard**: Argon2id resists GPU/ASIC attacks
- **Unique salts**: Each encryption uses random salt
- **No password storage**: Password never stored, only used for derivation
- **Secure parameters**: 19MB memory makes brute force expensive

## ASCII Armor

PQPGP supports PGP-style ASCII armor for text-safe transport:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGVxample...base64 encoded data...
=ABC1
-----END PGP PUBLIC KEY BLOCK-----
```

### Supported Types

- `PGP PUBLIC KEY BLOCK` - Public keys
- `PGP PRIVATE KEY BLOCK` - Private keys
- `PGP MESSAGE` - Encrypted messages
- `PGP SIGNATURE` - Detached signatures
- `PGP SIGNED MESSAGE` - Cleartext signed messages

### Usage

```rust
use pqpgp::armor::{armor_encode, armor_decode, ArmorType};

// Encode
let armored = armor_encode(ArmorType::PublicKey, &key_bytes)?;

// Decode
let (armor_type, decoded) = armor_decode(&armored)?;
```

### Signed Messages

```rust
use pqpgp::armor::{create_signed_message, parse_signed_message};

// Create cleartext signed message
let signed = create_signed_message(message, &signature_bytes)?;

// Parse and extract
let (original_message, signature_bytes) = parse_signed_message(&signed)?;
```

## Packet Format

PQPGP uses PGP-compatible packet format (RFC 4880) with new algorithm identifiers:

### Packet Types

| Tag | Type                             | Description                 |
| --- | -------------------------------- | --------------------------- |
| 1   | Public-Key Encrypted Session Key | ML-KEM encapsulated key     |
| 2   | Signature                        | ML-DSA-87 signature         |
| 5   | Secret Key                       | Encrypted private key       |
| 6   | Public Key                       | ML-KEM or ML-DSA public key |
| 9   | Symmetrically Encrypted Data     | AES-256-GCM ciphertext      |
| 13  | User ID                          | Identity string             |

### Algorithm IDs

| ID  | Algorithm   |
| --- | ----------- |
| 100 | ML-KEM-1024 |
| 101 | ML-DSA-87   |
| 7   | AES-256     |

## Keyring Management

PQPGP provides a keyring system for managing multiple keys:

```rust
use pqpgp::keyring::{PublicKeyring, PrivateKeyring};

// Public keyring
let mut public_ring = PublicKeyring::new();
public_ring.add_key(key_entry)?;
let key = public_ring.get_by_fingerprint(&fingerprint)?;
let keys = public_ring.search_by_user_id("alice@example.com")?;

// Private keyring (password protected)
let mut private_ring = PrivateKeyring::new();
private_ring.add_key(key_entry)?;
```

### Key Fingerprints

Keys are identified by their SHA3-512 fingerprint (truncated to 20 bytes for display):

```rust
let fingerprint = public_key.fingerprint();
// "A1B2C3D4E5F60708..."
```

## Sign-Then-Encrypt Workflow

Traditional PGP workflow for authenticated, confidential messages:

```rust
use pqpgp::crypto::{sign_message, encrypt_message, decrypt_message, verify_signature};
use pqpgp::armor::{create_signed_message, parse_signed_message};

// Sender: Sign then encrypt
let signature = sign_message(sender_sign_key, message.as_bytes(), password)?;
let signed_message = create_signed_message(message, &signature)?;
let encrypted = encrypt_message(recipient_enc_key, signed_message.as_bytes())?;

// Recipient: Decrypt then verify
let decrypted = decrypt_message(recipient_enc_key, &encrypted, password)?;
let (original, sig_bytes) = parse_signed_message(&String::from_utf8(decrypted)?)?;
verify_signature(sender_sign_key, original.as_bytes(), &signature)?;
```

## Command Line Interface

```bash
# Generate keys
pqpgp generate-key mlkem1024 "Alice <alice@example.com>"
pqpgp generate-key mldsa87 "Alice <alice@example.com>" --password

# List keys
pqpgp list-keys

# Encrypt/Decrypt
pqpgp encrypt alice@example.com message.txt message.pgp
pqpgp decrypt message.pgp decrypted.txt

# Sign/Verify
pqpgp sign A1B2C3D4 document.txt document.sig
pqpgp verify document.txt document.sig

# Import/Export
pqpgp import keys.asc
pqpgp export alice@example.com alice_public.asc
```

## Security Considerations

### Quantum Threat

Current estimates suggest quantum computers capable of breaking RSA/ECDSA may emerge in 10-30 years. PQPGP provides:

- **Immediate protection**: Deploy quantum-resistant crypto today
- **Harvest-now-decrypt-later defense**: Data encrypted today remains safe
- **Smooth migration**: PGP-compatible format for gradual adoption

### Key Sizes

Post-quantum keys are larger than classical keys:

| Key Type             | Public  | Private | Signature |
| -------------------- | ------- | ------- | --------- |
| ML-KEM-1024          | 1,568 B | 3,168 B | N/A       |
| ML-DSA-87            | 2,592 B | 4,896 B | 4,627 B   |
| RSA-2048 (classical) | 256 B   | 1,190 B | 256 B     |
| Ed25519 (classical)  | 32 B    | 64 B    | 64 B      |

The increased size is the cost of quantum resistance.

### Timing Attacks

PQPGP implements constant-time operations for sensitive comparisons:

```rust
use pqpgp::crypto::timing::{constant_time_eq, TimingSafeError};

// Constant-time comparison
if constant_time_eq(provided_mac, expected_mac) {
    // Valid
}
```

### Input Validation

All inputs are validated before processing:

- Key size verification
- Algorithm ID whitelist
- Message size limits
- UTF-8 validation
- Rate limiting

## Module Structure

```
src/
├── crypto/
│   ├── keys.rs        # Key generation (ML-KEM, ML-DSA)
│   ├── encryption.rs  # Encrypt/decrypt (ML-KEM + AES-GCM)
│   ├── signature.rs   # Sign/verify (ML-DSA-87)
│   ├── password.rs    # Argon2id password protection
│   └── timing.rs      # Constant-time operations
├── armor/
│   └── mod.rs         # ASCII armor encoding/decoding
├── packet/
│   └── mod.rs         # PGP packet format
├── keyring/
│   └── mod.rs         # Key storage and management
├── validation/
│   └── mod.rs         # Input validation and rate limiting
└── lib.rs             # Public API
```

## Standards Compliance

- **RFC 4880**: OpenPGP Message Format (packet structure)
- **RFC 5869**: HKDF key derivation
- **RFC 9106**: Argon2 password hashing
- **NIST FIPS 203**: ML-KEM specification
- **NIST FIPS 204**: ML-DSA specification
- **NIST FIPS 197**: AES specification
- **NIST FIPS 202**: SHA-3 specification
