# Cryptographic Handshake

## Purpose

The handshake establishes authenticated peer identities and derives independent symmetric traffic material for the two directions of a TCP connection. It combines ML-KEM-768, X25519 and ML-DSA-65, with HKDF-SHA3 used for key derivation.

## Algorithms and sizes

| Value | Size |
|---|---:|
| ML-DSA-65 public key | 1,952 bytes |
| ML-DSA-65 signature | 3,309 bytes |
| ML-KEM-768 public key | 1,184 bytes |
| ML-KEM-768 ciphertext | 1,088 bytes |
| ML-KEM shared secret | 32 bytes |
| X25519 public key | 32 bytes |
| X25519 shared secret | 32 bytes |
| Per-peer salt | 16 bytes |
| Client identity token | 64 bytes |

## Long-term identities

Each peer has a persistent ML-DSA-65 identity key pair. The public key is used to verify signatures on identity and handshake messages.

### Server identity enrollment

1. The client checks whether it has a locally stored server ML-DSA-65 public key.
2. The client sends a one-byte status: `0x00` when the key is already stored, or `0x01` when it needs the server's public key.
3. When requested, the server sends its 1,952-byte ML-DSA-65 public key.
4. The client constructs the public-key object and stores the key for later connections.

This is a trust-on-first-use (TOFU) model: the first server key received is the key pinned by the client for later connections.

### Client identity enrollment and lookup

The client sends a one-byte status:

- `0x01`: the client has an identity token and sends the 64-byte token.
- `0x00`: the client has no token and sends its 1,952-byte ML-DSA-65 public key.

For a new client identity, the server creates a 64-byte token using:

```text
identity_token = SHA3-512(client_mldsa_public_key_bytes || random_64_bytes)
```

The server returns the token followed by an ML-DSA-65 signature over the token, using the context string:

```text
SERVER ASSIGNED IDENTITY TOKEN
```

The server stores the client's ML-DSA public key under the identity token. On subsequent connections, the token allows the server to retrieve the corresponding public key. The client's later handshake signatures prove possession of the private key associated with that registered public key.

## ML-KEM public-key exchange

The peers exchange their ephemeral ML-KEM-768 public keys before encapsulation.

1. The client sends its 1,184-byte ML-KEM-768 public key and an ML-DSA-65 signature over that public key. The signature context is `CLIENT MLKEM768PublicKey`.
2. The server verifies the signature using the client's registered ML-DSA public key.
3. The server sends its 1,184-byte ML-KEM-768 public key and an ML-DSA-65 signature over that public key. The signature context is `SERVER MLKEM768PublicKey`.
4. The client verifies the signature using the pinned server ML-DSA public key.

## Two ML-KEM encapsulations and X25519

Each peer encapsulates to the other peer's ML-KEM public key. This produces two independent ML-KEM shared secrets.

### Server contribution

1. The server encapsulates to the client's ML-KEM public key, producing the server-side ML-KEM shared secret and a 1,088-byte ciphertext.
2. The server creates a fresh ephemeral X25519 key pair and a 16-byte server salt.
3. It sends the following signed payload:

```text
server_mlkem_ciphertext (1088 bytes)
|| server_x25519_public_key (32 bytes)
|| server_salt (16 bytes)
```

The signature context is `SERVER HANDSHAKE VALUES`.

4. The client verifies the signature, decapsulates the ML-KEM ciphertext using its ephemeral ML-KEM private key, and calculates the X25519 shared secret using its ephemeral X25519 private key and the server's public key.

### Client contribution

1. The client encapsulates to the server's ML-KEM public key, producing the client-side ML-KEM shared secret and a 1,088-byte ciphertext.
2. The client creates a fresh ephemeral X25519 key pair and a 16-byte client salt.
3. It sends the following signed payload:

```text
client_mlkem_ciphertext (1088 bytes)
|| client_x25519_public_key (32 bytes)
|| client_salt (16 bytes)
```

The signature context is `CLIENT HANDSHAKE VALUES`.

4. The server verifies the signature, decapsulates the ML-KEM ciphertext using its ephemeral ML-KEM private key, and calculates the same X25519 shared secret using its ephemeral X25519 private key and the client's public key.

## Directional traffic-key derivation

Let:

- `S_client` be the ML-KEM shared secret produced when the client encapsulates to the server's ML-KEM public key.
- `S_server` be the ML-KEM shared secret produced when the server encapsulates to the client's ML-KEM public key.
- `Z` be the X25519 shared secret.
- `salt_client` be the client-generated 16-byte salt.
- `salt_server` be the server-generated 16-byte salt.

The client-to-server traffic key is:

```text
K_client_to_server = HKDF-SHA3-256(
    IKM  = S_client || Z,
    salt = salt_client,
    info = "CLIENT KEY",
    L    = 32 bytes
)
```

The server-to-client traffic key is:

```text
K_server_to_client = HKDF-SHA3-256(
    IKM  = S_server || Z,
    salt = salt_server,
    info = "SERVER KEY",
    L    = 32 bytes
)
```

The client uses `K_client_to_server` for sending and `K_server_to_client` for receiving. The server uses `K_server_to_client` for sending and `K_client_to_server` for receiving.

## Directional AAD-counter derivation

Each traffic direction has a separate 64-byte initial AAD-counter value derived from that direction's traffic key.

```text
C_client_to_server = HKDF-SHA3-512(
    IKM  = K_client_to_server,
    salt = salt_client || salt_server,
    info = "CLIENT AAD COUNTER",
    L    = 64 bytes
)
```

```text
C_server_to_client = HKDF-SHA3-512(
    IKM  = K_server_to_client,
    salt = salt_server || salt_client,
    info = "SERVER AAD COUNTER",
    L    = 64 bytes
)
```

The directional pairing is:

| Direction | Sender's initial counter | Receiver's matching initial counter |
|---|---|---|
| Client → Server | Client sending counter | Server receiving counter |
| Server → Client | Server sending counter | Client receiving counter |

For each encrypted data fragment, the current 64-byte counter value is supplied as AES-GCM additional authenticated data (AAD). The counter is interpreted as a big-endian integer and incremented for the next encrypted data fragment.

## Signature context strings

The implementation uses separate ML-DSA context strings for the signed payload types:

| Payload | Context string |
|---|---|
| Server-assigned client identity token | `SERVER ASSIGNED IDENTITY TOKEN` |
| Client ML-KEM public key | `CLIENT MLKEM768PublicKey` |
| Server ML-KEM public key | `SERVER MLKEM768PublicKey` |
| Server handshake values | `SERVER HANDSHAKE VALUES` |
| Client handshake values | `CLIENT HANDSHAKE VALUES` |

The context string is part of the signature operation and must match between signing and verification.
