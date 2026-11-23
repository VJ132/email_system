# Architecture

## 1. Scope

The repository currently contains an experimental encrypted transport prototype for a future email system. Its current executable path is a localhost client/server demonstration over asynchronous TCP. It establishes peer identities, derives hybrid session keys, and exchanges framed encrypted data in both directions.

It is not yet an email service: the current server does not store mail, route messages, manage inboxes, or expose an email application protocol. It receives a test payload, reports its frame count and assembled length, and sends a fixed test response.

## 2. Components

### Client

`src/client/transport/main.py` is responsible for:

- Loading its persistent ML-DSA-65 identity and optional identity token.
- Loading or bootstrapping the server's ML-DSA-65 public key.
- Registering its public identity on first use or presenting its 64-byte identity token on later connections.
- Generating an ephemeral ML-KEM-768 keypair and X25519 keypair for the handshake.
- Verifying server signatures and deriving directional session material.
- Fragmenting outbound data, encrypting each fragment, and authenticating each header.
- Receiving, authenticating, decrypting, and assembling server messages.

The current client opens an IPv6 TCP connection to `localhost:6969`, sends one test payload of `MAX_DATA_BYTES_PER_FRAME + 1` bytes, then continuously receives logical messages.

### Server

`src/server/transport/main.py` is responsible for:

- Loading its persistent ML-DSA-65 identity.
- Sending its public identity key when the client has no stored pin.
- Registering client public identities or resolving a previously assigned identity token.
- Verifying client-signed handshake values.
- Generating ephemeral ML-KEM-768 and X25519 keypairs for each handshake.
- Deriving the matching server-side directional session material.
- Receiving and assembling client messages.
- Sending the current fixed test response using its independent server-to-client key material.

The server uses `asyncio.start_server()` on `localhost:6969` with `AF_INET6` and runs a connection handler per accepted stream.

### Cryptographic helpers

`src/crypto/helpers.py` centralizes:

- Ephemeral ML-KEM-768 and X25519 key generation.
- Persistent ML-DSA-65 identity-key loading or generation.
- AES-256-GCM frame encryption and decryption.
- HMAC-SHA3-256 generation and verification.
- Small file read/write helpers for the current key layout.

## 3. Key lifetimes

| Material                                 | Lifetime                   | Purpose                                              |
| ---------------------------------------- | -------------------------- | ---------------------------------------------------- |
| Client ML-DSA-65 keypair                 | Persistent                 | Client handshake identity                            |
| Server ML-DSA-65 keypair                 | Persistent                 | Server handshake identity and identity-token signing |
| Client's pinned server ML-DSA public key | Persistent at client       | TOFU server identity continuity                      |
| Client identity token                    | Persistent at client       | Identifies a previously registered client key        |
| Client ML-KEM-768 keypair                | Per handshake              | Receives the server's KEM contribution               |
| Server ML-KEM-768 keypair                | Per handshake              | Receives the client's KEM contribution               |
| Client X25519 keypair                    | Per handshake              | Ephemeral classical shared-secret contribution       |
| Server X25519 keypair                    | Per handshake              | Ephemeral classical shared-secret contribution       |
| AES/HMAC keys and counters               | Per session, per direction | Protect records in each direction                    |

`fetch_self_keys()` generates fresh ML-KEM and X25519 keypairs whenever it is called. It loads the ML-DSA private seed from the local key directory or generates a persistent identity if the helper considers that seed unavailable.

## 4. Identity state

The server maps 64-byte identity tokens to client ML-DSA public keys. It maintains an in-memory `client_key_journal` and can load a client's public key from a directory named after the token's hexadecimal representation. During registration, the server creates a token from the client's public key concatenated with 64 random bytes, hashes the value with SHA3-512, signs the token using the context `SERVER ASSIGNED IDENTITY TOKEN`, and stores the public key.

The client stores the returned token in `keys/self/identity_token.key`. Subsequent handshakes send the token rather than the full identity public key.

## 5. Connection and message flow

1. The client opens an IPv6 TCP stream to `localhost:6969`.
2. The client and server perform the identity/bootstrap exchange.
3. They exchange signed ML-KEM public keys and signed handshake values.
4. They calculate two independent ML-KEM shared secrets and one common X25519 shared secret.
5. They derive matching directional key material.
6. The client sends a logical message as one or more authenticated encrypted frames followed by an authenticated terminator.
7. The server receives and assembles the logical message, then sends its current test response in the reverse direction.
8. The client receives and assembles the response. Both receive loops are structured to continue processing further logical messages on the stream.

## 6. Current test payload behavior

The client sends `b"A" * (MAX_DATA_BYTES_PER_FRAME + 1)`, which is split into two data frames because it is one byte larger than the configured maximum frame plaintext.

After receiving a complete logical message, the current server constructs and sends a separate response with the same test length and content pattern. This is a fixed test response, not an echo of arbitrary application data.

The endpoint code reports the number of data frames and assembled payload length. It does not yet pass the received payload to an email application or persist it.

## 7. Source layout

```text
email_system/
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CRYPTOGRAPHIC_HANDSHAKE.md
│   ├── IMPLEMENTATION_STATUS.md
│   ├── RECORD_LAYER.md
│   └── THREAT_MODEL.md
└── src/
    ├── client/transport/main.py
    ├── crypto/helpers.py
    └── server/transport/main.py
```

The editable protocol diagram is distributed separately as `email_system_protocol.excalidraw` and is also included in the documentation bundle under `diagrams/`.
