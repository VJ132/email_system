# Architecture

## Overview

`email_system` is an experimental email-system project whose transport foundation is a hybrid cryptographic protocol over TCP. The design separates long-term peer identity from per-connection key-establishment material, derives independent traffic keys for each direction, and protects application data in encrypted fragments.

The email application is intended to build on top of this transport. Mailbox management, message storage, message submission and delivery, retrieval, and the user-facing client belong to the application layer.

## High-level components

```text
+---------------------------+               +---------------------------+
|           Client          |               |           Server          |
|                           |               |                           |
| Persistent ML-DSA identity|               | Persistent ML-DSA identity|
| Ephemeral ML-KEM-768 pair |               | Ephemeral ML-KEM-768 pair |
| Ephemeral X25519 pair     |               | Ephemeral X25519 pair     |
|                           |               |                           |
| Identity / handshake      |<---- TCP ---->| Identity / handshake      |
| HKDF key schedule         |               | HKDF key schedule         |
| AES-GCM record layer      |<---- TCP ---->| AES-GCM record layer      |
+---------------------------+               +---------------------------+
```

## Cryptographic responsibilities

| Component | Responsibility |
|---|---|
| ML-DSA-65 | Long-term signing identity for each peer; authenticates exchanged KEM public keys and handshake values |
| ML-KEM-768 | Two key-encapsulation exchanges, one initiated by each peer |
| X25519 | Ephemeral classical Diffie–Hellman contribution |
| HKDF-SHA3-256 | Derives the 32-byte traffic key for each direction |
| HKDF-SHA3-512 | Derives the 64-byte initial AAD-counter value for each direction |
| AES-256-GCM | Encrypts and authenticates each data fragment |
| `asyncio` streams | Provides the TCP byte stream and exact-length reads |

The ML-DSA identity keys are persistent. The ML-KEM-768 and X25519 key pairs are generated for a connection when each peer enters the handshake.

## Connection flow

The detailed message sequence and key derivation are specified in [CRYPTOGRAPHIC_HANDSHAKE.md](CRYPTOGRAPHIC_HANDSHAKE.md). At a high level:

1. The client checks whether it has a pinned server ML-DSA public key. When it does not, it requests the server's public key and stores it for subsequent connections.
2. The client presents its identity token or registers its ML-DSA public key.
3. The server resolves the client's ML-DSA public key using the identity token, or registers the public key for a new client.
4. The peers exchange ML-KEM-768 public keys, with each public key authenticated by the sender's ML-DSA identity key.
5. The server encapsulates to the client's ML-KEM public key and sends the ciphertext, its X25519 public key and its salt in a signed handshake message.
6. The client encapsulates to the server's ML-KEM public key and sends the ciphertext, its X25519 public key and its salt in a signed handshake message.
7. Both peers calculate the X25519 shared secret, obtain the two ML-KEM shared secrets and derive directional traffic keys and AAD-counter seeds.

## Directional key model

The two endpoints derive matching material for each traffic direction:

| Traffic direction | Key used by sender | Matching key used by receiver |
|---|---|---|
| Client → Server | Client sending key | Server receiving key |
| Server → Client | Server sending key | Client receiving key |

The directional AAD-counter seeds follow the same pairing. The exact HKDF salts, context strings, input keying material and output lengths are documented in [CRYPTOGRAPHIC_HANDSHAKE.md](CRYPTOGRAPHIC_HANDSHAKE.md).

## Record flow

The transport carries encrypted fragments over the established TCP stream. A fragment consists of a three-byte length field, a 12-byte nonce, AES-GCM ciphertext and a 16-byte authentication tag. A three-byte zero-length header marks the end of the current message in the current framing design.

The client splits outgoing messages into fragments. The receiving side reads the declared frame body, decrypts each fragment, and concatenates fragment plaintext until it reaches the message-end marker.

See [RECORD_LAYER.md](RECORD_LAYER.md) for the wire layout and counter handling.

## Identity storage

- The client stores the server's ML-DSA public key after first-use enrollment.
- The client stores its own ML-DSA private identity key and its assigned identity token.
- The server stores client ML-DSA public keys under identity-token-derived directories and maintains an in-memory lookup cache.
- ML-KEM and X25519 key pairs are connection-scoped key-establishment material.

## Application layer

The transport is intended to carry email-system application messages. The application layer can define its own message types and serialization for account operations, mailbox operations, message submission, delivery and retrieval. Those application semantics should remain separate from the cryptographic handshake and transport record format.
