# email_system

An experimental email-system project built around a hybrid post-quantum transport design. The transport prototype combines ML-KEM-768, X25519, ML-DSA-65, HKDF-SHA3 and AES-256-GCM.

> **Project status:** Experimental and under active development. The protocol is a research and engineering project and has not undergone independent security review. It should not be treated as a production-ready replacement for established secure transport protocols.

## Overview

The project explores a transport layer for an email system. Its current design establishes peer identities, combines post-quantum and classical key-establishment contributions, derives independent traffic keys for each direction, and encrypts framed application data over TCP.

The email application is the broader project goal. Mailbox management, message storage, submission, delivery, retrieval and a user-facing client belong to the application layer built above the transport.

## Cryptographic components

| Component | Role |
|---|---|
| ML-KEM-768 | Post-quantum key encapsulation; each peer contributes a shared secret |
| X25519 | Ephemeral classical Diffie–Hellman contribution |
| ML-DSA-65 | Long-term signing identity and authentication of exchanged handshake values |
| HKDF-SHA3-256 | Derives the directional 32-byte AES-GCM traffic keys |
| HKDF-SHA3-512 | Derives the directional 64-byte initial AAD-counter values |
| AES-256-GCM | Encrypts and authenticates transport fragments |

The protocol uses separate keys and counter state for client-to-server and server-to-client traffic.

## High-level connection flow

1. The client obtains or reuses the server's ML-DSA-65 public identity key. The first-use flow pins the key for later connections.
2. The client presents its registered identity token or registers its ML-DSA-65 public key.
3. The peers exchange ML-KEM-768 public keys authenticated with their ML-DSA identities.
4. Each peer encapsulates to the other peer's ML-KEM public key. Each also contributes an ephemeral X25519 public key and a fresh 16-byte salt.
5. The peers verify the signed handshake values, decapsulate the ML-KEM ciphertexts, calculate the X25519 shared secret and derive directional traffic material with HKDF.
6. Application data is divided into transport fragments and protected with AES-256-GCM.

See [docs/CRYPTOGRAPHIC_HANDSHAKE.md](docs/CRYPTOGRAPHIC_HANDSHAKE.md) for the message flow and derivation details.

## Transport framing

Each encrypted fragment is carried in this format:

```text
+----------------------+------------------------------+
| Field                | Size                         |
+----------------------+------------------------------+
| Encrypted length     | 3 bytes                     |
| Nonce                | 12 bytes                    |
| Ciphertext           | Variable                    |
| Authentication tag   | 16 bytes                    |
+----------------------+------------------------------+
```

The three-byte unsigned big-endian length is the ciphertext length plus the 16-byte authentication tag. It does not include the nonce. A three-byte zero length is used as the current message-end marker.

The maximum plaintext fragment size selected by the current client is `0xFFFFFF - 16` bytes. The record-layer description is in [docs/RECORD_LAYER.md](docs/RECORD_LAYER.md).

## Repository documentation

- [Architecture](docs/ARCHITECTURE.md) — system components, connection flow and responsibilities.
- [Cryptographic handshake](docs/CRYPTOGRAPHIC_HANDSHAKE.md) — identity handling, signed messages and HKDF derivations.
- [Record layer](docs/RECORD_LAYER.md) — frame layout, fragmentation, nonces and directional counters.
- [Threat model](docs/THREAT_MODEL.md) — project scope, security goals, assumptions and trust boundaries.

## Development environment

The current implementation is written in Python and uses:

- Python 3.10 or later.
- `asyncio` TCP streams.
- The `cryptography` package with the ML-KEM and ML-DSA APIs used by the source.

Install the cryptography dependency with:

```bash
python -m pip install --upgrade cryptography
```

The source currently keeps key-directory paths in the client and server scripts. Configure those paths for the local environment before running either endpoint. Start the server before connecting with the client.

## Development direction

- Specify the handshake and record formats precisely.
- Build automated tests for key agreement, identity authentication and encrypted transport.
- Add the email application layer: accounts, mailboxes, message submission, delivery and retrieval.
- Add persistent message storage and a user-facing client.
- Document deployment and operational configuration.

## Security note

The project is experimental. The use of standardized cryptographic primitives does not by itself establish the security of a protocol built from them. Review the complete protocol design and implementation before relying on it for sensitive communication.
