# email_system

An independently developed experimental email-system project with a custom hybrid post-quantum/classical encrypted transport prototype.

> **Status:** Experimental. The implementation is intended for cryptographic engineering and protocol experimentation. It has not been formally verified or independently security-audited and should not be used as a production secure transport or as a replacement for TLS.

## Current scope

The current source demonstrates an asynchronous TCP connection, peer identity handling, a hybrid key-establishment handshake, directional key derivation, and bidirectional encrypted record exchange. The supplied client sends a fragmented test payload. The server receives it and sends a separate fragmented test response. The receive loops assemble messages and report their frame count and payload length.

This is not yet a complete email application. Mailboxes, account management, message storage, message submission/delivery, retrieval, and a user-facing mail client are application-layer work that sits above the transport.

## Cryptographic components

| Component | Role |
|---|---|
| ML-KEM-768 | Post-quantum key encapsulation; one independent shared secret is established in each direction |
| X25519 | Ephemeral classical Diffie–Hellman contribution shared by both directions |
| ML-DSA-65 | Persistent signing identity used to authenticate handshake messages |
| HKDF-SHA3-256 | Derives directional 32-byte AES-GCM traffic keys |
| HKDF-SHA3-512 | Derives directional HMAC keys and 64-byte initial counters |
| AES-256-GCM | Encrypts and authenticates each data-frame payload |
| HMAC-SHA3-256 | Authenticates the frame header together with its sequence counter |

The client-to-server and server-to-client paths use separate AES keys, HMAC keys, and counters. The directional key schedule is described in [CRYPTOGRAPHIC_HANDSHAKE.md](docs/CRYPTOGRAPHIC_HANDSHAKE.md).

## Connection flow

1. The client loads or bootstraps the server's ML-DSA-65 public key using Trust On First Use (TOFU).
2. The client authenticates with its existing identity token or registers its ML-DSA-65 public key.
3. The client and server exchange ML-KEM-768 public keys, each signed by the sender's ML-DSA identity.
4. The server encapsulates to the client's ML-KEM public key and sends the ciphertext, its ephemeral X25519 public key, a 16-byte salt, and an ML-DSA signature.
5. The client decapsulates the ciphertext, computes the X25519 shared secret, then encapsulates to the server's ML-KEM public key and sends its corresponding signed values.
6. The server decapsulates the client ciphertext and computes the same X25519 shared secret.
7. Both endpoints derive matching directional AES keys, HMAC keys, and initial counters with HKDF.
8. Data is fragmented into frames protected by AES-256-GCM, with HMAC authentication for each frame header and counter.

See [CRYPTOGRAPHIC_HANDSHAKE.md](docs/CRYPTOGRAPHIC_HANDSHAKE.md) and [RECORD_LAYER.md](docs/RECORD_LAYER.md) for the protocol details.

## Protocol diagram

The editable architecture and protocol-flow diagram is [email_system_protocol.excalidraw](diagrams/email_system_protocol.excalidraw). Open it at [Excalidraw](https://excalidraw.com) using **Open** or **Load**.

## Repository documentation

- [Architecture](docs/ARCHITECTURE.md) — endpoints, identity state, connection lifecycle, and present application scope.
- [Cryptographic handshake](docs/CRYPTOGRAPHIC_HANDSHAKE.md) — identity registration, signed handshake payloads, KEM roles, X25519, and exact HKDF derivations.
- [Record layer](docs/RECORD_LAYER.md) — wire format, counters, HMAC, AES-GCM, fragmentation, and terminators.
- [Threat model](docs/THREAT_MODEL.md) — assets, assumptions, trust boundaries, protections, and limitations.
- [Implementation status](docs/IMPLEMENTATION_STATUS.md) — source-visible behavior and remaining engineering work.

## Development environment

The code is Python and uses `asyncio` TCP streams and the `cryptography` package. The installed `cryptography` release must expose the ML-KEM and ML-DSA APIs imported by `src/crypto/helpers.py`:

```python
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa, x25519
```

Install or upgrade the dependency in a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade cryptography
```

The endpoint scripts currently derive their key-directory paths relative to their own source files. Ensure the expected `keys/` directory structure exists and is writable before running the endpoints. The server listens on `localhost:6969` using IPv6; start it before launching the client.

## Security note

The use of standardized cryptographic primitives does not by itself establish the security of a protocol composed from them. The handshake, identity bootstrap, key schedule, record state machine, nonce lifecycle, and operational key storage all require careful review. Do not use this prototype to protect real email or other sensitive traffic.
