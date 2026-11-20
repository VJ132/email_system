# Threat Model and Security Scope

## Purpose

This document describes the intended security scope of the experimental `email_system` transport design. It identifies the data being protected, the network setting, the trust model and the boundaries of the project. It is a design overview, not a formal security proof or independent audit.

## Assets

The transport is designed to protect or manage:

- Application payload bytes while they travel between the client and server.
- The persistent ML-DSA-65 identity private keys of the peers.
- Per-connection ML-KEM-768 and X25519 key-establishment material.
- Directional AES-GCM traffic keys and AAD-counter state.
- The association between a client identity token and its ML-DSA public key.

## Network setting

The protocol operates over TCP and is intended to communicate across a network where traffic may be observed or modified by parties between the endpoints. The cryptographic design uses signed handshake values, hybrid key establishment and authenticated encryption for transport fragments.

## Trust model

### Peer identities

Each peer has a persistent ML-DSA-65 signing identity. The peer's public key is used to verify the signatures associated with identity registration and handshake values.

### Server first-use pinning

The client stores the server's ML-DSA public key after the first-use exchange. Later connections use the stored key as the server identity key. This is a trust-on-first-use model; the initial key enrollment is the point at which the client establishes which server key it will subsequently trust.

### Client identity registration

The server associates a 64-byte identity token with a client's ML-DSA public key. On later connections, the token identifies the registered public key, and ML-DSA signatures provide proof of possession of the corresponding private key during the handshake.

### Endpoint assumptions

The design assumes that the client and server endpoints, their operating systems, the Python runtime and the underlying cryptographic library are trusted. Endpoint compromise is outside the protection provided by transport encryption because an endpoint processes plaintext and holds the keys needed for its connection.

## Intended security properties

The design aims to provide:

- Peer authentication based on persistent ML-DSA-65 identity keys.
- A post-quantum key-establishment contribution using ML-KEM-768.
- A classical ephemeral key-establishment contribution using X25519.
- Separate symmetric traffic keys for the two communication directions.
- Confidentiality and integrity for encrypted transport fragments using AES-256-GCM.

These are the goals of the construction. The security of the complete protocol depends on the composition of its algorithms, message flow, state management and implementation. The use of standardized primitives alone is not a proof of protocol security.

## Security boundaries

The transport design concerns data while it is moving between connected endpoints. It does not, by itself, define:

- Protection for messages after delivery to an endpoint.
- Encryption of stored mail or mailbox databases.
- End-to-end encryption between email users through intermediary mail servers.
- Protection against a compromised client, server, operating system or cryptographic library.
- Hiding communication metadata such as network addresses, traffic timing or message sizes.
- Availability against denial-of-service attacks.

Those properties require additional application, storage, operational and protocol design.

## Project status

`email_system` is an experimental engineering project. Its cryptographic design and implementation should be reviewed and tested before it is used for sensitive communication or described as a production-ready secure transport protocol. It is not presented as a replacement for TLS or as a formally verified protocol.
