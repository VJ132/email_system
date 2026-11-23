# Threat Model and Security Boundaries

## 1. Status

This is an experimental custom protocol built from standardized cryptographic primitives. It has not undergone formal verification or independent security review. The use of ML-KEM, X25519, ML-DSA, HKDF, AES-GCM, and HMAC does not by itself prove the security of the composed protocol.

## 2. Assets

The implementation is intended to protect:

- The confidentiality and integrity of application payloads sent over the TCP connection.
- The authenticity of handshake messages signed by a peer's ML-DSA identity key.
- The separation of client-to-server and server-to-client traffic keys.
- The integrity and expected order of frame metadata within a session.
- The continuity of previously pinned server identity and registered client identity state.

Long-term ML-DSA private seeds, ephemeral KEM/X25519 private keys, derived traffic keys, identity tokens, and stored public-key associations are also security-sensitive state.

## 3. Adversary capabilities considered by the design

The intended network threat model includes an attacker who can observe, delay, inject, replay, modify, truncate, or drop TCP traffic. The cryptographic design uses signatures, key encapsulation, Diffie–Hellman, HKDF, HMAC, and AEAD to authenticate handshake payloads and protect data records against these actions within the assumptions of the primitives and implementation.

The current implementation does not attempt to provide availability against an attacker who can block the network, exhaust server resources, or hold a connection open indefinitely.

## 4. Implemented mechanisms

### Hybrid key establishment

Two independent ML-KEM-768 shared secrets are established in opposite directions. A common ephemeral X25519 shared secret contributes to each directional derivation. This is intended to combine post-quantum and classical key-establishment contributions.

### Identity authentication

Persistent ML-DSA-65 keys sign the handshake's public-key and handshake-value payloads. Distinct context strings are used for the different signed message types.

### Directional key separation

HKDF derives separate AES-256-GCM keys, HMAC-SHA3-256 keys, and initial counters for each traffic direction. The client sending material matches the server receiving material, and vice versa.

### Record integrity

AES-256-GCM authenticates encrypted payloads and the counter supplied as AAD. HMAC-SHA3-256 authenticates each record header together with its directional counter. The authenticated terminator consumes a counter value.

### Frame sequence checking

The receiver advances its expected counter before checking the incoming record. A record carrying an earlier or later counter does not match the HMAC expected for the next sequence value.

## 5. Trust assumptions and limitations

### First-contact server identity

The client uses Trust On First Use (TOFU) to store the server's ML-DSA public key. On a first connection, the public key is delivered over the connection being established. Without independent fingerprint verification or trusted provisioning, an active attacker present during first contact may substitute a key. TOFU provides continuity after the first pin is stored; it does not authenticate the initial key out of band.

### Handshake transcript binding and key confirmation

The current handshake signs individual message payloads with distinct ML-DSA context strings. It does not include a transcript-bound Finished message or an explicit key-confirmation round trip. The complete ordered handshake transcript is not bound into a final confirmation value. These are important design items for a protocol intended to resist more complex handshake manipulation and state-confusion attacks.

### Nonce lifecycle

The implementation generates a random 96-bit AES-GCM nonce for each frame. AES-GCM requires nonce uniqueness under a key, but the current code does not explicitly track nonce use or derive nonces deterministically from the record counter. The operational nonce-use bound and collision strategy need to be specified.

### Counter lifecycle

The counter is 64 bytes and increments as a big-endian integer. An explicit policy is needed for exhaustion and overflow. The client currently calls `write()` once per connection; if it later supports multiple calls on one stream, the advanced send counter must be retained in connection state between calls.

### Key storage

The helper stores persistent ML-DSA private seeds and identity data in ordinary local files. The current helper does not establish a hardened key-storage boundary, atomic update policy, access-control policy, rotation scheme, or secure-erasure procedure. Deployment requires restrictive filesystem permissions and protection of the key directory.

### Resource exhaustion and connection lifecycle

The record format limits the size of one frame through its 24-bit header, but the receive loops accumulate a complete logical message without a separate aggregate size bound. Explicit frame/message limits, handshake and record read deadlines, and comprehensive failure cleanup are still needed for robust network operation.

### Application-level replay

The record counters protect sequencing within a negotiated session. They do not define idempotency or duplicate suppression for application operations submitted again in a new session. The email/application layer needs its own message identifiers and replay/duplication policy where required.

### Confidentiality and metadata

Payload bytes are encrypted, but IP addresses, connection timing, traffic volume, and frame sizes remain observable. The current protocol does not attempt traffic-analysis resistance.

## 6. Out of scope

The current code does not provide:

- A complete email application or mailbox storage model.
- An independently authenticated first-contact server key without out-of-band provisioning.
- A formal proof of the custom handshake or record protocol.
- A guarantee of availability under denial-of-service conditions.
- Application-level replay protection or message-delivery guarantees.
- A claim of post-quantum security for the entire protocol without review of the composition, implementation, and deployment.

## 7. Appropriate project description

Use descriptions such as:

- Experimental hybrid post-quantum/classical encrypted transport.
- Independent cryptographic engineering project.
- Custom transport prototype using ML-KEM-768, X25519, ML-DSA-65, HKDF, and AES-256-GCM.
- Security properties under active investigation.

Avoid claims such as *unbreakable*, *bulletproof*, *quantum-proof*, *production-secure*, *formally secure*, or *TLS replacement*.
