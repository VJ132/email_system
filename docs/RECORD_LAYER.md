# Transport Record Layer

## Overview

The transport record layer carries application data over a TCP byte stream. Messages are divided into fragments, each encrypted with AES-256-GCM using the traffic key and directional AAD-counter state established by the handshake.

## Encrypted fragment format

Each encrypted fragment is encoded as:

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

The length is an unsigned, big-endian, three-byte integer. It represents the ciphertext and 16-byte authentication tag together. It does not include the three-byte length field or the 12-byte nonce.

The cryptographic helper constructs the encrypted fragment as:

```text
nonce || AESGCM.encrypt(nonce, plaintext, aad)
```

The AES-GCM operation returns ciphertext followed by the 16-byte authentication tag. For a plaintext fragment of `n` bytes:

```text
length field = n + 16
wire size    = 3 + 12 + n + 16 bytes
```

The client currently sets:

```python
MAX_DATA_BYTES_PER_FRAME = 0xFFFFFF - 16
```

The maximum value of a three-byte unsigned length field is `0xFFFFFF`. With the 16-byte tag included in that length, the configured maximum plaintext fragment size is `0xFFFFFF - 16` bytes.

## Message fragmentation

The sender divides an application message into fragments no larger than `MAX_DATA_BYTES_PER_FRAME`. Each fragment is encrypted separately and written to the TCP stream with its length prefix.

A message can therefore be represented by one encrypted fragment or by multiple encrypted fragments. The receiver reads each frame, decrypts its fragment and appends the resulting plaintext to the current message buffer.

## Message boundary marker

After writing all encrypted fragments belonging to a message, the current framing format writes:

```text
00 00 00
```

A zero value in the three-byte length field marks the end of the current message. The receiver returns the accumulated plaintext as one message when it reads this marker.

## Nonce and authentication tag

The cryptographic helper creates a fresh 12-byte nonce for each encryption operation using:

```python
nonce = os.urandom(12)
```

AES-256-GCM produces the ciphertext and a 16-byte authentication tag. The nonce is transmitted with the encrypted fragment so the receiver can perform decryption and tag verification.

## AAD and directional counters

The handshake derives a separate 64-byte initial AAD-counter value for each traffic direction. The sender supplies the current counter value as the AAD input to AES-GCM for each encrypted data fragment.

After an encrypted data fragment is processed, the counter is interpreted as a big-endian integer, incremented, and encoded again as 64 bytes:

```python
counter = (int.from_bytes(counter, "big") + 1).to_bytes(64, "big")
```

The client-to-server and server-to-client directions maintain independent counter state. The sender's initial counter is derived to match the receiver's initial counter for the same direction. See [CRYPTOGRAPHIC_HANDSHAKE.md](CRYPTOGRAPHIC_HANDSHAKE.md#directional-aad-counter-derivation) for the derivation parameters.

The AAD counter and the AES-GCM nonce are separate values with separate roles: the counter is passed as AAD, while the 12-byte nonce is passed as the GCM nonce.

## TCP stream handling

TCP provides an ordered byte stream rather than application messages. The implementation uses `asyncio.StreamReader.readexactly()` to read the three-byte length field and then the number of bytes indicated by that field. This reconstructs complete frames even when the underlying TCP data arrives in multiple network packets or stream reads.

## Record-layer responsibilities

The record layer is responsible for:

- Encoding and decoding the frame length.
- Fragmenting outgoing application messages.
- Reassembling incoming fragments into messages.
- Supplying the appropriate directional traffic key and AAD-counter value to AES-GCM.
- Carrying the nonce, ciphertext and authentication tag between peers.
- Preserving independent state for each connection and traffic direction.
