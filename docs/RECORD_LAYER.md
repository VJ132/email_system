# Encrypted Record Layer

## 1. Overview

After the handshake, each endpoint has separate directional AES-256-GCM keys, HMAC-SHA3-256 keys, and 64-byte counter state. A logical message may contain one or more data frames and ends with an authenticated stream terminator.

## 2. Data-frame wire format

The exact wire order is:

```text
+----------------------+-----------------------------+
| Field                | Size                        |
+----------------------+-----------------------------+
| HEADER               | 3 bytes                     |
| HMAC                 | 32 bytes                    |
| NONCE                | 12 bytes                    |
| CIPHERTEXT           | Variable                    |
| GCM TAG              | 16 bytes                    |
+----------------------+-----------------------------+
```

Equivalent concatenation:

```text
HEADER || HMAC || NONCE || CIPHERTEXT || GCM_TAG
```

The 3-byte header is an unsigned big-endian integer. It contains the length of the AES-GCM ciphertext **including** its 16-byte tag, but **excluding** the 12-byte nonce. The encrypted frame body read by the receiver is therefore `12 + header_length` bytes.

## 3. Header authentication and sequence counter

For every data frame, the sender:

1. Increments its 64-byte directional counter by one, interpreted as a big-endian integer.
2. Encrypts the plaintext using AES-256-GCM, with the incremented counter bytes as associated authenticated data (AAD).
3. Sets the header to `len(encrypted_frame) - 12`, where `encrypted_frame` includes the nonce, ciphertext, and tag.
4. Computes HMAC-SHA3-256 over:

```text
HEADER || COUNTER
```

5. Writes the header, 32-byte HMAC, and encrypted frame.

The receiver:

1. Reads the 3-byte header and 32-byte HMAC.
2. Increments its expected directional counter.
3. Verifies the HMAC over `HEADER || COUNTER`.
4. If the header is nonzero, reads the 12-byte nonce plus the declared encrypted-frame length.
5. Decrypts and authenticates using AES-256-GCM with the same counter as AAD.
6. Appends the plaintext fragment to the current logical message.

HMAC authenticates the header and sequence number before the body is read. It does **not** cover the ciphertext bytes. AES-GCM separately authenticates the nonce/ciphertext/tag and the counter supplied as AAD.

## 4. AES-GCM nonce

The helper `encrypt_payload()` creates a 12-byte nonce with `os.urandom(12)` for each frame. The nonce is transmitted in cleartext before the ciphertext and tag.

AES-GCM requires nonce uniqueness under a given key. The current implementation uses random nonces and does not maintain an explicit per-key nonce registry or deterministic nonce allocator. The nonce lifecycle and collision-risk policy therefore remain important design considerations, especially if the number of frames per traffic key grows.

## 5. Frame and message size

The header is 24 bits, so the maximum value it can encode is `0xFFFFFF`.

The current implementation defines:

```python
MAX_DATA_BYTES_PER_FRAME = 0xFFFFFF - 16
```

The 16-byte GCM tag is included in the header length. The 12-byte nonce is excluded. Thus the configured maximum plaintext per frame is `0xFFFFFF - 16` bytes.

`write()` fragments a larger byte string into pieces no larger than this value. The receiver concatenates the decrypted fragments until the stream terminator arrives.

The 24-bit header bounds an individual frame. The current receiver does not define a separate maximum for the total assembled logical message.

## 6. Authenticated stream terminator

The terminator is:

```text
00 00 00 || HMAC-SHA3-256(STREAM_END || COUNTER)
```

where:

```python
STREAM_END = b"\x00" * 3
```

The sender increments the directional counter for the terminator, computes the HMAC over the zero-length header and that counter, then writes the 3-byte header and 32-byte HMAC. There is no nonce, ciphertext, or GCM tag for a terminator.

The receiver increments its expected counter and verifies the HMAC before treating the zero header as the end of the logical message. The terminator consumes a counter value just like a data frame.

## 7. Counter state and record ordering

Counters are independent for client-to-server and server-to-client traffic. The initial 64-byte values are derived by HKDF from the corresponding directional AES key and direction-specific salt ordering.

Each sender and receiver increments its own counter before processing a record. Since the counter is included in the HMAC input and is also used as GCM AAD, the receiver expects the next record in that direction. Old, duplicated, or skipped sequence values do not authenticate against the receiver's expected counter.

The current client `write()` function updates a local counter variable but does not return it. The client entry point currently invokes `write()` once per connection. Repeated independent calls to `write()` on the same connection need a persistent per-connection send-counter owner or a revised function interface that returns and retains the updated counter. Within a single `write()` call, the counter advances across all fragments and the terminator.

The server keeps its sending and receiving counter variables in the connection handler's scope, so they persist across its message loop. Counter exhaustion/overflow needs an explicit policy before long-lived or production use.

## 8. Current receive-loop behavior

Both client and server receive loops:

- Read a logical message as a sequence of authenticated frames.
- Accumulate plaintext fragments until an authenticated terminator.
- Report the frame count and assembled payload length.
- Continue waiting for the next logical message on the stream.

The current server then sends a fixed test response. Application-level message dispatch and delivery are not implemented in this record layer.

## 9. TCP and record-layer responsibilities

TCP provides an ordered byte stream and handles network packet retransmission. The record layer independently authenticates record metadata and checks the expected directional sequence state. The counter mechanism is not an application-level duplicate-request control: an application message deliberately submitted again inside a new valid session is a separate application-layer event.
