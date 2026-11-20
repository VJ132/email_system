# Rules to securely derive a symmetric key

## Digital Signatures

- MLDSA65 is going to be used as the signing algorithm.
- When a client connects to the server, it checks if it has stored the server's public MLDSA65 key stored locally, if it doesn't, it asks the server for its Public Identity Key.
- Server shares the key and the client pins it.
- The server follows up with the same thing to ensure it has the client's Public Identity Key.
## Deriving A Shared Secret
- To derive the shared secret, MLKEM786 and ECDH over Curve25519 is used.
- The same protocol is used to ensure the client and server has the MLKEM public keys of each other.
- The only difference would be that the payload would be signed by the private keys of the respective sender.
- After ensuring both peers have the MLKEM keys of each other, They both generate a secret, Encapsulate it using MLKEM Public Keys of the peer and send the public keys of X25519 along with it as a single payload signed by MLDSA Keys.
- Each generate 2 keys, Receiving Key and a Sending Key.
- Server generates the Sending key using HKDF(ServerGenertatedSecret + X25519SharedSecret), Client does the same with ClientGeneratedSecret for the ReceivingKey and viceversa for the ServerRecevingKey and ClientSendingKey.