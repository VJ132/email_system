from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import crypto.helpers as crypto_helpers
import asyncio
import socket
import sys
import os

keys_dir = os.path.dirname(os.path.dirname(__file__)) + "/keys/"
MAX_DATA_BYTES_PER_FRAME = 0xffffff - 16
STREAM_END = b"\x00" * 3

async def read(reader: asyncio.StreamReader, aes_key: bytes, hmac_key: bytes, counter: bytes):
    while True:
        payload = b""
        while True:
            header = await reader.readexactly(3)
            signature = await reader.readexactly(32)
            counter = (int.from_bytes(counter, "big") + 1).to_bytes(64, "big")
            crypto_helpers.verify_hmac_signature(hmac_key, header + counter, signature)
            if header == STREAM_END:
                break

            encrypted_frame = await reader.readexactly(12 + int.from_bytes(header, "big"))
            payload += crypto_helpers.decrypt_payload(aes_key, encrypted_frame, counter)


        print(payload)

async def write(writer: asyncio.StreamWriter, aes_key: bytes, hmac_key: bytes, counter: bytes, data: bytes):
    for i in range(0, len(data), MAX_DATA_BYTES_PER_FRAME):
        counter = (int.from_bytes(counter, "big") + 1).to_bytes(64, "big")
        encrypted_frame = crypto_helpers.encrypt_payload(aes_key, data[i:i + MAX_DATA_BYTES_PER_FRAME], counter)

        header = (len(encrypted_frame) - 12).to_bytes(3, "big")
        writer.write(header)
        writer.write(crypto_helpers.generate_hmac_signature(hmac_key, header + counter))
        writer.write(encrypted_frame)
        await writer.drain()


    counter = (int.from_bytes(counter, "big") + 1).to_bytes(64, "big")
    writer.write(STREAM_END)
    writer.write(crypto_helpers.generate_hmac_signature(hmac_key, STREAM_END + counter))
    await writer.drain()

async def establish_symmetric_keys(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
    mlkem_private_key, mlkem_public_key, x25519_private_key, x25519_public_key, mldsa_private_key, mldsa_public_key, identity_token = crypto_helpers.fetch_self_keys(keys_dir + "self/")

    # Check if the client has the server's MLDSA public key.
    try:
        with open(keys_dir + "server/mldsa_public.key", "rb") as mldsa_pub:
            server_mldsa_public_key = crypto_helpers.mldsa.MLDSA65PublicKey.from_public_bytes(mldsa_pub.read(1952))

        writer.write(b"\x00")
        await writer.drain()
    except:
        # Client doesnot have the server's public key.
        writer.write(b"\x01")
        await writer.drain()

        server_mldsa_public_key = crypto_helpers.mldsa.MLDSA65PublicKey.from_public_bytes(await reader.readexactly(1952))
        with open(keys_dir + "server/mldsa_public.key", "wb") as file:
            file.write(server_mldsa_public_key.public_bytes_raw())

    if identity_token != None:
        writer.write(b"\x01" + identity_token)
        await writer.drain()
    else:
        writer.write(b"\x00")
        writer.write(mldsa_public_key.public_bytes_raw())
        await writer.drain()

        payload = await reader.readexactly(64 + 3309)
        try:
            server_mldsa_public_key.verify(payload[64:], payload[:64], b"SERVER ASSIGNED IDENTITY TOKEN")
            with open(keys_dir + "self/identity_token.key", "wb") as file:
                file.write(payload[:64])
        except:
            print(f"CRITICAL: Signature verification failed while receiving Server Assigned Identity Token, Dropping Connection!")
            writer.close()
            await writer.wait_closed()
            sys.exit(1)

    writer.write(mlkem_public_key.public_bytes_raw() + mldsa_private_key.sign(mlkem_public_key.public_bytes_raw(), b"CLIENT MLKEM768PublicKey"))
    await writer.drain()

    payload = await reader.readexactly(1184 + 3309)
    try:
        server_mldsa_public_key.verify(payload[1184:], payload[:1184], b"SERVER MLKEM768PublicKey")
        server_mlkem_public_key = crypto_helpers.mlkem.MLKEM768PublicKey.from_public_bytes(payload[:1184])
    except:
        print(f"CRITICAL: Signature verification failed while receiving Server's MLKEM Public Key, Dropping Connection!")
        writer.close()
        await writer.wait_closed()
        sys.exit(1)

    payload = await reader.readexactly(1088 + 32 + 16 + 3309)
    try:
        server_mldsa_public_key.verify(payload[1088 + 32 + 16:], payload[:1088 + 32 + 16], b"SERVER HANDSHAKE VALUES")
        server_mlkem_secret = mlkem_private_key.decapsulate(payload[:1088])
        x25519_shared_secret =  x25519_private_key.exchange(crypto_helpers.x25519.X25519PublicKey.from_public_bytes(payload[1088:1088 + 32]))
        server_salt = payload[1088 + 32:1088 + 32 + 16]
    except:
        print(f"CRITICAL: Signature verification failed while receiving Server's Handshake Values, Dropping Connection!")
        writer.close()
        await writer.wait_closed()
        sys.exit(1)

    mlkem_secret, mlkem_ciphertext = server_mlkem_public_key.encapsulate()
    salt = os.urandom(16)

    payload = mlkem_ciphertext + x25519_public_key.public_bytes_raw() + salt

    writer.write(payload + mldsa_private_key.sign(payload, b"CLIENT HANDSHAKE VALUES"))
    await writer.drain()

    rec_aes_hkdf_ctx = HKDF(hashes.SHA3_256(), 32, server_salt, b"SERVER KEY")
    sen_aes_hkdf_ctx = HKDF(hashes.SHA3_256(), 32, salt, b"CLIENT KEY")
    rec_hmac_hkdf_ctx = HKDF(hashes.SHA3_512(), 32, server_salt + salt, b"SERVER HMAC KEY")
    sen_hmac_hkdf_ctx = HKDF(hashes.SHA3_512(), 32, salt + server_salt, b"CLIENT HMAC KEY")
    rec_counter_hkdf_ctx = HKDF(hashes.SHA3_512(), 64, server_salt + salt, b"SERVER AAD COUNTER")
    sen_counter_hkdf_ctx = HKDF(hashes.SHA3_512(), 64, salt + server_salt, b"CLIENT AAD COUNTER")

    sending_aes_key = sen_aes_hkdf_ctx.derive(mlkem_secret + x25519_shared_secret)
    receiving_aes_key = rec_aes_hkdf_ctx.derive(server_mlkem_secret + x25519_shared_secret)
    sending_hmac_key = sen_hmac_hkdf_ctx.derive(mlkem_secret + x25519_shared_secret)
    receiving_hmac_key = rec_hmac_hkdf_ctx.derive(server_mlkem_secret + x25519_shared_secret)
    sending_counter = sen_counter_hkdf_ctx.derive(sending_aes_key)
    receiving_counter = rec_counter_hkdf_ctx.derive(receiving_aes_key)

    return sending_aes_key, receiving_aes_key, sending_hmac_key, receiving_hmac_key, sending_counter, receiving_counter

async def connect():
    r, w = await asyncio.open_connection("localhost", 6969, family = socket.AF_INET6)
    sending_aes_key, receiving_aes_key, sending_hmac_key, receiving_hmac_key, sending_counter, receiving_counter = await establish_symmetric_keys(r, w)
    print(f"Sending Key: {sending_aes_key.hex().upper()}\nReceiving Key: {receiving_aes_key.hex().upper()}")
    await write(w, sending_aes_key, sending_hmac_key, sending_counter, b"A" * (MAX_DATA_BYTES_PER_FRAME + 1))
    await read(r, receiving_aes_key, receiving_hmac_key, receiving_counter)

def main():
    asyncio.run(connect())

if __name__ == "__main__":
    main()
