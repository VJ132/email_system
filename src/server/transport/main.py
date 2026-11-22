from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import crypto.helpers as crypto_helpers
import asyncio
import shutil
import socket
import sys
import os

keys_dir = os.path.dirname(os.path.dirname(__file__)) + "/keys/"
STREAM_END = b"\x00" * 3
client_key_journal = {}

async def establish_symmetric_keys(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes] | None:
    mlkem_private_key, mlkem_public_key, x25519_private_key, x25519_public_key, mldsa_private_key, mldsa_public_key, _ = crypto_helpers.fetch_self_keys(keys_dir + "self/")
    if await reader.readexactly(1) == b"\x01":
        writer.write(mldsa_public_key.public_bytes_raw())
        await writer.drain()

    if await reader.readexactly(1) == b"\x01":
        client_identity_token = await reader.readexactly(64)
        try:
            client_mldsa_public_key = client_key_journal[client_identity_token]
        except KeyError:
            try:
                os.makedirs(keys_dir + "clients/" + client_identity_token.hex(), exist_ok=True)
                with open(keys_dir + "clients/" + client_identity_token.hex() + "/mldsa_public.key", "rb") as file:
                    client_mldsa_public_key = crypto_helpers.mldsa.MLDSA65PublicKey.from_public_bytes(file.read(1952))

                client_key_journal[client_identity_token] = client_mldsa_public_key
            except:
                print(f"WARNING: Stale handshake state, Dropping connection with {writer.get_extra_info("peername")}!")
                shutil.rmtree(keys_dir + "clients/" + client_identity_token.hex())
                writer.close()
                await writer.wait_closed()
                return
    else:
        client_mldsa_public_bytes = await reader.readexactly(1952)
        sha3_512_ctx = hashes.Hash(hashes.SHA3_512())
        sha3_512_ctx.update(client_mldsa_public_bytes)
        sha3_512_ctx.update(os.urandom(64))
        client_identity_token = sha3_512_ctx.finalize()

        writer.write(client_identity_token)
        writer.write(mldsa_private_key.sign(client_identity_token, b"SERVER ASSIGNED IDENTITY TOKEN"))
        await writer.drain()

        client_mldsa_public_key = crypto_helpers.mldsa.MLDSA65PublicKey.from_public_bytes(client_mldsa_public_bytes)
        os.makedirs(keys_dir + "clients/" + client_identity_token.hex(), exist_ok=True)
        with open(keys_dir + "clients/" + client_identity_token.hex() + "/mldsa_public.key", "wb") as file:
            file.write(client_mldsa_public_bytes)

        client_key_journal[client_identity_token] = client_mldsa_public_key

    payload = await reader.readexactly(1184 + 3309)
    try:
        client_mldsa_public_key.verify(payload[1184:], payload[:1184], b"CLIENT MLKEM768PublicKey")
        client_mlkem_public_key = crypto_helpers.mlkem.MLKEM768PublicKey.from_public_bytes(payload[:1184])
    except:
        print(f"CRITICAL: Signature verification failed while receiving client's mlkem public key, Dropping connection with {writer.get_extra_info("peername")}!")
        writer.close()
        await writer.wait_closed()
        return

    writer.write(mlkem_public_key.public_bytes_raw())
    writer.write(mldsa_private_key.sign(mlkem_public_key.public_bytes_raw(), b"SERVER MLKEM768PublicKey"))
    await writer.drain()

    mlkem_secret, mlkem_ciphertext = client_mlkem_public_key.encapsulate()
    salt = os.urandom(16)

    payload = mlkem_ciphertext + x25519_public_key.public_bytes_raw() + salt

    writer.write(payload)
    writer.write(mldsa_private_key.sign(payload, b"SERVER HANDSHAKE VALUES"))
    await writer.drain()

    payload = await reader.readexactly(1088 + 32 + 16 + 3309)
    try:
        client_mldsa_public_key.verify(payload[1088 + 32 + 16:], payload[:1088 + 32 + 16], b"CLIENT HANDSHAKE VALUES")
        client_mlkem_secret = mlkem_private_key.decapsulate(payload[:1088])
        x25519_shared_secret =  x25519_private_key.exchange(crypto_helpers.x25519.X25519PublicKey.from_public_bytes(payload[1088:1088 + 32]))
        client_salt = payload[1088 + 32:1088 + 32 + 16]
    except:
        print(f"CRITICAL: Signature verification failed while receiving Server's Handshake Values, Dropping Connection!")
        writer.close()
        await writer.wait_closed()
        return

    rec_aes_hkdf_ctx = HKDF(hashes.SHA3_256(), 32, client_salt, b"CLIENT KEY")
    sen_aes_hkdf_ctx = HKDF(hashes.SHA3_256(), 32, salt, b"SERVER KEY")
    rec_hmac_hkdf_ctx = HKDF(hashes.SHA3_512(), 32, client_salt + salt, b"CLIENT HMAC KEY")
    sen_hmac_hkdf_ctx = HKDF(hashes.SHA3_512(), 32, salt + client_salt, b"SERVER HMAC KEY")
    rec_counter_hkdf_ctx = HKDF(hashes.SHA3_512(), 64, client_salt + salt, b"CLIENT AAD COUNTER")
    sen_counter_hkdf_ctx = HKDF(hashes.SHA3_512(), 64, salt + client_salt, b"SERVER AAD COUNTER")

    sending_aes_key = sen_aes_hkdf_ctx.derive(mlkem_secret + x25519_shared_secret)
    receiving_aes_key = rec_aes_hkdf_ctx.derive(client_mlkem_secret + x25519_shared_secret)
    sending_hmac_key = sen_hmac_hkdf_ctx.derive(mlkem_secret + x25519_shared_secret)
    receiving_hmac_key = rec_hmac_hkdf_ctx.derive(client_mlkem_secret + x25519_shared_secret)
    sending_counter = sen_counter_hkdf_ctx.derive(sending_aes_key)
    receiving_counter = rec_counter_hkdf_ctx.derive(receiving_aes_key)

    return sending_aes_key, receiving_aes_key, sending_hmac_key, receiving_hmac_key, sending_counter, receiving_counter


async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    print(f"LOG: Connection from {writer.get_extra_info("peername")}")
    keys = await establish_symmetric_keys(reader, writer)
    if keys == None:
        return

    sending_aes_key, receiving_aes_key, sending_hmac_key, receiving_hmac_key, sending_counter, receiving_counter = keys
    print(f"Sending Key: {sending_aes_key.hex().upper()}\nReceiving Key: {receiving_aes_key.hex().upper()}")
    while True:
        payload = b""
        while True:
            header = await reader.readexactly(3)
            signature = await reader.readexactly(32)
            receiving_counter = (int.from_bytes(receiving_counter, "big") + 1).to_bytes(64, "big")
            crypto_helpers.verify_hmac_signature(receiving_hmac_key, header + receiving_counter, signature)
            if header == STREAM_END:
                break

            encrypted_frame = await reader.readexactly(12 + int.from_bytes(header, "big"))
            payload += crypto_helpers.decrypt_payload(receiving_aes_key, encrypted_frame, receiving_counter)

async def start_serving():
    server_ctx = await asyncio.start_server(handle_connection, "localhost", 6969, family = socket.AF_INET6)
    print(f"LOG: Serving forever.")
    async with server_ctx:
        await server_ctx.serve_forever()

def main():
    asyncio.run(start_serving())

if __name__ == "__main__":
    main()
