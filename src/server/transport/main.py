from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from shared.transport import TransportSession
import crypto.helpers as crypto_helpers
import asyncio
import shutil
import socket
import sys
import os

keys_dir = os.path.dirname(os.path.dirname(__file__)) + "/keys/"

class TransportServer:
    def __init__(self):
        self.MAX_DATA_BYTES_PER_FRAME = 0xffffff - 16
        self.STREAM_END = b"\x00" * 3
        self.connections: dict[bytes, TransportSession] = {}

    async def establish_symmetric_keys(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes | None:
        try:
            mlkem_private_key, mlkem_public_key, x25519_private_key, x25519_public_key, mldsa_private_key, mldsa_public_key, _ = crypto_helpers.fetch_self_keys(keys_dir + "self/")
            if await reader.readexactly(1) == b"\x01":
                writer.write(mldsa_public_key.public_bytes_raw())
                await writer.drain()

            if await reader.readexactly(1) == b"\x01":
                client_identity_token = await reader.readexactly(64)
                try:
                    os.makedirs(keys_dir + "clients/" + client_identity_token.hex(), exist_ok=True)
                    with open(keys_dir + "clients/" + client_identity_token.hex() + "/mldsa_public.key", "rb") as file:
                        client_mldsa_public_key = crypto_helpers.mldsa.MLDSA65PublicKey.from_public_bytes(file.read(1952))

                except FileNotFoundError:
                    print(f"WARNING: Stale handshake state, Dropping connection with {writer.get_extra_info("peername")}!")
                    shutil.rmtree(keys_dir + "clients/" + client_identity_token.hex())
                    writer.close()
                    await writer.wait_closed()
                    return
            else:
                client_mldsa_public_bytes = await reader.readexactly(1952)
                sha3_512_ctx = crypto_helpers.hashes.Hash(crypto_helpers.hashes.SHA3_512())
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

            payload = await reader.readexactly(1184 + 3309)
            try:
                client_mldsa_public_key.verify(payload[1184:], payload[:1184], b"CLIENT MLKEM768PublicKey")
                client_mlkem_public_key = crypto_helpers.mlkem.MLKEM768PublicKey.from_public_bytes(payload[:1184])
            except crypto_helpers.crypto_exceptions.InvalidSignature:
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
            except crypto_helpers.crypto_exceptions.InvalidSignature:
                print(f"CRITICAL: Signature verification failed while receiving Server's Handshake Values, Dropping Connection!")
                writer.close()
                await writer.wait_closed()
                return

            rec_aes_hkdf_ctx = HKDF(crypto_helpers.hashes.SHA3_256(), 32, client_salt, b"CLIENT KEY")
            sen_aes_hkdf_ctx = HKDF(crypto_helpers.hashes.SHA3_256(), 32, salt, b"SERVER KEY")
            rec_hmac_hkdf_ctx = HKDF(crypto_helpers.hashes.SHA3_512(), 32, client_salt + salt, b"CLIENT HMAC KEY")
            sen_hmac_hkdf_ctx = HKDF(crypto_helpers.hashes.SHA3_512(), 32, salt + client_salt, b"SERVER HMAC KEY")
            rec_counter_hkdf_ctx = HKDF(crypto_helpers.hashes.SHA3_512(), 64, client_salt + salt, b"CLIENT AAD COUNTER")
            sen_counter_hkdf_ctx = HKDF(crypto_helpers.hashes.SHA3_512(), 64, salt + client_salt, b"SERVER AAD COUNTER")

            self.connections[client_identity_token] = TransportSession()
            self.connections[client_identity_token].reader = reader
            self.connections[client_identity_token].writer = writer

            self.connections[client_identity_token].sending_aes_key = sen_aes_hkdf_ctx.derive(mlkem_secret + x25519_shared_secret)
            self.connections[client_identity_token].receiving_aes_key = rec_aes_hkdf_ctx.derive(client_mlkem_secret + x25519_shared_secret)
            self.connections[client_identity_token].sending_hmac_key = sen_hmac_hkdf_ctx.derive(mlkem_secret + x25519_shared_secret)
            self.connections[client_identity_token].receiving_hmac_key = rec_hmac_hkdf_ctx.derive(client_mlkem_secret + x25519_shared_secret)
            self.connections[client_identity_token].sending_counter = sen_counter_hkdf_ctx.derive(self.connections[client_identity_token].sending_aes_key)
            self.connections[client_identity_token].receiving_counter = rec_counter_hkdf_ctx.derive(self.connections[client_identity_token].receiving_aes_key)

            return client_identity_token

        except:
            return

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        print(f"LOG: Connection from {writer.get_extra_info("peername")}")
        client_identity_token = await self.establish_symmetric_keys(reader, writer)
        if client_identity_token == None:
            return

        try:
            while True:
                payload = b""
                frame_count = 0
                while True:
                    header = await reader.readexactly(3)
                    signature = await reader.readexactly(32)
                    self.connections[client_identity_token].receiving_counter = (int.from_bytes(self.connections[client_identity_token].receiving_counter, "big") + 1).to_bytes(64, "big")
                    crypto_helpers.verify_hmac_signature(self.connections[client_identity_token].receiving_hmac_key, header + self.connections[client_identity_token].receiving_counter, signature)
                    if header == self.STREAM_END:
                        break

                    encrypted_frame = await reader.readexactly(12 + int.from_bytes(header, "big"))
                    payload += crypto_helpers.decrypt_payload(self.connections[client_identity_token].receiving_aes_key, encrypted_frame, self.connections[client_identity_token].receiving_counter)

                    frame_count += 1

                print(f"Frames Received: {frame_count}\nPayload Length: {len(payload)}")

                frame_count = 0
                data = b"A" * (self.MAX_DATA_BYTES_PER_FRAME + 1)
                for i in range(0, len(data), self.MAX_DATA_BYTES_PER_FRAME):
                    self.connections[client_identity_token].sending_counter = (int.from_bytes(self.connections[client_identity_token].sending_counter, "big") + 1).to_bytes(64, "big")
                    encrypted_frame = crypto_helpers.encrypt_payload(self.connections[client_identity_token].sending_aes_key, data[i:i + self.MAX_DATA_BYTES_PER_FRAME], self.connections[client_identity_token].sending_counter)

                    header = (len(encrypted_frame) - 12).to_bytes(3, "big")
                    writer.write(header)
                    writer.write(crypto_helpers.generate_hmac_signature(self.connections[client_identity_token].sending_hmac_key, header + self.connections[client_identity_token].sending_counter))
                    writer.write(encrypted_frame)
                    await writer.drain()
                    frame_count += 1

                self.connections[client_identity_token].sending_counter = (int.from_bytes(self.connections[client_identity_token].sending_counter, "big") + 1).to_bytes(64, "big")
                writer.write(self.STREAM_END)
                writer.write(crypto_helpers.generate_hmac_signature(self.connections[client_identity_token].sending_hmac_key, self.STREAM_END + self.connections[client_identity_token].sending_counter))
                await writer.drain()

                print(f"Frames Sent: {frame_count}\nPayload Length: {len(data)}")

        except asyncio.exceptions.IncompleteReadError:
            del self.connections[client_identity_token]
            print(f"WARNING: Client {writer.get_extra_info("peername")} dropped connection unexpectedly.")

    async def start_serving(self):
        server_ctx = await asyncio.start_server(self.handle_connection, "localhost", 6969, family = socket.AF_INET6)
        print(f"LOG: Serving forever.")
        async with server_ctx:
            await server_ctx.serve_forever()

def main():
    server_ctx = TransportServer()
    asyncio.run(server_ctx.start_serving())

if __name__ == "__main__":
    main()
