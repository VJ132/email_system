from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa, x25519
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.kdf import hkdf
from cryptography.hazmat.primitives import hashes
import os

def encrypt_payload(key: bytes, payload: bytes, aad: bytes) -> bytes:
    nonce = bytearray(os.urandom(12))

    cipher_ctx = aead.AESGCM(key)

    nonce.extend(cipher_ctx.encrypt(nonce, payload, aad))

    return bytes(nonce)

def decrypt_payload(key: bytes, payload: bytes, aad: bytes) -> bytes:
    cipher_ctx = aead.AESGCM(key)

    return cipher_ctx.decrypt(payload[:12], payload[12:], aad)

def read_bytes(n: int, file_path: str) -> bytes | None:
    try:
        with open(file_path, "rb") as file:
            return file.read(n)
    except:
        return None

def write_bytes(contents: bytes, file_path: str):
    with open(file_path, "wb") as file:
        file.write(contents)

def fetch_self_keys(keys_dir: str) -> tuple[mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey, x25519.X25519PrivateKey, x25519.X25519PublicKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey, bytes | None]:
    mlkem_private_key = mlkem.MLKEM768PrivateKey.generate()
    mlkem_public_key = mlkem_private_key.public_key()

    x25519_private_key = x25519.X25519PrivateKey.generate()
    x25519_public_key = x25519_private_key.public_key()

    mldsa_private_bytes = read_bytes(32, keys_dir + "mldsa_private.key")
    if mldsa_private_bytes == None:
        print("WARNING: MLDSA KEYS MISSING, GENERATING A NEW PAIR.")
        mldsa_private_key = mldsa.MLDSA65PrivateKey.generate()
        mldsa_public_key = mldsa_private_key.public_key()
        write_bytes(mldsa_private_key.private_bytes_raw(), keys_dir + "mldsa_private.key")
    else:
        mldsa_private_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(mldsa_private_bytes)
        mldsa_public_key = mldsa_private_key.public_key()

    identity_token = read_bytes(64, keys_dir + "identity_token.key")

    return mlkem_private_key, mlkem_public_key, x25519_private_key, x25519_public_key, mldsa_private_key, mldsa_public_key, identity_token
