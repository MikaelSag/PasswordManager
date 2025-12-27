import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Password_hashing import verify_password


# Derives a 32 byte AES key from the user's master password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# Encrypts a vault entry using AES-256-GCM
def encrypt_vault_entry(key: bytes, plaintext: str) -> dict:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode()
    }


# Decrypts a vault entry that was encrypted with AES-256-GCM
def decrypt_vault_entry(key: bytes, stored: dict) -> str:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")

    aesgcm = AESGCM(key)
    nonce = base64.b64decode(stored["nonce"])
    ciphertext = base64.b64decode(stored["ciphertext"])
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode('utf-8')