"""Criptografia do cofre executada exclusivamente no cliente."""
import base64
import json
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b"PassKey-v1"
CHECK = b"PassKey vault check v1"


def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("A senha mestra não pode ser vazia")
    return hash_secret_raw(
        secret=password.encode("utf-8"), salt=salt, time_cost=3,
        memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID,
    )


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, AAD)


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) < 29:
        raise ValueError("Registro cifrado inválido")
    return AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], AAD)


def encrypt_record(key: bytes, value: dict) -> bytes:
    return encrypt(key, json.dumps(value, ensure_ascii=False).encode("utf-8"))


def decrypt_record(key: bytes, ciphertext: bytes) -> dict:
    result = json.loads(decrypt(key, ciphertext).decode("utf-8"))
    if not isinstance(result, dict):
        raise ValueError("Formato de registro inválido")
    return result
