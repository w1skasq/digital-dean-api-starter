"""Спільний контракт для cryptography та PyCryptodome без відкритого fallback."""

from Crypto.Cipher import AES, ChaCha20_Poly1305
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)

from app.security.profiles import BACKENDS, TAG_BYTES, validate_profile


class CiphertextError(Exception):
    """Повідомлення не пройшло перевірку автентичності."""


def seal_bytes(backend, algorithm, key, nonce, data, aad):
    """Повернути (ciphertext, tag); перевірити профіль і бібліотеку."""
    validate_profile(algorithm, key, nonce)
    is_aes = algorithm.startswith("AES-")
    if backend == "cryptography":
        factory = AESGCM if is_aes else ChaCha20Poly1305
        combined = factory(key).encrypt(nonce, data, aad)
        return combined[:-TAG_BYTES], combined[-TAG_BYTES:]
    if backend == "pycryptodome":
        cipher = (
            AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_BYTES)
            if is_aes
            else ChaCha20_Poly1305.new(key=key, nonce=nonce)
        )
        cipher.update(aad)
        return cipher.encrypt_and_digest(data)
    raise ValueError("Unsupported backend")


def open_bytes(backend, algorithm, key, nonce, ct, tag, aad):
    """Видати байти тільки після успішної перевірки повного тега."""
    validate_profile(algorithm, key, nonce)
    if backend not in BACKENDS:
        raise ValueError("Unsupported backend")
    if len(tag) != TAG_BYTES:
        raise CiphertextError("Verification failed")
    is_aes = algorithm.startswith("AES-")
    try:
        if backend == "cryptography":
            factory = AESGCM if is_aes else ChaCha20Poly1305
            return factory(key).decrypt(nonce, ct + tag, aad)
        cipher = (
            AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_BYTES)
            if is_aes
            else ChaCha20_Poly1305.new(key=key, nonce=nonce)
        )
        cipher.update(aad)
        return cipher.decrypt_and_verify(ct, tag)
    except (InvalidTag, ValueError) as exc:
        raise CiphertextError("Verification failed") from exc