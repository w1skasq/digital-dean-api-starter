"""Реалізуйте криптографічні адаптери без власних примітивів.

generate_keypair повертає (private, public). encrypt/decrypt приймають
profile, об'єкт відповідного ключа, bytes і keyword-only context.
Контекст: label для OAEP, label та AAD для RSA/AES, info для HPKE.
RSA/AES envelope: wrapped_key[384] || nonce[12] || ct_with_tag.
HPKE envelope: повернений Suite.encrypt enc || ct без перекодування.
"""
from cryptography.exceptions import InvalidTag
from app.security.asymmetric.profiles import CONTEXT, PROFILES, KEY_PROFILES


class DecryptionError(ValueError):
    """Єдина безпечна помилка відхилення криптографічного повідомлення."""


def generate_keypair(key_profile: str) -> tuple[object, object]:
    if key_profile not in KEY_PROFILES:
        raise ValueError("unsupported key profile")
    raise NotImplementedError("Implement library key generation")


def encrypt(profile: str, public: object, message: bytes,
            *, context: bytes = CONTEXT) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")
    raise NotImplementedError("Implement library encryption and fresh per-message material")


def _decrypt(profile: str, private: object, envelope: bytes, context: bytes) -> bytes:
    raise NotImplementedError("Implement strict envelope parsing and library decryption")


def decrypt(profile: str, private: object, envelope: bytes,
            *, context: bytes = CONTEXT) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")
    try:
        return _decrypt(profile, private, envelope, context)
    except (InvalidTag, ValueError) as exc:
        raise DecryptionError("decryption rejected") from exc
