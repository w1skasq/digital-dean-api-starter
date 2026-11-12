"""Криптографічні адаптери асиметричного та гібридного шифрування без власних примітивів."""

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite

from app.security.asymmetric.profiles import CONTEXT, KEY_PROFILES, PROFILES


class DecryptionError(ValueError):
    """Єдина безпечна помилка відхилення криптографічного повідомлення."""


def _oaep_padding(context: bytes) -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=context,
    )


def _check_bytes(value: object, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise ValueError(f"{name} must be bytes")
    return value


def _validate_public_key(profile: str, public: object) -> None:
    if profile == "rsa2048-oaep":
        if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 2048:
            raise ValueError("RSA-2048 public key required")
    elif profile in ("rsa3072-oaep", "rsa3072-oaep-aes256gcm"):
        if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 3072:
            raise ValueError("RSA-3072 public key required")
    elif profile == "hpke-x25519-aes256gcm":
        if not isinstance(public, x25519.X25519PublicKey):
            raise ValueError("X25519 public key required")
    elif profile == "hpke-p256-aes256gcm":
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(
            public.curve, ec.SECP256R1
        ):
            raise ValueError("P-256 public key required")


def _validate_private_key(profile: str, private: object) -> None:
    if profile == "rsa2048-oaep":
        if not isinstance(private, rsa.RSAPrivateKey) or private.key_size != 2048:
            raise ValueError("RSA-2048 private key required")
    elif profile in ("rsa3072-oaep", "rsa3072-oaep-aes256gcm"):
        if not isinstance(private, rsa.RSAPrivateKey) or private.key_size != 3072:
            raise ValueError("RSA-3072 private key required")
    elif profile == "hpke-x25519-aes256gcm":
        if not isinstance(private, x25519.X25519PrivateKey):
            raise ValueError("X25519 private key required")
    elif profile == "hpke-p256-aes256gcm":
        if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(
            private.curve, ec.SECP256R1
        ):
            raise ValueError("P-256 private key required")


def generate_keypair(key_profile: str) -> tuple[object, object]:
    if key_profile not in KEY_PROFILES:
        raise ValueError("unsupported key profile")

    if key_profile == "rsa-2048":
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_profile == "rsa-3072":
        private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    elif key_profile == "x25519":
        private = x25519.X25519PrivateKey.generate()
    else:
        private = ec.generate_private_key(ec.SECP256R1())

    return private, private.public_key()


def encrypt(
    profile: str,
    public: object,
    message: bytes,
    *,
    context: bytes = CONTEXT,
) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")

    msg = _check_bytes(message, "message")
    ctx = _check_bytes(context, "context")
    _validate_public_key(profile, public)

    if profile in ("rsa2048-oaep", "rsa3072-oaep"):
        return public.encrypt(msg, _oaep_padding(ctx))

    if profile == "rsa3072-oaep-aes256gcm":
        session_key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        wrapped_key = public.encrypt(session_key, _oaep_padding(ctx))
        ct_with_tag = AESGCM(session_key).encrypt(nonce, msg, ctx)
        return wrapped_key + nonce + ct_with_tag

    kem = KEM.X25519 if profile == "hpke-x25519-aes256gcm" else KEM.P256
    suite = Suite(kem, KDF.HKDF_SHA256, AEAD.AES_256_GCM)
    return suite.encrypt(msg, public, info=ctx)


def _decrypt(profile: str, private: object, envelope: bytes, context: bytes) -> bytes:
    env = _check_bytes(envelope, "envelope")
    ctx = _check_bytes(context, "context")
    _validate_private_key(profile, private)

    if profile == "rsa2048-oaep":
        if len(env) != 256:
            raise ValueError("invalid RSA-2048 ciphertext length")
        return private.decrypt(env, _oaep_padding(ctx))

    if profile == "rsa3072-oaep":
        if len(env) != 384:
            raise ValueError("invalid RSA-3072 ciphertext length")
        return private.decrypt(env, _oaep_padding(ctx))

    if profile == "rsa3072-oaep-aes256gcm":
        if len(env) < 412:
            raise ValueError("truncated RSA-3072 hybrid envelope")
        wrapped_key = env[:384]
        nonce = env[384:396]
        ct_with_tag = env[396:]
        session_key = private.decrypt(wrapped_key, _oaep_padding(ctx))
        if len(session_key) != 32:
            raise ValueError("invalid unwrapped AES key length")
        return AESGCM(session_key).decrypt(nonce, ct_with_tag, ctx)

    min_len = 48 if profile == "hpke-x25519-aes256gcm" else 81
    if len(env) < min_len:
        raise ValueError("truncated HPKE envelope")
    kem = KEM.X25519 if profile == "hpke-x25519-aes256gcm" else KEM.P256
    suite = Suite(kem, KDF.HKDF_SHA256, AEAD.AES_256_GCM)
    return suite.decrypt(env, private, info=ctx)


def decrypt(
    profile: str,
    private: object,
    envelope: bytes,
    *,
    context: bytes = CONTEXT,
) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")
    try:
        return _decrypt(profile, private, envelope, context)
    except (InvalidTag, ValueError, TypeError) as exc:
        raise DecryptionError("decryption rejected") from exc