"""Автоматизовані тести асиметричних та гібридних криптографічних адаптерів."""

import pytest

from app.security.asymmetric.adapters import (
    DecryptionError,
    decrypt,
    encrypt,
    generate_keypair,
)
from app.security.asymmetric.profiles import (
    PROFILES,
    expected_ciphertext_bytes,
    oaep_max_bytes,
)


@pytest.fixture(scope="module", params=list(PROFILES))
def profile(request):
    return request.param


def test_roundtrip_and_length(profile):
    private, public = generate_keypair(PROFILES[profile].key_profile)
    for size in PROFILES[profile].sizes:
        message = b"d" * size
        envelope = encrypt(profile, public, message)
        assert len(envelope) == expected_ciphertext_bytes(profile, size)
        assert decrypt(profile, private, envelope) == message


@pytest.mark.parametrize("failure", ["wrong_key", "tamper", "wrong_context"])
def test_decryption_rejects(profile, failure):
    private, public = generate_keypair(PROFILES[profile].key_profile)
    envelope = encrypt(profile, public, b"synthetic-record")
    context = b"digital-dean:practice-03:report-v1"
    if failure == "wrong_key":
        private, _ = generate_keypair(PROFILES[profile].key_profile)
    elif failure == "tamper":
        envelope = envelope[:-1] + bytes([envelope[-1] ^ 1])
    else:
        context = b"wrong-context"
    with pytest.raises(DecryptionError):
        decrypt(profile, private, envelope, context=context)


@pytest.mark.parametrize("bits", [2048, 3072])
def test_oaep_boundary(bits):
    private, public = generate_keypair(f"rsa-{bits}")
    profile = f"rsa{bits}-oaep"
    limit = oaep_max_bytes(bits)
    message = b"d" * limit
    assert decrypt(profile, private, encrypt(profile, public, message)) == message
    with pytest.raises(ValueError):
        encrypt(profile, public, b"d" * (limit + 1))


def test_unknown_profile_rejected():
    with pytest.raises(ValueError):
        encrypt("unknown", None, b"synthetic")
    with pytest.raises(ValueError):
        decrypt("unknown", None, b"synthetic")
    with pytest.raises(ValueError):
        generate_keypair("unknown-key")


def test_truncated_envelope_rejected(profile):
    private, public = generate_keypair(PROFILES[profile].key_profile)
    size = PROFILES[profile].sizes[0]
    envelope = encrypt(profile, public, b"x" * size)
    with pytest.raises(DecryptionError):
        decrypt(profile, private, envelope[:-1])


def test_mismatched_key_type_rejected():
    rsa2048_priv, rsa2048_pub = generate_keypair("rsa-2048")
    rsa3072_priv, rsa3072_pub = generate_keypair("rsa-3072")
    x_priv, x_pub = generate_keypair("x25519")
    p_priv, p_pub = generate_keypair("p256")

    with pytest.raises(ValueError):
        encrypt("rsa3072-oaep", rsa2048_pub, b"msg")
    with pytest.raises(ValueError):
        encrypt("hpke-x25519-aes256gcm", p_pub, b"msg")
    with pytest.raises(ValueError):
        encrypt("hpke-p256-aes256gcm", x_pub, b"msg")

    env = encrypt("rsa3072-oaep", rsa3072_pub, b"msg")
    with pytest.raises(DecryptionError):
        decrypt("rsa3072-oaep", rsa2048_priv, env)

    hpke_env = encrypt("hpke-x25519-aes256gcm", x_pub, b"msg")
    with pytest.raises(DecryptionError):
        decrypt("hpke-x25519-aes256gcm", p_priv, hpke_env)


def test_fresh_randomness_per_encryption(profile):
    _, public = generate_keypair(PROFILES[profile].key_profile)
    size = PROFILES[profile].sizes[0]
    msg = b"a" * size
    env1 = encrypt(profile, public, msg)
    env2 = encrypt(profile, public, msg)
    assert env1 != env2