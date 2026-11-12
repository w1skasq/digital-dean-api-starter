"""Початкові критерії приймання: TODO повинні стати реалізацією."""
import pytest
from app.security.asymmetric.adapters import DecryptionError, decrypt, encrypt, generate_keypair
from app.security.asymmetric.profiles import PROFILES, expected_ciphertext_bytes, oaep_max_bytes


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
