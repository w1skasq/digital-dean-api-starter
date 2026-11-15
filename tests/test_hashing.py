"""Критерії приймання; TODO реалізації мають бути виконані, а не пропущені."""
import pytest
from app.security.hashing import profiles
from app.security.hashing.adapters import hash_bytes, hamming_bits, prepare_operation

# Public fixed inputs. These constants are test vectors, NOT benchmark results.
# SHA/MD5 follow official vectors; BLAKE2 profiles were independently checked
# against PyCryptodome with digest_bits=256, not a truncated 512-bit digest.
VECTORS = {
    "sha256": (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    "sha512": (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192"
        "992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    "sha3-256": (
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    "blake2b-256": (
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"),
    "blake2s-256": (
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
    "md5": ("d41d8cd98f00b204e9800998ecf8427e", "900150983cd24fb0d6963f7d28e17f72"),
    "sha1": ("da39a3ee5e6b4b0d3255bfef95601890afd80709",
             "a9993e364706816aba3e25717850c26c9cd0d89d"),
}


def available(algorithm):
    row = next(x for x in profiles.probe_profiles() if x["algorithm"] == algorithm)
    if not row["available"]:
        assert profiles.PROFILES[algorithm].legacy
        assert row["reason"] == "not_available_in_environment"
    return row["available"]


@pytest.mark.parametrize("algorithm", profiles.PROFILES)
def test_factory_metadata(algorithm):
    if available(algorithm):
        assert len(profiles.make_hasher(algorithm).digest()) == profiles.PROFILES[
            algorithm].digest_bytes


@pytest.mark.parametrize("algorithm", profiles.PROFILES)
@pytest.mark.parametrize("index,payload", [(0, b""), (1, b"abc")])
def test_known_vectors(algorithm, index, payload):
    if available(algorithm):
        assert hash_bytes(algorithm, payload).hex() == VECTORS[algorithm][index]


@pytest.mark.parametrize("algorithm", profiles.PROFILES)
@pytest.mark.parametrize("size", [0, 16383, 16384, 16385])
def test_chunk_boundaries(algorithm, size):
    if available(algorithm):
        data = profiles.synthetic_payload(size)
        assert hash_bytes(algorithm, data) == hash_bytes(algorithm, data, "chunked")


@pytest.mark.parametrize("algorithm", profiles.PROFILES)
def test_unicode_and_no_shared_mutable_state(algorithm):
    if available(algorithm):
        text = "Відомість Цифрового деканату".encode("utf-8")
        first = hash_bytes(algorithm, text)
        hash_bytes(algorithm, b"a different message")
        expected = profiles.make_hasher(algorithm)
        expected.update(text)
        assert first == hash_bytes(algorithm, text) == expected.digest()


@pytest.mark.parametrize("algorithm,mode,data", [
    ("sha256", "unknown", b"a"), ("../report", "whole", b"a"),
    ("sha256", "whole", "not bytes"),
])
def test_reject_unsupported_input(algorithm, mode, data):
    with pytest.raises((ValueError, TypeError)):
        hash_bytes(algorithm, data, mode)


@pytest.mark.parametrize("left,right,expected", [
    (b"\x00", b"\xff", 8), (b"\x01\x80", b"\x00\x00", 2),
    (b"\xaa", b"\xaa", 0),
])
def test_hamming_bits(left, right, expected):
    assert hamming_bits(left, right) == expected


@pytest.mark.parametrize("left,right", [(b"", b""), (b"a", b"ab"), ("a", b"a")])
def test_hamming_rejects_invalid_inputs(left, right):
    with pytest.raises((ValueError, TypeError)):
        hamming_bits(left, right)


def test_prepared_operation_has_no_shared_hash_state():
    payload = profiles.synthetic_payload(16385)
    operation = prepare_operation("sha256", payload, "chunked")
    assert callable(operation)
    expected = profiles.make_hasher("sha256")
    expected.update(payload)
    assert operation() == operation() == expected.digest()


def test_required_profile_must_not_silently_disappear(monkeypatch):
    original = profiles.make_hasher
    def unavailable(name):
        if name == "sha256":
            raise ValueError("policy")
        return original(name)
    monkeypatch.setattr(profiles, "make_hasher", unavailable)
    with pytest.raises(RuntimeError):
        profiles.probe_profiles()


def test_legacy_unavailability_is_explicit(monkeypatch):
    original = profiles.make_hasher
    def unavailable(name):
        if name == "md5":
            raise ValueError("policy")
        return original(name)
    monkeypatch.setattr(profiles, "make_hasher", unavailable)
    row = next(x for x in profiles.probe_profiles() if x["algorithm"] == "md5")
    assert row == dict(algorithm="md5", available=False, implementation=None,
                       reason="not_available_in_environment")
