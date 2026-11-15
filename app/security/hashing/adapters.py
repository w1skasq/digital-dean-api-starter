"""Реалізуйте бібліотечне хешування; не пишіть власних криптопримітивів."""
from app.security.hashing.profiles import CHUNK_BYTES, PROFILES, make_hasher


def prepare_operation(algorithm: str, data: bytes, mode: str = "whole"):
    # TODO validate and prepare immutable chunks OUTSIDE the timed operation.
    # TODO return a no-argument callable that makes a NEW hasher, updates it,
    # and returns digest bytes on EVERY call. Never capture a mutable hasher.
    raise NotImplementedError("Prepare a repeatable full hashing operation")


def hash_bytes(algorithm: str, data: bytes, mode: str = "whole") -> bytes:
    # TODO validate the profile, bytes input and whole/chunked mode.
    # TODO create a NEW hasher for each call, update, return digest() bytes.
    # May call prepare_operation(... )(). The benchmark prepares ONCE, not per run.
    # chunked uses CHUNK_BYTES; do not keep mutable global hash objects.
    raise NotImplementedError("Implement whole and chunked hashing")


def hamming_bits(left: bytes, right: bytes) -> int:
    # TODO require equal nonzero lengths; count differing bits, not hex digits.
    raise NotImplementedError("Implement bytewise Hamming distance")
