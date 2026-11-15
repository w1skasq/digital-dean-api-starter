"""Реалізуйте бібліотечне хешування; не пишіть власних криптопримітивів."""
from app.security.hashing.profiles import CHUNK_BYTES, PROFILES, make_hasher


def _validate_inputs(algorithm: str, data: bytes, mode: str) -> None:
    if type(algorithm) is not str or algorithm not in PROFILES:
        raise ValueError("unknown hash profile")
    if type(data) is not bytes:
        raise TypeError("data must be exact bytes")
    if type(mode) is not str or mode not in ("whole", "chunked"):
        raise ValueError("mode must be 'whole' or 'chunked'")


def prepare_operation(algorithm: str, data: bytes, mode: str = "whole"):
    """Validate and prepare immutable chunks OUTSIDE the timed operation."""
    _validate_inputs(algorithm, data, mode)
    # Проверим доступность конструктора в среде заранее
    make_hasher(algorithm)

    if mode == "whole":
        def run_whole() -> bytes:
            state = make_hasher(algorithm)
            state.update(data)
            return state.digest()

        return run_whole

    chunks = tuple(data[i:i + CHUNK_BYTES] for i in range(0, len(data), CHUNK_BYTES))

    def run_chunked() -> bytes:
        state = make_hasher(algorithm)
        for part in chunks:
            state.update(part)
        return state.digest()

    return run_chunked


def hash_bytes(algorithm: str, data: bytes, mode: str = "whole") -> bytes:
    """Create a NEW hasher for each call, update, return digest() bytes."""
    return prepare_operation(algorithm, data, mode)()


def hamming_bits(left: bytes, right: bytes) -> int:
    """Require equal nonzero lengths; count differing bits, not hex digits."""
    if type(left) is not bytes or type(right) is not bytes:
        raise TypeError("both arguments must be exact bytes")
    if len(left) == 0 or len(right) == 0:
        raise ValueError("inputs must be non-empty")
    if len(left) != len(right):
        raise ValueError("inputs must have equal byte length")
    return sum((a ^ b).bit_count() for a, b in zip(left, right))