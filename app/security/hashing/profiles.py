"""Явні профілі та конструктори. MD5/SHA-1 лише для навчального порівняння."""
import hashlib
from dataclasses import dataclass
from typing import Literal

AlgorithmID = Literal[
    "sha256", "sha512", "sha3-256", "blake2b-256", "blake2s-256", "md5", "sha1"
]
Mode = Literal["whole", "chunked"]
PAYLOAD_SIZES = (64, 1024, 65536, 1048576)
CHUNK_BYTES = 16384
SERIES = 5
WARMUP = 10
AVALANCHE_TRIALS = 100
AVALANCHE_BYTES = 1024
CHECK_NAMES = (
    "known-abc", "known-empty", "unicode-utf8", "determinism",
    "digest-length", "stream-equivalence",
)


@dataclass(frozen=True)
class Profile:
    digest_bytes: int
    legacy: bool = False


PROFILES = {
    "sha256": Profile(32), "sha512": Profile(64), "sha3-256": Profile(32),
    "blake2b-256": Profile(32), "blake2s-256": Profile(32),
    "md5": Profile(16, True), "sha1": Profile(20, True),
}


FACTORIES = {
        "sha256": hashlib.sha256, "sha512": hashlib.sha512,
        "sha3-256": hashlib.sha3_256,
        "blake2b-256": lambda: hashlib.blake2b(digest_size=32),
        "blake2s-256": lambda: hashlib.blake2s(digest_size=32),
        # False declares a non-security educational use; never change host policies.
        "md5": lambda: hashlib.md5(usedforsecurity=False),
        "sha1": lambda: hashlib.sha1(usedforsecurity=False),
}


def make_hasher(algorithm: str):
    """Новий об'єкт для кожного повідомлення; без ключа і без солі."""
    if algorithm not in FACTORIES:
        raise ValueError("unknown hash profile")
    return FACTORIES[algorithm]()


def probe_profiles() -> list[dict]:
    """Не приховує помилку основного профілю під статусом legacy unavailable."""
    statuses = []
    for algorithm, profile in PROFILES.items():
        try:
            hasher = make_hasher(algorithm)
        except ValueError:
            if not profile.legacy:
                raise RuntimeError("required hash profile unavailable") from None
            statuses.append(dict(algorithm=algorithm, available=False,
                                 reason="not_available_in_environment",
                                 implementation=None))
        else:
            kind = type(hasher)
            statuses.append(dict(algorithm=algorithm, available=True, reason=None,
                                 implementation=f"{kind.__module__}.{kind.__name__}"))
    return statuses


def repeat_count(payload_bytes: int) -> int:
    if type(payload_bytes) is not int or payload_bytes not in PAYLOAD_SIZES:
        raise ValueError("unsupported payload size")
    return 100 if payload_bytes == 1048576 else 1000


def synthetic_payload(size: int) -> bytes:
    """Публічні синтетичні байти, не генератор ключів або справжня відомість."""
    if type(size) is not int or size < 0:
        raise ValueError("invalid synthetic size")
    pattern = b"Digital Dean synthetic export v1\n"
    return (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]
