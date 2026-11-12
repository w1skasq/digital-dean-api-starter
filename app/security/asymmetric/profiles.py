"""Фіксований дозволений перелік; клієнт не керує алгоритмами."""
from dataclasses import dataclass

CONTEXT = b"digital-dean:practice-03:report-v1"
HYBRID_SIZES = (1024, 65536, 1048576)
DIRECT_SIZE = 64
KEY_PROFILES = ("rsa-2048", "rsa-3072", "x25519", "p256")


@dataclass(frozen=True)
class Profile:
    group: str
    key_profile: str
    sizes: tuple[int, ...]
    overhead_bytes: int | None


PROFILES = {
    "rsa2048-oaep": Profile("direct", "rsa-2048", (64,), None),
    "rsa3072-oaep": Profile("direct", "rsa-3072", (64,), None),
    "rsa3072-oaep-aes256gcm": Profile("hybrid", "rsa-3072", HYBRID_SIZES, 412),
    "hpke-x25519-aes256gcm": Profile("hybrid", "x25519", HYBRID_SIZES, 48),
    "hpke-p256-aes256gcm": Profile("hybrid", "p256", HYBRID_SIZES, 81),
}


def oaep_max_bytes(key_bits: int) -> int:
    if key_bits not in (2048, 3072):
        raise ValueError("unsupported RSA key size")
    return key_bits // 8 - 2 * 32 - 2


def expected_ciphertext_bytes(profile: str, payload_bytes: int) -> int:
    spec = PROFILES[profile]
    if spec.group == "direct":
        return 256 if spec.key_profile == "rsa-2048" else 384
    return payload_bytes + spec.overhead_bytes
