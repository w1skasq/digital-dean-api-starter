"""Структура та семантичний валідатор базового звіту практичної 3."""

from datetime import datetime, timezone
import math
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from app.security.asymmetric.profiles import (
    DIRECT_SIZE,
    HYBRID_SIZES,
    KEY_PROFILES,
    PROFILES,
    expected_ciphertext_bytes,
)


def _exact_integer(value: object) -> int:
    # Numeric Literal comparisons alone can accept True or 5.0 as integers.
    if type(value) is not int:
        raise ValueError("an exact integer is required")
    return value


One = Annotated[Literal[1], BeforeValidator(_exact_integer)]
Five = Annotated[Literal[5], BeforeValidator(_exact_integer)]
Ten = Annotated[Literal[10], BeforeValidator(_exact_integer)]
Twenty = Annotated[Literal[20], BeforeValidator(_exact_integer)]
SixtyFour = Annotated[Literal[64], BeforeValidator(_exact_integer)]

ProfileId = Literal[
    "rsa2048-oaep",
    "rsa3072-oaep",
    "rsa3072-oaep-aes256gcm",
    "hpke-x25519-aes256gcm",
    "hpke-p256-aes256gcm",
]
KeyId = Literal["rsa-2048", "rsa-3072", "x25519", "p256"]
PositiveFloat = Annotated[float, Field(gt=0, allow_inf_nan=False)]
NonNegativeFloat = Annotated[float, Field(ge=0, allow_inf_nan=False)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Experiment(StrictModel):
    series: Five
    operations_per_series: Twenty
    warmup: Ten
    keygen_runs: Five
    direct_payload_bytes: SixtyFour
    hybrid_sizes_bytes: list[int]
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    created_at_utc: str = Field(min_length=20, max_length=40)


class Environment(StrictModel):
    python: str = Field(min_length=1, max_length=100)
    cryptography: Literal["48.0.1"]
    openssl: str = Field(min_length=1, max_length=150)
    os: str = Field(min_length=1, max_length=150)
    cpu: str = Field(min_length=1, max_length=200)


class KeyGeneration(StrictModel):
    key_profile: KeyId
    runs: Five
    median_ns: PositiveFloat
    iqr_ns: NonNegativeFloat
    public_key_der_bytes: int = Field(gt=0, le=4096)


class Result(StrictModel):
    profile: ProfileId
    group: Literal["direct", "hybrid"]
    operation: Literal["encrypt", "decrypt"]
    payload_bytes: int = Field(gt=0, le=1048576)
    series: Five
    operations_per_series: Twenty
    median_ns: PositiveFloat
    iqr_ns: NonNegativeFloat
    ciphertext_bytes: int = Field(gt=0, le=1048988)
    throughput_mib_s: PositiveFloat | None


class Check(StrictModel):
    profile: ProfileId
    name: Literal["roundtrip", "wrong_key", "tamper", "wrong_context", "oaep_boundary"]
    passed: bool


class BenchmarkReport(StrictModel):
    schema_version: One
    experiment: Experiment
    environment: Environment
    key_generation: list[KeyGeneration] = Field(min_length=4, max_length=4)
    results: list[Result] = Field(min_length=22, max_length=22)
    checks: list[Check] = Field(min_length=22, max_length=22)


class BenchmarkResponse(BenchmarkReport):
    # First validate the complete saved report, then filter only results.
    # Keep key_generation and checks complete. An empty filtered list is valid.
    results: list[Result] = Field(max_length=22)


def expected_throughput_mib_s(payload_bytes: int, median_ns: float) -> float:
    return (payload_bytes * 1_000_000_000.0) / ((2**20) * median_ns)


def _validate_utc_timestamp(raw: str) -> None:
    normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("created_at_utc must be in UTC")


def validate_complete_report(data: object) -> BenchmarkReport:
    report = BenchmarkReport.model_validate(data)

    # 1. Experiment metadata checks
    if [type(x) is int for x in report.experiment.hybrid_sizes_bytes] != [True, True, True]:
        raise ValueError("hybrid_sizes_bytes must contain exact integers")
    if report.experiment.hybrid_sizes_bytes != list(HYBRID_SIZES):
        raise ValueError("unexpected hybrid_sizes_bytes")
    if report.experiment.direct_payload_bytes != DIRECT_SIZE:
        raise ValueError("unexpected direct_payload_bytes")
    _validate_utc_timestamp(report.experiment.created_at_utc)

    # 2. Key generation coverage (4 unique profiles)
    seen_keys = [item.key_profile for item in report.key_generation]
    if len(set(seen_keys)) != 4 or set(seen_keys) != set(KEY_PROFILES):
        raise ValueError("incomplete or duplicate key_generation profiles")

    # 3. Results coverage (22 unique tuples) & formulas
    expected_result_keys: set[tuple[str, str, int]] = set()
    for prof_name, spec in PROFILES.items():
        for size in spec.sizes:
            for op in ("encrypt", "decrypt"):
                expected_result_keys.add((prof_name, op, size))

    seen_result_keys: set[tuple[str, str, int]] = set()
    for item in report.results:
        key = (item.profile, item.operation, item.payload_bytes)
        if key in seen_result_keys:
            raise ValueError("duplicate result entry")
        seen_result_keys.add(key)

        spec = PROFILES[item.profile]
        if item.group != spec.group:
            raise ValueError("mismatched group for profile")
        if item.payload_bytes not in spec.sizes:
            raise ValueError("mismatched payload_bytes for profile")
        if item.ciphertext_bytes != expected_ciphertext_bytes(item.profile, item.payload_bytes):
            raise ValueError("mismatched ciphertext_bytes")

        if item.group == "direct":
            if item.throughput_mib_s is not None:
                raise ValueError("direct RSA throughput_mib_s must be null")
        else:
            if item.throughput_mib_s is None:
                raise ValueError("hybrid throughput_mib_s must be positive")
            expected_tp = expected_throughput_mib_s(item.payload_bytes, item.median_ns)
            if not math.isclose(item.throughput_mib_s, expected_tp, rel_tol=1e-6, abs_tol=1e-9):
                raise ValueError("inconsistent throughput_mib_s formula")

    if seen_result_keys != expected_result_keys:
        raise ValueError("incomplete results coverage")

    # 4. Checks coverage (22 unique pairs; false values are preserved, not hidden)
    expected_checks: set[tuple[str, str]] = set()
    for prof_name in PROFILES:
        for check_name in ("roundtrip", "wrong_key", "tamper", "wrong_context"):
            expected_checks.add((prof_name, check_name))
    expected_checks.add(("rsa2048-oaep", "oaep_boundary"))
    expected_checks.add(("rsa3072-oaep", "oaep_boundary"))

    seen_checks: set[tuple[str, str]] = set()
    for chk in report.checks:
        pair = (chk.profile, chk.name)
        if pair in seen_checks:
            raise ValueError("duplicate check entry")
        seen_checks.add(pair)

    if seen_checks != expected_checks:
        raise ValueError("incomplete checks coverage")

    return report