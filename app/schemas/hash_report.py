"""Структура звіту; змістову перевірку validate_report реалізує студент."""
import math
from datetime import datetime
from typing import Annotated, Literal
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StrictInt
from app.security.hashing.profiles import (
    AVALANCHE_BYTES,
    AVALANCHE_TRIALS,
    CHECK_NAMES,
    PAYLOAD_SIZES,
    PROFILES,
    AlgorithmID,
    Mode,
    repeat_count,
)


def _exact_int(value):
    if type(value) is not int:
        raise ValueError("integer required; bool/float/string is not an integer")
    return value


Version = Annotated[Literal[1], BeforeValidator(_exact_int)]
Int5 = Annotated[Literal[5], BeforeValidator(_exact_int)]
Int10 = Annotated[Literal[10], BeforeValidator(_exact_int)]
Int100 = Annotated[Literal[100], BeforeValidator(_exact_int)]
Int1000 = Annotated[Literal[1000], BeforeValidator(_exact_int)]
Int1024 = Annotated[Literal[1024], BeforeValidator(_exact_int)]
Int16384 = Annotated[Literal[16384], BeforeValidator(_exact_int)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonnegativeInt = Annotated[StrictInt, Field(ge=0)]
Positive = Annotated[float, Field(gt=0)]
Nonnegative = Annotated[float, Field(ge=0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", allow_inf_nan=False)


class Parameters(StrictModel):
    sizes: list[PositiveInt] = Field(min_length=4, max_length=4)
    chunk_bytes: Int16384
    warmup: Int10
    series: Int5
    repeats_small: Int1000
    repeats_large: Int100
    avalanche_trials: Int100
    avalanche_bytes: Int1024


class Environment(StrictModel):
    python: str = Field(min_length=1, max_length=160)
    openssl_ssl: str = Field(min_length=1, max_length=160)
    os: str = Field(min_length=1, max_length=240)
    cpu: str = Field(min_length=1, max_length=160)
    architecture: str = Field(min_length=1, max_length=80)


class AlgorithmStatus(StrictModel):
    algorithm: AlgorithmID
    available: bool
    reason: Literal["not_available_in_environment"] | None
    implementation: str | None = Field(max_length=160)


class PerformanceResult(StrictModel):
    algorithm: AlgorithmID
    mode: Mode
    payload_bytes: PositiveInt
    digest_bytes: PositiveInt
    repeats: PositiveInt
    median_ns: Positive
    iqr_ns: Nonnegative
    throughput_mib_s: Positive


class AvalancheResult(StrictModel):
    algorithm: AlgorithmID
    input_bytes: Int1024
    trials: Int100
    digest_bits: PositiveInt
    min_flipped_bits: NonnegativeInt
    max_flipped_bits: NonnegativeInt
    mean_flipped_bits: Nonnegative
    mean_fraction: float = Field(ge=0, le=1)


class CorrectnessCheck(StrictModel):
    algorithm: AlgorithmID
    name: Literal[
        "known-abc",
        "known-empty",
        "unicode-utf8",
        "determinism",
        "digest-length",
        "stream-equivalence",
    ]
    passed: bool


class Summary(StrictModel):
    algorithms_count: PositiveInt
    available_count: PositiveInt
    results_count: NonnegativeInt
    checks_count: NonnegativeInt
    all_checks_passed: bool


class HashReport(StrictModel):
    schema_version: Version
    created_at: str = Field(min_length=20, max_length=40)
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    parameters: Parameters
    environment: Environment
    algorithms: list[AlgorithmStatus] = Field(min_length=7, max_length=7)
    results: list[PerformanceResult] = Field(min_length=40, max_length=56)
    avalanche: list[AvalancheResult] = Field(min_length=5, max_length=7)
    checks: list[CorrectnessCheck] = Field(min_length=30, max_length=42)


class HashResponse(HashReport):
    # Filtering may return fewer results; full disk report must stay complete.
    results: list[PerformanceResult] = Field(max_length=56)
    summary: Summary | None = None


def _validate_utc_iso8601(value: str) -> None:
    if not (value.endswith("Z") or value.endswith("+00:00")):
        raise ValueError("created_at must be in UTC (Z or +00:00)")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("created_at is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("created_at must have zero UTC offset")


def validate_report(data: object) -> HashReport:
    report = HashReport.model_validate(data)
    _validate_utc_iso8601(report.created_at)

    if tuple(report.parameters.sizes) != PAYLOAD_SIZES:
        raise ValueError("parameters.sizes must match (64, 1024, 65536, 1048576)")

    # 1. Проверка статусов алгоритмов
    seen_algos: set[str] = set()
    available_algos: list[str] = []
    for item in report.algorithms:
        if item.algorithm in seen_algos:
            raise ValueError(f"duplicate algorithm status: {item.algorithm}")
        seen_algos.add(item.algorithm)
        profile = PROFILES[item.algorithm]
        if item.available:
            if item.reason is not None:
                raise ValueError("available algorithm must have reason=None")
            if not item.implementation or not item.implementation.strip():
                raise ValueError("available algorithm must specify implementation")
            available_algos.append(item.algorithm)
        else:
            if not profile.legacy:
                raise ValueError(f"core profile {item.algorithm} cannot be unavailable")
            if item.reason != "not_available_in_environment":
                raise ValueError("unavailable legacy profile requires reason='not_available_in_environment'")
            if item.implementation is not None:
                raise ValueError("unavailable profile must have implementation=None")

    if seen_algos != set(PROFILES.keys()):
        raise ValueError("algorithms must cover all 7 profiles exactly once")

    available_set = set(available_algos)
    avail_count = len(available_set)

    # 2. Проверка матрицы результатов (8 * A)
    expected_result_keys = {
        (alg, mode, size)
        for alg in available_set
        for mode in ("whole", "chunked")
        for size in PAYLOAD_SIZES
    }
    if len(report.results) != len(expected_result_keys):
        raise ValueError("results count mismatch with available algorithms")

    seen_results: set[tuple[str, str, int]] = set()
    for res in report.results:
        if res.algorithm not in available_set:
            raise ValueError(f"result present for unavailable algorithm: {res.algorithm}")
        key = (res.algorithm, res.mode, res.payload_bytes)
        if key in seen_results:
            raise ValueError(f"duplicate performance result: {key}")
        seen_results.add(key)

        if res.digest_bytes != PROFILES[res.algorithm].digest_bytes:
            raise ValueError(f"invalid digest_bytes for {res.algorithm}")
        expected_repeats = repeat_count(res.payload_bytes)
        if res.repeats != expected_repeats:
            raise ValueError(f"invalid repeats for payload {res.payload_bytes}")

        expected_tp = res.payload_bytes * 1e9 / ((2**20) * res.median_ns)
        if not math.isclose(res.throughput_mib_s, expected_tp, rel_tol=1e-6, abs_tol=1e-6):
            raise ValueError("throughput_mib_s does not match formula")

    if seen_results != expected_result_keys:
        raise ValueError("results matrix coverage incomplete")

    # 3. Проверка лавинного эффекта (1 * A)
    if len(report.avalanche) != avail_count:
        raise ValueError("avalanche count mismatch with available algorithms")

    seen_avalanche: set[str] = set()
    for av in report.avalanche:
        if av.algorithm not in available_set:
            raise ValueError(f"avalanche present for unavailable algorithm: {av.algorithm}")
        if av.algorithm in seen_avalanche:
            raise ValueError(f"duplicate avalanche entry: {av.algorithm}")
        seen_avalanche.add(av.algorithm)

        if av.input_bytes != AVALANCHE_BYTES or av.trials != AVALANCHE_TRIALS:
            raise ValueError("invalid avalanche parameters")
        expected_bits = PROFILES[av.algorithm].digest_bytes * 8
        if av.digest_bits != expected_bits:
            raise ValueError(f"invalid digest_bits for {av.algorithm}")
        if not (0 <= av.min_flipped_bits <= av.mean_flipped_bits <= av.max_flipped_bits <= av.digest_bits):
            raise ValueError("invalid avalanche bit distance bounds")
        expected_frac = av.mean_flipped_bits / av.digest_bits
        if not math.isclose(av.mean_fraction, expected_frac, rel_tol=1e-6, abs_tol=1e-6):
            raise ValueError("mean_fraction does not match mean_flipped_bits / digest_bits")

    if seen_avalanche != available_set:
        raise ValueError("avalanche coverage incomplete")

    # 4. Проверка корректности (6 * A)
    expected_check_keys = {(alg, name) for alg in available_set for name in CHECK_NAMES}
    if len(report.checks) != len(expected_check_keys):
        raise ValueError("checks count mismatch with available algorithms")

    seen_checks: set[tuple[str, str]] = set()
    for chk in report.checks:
        if chk.algorithm not in available_set:
            raise ValueError(f"check present for unavailable algorithm: {chk.algorithm}")
        ckey = (chk.algorithm, chk.name)
        if ckey in seen_checks:
            raise ValueError(f"duplicate check entry: {ckey}")
        seen_checks.add(ckey)

    if seen_checks != expected_check_keys:
        raise ValueError("checks coverage incomplete")

    return report