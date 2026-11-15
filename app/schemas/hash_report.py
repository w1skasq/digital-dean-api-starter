"""Структура звіту; змістову перевірку validate_report реалізує студент."""
from typing import Annotated, Literal
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StrictInt
from app.security.hashing.profiles import AlgorithmID, Mode


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
    name: Literal["known-abc", "known-empty", "unicode-utf8", "determinism",
                  "digest-length", "stream-equivalence"]
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


def validate_report(data: object) -> HashReport:
    # TODO HashReport.model_validate, then exact coverage and unique tuples.
    # TODO allowed unavailable states, real UTC date, sizes, digest lengths,
    # repeats, throughput, avalanche bounds/fractions, and check coverage.
    # A passed=False check is valid diagnostic data and must not disappear.
    raise NotImplementedError("Implement complete hash report validation")
