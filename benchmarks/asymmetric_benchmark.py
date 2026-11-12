"""Окремий експеримент, не виклик з HTTP. Дані створює студент."""
import statistics
from time import perf_counter_ns

SERIES = 5
OPERATIONS = 20
WARMUP = 10
KEYGEN_RUNS = 5
CSV_COLUMNS = (
    "group", "profile", "operation", "payload_bytes", "series_index",
    "operations", "elapsed_ns", "ns_per_operation", "ciphertext_bytes",
)


def measure_batch(operation, count: int = OPERATIONS) -> tuple[int, float]:
    if count < 1:
        raise ValueError("count must be positive")
    started = perf_counter_ns()
    for _ in range(count):
        operation()
    elapsed = perf_counter_ns() - started
    return elapsed, elapsed / count


def summarize(samples: list[float]) -> tuple[float, float]:
    if len(samples) != SERIES:
        raise ValueError("five series required")
    q1, _, q3 = statistics.quantiles(samples, n=4, method="inclusive")
    return float(statistics.median(samples)), float(q3 - q1)


def run_experiment() -> None:
    # TODO generate recipient keys separately; warmup; rotate profile order;
    # encrypt/decrypt series; independent key generation; 22 correctness checks;
    # validate complete report; write 130 raw rows + report to fixed output dir.
    # Setup/decrypt envelopes, verification, DER serialization, file IO and
    # JSON conversion stay outside the relevant timing interval.
    raise NotImplementedError("Implement the offline experiment")


def main() -> int:
    try:
        run_experiment()
    except NotImplementedError as exc:
        print(str(exc))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
