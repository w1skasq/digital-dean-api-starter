"""Локальний експеримент. У гілці немає готових виміряних результатів."""
from statistics import median, quantiles
from time import perf_counter_ns
from app.security.hashing.profiles import PROFILES, repeat_count, synthetic_payload


def measure_batch(operation, repeats: int) -> float:
    if type(repeats) is not int or repeats <= 0:
        raise ValueError("positive repeat count required")
    start = perf_counter_ns()
    for _ in range(repeats):
        operation()
    elapsed_ns = perf_counter_ns() - start
    return elapsed_ns / repeats


def summarize(samples: list[float]) -> tuple[float, float]:
    if len(samples) != 5:
        raise ValueError("five series required")
    q1, _, q3 = quantiles(samples, n=4, method="inclusive")
    return median(samples), q3 - q1


def run_experiment() -> None:
    # TODO require a clean working tree and record git rev-parse HEAD BEFORE run.
    # TODO statuses, prepared whole/chunked operations, warmup, five series,
    # six correctness checks per available profile and 100 one-bit mutations.
    # TODO raw.csv, avalanche.csv and complete validated report.json in
    # results/practice-04/. Keep false checks and exit nonzero if any fail.
    # Do not include file I/O, data preparation or hex conversion in timers.
    raise NotImplementedError("Implement the local reproducible experiment")


if __name__ == "__main__":
    try:
        run_experiment()
    except NotImplementedError as exc:
        raise SystemExit(str(exc)) from None
