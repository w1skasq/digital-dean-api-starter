"""Модуль микробенчмарков симметричного AEAD-шифрования (Практическая работа 2)."""

import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
from secrets import token_bytes
from statistics import median
import sys
import time

import Crypto
import cryptography

from app.security.adapters import open_bytes, seal_bytes
from app.security.nonce import NonceSequence
from app.security.profiles import BACKENDS, KEY_BYTES

SIZES_BYTES = (1024, 65536, 1048576)
WARMUP = 10
SERIES = 5
OPERATIONS_PER_SERIES = 100
BENCHMARK_AAD = b"digital-dean-practice-02-benchmark".ljust(64, b".")


def _inclusive_percentile(sorted_values: list[float], p: float) -> float:
    n = len(sorted_values)
    if n == 1:
        return float(sorted_values[0])
    pos = (n - 1) * p
    low = int(pos)
    high = min(low + 1, n - 1)
    frac = pos - low
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * frac


def measure_batch(operation, arguments) -> float:
    """Измеряет среднее время (в наносекундах) одной операции в серии."""
    args_list = list(arguments)
    if not args_list:
        raise ValueError("Arguments sequence must not be empty")
    start = time.perf_counter_ns()
    for args in args_list:
        operation(*args)
    elapsed = time.perf_counter_ns() - start
    return elapsed / len(args_list)


def summarize(series_mean_ns, size_bytes) -> dict:
    """Вычисляет медиану 5 средних, inclusive IQR и пропускную способность в МиБ/с."""
    values = sorted(float(v) for v in series_mean_ns)
    if not values:
        raise ValueError("Series list must not be empty")
    med_ns = float(median(values))
    q1 = _inclusive_percentile(values, 0.25)
    q3 = _inclusive_percentile(values, 0.75)
    iqr_ns = float(q3 - q1)
    throughput_mib_s = (
        (size_bytes / (1024 * 1024)) / (med_ns / 1_000_000_000)
        if med_ns > 0
        else 0.0
    )
    return {
        "median_ns": round(med_ns, 2),
        "iqr_ns": round(iqr_ns, 2),
        "throughput_mib_s": round(throughput_mib_s, 3),
    }


def _environment_info() -> dict:
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "cryptography_version": cryptography.__version__,
        "pycryptodome_version": Crypto.__version__,
    }


def run_benchmark(output_dir: Path) -> None:
    """Выполняет 180 серий (36 агрегатов) и сохраняет raw.csv и report.json."""
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_rows: list[dict] = []
    aggregates: list[dict] = []

    for backend in BACKENDS:
        for algorithm, key_size in KEY_BYTES.items():
            key = token_bytes(key_size)
            nonces = NonceSequence(limit=1_000_000)

            for size_bytes in SIZES_BYTES:
                payload = token_bytes(size_bytes)

                # Прогрев шифрования (каждый вызов с новым nonce)
                warmup_seal_args = [
                    (backend, algorithm, key, nonces.next(), payload, BENCHMARK_AAD)
                    for _ in range(WARMUP)
                ]
                measure_batch(seal_bytes, warmup_seal_args)

                seal_series_means: list[float] = []
                for series_idx in range(1, SERIES + 1):
                    batch_args = [
                        (backend, algorithm, key, nonces.next(), payload, BENCHMARK_AAD)
                        for _ in range(OPERATIONS_PER_SERIES)
                    ]
                    mean_ns = measure_batch(seal_bytes, batch_args)
                    seal_series_means.append(mean_ns)
                    raw_rows.append(
                        {
                            "backend": backend,
                            "algorithm": algorithm,
                            "size_bytes": size_bytes,
                            "operation": "encrypt",
                            "series": series_idx,
                            "operations_count": OPERATIONS_PER_SERIES,
                            "mean_ns": round(mean_ns, 2),
                        }
                    )

                seal_stats = summarize(seal_series_means, size_bytes)
                aggregates.append(
                    {
                        "backend": backend,
                        "algorithm": algorithm,
                        "size_bytes": size_bytes,
                        "operation": "encrypt",
                        **seal_stats,
                    }
                )

                # Прогрев расшифрования (каждый шифртекст подготовлен со своим nonce)
                warmup_open_args = []
                for _ in range(WARMUP):
                    n = nonces.next()
                    ct, tag = seal_bytes(
                        backend, algorithm, key, n, payload, BENCHMARK_AAD
                    )
                    warmup_open_args.append(
                        (backend, algorithm, key, n, ct, tag, BENCHMARK_AAD)
                    )
                measure_batch(open_bytes, warmup_open_args)

                open_series_means: list[float] = []
                for series_idx in range(1, SERIES + 1):
                    batch_open_args = []
                    for _ in range(OPERATIONS_PER_SERIES):
                        n = nonces.next()
                        ct, tag = seal_bytes(
                            backend, algorithm, key, n, payload, BENCHMARK_AAD
                        )
                        batch_open_args.append(
                            (backend, algorithm, key, n, ct, tag, BENCHMARK_AAD)
                        )
                    mean_ns = measure_batch(open_bytes, batch_open_args)
                    open_series_means.append(mean_ns)
                    raw_rows.append(
                        {
                            "backend": backend,
                            "algorithm": algorithm,
                            "size_bytes": size_bytes,
                            "operation": "decrypt",
                            "series": series_idx,
                            "operations_count": OPERATIONS_PER_SERIES,
                            "mean_ns": round(mean_ns, 2),
                        }
                    )

                open_stats = summarize(open_series_means, size_bytes)
                aggregates.append(
                    {
                        "backend": backend,
                        "algorithm": algorithm,
                        "size_bytes": size_bytes,
                        "operation": "decrypt",
                        **open_stats,
                    }
                )

    raw_csv_path = output_dir / "raw.csv"
    with raw_csv_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "backend",
                "algorithm",
                "size_bytes",
                "operation",
                "series",
                "operations_count",
                "mean_ns",
            ],
        )
        writer.writeheader()
        writer.writerows(raw_rows)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "methodology": {
            "warmup_operations": WARMUP,
            "series_count": SERIES,
            "operations_per_series": OPERATIONS_PER_SERIES,
            "sizes_bytes": list(SIZES_BYTES),
            "aad_length_bytes": len(BENCHMARK_AAD),
        },
        "environment": _environment_info(),
        "results": aggregates,
    }
    report_path = output_dir / "report.json"
    with report_path.open("w", encoding="utf-8") as json_file:
        json.dump(report, json_file, ensure_ascii=False, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Practice 2 symmetric benchmark")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        run_benchmark(args.output_dir)
    except NotImplementedError as exc:
        parser.exit(2, f"Практична 2: модуль вимірювань ще не реалізовано: {exc}\n")


if __name__ == "__main__":
    main()