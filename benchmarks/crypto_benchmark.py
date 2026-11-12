"""Заповніть функції за методикою практичної роботи, не вигадуйте результати."""

import argparse
from pathlib import Path

SIZES_BYTES = (1024, 65536, 1048576)
WARMUP = 10
SERIES = 5
OPERATIONS_PER_SERIES = 100
BENCHMARK_AAD = b"digital-dean-practice-02-benchmark".ljust(64, b".")


def measure_batch(operation, arguments) -> float:
    """TODO: perf_counter_ns, середній час серії; аргументи вже підготовлені."""
    raise NotImplementedError("Implement timed batches")


def summarize(series_mean_ns, size_bytes) -> dict:
    """TODO: медіана 5 середніх, inclusive IQR і МіБ/с за початковими байтами."""
    raise NotImplementedError("Implement aggregate statistics")


def run_benchmark(output_dir: Path) -> None:
    """TODO: шість комбінацій, 3 розміри, 2 операції; 180 серій, 36 агрегатів."""
    raise NotImplementedError("Implement experiment and verified result files")


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

# TODO: окремий випадковий ключ і спільний лічильник на бібліотеку/профіль.
# TODO: не повторюйте nonce під час прогрівання чи підготовки розшифрування.
# TODO: ключі, дані та контекст готують поза таймером; об’єкт шифру — всередині.
# TODO: raw.csv, report.json та фактичне середовище, без ключів і приміток.
