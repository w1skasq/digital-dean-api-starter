"""Маршрут тільки читає звіт; не запускає вимірювання через HTTP."""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["crypto-lab"])
REPORT_PATH = Path(__file__).resolve().parents[2] / "results/practice-02/report.json"
UNAVAILABLE_DETAIL = "Benchmark results unavailable"

REQUIRED_KEYS = {"generated_at", "methodology", "environment", "results"}
REQUIRED_ITEM_KEYS = {
    "backend",
    "algorithm",
    "size_bytes",
    "operation",
    "median_ns",
    "iqr_ns",
    "throughput_mib_s",
}


def load_benchmark_report(path: Path) -> dict:
    """Прочитати й перевірити report.json, не приймати шлях від клієнта."""
    if not path.is_file():
        raise FileNotFoundError("Benchmark report not found")

    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Corrupted benchmark report") from exc

    if not isinstance(data, dict) or not REQUIRED_KEYS.issubset(data.keys()):
        raise ValueError("Invalid report schema")
    if not isinstance(data["methodology"], dict) or not isinstance(
        data["environment"], dict
    ):
        raise ValueError("Invalid report metadata")
    results = data["results"]
    if not isinstance(results, list) or len(results) == 0:
        raise ValueError("Empty or invalid results list")

    for item in results:
        if not isinstance(item, dict) or not REQUIRED_ITEM_KEYS.issubset(item.keys()):
            raise ValueError("Invalid benchmark aggregate entry")
        if (
            not isinstance(item["median_ns"], (int, float))
            or not isinstance(item["iqr_ns"], (int, float))
            or not isinstance(item["throughput_mib_s"], (int, float))
        ):
            raise ValueError("Invalid numeric metrics in report")

    return data


@router.get("/benchmark-results", status_code=status.HTTP_200_OK)
def get_benchmark_results() -> dict:
    try:
        return load_benchmark_report(REPORT_PATH)
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=UNAVAILABLE_DETAIL,
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=UNAVAILABLE_DETAIL,
        ) from exc