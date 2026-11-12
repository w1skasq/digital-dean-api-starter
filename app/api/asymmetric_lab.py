"""Додайте новий маршрут та підключення до наявного app/main.py."""
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import ValidationError
from app.schemas.asymmetric_report import BenchmarkReport, validate_complete_report

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["asymmetric-lab"])
REPORT_PATH = Path(__file__).resolve().parents[2] / "results/practice-03/report.json"
MAX_REPORT_BYTES = 1048576  # Local teaching limit, not a universal JSON limit.


def _reject_constant(value: str):
    raise ValueError("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def load_report() -> BenchmarkReport:
    try:
        with REPORT_PATH.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("report too large")
        data = json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
        return validate_complete_report(data)
    except FileNotFoundError as exc:
        raise HTTPException(404, "benchmark report not found") from exc
    except (OSError, ValueError, ValidationError) as exc:
        raise HTTPException(500, "benchmark report invalid") from exc


def get_asymmetric_benchmark_results() -> BenchmarkReport:
    # TODO register @router.get("/asymmetric-benchmark-results", response_model=...)
    # TODO return validated report and implement the individual variant.
    # Do not import/run the benchmark here or accept a client file path.
    raise NotImplementedError("Implement the new API operation")
