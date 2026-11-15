"""Новий маршрутизатор: зареєструйте GET і підключіть до наявного app/main.py."""
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import ValidationError
from app.schemas.hash_report import HashReport, HashResponse, validate_report

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["hash-lab"])
REPORT_PATH = Path(__file__).resolve().parents[2] / "results/practice-04/report.json"
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


def load_report() -> HashReport:
    try:
        with REPORT_PATH.open("rb") as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("report too large")
        data = json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
        return validate_report(data)
    except FileNotFoundError as exc:
        raise HTTPException(404, "hash report not found") from exc
    except (OSError, ValueError, ValidationError) as exc:
        raise HTTPException(500, "hash report invalid") from exc


def get_hash_benchmark_results() -> HashResponse:
    # TODO @router.get("/hash-benchmark-results", response_model=HashResponse)
    # TODO full validation BEFORE filtering and the student's own variant.
    # No arbitrary path, POST benchmark, input documents or benchmark imports.
    raise NotImplementedError("Implement the new hash results API operation")
