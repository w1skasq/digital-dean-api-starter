"""HTTP-маршрут читання перевіреного звіту асиметричного експерименту (Варіант 0)."""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError

from app.schemas.asymmetric_report import (
    BenchmarkReport,
    BenchmarkResponse,
    ProfileId,
    validate_complete_report,
)

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
        data = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        return validate_complete_report(data)
    except FileNotFoundError as exc:
        raise HTTPException(404, "benchmark report not found") from exc
    except (OSError, ValueError, ValidationError) as exc:
        raise HTTPException(500, "benchmark report invalid") from exc


@router.get("/asymmetric-benchmark-results", response_model=BenchmarkResponse)
def get_asymmetric_benchmark_results(
    profile: ProfileId | None = Query(
        default=None,
        description="Необов'язковий фільтр результатів за криптографічним профілем (Варіант 0).",
    ),
) -> BenchmarkResponse:
    report = load_report()
    filtered_results = (
        [item for item in report.results if item.profile == profile]
        if profile is not None
        else list(report.results)
    )
    return BenchmarkResponse(
        schema_version=report.schema_version,
        experiment=report.experiment,
        environment=report.environment,
        key_generation=report.key_generation,
        results=filtered_results,
        checks=report.checks,
    )