"""Новий маршрутизатор: зареєструйте GET і підключіть до наявного app/main.py."""
import json
from pathlib import Path
from typing import Annotated
from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError
from app.schemas.hash_report import HashReport, HashResponse, validate_report
from app.security.hashing.profiles import AlgorithmID

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
        data = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        return validate_report(data)
    except FileNotFoundError as exc:
        raise HTTPException(404, "hash report not found") from exc
    except (OSError, ValueError, ValidationError) as exc:
        raise HTTPException(500, "hash report invalid") from exc


@router.get(
    "/hash-benchmark-results",
    response_model=HashResponse,
    summary="Отримати перевірені результати дослідження алгоритмів хешування",
    description=(
        "Повертає валідований звіт експерименту хешування. "
        "Варіант 0: необов'язковий параметр `algorithm` фільтрує масив `results` "
        "за одним із 7 фіксованих ідентифікаторів профілів."
    ),
)
def get_hash_benchmark_results(
    algorithm: Annotated[
        AlgorithmID | None,
        Query(
            description="Необов'язковий фільтр за ідентифікатором профілю (Варіант 0)."
        ),
    ] = None,
) -> HashResponse:
    report = load_report()
    payload = report.model_dump()
    if algorithm is not None:
        payload["results"] = [
            item for item in payload["results"] if item["algorithm"] == algorithm
        ]
    return HashResponse.model_validate(payload)