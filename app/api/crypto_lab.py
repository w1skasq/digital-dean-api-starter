"""Маршрут тільки читає звіт; не запускає вимірювання через HTTP."""

from pathlib import Path

from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/lab/crypto", tags=["crypto-lab"])
REPORT_PATH = Path(__file__).resolve().parents[2] / "results/practice-02/report.json"


def load_benchmark_report(path: Path) -> dict:
    """TODO: прочитати й перевірити report.json, не приймати шлях від клієнта."""
    raise NotImplementedError("Implement validated benchmark report reader")


# TODO: GET /benchmark-results, 200 із повним агрегованим звітом.
# TODO: відсутній файл: 404; пошкоджений: 500 із безпечним detail.
# TODO: detail="Benchmark results unavailable", без внутрішніх шляхів.
# TODO: path беріть із конфігурації; тест підмінює конфігурацію, не HTTP-вхід.
# TODO: підключіть router у своєму main.py після реалізації.
