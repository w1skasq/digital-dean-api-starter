"""Ці тести не потребують готових або вигаданих вимірювань."""
import pytest
from pydantic import ValidationError
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app.main import app
from app.api import asymmetric_lab as lab
from app.schemas.asymmetric_report import Experiment

ROUTE = "/api/v1/lab/crypto/asymmetric-benchmark-results"


def test_missing_report_reader(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "REPORT_PATH", tmp_path / "absent.json")
    with pytest.raises(HTTPException) as error:
        lab.load_report()
    assert error.value.status_code == 404
    assert error.value.detail == "benchmark report not found"


@pytest.mark.parametrize("raw", [b"{", b'{"x":1,"x":2}', b'{"x":NaN}', b"{}"])
def test_invalid_report_reader(tmp_path, monkeypatch, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    monkeypatch.setattr(lab, "REPORT_PATH", path)
    with pytest.raises(HTTPException) as error:
        lab.load_report()
    assert error.value.status_code == 500
    assert error.value.detail == "benchmark report invalid"


def test_route_registered():
    paths = app.openapi()["paths"]
    assert ROUTE in paths
    assert "get" in paths[ROUTE]


def test_api_missing_report(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "REPORT_PATH", tmp_path / "absent.json")
    response = TestClient(app).get(ROUTE)
    assert response.status_code == 404
    assert response.json() == {"detail": "benchmark report not found"}


def test_api_invalid_report(tmp_path, monkeypatch):
    path = tmp_path / "bad.json"
    path.write_bytes(b"not json")
    monkeypatch.setattr(lab, "REPORT_PATH", path)
    response = TestClient(app).get(ROUTE)
    assert response.status_code == 500
    assert response.json() == {"detail": "benchmark report invalid"}


@pytest.mark.parametrize("value", [True, 5.0, "5"])
def test_metadata_requires_exact_integer(value):
    metadata = dict(
        series=value, operations_per_series=20, warmup=10, keygen_runs=5,
        direct_payload_bytes=64, hybrid_sizes_bytes=[1024, 65536, 1048576],
        source_commit="0" * 40, created_at_utc="2026-10-07T00:00:00Z",
    )
    with pytest.raises(ValidationError):
        Experiment.model_validate(metadata)


def test_report_limit(tmp_path, monkeypatch):
    path = tmp_path / "oversize.json"
    path.write_bytes(b"x" * (lab.MAX_REPORT_BYTES + 1))
    monkeypatch.setattr(lab, "REPORT_PATH", path)
    with pytest.raises(HTTPException) as error:
        lab.load_report()
    assert error.value.status_code == 500
    assert error.value.detail == "benchmark report invalid"

# Add your own tests for valid measured report, duplicate result tuples,
# missing coverage, false correctness checks, numeric types/NaN/Inf,
# variant, report limit, no benchmark call and regressions of practicals 1/2.
