"""Тести семантичної схеми звіту, HTTP-маршруту та індивідуального Варіанта 0."""

import copy
import json

from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.api import asymmetric_lab as lab
from app.main import app
from app.schemas.asymmetric_report import (
    Experiment,
    expected_throughput_mib_s,
    validate_complete_report,
)
from app.security.asymmetric.profiles import PROFILES, expected_ciphertext_bytes
from benchmarks import asymmetric_benchmark

ROUTE = "/api/v1/lab/crypto/asymmetric-benchmark-results"


def _sample_complete_report() -> dict:
    key_generation = [
        {
            "key_profile": kp,
            "runs": 5,
            "median_ns": 12000.0 + idx * 100.0,
            "iqr_ns": 250.0,
            "public_key_der_bytes": 91 if kp == "p256" else (44 if kp == "x25519" else 294),
        }
        for idx, kp in enumerate(("rsa-2048", "rsa-3072", "x25519", "p256"))
    ]

    results = []
    for prof_name, spec in PROFILES.items():
        for size in spec.sizes:
            for op in ("encrypt", "decrypt"):
                med = 50000.0
                tp = None if spec.group == "direct" else round(expected_throughput_mib_s(size, med), 6)
                results.append(
                    {
                        "profile": prof_name,
                        "group": spec.group,
                        "operation": op,
                        "payload_bytes": size,
                        "series": 5,
                        "operations_per_series": 20,
                        "median_ns": med,
                        "iqr_ns": 500.0,
                        "ciphertext_bytes": expected_ciphertext_bytes(prof_name, size),
                        "throughput_mib_s": tp,
                    }
                )

    checks = []
    for prof_name in PROFILES:
        for name in ("roundtrip", "wrong_key", "tamper", "wrong_context"):
            checks.append({"profile": prof_name, "name": name, "passed": True})
    checks.append({"profile": "rsa2048-oaep", "name": "oaep_boundary", "passed": True})
    checks.append({"profile": "rsa3072-oaep", "name": "oaep_boundary", "passed": True})

    return {
        "schema_version": 1,
        "experiment": {
            "series": 5,
            "operations_per_series": 20,
            "warmup": 10,
            "keygen_runs": 5,
            "direct_payload_bytes": 64,
            "hybrid_sizes_bytes": [1024, 65536, 1048576],
            "source_commit": "a" * 40,
            "created_at_utc": "2026-10-07T12:00:00Z",
        },
        "environment": {
            "python": "3.14.3",
            "cryptography": "48.0.1",
            "openssl": "OpenSSL 3.5.0",
            "os": "Windows 11",
            "cpu": "x86_64",
        },
        "key_generation": key_generation,
        "results": results,
        "checks": checks,
    }


def test_missing_report_reader(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "REPORT_PATH", tmp_path / "absent.json")
    with pytest.raises(HTTPException) as error:
        lab.load_report()
    assert error.value.status_code == 404
    assert error.value.detail == "benchmark report not found"


@pytest.mark.parametrize("raw", [b"{", b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b"{}"])
def test_invalid_report_reader(tmp_path, monkeypatch, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    monkeypatch.setattr(lab, "REPORT_PATH", path)
    with pytest.raises(HTTPException) as error:
        lab.load_report()
    assert error.value.status_code == 500
    assert error.value.detail == "benchmark report invalid"


def test_route_registered():
    openapi = app.openapi()
    assert openapi["info"]["version"] == "0.3.0"
    paths = openapi["paths"]
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
        series=value,
        operations_per_series=20,
        warmup=10,
        keygen_runs=5,
        direct_payload_bytes=64,
        hybrid_sizes_bytes=[1024, 65536, 1048576],
        source_commit="0" * 40,
        created_at_utc="2026-10-07T00:00:00Z",
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


def test_semantic_validation_and_edge_cases():
    base = _sample_complete_report()
    validated = validate_complete_report(base)
    assert len(validated.results) == 22

    # Extra field rejected
    with_extra = copy.deepcopy(base)
    with_extra["unexpected"] = 123
    with pytest.raises(ValidationError):
        validate_complete_report(with_extra)

    # Duplicate result tuple rejected
    dup_res = copy.deepcopy(base)
    dup_res["results"][1] = copy.deepcopy(dup_res["results"][0])
    with pytest.raises(ValueError):
        validate_complete_report(dup_res)

    # Wrong throughput formula rejected
    bad_tp = copy.deepcopy(base)
    for item in bad_tp["results"]:
        if item["group"] == "hybrid":
            item["throughput_mib_s"] = 999999.0
            break
    with pytest.raises(ValueError):
        validate_complete_report(bad_tp)

    # Negative timing rejected
    neg_time = copy.deepcopy(base)
    neg_time["results"][0]["median_ns"] = -1.0
    with pytest.raises(ValidationError):
        validate_complete_report(neg_time)

    # False check is retained honestly, not hidden
    failed_chk = copy.deepcopy(base)
    failed_chk["checks"][0]["passed"] = False
    validated_failed = validate_complete_report(failed_chk)
    assert validated_failed.checks[0].passed is False


def test_api_valid_report_no_benchmark_and_variant_0(tmp_path, monkeypatch):
    report_data = _sample_complete_report()
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps(report_data), encoding="utf-8")
    monkeypatch.setattr(lab, "REPORT_PATH", report_file)

    def _forbid_benchmark(*args, **kwargs):
        raise AssertionError("HTTP endpoint must not invoke run_experiment")

    monkeypatch.setattr(asymmetric_benchmark, "run_experiment", _forbid_benchmark)

    client = TestClient(app)

    # Unfiltered complete response
    full_resp = client.get(ROUTE)
    assert full_resp.status_code == 200
    body = full_resp.json()
    assert body["schema_version"] == 1
    assert len(body["key_generation"]) == 4
    assert len(body["results"]) == 22
    assert len(body["checks"]) == 22

    # Variant 0: filter by direct profile (2 results, full key_generation and checks)
    direct_resp = client.get(ROUTE, params={"profile": "rsa2048-oaep"})
    assert direct_resp.status_code == 200
    direct_body = direct_resp.json()
    assert len(direct_body["key_generation"]) == 4
    assert len(direct_body["checks"]) == 22
    assert len(direct_body["results"]) == 2
    assert all(r["profile"] == "rsa2048-oaep" for r in direct_body["results"])

    # Variant 0: filter by hybrid profile (6 results, full key_generation and checks)
    hybrid_resp = client.get(ROUTE, params={"profile": "hpke-x25519-aes256gcm"})
    assert hybrid_resp.status_code == 200
    hybrid_body = hybrid_resp.json()
    assert len(hybrid_body["key_generation"]) == 4
    assert len(hybrid_body["checks"]) == 22
    assert len(hybrid_body["results"]) == 6
    assert all(r["profile"] == "hpke-x25519-aes256gcm" for r in hybrid_body["results"])

    # Variant 0: unknown profile rejected with 422
    bad_resp = client.get(ROUTE, params={"profile": "rsa1024-pkcs1"})
    assert bad_resp.status_code == 422