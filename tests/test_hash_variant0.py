"""Additional student tests for Practice 4 (Variant 0, boundary chunks, and report invariants)."""
import copy
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.api import hash_lab
from app.main import app
from app.schemas.hash_report import validate_report
from app.security.hashing.adapters import hamming_bits, hash_bytes, prepare_operation
from app.security.hashing.profiles import CHUNK_BYTES, PROFILES, synthetic_payload
from tests.test_hash_report import synthetic_report


@pytest.mark.parametrize("size", [0, 1, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1, 65536])
def test_chunk_boundary_equivalence_and_fresh_state(size: int) -> None:
    payload = synthetic_payload(size)
    for algorithm, profile in PROFILES.items():
        op_whole = prepare_operation(algorithm, payload, "whole")
        op_chunked = prepare_operation(algorithm, payload, "chunked")
        d1 = op_whole()
        d2 = op_chunked()
        # Repeated call on the same prepared operation must create a fresh hasher state
        d3 = op_chunked()
        assert d1 == d2 == d3
        assert len(d1) == profile.digest_bytes
        assert hash_bytes(algorithm, payload, "chunked") == d1


def test_hamming_bits_validation_and_exact_count() -> None:
    assert hamming_bits(b"\x00\x00", b"\x00\x00") == 0
    assert hamming_bits(b"\xff\x00", b"\x00\xff") == 16
    assert hamming_bits(b"\x01", b"\x00") == 1

    with pytest.raises(TypeError):
        hamming_bits("00", b"\x00")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        hamming_bits(b"", b"")
    with pytest.raises(ValueError):
        hamming_bits(b"\x01\x02", b"\x01")


def test_validate_report_rejects_bad_utc_and_formula_mismatch() -> None:
    valid = synthetic_report()
    assert validate_report(valid).schema_version == 1

    non_utc = copy.deepcopy(valid)
    non_utc["created_at"] = "2026-11-16T01:00:00+02:00"
    with pytest.raises(ValueError):
        validate_report(non_utc)

    bad_tp = copy.deepcopy(valid)
    bad_tp["results"][0]["throughput_mib_s"] += 50.0
    with pytest.raises(ValueError):
        validate_report(bad_tp)

    bad_frac = copy.deepcopy(valid)
    bad_frac["avalanche"][0]["mean_fraction"] = 0.99
    with pytest.raises(ValueError):
        validate_report(bad_frac)


def test_api_variant_0_filter_unavailable_and_invalid_algorithm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report_data = synthetic_report()
    # Simulate environment where legacy sha1 is unavailable
    for st in report_data["algorithms"]:
        if st["algorithm"] == "sha1":
            st["available"] = False
            st["reason"] = "not_available_in_environment"
            st["implementation"] = None
    report_data["results"] = [r for r in report_data["results"] if r["algorithm"] != "sha1"]
    report_data["avalanche"] = [a for a in report_data["avalanche"] if a["algorithm"] != "sha1"]
    report_data["checks"] = [c for c in report_data["checks"] if c["algorithm"] != "sha1"]

    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps(report_data), encoding="utf-8")
    monkeypatch.setattr(hash_lab, "REPORT_PATH", report_file)

    client = TestClient(app)

    # Full report (A=6 -> 48 results)
    r_all = client.get("/api/v1/lab/crypto/hash-benchmark-results")
    assert r_all.status_code == 200
    body_all = r_all.json()
    assert len(body_all["algorithms"]) == 7
    assert len(body_all["results"]) == 48

    # Variant 0: filter by available algorithm -> 8 results, full algorithms/avalanche/checks
    r_sha256 = client.get("/api/v1/lab/crypto/hash-benchmark-results?algorithm=sha256")
    assert r_sha256.status_code == 200
    body_sha256 = r_sha256.json()
    assert len(body_sha256["results"]) == 8
    assert all(item["algorithm"] == "sha256" for item in body_sha256["results"])
    assert len(body_sha256["algorithms"]) == 7
    assert len(body_sha256["avalanche"]) == 6
    assert len(body_sha256["checks"]) == 36

    # Variant 0: known but unavailable legacy profile -> 200 with empty results
    r_sha1 = client.get("/api/v1/lab/crypto/hash-benchmark-results?algorithm=sha1")
    assert r_sha1.status_code == 200
    body_sha1 = r_sha1.json()
    assert body_sha1["results"] == []
    assert len(body_sha1["algorithms"]) == 7
    assert len(body_sha1["avalanche"]) == 6
    assert len(body_sha1["checks"]) == 36

    # Variant 0: unknown algorithm -> 422
    r_bad = client.get("/api/v1/lab/crypto/hash-benchmark-results?algorithm=keccak256")
    assert r_bad.status_code == 422
