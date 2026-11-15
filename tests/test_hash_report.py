"""Синтетичні фікстури для тестів схеми; це НЕ дані експерименту студента."""
import copy
import json
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from app.api import hash_lab
from app.schemas.hash_report import validate_report
from app.security.hashing.profiles import CHECK_NAMES, PAYLOAD_SIZES, PROFILES

PATH = "/api/v1/lab/crypto/hash-benchmark-results"


def synthetic_report():
    results, avalanche, checks, statuses = [], [], [], []
    for algorithm, profile in PROFILES.items():
        statuses.append(dict(algorithm=algorithm, available=True,
                             reason=None, implementation="test.fixture"))
        for size in PAYLOAD_SIZES:
            for mode in ("whole", "chunked"):
                results.append(dict(algorithm=algorithm, mode=mode,
                    payload_bytes=size, digest_bytes=profile.digest_bytes,
                    repeats=100 if size == 1048576 else 1000,
                    median_ns=1000.0, iqr_ns=10.0,
                    throughput_mib_s=size * 1e9 / (2**20 * 1000.0)))
        n = 8 * profile.digest_bytes
        avalanche.append(dict(algorithm=algorithm, input_bytes=1024, trials=100,
            digest_bits=n, min_flipped_bits=n//2-1, max_flipped_bits=n//2+1,
            mean_flipped_bits=n/2, mean_fraction=0.5))
        checks.extend(dict(algorithm=algorithm, name=name, passed=True)
                      for name in CHECK_NAMES)
    return dict(schema_version=1, created_at="2026-10-23T00:00:00Z",
        source_commit="a"*40, environment=dict(python="test", openssl_ssl="test",
            os="test", cpu="test", architecture="test"),
        parameters=dict(sizes=list(PAYLOAD_SIZES), chunk_bytes=16384, warmup=10,
            series=5, repeats_small=1000, repeats_large=100,
            avalanche_trials=100, avalanche_bytes=1024),
        algorithms=statuses, results=results, avalanche=avalanche, checks=checks)


def test_complete_schema_and_preservation_of_failed_check():
    data = synthetic_report()
    data["checks"][0]["passed"] = False
    report = validate_report(data)
    assert len(report.results) == 56 and report.checks[0].passed is False


def test_absent_legacy_profiles_have_no_fake_results():
    data = synthetic_report()
    for row in data["algorithms"]:
        if row["algorithm"] in ("md5", "sha1"):
            row.update(available=False, reason="not_available_in_environment",
                       implementation=None)
    for field in ("results", "avalanche", "checks"):
        data[field] = [x for x in data[field]
                       if x["algorithm"] not in ("md5", "sha1")]
    assert len(validate_report(data).results) == 40


@pytest.mark.parametrize("path,value", [
    (("schema_version",), True), (("schema_version",), 1.0),
    (("source_commit",), "not-a-commit"),
    (("created_at",), "2026-10-23T00:00:00"),
    (("created_at",), "2026-02-30T00:00:00Z"),
    (("parameters", "sizes"), [64, 1024, 65536, 65536]),
    (("parameters", "series"), 5.0),
    (("results", 0, "payload_bytes"), 65),
    (("results", 0, "digest_bytes"), 64),
    (("results", 0, "repeats"), 100),
    (("results", 0, "median_ns"), float("nan")),
    (("results", 0, "median_ns"), True),
    (("results", 0, "throughput_mib_s"), 1.0),
    (("avalanche", 0, "mean_fraction"), 0.25),
    (("avalanche", 0, "max_flipped_bits"), 257),
    (("checks", 0, "passed"), "true"),
    (("algorithms", 0, "available"), False),
])
def test_rejects_structural_and_semantic_inconsistency(path, value):
    data = synthetic_report()
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        validate_report(data)


@pytest.mark.parametrize("field", ["results", "avalanche", "checks", "algorithms"])
def test_rejects_duplicate_records(field):
    data = synthetic_report()
    data[field][-1] = copy.deepcopy(data[field][0])
    with pytest.raises(ValueError):
        validate_report(data)


def test_rejects_extra_secret_field():
    data = synthetic_report()
    data["private_key"] = "must not be accepted"
    with pytest.raises(ValueError):
        validate_report(data)


@pytest.mark.parametrize("content,status,detail", [
    (None, 404, "hash report not found"),
    (b"broken JSON", 500, "hash report invalid"),
    (b'{"schema_version":1,"schema_version":1}', 500, "hash report invalid"),
    (b'{"n":NaN}', 500, "hash report invalid"),
    (b" " * 1048577, 500, "hash report invalid"),
])
def test_bounded_reader_safe_errors(tmp_path, monkeypatch, content, status, detail):
    path = tmp_path / "report.json"
    if content is not None:
        path.write_bytes(content)
    monkeypatch.setattr(hash_lab, "REPORT_PATH", path)
    with pytest.raises(HTTPException) as error:
        hash_lab.load_report()
    assert error.value.status_code == status and error.value.detail == detail


def test_new_route_reads_valid_report(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(synthetic_report()), encoding="utf-8")
    monkeypatch.setattr(hash_lab, "REPORT_PATH", path)
    app = FastAPI()
    app.include_router(hash_lab.router)
    response = TestClient(app).get(PATH)
    assert response.status_code == 200
    body = response.json()
    assert len(body["results"]) == 56 and len(body["checks"]) == 42


def test_route_connected_to_same_existing_application():
    from app.main import app
    assert PATH in TestClient(app).get("/openapi.json").json()["paths"]

# TODO Add tests of YOUR variant, missing matrix rows, timezone and raw/JSON
# consistency, finite measurements, no benchmark import/call in the HTTP route,
# and the earlier application's regressions. Do not delete or skip TODO tests.
