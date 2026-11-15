"""Локальний експеримент. У гілці немає готових виміряних результатів."""
import csv
import hashlib
import json
import platform
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from statistics import median, quantiles
from time import perf_counter_ns

from app.schemas.hash_report import validate_report
from app.security.hashing.adapters import hamming_bits, hash_bytes, prepare_operation
from app.security.hashing.profiles import (
    AVALANCHE_BYTES,
    AVALANCHE_TRIALS,
    CHUNK_BYTES,
    PAYLOAD_SIZES,
    PROFILES,
    SERIES,
    WARMUP,
    probe_profiles,
    repeat_count,
    synthetic_payload,
)

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "results" / "practice-04"

KNOWN_ABC = {
    "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "sha512": (
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    ),
    "sha3-256": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    "blake2b-256": "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    "blake2s-256": "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
    "md5": "900150983cd24fb0d6963f7d28e17f72",
    "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
}

KNOWN_EMPTY = {
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha512": (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    ),
    "sha3-256": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    "blake2b-256": "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
    "blake2s-256": "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
}


def measure_batch(operation, repeats: int) -> float:
    if type(repeats) is not int or repeats <= 0:
        raise ValueError("positive repeat count required")
    start = perf_counter_ns()
    for _ in range(repeats):
        operation()
    elapsed_ns = perf_counter_ns() - start
    return elapsed_ns / repeats


def _measure_series_raw(operation, repeats: int) -> tuple[int, float]:
    if type(repeats) is not int or repeats <= 0:
        raise ValueError("positive repeat count required")
    start = perf_counter_ns()
    for _ in range(repeats):
        operation()
    elapsed_ns = perf_counter_ns() - start
    if elapsed_ns <= 0:
        elapsed_ns = 1
    return elapsed_ns, elapsed_ns / repeats


def summarize(samples: list[float]) -> tuple[float, float]:
    if len(samples) != 5:
        raise ValueError("five series required")
    q1, _, q3 = quantiles(samples, n=4, method="inclusive")
    return median(samples), q3 - q1


def _require_clean_git_commit() -> str:
    status = subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=ROOT, text=True
    ).strip()
    if status:
        raise RuntimeError(
            "Working tree is not clean. Commit all code changes before running benchmark."
        )
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if len(commit) != 40:
        raise RuntimeError("Failed to read 40-char HEAD commit SHA")
    return commit


def _run_correctness_checks(algorithm: str, payloads: dict[int, bytes]) -> list[dict]:
    expected_len = PROFILES[algorithm].digest_bytes
    unicode_bytes = "Цифровий деканат — відомість №4 🇺🇦".encode("utf-8")

    # Independent reference constructor for UTF-8 check
    if algorithm == "blake2b-256":
        ref_unicode = hashlib.blake2b(unicode_bytes, digest_size=32).digest()
    elif algorithm == "blake2s-256":
        ref_unicode = hashlib.blake2s(unicode_bytes, digest_size=32).digest()
    elif algorithm in ("md5", "sha1"):
        ref_unicode = getattr(hashlib, algorithm)(
            unicode_bytes, usedforsecurity=False
        ).digest()
    else:
        ref_unicode = getattr(hashlib, algorithm.replace("-", "_"))(
            unicode_bytes
        ).digest()

    d1 = hash_bytes(algorithm, payloads[1024], "whole")
    _ = hash_bytes(algorithm, payloads[64], "chunked")
    d2 = hash_bytes(algorithm, payloads[1024], "whole")

    stream_ok = all(
        hash_bytes(algorithm, payloads[sz], "whole")
        == hash_bytes(algorithm, payloads[sz], "chunked")
        for sz in PAYLOAD_SIZES
    )

    checks = [
        ("known-abc", hash_bytes(algorithm, b"abc", "whole").hex() == KNOWN_ABC[algorithm]),
        ("known-empty", hash_bytes(algorithm, b"", "whole").hex() == KNOWN_EMPTY[algorithm]),
        ("unicode-utf8", hash_bytes(algorithm, unicode_bytes, "whole") == ref_unicode),
        ("determinism", d1 == d2),
        ("digest-length", len(d1) == expected_len),
        ("stream-equivalence", stream_ok),
    ]
    return [
        {"algorithm": algorithm, "name": name, "passed": bool(passed)}
        for name, passed in checks
    ]


def _run_avalanche(algorithm: str, base_payload: bytes) -> tuple[dict, list[dict]]:
    digest_bits = PROFILES[algorithm].digest_bytes * 8
    orig_digest = hash_bytes(algorithm, base_payload, "whole")
    raw_rows: list[dict] = []
    distances: list[int] = []

    for bit_index in range(AVALANCHE_TRIALS):
        mutated = bytearray(base_payload)
        mutated[bit_index // 8] ^= 1 << (bit_index % 8)
        mut_digest = hash_bytes(algorithm, bytes(mutated), "whole")
        dist = hamming_bits(orig_digest, mut_digest)
        frac = dist / digest_bits
        distances.append(dist)
        raw_rows.append(
            {
                "algorithm": algorithm,
                "trial": bit_index + 1,
                "bit_index": bit_index,
                "digest_bits": digest_bits,
                "flipped_bits": dist,
                "fraction": frac,
            }
        )

    mean_dist = sum(distances) / len(distances)
    summary = {
        "algorithm": algorithm,
        "input_bytes": AVALANCHE_BYTES,
        "trials": AVALANCHE_TRIALS,
        "digest_bits": digest_bits,
        "min_flipped_bits": min(distances),
        "max_flipped_bits": max(distances),
        "mean_flipped_bits": mean_dist,
        "mean_fraction": mean_dist / digest_bits,
    }
    return summary, raw_rows


def run_experiment() -> None:
    source_commit = _require_clean_git_commit()
    statuses = probe_profiles()
    available_algos = [s["algorithm"] for s in statuses if s["available"]]

    # Pre-build synthetic payloads outside all timers
    payloads = {sz: synthetic_payload(sz) for sz in PAYLOAD_SIZES}
    avalanche_input = synthetic_payload(AVALANCHE_BYTES)

    raw_perf_rows: list[dict] = []
    perf_results: list[dict] = []
    avalanche_results: list[dict] = []
    all_checks: list[dict] = []

    for alg in available_algos:
        digest_bytes = PROFILES[alg].digest_bytes
        for mode in ("whole", "chunked"):
            for sz in PAYLOAD_SIZES:
                repeats = repeat_count(sz)
                op = prepare_operation(alg, payloads[sz], mode)

                # Warmup outside timer
                for _ in range(WARMUP):
                    op()

                series_means: list[float] = []
                for series_idx in range(1, SERIES + 1):
                    elapsed_ns, ns_per_op = _measure_series_raw(op, repeats)
                    series_means.append(ns_per_op)
                    raw_perf_rows.append(
                        {
                            "algorithm": alg,
                            "mode": mode,
                            "payload_bytes": sz,
                            "series": series_idx,
                            "repeats": repeats,
                            "elapsed_ns": elapsed_ns,
                            "ns_per_op": ns_per_op,
                        }
                    )

                med_ns, iqr_ns = summarize(series_means)
                throughput = sz * 1e9 / ((2**20) * med_ns)
                perf_results.append(
                    {
                        "algorithm": alg,
                        "mode": mode,
                        "payload_bytes": sz,
                        "digest_bytes": digest_bytes,
                        "repeats": repeats,
                        "median_ns": med_ns,
                        "iqr_ns": iqr_ns,
                        "throughput_mib_s": throughput,
                    }
                )

        av_summary, av_rows = _run_avalanche(alg, avalanche_input)
        avalanche_results.append(av_summary)
        raw_perf_rows_av = av_rows
        if alg == available_algos[0]:
            all_avalanche_rows = list(raw_perf_rows_av)
        else:
            all_avalanche_rows.extend(raw_perf_rows_av)

        all_checks.extend(_run_correctness_checks(alg, payloads))

    report_dict = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_commit": source_commit,
        "parameters": {
            "sizes": list(PAYLOAD_SIZES),
            "chunk_bytes": CHUNK_BYTES,
            "warmup": WARMUP,
            "series": SERIES,
            "repeats_small": repeat_count(64),
            "repeats_large": repeat_count(1048576),
            "avalanche_trials": AVALANCHE_TRIALS,
            "avalanche_bytes": AVALANCHE_BYTES,
        },
        "environment": {
            "python": sys.version.split()[0],
            "openssl_ssl": ssl.OPENSSL_VERSION,
            "os": f"{platform.system()} {platform.release()}",
            "cpu": platform.processor() or platform.machine(),
            "architecture": platform.machine(),
        },
        "algorithms": statuses,
        "results": perf_results,
        "avalanche": avalanche_results,
        "checks": all_checks,
    }

    validated = validate_report(report_dict)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with (OUT_DIR / "raw.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "algorithm",
                "mode",
                "payload_bytes",
                "series",
                "repeats",
                "elapsed_ns",
                "ns_per_op",
            ],
        )
        writer.writeheader()
        writer.writerows(raw_perf_rows)

    with (OUT_DIR / "avalanche.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "algorithm",
                "trial",
                "bit_index",
                "digest_bits",
                "flipped_bits",
                "fraction",
            ],
        )
        writer.writeheader()
        writer.writerows(all_avalanche_rows)

    (OUT_DIR / "report.json").write_text(
        json.dumps(validated.model_dump(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    if any(not chk["passed"] for chk in all_checks):
        raise SystemExit("One or more correctness checks failed; diagnostic report saved.")


if __name__ == "__main__":
    try:
        run_experiment()
    except NotImplementedError as exc:
        raise SystemExit(str(exc)) from None