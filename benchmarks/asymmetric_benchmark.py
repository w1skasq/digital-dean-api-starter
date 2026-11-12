"""Окремий обчислювальний експеримент практичної 3 (не викликається з HTTP)."""

import argparse
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
from time import perf_counter_ns

import cryptography
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives import serialization

from app.schemas.asymmetric_report import expected_throughput_mib_s, validate_complete_report
from app.security.asymmetric.adapters import (
    DecryptionError,
    decrypt,
    encrypt,
    generate_keypair,
)
from app.security.asymmetric.profiles import (
    CONTEXT,
    DIRECT_SIZE,
    HYBRID_SIZES,
    KEY_PROFILES,
    PROFILES,
    expected_ciphertext_bytes,
    oaep_max_bytes,
)

SERIES = 5
OPERATIONS = 20
WARMUP = 10
KEYGEN_RUNS = 5
CSV_COLUMNS = (
    "group",
    "profile",
    "operation",
    "payload_bytes",
    "series_index",
    "operations",
    "elapsed_ns",
    "ns_per_operation",
    "ciphertext_bytes",
)

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[1] / "results" / "practice-03"


def measure_batch(operation, count: int = OPERATIONS) -> tuple[int, float]:
    if count < 1:
        raise ValueError("count must be positive")
    started = perf_counter_ns()
    for _ in range(count):
        operation()
    elapsed = perf_counter_ns() - started
    return elapsed, elapsed / count


def summarize(samples: list[float]) -> tuple[float, float]:
    if len(samples) != SERIES:
        raise ValueError("five series required")
    q1, _, q3 = statistics.quantiles(samples, n=4, method="inclusive")
    return float(statistics.median(samples)), float(q3 - q1)


def _git_head_sha(repo_root: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if len(out) == 40:
            return out.lower()
    except Exception:
        pass
    return "0" * 40


def _collect_environment() -> dict[str, str]:
    cpu_name = platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER") or platform.machine() or "unknown-cpu"
    os_name = f"{platform.system()} {platform.release()} ({platform.machine()})"
    return {
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": openssl_backend.openssl_version_text(),
        "os": os_name[:150],
        "cpu": cpu_name[:200],
    }


def _public_der_length(public: object) -> int:
    der = public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return len(der)


def _run_correctness_checks(recipient_keys: dict[str, tuple[object, object]]) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    for prof_name, spec in PROFILES.items():
        private, public = recipient_keys[spec.key_profile]

        # 1. roundtrip across all sizes for this profile
        roundtrip_ok = True
        try:
            for size in spec.sizes:
                msg = os.urandom(size)
                env = encrypt(prof_name, public, msg, context=CONTEXT)
                if len(env) != expected_ciphertext_bytes(prof_name, size):
                    roundtrip_ok = False
                restored = decrypt(prof_name, private, env, context=CONTEXT)
                if restored != msg:
                    roundtrip_ok = False
        except Exception:
            roundtrip_ok = False
        checks.append({"profile": prof_name, "name": "roundtrip", "passed": roundtrip_ok})

        # 2. wrong_key
        wrong_key_ok = False
        try:
            other_priv, _ = generate_keypair(spec.key_profile)
            env = encrypt(prof_name, public, b"synthetic-check-record", context=CONTEXT)
            try:
                decrypt(prof_name, other_priv, env, context=CONTEXT)
            except DecryptionError:
                wrong_key_ok = True
        except Exception:
            wrong_key_ok = False
        checks.append({"profile": prof_name, "name": "wrong_key", "passed": wrong_key_ok})

        # 3. tamper (flip last byte)
        tamper_ok = False
        try:
            env = encrypt(prof_name, public, b"synthetic-check-record", context=CONTEXT)
            tampered = env[:-1] + bytes([env[-1] ^ 0x01])
            try:
                decrypt(prof_name, private, tampered, context=CONTEXT)
            except DecryptionError:
                tamper_ok = True
        except Exception:
            tamper_ok = False
        checks.append({"profile": prof_name, "name": "tamper", "passed": tamper_ok})

        # 4. wrong_context
        wrong_ctx_ok = False
        try:
            env = encrypt(prof_name, public, b"synthetic-check-record", context=CONTEXT)
            try:
                decrypt(prof_name, private, env, context=b"digital-dean:practice-03:wrong-context")
            except DecryptionError:
                wrong_ctx_ok = True
        except Exception:
            wrong_ctx_ok = False
        checks.append({"profile": prof_name, "name": "wrong_context", "passed": wrong_ctx_ok})

    # 5. oaep_boundary for direct RSA profiles
    for bits, prof_name in ((2048, "rsa2048-oaep"), (3072, "rsa3072-oaep")):
        private, public = recipient_keys[f"rsa-{bits}"]
        limit = oaep_max_bytes(bits)
        boundary_ok = False
        try:
            max_msg = b"m" * limit
            env = encrypt(prof_name, public, max_msg, context=CONTEXT)
            if decrypt(prof_name, private, env, context=CONTEXT) == max_msg:
                try:
                    encrypt(prof_name, public, b"m" * (limit + 1), context=CONTEXT)
                except ValueError:
                    boundary_ok = True
        except Exception:
            boundary_ok = False
        checks.append({"profile": prof_name, "name": "oaep_boundary", "passed": boundary_ok})

    return checks


def _atomic_write_text(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.with_name(f".{target.name}.tmp.{os.getpid()}")
    tmp_path.write_text(content, encoding="utf-8", newline="\n")
    os.replace(tmp_path, target)


def run_experiment(output_dir: Path = DEFAULT_OUTPUT_DIR) -> dict[str, object]:
    repo_root = Path(__file__).resolve().parents[1]
    source_commit = _git_head_sha(repo_root)
    env_info = _collect_environment()

    raw_rows: list[dict[str, object]] = []
    keygen_summary: list[dict[str, object]] = []

    # 1. Key generation measurements (4 profiles x 5 independent runs = 20 CSV rows)
    for key_prof in KEY_PROFILES:
        # Warmup keypair outside measurements
        _ = generate_keypair(key_prof)

        samples: list[float] = []
        der_size = 0
        for series_idx in range(1, SERIES + 1):
            started = perf_counter_ns()
            priv, pub = generate_keypair(key_prof)
            elapsed = perf_counter_ns() - started
            if series_idx == 1:
                der_size = _public_der_length(pub)
            samples.append(float(elapsed))
            raw_rows.append(
                {
                    "group": "key_generation",
                    "profile": key_prof,
                    "operation": "keygen",
                    "payload_bytes": 0,
                    "series_index": series_idx,
                    "operations": 1,
                    "elapsed_ns": elapsed,
                    "ns_per_operation": float(elapsed),
                    "ciphertext_bytes": 0,
                }
            )

        med_ns, iqr_ns = summarize(samples)
        keygen_summary.append(
            {
                "key_profile": key_prof,
                "runs": KEYGEN_RUNS,
                "median_ns": med_ns,
                "iqr_ns": iqr_ns,
                "public_key_der_bytes": der_size,
            }
        )

    # Recipient keys for encrypt/decrypt created outside timer
    recipient_keys = {kp: generate_keypair(kp) for kp in KEY_PROFILES}

    # Pre-build synthetic payloads outside timer
    payloads: dict[int, bytes] = {
        size: os.urandom(size) for size in (DIRECT_SIZE, *HYBRID_SIZES)
    }

    # Collect per-(profile, operation, payload_bytes) series averages
    series_samples: dict[tuple[str, str, int], list[float]] = {}

    def _measure_group(group_profiles: tuple[str, ...], sizes: tuple[int, ...]) -> None:
        # Warmup for every combination (outside CSV)
        for prof_name in group_profiles:
            spec = PROFILES[prof_name]
            priv, pub = recipient_keys[spec.key_profile]
            for size in sizes:
                msg = payloads[size]
                for _ in range(WARMUP):
                    env = encrypt(prof_name, pub, msg, context=CONTEXT)
                    _ = decrypt(prof_name, priv, env, context=CONTEXT)

        # 5 series with cyclic rotation of profile order
        for series_idx in range(1, SERIES + 1):
            shift = (series_idx - 1) % len(group_profiles)
            rotated = group_profiles[shift:] + group_profiles[:shift]
            for size in sizes:
                msg = payloads[size]
                for prof_name in rotated:
                    spec = PROFILES[prof_name]
                    priv, pub = recipient_keys[spec.key_profile]
                    ct_len = expected_ciphertext_bytes(prof_name, size)

                    # Encrypt batch
                    enc_elapsed, enc_per_op = measure_batch(
                        lambda p=prof_name, k=pub, m=msg: encrypt(p, k, m, context=CONTEXT),
                        OPERATIONS,
                    )
                    series_samples.setdefault((prof_name, "encrypt", size), []).append(enc_per_op)
                    raw_rows.append(
                        {
                            "group": spec.group,
                            "profile": prof_name,
                            "operation": "encrypt",
                            "payload_bytes": size,
                            "series_index": series_idx,
                            "operations": OPERATIONS,
                            "elapsed_ns": enc_elapsed,
                            "ns_per_operation": enc_per_op,
                            "ciphertext_bytes": ct_len,
                        }
                    )

                    # Prepare 20 envelopes outside timer, then measure decrypt batch
                    envelopes = [
                        encrypt(prof_name, pub, msg, context=CONTEXT) for _ in range(OPERATIONS)
                    ]
                    idx = 0

                    def _dec_step(p=prof_name, k=priv, envs=envelopes):
                        nonlocal idx
                        res = decrypt(p, k, envs[idx], context=CONTEXT)
                        idx += 1
                        return res

                    dec_elapsed, dec_per_op = measure_batch(_dec_step, OPERATIONS)
                    # Verify decrypted output after stopping timer
                    assert decrypt(prof_name, priv, envelopes[-1], context=CONTEXT) == msg

                    series_samples.setdefault((prof_name, "decrypt", size), []).append(dec_per_op)
                    raw_rows.append(
                        {
                            "group": spec.group,
                            "profile": prof_name,
                            "operation": "decrypt",
                            "payload_bytes": size,
                            "series_index": series_idx,
                            "operations": OPERATIONS,
                            "elapsed_ns": dec_elapsed,
                            "ns_per_operation": dec_per_op,
                            "ciphertext_bytes": ct_len,
                        }
                    )

    # 2. Direct RSA (2 profiles x 64B x 2 ops x 5 series = 20 CSV rows)
    _measure_group(("rsa2048-oaep", "rsa3072-oaep"), (DIRECT_SIZE,))

    # 3. Hybrid schemes (3 profiles x 3 sizes x 2 ops x 5 series = 90 CSV rows)
    _measure_group(
        ("rsa3072-oaep-aes256gcm", "hpke-x25519-aes256gcm", "hpke-p256-aes256gcm"),
        HYBRID_SIZES,
    )

    assert len(raw_rows) == 130, f"expected 130 raw rows, got {len(raw_rows)}"

    # Aggregate 22 combinations in deterministic profile/size/operation order
    results_summary: list[dict[str, object]] = []
    for prof_name, spec in PROFILES.items():
        for size in spec.sizes:
            for op in ("encrypt", "decrypt"):
                med_ns, iqr_ns = summarize(series_samples[(prof_name, op, size)])
                tp = (
                    None
                    if spec.group == "direct"
                    else round(expected_throughput_mib_s(size, med_ns), 6)
                )
                results_summary.append(
                    {
                        "profile": prof_name,
                        "group": spec.group,
                        "operation": op,
                        "payload_bytes": size,
                        "series": SERIES,
                        "operations_per_series": OPERATIONS,
                        "median_ns": med_ns,
                        "iqr_ns": iqr_ns,
                        "ciphertext_bytes": expected_ciphertext_bytes(prof_name, size),
                        "throughput_mib_s": tp,
                    }
                )

    checks = _run_correctness_checks(recipient_keys)
    created_at_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    report_payload: dict[str, object] = {
        "schema_version": 1,
        "experiment": {
            "series": SERIES,
            "operations_per_series": OPERATIONS,
            "warmup": WARMUP,
            "keygen_runs": KEYGEN_RUNS,
            "direct_payload_bytes": DIRECT_SIZE,
            "hybrid_sizes_bytes": list(HYBRID_SIZES),
            "source_commit": source_commit,
            "created_at_utc": created_at_utc,
        },
        "environment": env_info,
        "key_generation": keygen_summary,
        "results": results_summary,
        "checks": checks,
    }

    # Validate before writing anything to disk
    validated = validate_complete_report(report_payload)
    validated_dict = validated.model_dump()

    # Serialize CSV in memory and write atomically
    from io import StringIO

    csv_buf = StringIO()
    writer = csv.DictWriter(csv_buf, fieldnames=list(CSV_COLUMNS), lineterminator="\n")
    writer.writeheader()
    writer.writerows(raw_rows)

    _atomic_write_text(output_dir / "raw.csv", csv_buf.getvalue())
    _atomic_write_text(
        output_dir / "report.json",
        json.dumps(validated_dict, indent=2, ensure_ascii=False) + "\n",
    )
    return validated_dict


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Practice 03 asymmetric crypto benchmark")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to write raw.csv and report.json",
    )
    args = parser.parse_args(argv)
    try:
        run_experiment(output_dir=args.output_dir)
    except NotImplementedError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())