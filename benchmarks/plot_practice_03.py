"""Генерація двох SVG-графіків за даними results/practice-03/report.json."""

import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "results" / "practice-03" / "report.json"
OUT_DIR = ROOT / "results" / "practice-03"


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_hybrid_latency_svg(report: dict) -> str:
    # Графік 1: Медіанний час encrypt та decrypt (мкс) для гібридних схем на 1 KiB, 64 KiB, 1 MiB
    profiles = [
        ("rsa3072-oaep-aes256gcm", "RSA-3072 + AES-256-GCM", "#d95f02"),
        ("hpke-x25519-aes256gcm", "HPKE X25519 + AES-256-GCM", "#1b9e77"),
        ("hpke-p256-aes256gcm", "HPKE P-256 + AES-256-GCM", "#7570b3"),
    ]
    sizes = [
        (1024, "1 KiB (1024 Б)"),
        (65536, "64 KiB (65536 Б)"),
        (1048576, "1 MiB (1048576 Б)"),
    ]
    lookup = {
        (r["profile"], r["operation"], r["payload_bytes"]): r["median_ns"] / 1000.0
        for r in report["results"]
    }

    w, h = 980, 500
    margin_l, margin_r, margin_t, margin_b = 85, 30, 75, 115
    plot_w = w - margin_l - margin_r
    plot_h = h - margin_t - margin_b
    max_val = 3200.0  # мкс

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{w/2}" y="28" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" font-size="16" font-weight="bold" fill="#111">'
        "Медіанний час шифрування та розшифрування гібридних схем (мкс, менше — краще)</text>",
        f'<text x="{w/2}" y="48" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" font-size="11" fill="#555">'
        "Джерело: results/practice-03/report.json (5 серій × 20 операцій, commit 9d3beec)</text>",
    ]

    for tick in range(0, 3201, 400):
        y = margin_t + plot_h - (tick / max_val) * plot_h
        lines.append(
            f'<line x1="{margin_l}" y1="{y:.1f}" x2="{w - margin_r}" y2="{y:.1f}" stroke="#e5e7eb" stroke-width="1"/>'
        )
        lines.append(
            f'<text x="{margin_l - 8}" y="{y + 4:.1f}" text-anchor="end" font-family="Segoe UI, Arial, sans-serif" font-size="11" fill="#374151">{tick}</text>'
        )

    lines.append(
        f'<text x="22" y="{margin_t + plot_h/2}" transform="rotate(-90 22,{margin_t + plot_h/2})" text-anchor="middle" '
        'font-family="Segoe UI, Arial, sans-serif" font-size="12" font-weight="bold" fill="#111">Медіанний час на операцію, мкс</text>'
    )

    groups = [(sz, sz_lbl, op) for sz, sz_lbl in sizes for op in ("encrypt", "decrypt")]
    group_w = plot_w / len(groups)
    bar_w = 30

    for g_idx, (sz, sz_lbl, op) in enumerate(groups):
        gx = margin_l + g_idx * group_w
        cx = gx + group_w / 2
        if g_idx > 0:
            lines.append(
                f'<line x1="{gx:.1f}" y1="{margin_t}" x2="{gx:.1f}" y2="{margin_t + plot_h}" stroke="#f3f4f6" stroke-width="1"/>'
            )

        for p_idx, (prof_id, _, color) in enumerate(profiles):
            val = lookup[(prof_id, op, sz)]
            bh = (val / max_val) * plot_h
            bx = cx - (1.5 * bar_w) + p_idx * (bar_w + 3)
            by = margin_t + plot_h - bh
            lines.append(
                f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w}" height="{bh:.1f}" fill="{color}" rx="2"/>'
            )
            lines.append(
                f'<text x="{bx + bar_w/2:.1f}" y="{by - 4:.1f}" text-anchor="middle" '
                f'font-family="Segoe UI, Arial, sans-serif" font-size="9.5" fill="#111">{val:.0f}</text>'
            )

        lines.append(
            f'<text x="{cx:.1f}" y="{margin_t + plot_h + 18}" text-anchor="middle" '
            f'font-family="Segoe UI, Arial, sans-serif" font-size="11" font-weight="bold" fill="#111">{op}</text>'
        )
        if op == "encrypt":
            lines.append(
                f'<text x="{gx + group_w:.1f}" y="{margin_t + plot_h + 36}" text-anchor="middle" '
                f'font-family="Segoe UI, Arial, sans-serif" font-size="11" fill="#374151">{_esc(sz_lbl)}</text>'
            )

    lines.append(
        f'<line x1="{margin_l}" y1="{margin_t}" x2="{margin_l}" y2="{margin_t + plot_h}" stroke="#374151" stroke-width="1.5"/>'
    )
    lines.append(
        f'<line x1="{margin_l}" y1="{margin_t + plot_h}" x2="{w - margin_r}" y2="{margin_t + plot_h}" stroke="#374151" stroke-width="1.5"/>'
    )

    lx = margin_l
    ly = h - 32
    for prof_id, label, color in profiles:
        lines.append(f'<rect x="{lx}" y="{ly - 11}" width="14" height="14" fill="{color}" rx="2"/>')
        lines.append(
            f'<text x="{lx + 20}" y="{ly}" font-family="Segoe UI, Arial, sans-serif" font-size="11.5" fill="#111">{_esc(label)}</text>'
        )
        lx += 290

    lines.append("</svg>")
    return "\n".join(lines)


def build_keygen_and_direct_svg(report: dict) -> str:
    # Графік 2: Час генерації ключів (мкс, логарифмічна шкала) та розмір публічного ключа DER (байти)
    kg_map = {item["key_profile"]: item for item in report["key_generation"]}
    items = [
        ("rsa-2048", "RSA-2048", "#d95f02"),
        ("rsa-3072", "RSA-3072", "#e7298a"),
        ("x25519", "X25519", "#1b9e77"),
        ("p256", "ECDH P-256", "#7570b3"),
    ]

    w, h = 920, 440
    margin_l, margin_r, margin_t, margin_b = 95, 35, 75, 95
    plot_w = w - margin_l - margin_r
    plot_h = h - margin_t - margin_b
    min_exp, max_exp = 1.0, 6.0

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{w/2}" y="28" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" font-size="16" font-weight="bold" fill="#111">'
        "Медіанний час генерації ключової пари (мкс, логарифмічна шкала) та розмір DER-ключа</text>",
        f'<text x="{w/2}" y="48" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" font-size="11" fill="#555">'
        "Джерело: results/practice-03/report.json (5 незалежних запусків на профіль ключа)</text>",
    ]

    for exp in range(1, 7):
        val_us = 10**exp
        y = margin_t + plot_h - ((exp - min_exp) / (max_exp - min_exp)) * plot_h
        lines.append(
            f'<line x1="{margin_l}" y1="{y:.1f}" x2="{w - margin_r}" y2="{y:.1f}" stroke="#e5e7eb" stroke-width="1"/>'
        )
        lbl = f"{val_us:,}".replace(",", " ")
        lines.append(
            f'<text x="{margin_l - 8}" y="{y + 4:.1f}" text-anchor="end" font-family="Segoe UI, Arial, sans-serif" font-size="11" fill="#374151">{lbl} мкс</text>'
        )

    lines.append(
        f'<text x="22" y="{margin_t + plot_h/2}" transform="rotate(-90 22,{margin_t + plot_h/2})" text-anchor="middle" '
        'font-family="Segoe UI, Arial, sans-serif" font-size="12" font-weight="bold" fill="#111">Час генерації ключа, мкс (log10)</text>'
    )

    col_w = plot_w / len(items)
    bar_w = 78
    for idx, (kp, title, color) in enumerate(items):
        rec = kg_map[kp]
        us = rec["median_ns"] / 1000.0
        der = rec["public_key_der_bytes"]
        exp_val = math.log10(us)
        bh = ((exp_val - min_exp) / (max_exp - min_exp)) * plot_h
        cx = margin_l + idx * col_w + col_w / 2
        bx = cx - bar_w / 2
        by = margin_t + plot_h - bh

        lines.append(
            f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w}" height="{bh:.1f}" fill="{color}" rx="3"/>'
        )
        lines.append(
            f'<text x="{cx:.1f}" y="{by - 18:.1f}" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" '
            f'font-size="11.5" font-weight="bold" fill="#111">{us:,.1f} мкс</text>'.replace(",", " ")
        )
        lines.append(
            f'<text x="{cx:.1f}" y="{by - 4:.1f}" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" '
            f'font-size="10.5" fill="#374151">(DER: {der} Б)</text>'
        )
        lines.append(
            f'<text x="{cx:.1f}" y="{margin_t + plot_h + 22}" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" '
            f'font-size="12" font-weight="bold" fill="#111">{_esc(title)}</text>'
        )

    lines.append(
        f'<line x1="{margin_l}" y1="{margin_t}" x2="{margin_l}" y2="{margin_t + plot_h}" stroke="#374151" stroke-width="1.5"/>'
    )
    lines.append(
        f'<line x1="{margin_l}" y1="{margin_t + plot_h}" x2="{w - margin_r}" y2="{margin_t + plot_h}" stroke="#374151" stroke-width="1.5"/>'
    )

    lx = margin_l
    ly = h - 25
    for _, title, color in items:
        lines.append(f'<rect x="{lx}" y="{ly - 11}" width="14" height="14" fill="{color}" rx="2"/>')
        lines.append(
            f'<text x="{lx + 20}" y="{ly}" font-family="Segoe UI, Arial, sans-serif" font-size="11.5" fill="#111">{_esc(title)}</text>'
        )
        lx += 180

    lines.append("</svg>")
    return "\n".join(lines)


def main() -> None:
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    (OUT_DIR / "chart_hybrid_latency.svg").write_text(
        build_hybrid_latency_svg(report), encoding="utf-8"
    )
    (OUT_DIR / "chart_keygen_latency.svg").write_text(
        build_keygen_and_direct_svg(report), encoding="utf-8"
    )
    print("Generated chart_hybrid_latency.svg and chart_keygen_latency.svg")


if __name__ == "__main__":
    main()