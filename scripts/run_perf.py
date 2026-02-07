import csv
import os
import subprocess
import sys
from pathlib import Path
from typing import List


EXPECTED_COLUMNS = [
    "ts_iso",
    "iteration",
    "t_sign_ms",
    "t_authorize_ms",
    "decision",
    "reason",
]


def percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    if low == high:
        return float(ordered[low])
    weight = rank - low
    return float(ordered[low] + (ordered[high] - ordered[low]) * weight)


def parse_csv(path: Path) -> List[dict]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != EXPECTED_COLUMNS:
            raise RuntimeError(f"unexpected columns: {reader.fieldnames}")
        return list(reader)


def print_summary(rows: List[dict]) -> None:
    sign_values = [float(row["t_sign_ms"]) for row in rows]
    auth_values = [float(row["t_authorize_ms"]) for row in rows]
    allow_count = sum(1 for row in rows if row["decision"] == "allow")
    deny_count = len(rows) - allow_count
    print(f"runs: {len(rows)}")
    print(f"allow_count: {allow_count}")
    print(f"deny_count: {deny_count}")
    print(f"sign_p50_ms: {percentile(sign_values, 50):.3f}")
    print(f"sign_p95_ms: {percentile(sign_values, 95):.3f}")
    print(f"authorize_p50_ms: {percentile(auth_values, 50):.3f}")
    print(f"authorize_p95_ms: {percentile(auth_values, 95):.3f}")


def main() -> int:
    profile = os.getenv("PERF_PROFILE", "lite").strip() or "lite"
    service = "device_agent_moderate" if profile == "moderate" else "device_agent"
    compose_cmd = [
        "docker",
        "compose",
        "-f",
        "docker-compose.yml",
        "-f",
        "docker-compose.perf.yml",
        "--profile",
        profile,
    ]

    out_dir = Path("perf-out")
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "results.csv"
    if csv_path.exists():
        csv_path.unlink()

    try:
        subprocess.run(compose_cmd + ["up", "-d", "--build", "issuer", "verifier"], check=True)
        subprocess.run(compose_cmd + ["run", "--rm", "--build", service], check=True)
    finally:
        subprocess.run(compose_cmd + ["down"], check=False)

    if not csv_path.exists():
        print("results.csv not found", flush=True)
        return 1

    try:
        rows = parse_csv(csv_path)
    except Exception as exc:
        print(str(exc), flush=True)
        return 1

    print_summary(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
