import argparse
import csv
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_CONTAINERS = [
    "issuer",
    "verifier",
    "peer0.org1.example.com",
    "peer0.org2.example.com",
    "orderer.example.com",
    "dev-peer0.org1.example.com",
    "dev-peer0.org2.example.com",
]

CSV_FIELDS = [
    "timestamp",
    "label",
    "container_id",
    "container_name",
    "cpu_percent",
    "memory_usage_bytes",
    "memory_limit_bytes",
    "memory_percent",
    "network_rx_bytes",
    "network_tx_bytes",
    "block_read_bytes",
    "block_write_bytes",
]

UNIT_MULTIPLIERS = {
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
}


def main() -> None:
    args = parse_args()
    output_path = args.output or default_output_path(args.label)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    container_filters = parse_container_filters(args.containers)
    deadline = time.monotonic() + args.duration if args.duration else None
    wrote_rows = False
    warned_no_matches = False

    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        handle.flush()

        try:
            while True:
                rows = sample_stats(args.label, container_filters)
                if not rows and not wrote_rows and not warned_no_matches:
                    print(
                        "warning: no matching Docker containers found for resource monitoring",
                        file=sys.stderr,
                        flush=True,
                    )
                    warned_no_matches = True
                    if args.duration:
                        raise SystemExit(1)
                for row in rows:
                    writer.writerow(row)
                    wrote_rows = True
                handle.flush()

                if deadline is not None and time.monotonic() >= deadline:
                    break
                time.sleep(args.interval)
        except KeyboardInterrupt:
            pass

    print(f"Resource results: {output_path}", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect Docker CPU and memory stats as CSV.")
    parser.add_argument("--duration", type=float, default=None, help="seconds to collect before exiting")
    parser.add_argument("--label", default=os.getenv("RESOURCE_MONITOR_LABEL", "manual"))
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="CSV output path; defaults to results/resource_usage_<timestamp>.csv",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.getenv("RESOURCE_MONITOR_INTERVAL_SECONDS", "1")),
        help="seconds between samples",
    )
    parser.add_argument(
        "--containers",
        default=os.getenv("RESOURCE_MONITOR_CONTAINERS", ""),
        help="comma separated container name substrings",
    )
    args = parser.parse_args()
    if args.interval <= 0:
        raise SystemExit("--interval must be greater than 0")
    if args.duration is not None and args.duration <= 0:
        raise SystemExit("--duration must be greater than 0")
    return args


def default_output_path(label: str) -> Path:
    output_dir = Path(os.getenv("RESOURCE_MONITOR_OUTPUT_DIR", "results"))
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_label = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in label)
    return output_dir / f"resource_usage_{safe_label}_{timestamp}.csv"


def parse_container_filters(value: str) -> list[str]:
    filters = [item.strip() for item in value.split(",") if item.strip()]
    return filters or DEFAULT_CONTAINERS


def sample_stats(label: str, container_filters: list[str]) -> list[dict[str, Any]]:
    stats = docker_stats_json()
    matched = []
    for item in stats:
        name = str(item.get("Name") or item.get("Container") or "")
        container_id = str(item.get("ID") or item.get("ContainerID") or "")
        if not matches_container(name, container_id, container_filters):
            continue
        matched.append(to_csv_row(label, item, name, container_id))
    return matched


def docker_stats_json() -> list[dict[str, Any]]:
    command = ["docker", "stats", "--no-stream", "--format", "json"]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise SystemExit("docker command not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise SystemExit("docker stats timed out") from exc

    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "docker stats failed"
        raise SystemExit(message)

    rows = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"failed to parse docker stats JSON line: {line}") from exc
    return rows


def matches_container(name: str, container_id: str, filters: list[str]) -> bool:
    haystack = f"{name} {container_id}".lower()
    return any(item.lower() in haystack for item in filters)


def to_csv_row(
    label: str,
    item: dict[str, Any],
    container_name: str,
    container_id: str,
) -> dict[str, Any]:
    memory_usage, memory_limit = parse_pair(str(item.get("MemUsage", "")))
    network_rx, network_tx = parse_pair(str(item.get("NetIO", "")))
    block_read, block_write = parse_pair(str(item.get("BlockIO", "")))
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "label": label,
        "container_id": container_id,
        "container_name": container_name,
        "cpu_percent": parse_percent(str(item.get("CPUPerc", ""))),
        "memory_usage_bytes": memory_usage,
        "memory_limit_bytes": memory_limit,
        "memory_percent": parse_percent(str(item.get("MemPerc", ""))),
        "network_rx_bytes": network_rx,
        "network_tx_bytes": network_tx,
        "block_read_bytes": block_read,
        "block_write_bytes": block_write,
    }


def parse_pair(value: str) -> tuple[int, int]:
    if "/" not in value:
        return 0, 0
    left, right = value.split("/", 1)
    return parse_bytes(left), parse_bytes(right)


def parse_percent(value: str) -> float:
    value = value.strip().rstrip("%")
    if not value:
        return 0.0
    return float(value)


def parse_bytes(value: str) -> int:
    cleaned = value.strip().replace(" ", "")
    if not cleaned:
        return 0
    number_chars = []
    unit_chars = []
    for char in cleaned:
        if char.isdigit() or char == ".":
            number_chars.append(char)
        else:
            unit_chars.append(char)
    if not number_chars:
        return 0
    number = float("".join(number_chars))
    unit = "".join(unit_chars).lower()
    multiplier = UNIT_MULTIPLIERS.get(unit, 1)
    return int(number * multiplier)


if __name__ == "__main__":
    main()
