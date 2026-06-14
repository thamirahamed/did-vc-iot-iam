import argparse
import csv
import json
import os
import socket
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
    "dashboard-api",
    "fabric-adapter",
    "benchmark-agent-gateway",
    "benchmark-agent-constrained",
    "benchmark-agent-low",
    "benchmark-agent-tiny",
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
    except FileNotFoundError:
        return docker_socket_stats_json()
    except subprocess.TimeoutExpired as exc:
        raise SystemExit("docker stats timed out") from exc

    if completed.returncode != 0:
        if Path("/var/run/docker.sock").exists():
            return docker_socket_stats_json()
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


def docker_socket_stats_json() -> list[dict[str, Any]]:
    if not Path("/var/run/docker.sock").exists():
        raise SystemExit("Docker socket not available")
    containers = docker_api_get_json("/containers/json")
    rows = []
    for container in containers if isinstance(containers, list) else []:
        container_id = str(container.get("Id") or "")
        service = container_service_name(container)
        stats = docker_api_get_json(f"/containers/{container_id}/stats?stream=false")
        memory_usage = int(docker_memory_bytes(stats))
        memory_limit = int((stats.get("memory_stats") or {}).get("limit") or 0)
        rows.append(
            {
                "ID": container_id[:12],
                "Name": service,
                "CPUPerc": f"{docker_cpu_percent(stats):.3f}%",
                "MemUsage": f"{memory_usage}B / {memory_limit}B",
                "MemPerc": "0%",
                "NetIO": "0B / 0B",
                "BlockIO": "0B / 0B",
            }
        )
    return rows


def docker_api_get_json(path: str) -> Any:
    request = f"GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n".encode("ascii")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect("/var/run/docker.sock")
        sock.sendall(request)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    response = b"".join(chunks)
    headers, _, body = response.partition(b"\r\n\r\n")
    if b"transfer-encoding: chunked" in headers.lower():
        body = decode_chunked_body(body)
    return json.loads(body.decode("utf-8"))


def decode_chunked_body(body: bytes) -> bytes:
    decoded = bytearray()
    remaining = body
    while remaining:
        size_text, separator, rest = remaining.partition(b"\r\n")
        if not separator:
            break
        size = int(size_text.split(b";", 1)[0], 16)
        if size == 0:
            break
        decoded.extend(rest[:size])
        remaining = rest[size + 2 :]
    return bytes(decoded)


def container_service_name(container: dict[str, Any]) -> str:
    labels = container.get("Labels") if isinstance(container.get("Labels"), dict) else {}
    service = labels.get("com.docker.compose.service")
    if service:
        return str(service)
    names = container.get("Names") if isinstance(container.get("Names"), list) else []
    return str(names[0]).strip("/") if names else str(container.get("Id") or "")


def docker_cpu_percent(stats: dict[str, Any]) -> float:
    cpu_stats = stats.get("cpu_stats") if isinstance(stats.get("cpu_stats"), dict) else {}
    precpu_stats = stats.get("precpu_stats") if isinstance(stats.get("precpu_stats"), dict) else {}
    cpu_usage = cpu_stats.get("cpu_usage") if isinstance(cpu_stats.get("cpu_usage"), dict) else {}
    precpu_usage = precpu_stats.get("cpu_usage") if isinstance(precpu_stats.get("cpu_usage"), dict) else {}
    cpu_delta = float(cpu_usage.get("total_usage") or 0) - float(precpu_usage.get("total_usage") or 0)
    system_delta = float(cpu_stats.get("system_cpu_usage") or 0) - float(precpu_stats.get("system_cpu_usage") or 0)
    online_cpus = float(cpu_stats.get("online_cpus") or len(cpu_usage.get("percpu_usage") or []) or 1)
    if cpu_delta <= 0 or system_delta <= 0:
        return 0.0
    return (cpu_delta / system_delta) * online_cpus * 100.0


def docker_memory_bytes(stats: dict[str, Any]) -> float:
    memory_stats = stats.get("memory_stats") if isinstance(stats.get("memory_stats"), dict) else {}
    usage = float(memory_stats.get("usage") or 0)
    nested = memory_stats.get("stats")
    cache = float(nested.get("cache") or 0) if isinstance(nested, dict) else 0.0
    return max(0.0, usage - cache)


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
