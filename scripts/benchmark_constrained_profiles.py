import csv
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


RUNS = int(os.getenv("BENCHMARK_RUNS", "3"))
WARMUP_RUNS = int(os.getenv("BENCHMARK_WARMUP_RUNS", "1"))
OUTPUT_DIR = Path(os.getenv("BENCHMARK_OUTPUT_DIR", "results"))
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "30"))
TIMING_SCOPE = (
    "Measured lifecycle includes device-agent DID registration/resolution, VC issuance, "
    "authorization, revocation, proof refresh, and replacement authorization. It excludes "
    "wallet reset, setup, health checks, container startup, and artificial cache wait."
)

PROFILES = [
    {
        "profile": "gateway",
        "label": "Gateway",
        "cpu_limit": "1.0",
        "memory_limit": "512 MB",
        "url": os.getenv("BENCHMARK_AGENT_GATEWAY_URL", "http://benchmark-agent-gateway:8031"),
        "container_filter": "benchmark-agent-gateway",
    },
    {
        "profile": "constrained",
        "label": "Constrained",
        "cpu_limit": "0.5",
        "memory_limit": "256 MB",
        "url": os.getenv("BENCHMARK_AGENT_CONSTRAINED_URL", "http://benchmark-agent-constrained:8031"),
        "container_filter": "benchmark-agent-constrained",
    },
    {
        "profile": "low_resource",
        "label": "Low resource",
        "cpu_limit": "0.25",
        "memory_limit": "128 MB",
        "url": os.getenv("BENCHMARK_AGENT_LOW_URL", "http://benchmark-agent-low:8031"),
        "container_filter": "benchmark-agent-low",
    },
    {
        "profile": "tiny",
        "label": "Tiny IoT",
        "cpu_limit": "0.1",
        "memory_limit": os.getenv("BENCHMARK_AGENT_TINY_MEMORY_LABEL", "64 MB"),
        "url": os.getenv("BENCHMARK_AGENT_TINY_URL", "http://benchmark-agent-tiny:8031"),
        "container_filter": "benchmark-agent-tiny",
    },
]


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = OUTPUT_DIR / f"constrained_benchmark_{timestamp}.json"
    resource_rows: list[dict[str, Any]] = []
    profiles = []
    for profile in PROFILES:
        resource_path = OUTPUT_DIR / f"resource_usage_constrained_{profile['profile']}_{timestamp}.csv"
        monitor = start_resource_monitor(resource_path, profile["container_filter"])
        started = time.perf_counter()
        try:
            response = post_json(
                f"{profile['url'].rstrip('/')}/run",
                {
                    "runs": RUNS,
                    "warmup_runs": WARMUP_RUNS,
                    "profile": profile["profile"],
                    "force_fresh_verifier_state": True,
                },
            )
            summary = response.get("summary") if isinstance(response, dict) else {}
            status = str(response.get("status") or "failed")
            error = response.get("stderr_tail") if status != "completed" else None
        except Exception as exc:
            summary = {}
            status = "failed"
            error = str(exc)
        finally:
            stop_resource_monitor(monitor)
        measured_lifecycle_ms = summary.get("measured_lifecycle_ms") or summary.get("full_lifecycle_ms")
        breakdown_by_stage_ms = summary.get("breakdown_by_stage_ms")
        if not isinstance(breakdown_by_stage_ms, dict):
            breakdown_by_stage_ms = {
                key: summary.get(key)
                for key in (
                    "did_create_ms",
                    "did_resolve_ms",
                    "identity_vc_issue_ms",
                    "capability_vc_issue_ms",
                    "proof_refresh_ms",
                    "auth_allow_ms",
                    "auth_wrong_action_deny_ms",
                    "revoke_capability_ms",
                    "auth_revoked_or_stale_deny_ms",
                    "replacement_capability_issue_ms",
                    "auth_replacement_allow_ms",
                )
                if isinstance(summary.get(key), (int, float))
            }
        resources = summarize_resource_csv(resource_path, "Constrained device emulation")
        resource_rows.extend(resources)
        peak = peak_resource(resources)
        profiles.append(
            {
                "profile": profile["profile"],
                "label": profile["label"],
                "cpu_limit": profile["cpu_limit"],
                "memory_limit": profile["memory_limit"],
                "full_lifecycle_ms": measured_lifecycle_ms,
                "measured_lifecycle_ms": measured_lifecycle_ms,
                "raw_wall_clock_ms": summary.get("raw_wall_clock_ms") or measured_lifecycle_ms,
                "excluded_wait_ms": summary.get("excluded_wait_ms") or 0.0,
                "includes_cache_wait": bool(summary.get("includes_cache_wait")),
                "timing_scope": summary.get("timing_scope") or TIMING_SCOPE,
                "uses_device_agent": True,
                "uses_holder_agent": bool(summary.get("uses_holder_agent")),
                "breakdown_by_stage_ms": breakdown_by_stage_ms,
                "auth_allow_ms": summary.get("auth_allow_ms"),
                "proof_refresh_ms": summary.get("proof_refresh_ms"),
                "did_create_ms": summary.get("did_create_ms"),
                "identity_vc_issue_ms": summary.get("identity_vc_issue_ms"),
                "capability_vc_issue_ms": summary.get("capability_vc_issue_ms"),
                "revoke_capability_ms": summary.get("revoke_capability_ms"),
                "payload_size_bytes": summary.get("auth_allow_request_bytes"),
                "peak_cpu_percent": peak.get("peak_cpu_percent"),
                "peak_ram_mb": peak.get("peak_memory_mb"),
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                "status": "completed" if status == "completed" else "failed",
                "error": error,
            }
        )
    gateway_profile = next(
        (item for item in profiles if item.get("profile") == "gateway"),
        profiles[0] if profiles else {},
    )
    result = {
        "benchmark_type": "constrained",
        "profile": "docker_constrained_agents",
        "mode": "docker constrained device emulation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "measured_lifecycle_ms": gateway_profile.get("measured_lifecycle_ms"),
        "raw_wall_clock_ms": gateway_profile.get("raw_wall_clock_ms"),
        "excluded_wait_ms": gateway_profile.get("excluded_wait_ms") or 0.0,
        "includes_cache_wait": bool(gateway_profile.get("includes_cache_wait")),
        "timing_scope": TIMING_SCOPE,
        "uses_device_agent": True,
        "uses_holder_agent": False,
        "breakdown_by_stage_ms": gateway_profile.get("breakdown_by_stage_ms") or {},
        "profiles": profiles,
        "resource_usage": resource_rows,
    }
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Constrained results: {output_path}")


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def start_resource_monitor(path: Path, container_filter: str) -> subprocess.Popen | None:
    command = [
        sys.executable,
        str(Path(__file__).with_name("collect_docker_stats.py")),
        "--label",
        "constrained",
        "--output",
        str(path),
        "--interval",
        os.getenv("RESOURCE_MONITOR_INTERVAL_SECONDS", "1"),
        "--containers",
        container_filter,
    ]
    try:
        return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return None


def stop_resource_monitor(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def summarize_resource_csv(path: Path, section: str) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    grouped: dict[str, list[dict[str, str]]] = {}
    try:
        with path.open("r", newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                grouped.setdefault(row.get("container_name") or "unknown", []).append(row)
    except OSError:
        return []
    rows = []
    for service, samples in grouped.items():
        cpu = [float(sample.get("cpu_percent") or 0) for sample in samples]
        mem = [float(sample.get("memory_usage_bytes") or 0) / (1024 * 1024) for sample in samples]
        rows.append(
            {
                "service": service,
                "section": section,
                "avg_cpu_percent": round(sum(cpu) / len(cpu), 3) if cpu else None,
                "peak_cpu_percent": round(max(cpu), 3) if cpu else None,
                "avg_memory_mb": round(sum(mem) / len(mem), 3) if mem else None,
                "peak_memory_mb": round(max(mem), 3) if mem else None,
            }
        )
    return rows


def peak_resource(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "peak_cpu_percent": max((row.get("peak_cpu_percent") or 0 for row in rows), default=None),
        "peak_memory_mb": max((row.get("peak_memory_mb") or 0 for row in rows), default=None),
    }


if __name__ == "__main__":
    main()
