import csv
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from parse_fabric_tuning_results import PROFILES, load_tuning_results

RUNS = int(os.getenv("BENCHMARK_RUNS", "1"))
WARMUP_RUNS = int(os.getenv("BENCHMARK_WARMUP_RUNS", "0"))
OUTPUT_DIR = Path(os.getenv("BENCHMARK_OUTPUT_DIR", "results"))
TUNING_RESULTS_DIR = Path(
    os.getenv("FABRIC_TUNING_RESULTS_DIR", "data/dashboard/fabric-tuning-results")
)
MAIN_TUNED_PROFILE_ID = "larger_batch"
WRITE_PRESSURE_PROFILE_IDS = {"low_latency", "larger_batch"}


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = OUTPUT_DIR / f"fabric_tuning_{timestamp}.json"
    resource_usage: list[dict[str, Any]] = []
    tuned_profile = next(profile for profile in PROFILES if profile["profile_id"] == MAIN_TUNED_PROFILE_ID)
    tuned_row, resources = current_profile_from_existing_summaries(tuned_profile)
    if tuned_row is None:
        tuned_row, resources = run_current_profile(tuned_profile, timestamp)
    resource_usage.extend(resources)
    saved = load_tuning_results(TUNING_RESULTS_DIR)
    rows = []
    for profile in saved["profiles"]:
        row = tuned_row if profile["profile_id"] == MAIN_TUNED_PROFILE_ID else profile
        rows.append(ensure_write_pressure(row))
    result = {**saved, "generated_at": datetime.now(timezone.utc).isoformat(), "profiles": rows, "resource_usage": resource_usage}
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Fabric tuning results: {output_path}")


def current_profile_from_existing_summaries(profile: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]] | tuple[None, list[dict[str, Any]]]:
    pipeline_path = Path(os.getenv("FABRIC_TUNING_CURRENT_PIPELINE_SUMMARY_PATH", ""))
    if not pipeline_path.is_file():
        return None, []
    metrics = parse_pipeline_summary(pipeline_path)
    ops_metrics: dict[str, Any] = {}
    ops_path = Path(os.getenv("FABRIC_TUNING_CURRENT_FABRIC_OPS_SUMMARY_PATH", ""))
    if ops_path.is_file():
        ops_metrics = parse_fabric_ops_summary(ops_path)
    row = current_profile_row(profile, metrics, ops_metrics)
    row["pipeline_summary_path"] = str(pipeline_path)
    if ops_path.is_file():
        row["fabric_ops_summary_path"] = str(ops_path)
    pressure_summary = run_write_pressure(profile["profile_id"])
    if pressure_summary:
        row["write_pressure"] = pressure_summary
    return row, []


def run_current_profile(profile: dict[str, Any], timestamp: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    before = set(OUTPUT_DIR.glob("*"))
    env = {
        **os.environ,
        "BENCHMARK_RUNS": str(RUNS),
        "BENCHMARK_WARMUP_RUNS": str(WARMUP_RUNS),
        "BENCHMARK_OUTPUT_DIR": str(OUTPUT_DIR),
        "BENCHMARK_PROFILE": "fabric_accumulator_perf",
        "BENCHMARK_LABEL": f"fabric_tuning_{profile['profile_id']}",
        "ISSUER_URL": "http://issuer:8000",
        "VERIFIER_URL": "http://verifier:8001",
        "FABRIC_ADAPTER_URL": "http://fabric-adapter:8010",
        "FABRIC_ENABLED": "true",
        "FABRIC_CLIENT_MODE": "adapter",
        "REVOCATION_MODE": "accumulator",
        "AUDIT_MODE": "async",
        "HTTP_TIMEOUT_SECONDS": os.getenv("HTTP_TIMEOUT_SECONDS", "60"),
        "HTTP_RETRY_ATTEMPTS": os.getenv("HTTP_RETRY_ATTEMPTS", "5"),
        "HTTP_RETRY_SLEEP_SECONDS": os.getenv("HTTP_RETRY_SLEEP_SECONDS", "1"),
        "BENCHMARK_AGENT_GATEWAY_URL": os.getenv(
            "BENCHMARK_AGENT_GATEWAY_URL", "http://benchmark-agent-gateway:8031"
        ),
        "FABRIC_OPS_RUNS": str(RUNS),
        "FABRIC_OPS_WARMUP_RUNS": str(WARMUP_RUNS),
        "FABRIC_OPS_OUTPUT_DIR": str(OUTPUT_DIR),
        "FABRIC_OPS_LABEL": f"fabric_tuning_{profile['profile_id']}",
    }
    pipeline_process = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("benchmark_agent_pipeline.py"))],
        cwd=Path(__file__).resolve().parent.parent,
        env=env,
        capture_output=True,
        text=True,
        timeout=int(os.getenv("BENCHMARK_TIMEOUT_SECONDS", "900")),
        shell=False,
    )
    ops_process = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("benchmark_fabric_ops.py"))],
        cwd=Path(__file__).resolve().parent.parent,
        env=env,
        capture_output=True,
        text=True,
        timeout=int(os.getenv("BENCHMARK_TIMEOUT_SECONDS", "900")),
        shell=False,
    )
    pressure_summary = run_write_pressure(profile["profile_id"])
    after = set(OUTPUT_DIR.glob("*"))
    created = sorted(after - before, key=lambda path: path.stat().st_mtime, reverse=True)
    summary_paths = [path for path in created if path.name.startswith("benchmark_summary_")]
    ops_summary_paths = [path for path in created if path.name.startswith("fabric_ops_summary_")]
    metrics = parse_pipeline_summary(summary_paths[0]) if summary_paths else {}
    ops_metrics = parse_fabric_ops_summary(ops_summary_paths[0]) if ops_summary_paths else {}
    failed_process = pipeline_process if pipeline_process.returncode != 0 else ops_process if ops_process.returncode != 0 else None
    row = current_profile_row(profile, metrics, ops_metrics)
    row["status"] = "completed" if failed_process is None else "failed"
    row["reason"] = None if failed_process is None else short_error(failed_process.stderr or failed_process.stdout)
    row["error"] = None if failed_process is None else (failed_process.stderr[-1000:] or failed_process.stdout[-1000:])
    if pressure_summary:
        row["write_pressure"] = pressure_summary
    return row, []


def current_profile_row(profile: dict[str, Any], metrics: dict[str, Any], ops_metrics: dict[str, Any]) -> dict[str, Any]:
    return {
        **profile,
        "status": "completed",
        "reason": None,
        "full_lifecycle_ms": metrics.get("full_lifecycle_ms"),
        "auth_allow_ms": metrics.get("auth_allow_ms"),
        "revocation_ms": metrics.get("revocation_ms"),
        "proof_refresh_ms": metrics.get("proof_refresh_ms"),
        "ledger_read_ms": ops_metrics.get("ledger_read_ms"),
        "ledger_write_ms": ops_metrics.get("ledger_write_ms"),
        "read_p50_ms": ops_metrics.get("read_p50_ms") or metrics.get("auth_allow_ms"),
        "read_p95_ms": ops_metrics.get("read_p95_ms") or metrics.get("auth_allow_ms"),
        "write_p50_ms": ops_metrics.get("write_p50_ms") or metrics.get("revocation_ms"),
        "write_p95_ms": ops_metrics.get("write_p95_ms") or metrics.get("revocation_ms"),
        "read_tps": throughput(ops_metrics.get("ledger_read_ms")),
        "write_tps": throughput(ops_metrics.get("ledger_write_ms")),
        "tps": throughput(metrics.get("full_lifecycle_ms")),
        "cpu_peak": None,
        "ram_peak": None,
        "error": None,
    }


def parse_pipeline_summary(path: Path) -> dict[str, Any]:
    values: dict[str, float] = {}
    with path.open("r", newline="", encoding="utf-8") as handle:
        for csv_row in csv.DictReader(handle):
            metric = str(csv_row.get("metric") or "")
            mean = csv_row.get("mean")
            if metric and mean not in (None, ""):
                values[metric] = float(str(mean))
    return {
        "full_lifecycle_ms": values.get("full_iteration_ms"),
        "auth_allow_ms": values.get("auth_allow_ms"),
        "revocation_ms": values.get("revoke_capability_ms"),
        "proof_refresh_ms": values.get("proof_refresh_ms"),
    }


def run_write_pressure(profile_id: str) -> dict[str, Any] | None:
    before = set(OUTPUT_DIR.glob("*"))
    env = {
        **os.environ,
        "FABRIC_OPS_MODE": "fabric_write_pressure",
        "FABRIC_OPS_RUNS": "1",
        "FABRIC_OPS_WARMUP_RUNS": "0",
        "FABRIC_OPS_OUTPUT_DIR": str(OUTPUT_DIR),
        "FABRIC_OPS_LABEL": f"fabric_tuning_{profile_id}_write_pressure",
        "FABRIC_WRITE_PRESSURE_WRITES_PER_TYPE": os.getenv("FABRIC_WRITE_PRESSURE_WRITES_PER_TYPE", "25"),
        "FABRIC_ENABLED": "true",
        "FABRIC_CLIENT_MODE": "adapter",
        "FABRIC_ADAPTER_URL": "http://fabric-adapter:8010",
        "HTTP_TIMEOUT_SECONDS": os.getenv("HTTP_TIMEOUT_SECONDS", "60"),
        "HTTP_RETRY_ATTEMPTS": os.getenv("HTTP_RETRY_ATTEMPTS", "5"),
        "HTTP_RETRY_SLEEP_SECONDS": os.getenv("HTTP_RETRY_SLEEP_SECONDS", "1"),
    }
    process = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("benchmark_fabric_ops.py"))],
        cwd=Path(__file__).resolve().parent.parent,
        env=env,
        capture_output=True,
        text=True,
        timeout=int(os.getenv("BENCHMARK_TIMEOUT_SECONDS", "900")),
        shell=False,
    )
    after = set(OUTPUT_DIR.glob("*"))
    created = sorted(after - before, key=lambda path: path.stat().st_mtime, reverse=True)
    summary_paths = [path for path in created if path.name.startswith("fabric_write_pressure_") and path.suffix == ".json"]
    if not summary_paths:
        return {
            "status": "failed",
            "error": short_error(process.stderr or process.stdout or "write pressure summary was not created"),
        }
    try:
        summary = json.loads(summary_paths[0].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "failed", "error": short_error(str(exc))}
    if process.returncode != 0:
        summary["status"] = "failed"
        summary["error"] = short_error(process.stderr or process.stdout)
    else:
        summary["status"] = summary.get("status") or "completed"
    return summary


def ensure_write_pressure(profile: dict[str, Any]) -> dict[str, Any]:
    profile_id = str(profile.get("profile_id") or "")
    if profile_id not in WRITE_PRESSURE_PROFILE_IDS:
        return profile
    if isinstance(profile.get("write_pressure"), dict):
        return profile
    if profile.get("status") in {"not_run", "not_supported"}:
        return profile
    pressure_summary = run_write_pressure(profile_id)
    if not pressure_summary:
        return profile
    row = dict(profile)
    row["write_pressure"] = pressure_summary
    if pressure_summary.get("summary_path"):
        row["write_pressure_summary_path"] = pressure_summary.get("summary_path")
    return row


def parse_fabric_ops_summary(path: Path) -> dict[str, Any]:
    values: dict[str, dict[str, float]] = {}
    with path.open("r", newline="", encoding="utf-8") as handle:
        for csv_row in csv.DictReader(handle):
            operation = str(csv_row.get("operation") or "")
            if operation:
                values[operation] = {
                    key: float(str(csv_row[key]))
                    for key in ("mean", "p50", "p95")
                    if csv_row.get(key) not in (None, "")
                }
    read_ops = ["ping", "read_did", "read_credential_status", "get_accumulator_state", "list_audit_events"]
    write_ops = ["register_did", "register_credential_status", "revoke_credential", "put_accumulator_state", "add_audit_event"]
    return {
        "ledger_read_ms": operation_average(values, read_ops, "mean"),
        "ledger_write_ms": operation_average(values, write_ops, "mean"),
        "read_p50_ms": operation_average(values, read_ops, "p50"),
        "read_p95_ms": operation_average(values, read_ops, "p95"),
        "write_p50_ms": operation_average(values, write_ops, "p50"),
        "write_p95_ms": operation_average(values, write_ops, "p95"),
    }


def operation_average(values: dict[str, dict[str, float]], operations: list[str], column: str) -> float | None:
    collected = [values[operation][column] for operation in operations if column in values.get(operation, {})]
    return sum(collected) / len(collected) if collected else None


def throughput(duration_ms: Any) -> float | None:
    if duration_ms is None or duration_ms <= 0:
        return None
    return round(1000.0 / float(duration_ms), 3)


def short_error(text: str) -> str:
    collapsed = " ".join(str(text or "").split())
    return collapsed[:240] if collapsed else "benchmark failed"


if __name__ == "__main__":
    main()
