import csv
import hashlib
import json
import math
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "issuer-service"))
from app import fabric_client  # noqa: E402


RUNS = int(os.getenv("FABRIC_OPS_RUNS", "10"))
WARMUP_RUNS = int(os.getenv("FABRIC_OPS_WARMUP_RUNS", "2"))
OUTPUT_DIR = Path(os.getenv("FABRIC_OPS_OUTPUT_DIR", "results"))
LABEL = os.getenv("FABRIC_OPS_LABEL", "fabric_ops_manual")
MODE = os.getenv("FABRIC_OPS_MODE", "operation_timings").strip().lower()
PRESSURE_WRITES_PER_TYPE = int(os.getenv("FABRIC_WRITE_PRESSURE_WRITES_PER_TYPE", "25"))
os.environ.setdefault("FABRIC_ENABLED", "true")

RAW_FIELDS = [
    "timestamp",
    "label",
    "iteration",
    "operation",
    "fabric_enabled",
    "fabric_client_mode",
    "fabric_adapter_url",
    "peer_mode",
    "duration_ms",
    "ok",
    "error",
]
SUMMARY_FIELDS = [
    "operation",
    "count",
    "mean",
    "min",
    "max",
    "p50",
    "p95",
    "success_count",
    "failure_count",
]


def main() -> None:
    if RUNS < 1:
        raise SystemExit("FABRIC_OPS_RUNS must be at least 1")
    if WARMUP_RUNS < 0:
        raise SystemExit("FABRIC_OPS_WARMUP_RUNS must be 0 or greater")
    if not fabric_client.fabric_enabled():
        raise SystemExit("FABRIC_ENABLED must be true for benchmark_fabric_ops.py")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if MODE == "fabric_write_pressure":
        run_write_pressure()
        return
    if MODE not in {"operation_timings", "fabric_ops"}:
        raise SystemExit(f"unsupported FABRIC_OPS_MODE: {MODE}")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_path = OUTPUT_DIR / f"fabric_ops_raw_{timestamp}.csv"
    summary_path = OUTPUT_DIR / f"fabric_ops_summary_{timestamp}.csv"

    for iteration in range(1, WARMUP_RUNS + 1):
        print(f"Warmup iteration {iteration}/{WARMUP_RUNS}")
        run_operation_set(iteration)

    rows = []
    for iteration in range(1, RUNS + 1):
        print(f"Measured iteration {iteration}/{RUNS}")
        rows.extend(run_operation_set(iteration))

    with raw_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RAW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    summary_rows = build_summary(rows)
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(summary_rows)

    print_summary(summary_rows)
    print(f"Fabric ops raw results: {raw_path}")
    print(f"Fabric ops summary results: {summary_path}")

    if not any(row["ok"] == "true" for row in rows):
        raise SystemExit(1)


def run_write_pressure() -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_path = OUTPUT_DIR / f"fabric_write_pressure_raw_{timestamp}.csv"
    summary_path = OUTPUT_DIR / f"fabric_write_pressure_{timestamp}.json"
    run_id = f"{timestamp.lower()}-{uuid.uuid4().hex[:8]}"
    operations = write_pressure_operations(run_id, PRESSURE_WRITES_PER_TYPE)
    rows = []
    started = time.perf_counter()
    for index, (group, call) in enumerate(operations, start=1):
        rows.append(measure_operation(1, group, call) | {"write_index": str(index), "run_id": run_id})
    total_duration_ms = (time.perf_counter() - started) * 1000
    raw_fields = RAW_FIELDS + ["write_index", "run_id"]
    with raw_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=raw_fields)
        writer.writeheader()
        writer.writerows(rows)
    summary = build_write_pressure_summary(rows, total_duration_ms)
    summary["raw_path"] = str(raw_path)
    summary["summary_path"] = str(summary_path)
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
    print(f"Fabric write pressure raw results: {raw_path}")
    print(f"Fabric write pressure summary results: {summary_path}")
    print(json.dumps(summary, indent=2, sort_keys=True))
    if summary["successful_writes"] == 0:
        raise SystemExit(1)


def write_pressure_operations(run_id: str, per_type: int) -> list[tuple[str, Callable[[], dict[str, Any]]]]:
    operations: list[tuple[str, Callable[[], dict[str, Any]]]] = []
    for index in range(1, per_type + 1):
        context = SyntheticContext(prefix=f"pressure-did-{run_id}-{index}")
        operations.append(("did_registry", context.register_did))
    for index in range(1, per_type + 1):
        context = SyntheticContext(prefix=f"pressure-credential-{run_id}-{index}")
        operations.append(("credential_status", context.register_credential_status))
    for index in range(1, per_type + 1):
        context = SyntheticContext(prefix=f"pressure-accumulator-{run_id}-{index}")
        operations.append(("accumulator_state", context.put_accumulator_state))
    for index in range(1, per_type + 1):
        context = SyntheticContext(prefix=f"pressure-audit-{run_id}-{index}")
        operations.append(("audit_event", context.add_audit_event))
    return operations


def run_operation_set(iteration: int) -> list[dict[str, str]]:
    context = SyntheticContext()
    combined_register_context = SyntheticContext()
    combined_revoke_context = SyntheticContext()
    combined_revoke_context.register_credential_status()
    operations: list[tuple[str, Callable[[], dict[str, Any]]]] = [
        ("ping", lambda: fabric_client._query_json("Ping", [])),
        ("register_did", context.register_did),
        ("read_did", context.read_did),
        ("register_credential_status", context.register_credential_status),
        ("read_credential_status", context.read_credential_status),
        ("revoke_credential", context.revoke_credential),
        ("put_accumulator_state", context.put_accumulator_state),
        ("get_accumulator_state", context.get_accumulator_state),
        (
            "register_credential_with_accumulator_state",
            combined_register_context.register_credential_with_accumulator_state,
        ),
        (
            "revoke_credential_with_accumulator_state",
            combined_revoke_context.revoke_credential_with_accumulator_state,
        ),
        ("add_audit_event", context.add_audit_event),
        ("list_audit_events", context.list_audit_events),
    ]
    return [measure_operation(iteration, name, call) for name, call in operations]


def measure_operation(
    iteration: int, operation: str, call: Callable[[], dict[str, Any]]
) -> dict[str, str]:
    start = time.perf_counter()
    ok = False
    error = ""
    try:
        result = call()
        ok = bool(result.get("ok"))
        if not ok:
            error = str(result.get("error") or result.get("stderr") or "operation failed")
    except Exception as exc:
        error = str(exc)
    duration_ms = (time.perf_counter() - start) * 1000
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "label": LABEL,
        "iteration": str(iteration),
        "operation": operation,
        "fabric_enabled": str(fabric_client.fabric_enabled()).lower(),
        "fabric_client_mode": os.getenv("FABRIC_CLIENT_MODE", "peer_cli").strip().lower(),
        "fabric_adapter_url": os.getenv("FABRIC_ADAPTER_URL", ""),
        "peer_mode": os.getenv("FABRIC_PEER_MODE", "local").strip().lower(),
        "duration_ms": f"{duration_ms:.3f}",
        "ok": str(ok).lower(),
        "error": error,
    }


class SyntheticContext:
    def __init__(self, prefix: str | None = None) -> None:
        suffix = prefix or f"fabric-ops-{uuid.uuid4()}"
        self.did = f"did:iot:{suffix}"
        self.credential_id = f"urn:uuid:{suffix}"
        self.accumulator_id = suffix
        self.audit_event_id = suffix
        self.created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def register_did(self) -> dict:
        return fabric_client.register_did(
            self.did,
            "fabric-ops-public-key",
            hashlib.sha256(self.did.encode("utf-8")).hexdigest(),
            self.created_at,
        )

    def read_did(self) -> dict:
        return fabric_client._query_json("GetDID", [self.did])

    def register_credential_status(self) -> dict:
        return fabric_client.register_credential_status(self.synthetic_vc())

    def read_credential_status(self) -> dict:
        return fabric_client.get_credential_status(self.credential_id)

    def revoke_credential(self) -> dict:
        return fabric_client.revoke_credential_on_ledger(
            self.credential_id,
            "fabric ops benchmark",
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

    def put_accumulator_state(self) -> dict:
        return fabric_client.put_accumulator_state(self.synthetic_accumulator_state())

    def get_accumulator_state(self) -> dict:
        return fabric_client.get_accumulator_state(self.accumulator_id)

    def register_credential_with_accumulator_state(self) -> dict:
        return fabric_client.register_credential_with_accumulator_state(
            fabric_client.credential_status_record(self.synthetic_vc()),
            self.synthetic_accumulator_state(),
        )

    def revoke_credential_with_accumulator_state(self) -> dict:
        return fabric_client.revoke_credential_with_accumulator_state(
            self.credential_id,
            "fabric ops benchmark",
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            self.synthetic_accumulator_state(),
        )

    def add_audit_event(self) -> dict:
        return fabric_client.write_audit_event(
            {
                "event_id": self.audit_event_id,
                "event_type": "FABRIC_OPS_BENCHMARK",
                "subject_did": self.did,
                "credential_id": self.credential_id,
                "decision": "allow",
                "reason": "benchmark",
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "service": "benchmark",
                "metadata": {"label": LABEL},
            }
        )

    def list_audit_events(self) -> dict:
        return fabric_client.list_audit_events(10)

    def synthetic_vc(self) -> dict[str, Any]:
        return {
            "id": self.credential_id,
            "type": ["VerifiableCredential", "FabricOpsCredential"],
            "issuer": "did:iot:fabric-ops-issuer",
            "issuanceDate": self.created_at,
            "expirationDate": "2099-01-01T00:00:00Z",
            "credentialSubject": {"id": self.did},
        }

    def synthetic_accumulator_state(self) -> dict[str, Any]:
        return {
            "accumulator_id": self.accumulator_id,
            "version": int(time.time() * 1000),
            "root": hashlib.sha256(str(uuid.uuid4()).encode("utf-8")).hexdigest(),
            "algorithm": "MERKLE_SHA256_EVOKE_INSPIRED",
            "active_count": 1,
            "revoked_count": 0,
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }


def build_summary(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    by_operation: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_operation.setdefault(row["operation"], []).append(row)

    summary_rows = []
    for operation in sorted(by_operation):
        op_rows = by_operation[operation]
        successes = [row for row in op_rows if row["ok"] == "true"]
        values = [float(row["duration_ms"]) for row in successes]
        failure_count = len(op_rows) - len(successes)
        metric = summarize_values(values)
        summary_rows.append(
            {
                "operation": operation,
                **metric,
                "success_count": str(len(successes)),
                "failure_count": str(failure_count),
            }
        )
    return summary_rows


def build_write_pressure_summary(rows: list[dict[str, str]], total_duration_ms: float) -> dict[str, Any]:
    success_rows = [row for row in rows if row["ok"] == "true"]
    durations = [float(row["duration_ms"]) for row in success_rows]
    group_summaries = []
    for group in ("did_registry", "credential_status", "accumulator_state", "audit_event"):
        group_rows = [row for row in rows if row["operation"] == group]
        group_successes = [row for row in group_rows if row["ok"] == "true"]
        group_durations = [float(row["duration_ms"]) for row in group_successes]
        metric = summarize_values(group_durations)
        group_summaries.append(
            {
                "operation_type": group,
                "count": len(group_rows),
                "successful_writes": len(group_successes),
                "failures": len(group_rows) - len(group_successes),
                "average_latency_ms": float(metric["mean"]) if metric["mean"] else None,
                "p50_latency_ms": float(metric["p50"]) if metric["p50"] else None,
                "p95_latency_ms": float(metric["p95"]) if metric["p95"] else None,
            }
        )
    metric = summarize_values(durations)
    failed_writes = len(rows) - len(success_rows)
    return {
        "benchmark_type": "fabric_write_pressure",
        "label": LABEL,
        "status": "completed_with_failures" if failed_writes else "completed",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_writes": len(rows),
        "successful_writes": len(success_rows),
        "failed_writes": failed_writes,
        "total_duration_ms": round(total_duration_ms, 3),
        "average_write_latency_ms": float(metric["mean"]) if metric["mean"] else None,
        "p50_write_latency_ms": float(metric["p50"]) if metric["p50"] else None,
        "p95_write_latency_ms": float(metric["p95"]) if metric["p95"] else None,
        "min_write_latency_ms": float(metric["min"]) if metric["min"] else None,
        "max_write_latency_ms": float(metric["max"]) if metric["max"] else None,
        "writes_per_second": round((len(success_rows) / total_duration_ms) * 1000, 3)
        if total_duration_ms > 0
        else None,
        "groups": group_summaries,
    }


def summarize_values(values: list[float]) -> dict[str, str]:
    if not values:
        return {"count": "0", "mean": "", "min": "", "max": "", "p50": "", "p95": ""}
    values = sorted(values)
    return {
        "count": str(len(values)),
        "mean": fmt(mean(values)),
        "min": fmt(values[0]),
        "max": fmt(values[-1]),
        "p50": fmt(percentile(values, 50)),
        "p95": fmt(percentile(values, 95)),
    }


def percentile(values: list[float], percentile_value: float) -> float:
    if len(values) == 1:
        return values[0]
    rank = (percentile_value / 100) * (len(values) - 1)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return values[lower]
    weight = rank - lower
    return values[lower] * (1 - weight) + values[upper] * weight


def fmt(value: float) -> str:
    return f"{value:.3f}"


def print_summary(rows: list[dict[str, str]]) -> None:
    widths = {field: len(field) for field in SUMMARY_FIELDS}
    for row in rows:
        for field in SUMMARY_FIELDS:
            widths[field] = max(widths[field], len(row[field]))
    print("  ".join(field.ljust(widths[field]) for field in SUMMARY_FIELDS))
    print("  ".join("-" * widths[field] for field in SUMMARY_FIELDS))
    for row in rows:
        print("  ".join(row[field].ljust(widths[field]) for field in SUMMARY_FIELDS))


if __name__ == "__main__":
    main()
