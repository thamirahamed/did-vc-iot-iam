import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROFILE_ALIASES = {
    "fast_block_commit": "low_latency",
    "larger_batch_window": "larger_batch",
}

PROFILES: list[dict[str, Any]] = [
    {
        "profile_id": "current",
        "label": "Original Fabric baseline",
        "description": "Saved comparison profile using the original Fabric test-network batch settings.",
        "block_size": "max_message_count=10, preferred_max_bytes=512 KB, absolute_max_bytes=99 MB",
        "batch_timeout": "2s",
        "endorsement_policy": "current",
        "read_tps": None,
        "write_tps": None,
        "write_pressure": None,
        "status": "not_run",
        "reason": "Original Fabric baseline saved run is not available.",
    },
    {
        "profile_id": "low_latency",
        "label": "Fast block commit",
        "description": "Smaller blocks and shorter batch timeout for lower latency IAM writes.",
        "block_size": "max_message_count=5, preferred_max_bytes=512 KB, absolute_max_bytes=10 MB",
        "batch_timeout": "500ms",
        "endorsement_policy": "current",
        "read_tps": None,
        "write_tps": None,
        "write_pressure": None,
        "status": "not_run",
        "reason": "Run scripts\\run_fabric_profile_benchmark.ps1 -Profile low_latency.",
    },
    {
        "profile_id": "larger_batch",
        "label": "Main tuned Fabric settings",
        "description": "Main Fabric configuration used by the demo pipeline and benchmark API flows.",
        "block_size": "max_message_count=50, preferred_max_bytes=2 MB, absolute_max_bytes=10 MB",
        "batch_timeout": "2s",
        "endorsement_policy": "current",
        "read_tps": None,
        "write_tps": None,
        "write_pressure": None,
        "status": "not_run",
        "reason": "Run all benchmarks to collect the main tuned Fabric settings.",
    },
    {
        "profile_id": "light_endorsement",
        "label": "Light endorsement",
        "description": "Lighter endorsement policy if chaincode/config supports it.",
        "block_size": "current",
        "batch_timeout": "current",
        "endorsement_policy": "not_applicable",
        "read_tps": None,
        "write_tps": None,
        "write_pressure": None,
        "status": "not_supported",
        "reason": "Endorsement policy cannot be changed safely after chaincode deployment in this runner.",
    },
]


NUMERIC_FIELDS = {
    "full_lifecycle_ms",
    "auth_allow_ms",
    "revocation_ms",
    "proof_refresh_ms",
    "ledger_read_ms",
    "ledger_write_ms",
    "read_p50_ms",
    "read_p95_ms",
    "write_p50_ms",
    "write_p95_ms",
    "read_tps",
    "write_tps",
    "tps",
    "cpu",
    "ram",
    "cpu_peak",
    "ram_peak",
}


def load_tuning_results(results_dir: str | Path) -> dict[str, Any]:
    directory = Path(results_dir)
    by_profile = {profile["profile_id"]: dict(profile) for profile in PROFILES}
    sources: list[str] = []
    if directory.exists():
        for path in sorted(directory.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                continue
            profile_id = canonical_profile_id(str(data.get("profile_id") or path.stem))
            if profile_id not in by_profile:
                continue
            data["profile_id"] = profile_id
            if not data.get("write_pressure"):
                pressure = latest_write_pressure(directory, profile_id)
                if pressure:
                    data["write_pressure"] = pressure
                    data["write_pressure_summary_path"] = pressure.get("summary_path")
            merged = {**by_profile[profile_id], **normalize_profile_result(data)}
            merged = canonical_profile_metadata(merged)
            merged["source"] = str(path)
            by_profile[profile_id] = merged
            sources.append(str(path))
    if by_profile["current"].get("status") in {"not_run", "not_supported"}:
        saved_current = latest_profile_from_benchmark_results(directory.parent / "benchmark-results", "current")
        if saved_current:
            by_profile["current"] = {
                **by_profile["current"],
                **normalize_profile_result(saved_current),
                "label": "Original Fabric baseline",
                "description": "Saved comparison profile using the original Fabric test-network batch settings.",
                "source": saved_current.get("source"),
            }
            if saved_current.get("source"):
                sources.append(str(saved_current["source"]))
    return {
        "benchmark_type": "fabric_tuning",
        "profile": "fabric_tuning_matrix",
        "mode": "fabric",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profiles": [by_profile[profile["profile_id"]] for profile in PROFILES],
        "source": ",".join(sources) if sources else None,
    }


def normalize_profile_result(data: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(data)
    normalized["profile_id"] = canonical_profile_id(str(normalized.get("profile_id") or ""))
    for key in NUMERIC_FIELDS:
        normalized[key] = _float_or_none(normalized.get(key))
    if normalized.get("cpu_peak") is None:
        normalized["cpu_peak"] = normalized.get("cpu")
    if normalized.get("ram_peak") is None:
        normalized["ram_peak"] = normalized.get("ram")
    normalized["status"] = str(normalized.get("status") or "not_run")
    normalized["reason"] = normalized.get("reason") or normalized.get("error") or None
    return canonical_profile_metadata(normalized)


def canonical_profile_metadata(profile: dict[str, Any]) -> dict[str, Any]:
    profile_id = str(profile.get("profile_id") or "")
    if profile_id == "current":
        return {
            **profile,
            "label": "Original Fabric baseline",
            "description": "Saved comparison profile using the original Fabric test-network batch settings.",
            "block_size": "max_message_count=10, preferred_max_bytes=512 KB, absolute_max_bytes=99 MB",
            "batch_timeout": "2s",
        }
    if profile_id == "larger_batch":
        return {
            **profile,
            "label": "Main tuned Fabric settings",
            "description": "Main Fabric configuration used by the demo pipeline and benchmark API flows.",
            "block_size": "max_message_count=50, preferred_max_bytes=2 MB, absolute_max_bytes=10 MB",
            "batch_timeout": "2s",
        }
    if profile_id == "low_latency":
        return {
            **profile,
            "label": "Fast block commit",
        }
    return profile


def canonical_profile_id(profile_id: str) -> str:
    return PROFILE_ALIASES.get(profile_id, profile_id)


def latest_write_pressure(directory: Path, profile_id: str) -> dict[str, Any] | None:
    raw_dir = directory / f"{profile_id}-raw"
    if not raw_dir.exists():
        return None
    candidates = sorted(
        raw_dir.glob("fabric_write_pressure_*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            data.setdefault("summary_path", str(path))
            return data
    return None


def latest_profile_from_benchmark_results(results_dir: Path, profile_id: str) -> dict[str, Any] | None:
    if not results_dir.exists():
        return None
    candidates = sorted(
        results_dir.glob("*/fabric_tuning_*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        for profile in data.get("profiles", []):
            if not isinstance(profile, dict):
                continue
            if canonical_profile_id(str(profile.get("profile_id") or "")) == profile_id:
                row = dict(profile)
                row["profile_id"] = profile_id
                row["source"] = str(path)
                return row
    return None


def _float_or_none(value: Any) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


if __name__ == "__main__":
    import sys

    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/dashboard/fabric-tuning-results")
    print(json.dumps(load_tuning_results(path), indent=2, sort_keys=True))
