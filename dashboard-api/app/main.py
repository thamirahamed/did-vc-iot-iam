import csv
import json
from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .config import load_project_env

load_project_env()

from . import client
from .models import (
    AuthorizeRequest,
    BenchmarkRunRequest,
    BenchmarkSuiteRunRequest,
    CapabilityIssueRequest,
    CleanStateRequest,
    DeviceCreateRequest,
    RevokeRequest,
    ScenarioRunRequest,
)
from .store import DeviceStore


dashboard_data_dir = Path(os.getenv("DASHBOARD_DATA_DIR", "data/dashboard"))
store = DeviceStore(os.getenv("DASHBOARD_DB_PATH", str(dashboard_data_dir / "dashboard.db")))
app = FastAPI(title="Dashboard API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

benchmark_lock = threading.Lock()
BENCHMARK_TYPES = {
    "local",
    "fabric_pipeline",
    "fabric_ops",
    "constrained",
    "revocation_connectivity",
    "fabric_tuning",
}

BENCHMARK_LABELS = {
    "did_create_ms": ("did_create", "Register device DID", "Identity"),
    "did_resolve_ms": ("did_resolve", "Resolve device DID", "Identity"),
    "identity_vc_issue_ms": ("identity_issue", "Issue identity VC", "Credentials"),
    "capability_vc_issue_ms": ("capability_issue", "Issue capability VC", "Credentials"),
    "auth_allow_ms": ("auth_allow", "Verify valid access", "Authorization"),
    "auth_wrong_action_deny_ms": ("wrong_action_deny", "Deny wrong action", "Authorization"),
    "revoke_capability_ms": ("revoke_capability", "Revoke capability VC", "Revocation"),
    "auth_revoked_or_stale_deny_ms": ("revoked_deny", "Deny revoked credential", "Revocation"),
    "replacement_capability_issue_ms": (
        "replacement_capability_issue",
        "Issue replacement capability VC",
        "Recovery",
    ),
    "proof_refresh_ms": ("proof_refresh", "Refresh accumulator proof", "Accumulator"),
    "auth_replacement_allow_ms": ("replacement_allow", "Verify restored access", "Recovery"),
    "full_iteration_ms": ("full_lifecycle", "Full lifecycle", "Lifecycle"),
}

FABRIC_PIPELINE_EXPECTED_METRICS = tuple(BENCHMARK_LABELS.keys())

FABRIC_OP_LABELS = {
    "ping": ("fabric_ping", "Fabric chaincode ping", "Fabric"),
    "register_did": ("did_write", "Write DID registry", "Fabric DID"),
    "read_did": ("did_read", "Read DID registry", "Fabric DID"),
    "register_credential_status": (
        "credential_write",
        "Write credential status",
        "Credential Status",
    ),
    "read_credential_status": (
        "credential_read",
        "Read credential status",
        "Credential Status",
    ),
    "revoke_credential": ("fabric_revoke_credential", "Revoke credential", "Revocation"),
    "put_accumulator_state": (
        "accumulator_write",
        "Write accumulator state",
        "Accumulator",
    ),
    "get_accumulator_state": (
        "accumulator_read",
        "Read accumulator state",
        "Accumulator",
    ),
    "register_credential_with_accumulator_state": (
        "fabric_register_credential_with_accumulator",
        "Register credential with accumulator",
        "Combined",
    ),
    "revoke_credential_with_accumulator_state": (
        "fabric_revoke_credential_with_accumulator",
        "Revoke credential with accumulator",
        "Combined",
    ),
    "add_audit_event": ("audit_write", "Write audit event", "Audit"),
    "list_audit_events": ("fabric_list_audit_events", "List audit events", "Audit"),
}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/dashboard/config")
def dashboard_config() -> dict[str, Any]:
    fabric_samples_raw = os.getenv("FABRIC_SAMPLES_PATH", "")
    fabric_samples_path = Path(fabric_samples_raw) if fabric_samples_raw else None
    fabric_test_network_path = _fabric_test_network_path()
    wrapper_path = _fabric_wrapper_path()
    crlf_files = _crlf_files(fabric_test_network_path, wrapper_path)
    return {
        "fabric_samples_path": str(fabric_samples_path) if fabric_samples_path else None,
        "fabric_test_network_path": str(fabric_test_network_path) if fabric_test_network_path else None,
        "fabric_samples_path_exists": fabric_samples_path.exists() if fabric_samples_path else False,
        "fabric_test_network_exists": fabric_test_network_path.exists() if fabric_test_network_path else False,
        "fabric_network_wrapper_exists": wrapper_path.exists() if wrapper_path else False,
        "fabric_scripts_crlf_detected": bool(crlf_files),
        "fabric_scripts_crlf_files": [str(path) for path in crlf_files[:10]],
        "dashboard_db_path": os.getenv("DASHBOARD_DB_PATH", str(dashboard_data_dir / "dashboard.db")),
        "issuer_url": client.ISSUER_URL,
        "verifier_url": client.VERIFIER_URL,
        "fabric_adapter_url": client.FABRIC_ADAPTER_URL,
    }


@app.post("/dashboard/performance/benchmarks/run")
def run_benchmark(payload: BenchmarkRunRequest) -> dict[str, Any]:
    if payload.benchmark_type not in BENCHMARK_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported benchmark type.")
    if payload.runs < 1:
        raise HTTPException(status_code=400, detail="runs must be at least 1")
    if payload.warmup_runs < 0:
        raise HTTPException(status_code=400, detail="warmup_runs must be 0 or greater")
    if store.running_benchmark_job() is not None or store.running_benchmark_suite() is not None:
        raise HTTPException(status_code=409, detail="A benchmark is already running.")

    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "benchmark_type": payload.benchmark_type,
        "status": "queued",
        "started_at": _now(),
        "finished_at": None,
        "error": None,
        "stdout_tail": "",
        "stderr_tail": "",
        "summary": None,
        "return_code": None,
        "output_dir": None,
        "summary_path": None,
        "raw_path": None,
    }
    store.add_benchmark_job(job)
    thread = threading.Thread(
        target=_run_benchmark_job,
        args=(job_id, payload.benchmark_type, payload.runs, payload.warmup_runs),
        daemon=True,
    )
    thread.start()
    return {"job_id": job_id, "status": "queued"}


@app.post("/dashboard/performance/benchmarks/run-constrained")
def run_constrained_benchmark(payload: BenchmarkSuiteRunRequest) -> dict[str, Any]:
    return _start_single_benchmark("constrained", payload.runs, payload.warmup_runs)


@app.get("/dashboard/performance/benchmarks/constrained/latest")
def latest_constrained_benchmark() -> dict[str, Any]:
    return {"job": store.latest_benchmark_job_by_type("constrained")}


@app.post("/dashboard/performance/benchmarks/run-tuning")
def run_tuning_benchmark(payload: BenchmarkSuiteRunRequest) -> dict[str, Any]:
    return _start_single_benchmark("fabric_tuning", payload.runs, payload.warmup_runs)


@app.get("/dashboard/performance/benchmarks/tuning/latest")
def latest_tuning_benchmark() -> dict[str, Any]:
    job = store.latest_benchmark_job_by_type("fabric_tuning")
    return {"job": _job_with_saved_fabric_tuning(job)}


@app.post("/dashboard/performance/benchmarks/run-revocation-connectivity")
def run_revocation_connectivity_benchmark(payload: BenchmarkSuiteRunRequest) -> dict[str, Any]:
    return _start_single_benchmark("revocation_connectivity", payload.runs, payload.warmup_runs)


@app.get("/dashboard/performance/benchmarks/revocation-connectivity/latest")
def latest_revocation_connectivity_benchmark() -> dict[str, Any]:
    return {"job": store.latest_benchmark_job_by_type("revocation_connectivity")}


@app.post("/dashboard/performance/benchmarks/run-all")
def run_all_benchmarks(payload: BenchmarkSuiteRunRequest) -> dict[str, Any]:
    if payload.runs < 1:
        raise HTTPException(status_code=400, detail="runs must be at least 1")
    if payload.warmup_runs < 0:
        raise HTTPException(status_code=400, detail="warmup_runs must be 0 or greater")
    if store.running_benchmark_job() is not None or store.running_benchmark_suite() is not None:
        raise HTTPException(status_code=409, detail="A benchmark suite is already running.")

    suite_id = str(uuid.uuid4())
    suite = {
        "suite_job_id": suite_id,
        "status": "queued",
        "started_at": _now(),
        "finished_at": None,
        "current_step": None,
        "error": None,
        "steps": [],
        "combined_summary": None,
    }
    store.add_benchmark_suite(suite)
    thread = threading.Thread(
        target=_run_benchmark_suite,
        args=(suite_id, payload.runs, payload.warmup_runs),
        daemon=True,
    )
    thread.start()
    return {"suite_job_id": suite_id, "status": "queued"}


@app.get("/dashboard/performance/benchmarks/latest-suite")
def latest_benchmark_suite() -> dict[str, Any]:
    return {"suite": _suite_with_saved_fabric_tuning(store.latest_benchmark_suite())}


@app.get("/dashboard/performance/benchmarks/suites/{suite_job_id}")
def get_benchmark_suite(suite_job_id: str) -> dict[str, Any]:
    suite = store.get_benchmark_suite(suite_job_id)
    if suite is None:
        raise HTTPException(status_code=404, detail="Benchmark suite not found.")
    return _suite_with_saved_fabric_tuning(suite)


@app.get("/dashboard/performance/benchmarks/latest")
def latest_benchmark() -> dict[str, Any]:
    return {"job": store.latest_benchmark_job()}


@app.get("/dashboard/performance/benchmarks/{job_id}")
def get_benchmark_job(job_id: str) -> dict[str, Any]:
    job = store.get_benchmark_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Benchmark job not found.")
    return job


def _start_single_benchmark(benchmark_type: str, runs: int, warmup_runs: int) -> dict[str, Any]:
    if benchmark_type not in BENCHMARK_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported benchmark type.")
    if runs < 1:
        raise HTTPException(status_code=400, detail="runs must be at least 1")
    if warmup_runs < 0:
        raise HTTPException(status_code=400, detail="warmup_runs must be 0 or greater")
    if store.running_benchmark_job() is not None or store.running_benchmark_suite() is not None:
        raise HTTPException(status_code=409, detail="A benchmark is already running.")

    job_id = str(uuid.uuid4())
    store.add_benchmark_job(
        {
            "job_id": job_id,
            "benchmark_type": benchmark_type,
            "status": "queued",
            "started_at": _now(),
            "finished_at": None,
            "error": None,
            "stdout_tail": "",
            "stderr_tail": "",
            "summary": None,
            "return_code": None,
            "output_dir": None,
            "summary_path": None,
            "raw_path": None,
        }
    )
    thread = threading.Thread(
        target=_run_benchmark_job,
        args=(job_id, benchmark_type, runs, warmup_runs),
        daemon=True,
    )
    thread.start()
    return {"job_id": job_id, "status": "queued"}


@app.get("/dashboard/devices")
def list_devices() -> dict[str, Any]:
    return {"devices": [_public_device(device) for device in store.list_devices()]}


@app.post("/dashboard/devices")
def create_device(payload: DeviceCreateRequest) -> dict[str, Any]:
    now = _now()
    device_id = str(uuid.uuid4())
    private_key_b64, public_key_b64 = client.generate_device_keypair()
    did_response = _call_or_502(lambda: client.create_did(public_key_b64), "DID creation failed")
    did = did_response.get("did")
    if not did:
        raise HTTPException(status_code=502, detail="DID creation response did not include did")

    device = {
        "id": device_id,
        "label": payload.label or f"device-{len(store.list_devices()) + 1:02d}",
        "did": did,
        "status": "active",
        "public_key": public_key_b64,
        "public_key_prefix": public_key_b64[:16],
        "private_key": private_key_b64,
        "did_document": did_response.get("did_document"),
        "identity_vc": None,
        "identity_proof": None,
        "capability_vc": None,
        "capability_proof": None,
        "credential_status": "not-issued",
        "created_at": now,
        "updated_at": now,
        "last_decision": None,
        "last_error": None,
    }
    created = store.add_device(device)
    return {"device": _public_device(created)}


@app.get("/dashboard/devices/{device_id}")
def get_device(device_id: str) -> dict[str, Any]:
    return {"device": _public_device(_require_device(device_id))}


@app.post("/dashboard/devices/{device_id}/issue-identity")
def issue_identity(device_id: str) -> dict[str, Any]:
    device = _require_device(device_id)
    _require_did(device)
    vc, proof = _call_or_502(
        lambda: client.issue_identity(device["did"], device["public_key"]),
        "Identity VC issuance failed",
    )
    updated = _update(device_id, {"identity_vc": vc, "identity_proof": proof, "last_error": None})
    _record_credential_link(updated, vc, "identity")
    return {"device": _public_device(updated)}


@app.post("/dashboard/devices/{device_id}/issue-capability")
def issue_capability(device_id: str, payload: CapabilityIssueRequest) -> dict[str, Any]:
    device = _require_device(device_id)
    _require_did(device)
    vc, proof = _call_or_502(
        lambda: client.issue_capability(device["did"], payload.action, payload.resource),
        "Capability VC issuance failed",
    )
    identity_proof = device.get("identity_proof")
    identity_vc = device.get("identity_vc")
    if isinstance(identity_vc, dict) and identity_vc.get("id"):
        try:
            identity_proof = client.refresh_proof(identity_vc["id"])
        except Exception as exc:
            _update(device_id, {"last_error": f"Identity proof refresh failed after capability issuance: {exc}"})
            raise HTTPException(
                status_code=502,
                detail=f"Identity proof refresh failed after capability issuance: {exc}",
            ) from exc
    accumulator = _optional_accumulator_state()
    patch = {
        "capability_vc": vc,
        "capability_proof": proof,
        "identity_proof": identity_proof,
        "credential_status": "active",
        "last_error": None,
    }
    if accumulator is not None:
        patch["last_accumulator_state"] = accumulator
    updated = _update(device_id, patch)
    _record_credential_link(updated, vc, "capability")
    return {"device": _public_device(updated)}


@app.post("/dashboard/devices/{device_id}/refresh-proof")
def refresh_device_proofs(device_id: str) -> dict[str, Any]:
    device = _require_device(device_id)
    patch: dict[str, Any] = {"last_error": None}
    identity_vc = device.get("identity_vc")
    capability_vc = device.get("capability_vc")
    try:
        if isinstance(identity_vc, dict) and identity_vc.get("id"):
            patch["identity_proof"] = client.refresh_proof(identity_vc["id"])
        if isinstance(capability_vc, dict) and capability_vc.get("id"):
            patch["capability_proof"] = client.refresh_proof(capability_vc["id"])
    except Exception as exc:
        _update(device_id, {"last_error": f"Proof refresh failed: {exc}"})
        raise HTTPException(status_code=502, detail=f"Proof refresh failed: {exc}") from exc
    if len(patch) == 1:
        raise HTTPException(status_code=400, detail="device has no credentials to refresh")
    updated = _update(device_id, patch)
    return {"device": _public_device(updated)}


@app.post("/dashboard/devices/{device_id}/authorize")
def authorize_device(device_id: str, payload: AuthorizeRequest) -> dict[str, Any]:
    device = _require_device(device_id)
    identity_vc = device.get("identity_vc")
    capability_vc = device.get("capability_vc")
    if not isinstance(identity_vc, dict) or not isinstance(capability_vc, dict):
        raise HTTPException(status_code=400, detail="identity and capability VCs are required")
    auth_payload = client.sign_authorization_payload(
        private_key_b64=device["private_key"],
        identity_vc=identity_vc,
        capability_vc=capability_vc,
        action=payload.action,
        resource=payload.resource,
        identity_proof=device.get("identity_proof"),
        capability_proof=device.get("capability_proof"),
        tamper_signature=payload.tamper_signature,
    )
    decision = _call_or_502(lambda: client.authorize(auth_payload), "Authorization failed")
    updated = _update(
        device_id,
        {
            "last_decision": decision.get("decision"),
            "last_reason": decision.get("reason"),
            "last_error": None,
        },
    )
    _record_device_event(
        updated,
        "AUTH_ALLOW" if decision.get("decision") == "allow" else "AUTH_DENY",
        service="dashboard",
        credential_id=_credential_id(capability_vc),
        result=decision.get("decision") or "recorded",
        reason=decision.get("reason") or "authorized",
    )
    return {"decision": decision, "device": _public_device(updated)}


@app.post("/dashboard/devices/{device_id}/revoke")
def revoke_device(device_id: str, payload: RevokeRequest) -> dict[str, Any]:
    device = _require_device(device_id)
    capability_vc = device.get("capability_vc")
    if not isinstance(capability_vc, dict) or not capability_vc.get("id"):
        raise HTTPException(status_code=400, detail="device has no capability VC to revoke")
    _record_credential_link(device, capability_vc, "capability")
    revoke_response = _call_or_502(
        lambda: client.revoke(capability_vc["id"], payload.reason),
        "Capability revocation failed",
    )
    accumulator = _optional_accumulator_state()
    patch = {
        "credential_status": "revoked",
        "status": "revoked",
        "last_error": None,
    }
    if accumulator is not None:
        patch["last_accumulator_state"] = accumulator
    updated = _update(device_id, patch)
    return {"revoke": revoke_response, "device": _public_device(updated)}


@app.post("/dashboard/devices/{device_id}/restore-access")
def restore_device_access(device_id: str) -> dict[str, Any]:
    device = _require_device(device_id)
    _require_did(device)
    if device.get("status") != "revoked":
        raise HTTPException(
            status_code=400,
            detail="Device is not revoked. Restore Access is only for revoked devices.",
        )

    identity_vc = device.get("identity_vc")
    identity_proof = device.get("identity_proof")
    if not isinstance(identity_vc, dict) or not identity_vc.get("id"):
        try:
            identity_vc, identity_proof = client.issue_identity_with_proof(
                device["did"],
                device["public_key"],
            )
        except Exception as exc:
            detail = (
                "Identity VC is not present in issuer accumulator. "
                f"Reissuing identity credential for restore failed: {exc}"
            )
            _raise_restore_conflict(device_id, detail, exc)
    else:
        try:
            identity_proof = client.refresh_proof(identity_vc["id"])
        except Exception as exc:
            if not _is_accumulator_missing_error(exc):
                detail = str(exc)
                _raise_restore_conflict(device_id, detail, exc)
            try:
                identity_vc, identity_proof = client.issue_identity_with_proof(
                    device["did"],
                    device["public_key"],
                )
            except Exception as issue_exc:
                detail = (
                    "Identity VC is not present in issuer accumulator. "
                    f"Reissuing identity credential for restore failed: {issue_exc}"
                )
                _raise_restore_conflict(device_id, detail, issue_exc)

    if not isinstance(identity_proof, dict):
        _raise_restore_conflict(
            device_id,
            "Restore failed because identity proof is missing after identity preparation.",
        )

    old_capability_id = _credential_id(device.get("capability_vc"))
    try:
        capability_vc, capability_proof = client.issue_capability_with_proof(
            device["did"],
            "read",
            "iot:device:example",
        )
    except Exception as exc:
        _raise_restore_conflict(device_id, str(exc), exc)

    fresh_capability_id = _credential_id(capability_vc)
    if not fresh_capability_id:
        _raise_restore_conflict(
            device_id,
            "Restore failed because fresh capability credential did not include an id.",
        )
    if fresh_capability_id == old_capability_id:
        _raise_restore_conflict(
            device_id,
            "Restore failed because issuer reused the revoked capability credential id.",
        )
    _validate_proof_for_credential(
        device_id,
        capability_proof,
        fresh_capability_id,
        "fresh capability issuance proof",
    )
    try:
        capability_proof = client.refresh_proof(fresh_capability_id)
    except Exception as exc:
        detail = (
            "Restore failed because the fresh capability credential was not registered "
            f"in the accumulator. {exc}"
        )
        _raise_restore_conflict(device_id, detail, exc)
    _validate_proof_for_credential(
        device_id,
        capability_proof,
        fresh_capability_id,
        "fresh capability accumulator proof",
    )

    if isinstance(identity_vc, dict) and identity_vc.get("id"):
        try:
            identity_proof = client.refresh_proof(identity_vc["id"])
        except Exception as exc:
            detail = (
                "Restore failed after capability issuance because identity proof refresh failed."
                f" {exc}"
            )
            _raise_restore_conflict(device_id, detail, exc)
    _validate_proof_for_credential(
        device_id,
        identity_proof,
        str(identity_vc.get("id")),
        "identity proof after capability issuance",
    )

    accumulator = _optional_accumulator_state()
    patch = {
        "status": "active",
        "identity_vc": identity_vc,
        "identity_proof": identity_proof,
        "capability_vc": capability_vc,
        "capability_proof": capability_proof,
        "credential_status": "active",
        "last_decision": None,
        "last_reason": None,
        "last_error": None,
    }
    if accumulator is not None:
        patch["last_accumulator_state"] = accumulator
    updated = _update(device_id, patch)
    _record_credential_link(updated, identity_vc, "identity")
    _record_credential_link(updated, capability_vc, "capability")
    _record_device_event(
        updated,
        "ACCESS_RESTORED",
        service="dashboard",
        credential_id=fresh_capability_id,
        result="active",
        reason="access restored",
    )
    return {"device": _public_device(updated)}


@app.get("/dashboard/devices/{device_id}/audit-events")
def get_device_audit_events(
    device_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
) -> dict[str, Any]:
    device = _require_device(device_id)
    events, warnings = _combined_audit_events(500)
    scoped = [
        _device_timeline_item(event, device)
        for event in events
        if _event_belongs_to_device(event, device)
        and event.get("service") != "dashboard-map"
    ]
    scoped.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    total = len(scoped)
    total_pages = max(1, (total + page_size - 1) // page_size)
    if page > total_pages:
        page = total_pages
    start = (page - 1) * page_size
    return {
        "items": scoped[start : start + page_size],
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "warnings": warnings,
    }


@app.get("/dashboard/scenarios/results")
def get_scenario_results(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
) -> dict[str, Any]:
    return store.list_scenario_results(page, page_size)


@app.post("/dashboard/scenarios/{scenario_id}")
def run_scenario(scenario_id: str, payload: ScenarioRunRequest) -> dict[str, Any]:
    scenarios = {
        "happy-path": ("Happy Path", "allow", _run_happy_path_scenario),
        "wrong-action": ("Wrong Action Attack", "deny", _run_wrong_action_scenario),
        "bad-signature": ("Bad Signature Attack", "deny", _run_bad_signature_scenario),
        "revocation": ("Revocation Scenario", "deny", _run_revocation_scenario),
        "proof-refresh": ("Proof Refresh Scenario", "allow", _run_proof_refresh_scenario),
    }
    if scenario_id not in scenarios:
        raise HTTPException(status_code=404, detail="Scenario not found.")

    scenario_name, expected, runner = scenarios[scenario_id]
    device = _require_device(payload.device_id)
    try:
        decision, updated_device, reason_prefix = runner(device)
        actual = _decision_value(decision)
        reason = _scenario_reason(decision, reason_prefix)
        status = "pass" if actual == expected else "fail"
        result = _store_scenario_result(
            scenario_id,
            scenario_name,
            updated_device,
            expected,
            actual,
            reason,
            status,
            {"decision": decision},
        )
        return {"result": result, "device": _public_device(updated_device)}
    except HTTPException as exc:
        latest = store.get_device(payload.device_id) or device
        result = _store_scenario_result(
            scenario_id,
            scenario_name,
            latest,
            expected,
            "error",
            str(exc.detail),
            "error",
            {"error": exc.detail},
        )
        raise HTTPException(status_code=exc.status_code, detail=str(exc.detail)) from exc
    except Exception as exc:
        latest = store.get_device(payload.device_id) or device
        result = _store_scenario_result(
            scenario_id,
            scenario_name,
            latest,
            expected,
            "error",
            str(exc),
            "error",
            {"error": str(exc)},
        )
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/dashboard/accumulator/state")
def get_accumulator_state() -> dict[str, Any]:
    try:
        return client.accumulator_state()
    except RuntimeError as exc:
        text = str(exc)
        if _is_upstream_unavailable(text):
            raise HTTPException(status_code=503, detail="Issuer unavailable.") from exc
        raise HTTPException(status_code=503, detail=f"Accumulator state read failed: {exc}") from exc


@app.get("/dashboard/audit/events")
def get_audit_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(15, ge=1, le=100),
    limit: int | None = Query(None, ge=1),
) -> dict[str, Any]:
    devices = store.list_devices()
    fetch_limit = limit or int(os.getenv("DASHBOARD_AUDIT_FETCH_LIMIT", "5000"))
    events, warnings = _combined_audit_events(fetch_limit)
    visible_events = [event for event in events if event.get("service") != "dashboard-map"]
    normalized_events = _normalize_audit_events(visible_events, devices)
    total = len(normalized_events)
    total_pages = max(1, (total + page_size - 1) // page_size)
    safe_page = min(page, total_pages)
    start = (safe_page - 1) * page_size
    items = normalized_events[start : start + page_size]
    return {
        "items": items,
        "events": items,
        "page": safe_page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "warnings": warnings,
    }


@app.post("/dashboard/clean-state")
def clean_state(payload: CleanStateRequest) -> dict[str, Any]:
    if payload.confirm != "RESET":
        raise HTTPException(status_code=400, detail="confirm must be exactly RESET")
    if payload.reset_fabric:
        raise HTTPException(
            status_code=400,
            detail="Fabric reset is no longer supported from the dashboard UI. Run Fabric reset manually from Git Bash.",
        )

    store.clear_all()
    return {
        "ok": True,
        "dashboard_cleared": True,
        "fabric_reset": False,
        "message": "Dashboard demo session reset. Fabric ledger was not changed.",
    }


@app.get("/dashboard/ledger/summary")
def ledger_summary() -> dict[str, Any]:
    devices = store.list_devices()
    accumulator, accumulator_error = _issuer_accumulator_state_for_summary()
    issuer, issuer_warning = client.optional_get(f"{client.ISSUER_URL}/health")
    verifier, verifier_warning = client.optional_get(f"{client.VERIFIER_URL}/health")
    adapter, adapter_warning = client.optional_get(f"{client.FABRIC_ADAPTER_URL}/health")
    warnings = [
        warning
        for warning in (accumulator_error, issuer_warning, verifier_warning, adapter_warning)
        if warning
    ]
    return {
        "registered_devices": len(devices),
        "active_credentials": sum(1 for device in devices if _has_active_capability(device)),
        "revoked_credentials": sum(1 for device in devices if _has_revoked_capability(device)),
        "accumulator_version": _accumulator_field(accumulator, "version", "unknown"),
        "accumulator_root": accumulator.get("root") if accumulator else None,
        "accumulator_state_ok": accumulator_error is None,
        "accumulator_state_error": accumulator_error,
        "issuer_health": _health_text(issuer),
        "verifier_health": _health_text(verifier),
        "fabric_adapter_health": _health_text(adapter),
        "fabric_network": "connected" if _is_ok(adapter) else "unknown",
        "warnings": warnings,
    }


def _require_device(device_id: str) -> dict[str, Any]:
    device = store.get_device(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found.")
    return device


def _require_did(device: dict[str, Any]) -> None:
    if not device.get("did") or not device.get("public_key"):
        raise HTTPException(status_code=400, detail="device DID and public key are required")


def _update(device_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    patch["updated_at"] = _now()
    updated = store.update_device(device_id, patch)
    if updated is None:
        raise HTTPException(status_code=404, detail="Device not found.")
    return updated


def _public_device(device: dict[str, Any]) -> dict[str, Any]:
    public = {
        key: value
        for key, value in device.items()
        if key not in {"private_key", "public_key"}
    }
    public["has_private_key"] = bool(device.get("private_key"))
    return public


def _run_benchmark_job(job_id: str, benchmark_type: str, runs: int, warmup_runs: int) -> None:
    with benchmark_lock:
        _execute_benchmark_job(job_id, benchmark_type, runs, warmup_runs)


def _run_benchmark_suite(suite_id: str, runs: int, warmup_runs: int) -> None:
    with benchmark_lock:
        steps: list[dict[str, Any]] = []
        store.update_benchmark_suite(suite_id, {"status": "running", "started_at": _now()})
        for benchmark_type in (
            "local",
            "fabric_pipeline",
            "fabric_ops",
            "constrained",
            "revocation_connectivity",
            "fabric_tuning",
        ):
            store.update_benchmark_suite(
                suite_id,
                {
                    "status": "running",
                    "current_step": benchmark_type,
                    "steps": steps,
                },
            )
            job_id = str(uuid.uuid4())
            store.add_benchmark_job(
                {
                    "job_id": job_id,
                    "benchmark_type": benchmark_type,
                    "status": "queued",
                    "started_at": _now(),
                    "finished_at": None,
                    "error": None,
                    "stdout_tail": "",
                    "stderr_tail": "",
                    "summary": None,
                    "return_code": None,
                    "output_dir": None,
                    "summary_path": None,
                    "raw_path": None,
                }
            )
            job = _execute_benchmark_job(
                job_id,
                benchmark_type,
                runs,
                warmup_runs,
                extra_env=_benchmark_suite_step_env(benchmark_type, steps),
            )
            step = {
                "benchmark_type": benchmark_type,
                "status": job["status"],
                "job_id": job_id,
                "summary": job.get("summary"),
                "error": job.get("error"),
                "profile": _summary_value(job.get("summary"), "profile"),
                "mode": _summary_value(job.get("summary"), "mode"),
                "output_dir": job.get("output_dir"),
                "summary_path": job.get("summary_path"),
                "raw_path": job.get("raw_path"),
                "stdout_tail": job.get("stdout_tail"),
                "stderr_tail": job.get("stderr_tail"),
            }
            steps.append(step)
            combined = _build_combined_benchmark_summary(steps)
            store.update_benchmark_suite(
                suite_id,
                {
                    "steps": steps,
                    "combined_summary": combined,
                    "current_step": benchmark_type,
                },
            )
        failed_steps = [step for step in steps if step.get("status") == "failed"]
        succeeded_steps = [step for step in steps if step.get("status") == "completed"]
        final_status = "completed_with_errors" if failed_steps and succeeded_steps else "failed" if failed_steps else "completed"
        final_error = "; ".join(
            str(step.get("error") or f"{_benchmark_name(str(step.get('benchmark_type')))} benchmark failed")
            for step in failed_steps
        ) or None
        store.update_benchmark_suite(
            suite_id,
            {
                "status": final_status,
                "finished_at": _now(),
                "current_step": None,
                "steps": steps,
                "combined_summary": _build_combined_benchmark_summary(steps),
                "error": final_error,
            },
        )
        if succeeded_steps:
            _record_benchmark_event(
                "BENCHMARK_COMPLETED",
                final_status,
                "benchmark suite completed with errors" if failed_steps else "benchmark suite completed",
                suite_id=suite_id,
            )


def _execute_benchmark_job(
    job_id: str,
    benchmark_type: str,
    runs: int,
    warmup_runs: int,
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    output_root = Path(os.getenv("BENCHMARK_OUTPUT_DIR", "/data/dashboard/benchmark-results"))
    output_dir = output_root / job_id
    output_dir.mkdir(parents=True, exist_ok=True)
    store.update_benchmark_job(
        job_id,
        {
            "status": "running",
            "started_at": _now(),
            "output_dir": str(output_dir),
            "summary_path": None,
            "raw_path": None,
            "summary": None,
        },
    )
    try:
        command, env = _benchmark_command(benchmark_type, runs, warmup_runs, output_dir)
        if extra_env:
            env.update(extra_env)
        if benchmark_type in {"fabric_pipeline", "fabric_ops", "fabric_tuning"}:
            _require_fabric_adapter_health()
        resource_monitor = DockerResourceMonitor(_benchmark_name(benchmark_type))
        resource_monitor.start()
        before = set(output_dir.glob("*"))
        try:
            process = subprocess.run(
                command,
                cwd=_repo_root(),
                env=env,
                capture_output=True,
                text=True,
                timeout=int(os.getenv("BENCHMARK_TIMEOUT_SECONDS", "900")),
                shell=False,
            )
        finally:
            resource_monitor.stop()
        after = set(output_dir.glob("*"))
        created = sorted(after - before, key=lambda path: path.stat().st_mtime, reverse=True)
        resource_rows = resource_monitor.summary()
        resource_error = resource_monitor.error
        stdout_tail = _tail(process.stdout)
        stderr_tail = _tail(process.stderr)
        status = "completed" if process.returncode == 0 else "failed"
        error = None
        summary = None
        summary_path = None
        raw_path = _find_raw_output_path(benchmark_type, created, output_dir)
        if status == "completed":
            summary, summary_path = _parse_benchmark_summary(benchmark_type, created, output_dir)
            summary["resource_usage"] = resource_rows
            summary["resource_usage_available"] = bool(resource_rows)
            if resource_error:
                summary["resource_usage_reason"] = resource_error
            if benchmark_type == "fabric_pipeline":
                missing = list(summary.get("missing_metrics") or [])
                if missing:
                    message = f"Fabric pipeline completed with missing metrics: {missing}"
                    summary["diagnostic"] = message
                    print(f"[dashboard-api] {message}. summary_path={summary_path}")
                headline_missing = [
                    key
                    for key in ("full_lifecycle_ms", "auth_allow_ms", "revocation_ms", "proof_refresh_ms")
                    if summary.get(key) is None
                ]
                if headline_missing or not summary.get("operations"):
                    print(
                        f"[dashboard-api] Fabric pipeline completed but summary normalization "
                        f"found missing keys: {headline_missing or []}, operations: {len(summary.get('operations') or [])}. "
                        f"summary_path={summary_path}"
                    )
        if process.returncode != 0:
            error = _short_benchmark_error(
                benchmark_type,
                stderr_tail or stdout_tail or f"exited with status {process.returncode}",
            )

        store.update_benchmark_job(
            job_id,
            {
                "status": status,
                "finished_at": _now(),
                "summary": summary,
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
                "error": error,
                "return_code": process.returncode,
                "output_dir": str(output_dir),
                "summary_path": str(summary_path) if summary_path else None,
                "raw_path": str(raw_path) if raw_path else None,
            },
        )
        if status == "completed" and benchmark_type == "fabric_ops":
            _record_benchmark_event(
                "FABRIC_OPS_BENCHMARK",
                "completed",
                "Fabric ops benchmark completed",
                job_id=job_id,
            )
    except Exception as exc:
        store.update_benchmark_job(
            job_id,
            {
                "status": "failed",
                "finished_at": _now(),
                "error": str(exc),
                "stderr_tail": str(exc),
                "return_code": -1,
                "output_dir": str(output_dir),
                "summary": None,
                "summary_path": None,
                "raw_path": None,
            },
        )
    job = store.get_benchmark_job(job_id)
    if job is None:
        raise RuntimeError(f"benchmark job {job_id} was not persisted")
    return job


def _benchmark_suite_step_env(benchmark_type: str, steps: list[dict[str, Any]]) -> dict[str, str]:
    if benchmark_type != "fabric_tuning":
        return {}
    env: dict[str, str] = {}
    fabric_pipeline = next(
        (
            step
            for step in steps
            if step.get("benchmark_type") == "fabric_pipeline"
            and step.get("status") == "completed"
            and step.get("summary_path")
        ),
        None,
    )
    if fabric_pipeline:
        env["FABRIC_TUNING_CURRENT_PIPELINE_SUMMARY_PATH"] = str(fabric_pipeline["summary_path"])
    fabric_ops = next(
        (
            step
            for step in steps
            if step.get("benchmark_type") == "fabric_ops"
            and step.get("status") == "completed"
            and step.get("summary_path")
        ),
        None,
    )
    if fabric_ops:
        env["FABRIC_TUNING_CURRENT_FABRIC_OPS_SUMMARY_PATH"] = str(fabric_ops["summary_path"])
    return env


def _benchmark_command(
    benchmark_type: str,
    runs: int,
    warmup_runs: int,
    output_dir: Path,
) -> tuple[list[str], dict[str, str]]:
    repo_root = _repo_root()
    env = build_docker_benchmark_env(runs, warmup_runs, output_dir, benchmark_type, repo_root)
    if benchmark_type == "local":
        env.update(
            {
                "BENCHMARK_PROFILE": "centralized_baseline",
                "FABRIC_ENABLED": "false",
                "FABRIC_CLIENT_MODE": "centralized",
                "REVOCATION_MODE": "centralized",
                "CENTRALIZED_DB_MODE": os.getenv("CENTRALIZED_DB_MODE", "sqlite"),
                "CENTRALIZED_AUDIT_ENABLED": os.getenv("CENTRALIZED_AUDIT_ENABLED", "true"),
                "CENTRALIZED_COMMIT_EACH_OPERATION": os.getenv(
                    "CENTRALIZED_COMMIT_EACH_OPERATION",
                    "true",
                ),
            }
        )
        return [sys.executable, str(repo_root / "scripts" / "benchmark_centralized_baseline.py")], env
    if benchmark_type == "fabric_pipeline":
        env.update(
            {
                "BENCHMARK_PROFILE": "fabric_accumulator_perf",
                "REVOCATION_MODE": "accumulator",
                "AUDIT_MODE": "async",
                "FABRIC_ENABLED": "true",
                "FABRIC_CLIENT_MODE": "adapter",
                "BENCHMARK_FORCE_FRESH_VERIFIER_STATE": "true",
                "BENCHMARK_AGENT_GATEWAY_URL": os.getenv(
                    "BENCHMARK_AGENT_GATEWAY_URL",
                    "http://benchmark-agent-gateway:8031",
                ),
            }
        )
        return [sys.executable, str(repo_root / "scripts" / "benchmark_agent_pipeline.py")], env
    if benchmark_type == "fabric_ops":
        env.update(
            {
                "FABRIC_ENABLED": "true",
                "FABRIC_CLIENT_MODE": "adapter",
                "FABRIC_PEER_MODE": "adapter",
            }
        )
        return [sys.executable, str(repo_root / "scripts" / "benchmark_fabric_ops.py")], env
    if benchmark_type == "constrained":
        env.update(
            {
                "BENCHMARK_AGENT_GATEWAY_URL": os.getenv(
                    "BENCHMARK_AGENT_GATEWAY_URL",
                    "http://benchmark-agent-gateway:8031",
                ),
                "BENCHMARK_AGENT_CONSTRAINED_URL": os.getenv(
                    "BENCHMARK_AGENT_CONSTRAINED_URL",
                    "http://benchmark-agent-constrained:8031",
                ),
                "BENCHMARK_AGENT_LOW_URL": os.getenv(
                    "BENCHMARK_AGENT_LOW_URL",
                    "http://benchmark-agent-low:8031",
                ),
                "BENCHMARK_AGENT_TINY_URL": os.getenv(
                    "BENCHMARK_AGENT_TINY_URL",
                    "http://benchmark-agent-tiny:8031",
                ),
                "BENCHMARK_AGENT_TINY_MEMORY_LABEL": os.getenv(
                    "BENCHMARK_AGENT_TINY_MEMORY_LABEL",
                    "64 MB",
                ),
            }
        )
        return [sys.executable, str(repo_root / "scripts" / "benchmark_constrained_profiles.py")], env
    if benchmark_type == "revocation_connectivity":
        env.update(
            {
                "REVOCATION_DELAY_SECONDS": os.getenv("REVOCATION_DELAY_SECONDS", "5"),
                "BENCHMARK_AGENT_GATEWAY_URL": os.getenv(
                    "BENCHMARK_AGENT_GATEWAY_URL",
                    "http://benchmark-agent-gateway:8031",
                ),
                "BENCHMARK_AGENT_CONSTRAINED_URL": os.getenv(
                    "BENCHMARK_AGENT_CONSTRAINED_URL",
                    "http://benchmark-agent-constrained:8031",
                ),
            }
        )
        return [sys.executable, str(repo_root / "scripts" / "benchmark_revocation_connectivity.py")], env
    if benchmark_type == "fabric_tuning":
        env.update(
            {
                "FABRIC_ENABLED": "true",
                "FABRIC_CLIENT_MODE": "adapter",
                "REVOCATION_MODE": "accumulator",
                "AUDIT_MODE": "async",
                "BENCHMARK_AGENT_GATEWAY_URL": os.getenv(
                    "BENCHMARK_AGENT_GATEWAY_URL",
                    "http://benchmark-agent-gateway:8031",
                ),
            }
        )
        return [sys.executable, str(repo_root / "scripts" / "run_fabric_tuning_matrix.py")], env
    raise ValueError(f"Unsupported benchmark type: {benchmark_type}")


def build_docker_benchmark_env(
    runs: int,
    warmup_runs: int,
    output_dir: Path,
    benchmark_type: str,
    repo_root: Path,
) -> dict[str, str]:
    label = f"dashboard_{benchmark_type}_{uuid.uuid4().hex[:8]}"
    return {
        **os.environ,
        "ISSUER_URL": "http://issuer:8000",
        "VERIFIER_URL": "http://verifier:8001",
        "FABRIC_ADAPTER_URL": "http://fabric-adapter:8010",
        "DASHBOARD_API_URL": "http://dashboard-api:8020",
        "BENCHMARK_RUNS": str(runs),
        "BENCHMARK_WARMUP_RUNS": str(warmup_runs),
        "BENCHMARK_OUTPUT_DIR": str(output_dir),
        "BENCHMARK_LABEL": label,
        "FABRIC_OPS_RUNS": str(runs),
        "FABRIC_OPS_WARMUP_RUNS": str(warmup_runs),
        "FABRIC_OPS_OUTPUT_DIR": str(output_dir),
        "FABRIC_OPS_LABEL": label,
        "HTTP_TIMEOUT_SECONDS": "60",
        "HTTP_RETRY_ATTEMPTS": "5",
        "HTTP_RETRY_SLEEP_SECONDS": "1",
        "PYTHONPATH": str(repo_root),
    }


RESOURCE_CONTAINER_FILTERS = [
    "issuer",
    "verifier",
    "dashboard-api",
    "fabric-adapter",
    "peer0.org1",
    "peer0.org2",
    "orderer",
    "benchmark-agent-gateway",
    "benchmark-agent-constrained",
    "benchmark-agent-low",
    "benchmark-agent-tiny",
]


class DockerResourceMonitor:
    def __init__(self, section: str) -> None:
        self.section = section
        self.interval = float(os.getenv("RESOURCE_MONITOR_INTERVAL_SECONDS", "1"))
        self.rows: list[dict[str, Any]] = []
        self.error: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not Path("/var/run/docker.sock").exists():
            self.error = "Docker socket not available to dashboard-api"
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(2.0, self.interval + 1.0))

    def summary(self) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in self.rows:
            grouped.setdefault(str(row.get("service") or "unknown"), []).append(row)
        result = []
        for service, samples in grouped.items():
            cpu_values = [float(sample.get("cpu_percent") or 0) for sample in samples]
            memory_values = [float(sample.get("memory_mb") or 0) for sample in samples]
            result.append(
                {
                    "service": service,
                    "section": self.section,
                    "avg_cpu_percent": round(sum(cpu_values) / len(cpu_values), 3) if cpu_values else None,
                    "peak_cpu_percent": round(max(cpu_values), 3) if cpu_values else None,
                    "avg_memory_mb": round(sum(memory_values) / len(memory_values), 3) if memory_values else None,
                    "peak_memory_mb": round(max(memory_values), 3) if memory_values else None,
                    "sample_count": len(samples),
                }
            )
        return sorted(result, key=lambda row: str(row.get("service") or ""))

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.rows.extend(_sample_docker_resource_rows())
            except Exception as exc:
                self.error = f"Docker stats unavailable to dashboard-api: {exc}"
                return
            self._stop.wait(self.interval)


def _sample_docker_resource_rows() -> list[dict[str, Any]]:
    containers = _docker_api_get_json("/containers/json")
    rows = []
    for container in containers if isinstance(containers, list) else []:
        service = _container_service_name(container)
        if not service or not _matches_resource_container(service):
            continue
        container_id = str(container.get("Id") or "")
        stats = _docker_api_get_json(f"/containers/{container_id}/stats?stream=false")
        rows.append(
            {
                "service": service,
                "cpu_percent": _docker_cpu_percent(stats),
                "memory_mb": _docker_memory_mb(stats),
            }
        )
    return rows


def _docker_api_get_json(path: str) -> Any:
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
        body = _decode_chunked_body(body)
    return json.loads(body.decode("utf-8"))


def _decode_chunked_body(body: bytes) -> bytes:
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


def _container_service_name(container: dict[str, Any]) -> str | None:
    labels = container.get("Labels") if isinstance(container.get("Labels"), dict) else {}
    compose_service = labels.get("com.docker.compose.service")
    if compose_service:
        return str(compose_service)
    names = container.get("Names") if isinstance(container.get("Names"), list) else []
    if names:
        return str(names[0]).strip("/").split("-")[0]
    return None


def _matches_resource_container(service: str) -> bool:
    service_lower = service.lower()
    return any(item in service_lower for item in RESOURCE_CONTAINER_FILTERS)


def _docker_cpu_percent(stats: dict[str, Any]) -> float:
    cpu_stats = stats.get("cpu_stats") if isinstance(stats.get("cpu_stats"), dict) else {}
    precpu_stats = stats.get("precpu_stats") if isinstance(stats.get("precpu_stats"), dict) else {}
    cpu_usage = cpu_stats.get("cpu_usage") if isinstance(cpu_stats.get("cpu_usage"), dict) else {}
    precpu_usage = precpu_stats.get("cpu_usage") if isinstance(precpu_stats.get("cpu_usage"), dict) else {}
    cpu_delta = float(cpu_usage.get("total_usage") or 0) - float(precpu_usage.get("total_usage") or 0)
    system_delta = float(cpu_stats.get("system_cpu_usage") or 0) - float(precpu_stats.get("system_cpu_usage") or 0)
    online_cpus = float(cpu_stats.get("online_cpus") or len(cpu_usage.get("percpu_usage") or []) or 1)
    if cpu_delta <= 0 or system_delta <= 0:
        return 0.0
    return round((cpu_delta / system_delta) * online_cpus * 100.0, 3)


def _docker_memory_mb(stats: dict[str, Any]) -> float:
    memory_stats = stats.get("memory_stats") if isinstance(stats.get("memory_stats"), dict) else {}
    usage = float(memory_stats.get("usage") or 0)
    cache = 0.0
    nested = memory_stats.get("stats")
    if isinstance(nested, dict):
        cache = float(nested.get("cache") or 0)
    return round(max(0.0, usage - cache) / (1024 * 1024), 3)


def _parse_benchmark_summary(
    benchmark_type: str,
    created: list[Path],
    output_dir: Path,
) -> tuple[dict[str, Any], Path | None]:
    profile = _benchmark_profile(benchmark_type)
    mode = _benchmark_mode(benchmark_type)
    if benchmark_type == "constrained":
        candidates = [
            path
            for path in created
            if path.name.startswith("constrained_benchmark_") and path.suffix == ".json"
        ] or sorted(output_dir.glob("constrained_benchmark_*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        return _with_benchmark_metadata(_read_json_summary(candidates), benchmark_type, profile, mode), candidates[0] if candidates else None
    if benchmark_type == "revocation_connectivity":
        candidates = [
            path
            for path in created
            if path.name.startswith("revocation_connectivity_") and path.suffix == ".json"
        ] or sorted(output_dir.glob("revocation_connectivity_*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        return _with_benchmark_metadata(_read_json_summary(candidates), benchmark_type, profile, mode), candidates[0] if candidates else None
    if benchmark_type == "fabric_tuning":
        candidates = [
            path
            for path in created
            if path.name.startswith("fabric_tuning_") and path.suffix == ".json"
        ] or sorted(output_dir.glob("fabric_tuning_*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        return _with_benchmark_metadata(_read_json_summary(candidates), benchmark_type, profile, mode), candidates[0] if candidates else None
    if benchmark_type == "fabric_ops":
        candidates = [
            path
            for path in created
            if path.name.startswith("fabric_ops_summary_") and path.suffix == ".csv"
        ] or sorted(output_dir.glob("fabric_ops_summary_*.csv"), key=lambda path: path.stat().st_mtime, reverse=True)
        if not candidates:
            return _with_benchmark_metadata(_empty_benchmark_summary(), benchmark_type, profile, mode), None
        return _with_benchmark_metadata(_parse_fabric_ops_summary(candidates[0]), benchmark_type, profile, mode), candidates[0]

    candidates = [
        path
        for path in created
        if path.name.startswith("benchmark_summary_") and path.suffix == ".csv"
    ] or sorted(output_dir.glob("benchmark_summary_*.csv"), key=lambda path: path.stat().st_mtime, reverse=True)
    if not candidates:
        return _with_benchmark_metadata(_empty_benchmark_summary(), benchmark_type, profile, mode), None
    return _with_benchmark_metadata(_parse_pipeline_summary(candidates[0]), benchmark_type, profile, mode), candidates[0]


def _find_raw_output_path(benchmark_type: str, created: list[Path], output_dir: Path) -> Path | None:
    patterns = {
        "local": "benchmark_raw_*.csv",
        "fabric_pipeline": "benchmark_raw_*.csv",
        "fabric_ops": "fabric_ops_raw_*.csv",
        "constrained": "constrained_benchmark_*.json",
        "revocation_connectivity": "revocation_connectivity_*.json",
        "fabric_tuning": "fabric_tuning_*.json",
    }
    pattern = patterns.get(benchmark_type)
    if not pattern:
        return None
    prefix = pattern.split("*", 1)[0]
    suffix = pattern.rsplit("*", 1)[-1]
    candidates = [
        path
        for path in created
        if path.name.startswith(prefix) and path.name.endswith(suffix)
    ] or sorted(output_dir.glob(pattern), key=lambda path: path.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def _short_benchmark_error(benchmark_type: str, detail: str) -> str:
    text = " ".join(str(detail or "").split())
    lowered = text.lower()
    name = _benchmark_name(benchmark_type)
    if "peer0.org1.example.com" in lowered and (
        "no such host" in lowered
        or "name or service not known" in lowered
        or "temporary failure in name resolution" in lowered
        or "lookup peer0.org1.example.com" in lowered
    ):
        return f"{name} benchmark failed: Fabric peer DNS was not reachable from benchmark runner."
    if benchmark_type == "fabric_pipeline" and (
        "connection refused" in lowered
        or "timed out" in lowered
        or "name or service not known" in lowered
        or "temporary failure in name resolution" in lowered
        or "/health" in lowered
    ):
        return f"{name} benchmark failed: issuer service was not reachable from benchmark runner."
    if len(text) > 240:
        text = f"{text[:237]}..."
    return f"{name} benchmark failed: {text or 'script exited without details'}"


def _require_fabric_adapter_health() -> None:
    adapter, warning = client.optional_get("http://fabric-adapter:8010/health")
    if _is_ok(adapter):
        return
    raise RuntimeError(f"Fabric adapter health check failed before benchmark: {warning or adapter or 'unavailable'}")


def _read_json_summary(candidates: list[Path]) -> dict[str, Any]:
    if not candidates:
        return {}
    with candidates[0].open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        data["source"] = str(candidates[0])
        return data
    return {"source": str(candidates[0])}


def _parse_pipeline_summary(path: Path) -> dict[str, Any]:
    by_metric: dict[str, float] = {}
    with path.open("r", newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            metric = str(row.get("metric") or "")
            mean_value = _float_or_none(row.get("mean"))
            if metric and mean_value is not None:
                by_metric[metric] = mean_value
    missing_metrics = [metric for metric in FABRIC_PIPELINE_EXPECTED_METRICS if metric not in by_metric]
    operations = []
    for metric, (key, label, category) in BENCHMARK_LABELS.items():
        if metric in by_metric:
            operations.append(
                {
                    "key": key,
                    "label": label,
                    "duration_ms": round(by_metric[metric], 3),
                    "category": category,
                }
            )
    return {
        "full_lifecycle_ms": by_metric.get("full_iteration_ms"),
        "auth_allow_ms": by_metric.get("auth_allow_ms"),
        "revocation_ms": by_metric.get("revoke_capability_ms"),
        "proof_refresh_ms": by_metric.get("proof_refresh_ms"),
        "operations": operations,
        "available_metrics": sorted(by_metric.keys()),
        "missing_metrics": missing_metrics,
        "source": str(path),
    }


def _parse_fabric_ops_summary(path: Path) -> dict[str, Any]:
    operations = []
    by_key: dict[str, float] = {}
    with path.open("r", newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            operation = str(row.get("operation") or "")
            mean_value = _float_or_none(row.get("mean"))
            if not operation or mean_value is None:
                continue
            key, label, category = FABRIC_OP_LABELS.get(
                operation,
                (operation, operation.replace("_", " ").title(), "Fabric"),
            )
            by_key[key] = round(mean_value, 3)
            operations.append(
                {
                    "key": key,
                    "label": label,
                    "duration_ms": round(mean_value, 3),
                    "category": category,
                    "result": f"{row.get('success_count', '0')} ok / {row.get('failure_count', '0')} failed",
                }
            )
    read_keys = [
        "fabric_ping",
        "did_read",
        "credential_read",
        "accumulator_read",
        "fabric_list_audit_events",
    ]
    write_keys = [
        "did_write",
        "credential_write",
        "fabric_revoke_credential",
        "accumulator_write",
        "audit_write",
    ]
    read_latency = _mean_present([by_key.get(key) for key in read_keys])
    write_latency = _mean_present([by_key.get(key) for key in write_keys])
    full_total = sum(by_key.values()) if by_key else None
    return {
        "full_lifecycle_ms": round(full_total, 3) if full_total is not None else None,
        "auth_allow_ms": read_latency,
        "revocation_ms": write_latency,
        "proof_refresh_ms": by_key.get("accumulator_read"),
        "operations": operations,
        "source": str(path),
        "fabric_read_latency_ms": read_latency,
        "fabric_write_latency_ms": write_latency,
    }


def _build_combined_benchmark_summary(steps: list[dict[str, Any]]) -> dict[str, Any]:
    by_type = {
        str(step.get("benchmark_type")): step.get("summary")
        for step in steps
        if step.get("status") == "completed" and isinstance(step.get("summary"), dict)
    }
    local = by_type.get("local")
    fabric = by_type.get("fabric_pipeline")
    fabric_ops = by_type.get("fabric_ops")
    constrained = by_type.get("constrained")
    revocation_connectivity = by_type.get("revocation_connectivity")
    fabric_tuning = by_type.get("fabric_tuning")
    resource_usage = _combined_resource_usage(
        [local, fabric, fabric_ops, constrained, fabric_tuning, revocation_connectivity]
    )
    resource_reason = _resource_usage_reason(
        [local, fabric, fabric_ops, constrained, fabric_tuning, revocation_connectivity]
    )
    return {
        "comparison": {
            "local": _comparison_entry(local),
            "fabric": _comparison_entry(fabric),
        },
        "fabric_ops": _fabric_ops_entry(fabric_ops),
        "constrained": constrained if isinstance(constrained, dict) else None,
        "revocation_connectivity": revocation_connectivity
        if isinstance(revocation_connectivity, dict)
        else None,
        "fabric_tuning": fabric_tuning if isinstance(fabric_tuning, dict) else None,
        "resource_usage": resource_usage,
        "resource_usage_available": bool(resource_usage),
        "resource_usage_reason": None if resource_usage else resource_reason,
    }


def _combined_resource_usage(summaries: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for summary in summaries:
        if not isinstance(summary, dict):
            continue
        resource_rows = summary.get("resource_usage")
        if isinstance(resource_rows, list):
            rows.extend([row for row in resource_rows if isinstance(row, dict)])
    return rows


def _resource_usage_reason(summaries: list[Any]) -> str | None:
    for summary in summaries:
        if isinstance(summary, dict) and summary.get("resource_usage_reason"):
            return str(summary["resource_usage_reason"])
    return None


def _job_with_saved_fabric_tuning(job: dict[str, Any] | None) -> dict[str, Any] | None:
    saved = _saved_fabric_tuning_summary()
    if job is None:
        return {
            "job_id": "fabric-tuning-results",
            "benchmark_type": "fabric_tuning",
            "status": "completed",
            "started_at": None,
            "finished_at": saved.get("generated_at"),
            "error": None,
            "stdout_tail": "",
            "stderr_tail": "",
            "summary": saved,
            "return_code": 0,
            "output_dir": str(_fabric_tuning_results_dir()),
            "summary_path": saved.get("source"),
            "raw_path": None,
        }
    if job.get("benchmark_type") != "fabric_tuning":
        return job
    return {**job, "summary": _merge_fabric_tuning_summary(job.get("summary"))}


def _suite_with_saved_fabric_tuning(suite: dict[str, Any] | None) -> dict[str, Any] | None:
    if suite is None:
        return None
    combined = suite.get("combined_summary")
    if not isinstance(combined, dict):
        return suite
    merged_tuning = _merge_fabric_tuning_summary(combined.get("fabric_tuning"))
    updated_combined = {**combined, "fabric_tuning": merged_tuning}
    return {**suite, "combined_summary": updated_combined}


def _merge_fabric_tuning_summary(summary: Any) -> dict[str, Any]:
    saved = _saved_fabric_tuning_summary()
    profile_aliases = {
        "fast_block_commit": "low_latency",
        "larger_batch_window": "larger_batch",
    }
    if not isinstance(summary, dict):
        return saved
    saved_by_id = {
        str(profile.get("profile_id")): profile
        for profile in saved.get("profiles", [])
        if isinstance(profile, dict)
    }
    merged_profiles = []
    for profile in summary.get("profiles", []):
        if not isinstance(profile, dict):
            continue
        profile_id = profile_aliases.get(str(profile.get("profile_id") or ""), str(profile.get("profile_id") or ""))
        profile = {**profile, "profile_id": profile_id}
        saved_profile = saved_by_id.pop(profile_id, None)
        if saved_profile and profile_id == "larger_batch" and profile.get("status") == "completed":
            merged_profiles.append({
                **profile,
                "write_pressure": profile.get("write_pressure") or saved_profile.get("write_pressure"),
                "write_pressure_summary_path": profile.get("write_pressure_summary_path") or saved_profile.get("write_pressure_summary_path"),
            })
        elif saved_profile and (
            saved_profile.get("status") not in {"not_run", "not_supported"}
            or profile.get("status") != "completed"
        ):
            merged_profiles.append({**profile, **saved_profile})
        else:
            merged_profiles.append(profile)
    existing_ids = {str(profile.get("profile_id")) for profile in merged_profiles if isinstance(profile, dict)}
    for profile in saved.get("profiles", []):
        if isinstance(profile, dict) and str(profile.get("profile_id")) not in existing_ids:
            merged_profiles.append(profile)
    merged_profiles = [
        _canonical_fabric_tuning_profile_metadata(profile) if isinstance(profile, dict) else profile
        for profile in merged_profiles
    ]
    ordered_ids = ["current", "low_latency", "larger_batch", "light_endorsement"]
    merged_profiles.sort(
        key=lambda profile: ordered_ids.index(str(profile.get("profile_id")))
        if str(profile.get("profile_id")) in ordered_ids
        else len(ordered_ids)
    )
    return {**summary, "profiles": merged_profiles, "manual_results_source": saved.get("source")}


def _saved_fabric_tuning_summary() -> dict[str, Any]:
    profile_aliases = {
        "fast_block_commit": "low_latency",
        "larger_batch_window": "larger_batch",
    }
    profile_defaults = [
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
    by_id = {profile["profile_id"]: dict(profile) for profile in profile_defaults}
    sources = []
    results_dir = _fabric_tuning_results_dir()
    if results_dir.exists():
        for path in sorted(results_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                continue
            profile_id = profile_aliases.get(str(data.get("profile_id") or path.stem), str(data.get("profile_id") or path.stem))
            if profile_id in by_id:
                data["profile_id"] = profile_id
                if not data.get("write_pressure"):
                    pressure = _latest_saved_write_pressure(results_dir, profile_id)
                    if pressure:
                        data["write_pressure"] = pressure
                        data["write_pressure_summary_path"] = pressure.get("summary_path")
                by_id[profile_id] = _canonical_fabric_tuning_profile_metadata({**by_id[profile_id], **data, "source": str(path)})
                sources.append(str(path))
    if by_id["current"].get("status") in {"not_run", "not_supported"}:
        saved_current = _latest_saved_tuning_profile_from_benchmark_results("current")
        if saved_current:
            by_id["current"] = _canonical_fabric_tuning_profile_metadata({
                **by_id["current"],
                **saved_current,
                "label": "Original Fabric baseline",
                "description": "Saved comparison profile using the original Fabric test-network batch settings.",
            })
            if saved_current.get("source"):
                sources.append(str(saved_current["source"]))
    return {
        "benchmark_type": "fabric_tuning",
        "profile": "fabric_tuning_matrix",
        "mode": "fabric",
        "generated_at": _now(),
        "profiles": [by_id[profile["profile_id"]] for profile in profile_defaults],
        "source": ",".join(sources) if sources else None,
    }


def _fabric_tuning_results_dir() -> Path:
    return Path(os.getenv("FABRIC_TUNING_RESULTS_DIR", str(dashboard_data_dir / "fabric-tuning-results")))


def _canonical_fabric_tuning_profile_metadata(profile: dict[str, Any]) -> dict[str, Any]:
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


def _latest_saved_write_pressure(results_dir: Path, profile_id: str) -> dict[str, Any] | None:
    raw_dir = results_dir / f"{profile_id}-raw"
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


def _latest_saved_tuning_profile_from_benchmark_results(profile_id: str) -> dict[str, Any] | None:
    results_dir = dashboard_data_dir / "benchmark-results"
    if not results_dir.exists():
        return None
    candidates = sorted(
        results_dir.glob("*/fabric_tuning_*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    profile_aliases = {
        "fast_block_commit": "low_latency",
        "larger_batch_window": "larger_batch",
    }
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        for profile in data.get("profiles", []):
            if not isinstance(profile, dict):
                continue
            found_id = profile_aliases.get(str(profile.get("profile_id") or ""), str(profile.get("profile_id") or ""))
            if found_id == profile_id:
                row = dict(profile)
                row["profile_id"] = profile_id
                row["source"] = str(path)
                return row
    return None


def _comparison_entry(summary: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(summary, dict):
        return None
    return {
        "headline": {
            "full_lifecycle_ms": summary.get("full_lifecycle_ms"),
            "auth_allow_ms": summary.get("auth_allow_ms"),
            "revocation_ms": summary.get("revocation_ms"),
            "proof_refresh_ms": summary.get("proof_refresh_ms"),
        },
        "operations": summary.get("operations") or [],
        "profile": summary.get("profile"),
        "mode": summary.get("mode"),
    }


def _fabric_ops_entry(summary: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(summary, dict):
        return None
    return {
        "headline": {
            "total_operations_ms": summary.get("full_lifecycle_ms"),
            "ledger_read_ms": summary.get("fabric_read_latency_ms"),
            "ledger_write_ms": summary.get("fabric_write_latency_ms"),
            "accumulator_read_ms": summary.get("proof_refresh_ms"),
        },
        "operations": summary.get("operations") or [],
        "profile": summary.get("profile"),
        "mode": summary.get("mode"),
    }


def _empty_benchmark_summary() -> dict[str, Any]:
    return {
        "full_lifecycle_ms": None,
        "auth_allow_ms": None,
        "revocation_ms": None,
        "proof_refresh_ms": None,
        "operations": [],
    }


def _with_benchmark_metadata(
    summary: dict[str, Any],
    benchmark_type: str,
    profile: str,
    mode: str,
) -> dict[str, Any]:
    summary["benchmark_type"] = benchmark_type
    summary["profile"] = profile
    summary["mode"] = mode
    return summary


def _benchmark_profile(benchmark_type: str) -> str:
    if benchmark_type == "fabric_pipeline":
        return "fabric_accumulator_perf"
    if benchmark_type == "fabric_ops":
        return "fabric_ops"
    if benchmark_type == "constrained":
        return "docker_constrained_agents"
    if benchmark_type == "revocation_connectivity":
        return "accumulator_connectivity"
    if benchmark_type == "fabric_tuning":
        return "fabric_tuning_matrix"
    return "centralized_baseline"


def _benchmark_mode(benchmark_type: str) -> str:
    if benchmark_type == "fabric_pipeline":
        return "fabric"
    if benchmark_type == "fabric_ops":
        return "fabric_ops"
    if benchmark_type == "constrained":
        return "docker constrained device emulation"
    if benchmark_type == "revocation_connectivity":
        return "fabric"
    if benchmark_type == "fabric_tuning":
        return "fabric"
    return "centralized"


def _summary_value(summary: Any, key: str) -> Any:
    return summary.get(key) if isinstance(summary, dict) else None


def _float_or_none(value: Any) -> float | None:
    try:
        if value is None or str(value).strip() == "":
            return None
        return float(value)
    except ValueError:
        return None


def _mean_present(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    if not present:
        return None
    return round(sum(present) / len(present), 3)


def _benchmark_name(benchmark_type: str) -> str:
    return {
        "local": "Centralised Baseline",
        "fabric_pipeline": "Fabric pipeline",
        "fabric_ops": "Fabric ops",
        "constrained": "Constrained device emulation",
        "revocation_connectivity": "Revocation connectivity",
        "fabric_tuning": "Fabric tuning",
    }.get(benchmark_type, benchmark_type)


def _tail(value: str, limit: int = 4000) -> str:
    return value[-limit:] if value else ""


def _repo_root() -> Path:
    return Path(os.getenv("DASHBOARD_REPO_ROOT", "/workspace"))


def _run_happy_path_scenario(device: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
    _require_active_credentials(device, require_identity_proof=True, require_capability_proof=True)
    decision, updated = _authorize_for_scenario(
        device,
        "read",
        "iot:device:example",
        False,
        auto_refresh=True,
        retry_on_stale=True,
    )
    return decision, updated, "authorization allowed"


def _run_wrong_action_scenario(device: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
    _require_active_credentials(device, require_identity_proof=False, require_capability_proof=True)
    decision, updated = _authorize_for_scenario(
        device,
        "write",
        "iot:device:example",
        False,
        auto_refresh=True,
        retry_on_stale=True,
    )
    return decision, updated, "requested action not permitted"


def _run_bad_signature_scenario(device: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
    _require_active_credentials(device, require_identity_proof=False, require_capability_proof=True)
    decision, updated = _authorize_for_scenario(device, "read", "iot:device:example", True)
    return decision, updated, "device signature invalid"


def _run_revocation_scenario(device: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
    _require_active_credentials(device, require_identity_proof=False, require_capability_proof=True)
    capability_vc = device.get("capability_vc")
    if not isinstance(capability_vc, dict) or not capability_vc.get("id"):
        raise HTTPException(status_code=400, detail="device has no capability VC to revoke")
    _call_or_502(
        lambda: client.revoke(capability_vc["id"], "security scenario revocation"),
        "Capability revocation failed",
    )
    patch: dict[str, Any] = {
        "credential_status": "revoked",
        "status": "revoked",
        "last_error": None,
    }
    accumulator = _optional_accumulator_state()
    if accumulator is not None:
        patch["last_accumulator_state"] = accumulator
    revoked = _update(device["id"], patch)
    decision, updated = _authorize_for_scenario(
        revoked,
        "read",
        "iot:device:example",
        False,
        retry_on_stale=True,
    )
    return decision, updated, "credential revoked"


def _run_proof_refresh_scenario(device: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
    _require_active_credentials(device, require_identity_proof=True, require_capability_proof=True)
    patch: dict[str, Any] = {"last_error": None}
    identity_vc = device.get("identity_vc")
    capability_vc = device.get("capability_vc")
    try:
        if isinstance(identity_vc, dict) and identity_vc.get("id"):
            patch["identity_proof"] = client.refresh_proof(identity_vc["id"])
        if isinstance(capability_vc, dict) and capability_vc.get("id"):
            patch["capability_proof"] = client.refresh_proof(capability_vc["id"])
    except Exception as exc:
        _update(device["id"], {"last_error": f"Proof refresh failed: {exc}"})
        raise HTTPException(status_code=502, detail=f"Proof refresh failed: {exc}") from exc
    refreshed = _update(device["id"], patch)
    decision, updated = _authorize_for_scenario(
        refreshed,
        "read",
        "iot:device:example",
        False,
        auto_refresh=True,
        retry_on_stale=True,
    )
    return decision, updated, "proof refreshed before authorization"


def _authorize_for_scenario(
    device: dict[str, Any],
    action: str,
    resource: str,
    tamper_signature: bool,
    *,
    auto_refresh: bool = False,
    retry_on_stale: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    identity_vc = device.get("identity_vc")
    capability_vc = device.get("capability_vc")
    if not isinstance(identity_vc, dict) or not isinstance(capability_vc, dict):
        raise HTTPException(status_code=400, detail="identity and capability VCs are required")

    working_device = device
    refresh_attempted = False
    if auto_refresh and not tamper_signature and _is_active_non_revoked_device(working_device):
        working_device, refresh_attempted = _refresh_scenario_proofs_if_stale(working_device)
        identity_vc = working_device.get("identity_vc")
        capability_vc = working_device.get("capability_vc")
        if not isinstance(identity_vc, dict) or not isinstance(capability_vc, dict):
            raise HTTPException(status_code=400, detail="identity and capability VCs are required")

    auth_payload = client.sign_authorization_payload(
        private_key_b64=working_device["private_key"],
        identity_vc=identity_vc,
        capability_vc=capability_vc,
        action=action,
        resource=resource,
        identity_proof=working_device.get("identity_proof"),
        capability_proof=working_device.get("capability_proof"),
        tamper_signature=tamper_signature,
    )
    decision = _call_or_502(lambda: client.authorize(auth_payload), "Authorization failed")
    initial_decision = dict(decision)

    if (
        retry_on_stale
        and not tamper_signature
        and decision.get("decision") == "deny"
        and decision.get("reason") == "accumulator proof stale"
    ):
        retry_device, retry_refreshed = _refresh_scenario_proofs_for_retry(working_device)
        refresh_attempted = refresh_attempted or retry_refreshed
        if retry_device is not None:
            working_device = retry_device
            identity_vc = working_device.get("identity_vc")
            capability_vc = working_device.get("capability_vc")
            if not isinstance(identity_vc, dict) or not isinstance(capability_vc, dict):
                raise HTTPException(status_code=400, detail="identity and capability VCs are required")
            retry_payload = client.sign_authorization_payload(
                private_key_b64=working_device["private_key"],
                identity_vc=identity_vc,
                capability_vc=capability_vc,
                action=action,
                resource=resource,
                identity_proof=working_device.get("identity_proof"),
                capability_proof=working_device.get("capability_proof"),
                tamper_signature=False,
            )
            decision = _call_or_502(lambda: client.authorize(retry_payload), "Authorization failed")
            if decision.get("decision") == "allow" and initial_decision.get("reason") == "accumulator proof stale":
                decision = {**decision, "reason": "authorized after proof refresh"}
        elif _has_revoked_capability(working_device):
            decision = {"decision": "deny", "reason": "credential revoked in accumulator"}

    updated = _update(
        working_device["id"],
        {
            "last_decision": decision.get("decision"),
            "last_reason": decision.get("reason"),
            "last_error": None,
        },
    )
    if refresh_attempted:
        decision = {**decision, "initial_decision": initial_decision}
    return decision, updated


def _refresh_scenario_proofs_if_stale(device: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    accumulator = _optional_accumulator_state()
    if not isinstance(accumulator, dict):
        return device, False
    latest_version = _safe_int(accumulator.get("version"))
    latest_root = str(accumulator.get("root") or "")
    if latest_version is None or not latest_root:
        return device, False

    needs_refresh = False
    for proof in (device.get("identity_proof"), device.get("capability_proof")):
        if not isinstance(proof, dict):
            continue
        proof_version = _safe_int(proof.get("version"))
        proof_root = str(proof.get("root") or "")
        if proof_version != latest_version or proof_root != latest_root:
            needs_refresh = True
            break
    if not needs_refresh:
        return device, False
    refreshed = _refresh_scenario_proofs(device)
    return refreshed, True


def _refresh_scenario_proofs_for_retry(device: dict[str, Any]) -> tuple[dict[str, Any] | None, bool]:
    if not _is_active_non_revoked_device(device):
        if not _has_revoked_capability(device):
            return None, False
        try:
            _refresh_scenario_proofs(device)
        except Exception as exc:
            _update(device["id"], {"last_error": f"Revoked proof refresh blocked: {exc}"})
            return None, True
        return None, True
    try:
        return _refresh_scenario_proofs(device), True
    except Exception as exc:
        _update(device["id"], {"last_error": f"Proof refresh failed after stale authorization: {exc}"})
        if _has_revoked_capability(device) or _is_accumulator_missing_error(exc):
            return None, True
        raise HTTPException(status_code=502, detail=f"Proof refresh failed after stale authorization: {exc}") from exc


def _refresh_scenario_proofs(device: dict[str, Any]) -> dict[str, Any]:
    patch: dict[str, Any] = {"last_error": None}
    identity_vc = device.get("identity_vc")
    capability_vc = device.get("capability_vc")
    if isinstance(identity_vc, dict) and identity_vc.get("id"):
        patch["identity_proof"] = client.refresh_proof(identity_vc["id"])
    if isinstance(capability_vc, dict) and capability_vc.get("id"):
        patch["capability_proof"] = client.refresh_proof(capability_vc["id"])
    return _update(device["id"], patch)


def _is_active_non_revoked_device(device: dict[str, Any]) -> bool:
    return (
        device.get("status") == "active"
        and device.get("credential_status") == "active"
        and not _has_revoked_capability(device)
    )


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _require_active_credentials(
    device: dict[str, Any],
    *,
    require_identity_proof: bool,
    require_capability_proof: bool,
) -> None:
    if device.get("status") != "active":
        raise HTTPException(
            status_code=400,
            detail="Restore access before running active credential scenarios.",
        )
    if not isinstance(device.get("identity_vc"), dict):
        raise HTTPException(status_code=400, detail="identity VC is required")
    if not isinstance(device.get("capability_vc"), dict):
        raise HTTPException(status_code=400, detail="capability VC is required")
    if device.get("credential_status") != "active":
        raise HTTPException(status_code=400, detail="active capability VC is required")
    if require_identity_proof and not isinstance(device.get("identity_proof"), dict):
        raise HTTPException(status_code=400, detail="identity proof is required")
    if require_capability_proof and not isinstance(device.get("capability_proof"), dict):
        raise HTTPException(status_code=400, detail="capability proof is required")


def _decision_value(decision: dict[str, Any]) -> str:
    value = str(decision.get("decision") or decision.get("result") or "").lower()
    if value in {"allow", "deny"}:
        return value
    return "unknown"


def _scenario_reason(decision: dict[str, Any], prefix: str) -> str:
    reason = str(decision.get("reason") or "").strip()
    if reason:
        return reason
    return prefix


def _store_scenario_result(
    scenario_id: str,
    scenario_name: str,
    device: dict[str, Any],
    expected: str,
    actual: str,
    reason: str,
    status: str,
    raw: dict[str, Any],
) -> dict[str, Any]:
    result = {
        "id": str(uuid.uuid4()),
        "time": _now(),
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "device_id": device.get("id") or "unknown",
        "device_label": device.get("label") or "Unknown Device",
        "expected": expected,
        "actual": actual,
        "reason": reason,
        "status": status,
        "raw": raw,
    }
    store.add_scenario_result(result)
    return {
        "id": result["id"],
        "time": result["time"],
        "scenario_id": scenario_id,
        "scenario": scenario_name,
        "device_id": result["device_id"],
        "device": result["device_label"],
        "expected": expected,
        "actual": actual,
        "reason": reason,
        "status": status,
    }


def _combined_audit_events(limit: int) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    events: list[dict[str, Any]] = []
    issuer_events, issuer_warning = client.optional_get(
        f"{client.ISSUER_URL}/audit/events?limit={limit}"
    )
    verifier_events, verifier_warning = client.optional_get(
        f"{client.VERIFIER_URL}/audit/events?limit={limit}"
    )
    if issuer_events is not None:
        events.extend(issuer_events.get("events", []))
    else:
        warnings.append(f"issuer audit unavailable: {issuer_warning}")
    if verifier_events is not None:
        events.extend(verifier_events.get("events", []))
    else:
        warnings.append(f"verifier audit unavailable: {verifier_warning}")

    events.extend(store.list_events(limit))
    deduped: dict[str, dict[str, Any]] = {}
    for index, event in enumerate(events):
        key = str(event.get("event_id") or f"event-{index}")
        deduped[key] = event
    events = list(deduped.values())
    events.sort(
        key=lambda item: str(item.get("created_at") or item.get("timestamp") or ""),
        reverse=True,
    )
    return events, warnings


def _record_credential_link(
    device: dict[str, Any],
    credential: Any,
    credential_type: str,
) -> None:
    credential_id = _credential_id(credential)
    if not credential_id:
        return
    store.upsert_event(
        {
            "event_id": f"credential-link:{device['id']}:{credential_id}",
            "created_at": _now(),
            "event_type": "CREDENTIAL_LINK",
            "service": "dashboard-map",
            "device_id": device.get("id"),
            "device_label": device.get("label"),
            "subject_did": device.get("did"),
            "credential_id": credential_id,
            "reason": credential_type,
        }
    )


def _record_device_event(
    device: dict[str, Any],
    event_type: str,
    service: str,
    credential_id: str | None = None,
    result: str = "recorded",
    reason: str | None = None,
) -> None:
    store.upsert_event(
        {
            "event_id": f"dashboard-event:{uuid.uuid4()}",
            "created_at": _now(),
            "event_type": event_type,
            "service": service,
            "device_id": device.get("id"),
            "device_label": device.get("label"),
            "subject_did": device.get("did"),
            "credential_id": credential_id,
            "result": result,
            "details": {"reason": reason or result},
        }
    )


def _record_benchmark_event(
    event_type: str,
    result: str,
    reason: str,
    *,
    suite_id: str | None = None,
    job_id: str | None = None,
) -> None:
    event_id = suite_id or job_id or str(uuid.uuid4())
    store.upsert_event(
        {
            "event_id": f"benchmark-event:{event_type}:{event_id}",
            "created_at": _now(),
            "event_type": event_type,
            "service": "benchmark",
            "device_id": None,
            "device_label": "Not applicable",
            "subject_did": "Not applicable",
            "credential_id": "Not applicable",
            "result": result,
            "details": {
                "reason": reason,
                "suite_job_id": suite_id,
                "job_id": job_id,
                "credential_type": "Not applicable",
            },
        }
    )


def _device_credential_ids(device: dict[str, Any]) -> set[str]:
    credential_ids = {
        value
        for value in (
            _credential_id(device.get("identity_vc")),
            _credential_id(device.get("capability_vc")),
        )
        if value
    }
    for event in store.list_events(10000):
        if event.get("device_id") == device.get("id"):
            credential_id = _event_credential_id(event)
            if credential_id:
                credential_ids.add(credential_id)
    return credential_ids


def _event_belongs_to_device(event: dict[str, Any], device: dict[str, Any]) -> bool:
    if event.get("device_id") == device.get("id"):
        return True
    if event.get("device_label") == device.get("label"):
        return True
    subject_did = event.get("subject_did") or event.get("subjectDid") or event.get("subject")
    if subject_did and subject_did == device.get("did"):
        return True
    credential_id = _event_credential_id(event)
    return bool(credential_id and credential_id in _device_credential_ids(device))


def _device_timeline_item(event: dict[str, Any], device: dict[str, Any]) -> dict[str, Any]:
    subject_or_credential = (
        event.get("subject_did")
        or event.get("subjectDid")
        or event.get("subject")
        or _event_credential_id(event)
        or "session"
    )
    return {
        "event": event.get("event_type") or "EVENT",
        "service": event.get("service") or "dashboard",
        "device": event.get("device_label") or device.get("label") or "unknown",
        "subject_or_credential": subject_or_credential,
        "result": event.get("decision") or event.get("reason") or event.get("result") or "recorded",
        "created_at": event.get("created_at") or event.get("timestamp") or "",
    }


def _has_active_capability(device: dict[str, Any]) -> bool:
    return isinstance(device.get("capability_vc"), dict) and not _has_revoked_capability(device)


def _has_revoked_capability(device: dict[str, Any]) -> bool:
    if device.get("status") == "revoked" or device.get("credential_status") == "revoked":
        return isinstance(device.get("capability_vc"), dict)
    capability_vc = device.get("capability_vc")
    if not isinstance(capability_vc, dict):
        return False
    credential_status = capability_vc.get("credentialStatus")
    return isinstance(credential_status, dict) and credential_status.get("revoked") is True


def _normalize_audit_events(events: list[dict[str, Any]], devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dashboard_did_labels = {
        device.get("did"): device.get("label")
        for device in devices
        if device.get("did") and device.get("label")
    }
    dashboard_credential_labels: dict[str, str] = {}
    for device in devices:
        for credential in (device.get("identity_vc"), device.get("capability_vc")):
            credential_id = _credential_id(credential)
            if credential_id and device.get("label"):
                dashboard_credential_labels[credential_id] = str(device["label"])

    benchmark_did_labels: dict[str, str] = {}
    credential_labels: dict[str, str] = dict(dashboard_credential_labels)
    credential_subjects: dict[str, str] = {}
    ordered = sorted(events, key=lambda item: str(item.get("created_at") or item.get("timestamp") or ""))
    for event in ordered:
        if _is_benchmark_event(event):
            continue
        subject = _event_subject(event)
        credential_id = _event_credential_id(event)
        label = None
        if subject:
            label = dashboard_did_labels.get(subject)
            if not label:
                label = benchmark_did_labels.setdefault(
                    subject,
                    f"benchmark-device-{len(benchmark_did_labels) + 1:02d}",
                )
        if not label and credential_id:
            label = credential_labels.get(credential_id)
        if label and credential_id:
            credential_labels[credential_id] = label
        if subject and credential_id:
            credential_subjects[credential_id] = subject

    return [
        _enrich_audit_event(
            event,
            devices,
            credential_labels,
            credential_subjects,
            dashboard_did_labels,
            benchmark_did_labels,
        )
        for event in events
    ]


def _enrich_audit_event(
    event: dict[str, Any],
    devices: list[dict[str, Any]],
    credential_labels: dict[str, str] | None = None,
    credential_subjects: dict[str, str] | None = None,
    dashboard_did_labels: dict[str, str] | None = None,
    benchmark_did_labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    enriched = dict(event)
    device = _device_for_event(event, devices)
    if _is_benchmark_event(enriched):
        enriched["device_id"] = None
        enriched["device_label"] = "Not applicable"
        enriched["subject_did"] = "Not applicable"
        enriched["credential_id"] = "Not applicable"
        enriched["credential_type"] = "Not applicable"
    else:
        subject = _event_subject(enriched)
        credential_id = _event_credential_id(enriched)
        mapped_label = None
        if device:
            mapped_label = device.get("label")
        if not mapped_label and subject and dashboard_did_labels:
            mapped_label = dashboard_did_labels.get(subject)
        if not mapped_label and credential_id and credential_labels:
            mapped_label = credential_labels.get(credential_id)
        if not mapped_label and subject and benchmark_did_labels:
            mapped_label = benchmark_did_labels.get(subject)
        if not subject and credential_id and credential_subjects:
            subject = credential_subjects.get(credential_id)
        enriched["device_id"] = device.get("id") if device else enriched.get("device_id")
        enriched["device_label"] = mapped_label or enriched.get("device_label") or "unknown"
        if subject:
            enriched["subject_did"] = subject
    enriched["result"] = _event_result(enriched)
    enriched["reason"] = _event_reason(enriched)
    return enriched


def _is_benchmark_event(event: dict[str, Any]) -> bool:
    event_type = str(event.get("event_type") or event.get("event") or "")
    service = str(event.get("service") or "")
    return service == "benchmark" or event_type in {"BENCHMARK_COMPLETED", "FABRIC_OPS_BENCHMARK"}


def _event_result(event: dict[str, Any]) -> str:
    event_type = str(event.get("event_type") or event.get("event") or "")
    metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
    result = (
        event.get("result")
        or event.get("decision")
        or metadata.get("result")
        or result_for_audit_event(event_type)
    )
    text = str(result or "").strip()
    if event_type == "VC_REVOKED" and text == "benchmark capability revocation":
        return "revoked"
    return text or "recorded"


def _event_reason(event: dict[str, Any]) -> str:
    event_type = str(event.get("event_type") or event.get("event") or "")
    metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    nested_details = event.get("details") or event.get("detail")
    if isinstance(nested_details, dict):
        details = {**details, **nested_details}
    candidates = [
        event.get("reason"),
        event.get("detail"),
        details.get("reason"),
        details.get("result_reason"),
        details.get("message"),
        details.get("error"),
        metadata.get("reason"),
        metadata.get("detail"),
        metadata.get("result_reason"),
        metadata.get("message"),
        metadata.get("error"),
    ]
    for candidate in candidates:
        text = str(candidate or "").strip()
        if text:
            return _friendly_audit_reason(event_type, text)
    return _friendly_audit_reason(event_type, "")


def _friendly_audit_reason(event_type: str, value: str) -> str:
    if value:
        if event_type == "VC_REVOKED" and value == "revoked":
            return "capability revoked"
        return value
    return {
        "AUTH_ALLOW": "authorized",
        "AUTH_DENY": "Not available",
        "VC_REVOKED": "capability revoked",
        "CAPABILITY_VC_ISSUED": "capability issued",
        "IDENTITY_VC_ISSUED": "identity credential issued",
        "DID_REGISTERED": "DID registered",
        "FABRIC_OPS_BENCHMARK": "Fabric ops benchmark completed",
        "BENCHMARK_COMPLETED": "benchmark suite completed",
    }.get(event_type, "Not available")


def result_for_audit_event(event_type: str) -> str:
    if event_type == "VC_REVOKED":
        return "revoked"
    if event_type == "AUTH_ALLOW":
        return "allow"
    if event_type == "AUTH_DENY":
        return "deny"
    if event_type in {"BENCHMARK_COMPLETED", "FABRIC_OPS_BENCHMARK"}:
        return "completed"
    return "recorded"


def _device_for_event(event: dict[str, Any], devices: list[dict[str, Any]]) -> dict[str, Any] | None:
    subject_did = event.get("subject_did") or event.get("subjectDid")
    credential_id = _event_credential_id(event)
    for device in devices:
        if subject_did and subject_did == device.get("did"):
            return device
        if credential_id and credential_id in {
            _credential_id(device.get("identity_vc")),
            _credential_id(device.get("capability_vc")),
        }:
            return device
    return None


def _event_credential_id(event: dict[str, Any]) -> str | None:
    credential_id = event.get("credential_id") or event.get("credentialId")
    if isinstance(credential_id, str):
        return credential_id
    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        credential_id = metadata.get("credential_id") or metadata.get("credentialId")
        if isinstance(credential_id, str):
            return credential_id
    return None


def _event_subject(event: dict[str, Any]) -> str | None:
    subject = event.get("subject_did") or event.get("subjectDid") or event.get("subject")
    if isinstance(subject, str) and subject:
        return subject
    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        subject = metadata.get("subject_did") or metadata.get("subjectDid") or metadata.get("subject")
        if isinstance(subject, str) and subject:
            return subject
    return None


def _credential_id(credential: Any) -> str | None:
    if isinstance(credential, dict) and isinstance(credential.get("id"), str):
        return credential["id"]
    return None


def _validate_proof_for_credential(
    device_id: str,
    proof: Any,
    credential_id: str,
    label: str,
) -> None:
    if not isinstance(proof, dict):
        _raise_restore_conflict(
            device_id,
            f"Restore failed because {label} is missing.",
        )
    proof_credential_id = _proof_credential_id(proof)
    if proof_credential_id is not None and proof_credential_id != credential_id:
        _raise_restore_conflict(
            device_id,
            f"Restore failed because {label} does not match credential {credential_id}.",
        )


def _proof_credential_id(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("credential_id", "credentialId", "credentialID", "id"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.startswith("urn:uuid:"):
                return candidate
        for child in value.values():
            found = _proof_credential_id(child)
            if found is not None:
                return found
    if isinstance(value, list):
        for child in value:
            found = _proof_credential_id(child)
            if found is not None:
                return found
    return None


def _accumulator_field(accumulator: dict[str, Any] | None, field: str, fallback: Any) -> Any:
    if not isinstance(accumulator, dict):
        return fallback
    value = accumulator.get(field)
    return fallback if value is None else value


def _issuer_accumulator_state_for_summary() -> tuple[dict[str, Any] | None, str | None]:
    url = f"{client.ISSUER_URL}/revocation/accumulator/state"
    try:
        return client.http_get_json(url), None
    except Exception as exc:
        return None, f"accumulator state unavailable: {exc}"


def has_crlf(path: Path) -> bool:
    try:
        return b"\r\n" in path.read_bytes()
    except OSError:
        return False


def _crlf_files(test_network: Path | None, wrapper_path: Path | None) -> list[Path]:
    candidates: list[Path] = []
    if test_network is not None:
        candidates.append(test_network / "network.sh")
        candidates.append(test_network / "network.config")
        scripts_dir = test_network / "scripts"
        if scripts_dir.exists():
            candidates.extend(sorted(scripts_dir.glob("*.sh")))
    if wrapper_path is not None:
        candidates.append(wrapper_path)
    return [path for path in candidates if path.is_file() and has_crlf(path)]


def _fabric_test_network_path() -> Path | None:
    explicit = os.getenv("FABRIC_TEST_NETWORK_PATH")
    if explicit:
        path = Path(explicit)
        if (path / "network.sh").exists():
            return path

    samples = os.getenv("FABRIC_SAMPLES_PATH")
    if samples:
        path = Path(samples) / "test-network"
        if (path / "network.sh").exists():
            return path

    return None


def _fabric_wrapper_path() -> Path | None:
    candidates = [
        Path(os.getenv("DASHBOARD_REPO_ROOT", "")) / "fabric" / "network.sh"
        if os.getenv("DASHBOARD_REPO_ROOT")
        else None,
        Path("/repo/fabric/network.sh"),
        Path("/workspace/fabric/network.sh"),
        Path.cwd().parent / "fabric" / "network.sh",
    ]
    for candidate in candidates:
        if candidate is not None and candidate.exists():
            return candidate
    return None


def _health_text(payload: dict[str, Any] | None) -> str:
    if _is_ok(payload):
        return "ok"
    return "unknown"


def _is_ok(payload: dict[str, Any] | None) -> bool:
    if not isinstance(payload, dict):
        return False
    return payload.get("status") == "ok" or payload.get("ok") is True


def _optional_accumulator_state() -> dict[str, Any] | None:
    try:
        return client.accumulator_state()
    except Exception:
        return None


def _is_accumulator_missing_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return (
        "not found" in text
        or "not present" in text
        or "credential not in accumulator" in text
        or "credential is not in accumulator" in text
    )


def _is_upstream_unavailable(text: str) -> bool:
    lowered = text.lower()
    return (
        "connection refused" in lowered
        or "timed out" in lowered
        or "name or service not known" in lowered
        or "temporary failure in name resolution" in lowered
    )


def _call_or_502(callable_obj, message: str):
    try:
        return callable_obj()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"{message}: {exc}") from exc


def _raise_restore_conflict(
    device_id: str,
    detail: str,
    exc: Exception | None = None,
) -> None:
    _update(device_id, {"last_error": detail})
    if exc is None:
        raise HTTPException(status_code=409, detail=detail)
    raise HTTPException(status_code=409, detail=detail) from exc


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
