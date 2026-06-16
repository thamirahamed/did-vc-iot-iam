import base64
import csv
import json
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


ISSUER_URL = os.getenv("ISSUER_URL", "http://issuer:8000").rstrip("/")
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://verifier:8001").rstrip("/")
TOXIPROXY_ISSUER_URL = os.getenv("TOXIPROXY_ISSUER_URL", "http://toxiproxy:18000").rstrip("/")
TOXIPROXY_VERIFIER_URL = os.getenv("TOXIPROXY_VERIFIER_URL", "http://toxiproxy:18001").rstrip("/")
FABRIC_ADAPTER_URL = os.getenv("FABRIC_ADAPTER_URL", "http://fabric-adapter:8010").rstrip("/")
TOXIPROXY_FABRIC_ADAPTER_URL = os.getenv(
    "TOXIPROXY_FABRIC_ADAPTER_URL", "http://toxiproxy:18010"
).rstrip("/")
OUTPUT_DIR = Path(os.getenv("BENCHMARK_OUTPUT_DIR", "/tmp/benchmark-agent-results"))
WALLET_DB_PATH = Path(os.getenv("BENCHMARK_AGENT_WALLET_DB", str(OUTPUT_DIR / "wallet.db")))
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "60"))
VERIFIER_CACHE_WAIT_SECONDS = float(os.getenv("VERIFIER_CACHE_WAIT_SECONDS", "2.2"))
ACTION = os.getenv("BENCHMARK_ACTION", "read")
RESOURCE = os.getenv("BENCHMARK_RESOURCE", "iot:device:example")
BENCHMARK_DEVICE_ID = os.getenv("BENCHMARK_DEVICE_ID", "benchmark-device-01")
TIMING_SCOPE = (
    "Measured lifecycle includes DID registration/resolution, identity and capability issuance, "
    "valid and wrong-action authorization, capability revocation, revoked/stale denial, "
    "replacement capability issuance, proof refresh, and restored authorization. It excludes "
    "wallet reset, setup, health checks, container startup, and artificial cache wait."
)


app = FastAPI(title="Benchmark Agent")


class RunRequest(BaseModel):
    runs: int = 3
    warmup_runs: int = 1
    profile: str = "gateway"
    preserve_wallet: bool = False
    network_profile: str = "none"
    force_fresh_verifier_state: bool = False


class CapabilityRequest(BaseModel):
    action: str = ACTION
    resource: str = RESOURCE


class RefreshProofRequest(BaseModel):
    credential_type: str
    network_profile: str = "none"
    network_retries: int = 2
    network_retry_delay_ms: int = 500


class AuthorizeAgentRequest(BaseModel):
    requested_action: str = ACTION
    requested_resource: str = RESOURCE
    auto_refresh: bool = False
    retry_on_stale: bool = False
    network_profile: str = "none"
    network_retries: int = 2
    network_retry_delay_ms: int = 500


@app.get("/health")
def health() -> dict[str, str]:
    init_wallet()
    return {"status": "ok", "service": "benchmark-agent"}


@app.post("/wallet/reset")
def reset_wallet_endpoint() -> dict[str, Any]:
    reset_wallet()
    return {"reset": True, "wallet": wallet_summary()}


@app.get("/wallet")
def wallet_endpoint() -> dict[str, Any]:
    return wallet_summary()


@app.post("/onboard")
def onboard() -> dict[str, Any]:
    wallet = load_wallet()
    if wallet.get("did") and wallet.get("private_key") and wallet.get("public_key"):
        return {"did": wallet["did"], "wallet": wallet_summary()}

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key_b64 = b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    private_key_b64 = b64encode(
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    response = http_post_json(f"{ISSUER_URL}/did/create", {"device_public_key": public_key_b64})
    did = response.get("did")
    if not did:
        raise HTTPException(status_code=502, detail="issuer did/create response missing did")
    update_wallet(
        {
            "device_id": wallet.get("device_id") or BENCHMARK_DEVICE_ID,
            "did": did,
            "private_key": private_key_b64,
            "public_key": public_key_b64,
        }
    )
    return {"did": did, "wallet": wallet_summary()}


@app.post("/issue-identity")
def issue_identity() -> dict[str, Any]:
    wallet = require_onboarded_wallet()
    response = http_post_json(
        f"{ISSUER_URL}/vc/issue/identity-with-proof",
        {"subject_did": wallet["did"], "device_public_key": wallet["public_key"]},
    )
    vc = response.get("vc")
    proof = response.get("accumulator_proof")
    if not isinstance(vc, dict) or not isinstance(proof, dict):
        raise HTTPException(status_code=502, detail="issuer identity response missing vc or accumulator_proof")
    update_wallet(vc_proof_patch("identity", vc, proof))
    return {"vc": vc, "accumulator_proof": proof, "wallet": wallet_summary()}


@app.post("/issue-capability")
def issue_capability(payload: CapabilityRequest) -> dict[str, Any]:
    wallet = require_onboarded_wallet()
    response = http_post_json(
        f"{ISSUER_URL}/vc/issue/capability-with-proof",
        {"subject_did": wallet["did"], "action": payload.action, "resource": payload.resource},
    )
    vc = response.get("vc")
    proof = response.get("accumulator_proof")
    if not isinstance(vc, dict) or not isinstance(proof, dict):
        raise HTTPException(status_code=502, detail="issuer capability response missing vc or accumulator_proof")
    update_wallet(vc_proof_patch("capability", vc, proof))
    return {"vc": vc, "accumulator_proof": proof, "wallet": wallet_summary()}


@app.post("/refresh-proof")
def refresh_proof_endpoint(payload: RefreshProofRequest) -> dict[str, Any]:
    start = time.perf_counter()
    proof, retry_meta = refresh_stored_proof(
        payload.credential_type,
        network_profile=payload.network_profile,
        network_retries=payload.network_retries,
        network_retry_delay_ms=payload.network_retry_delay_ms,
    )
    return {
        "credential_type": payload.credential_type,
        "accumulator_proof": proof,
        "latency_ms": elapsed_ms(start),
        **retry_meta,
        "wallet": wallet_summary(),
    }


@app.post("/authorize")
def authorize_endpoint(payload: AuthorizeAgentRequest) -> dict[str, Any]:
    return authorize_from_wallet(
        payload.requested_action,
        payload.requested_resource,
        auto_refresh=payload.auto_refresh,
        retry_on_stale=payload.retry_on_stale,
        network_profile=payload.network_profile,
        network_retries=payload.network_retries,
        network_retry_delay_ms=payload.network_retry_delay_ms,
    )


@app.post("/run")
def run_benchmark(payload: RunRequest) -> dict[str, Any]:
    started_at = now_iso()
    try:
        summary = run_pipeline(
            payload.runs,
            payload.warmup_runs,
            payload.profile,
            payload.preserve_wallet,
            payload.network_profile,
            payload.force_fresh_verifier_state,
        )
        return {
            "profile": payload.profile,
            "status": "completed",
            "started_at": started_at,
            "finished_at": now_iso(),
            "return_code": 0,
            "summary": summary,
            "stdout_tail": "",
            "stderr_tail": "",
        }
    except Exception as exc:
        return {
            "profile": payload.profile,
            "status": "failed",
            "started_at": started_at,
            "finished_at": now_iso(),
            "return_code": 1,
            "summary": {},
            "stdout_tail": "",
            "stderr_tail": str(exc),
        }


@app.post("/run-pipeline")
def run_pipeline_endpoint(payload: RunRequest) -> dict[str, Any]:
    started_at = now_iso()
    summary = run_pipeline(
        payload.runs,
        payload.warmup_runs,
        payload.profile,
        payload.preserve_wallet,
        payload.network_profile,
        payload.force_fresh_verifier_state,
    )
    return {
        "profile": payload.profile,
        "status": "completed",
        "started_at": started_at,
        "finished_at": now_iso(),
        "summary": summary,
    }


def run_pipeline(
    runs: int,
    warmup_runs: int,
    profile: str,
    preserve_wallet: bool = False,
    network_profile: str = "none",
    force_fresh_verifier_state: bool = False,
) -> dict[str, Any]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    total_runs = max(0, warmup_runs) + max(1, runs)
    for index in range(total_runs):
        row = run_pipeline_iteration(
            index + 1,
            preserve_wallet=preserve_wallet,
            network_profile=network_profile,
            force_fresh_verifier_state=force_fresh_verifier_state,
        )
        if index >= max(0, warmup_runs):
            rows.append(row)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_path = OUTPUT_DIR / f"benchmark_raw_agent_{profile}_{timestamp}.csv"
    summary_path = OUTPUT_DIR / f"benchmark_summary_agent_{profile}_{timestamp}.csv"
    write_rows(raw_path, rows)
    summary_rows = summarize_rows(rows)
    write_rows(summary_path, summary_rows)
    values = {row["metric"]: float(row["mean"]) for row in summary_rows if row.get("mean") not in (None, "")}
    breakdown = {
        key: values[key]
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
            "replacement_proof_refresh_ms",
            "auth_replacement_allow_ms",
        )
        if key in values
    }
    return {
        "full_lifecycle_ms": values.get("full_iteration_ms"),
        "measured_lifecycle_ms": values.get("measured_lifecycle_ms")
        or values.get("full_iteration_ms"),
        "raw_wall_clock_ms": values.get("raw_wall_clock_ms"),
        "excluded_wait_ms": values.get("excluded_wait_ms") or 0.0,
        "includes_cache_wait": False,
        "timing_scope": TIMING_SCOPE,
        "uses_device_agent": True,
        "uses_holder_agent": False,
        "breakdown_by_stage_ms": breakdown,
        "auth_allow_ms": values.get("auth_allow_ms"),
        "proof_refresh_ms": values.get("proof_refresh_ms"),
        "did_create_ms": values.get("did_create_ms"),
        "did_resolve_ms": values.get("did_resolve_ms"),
        "identity_vc_issue_ms": values.get("identity_vc_issue_ms"),
        "capability_vc_issue_ms": values.get("capability_vc_issue_ms"),
        "revoke_capability_ms": values.get("revoke_capability_ms"),
        "auth_wrong_action_deny_ms": values.get("auth_wrong_action_deny_ms"),
        "auth_revoked_or_stale_deny_ms": values.get("auth_revoked_or_stale_deny_ms"),
        "replacement_capability_issue_ms": values.get("replacement_capability_issue_ms"),
        "auth_replacement_allow_ms": values.get("auth_replacement_allow_ms"),
        "auth_allow_request_bytes": values.get("auth_allow_request_bytes"),
        "identity_vc_bytes": values.get("identity_vc_bytes"),
        "capability_vc_bytes": values.get("capability_vc_bytes"),
        "identity_proof_bytes": values.get("identity_proof_bytes"),
        "capability_proof_bytes": values.get("capability_proof_bytes"),
        "auth_allow_response_bytes": values.get("auth_allow_response_bytes"),
        "revoke_response_bytes": values.get("revoke_response_bytes"),
        "accumulator_state_bytes": values.get("accumulator_state_bytes"),
        "verifier_cache_wait_ms": values.get("verifier_cache_wait_ms"),
        "source": str(summary_path),
        "raw_source": str(raw_path),
    }


def run_pipeline_iteration(
    iteration: int,
    preserve_wallet: bool = False,
    network_profile: str = "none",
    force_fresh_verifier_state: bool = False,
) -> dict[str, Any]:
    raw_started = time.perf_counter()
    if not preserve_wallet:
        reset_wallet()
    row: dict[str, Any] = {"iteration": iteration}
    measured_started = time.perf_counter()
    excluded_wait_ms = 0.0

    onboard_response, row["did_create_ms"] = timed_call(onboard)
    _, row["did_resolve_ms"] = timed_call(lambda: resolve_did(str(onboard_response["did"])))
    identity_response, row["identity_vc_issue_ms"] = timed_call(issue_identity)
    capability_response, row["capability_vc_issue_ms"] = timed_call(lambda: issue_capability(CapabilityRequest()))
    row["identity_vc_bytes"] = json_size(identity_response.get("vc"))
    row["identity_proof_bytes"] = json_size(identity_response.get("accumulator_proof"))
    row["capability_vc_bytes"] = json_size(capability_response.get("vc"))
    row["capability_proof_bytes"] = json_size(capability_response.get("accumulator_proof"))

    refresh_started = time.perf_counter()
    refresh_stored_proof("identity", network_profile=network_profile)
    refresh_stored_proof("capability", network_profile=network_profile)
    row["proof_refresh_ms"] = elapsed_ms(refresh_started)

    allow_response = authorize_from_wallet(
        ACTION,
        RESOURCE,
        auto_refresh=False,
        retry_on_stale=False,
        network_profile=network_profile,
    )
    row["auth_allow_ms"] = allow_response["authorization_latency_ms"]
    row["auth_allow_request_bytes"] = allow_response.get("request_bytes")
    row["auth_allow_response_bytes"] = allow_response.get("response_bytes")
    row["auth_allow_decision"] = allow_response["final_decision"]
    row["auth_allow_reason"] = allow_response["final_reason"]
    expect_decision(allow_response, "allow", "allow authorization")

    wrong_response = authorize_from_wallet(
        "write",
        RESOURCE,
        auto_refresh=False,
        retry_on_stale=False,
        network_profile=network_profile,
    )
    row["auth_wrong_action_deny_ms"] = wrong_response["authorization_latency_ms"]
    row["wrong_action_decision"] = wrong_response["final_decision"]
    row["wrong_action_reason"] = wrong_response["final_reason"]
    expect_decision(wrong_response, "deny", "wrong action authorization")

    # Snapshot old credential before revocation
    wallet = load_wallet()
    old_capability_credential_id = wallet.get("capability_credential_id")
    old_identity_vc = json_load(wallet.get("identity_vc_json"))
    old_identity_proof = json_load(wallet.get("identity_accumulator_proof_json"))
    old_capability_vc = json_load(wallet.get("capability_vc_json"))
    old_capability_proof = json_load(wallet.get("capability_accumulator_proof_json"))

    revoke_started = time.perf_counter()
    revoke_body = http_post_json(
        f"{ISSUER_URL}/vc/revoke",
        {"credential_id": old_capability_credential_id, "reason": "benchmark capability revocation"},
    )
    row["revoke_capability_ms"] = elapsed_ms(revoke_started)
    row["revoke_response_bytes"] = json_size(revoke_body)
    accumulator_state = revoke_body.get("accumulator")
    if isinstance(accumulator_state, dict):
        row["accumulator_state_bytes"] = json_size(accumulator_state)

    if force_fresh_verifier_state:
        row["verifier_cache_wait_ms"] = 0.0
    elif VERIFIER_CACHE_WAIT_SECONDS > 0:
        row["verifier_cache_wait_ms"] = round(VERIFIER_CACHE_WAIT_SECONDS * 1000, 3)
        excluded_wait_ms += row["verifier_cache_wait_ms"]
        time.sleep(VERIFIER_CACHE_WAIT_SECONDS)
    else:
        row["verifier_cache_wait_ms"] = 0.0

    revoked_response = authorize_with_material(
        old_identity_vc,
        old_capability_vc,
        old_identity_proof,
        old_capability_proof,
        ACTION,
        RESOURCE,
        auto_refresh=False,
        retry_on_stale=False,
        network_profile=network_profile,
        force_fresh_accumulator=force_fresh_verifier_state,
    )
    row["auth_revoked_or_stale_deny_ms"] = revoked_response["authorization_latency_ms"]
    row["revoked_decision"] = revoked_response["final_decision"]
    row["revoked_reason"] = revoked_response["final_reason"]
    row["revoked_cap_id"] = old_capability_credential_id
    row["old_capability_credential_id"] = old_capability_credential_id
    row["replacement_capability_credential_id"] = ""
    row["used_snapshot"] = True

    if revoked_response.get("final_decision") == "allow":
        raise RuntimeError(f"revoked stale authorization unexpectedly allowed old capability credential {old_capability_credential_id}")
    expect_decision(revoked_response, "deny", "revoked or stale authorization")

    replacement_response, row["replacement_capability_issue_ms"] = timed_call(
        lambda: issue_capability(CapabilityRequest())
    )
    row["replacement_capability_vc_id"] = replacement_response.get("vc", {}).get("id", "")
    row["replacement_cap_id"] = row["replacement_capability_vc_id"]
    row["replacement_capability_credential_id"] = row["replacement_capability_vc_id"]

    replacement_refresh_started = time.perf_counter()
    refresh_stored_proof("identity", network_profile=network_profile)
    refresh_stored_proof("capability", network_profile=network_profile)
    row["replacement_proof_refresh_ms"] = elapsed_ms(replacement_refresh_started)
    replacement_allow = authorize_from_wallet(
        ACTION,
        RESOURCE,
        auto_refresh=False,
        retry_on_stale=False,
        network_profile=network_profile,
    )
    row["auth_replacement_allow_ms"] = replacement_allow["authorization_latency_ms"]
    row["replacement_allow_decision"] = replacement_allow["final_decision"]
    row["replacement_allow_reason"] = replacement_allow["final_reason"]
    expect_decision(replacement_allow, "allow", "replacement authorization")

    row["excluded_wait_ms"] = round(excluded_wait_ms, 3)
    row["raw_wall_clock_ms"] = elapsed_ms(raw_started)
    row["measured_lifecycle_ms"] = round(
        max(0.0, elapsed_ms(measured_started) - excluded_wait_ms),
        3,
    )
    row["full_iteration_ms"] = row["measured_lifecycle_ms"]
    row["includes_cache_wait"] = False
    return row


def authorize_from_wallet(
    requested_action: str,
    requested_resource: str,
    auto_refresh: bool,
    retry_on_stale: bool,
    network_profile: str = "none",
    network_retries: int = 2,
    network_retry_delay_ms: int = 500,
) -> dict[str, Any]:
    total_started = time.perf_counter()
    refresh_latency = 0.0
    refresh_attempted = False
    if auto_refresh:
        refresh_started = time.perf_counter()
        refresh_attempted = refresh_if_stale(
            network_profile=network_profile,
            network_retries=network_retries,
            network_retry_delay_ms=network_retry_delay_ms,
        )
        refresh_latency += elapsed_ms(refresh_started)

    request_payload = build_authorization_payload(requested_action, requested_resource)
    auth_started = time.perf_counter()
    urls = service_urls(network_profile)
    try:
        initial, initial_retry_meta = http_post_json_retry(
            f"{urls['verifier']}/authorize",
            request_payload,
            retries=network_retries,
            retry_delay_ms=network_retry_delay_ms,
        )
    except RuntimeError as exc:
        authorization_latency = elapsed_ms(auth_started)
        return network_error_response(
            str(exc),
            authorization_latency,
            elapsed_ms(total_started),
            json_size(request_payload),
            network_retries,
        )
    authorization_latency = elapsed_ms(auth_started)
    initial_decision = str(initial.get("decision") or "")
    initial_reason = str(initial.get("reason") or "")
    retry_decision = None
    retry_reason = None

    if retry_on_stale and initial_decision == "deny" and initial_reason == "accumulator proof stale":
        refresh_started = time.perf_counter()
        refresh_attempted = True
        for credential_type in ("identity", "capability"):
            refresh_stored_proof(
                credential_type,
                network_profile=network_profile,
                network_retries=network_retries,
                network_retry_delay_ms=network_retry_delay_ms,
            )
        refresh_latency += elapsed_ms(refresh_started)
        retry_payload = build_authorization_payload(requested_action, requested_resource)
        retry_started = time.perf_counter()
        try:
            retry, retry_meta = http_post_json_retry(
                f"{urls['verifier']}/authorize",
                retry_payload,
                retries=network_retries,
                retry_delay_ms=network_retry_delay_ms,
            )
            initial_retry_meta["network_retries_used"] += retry_meta["network_retries_used"]
        except RuntimeError as exc:
            retry = {
                "decision": "network_error",
                "reason": str(exc),
            }
            initial_retry_meta["network_error"] = str(exc)
        authorization_latency += elapsed_ms(retry_started)
        retry_decision = str(retry.get("decision") or "")
        retry_reason = str(retry.get("reason") or "")

    final_decision = retry_decision if retry_decision is not None else initial_decision
    final_reason = retry_reason if retry_reason is not None else initial_reason
    return {
        "initial_decision": initial_decision,
        "initial_reason": initial_reason,
        "refresh_attempted": refresh_attempted,
        "retry_decision": retry_decision,
        "retry_reason": retry_reason,
        "final_decision": final_decision,
        "final_reason": final_reason,
        "refresh_latency_ms": round(refresh_latency, 3),
        "authorization_latency_ms": round(authorization_latency, 3),
        "total_latency_ms": elapsed_ms(total_started),
        "request_bytes": json_size(request_payload),
        "response_bytes": json_size(retry) if retry_decision is not None else json_size(initial),
        **initial_retry_meta,
    }


def resolve_did(did: str) -> dict[str, Any]:
    response = http_get_json(f"{ISSUER_URL}/did/resolve?{urlencode({'did': did})}")
    if response.get("found") is not True:
        raise HTTPException(status_code=502, detail=f"issuer did/resolve did not find {did}")
    return response


def build_authorization_payload_from_material(
    identity_vc: dict[str, Any],
    capability_vc: dict[str, Any],
    identity_proof: dict[str, Any] | None,
    capability_proof: dict[str, Any] | None,
    requested_action: str,
    requested_resource: str,
    force_fresh_accumulator: bool = False,
) -> dict[str, Any]:
    wallet = require_onboarded_wallet()
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(b64decode(wallet["private_key"]))
    nonce = f"nonce_{uuid.uuid4()}"
    payload = {
        "identity_vc": identity_vc,
        "capability_vc": capability_vc,
        "nonce": nonce,
        "device_signature": b64encode(private_key.sign(nonce.encode("utf-8"))),
        "requested_action": requested_action,
        "requested_resource": requested_resource,
        "force_fresh_accumulator": force_fresh_accumulator,
    }
    if identity_proof is not None:
        payload["identity_accumulator_proof"] = identity_proof
    if capability_proof is not None:
        payload["capability_accumulator_proof"] = capability_proof
    return payload


def authorize_with_material(
    identity_vc: dict[str, Any],
    capability_vc: dict[str, Any],
    identity_proof: dict[str, Any] | None,
    capability_proof: dict[str, Any] | None,
    requested_action: str,
    requested_resource: str,
    auto_refresh: bool = False,
    retry_on_stale: bool = False,
    network_profile: str = "none",
    network_retries: int = 2,
    network_retry_delay_ms: int = 500,
    force_fresh_accumulator: bool = False,
) -> dict[str, Any]:
    total_started = time.perf_counter()
    refresh_latency = 0.0
    refresh_attempted = False

    if auto_refresh:
        refresh_started = time.perf_counter()
        refresh_attempted = refresh_if_stale(
            network_profile=network_profile,
            network_retries=network_retries,
            network_retry_delay_ms=network_retry_delay_ms,
        )
        refresh_latency += elapsed_ms(refresh_started)
        if refresh_attempted:
            wallet = load_wallet()
            identity_vc = json_load(wallet.get("identity_vc_json"))
            capability_vc = json_load(wallet.get("capability_vc_json"))
            identity_proof = json_load(wallet.get("identity_accumulator_proof_json"))
            capability_proof = json_load(wallet.get("capability_accumulator_proof_json"))

    request_payload = build_authorization_payload_from_material(
        identity_vc, capability_vc, identity_proof, capability_proof,
        requested_action, requested_resource, force_fresh_accumulator
    )
    auth_started = time.perf_counter()
    urls = service_urls(network_profile)
    try:
        initial, initial_retry_meta = http_post_json_retry(
            f"{urls['verifier']}/authorize",
            request_payload,
            retries=network_retries,
            retry_delay_ms=network_retry_delay_ms,
        )
    except RuntimeError as exc:
        authorization_latency = elapsed_ms(auth_started)
        return network_error_response(
            str(exc),
            authorization_latency,
            elapsed_ms(total_started),
            json_size(request_payload),
            network_retries,
        )
    authorization_latency = elapsed_ms(auth_started)
    initial_decision = str(initial.get("decision") or "")
    initial_reason = str(initial.get("reason") or "")
    retry_decision = None
    retry_reason = None

    if retry_on_stale and initial_decision == "deny" and initial_reason == "accumulator proof stale":
        refresh_started = time.perf_counter()
        refresh_attempted = True
        for credential_type in ("identity", "capability"):
            refresh_stored_proof(
                credential_type,
                network_profile=network_profile,
                network_retries=network_retries,
                network_retry_delay_ms=network_retry_delay_ms,
            )
        refresh_latency += elapsed_ms(refresh_started)

        wallet = load_wallet()
        refreshed_id_vc = json_load(wallet.get("identity_vc_json"))
        refreshed_cap_vc = json_load(wallet.get("capability_vc_json"))
        refreshed_id_proof = json_load(wallet.get("identity_accumulator_proof_json"))
        refreshed_cap_proof = json_load(wallet.get("capability_accumulator_proof_json"))

        retry_payload = build_authorization_payload_from_material(
            refreshed_id_vc, refreshed_cap_vc, refreshed_id_proof, refreshed_cap_proof,
            requested_action, requested_resource, force_fresh_accumulator
        )
        retry_started = time.perf_counter()
        try:
            retry, retry_meta = http_post_json_retry(
                f"{urls['verifier']}/authorize",
                retry_payload,
                retries=network_retries,
                retry_delay_ms=network_retry_delay_ms,
            )
            initial_retry_meta["network_retries_used"] += retry_meta["network_retries_used"]
        except RuntimeError as exc:
            retry = {
                "decision": "network_error",
                "reason": str(exc),
            }
            initial_retry_meta["network_error"] = str(exc)
        authorization_latency += elapsed_ms(retry_started)
        retry_decision = str(retry.get("decision") or "")
        retry_reason = str(retry.get("reason") or "")

    final_decision = retry_decision if retry_decision is not None else initial_decision
    final_reason = retry_reason if retry_reason is not None else initial_reason
    return {
        "initial_decision": initial_decision,
        "initial_reason": initial_reason,
        "refresh_attempted": refresh_attempted,
        "retry_decision": retry_decision,
        "retry_reason": retry_reason,
        "final_decision": final_decision,
        "final_reason": final_reason,
        "refresh_latency_ms": round(refresh_latency, 3),
        "authorization_latency_ms": round(authorization_latency, 3),
        "total_latency_ms": elapsed_ms(total_started),
        "request_bytes": json_size(request_payload),
        **initial_retry_meta,
    }


def refresh_if_stale(
    network_profile: str = "none",
    network_retries: int = 2,
    network_retry_delay_ms: int = 500,
) -> bool:
    wallet = require_credential_wallet()
    try:
        state, _ = http_get_json_retry(
            f"{service_urls(network_profile)['issuer']}/revocation/accumulator/state",
            retries=network_retries,
            retry_delay_ms=network_retry_delay_ms,
        )
    except Exception:
        return False
    latest_version = int(state.get("version") or -1)
    latest_root = state.get("root") or ""
    attempted = False
    for credential_type in ("identity", "capability"):
        version = int(wallet.get(f"{credential_type}_proof_version") or -1)
        root = wallet.get(f"{credential_type}_proof_root") or ""
        if version != latest_version or root != latest_root:
            refresh_stored_proof(
                credential_type,
                network_profile=network_profile,
                network_retries=network_retries,
                network_retry_delay_ms=network_retry_delay_ms,
            )
            attempted = True
    return attempted


def refresh_stored_proof(
    credential_type: str,
    network_profile: str = "none",
    network_retries: int = 2,
    network_retry_delay_ms: int = 500,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if credential_type not in {"identity", "capability"}:
        raise HTTPException(status_code=400, detail="credential_type must be identity or capability")
    wallet = require_credential_wallet()
    credential_id = wallet.get(f"{credential_type}_credential_id")
    if not credential_id:
        raise HTTPException(status_code=400, detail=f"{credential_type} credential id missing")
    try:
        proof, retry_meta = http_post_json_retry(
            f"{service_urls(network_profile)['issuer']}/revocation/accumulator/refresh-proof",
            {"credential_id": credential_id},
            retries=network_retries,
            retry_delay_ms=network_retry_delay_ms,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=extract_error_detail(str(exc))) from exc
    update_wallet(proof_patch(credential_type, proof))
    return proof, retry_meta


def build_authorization_payload(requested_action: str, requested_resource: str) -> dict[str, Any]:
    wallet = require_credential_wallet()
    identity_vc = json_load(wallet.get("identity_vc_json"))
    capability_vc = json_load(wallet.get("capability_vc_json"))
    identity_proof = json_load(wallet.get("identity_accumulator_proof_json"))
    capability_proof = json_load(wallet.get("capability_accumulator_proof_json"))
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(b64decode(wallet["private_key"]))
    nonce = f"nonce_{uuid.uuid4()}"
    return {
        "identity_vc": identity_vc,
        "capability_vc": capability_vc,
        "identity_accumulator_proof": identity_proof,
        "capability_accumulator_proof": capability_proof,
        "nonce": nonce,
        "device_signature": b64encode(private_key.sign(nonce.encode("utf-8"))),
        "requested_action": requested_action,
        "requested_resource": requested_resource,
    }


def init_wallet() -> None:
    WALLET_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(WALLET_DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS wallet (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                device_id TEXT,
                did TEXT,
                private_key TEXT,
                public_key TEXT,
                identity_vc_json TEXT,
                capability_vc_json TEXT,
                identity_accumulator_proof_json TEXT,
                capability_accumulator_proof_json TEXT,
                identity_credential_id TEXT,
                capability_credential_id TEXT,
                identity_proof_version INTEGER,
                capability_proof_version INTEGER,
                identity_proof_root TEXT,
                capability_proof_root TEXT,
                created_at TEXT,
                updated_at TEXT
            )
            """
        )
        now = now_iso()
        conn.execute(
            """
            INSERT OR IGNORE INTO wallet (id, device_id, created_at, updated_at)
            VALUES (1, ?, ?, ?)
            """,
            (BENCHMARK_DEVICE_ID, now, now),
        )


def reset_wallet() -> None:
    init_wallet()
    with sqlite3.connect(WALLET_DB_PATH) as conn:
        conn.execute("DELETE FROM wallet")
        now = now_iso()
        conn.execute(
            "INSERT INTO wallet (id, device_id, created_at, updated_at) VALUES (1, ?, ?, ?)",
            (BENCHMARK_DEVICE_ID, now, now),
        )


def load_wallet() -> dict[str, Any]:
    init_wallet()
    with sqlite3.connect(WALLET_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM wallet WHERE id = 1").fetchone()
    return dict(row) if row else {}


def update_wallet(patch: dict[str, Any]) -> None:
    init_wallet()
    patch = {**patch, "updated_at": now_iso()}
    assignments = ", ".join(f"{key} = ?" for key in patch)
    with sqlite3.connect(WALLET_DB_PATH) as conn:
        conn.execute(
            f"UPDATE wallet SET {assignments} WHERE id = 1",
            list(patch.values()),
        )


def wallet_summary() -> dict[str, Any]:
    wallet = load_wallet()
    return {
        "did": wallet.get("did"),
        "device_id": wallet.get("device_id"),
        "has_identity_vc": bool(wallet.get("identity_vc_json")),
        "has_capability_vc": bool(wallet.get("capability_vc_json")),
        "identity_credential_id": wallet.get("identity_credential_id"),
        "capability_credential_id": wallet.get("capability_credential_id"),
        "identity_proof_version": wallet.get("identity_proof_version"),
        "capability_proof_version": wallet.get("capability_proof_version"),
        "identity_proof_root_prefix": root_prefix(wallet.get("identity_proof_root")),
        "capability_proof_root_prefix": root_prefix(wallet.get("capability_proof_root")),
    }


def require_onboarded_wallet() -> dict[str, Any]:
    wallet = load_wallet()
    if not wallet.get("did") or not wallet.get("private_key") or not wallet.get("public_key"):
        raise HTTPException(status_code=400, detail="wallet is not onboarded")
    return wallet


def require_credential_wallet() -> dict[str, Any]:
    wallet = require_onboarded_wallet()
    if not wallet.get("identity_vc_json") or not wallet.get("capability_vc_json"):
        raise HTTPException(status_code=400, detail="identity and capability credentials are required")
    return wallet


def vc_proof_patch(credential_type: str, vc: dict[str, Any], proof: dict[str, Any]) -> dict[str, Any]:
    return {
        f"{credential_type}_vc_json": json_dumps(vc),
        f"{credential_type}_accumulator_proof_json": json_dumps(proof),
        f"{credential_type}_credential_id": vc.get("id"),
        **proof_patch(credential_type, proof),
    }


def proof_patch(credential_type: str, proof: dict[str, Any]) -> dict[str, Any]:
    return {
        f"{credential_type}_accumulator_proof_json": json_dumps(proof),
        f"{credential_type}_proof_version": int(proof.get("version") or 0),
        f"{credential_type}_proof_root": proof.get("root") or "",
    }


def http_get_json(url: str) -> dict[str, Any]:
    return http_json(Request(url, method="GET"))


def http_post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return http_json(Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST"))


def http_get_json_retry(
    url: str,
    retries: int,
    retry_delay_ms: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return http_json_retry(Request(url, method="GET"), retries, retry_delay_ms)


def http_post_json_retry(
    url: str,
    payload: dict[str, Any],
    retries: int,
    retry_delay_ms: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return http_json_retry(
        Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST"),
        retries,
        retry_delay_ms,
    )


def http_json_retry(
    request: Request,
    retries: int,
    retry_delay_ms: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    attempts = max(1, int(retries) + 1)
    delay_seconds = max(0, int(retry_delay_ms)) / 1000
    retries_used = 0
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                return json.loads(response.read().decode("utf-8")), {
                    "network_retries_used": retries_used,
                    "network_error": None,
                }
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"request failed: {exc.code} {body}") from exc
        except (ConnectionError, TimeoutError, URLError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                retries_used += 1
                time.sleep(delay_seconds)
    raise RuntimeError(f"request failed: {request.full_url}: {last_error}")


def http_json(request: Request) -> dict[str, Any]:
    attempts = int(os.getenv("HTTP_RETRY_ATTEMPTS", "3"))
    sleep_seconds = float(os.getenv("HTTP_RETRY_SLEEP_SECONDS", "0.5"))
    last_error: Exception | None = None
    for attempt in range(max(1, attempts)):
        try:
            with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"request failed: {exc.code} {body}") from exc
        except (ConnectionError, TimeoutError, URLError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(sleep_seconds)
    raise RuntimeError(f"request failed: {request.full_url}: {last_error}")


def extract_error_detail(text: str) -> str:
    marker = "request failed: 400 "
    if marker in text:
        body = text.split(marker, 1)[1]
        try:
            parsed = json.loads(body)
            detail = parsed.get("detail")
            if detail:
                return str(detail)
        except Exception:
            pass
    return text


def service_urls(network_profile: str) -> dict[str, str]:
    normalized = str(network_profile or "none").strip().lower()
    if normalized in {"packet_loss_10", "latency_250", "timeout", "disconnect"}:
        return {
            "issuer": TOXIPROXY_ISSUER_URL,
            "verifier": TOXIPROXY_VERIFIER_URL,
            "fabric_adapter": FABRIC_ADAPTER_URL,
        }
    return {
        "issuer": ISSUER_URL,
        "verifier": VERIFIER_URL,
        "fabric_adapter": FABRIC_ADAPTER_URL,
    }


def network_error_response(
    error: str,
    authorization_latency: float,
    total_latency: float,
    request_bytes: int,
    retries: int,
) -> dict[str, Any]:
    return {
        "initial_decision": "network_error",
        "initial_reason": error,
        "refresh_attempted": False,
        "retry_decision": None,
        "retry_reason": None,
        "final_decision": "network_error",
        "final_reason": error,
        "refresh_latency_ms": 0.0,
        "authorization_latency_ms": round(authorization_latency, 3),
        "total_latency_ms": round(total_latency, 3),
        "request_bytes": request_bytes,
        "network_retries_used": max(0, int(retries)),
        "network_error": error,
    }


def timed_call(callback) -> tuple[Any, float]:
    start = time.perf_counter()
    result = callback()
    return result, elapsed_ms(start)


def expect_decision(response: dict[str, Any], decision: str, label: str) -> None:
    if response.get("final_decision") != decision:
        raise RuntimeError(f"expected {decision} for {label}, got {response}")


def write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def summarize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metrics = [
        "full_iteration_ms",
        "did_create_ms",
        "did_resolve_ms",
        "identity_vc_issue_ms",
        "identity_vc_bytes",
        "identity_proof_bytes",
        "capability_vc_issue_ms",
        "capability_vc_bytes",
        "capability_proof_bytes",
        "proof_refresh_ms",
        "auth_allow_ms",
        "auth_allow_request_bytes",
        "auth_allow_response_bytes",
        "auth_wrong_action_deny_ms",
        "revoke_capability_ms",
        "revoke_response_bytes",
        "accumulator_state_bytes",
        "verifier_cache_wait_ms",
        "excluded_wait_ms",
        "raw_wall_clock_ms",
        "measured_lifecycle_ms",
        "auth_revoked_or_stale_deny_ms",
        "replacement_capability_issue_ms",
        "replacement_proof_refresh_ms",
        "auth_replacement_allow_ms",
    ]
    summary = []
    for metric in metrics:
        values = [float(row[metric]) for row in rows if isinstance(row.get(metric), (int, float))]
        if values:
            summary.append(
                {
                    "metric": metric,
                    "count": len(values),
                    "mean": round(mean(values), 3),
                    "min": round(min(values), 3),
                    "max": round(max(values), 3),
                    "p50": round(percentile(sorted(values), 50), 3),
                    "p95": round(percentile(sorted(values), 95), 3),
                }
            )
    return summary


def percentile(sorted_values: list[float], percentile_value: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (percentile_value / 100) * (len(sorted_values) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = rank - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight
    

def json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def json_load(value: str | None) -> Any:
    return json.loads(value) if value else None


def json_size(value: Any) -> int:
    if value is None:
        return 0
    return len(json_dumps(value).encode("utf-8"))


def root_prefix(value: Any) -> str | None:
    text = str(value or "")
    return text[:12] if text else None


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
