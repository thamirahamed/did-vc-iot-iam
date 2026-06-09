import base64
import csv
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from summarize_results import summarize_csv


ISSUER_URL = os.getenv("ISSUER_URL", "http://localhost:8000").rstrip("/")
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://localhost:8001").rstrip("/")
RUNS = int(os.getenv("BENCHMARK_RUNS", "30"))
WARMUP_RUNS = int(os.getenv("BENCHMARK_WARMUP_RUNS", "3"))
OUTPUT_DIR = Path(os.getenv("BENCHMARK_OUTPUT_DIR", "results"))
BENCHMARK_LABEL = os.getenv("BENCHMARK_LABEL", "manual")
BENCHMARK_PROFILE = os.getenv("BENCHMARK_PROFILE", "full").strip().lower()
REVOCATION_MODE = os.getenv("REVOCATION_MODE", "")
FABRIC_ENABLED = os.getenv("FABRIC_ENABLED", "")
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "30"))
RESOURCE_MONITOR_ENABLED = os.getenv("RESOURCE_MONITOR_ENABLED", "false").strip().lower() == "true"
RESOURCE_MONITOR_FAIL_CLOSED = (
    os.getenv("RESOURCE_MONITOR_FAIL_CLOSED", "false").strip().lower() == "true"
)
RESOURCE_MONITOR_INTERVAL_SECONDS = os.getenv("RESOURCE_MONITOR_INTERVAL_SECONDS", "1")
RESOURCE_MONITOR_CONTAINERS = os.getenv("RESOURCE_MONITOR_CONTAINERS", "")
RESOURCE_MONITOR_OUTPUT_DIR = Path(os.getenv("RESOURCE_MONITOR_OUTPUT_DIR", str(OUTPUT_DIR)))
RESOURCE_MONITOR_LABEL = os.getenv("RESOURCE_MONITOR_LABEL", BENCHMARK_LABEL)

ACTION = "read"
WRONG_ACTION = "write"
RESOURCE = "iot:device:example"

LATENCY_FIELDS = [
    "did_create_ms",
    "did_resolve_ms",
    "identity_vc_issue_ms",
    "capability_vc_issue_ms",
    "auth_allow_ms",
    "auth_wrong_action_deny_ms",
    "revoke_capability_ms",
    "auth_revoked_or_stale_deny_ms",
    "replacement_capability_issue_ms",
    "proof_refresh_ms",
    "auth_replacement_allow_ms",
    "full_iteration_ms",
]

SIZE_FIELDS = [
    "identity_vc_bytes",
    "capability_vc_bytes",
    "identity_proof_bytes",
    "capability_proof_bytes",
    "auth_allow_request_bytes",
    "auth_allow_response_bytes",
    "revoke_response_bytes",
    "accumulator_state_bytes",
]

RAW_FIELDS = [
    "timestamp",
    "benchmark_label",
    "benchmark_profile",
    "iteration",
    "fabric_enabled",
    "revocation_mode",
    "did",
    "identity_vc_id",
    "capability_vc_id",
    "replacement_capability_vc_id",
    *LATENCY_FIELDS,
    *SIZE_FIELDS,
    "auth_allow_decision",
    "auth_allow_reason",
    "wrong_action_decision",
    "wrong_action_reason",
    "revoked_decision",
    "revoked_reason",
    "replacement_allow_decision",
    "replacement_allow_reason",
    "error",
]


class HttpResponse:
    def __init__(self, body: dict[str, Any], raw_bytes: bytes) -> None:
        self.body = body
        self.raw_bytes = raw_bytes

    @property
    def size_bytes(self) -> int:
        return len(self.raw_bytes)


def main() -> None:
    if RUNS < 1:
        raise SystemExit("BENCHMARK_RUNS must be at least 1")
    if WARMUP_RUNS < 0:
        raise SystemExit("BENCHMARK_WARMUP_RUNS must be 0 or greater")
    validate_benchmark_profile()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    RESOURCE_MONITOR_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    run_timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_path = OUTPUT_DIR / f"benchmark_raw_{run_timestamp}.csv"
    resource_path = RESOURCE_MONITOR_OUTPUT_DIR / f"resource_usage_{run_timestamp}.csv"
    resource_monitor = None

    try:
        print(f"Issuer URL: {ISSUER_URL}")
        print(f"Verifier URL: {VERIFIER_URL}")
        print(f"Benchmark profile: {BENCHMARK_PROFILE}")
        print_profile_warning()
        print("Running health checks")
        http_get_json(f"{ISSUER_URL}/health")
        http_get_json(f"{VERIFIER_URL}/health")

        if RESOURCE_MONITOR_ENABLED:
            resource_monitor = start_resource_monitor(resource_path)
            wait_for_resource_monitor_sample(resource_monitor, resource_path)

        for iteration in range(1, WARMUP_RUNS + 1):
            print(f"Warmup iteration {iteration}/{WARMUP_RUNS}")
            run_iteration(iteration)

        failures = 0
        with raw_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=RAW_FIELDS)
            writer.writeheader()
            for iteration in range(1, RUNS + 1):
                print(f"Measured iteration {iteration}/{RUNS}")
                row = run_iteration(iteration)
                if row["error"]:
                    failures += 1
                    print(f"Iteration {iteration} failed: {row['error']}")
                writer.writerow(row)
                handle.flush()
    finally:
        if resource_monitor is not None:
            stop_resource_monitor(resource_monitor)

    summary_path = summarize_csv(raw_path)
    resource_summary_path = None
    if RESOURCE_MONITOR_ENABLED:
        print(f"Resource results: {resource_path}")
        if resource_path.exists():
            try:
                resource_summary_path = summarize_csv(resource_path)
            except SystemExit as exc:
                handle_resource_monitor_failure(f"resource summary failed: {exc}")

    print(f"Raw results: {raw_path}")
    print(f"Summary results: {summary_path}")
    if resource_summary_path is not None:
        print(f"Resource summary results: {resource_summary_path}")

    if failures == RUNS:
        raise SystemExit(1)


def start_resource_monitor(resource_path: Path) -> subprocess.Popen:
    command = [
        sys.executable,
        str(Path(__file__).with_name("collect_docker_stats.py")),
        "--label",
        RESOURCE_MONITOR_LABEL,
        "--output",
        str(resource_path),
        "--interval",
        RESOURCE_MONITOR_INTERVAL_SECONDS,
    ]
    if RESOURCE_MONITOR_CONTAINERS.strip():
        command.extend(["--containers", RESOURCE_MONITOR_CONTAINERS])

    try:
        process = subprocess.Popen(command)
    except Exception as exc:
        handle_resource_monitor_failure(f"failed to start resource monitor: {exc}")
        return None

    time.sleep(0.5)
    if process.poll() is not None:
        handle_resource_monitor_failure(
            f"resource monitor exited early with status {process.returncode}"
        )
    return process


def wait_for_resource_monitor_sample(process: subprocess.Popen | None, resource_path: Path) -> None:
    if process is None:
        return
    try:
        interval = float(RESOURCE_MONITOR_INTERVAL_SECONDS)
    except ValueError:
        interval = 1.0
    deadline = time.monotonic() + max(10.0, interval + 5.0)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            handle_resource_monitor_failure(
                f"resource monitor exited early with status {process.returncode}"
            )
            return
        if csv_has_data_row(resource_path):
            return
        time.sleep(0.2)
    handle_resource_monitor_failure("resource monitor did not write a sample before benchmark start")


def csv_has_data_row(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        with path.open("r", encoding="utf-8") as handle:
            return sum(1 for _ in handle) > 1
    except OSError:
        return False


def stop_resource_monitor(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def handle_resource_monitor_failure(message: str) -> None:
    if RESOURCE_MONITOR_FAIL_CLOSED:
        raise RuntimeError(message)
    print(f"Resource monitor warning: {message}")


def run_iteration(iteration: int) -> dict[str, Any]:
    row = empty_row(iteration)
    iteration_start = time.perf_counter()
    try:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key_b64 = b64encode(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )

        did_response, row["did_create_ms"] = timed_post(
            f"{ISSUER_URL}/did/create",
            {"device_public_key": public_key_b64},
        )
        subject_did = did_response.body["did"]
        row["did"] = subject_did

        _, row["did_resolve_ms"] = timed_get(
            f"{ISSUER_URL}/did/resolve?{urlencode({'did': subject_did})}"
        )

        identity_response, row["identity_vc_issue_ms"] = issue_identity(
            subject_did,
            public_key_b64,
        )
        identity_vc = identity_response["vc"]
        identity_proof = identity_response["proof"]
        row["identity_vc_id"] = identity_vc.get("id", "")
        row["identity_vc_bytes"] = json_size(identity_vc)
        row["identity_proof_bytes"] = json_size(identity_proof)

        capability_response, row["capability_vc_issue_ms"] = issue_capability(
            subject_did,
            ACTION,
            RESOURCE,
        )
        capability_vc = capability_response["vc"]
        capability_proof = capability_response["proof"]
        row["capability_vc_id"] = capability_vc.get("id", "")
        row["capability_vc_bytes"] = json_size(capability_vc)
        row["capability_proof_bytes"] = json_size(capability_proof)

        refreshed_identity_proof, refresh_ms = refresh_proof(identity_vc.get("id", ""))
        if refreshed_identity_proof is not None:
            identity_proof = refreshed_identity_proof
            row["proof_refresh_ms"] = refresh_ms

        allow_payload = build_authorize_payload(
            identity_vc,
            capability_vc,
            private_key,
            ACTION,
            RESOURCE,
            identity_proof,
            capability_proof,
        )
        row["auth_allow_request_bytes"] = json_size(allow_payload)
        allow_response, row["auth_allow_ms"] = timed_post(
            f"{VERIFIER_URL}/authorize",
            allow_payload,
        )
        row["auth_allow_response_bytes"] = allow_response.size_bytes
        row["auth_allow_decision"] = allow_response.body.get("decision", "")
        row["auth_allow_reason"] = allow_response.body.get("reason", "")
        expect_decision(allow_response.body, "allow", "allow authorization")

        wrong_action_payload = build_authorize_payload(
            identity_vc,
            capability_vc,
            private_key,
            WRONG_ACTION,
            RESOURCE,
            identity_proof,
            capability_proof,
        )
        wrong_action_response, row["auth_wrong_action_deny_ms"] = timed_post(
            f"{VERIFIER_URL}/authorize",
            wrong_action_payload,
        )
        row["wrong_action_decision"] = wrong_action_response.body.get("decision", "")
        row["wrong_action_reason"] = wrong_action_response.body.get("reason", "")
        expect_decision(wrong_action_response.body, "deny", "wrong action authorization")

        revoke_response, row["revoke_capability_ms"] = timed_post(
            f"{ISSUER_URL}/vc/revoke",
            {
                "credential_id": capability_vc["id"],
                "reason": "benchmark capability revocation",
            },
        )
        row["revoke_response_bytes"] = revoke_response.size_bytes
        if revoke_response.body.get("revoked") is not True:
            raise RuntimeError(f"expected revoked capability response, got {revoke_response.body}")

        accumulator_state = optional_get(f"{ISSUER_URL}/revocation/accumulator/state")
        if accumulator_state is not None:
            row["accumulator_state_bytes"] = accumulator_state.size_bytes

        revoked_payload = build_authorize_payload(
            identity_vc,
            capability_vc,
            private_key,
            ACTION,
            RESOURCE,
            identity_proof,
            capability_proof,
        )
        revoked_response, row["auth_revoked_or_stale_deny_ms"] = timed_post(
            f"{VERIFIER_URL}/authorize",
            revoked_payload,
        )
        row["revoked_decision"] = revoked_response.body.get("decision", "")
        row["revoked_reason"] = revoked_response.body.get("reason", "")
        expect_decision(revoked_response.body, "deny", "revoked or stale authorization")

        replacement_response, row["replacement_capability_issue_ms"] = issue_capability(
            subject_did,
            ACTION,
            RESOURCE,
        )
        replacement_capability_vc = replacement_response["vc"]
        replacement_capability_proof = replacement_response["proof"]
        row["replacement_capability_vc_id"] = replacement_capability_vc.get("id", "")

        refreshed_identity_proof, refresh_ms = refresh_proof(identity_vc.get("id", ""))
        if refreshed_identity_proof is not None:
            identity_proof = refreshed_identity_proof
            row["proof_refresh_ms"] = refresh_ms
        refreshed_replacement_proof, refresh_ms = refresh_proof(
            replacement_capability_vc.get("id", "")
        )
        if refreshed_replacement_proof is not None:
            replacement_capability_proof = refreshed_replacement_proof
            row["proof_refresh_ms"] = refresh_ms

        replacement_payload = build_authorize_payload(
            identity_vc,
            replacement_capability_vc,
            private_key,
            ACTION,
            RESOURCE,
            identity_proof,
            replacement_capability_proof,
        )
        replacement_allow_response, row["auth_replacement_allow_ms"] = timed_post(
            f"{VERIFIER_URL}/authorize",
            replacement_payload,
        )
        row["replacement_allow_decision"] = replacement_allow_response.body.get("decision", "")
        row["replacement_allow_reason"] = replacement_allow_response.body.get("reason", "")
        expect_decision(
            replacement_allow_response.body,
            "allow",
            "replacement capability authorization",
        )
    except Exception as exc:
        row["error"] = str(exc)
    finally:
        row["full_iteration_ms"] = elapsed_ms(iteration_start)
    return row


def empty_row(iteration: int) -> dict[str, Any]:
    row = {field: "" for field in RAW_FIELDS}
    row["timestamp"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    row["benchmark_label"] = BENCHMARK_LABEL
    row["benchmark_profile"] = BENCHMARK_PROFILE
    row["iteration"] = iteration
    row["fabric_enabled"] = FABRIC_ENABLED
    row["revocation_mode"] = REVOCATION_MODE
    row["error"] = ""
    return row


def validate_benchmark_profile() -> None:
    profiles = {"full", "no_audit", "status_only", "accumulator_hybrid"}
    if BENCHMARK_PROFILE not in profiles:
        raise SystemExit(
            f"BENCHMARK_PROFILE must be one of {', '.join(sorted(profiles))}"
        )


def print_profile_warning() -> None:
    revocation_mode = REVOCATION_MODE.strip().lower()
    audit_enabled = os.getenv("AUDIT_ENABLED", "true").strip().lower()
    if BENCHMARK_PROFILE == "no_audit" and audit_enabled != "false":
        print(
            "Benchmark profile warning: no_audit requires services started with "
            "AUDIT_ENABLED=false to disable audit writes."
        )
    if BENCHMARK_PROFILE == "status_only" and revocation_mode != "status":
        print(
            "Benchmark profile warning: status_only records metadata only; start "
            "services with REVOCATION_MODE=status for status-only behavior."
        )
    if BENCHMARK_PROFILE == "accumulator_hybrid" and revocation_mode not in (
        "accumulator",
        "hybrid",
    ):
        print(
            "Benchmark profile warning: accumulator_hybrid records metadata only; "
            "start services with REVOCATION_MODE=hybrid or accumulator."
        )


def issue_identity(subject_did: str, device_public_key_b64: str) -> tuple[dict[str, Any], float]:
    payload = {"subject_did": subject_did, "device_public_key": device_public_key_b64}
    try:
        response, duration_ms = timed_post(f"{ISSUER_URL}/vc/issue/identity-with-proof", payload)
        return {"vc": response.body["vc"], "proof": response.body.get("accumulator_proof")}, duration_ms
    except RuntimeError as exc:
        if "404" not in str(exc) and "405" not in str(exc):
            raise
    response, duration_ms = timed_post(f"{ISSUER_URL}/vc/issue/identity", payload)
    return {"vc": response.body, "proof": None}, duration_ms


def issue_capability(subject_did: str, action: str, resource: str) -> tuple[dict[str, Any], float]:
    payload = {"subject_did": subject_did, "action": action, "resource": resource}
    try:
        response, duration_ms = timed_post(f"{ISSUER_URL}/vc/issue/capability-with-proof", payload)
        return {"vc": response.body["vc"], "proof": response.body.get("accumulator_proof")}, duration_ms
    except RuntimeError as exc:
        if "404" not in str(exc) and "405" not in str(exc):
            raise
    response, duration_ms = timed_post(f"{ISSUER_URL}/vc/issue/capability", payload)
    return {"vc": response.body, "proof": None}, duration_ms


def refresh_proof(credential_id: str) -> tuple[dict[str, Any] | None, float]:
    if not credential_id:
        return None, 0.0
    try:
        response, duration_ms = timed_post(
            f"{ISSUER_URL}/revocation/accumulator/refresh-proof",
            {"credential_id": credential_id},
        )
        return response.body, duration_ms
    except RuntimeError as exc:
        if "404" in str(exc) or "405" in str(exc) or "credential not found" in str(exc):
            return None, 0.0
        raise


def build_authorize_payload(
    identity_vc: dict[str, Any],
    capability_vc: dict[str, Any],
    device_private_key: ed25519.Ed25519PrivateKey,
    requested_action: str,
    requested_resource: str,
    identity_accumulator_proof: dict[str, Any] | None = None,
    capability_accumulator_proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    nonce = f"nonce_{uuid.uuid4()}"
    payload = {
        "identity_vc": identity_vc,
        "capability_vc": capability_vc,
        "nonce": nonce,
        "device_signature": b64encode(device_private_key.sign(nonce.encode("utf-8"))),
        "requested_action": requested_action,
        "requested_resource": requested_resource,
    }
    if identity_accumulator_proof is not None:
        payload["identity_accumulator_proof"] = identity_accumulator_proof
    if capability_accumulator_proof is not None:
        payload["capability_accumulator_proof"] = capability_accumulator_proof
    return payload


def timed_get(url: str) -> tuple[HttpResponse, float]:
    start = time.perf_counter()
    response = http_get_json(url)
    return response, elapsed_ms(start)


def timed_post(url: str, payload: dict[str, Any]) -> tuple[HttpResponse, float]:
    start = time.perf_counter()
    response = http_post_json(url, payload)
    return response, elapsed_ms(start)


def http_get_json(url: str) -> HttpResponse:
    return http_json(Request(url, method="GET"))


def http_post_json(url: str, payload: dict[str, Any]) -> HttpResponse:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return http_json(
        Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
    )


def http_json(request: Request) -> HttpResponse:
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read()
    except HTTPError as exc:
        raw = exc.read()
        body = raw.decode("utf-8", errors="replace")
        raise RuntimeError(f"request failed: {exc.code} {body}") from exc
    return HttpResponse(json.loads(raw.decode("utf-8")), raw)


def optional_get(url: str) -> HttpResponse | None:
    try:
        return http_get_json(url)
    except RuntimeError as exc:
        if "404" in str(exc) or "405" in str(exc):
            return None
        raise


def expect_decision(response: dict[str, Any], decision: str, label: str) -> None:
    if response.get("decision") != decision:
        raise RuntimeError(f"expected {decision} for {label}, got {response}")


def json_size(value: Any) -> int:
    if value is None:
        return 0
    return len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
