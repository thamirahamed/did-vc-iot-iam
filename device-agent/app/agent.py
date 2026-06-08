import base64
import json
import os
import sys
import time
import uuid
from typing import Any, Dict, Iterable, Tuple
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from metrics import MetricRow, now_iso, summarize, write_csv


def log(msg: str = "") -> None:
    print(msg, flush=True)


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def tamper_b64(value: str) -> str:
    if not value:
        return value
    last = value[-1]
    return value[:-1] + ("A" if last != "A" else "B")


def http_post_json(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8")
        raise RuntimeError(f"request failed: {exc.code} {body}") from exc
    return json.loads(body)


def http_get_json(url: str) -> Dict[str, Any]:
    request = Request(url, method="GET")
    try:
        with urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8")
        raise RuntimeError(f"request failed: {exc.code} {body}") from exc
    return json.loads(body)


def wait_for_service(url: str, timeout_s: float = 30.0, interval_s: float = 0.5) -> None:
    deadline = time.time() + timeout_s
    last_error = None
    while time.time() < deadline:
        try:
            http_get_json(url)
            return
        except Exception as exc:
            last_error = exc
            time.sleep(interval_s)
    raise RuntimeError(f"service not ready: {url} ({last_error})")


def load_env() -> dict:
    perf_runs_env = os.getenv("PERF_RUNS", os.getenv("RUNS", "200"))
    return {
        "issuer_url": os.getenv("ISSUER_URL", "http://issuer:8000"),
        "verifier_url": os.getenv("VERIFIER_URL", "http://verifier:8001"),
        "action": os.getenv("ACTION", "read"),
        "resource": os.getenv("RESOURCE", "iot:device:example"),
        "runs": int(perf_runs_env),
        "warmup": int(os.getenv("WARMUP", "10")),
        "sleep_ms": int(os.getenv("SLEEP_MS", "0")),
        "out_csv": os.getenv("OUT_CSV", "/out/results.csv"),
        "mode": os.getenv("MODE", "perf").strip().lower(),
        "pause": os.getenv("PAUSE", "1") == "1",
        "show_json": os.getenv("SHOW_JSON", "0") == "1",
        "demo_revoke": os.getenv("DEMO_REVOKE", "0") == "1",
        "identity_vc_json": os.getenv("IDENTITY_VC_JSON", ""),
        "capability_vc_json": os.getenv("CAPABILITY_VC_JSON", ""),
        "identity_accumulator_proof_json": os.getenv("IDENTITY_ACCUMULATOR_PROOF_JSON", ""),
        "capability_accumulator_proof_json": os.getenv("CAPABILITY_ACCUMULATOR_PROOF_JSON", ""),
        "revocation_mode": os.getenv("REVOCATION_MODE", "status").strip().lower(),
        "debug": bool(os.getenv("DEBUG", "").strip()),
    }


def prepare_credentials(
    mode: str,
    issuer_url: str,
    action: str,
    resource: str,
    identity_vc_json: str,
    capability_vc_json: str,
    identity_accumulator_proof_json: str,
    capability_accumulator_proof_json: str,
    revocation_mode: str,
    device_public_key_b64: str,
    debug: bool,
    out_dir: str,
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any] | None, Dict[str, Any] | None]:
    identity_accumulator_proof = None
    capability_accumulator_proof = None
    if mode == "authorize_only":
        if not identity_vc_json:
            raise RuntimeError("IDENTITY_VC_JSON is required for authorize_only mode")
        if not capability_vc_json:
            raise RuntimeError("CAPABILITY_VC_JSON is required for authorize_only mode")
        try:
            identity_vc = json.loads(identity_vc_json)
            capability_vc = json.loads(capability_vc_json)
            if identity_accumulator_proof_json:
                identity_accumulator_proof = json.loads(identity_accumulator_proof_json)
            if capability_accumulator_proof_json:
                capability_accumulator_proof = json.loads(capability_accumulator_proof_json)
        except json.JSONDecodeError as exc:
            raise RuntimeError("IDENTITY_VC_JSON or CAPABILITY_VC_JSON is not valid JSON") from exc
    else:
        subject = http_post_json(
            f"{issuer_url}/did/create",
            {"device_public_key": device_public_key_b64},
        )
        subject_did = subject["did"]
        if revocation_mode in ("accumulator", "hybrid"):
            identity_response = http_post_json(
                f"{issuer_url}/vc/issue/identity-with-proof",
                {"subject_did": subject_did, "device_public_key": device_public_key_b64},
            )
            identity_vc = identity_response["vc"]
            identity_accumulator_proof = identity_response.get("accumulator_proof")
            capability_response = http_post_json(
                f"{issuer_url}/vc/issue/capability-with-proof",
                {"subject_did": subject_did, "action": action, "resource": resource},
            )
            capability_vc = capability_response["vc"]
            capability_accumulator_proof = capability_response.get("accumulator_proof")
            identity_accumulator_proof = http_post_json(
                f"{issuer_url}/revocation/accumulator/refresh-proof",
                {"credential_id": identity_vc["id"]},
            )
        else:
            identity_vc = http_post_json(
                f"{issuer_url}/vc/issue/identity",
                {"subject_did": subject_did, "device_public_key": device_public_key_b64},
            )
            capability_vc = http_post_json(
                f"{issuer_url}/vc/issue/capability",
                {"subject_did": subject_did, "action": action, "resource": resource},
            )

    if debug:
        path = os.path.join(out_dir, "identity_vc.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(identity_vc, handle, indent=2, sort_keys=True)
        path = os.path.join(out_dir, "capability_vc.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(capability_vc, handle, indent=2, sort_keys=True)
        if identity_accumulator_proof:
            path = os.path.join(out_dir, "identity_accumulator_proof.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(identity_accumulator_proof, handle, indent=2, sort_keys=True)
        if capability_accumulator_proof:
            path = os.path.join(out_dir, "capability_accumulator_proof.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(capability_accumulator_proof, handle, indent=2, sort_keys=True)

    return identity_vc, capability_vc, identity_accumulator_proof, capability_accumulator_proof


def section(step_num: int, title: str) -> None:
    log("==================================================")
    log(f"[STEP {step_num}] {title}")
    log("==================================================")


def api_call_line(method: str, path: str) -> None:
    log(f"→ {method} {path}")


def summary_kv(key: str, value: str) -> None:
    log(f"  - {key}: {value}")


def maybe_print_json(obj: Dict[str, Any], enabled: bool) -> None:
    if not enabled:
        return
    log("--- Full API response ---")
    log(json.dumps(obj, indent=2))
    log("-------------------------")


def pause_if_enabled(enabled: bool) -> None:
    if enabled:
        input("Press Enter to continue...")


def authorize_once(
    verifier_url: str,
    identity_vc: Dict[str, Any],
    capability_vc: Dict[str, Any],
    identity_accumulator_proof: Dict[str, Any] | None,
    capability_accumulator_proof: Dict[str, Any] | None,
    device_private_key: ed25519.Ed25519PrivateKey,
    action: str,
    resource: str,
) -> Tuple[float, float, str, str]:
    nonce = f"nonce_{uuid.uuid4()}"

    sign_start = time.perf_counter()
    signature = device_private_key.sign(nonce.encode("utf-8"))
    sign_end = time.perf_counter()
    signature_b64 = b64encode(signature)

    payload: Dict[str, Any] = {
        "identity_vc": identity_vc,
        "capability_vc": capability_vc,
        "nonce": nonce,
        "device_signature": signature_b64,
        "requested_action": action,
        "requested_resource": resource,
    }
    if identity_accumulator_proof is not None:
        payload["identity_accumulator_proof"] = identity_accumulator_proof
    if capability_accumulator_proof is not None:
        payload["capability_accumulator_proof"] = capability_accumulator_proof

    auth_start = time.perf_counter()
    try:
        response = http_post_json(f"{verifier_url}/authorize", payload)
        decision = response.get("decision", "error")
        reason = response.get("reason", "unknown")
    except Exception as exc:
        decision = "error"
        reason = str(exc)
    auth_end = time.perf_counter()

    t_sign_ms = (sign_end - sign_start) * 1000.0
    t_authorize_ms = (auth_end - auth_start) * 1000.0
    return t_sign_ms, t_authorize_ms, decision, reason


def run_performance(
    verifier_url: str,
    identity_vc: Dict[str, Any],
    capability_vc: Dict[str, Any],
    identity_accumulator_proof: Dict[str, Any] | None,
    capability_accumulator_proof: Dict[str, Any] | None,
    device_private_key: ed25519.Ed25519PrivateKey,
    action: str,
    resource: str,
    warmup: int,
    runs: int,
    sleep_ms: int,
) -> Iterable[MetricRow]:
    rows = []
    total_iterations = warmup + runs
    for idx in range(total_iterations):
        t_sign_ms, t_authorize_ms, decision, reason = authorize_once(
            verifier_url,
            identity_vc,
            capability_vc,
            identity_accumulator_proof,
            capability_accumulator_proof,
            device_private_key,
            action,
            resource,
        )

        if idx >= warmup:
            iteration = idx - warmup + 1
            rows.append(
                MetricRow(
                    ts_iso=now_iso(),
                    iteration=iteration,
                    t_sign_ms=t_sign_ms,
                    t_authorize_ms=t_authorize_ms,
                    decision=decision,
                    reason=reason,
                )
            )

        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000.0)
    return rows


def run_demo(
    settings: dict,
) -> Tuple[
    Dict[str, Any],
    Dict[str, Any],
    Dict[str, Any] | None,
    Dict[str, Any] | None,
    ed25519.Ed25519PrivateKey,
]:
    issuer_url = settings["issuer_url"]
    verifier_url = settings["verifier_url"]
    action = settings["action"]
    resource = settings["resource"]
    pause_enabled = settings["pause"]
    show_json = settings["show_json"]
    demo_revoke = settings["demo_revoke"]

    step = 1
    section(step, "Health checks")
    log("Checking issuer and verifier service health endpoints.")
    api_call_line("GET", "/health (issuer)")
    issuer_health = http_get_json(f"{issuer_url}/health")
    log("✓ Issuer healthy")
    api_call_line("GET", "/health (verifier)")
    verifier_health = http_get_json(f"{verifier_url}/health")
    log("✓ Verifier healthy")
    if show_json:
        maybe_print_json({"issuer": issuer_health, "verifier": verifier_health}, True)
    pause_if_enabled(pause_enabled)

    step += 1
    section(step, "Device keypair generation")
    log("Generating a device Ed25519 keypair locally.")
    log("The private key stays on the device.")
    device_private_key = ed25519.Ed25519PrivateKey.generate()
    device_public_key = device_private_key.public_key()
    device_public_key_b64 = b64encode(
        device_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    summary_kv("public key fingerprint", device_public_key_b64[:12])
    pause_if_enabled(pause_enabled)

    step += 1
    section(step, "DID creation")
    log("Creating and registering a DID document for the device public key.")
    api_call_line("POST", "/did/create")
    subject = http_post_json(
        f"{issuer_url}/did/create",
        {"device_public_key": device_public_key_b64},
    )
    subject_did = subject.get("did", "unknown")
    summary_kv("DID", subject_did)
    summary_kv("registered public key prefix", subject.get("public_key", "")[:12])
    maybe_print_json(subject, show_json)
    pause_if_enabled(pause_enabled)

    step += 1
    section(step, "DID resolution")
    log("Resolving the DID document from the issuer registry.")
    api_call_line("GET", "/did/resolve")
    did_resolution = http_get_json(f"{issuer_url}/did/resolve?did={subject_did}")
    did_document = did_resolution.get("did_document", {})
    summary_kv("found", str(did_resolution.get("found", False)))
    summary_kv("document id", did_document.get("id", "unknown"))
    maybe_print_json(did_resolution, show_json)
    pause_if_enabled(pause_enabled)

    step += 1
    section(step, "Identity VC issuance")
    log("Issuing an Identity VC that binds the DID to the device public key.")
    api_call_line("POST", "/vc/issue/identity")
    revocation_mode = settings["revocation_mode"]
    identity_accumulator_proof = None
    capability_accumulator_proof = None
    if revocation_mode in ("accumulator", "hybrid"):
        identity_response = http_post_json(
            f"{issuer_url}/vc/issue/identity-with-proof",
            {"subject_did": subject_did, "device_public_key": device_public_key_b64},
        )
        identity_vc = identity_response["vc"]
        identity_accumulator_proof = identity_response.get("accumulator_proof")
    else:
        identity_vc = http_post_json(
            f"{issuer_url}/vc/issue/identity",
            {"subject_did": subject_did, "device_public_key": device_public_key_b64},
        )
    identity_subject = identity_vc.get("credentialSubject", {})
    summary_kv("VC id", identity_vc.get("id", "unknown"))
    summary_kv("issuer", identity_vc.get("issuer", "unknown"))
    summary_kv("subject", identity_subject.get("id", "unknown"))
    summary_kv("bound public key prefix", identity_subject.get("devicePublicKey", "")[:12])
    summary_kv("expiry", identity_vc.get("expirationDate", "unknown"))
    maybe_print_json(identity_vc, show_json)
    pause_if_enabled(pause_enabled)

    step += 1
    section(step, "Capability VC issuance")
    log("Issuing a Capability VC with the requested action and resource.")
    api_call_line("POST", "/vc/issue/capability")
    if revocation_mode in ("accumulator", "hybrid"):
        capability_response = http_post_json(
            f"{issuer_url}/vc/issue/capability-with-proof",
            {"subject_did": subject_did, "action": action, "resource": resource},
        )
        capability_vc = capability_response["vc"]
        capability_accumulator_proof = capability_response.get("accumulator_proof")
        identity_accumulator_proof = http_post_json(
            f"{issuer_url}/revocation/accumulator/refresh-proof",
            {"credential_id": identity_vc["id"]},
        )
    else:
        capability_vc = http_post_json(
            f"{issuer_url}/vc/issue/capability",
            {"subject_did": subject_did, "action": action, "resource": resource},
        )
    capability_subject = capability_vc.get("credentialSubject", {})
    summary_kv("VC id", capability_vc.get("id", "unknown"))
    summary_kv("action", capability_subject.get("action", action))
    summary_kv("resource", capability_subject.get("resource", resource))
    summary_kv("expiry", capability_vc.get("expirationDate", "unknown"))
    maybe_print_json(capability_vc, show_json)
    pause_if_enabled(pause_enabled)

    step += 1
    section(step, "Proof of possession setup")
    log("Nonce = one-time challenge to prevent replay attacks.")
    log("The verifier will use devicePublicKey from the signed Identity VC.")
    pause_if_enabled(pause_enabled)

    def run_case(
        title: str, expected: str, requested_action: str, tamper_signature: bool = False
    ) -> None:
        nonlocal step
        step += 1
        section(step, title)
        api_call_line("POST", "/authorize")
        nonce = f"nonce_{uuid.uuid4()}"
        signature = device_private_key.sign(nonce.encode("utf-8"))
        signature_b64 = b64encode(signature)
        if tamper_signature:
            signature_b64 = tamper_b64(signature_b64)

        payload = {
            "identity_vc": identity_vc,
            "capability_vc": capability_vc,
            "nonce": nonce,
            "device_signature": signature_b64,
            "requested_action": requested_action,
            "requested_resource": resource,
        }
        if identity_accumulator_proof is not None:
            payload["identity_accumulator_proof"] = identity_accumulator_proof
        if capability_accumulator_proof is not None:
            payload["capability_accumulator_proof"] = capability_accumulator_proof
        response = http_post_json(f"{verifier_url}/authorize", payload)
        decision = response.get("decision", "unknown")
        reason = response.get("reason", "unknown")
        if decision != expected:
            log(f"✗ Expected {expected}, got {decision}")
            summary_kv("decision", decision)
            summary_kv("reason", reason)
            maybe_print_json(response, show_json)
            sys.exit(1)
        log(f"✓ Decision {decision}")
        summary_kv("decision", decision)
        summary_kv("reason", reason)
        maybe_print_json(response, show_json)
        pause_if_enabled(pause_enabled)

    run_case("Authorization case A (valid allow)", "allow", action)
    run_case("Authorization case B (wrong action)", "deny", "write")
    run_case("Authorization case C (tampered signature)", "deny", action, True)

    if demo_revoke:
        step += 1
        section(step, "Revocation case (capability revoked)")
        api_call_line("POST", "/vc/revoke")
        revoke_response = http_post_json(
            f"{issuer_url}/vc/revoke",
            {
                "credential_id": capability_vc["id"],
                "reason": "device agent demo revocation",
            },
        )
        summary_kv("revoked", str(revoke_response.get("revoked", False)))
        summary_kv("credential_id", revoke_response.get("credential_id", "unknown"))
        maybe_print_json(revoke_response, show_json)
        pause_if_enabled(pause_enabled)

        run_case("Authorization case D (revoked capability)", "deny", action)

    return (
        identity_vc,
        capability_vc,
        identity_accumulator_proof,
        capability_accumulator_proof,
        device_private_key,
    )


def main() -> None:
    settings = load_env()
    issuer_url = settings["issuer_url"]
    verifier_url = settings["verifier_url"]
    action = settings["action"]
    resource = settings["resource"]
    runs = settings["runs"]
    warmup = settings["warmup"]
    sleep_ms = settings["sleep_ms"]
    out_csv = settings["out_csv"]
    mode = settings["mode"]
    identity_vc_json = settings["identity_vc_json"]
    capability_vc_json = settings["capability_vc_json"]
    identity_accumulator_proof_json = settings["identity_accumulator_proof_json"]
    capability_accumulator_proof_json = settings["capability_accumulator_proof_json"]
    revocation_mode = settings["revocation_mode"]
    debug = settings["debug"]

    valid_modes = ("perf", "demo", "authorize_only", "full")
    if mode not in valid_modes:
        raise RuntimeError("MODE must be demo or perf")

    out_dir = os.path.dirname(out_csv) or "."
    os.makedirs(out_dir, exist_ok=True)

    if mode in ("perf", "full", "authorize_only"):
        log(f"Device agent starting, mode={mode}")

    identity_vc = None
    capability_vc = None
    identity_accumulator_proof = None
    capability_accumulator_proof = None
    device_private_key = None

    if mode == "demo":
        (
            identity_vc,
            capability_vc,
            identity_accumulator_proof,
            capability_accumulator_proof,
            device_private_key,
        ) = run_demo(settings)
    else:
        if mode in ("perf", "full"):
            wait_for_service(f"{issuer_url}/health")
        wait_for_service(f"{verifier_url}/health")

        device_private_key = ed25519.Ed25519PrivateKey.generate()
        device_public_key = device_private_key.public_key()
        device_public_key_b64 = b64encode(
            device_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )

        (
            identity_vc,
            capability_vc,
            identity_accumulator_proof,
            capability_accumulator_proof,
        ) = prepare_credentials(
            mode,
            issuer_url,
            action,
            resource,
            identity_vc_json,
            capability_vc_json,
            identity_accumulator_proof_json,
            capability_accumulator_proof_json,
            revocation_mode,
            device_public_key_b64,
            debug,
            out_dir,
        )

    if mode == "demo":
        log("Now running performance evaluation.")
        log(f"PERF_RUNS = {runs}")

    rows = run_performance(
        verifier_url,
        identity_vc,
        capability_vc,
        identity_accumulator_proof,
        capability_accumulator_proof,
        device_private_key,
        action,
        resource,
        warmup,
        runs,
        sleep_ms,
    )

    write_csv(out_csv, rows)
    summary = summarize(rows)

    if mode == "demo":
        summary_kv("runs", str(summary["runs"]))
        summary_kv("allow_count", str(summary["allow_count"]))
        summary_kv("deny_count", str(summary["deny_count"]))
        summary_kv("sign p50 (ms)", f"{summary['sign_p50_ms']:.3f}")
        summary_kv("sign p95 (ms)", f"{summary['sign_p95_ms']:.3f}")
        summary_kv("authorize p50 (ms)", f"{summary['authorize_p50_ms']:.3f}")
        summary_kv("authorize p95 (ms)", f"{summary['authorize_p95_ms']:.3f}")
        summary_kv("csv path", out_csv)
        log("Demo complete")
    else:
        log(f"runs: {summary['runs']}")
        log(f"allow_count: {summary['allow_count']}")
        log(f"deny_count: {summary['deny_count']}")
        log(f"sign_p50_ms: {summary['sign_p50_ms']:.3f}")
        log(f"sign_p95_ms: {summary['sign_p95_ms']:.3f}")
        log(f"authorize_p50_ms: {summary['authorize_p50_ms']:.3f}")
        log(f"authorize_p95_ms: {summary['authorize_p95_ms']:.3f}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(str(exc), flush=True)
        sys.exit(1)
