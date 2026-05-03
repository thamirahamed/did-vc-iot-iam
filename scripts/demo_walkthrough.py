import base64
import json
import os
import sys
import uuid
from typing import Any, Dict, Iterable, Tuple
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ISSUER_BASE_URL = "http://localhost:8000"
VERIFIER_BASE_URL = "http://localhost:8001"

SHOW_JSON = os.getenv("SHOW_JSON", "0") == "1"
PAUSE = os.getenv("PAUSE", "1") == "1"

def log(msg: str = "") -> None:
    print(msg, flush=True)


def print_section(title: str) -> None:
    log()
    log("==================================================")
    log(title)
    log("==================================================")


def print_step(step_num: int, text: str) -> None:
    log()
    log(f"[STEP {step_num}] {text}")


def pause() -> None:
    if PAUSE:
        if sys.stdin and sys.stdin.isatty():
            input("Press Enter to continue...")


def print_summary_block(title: str, rows: Iterable[Tuple[str, str]]) -> None:
    log(title)
    for key, value in rows:
        log(f"  - {key}: {value}")


def http_get_json(url: str) -> Dict[str, Any]:
    request = Request(url, method="GET")
    try:
        with urlopen(request, timeout=15) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8")
        raise RuntimeError(f"request failed: {exc.code} {body}") from exc
    return json.loads(body)


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


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def tamper_b64(value: str) -> str:
    if not value:
        return value
    last = value[-1]
    return value[:-1] + ("A" if last != "A" else "B")


def sign_nonce(private_key: ed25519.Ed25519PrivateKey, nonce: str) -> str:
    signature = private_key.sign(nonce.encode("utf-8"))
    return b64encode(signature)


def main() -> None:
    step = 1

    print_section("Phase 0: Introduction and Health Checks")
    log("This demo explains and showcases the full IAM flow step by step.")
    log("Issuer: http://localhost:8000 | Verifier: http://localhost:8001")
    log("This is an explanation/demo script, not a benchmarking tool.")
    log()

    print_step(step, "Health checks for issuer and verifier services.")
    step += 1
    log("-> GET /health (issuer)")
    issuer_health = http_get_json(f"{ISSUER_BASE_URL}/health")
    log("OK Issuer healthy")
    log("-> GET /health (verifier)")
    verifier_health = http_get_json(f"{VERIFIER_BASE_URL}/health")
    log("OK Verifier healthy")
    if SHOW_JSON:
        log()
        log("--- Full API response ---")
        log(json.dumps({"issuer": issuer_health, "verifier": verifier_health}, indent=2))
        log("-------------------------")
        log()
    pause()

    print_section("Phase 1: Device Onboarding")
    print_step(step, "Generate a local Ed25519 keypair for the device.")
    step += 1
    log("The private key never leaves the device.")
    device_private_key = ed25519.Ed25519PrivateKey.generate()
    device_public_key = device_private_key.public_key()
    device_public_key_b64 = b64encode(
        device_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    log(f"Public key fingerprint: {device_public_key_b64[:12]}")
    pause()

    print_step(step, "Send the public key to issuer and create a new DID.")
    step += 1
    log("-> POST /did/create (issuer)")
    subject = http_post_json(
        f"{ISSUER_BASE_URL}/did/create",
        {"device_public_key": device_public_key_b64},
    )
    subject_did = subject.get("did", "unknown")
    did_document = subject.get("did_document", {})
    print_summary_block(
        "DID created:",
        [
            ("DID", subject_did),
            ("DID document id", did_document.get("id", "unknown")),
            ("Registered public key prefix", subject.get("public_key", "")[:12]),
        ],
    )
    if SHOW_JSON:
        log()
        log("--- Full API response ---")
        log(json.dumps(subject, indent=2))
        log("-------------------------")
        log()
    pause()

    print_step(step, "Resolve the stored DID document.")
    step += 1
    log("-> GET /did/resolve (issuer)")
    did_resolution = http_get_json(f"{ISSUER_BASE_URL}/did/resolve?did={subject_did}")
    resolved_document = did_resolution.get("did_document", {})
    resolved_methods = resolved_document.get("verificationMethod", [{}])
    resolved_key = resolved_methods[0].get("publicKeyBase64Url", "")
    print_summary_block(
        "DID resolved:",
        [
            ("Found", str(did_resolution.get("found", False))),
            ("DID document id", resolved_document.get("id", "unknown")),
            ("Resolved public key prefix", resolved_key[:12]),
        ],
    )
    if SHOW_JSON:
        log()
        log("--- Full API response ---")
        log(json.dumps(did_resolution, indent=2))
        log("-------------------------")
        log()
    pause()

    print_section("Phase 2: Identity VC Issuance")
    print_step(step, "Issue an Identity VC binding the DID to the device public key.")
    step += 1
    log("-> POST /vc/issue/identity (issuer)")
    identity_vc = http_post_json(
        f"{ISSUER_BASE_URL}/vc/issue/identity",
        {"subject_did": subject_did, "device_public_key": device_public_key_b64},
    )
    identity_subject = identity_vc.get("credentialSubject", {})
    identity_issuance = identity_vc.get("issuanceDate", "unknown")
    identity_expiration = identity_vc.get("expirationDate", "unknown")
    print_summary_block(
        "Identity VC issued:",
        [
            ("VC ID", identity_vc.get("id", "unknown")),
            ("Issuer DID", identity_vc.get("issuer", "unknown")),
            ("Subject DID", identity_subject.get("id", "unknown")),
            ("Bound public key prefix", identity_subject.get("devicePublicKey", "")[:12]),
            ("Issuance date", identity_issuance),
            ("Expiration date", identity_expiration),
        ],
    )
    if SHOW_JSON:
        log()
        log("--- Full API response ---")
        log(json.dumps(identity_vc, indent=2))
        log("-------------------------")
        log()
    pause()

    print_section("Phase 3: Capability VC Issuance")
    print_step(step, "Issue a Capability VC granting read access to the device resource.")
    step += 1
    log("-> POST /vc/issue/capability (issuer)")
    capability_vc = http_post_json(
        f"{ISSUER_BASE_URL}/vc/issue/capability",
        {
            "subject_did": subject_did,
            "action": "read",
            "resource": "iot:device:example",
        },
    )
    capability_subject = capability_vc.get("credentialSubject", {})
    capability_issuance = capability_vc.get("issuanceDate", "unknown")
    capability_expiration = capability_vc.get("expirationDate", "unknown")
    print_summary_block(
        "Capability VC issued:",
        [
            ("VC ID", capability_vc.get("id", "unknown")),
            ("Action", capability_subject.get("action", "read")),
            ("Resource", capability_subject.get("resource", "iot:device:example")),
            ("Issuance date", capability_issuance),
            ("Expiration date", capability_expiration),
        ],
    )
    if SHOW_JSON:
        log()
        log("--- Full API response ---")
        log(json.dumps(capability_vc, indent=2))
        log("-------------------------")
        log()
    pause()

    print_section("Phase 4: Proof of Possession Setup")
    print_step(step, "Device signs a nonce for proof of possession.")
    step += 1
    log("A nonce is a one-time challenge used to prevent replay attacks.")
    log("The verifier checks the signature against devicePublicKey inside the signed Identity VC.")
    pause()

    print_section("Phase 5: Authorization Decision Demo")

    print_step(step, "Case A: Valid request should ALLOW.")
    step += 1
    log("  Requested by device:")
    log("    Action: read")
    log("    Resource: iot:device:example")
    log()
    log("  Capability credential allows:")
    log(f"    Action: {capability_subject.get('action', 'read')}")
    log(f"    Resource: {capability_subject.get('resource', 'iot:device:example')}")
    log()
    log("  Verifier checks Identity VC plus Capability VC before allowing.")
    log("  Verifier resolves the DID and compares the DID document key with the Identity VC key.")
    log("-> POST /authorize (verifier)")
    nonce = f"nonce_{uuid.uuid4()}"
    device_signature_b64 = sign_nonce(device_private_key, nonce)
    allow_payload: Dict[str, Any] = {
        "identity_vc": identity_vc,
        "capability_vc": capability_vc,
        "nonce": nonce,
        "device_signature": device_signature_b64,
        "requested_action": "read",
        "requested_resource": "iot:device:example",
    }
    allow_response = http_post_json(f"{VERIFIER_BASE_URL}/authorize", allow_payload)
    decision = allow_response.get("decision", "unknown")
    log()
    print_summary_block(
        "  Authorization result:",
        [
            ("Decision", decision),
            ("Reason", allow_response.get("reason", "n/a")),
        ],
    )
    if SHOW_JSON:
        log()
        log("--- Full API response ---")
        log(json.dumps(allow_response, indent=2))
        log("-------------------------")
        log()
    pause()

    print_step(step, "Case B: Wrong action should DENY.")
    step += 1
    log("  Requested by device:")
    log("    Action: write")
    log("    Resource: iot:device:example")
    log()
    log("  Capability credential allows:")
    log(f"    Action: {capability_subject.get('action', 'read')}")
    log(f"    Resource: {capability_subject.get('resource', 'iot:device:example')}")
    log()
    log("-> POST /authorize (verifier)")
    nonce = f"nonce_{uuid.uuid4()}"
    device_signature_b64 = sign_nonce(device_private_key, nonce)
    deny_action_payload = dict(allow_payload)
    deny_action_payload.update(
        {
            "nonce": nonce,
            "device_signature": device_signature_b64,
            "requested_action": "write",
        }
    )
    deny_action_response = http_post_json(
        f"{VERIFIER_BASE_URL}/authorize", deny_action_payload
    )
    decision = deny_action_response.get("decision", "unknown")
    log()
    print_summary_block(
        "  Authorization result:",
        [
            ("Decision", decision),
            ("Reason", deny_action_response.get("reason", "n/a")),
        ],
    )
    if SHOW_JSON:
        log()
        log("--- Full API response ---")
        log(json.dumps(deny_action_response, indent=2))
        log("-------------------------")
        log()
    pause()

    print_step(step, "Case C: Invalid signature should DENY.")
    step += 1
    log("  Requested by device:")
    log("    Action: read")
    log("    Resource: iot:device:example")
    log()
    log("  Capability credential allows:")
    log(f"    Action: {capability_subject.get('action', 'read')}")
    log(f"    Resource: {capability_subject.get('resource', 'iot:device:example')}")
    log()
    log("-> POST /authorize (verifier)")
    nonce = f"nonce_{uuid.uuid4()}"
    device_signature_b64 = sign_nonce(device_private_key, nonce)
    deny_signature_payload = dict(allow_payload)
    deny_signature_payload.update(
        {
            "nonce": nonce,
            "device_signature": tamper_b64(device_signature_b64),
        }
    )
    deny_signature_response = http_post_json(
        f"{VERIFIER_BASE_URL}/authorize", deny_signature_payload
    )
    decision = deny_signature_response.get("decision", "unknown")
    log()
    print_summary_block(
        "  Authorization result:",
        [
            ("Decision", decision),
            ("Reason", deny_signature_response.get("reason", "n/a")),
        ],
    )
    if SHOW_JSON:
        log()
        log("--- Full API response ---")
        log(json.dumps(deny_signature_response, indent=2))
        log("-------------------------")
        log()
    pause()

    print_section("Phase 6: Revocation")
    print_step(step, "Revoke the Capability VC at the issuer.")
    step += 1
    log("This MVP uses a persistent local revocation registry, not an EVOKE accumulator yet.")
    log("The issuer stores revoked credential IDs in data/revocation_registry.json.")
    log("-> POST /vc/revoke (issuer)")
    revoke_response = http_post_json(
        f"{ISSUER_BASE_URL}/vc/revoke",
        {
            "credential_id": capability_vc["id"],
            "reason": "demo capability revocation",
        },
    )
    print_summary_block(
        "Capability VC revoked:",
        [
            ("Credential ID", revoke_response.get("credential_id", "unknown")),
            ("Revoked", str(revoke_response.get("revoked", False))),
            ("Reason", revoke_response.get("reason", "n/a")),
        ],
    )
    if SHOW_JSON:
        log()
        log("--- Full API response ---")
        log(json.dumps(revoke_response, indent=2))
        log("-------------------------")
        log()
    pause()

    print_step(step, "Try the same valid request again.")
    step += 1
    log("The verifier checks the issuer status endpoint before allowing access.")
    log("Restarting the issuer does not clear records stored in the local registry file.")
    log("-> POST /authorize (verifier)")
    nonce = f"nonce_{uuid.uuid4()}"
    revoked_signature_b64 = sign_nonce(device_private_key, nonce)
    revoked_payload = {
        "identity_vc": identity_vc,
        "capability_vc": capability_vc,
        "nonce": nonce,
        "device_signature": revoked_signature_b64,
        "requested_action": "read",
        "requested_resource": "iot:device:example",
    }
    revoked_response = http_post_json(f"{VERIFIER_BASE_URL}/authorize", revoked_payload)
    print_summary_block(
        "  Authorization result:",
        [
            ("Decision", revoked_response.get("decision", "unknown")),
            ("Reason", revoked_response.get("reason", "n/a")),
        ],
    )
    if revoked_response.get("decision") != "deny":
        log("Expected deny after revocation.")
        sys.exit(1)
    if SHOW_JSON:
        log()
        log("--- Full API response ---")
        log(json.dumps(revoked_response, indent=2))
        log("-------------------------")
        log()
    pause()

    log()
    log("Demo complete")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(str(exc), flush=True)
        sys.exit(1)
