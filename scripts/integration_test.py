import base64
import json
import sys
import uuid
from typing import Any, Dict
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ISSUER_BASE_URL = "http://localhost:8000"
VERIFIER_BASE_URL = "http://localhost:8001"


def log(msg: str) -> None:
    print(msg, flush=True)


def main() -> None:
    log("Integration test started")

    log("Health check issuer")
    issuer_health = http_get_json(f"{ISSUER_BASE_URL}/health")
    log(f"Issuer health: {issuer_health}")

    log("Health check verifier")
    verifier_health = http_get_json(f"{VERIFIER_BASE_URL}/health")
    log(f"Verifier health: {verifier_health}")

    log("Requesting subject DID from issuer")
    subject = http_post_json(f"{ISSUER_BASE_URL}/did/create", {})
    subject_did = subject["did"]
    log(f"Subject DID: {subject_did}")

    log("Generating device keypair")
    device_private_key = ed25519.Ed25519PrivateKey.generate()
    device_public_key = device_private_key.public_key()
    device_public_key_b64 = b64encode(
        device_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    log("Device public key generated")

    log("Requesting identity VC from issuer")
    identity_vc = http_post_json(
        f"{ISSUER_BASE_URL}/vc/issue/identity",
        {
            "subject_did": subject_did,
            "device_public_key": device_public_key_b64,
        },
    )
    identity_id = identity_vc.get("id", "unknown")
    log(f"Identity VC issued, id: {identity_id}")

    log("Requesting capability VC from issuer")
    capability_vc = http_post_json(
        f"{ISSUER_BASE_URL}/vc/issue/capability",
        {
            "subject_did": subject_did,
            "action": "read",
            "resource": "iot:device:example",
        },
    )
    cap_id = capability_vc.get("id", "unknown")
    log(f"Capability VC issued, id: {cap_id}")

    payload = build_authorize_payload(
        identity_vc,
        capability_vc,
        device_private_key,
        "read",
        "iot:device:example",
    )

    log("Authorize test allow case")
    allow = http_post_json(f"{VERIFIER_BASE_URL}/authorize", payload)
    log(f"Allow response: {allow}")
    assert allow["decision"] == "allow", f"expected allow, got {allow}"

    log("Authorize test deny wrong action case")
    payload_wrong_action = dict(payload)
    payload_wrong_action["requested_action"] = "write"
    deny_action = http_post_json(f"{VERIFIER_BASE_URL}/authorize", payload_wrong_action)
    log(f"Deny wrong action response: {deny_action}")
    assert deny_action["decision"] == "deny", f"expected deny, got {deny_action}"

    log("Authorize test deny tampered identity VC devicePublicKey case")
    tampered_identity_vc = json.loads(json.dumps(identity_vc))
    tampered_identity_vc["credentialSubject"]["devicePublicKey"] = tamper_b64(
        device_public_key_b64
    )
    payload_tampered_identity = build_authorize_payload(
        tampered_identity_vc,
        capability_vc,
        device_private_key,
        "read",
        "iot:device:example",
    )
    deny_tampered_identity = http_post_json(
        f"{VERIFIER_BASE_URL}/authorize", payload_tampered_identity
    )
    log(f"Deny tampered identity response: {deny_tampered_identity}")
    assert deny_tampered_identity["decision"] == "deny", (
        f"expected deny, got {deny_tampered_identity}"
    )

    log("Authorize test deny mismatched identity/capability subject DID case")
    other_subject = http_post_json(f"{ISSUER_BASE_URL}/did/create", {})
    other_identity_vc = http_post_json(
        f"{ISSUER_BASE_URL}/vc/issue/identity",
        {
            "subject_did": other_subject["did"],
            "device_public_key": device_public_key_b64,
        },
    )
    payload_mismatch = build_authorize_payload(
        other_identity_vc,
        capability_vc,
        device_private_key,
        "read",
        "iot:device:example",
    )
    deny_mismatch = http_post_json(f"{VERIFIER_BASE_URL}/authorize", payload_mismatch)
    log(f"Deny subject mismatch response: {deny_mismatch}")
    assert deny_mismatch["decision"] == "deny", f"expected deny, got {deny_mismatch}"

    log("Authorize test deny bad signature case")
    payload_bad_signature = build_authorize_payload(
        identity_vc,
        capability_vc,
        device_private_key,
        "read",
        "iot:device:example",
    )
    payload_bad_signature["device_signature"] = tamper_b64(
        payload_bad_signature["device_signature"]
    )
    deny_signature = http_post_json(
        f"{VERIFIER_BASE_URL}/authorize", payload_bad_signature
    )
    log(f"Deny bad signature response: {deny_signature}")
    assert deny_signature["decision"] == "deny", f"expected deny, got {deny_signature}"

    log("All integration tests passed")


def http_get_json(url: str) -> Dict[str, Any]:
    request = Request(url, method="GET")
    try:
        with urlopen(request, timeout=10) as response:
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
        with urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8")
        raise RuntimeError(f"request failed: {exc.code} {body}") from exc
    return json.loads(body)


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def build_authorize_payload(
    identity_vc: Dict[str, Any],
    capability_vc: Dict[str, Any],
    device_private_key: ed25519.Ed25519PrivateKey,
    requested_action: str,
    requested_resource: str,
) -> Dict[str, Any]:
    nonce = f"nonce_{uuid.uuid4()}"
    device_signature = device_private_key.sign(nonce.encode("utf-8"))
    return {
        "identity_vc": identity_vc,
        "capability_vc": capability_vc,
        "nonce": nonce,
        "device_signature": b64encode(device_signature),
        "requested_action": requested_action,
        "requested_resource": requested_resource,
    }


def tamper_b64(value: str) -> str:
    if not value:
        return value
    last = value[-1]
    return value[:-1] + ("A" if last != "A" else "B")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(str(exc), flush=True)
        sys.exit(1)
