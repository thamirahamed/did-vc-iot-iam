import base64
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ISSUER_BASE_URL = "http://localhost:8000"
VERIFIER_BASE_URL = "http://localhost:8001"
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "30"))


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

    log("Requesting subject DID from issuer")
    subject = http_post_json(
        f"{ISSUER_BASE_URL}/did/create",
        {"device_public_key": device_public_key_b64},
    )
    subject_did = subject["did"]
    did_document = subject["did_document"]
    assert did_document["id"] == subject_did, f"unexpected DID document: {did_document}"
    assert did_document_key(did_document) == device_public_key_b64, (
        f"DID document key mismatch: {did_document}"
    )
    log(f"Subject DID: {subject_did}")

    log("Resolving subject DID")
    did_resolution = http_get_json(
        f"{ISSUER_BASE_URL}/did/resolve?{urlencode({'did': subject_did})}"
    )
    log(f"DID resolve response: {did_resolution}")
    assert did_resolution["found"] is True, f"expected DID found, got {did_resolution}"
    assert did_resolution["did_document"] == did_document, (
        f"resolved document mismatch: {did_resolution}"
    )

    log("Requesting identity VC from issuer")
    identity_vc, identity_accumulator_proof = issue_identity_with_proof(
        subject_did,
        device_public_key_b64,
    )
    identity_id = identity_vc.get("id", "unknown")
    log(f"Identity VC issued, id: {identity_id}")

    log("Identity VC issuance should fail for unregistered DID")
    unregistered_response = http_post_expect_error(
        f"{ISSUER_BASE_URL}/vc/issue/identity",
        {
            "subject_did": f"did:iot:{uuid.uuid4()}",
            "device_public_key": device_public_key_b64,
        },
    )
    log(f"Unregistered DID response: {unregistered_response}")
    assert unregistered_response["detail"] == "DID not registered", (
        f"unexpected error: {unregistered_response}"
    )

    log("Identity VC issuance should fail if key does not match DID document")
    wrong_private_key = ed25519.Ed25519PrivateKey.generate()
    wrong_public_key_b64 = b64encode(
        wrong_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    wrong_key_response = http_post_expect_error(
        f"{ISSUER_BASE_URL}/vc/issue/identity",
        {
            "subject_did": subject_did,
            "device_public_key": wrong_public_key_b64,
        },
    )
    log(f"Wrong DID key response: {wrong_key_response}")
    assert wrong_key_response["detail"] == "device public key does not match DID document", (
        f"unexpected error: {wrong_key_response}"
    )

    log("Requesting capability VC from issuer")
    capability_vc, capability_accumulator_proof = issue_capability_with_proof(
        subject_did,
        "read",
        "iot:device:example",
    )
    identity_accumulator_proof = refresh_accumulator_proof(identity_vc["id"])
    cap_id = capability_vc.get("id", "unknown")
    log(f"Capability VC issued, id: {cap_id}")

    payload = build_authorize_payload(
        identity_vc,
        capability_vc,
        device_private_key,
        "read",
        "iot:device:example",
        identity_accumulator_proof,
        capability_accumulator_proof,
    )

    log("Authorize test allow case")
    allow = http_post_json(f"{VERIFIER_BASE_URL}/authorize", payload)
    log(f"Allow response: {allow}")
    assert allow["decision"] == "allow", f"expected allow, got {allow}"
    log("Accumulator allow checked")

    if revocation_mode() in ("accumulator", "hybrid"):
        log("Authorize test deny missing accumulator proof case")
        payload_missing_proof = build_authorize_payload(
            identity_vc,
            capability_vc,
            device_private_key,
            "read",
            "iot:device:example",
        )
        deny_missing_proof = http_post_json(
            f"{VERIFIER_BASE_URL}/authorize", payload_missing_proof
        )
        log(f"Deny missing accumulator proof response: {deny_missing_proof}")
        assert deny_missing_proof == {
            "decision": "deny",
            "reason": "accumulator proof missing",
        }, f"expected accumulator proof missing deny, got {deny_missing_proof}"
        log("Accumulator missing proof deny checked")

        log("Authorize test deny tampered accumulator proof case")
        tampered_proof = json.loads(json.dumps(capability_accumulator_proof))
        tampered_proof["credential_hash"] = tamper_hash(tampered_proof["credential_hash"])
        payload_tampered_proof = build_authorize_payload(
            identity_vc,
            capability_vc,
            device_private_key,
            "read",
            "iot:device:example",
            identity_accumulator_proof,
            tampered_proof,
        )
        deny_tampered_proof = http_post_json(
            f"{VERIFIER_BASE_URL}/authorize", payload_tampered_proof
        )
        log(f"Deny tampered accumulator proof response: {deny_tampered_proof}")
        assert deny_tampered_proof == {
            "decision": "deny",
            "reason": "accumulator proof invalid",
        }, f"expected accumulator proof invalid deny, got {deny_tampered_proof}"
        log("Accumulator tampered proof deny checked")

    log("Authorize test deny missing DID registry entry case")
    original_document = remove_registry_did(subject_did)
    try:
        payload_missing_did = build_authorize_payload(
            identity_vc,
            capability_vc,
            device_private_key,
            "read",
            "iot:device:example",
            identity_accumulator_proof,
            capability_accumulator_proof,
        )
        deny_missing_did = http_post_json(
            f"{VERIFIER_BASE_URL}/authorize", payload_missing_did
        )
        log(f"Deny missing DID response: {deny_missing_did}")
        assert deny_missing_did == {
            "decision": "deny",
            "reason": "device DID not registered",
        }, f"expected DID not registered deny, got {deny_missing_did}"
    finally:
        if original_document:
            upsert_registry_did(subject_did, original_document)

    log("Authorize test deny DID document key mismatch case")
    mismatch_document = json.loads(json.dumps(did_document))
    mismatch_document["verificationMethod"][0]["publicKeyBase64Url"] = wrong_public_key_b64
    upsert_registry_did(subject_did, mismatch_document)
    try:
        payload_key_mismatch = build_authorize_payload(
            identity_vc,
            capability_vc,
            device_private_key,
            "read",
            "iot:device:example",
            identity_accumulator_proof,
            capability_accumulator_proof,
        )
        deny_key_mismatch = http_post_json(
            f"{VERIFIER_BASE_URL}/authorize", payload_key_mismatch
        )
        log(f"Deny DID key mismatch response: {deny_key_mismatch}")
        assert deny_key_mismatch == {
            "decision": "deny",
            "reason": "identity VC key does not match DID document",
        }, f"expected DID key mismatch deny, got {deny_key_mismatch}"
    finally:
        upsert_registry_did(subject_did, did_document)

    log("Revoking capability VC")
    revoke_capability = http_post_json(
        f"{ISSUER_BASE_URL}/vc/revoke",
        {
            "credential_id": capability_vc["id"],
            "reason": "integration test capability revocation",
        },
    )
    log(f"Capability revoke response: {revoke_capability}")
    assert revoke_capability["revoked"] is True, f"expected revoked, got {revoke_capability}"

    log("Checking revoked capability VC status endpoint")
    capability_status = http_get_json(
        f"{ISSUER_BASE_URL}/vc/status?{urlencode({'credential_id': capability_vc['id']})}"
    )
    log(f"Capability status response: {capability_status}")
    assert capability_status["revoked"] is True, (
        f"expected revoked status, got {capability_status}"
    )

    log("Checking revoked credential list endpoint")
    revoked_list = http_get_json(f"{ISSUER_BASE_URL}/vc/revoked")
    log(f"Revoked list response: {revoked_list}")
    revoked_ids = {
        record.get("credential_id") for record in revoked_list.get("revoked", [])
    }
    assert capability_vc["id"] in revoked_ids, (
        f"expected capability VC in revoked list, got {revoked_list}"
    )

    log("Checking persistent revocation registry file")
    revocation_registry = load_revocation_registry()
    assert capability_vc["id"] in revocation_registry, (
        f"expected capability VC in revocation registry file, got {revocation_registry}"
    )
    assert revocation_registry[capability_vc["id"]]["revoked"] is True, (
        f"expected persisted revoked=true, got {revocation_registry[capability_vc['id']]}"
    )
    log("Persistence file check passed")

    log("Authorize test deny revoked capability VC case")
    payload_revoked_capability = build_authorize_payload(
        identity_vc,
        capability_vc,
        device_private_key,
        "read",
        "iot:device:example",
        identity_accumulator_proof,
        capability_accumulator_proof,
    )
    deny_revoked_capability = http_post_json(
        f"{VERIFIER_BASE_URL}/authorize", payload_revoked_capability
    )
    log(f"Deny revoked capability response: {deny_revoked_capability}")
    assert_revoked_deny(
        deny_revoked_capability,
        "capability credential revoked",
        "capability revocation",
    )
    log("Accumulator revoked credential deny checked")

    log("Requesting replacement capability VC from issuer")
    capability_vc, capability_accumulator_proof = issue_capability_with_proof(
        subject_did,
        "read",
        "iot:device:example",
    )
    identity_accumulator_proof = refresh_accumulator_proof(identity_vc["id"])
    log(f"Replacement capability VC issued, id: {capability_vc.get('id', 'unknown')}")

    if revocation_mode() in ("accumulator", "hybrid"):
        refreshed_capability_proof = refresh_accumulator_proof(capability_vc["id"])
        assert refreshed_capability_proof["credential_hash"] == capability_accumulator_proof[
            "credential_hash"
        ], f"unexpected refreshed capability proof: {refreshed_capability_proof}"
        revoked_refresh_error = http_post_expect_error(
            f"{ISSUER_BASE_URL}/revocation/accumulator/refresh-proof",
            {"credential_id": cap_id},
        )
        assert "revoked" in revoked_refresh_error.get("detail", ""), (
            f"expected revoked proof refresh failure, got {revoked_refresh_error}"
        )
        log("Accumulator proof refresh checked")

    log("Authorize test allow replacement capability VC case")
    payload_replacement_capability = build_authorize_payload(
        identity_vc,
        capability_vc,
        device_private_key,
        "read",
        "iot:device:example",
        identity_accumulator_proof,
        capability_accumulator_proof,
    )
    allow_replacement = http_post_json(
        f"{VERIFIER_BASE_URL}/authorize", payload_replacement_capability
    )
    log(f"Replacement allow response: {allow_replacement}")
    assert allow_replacement["decision"] == "allow", (
        f"expected allow, got {allow_replacement}"
    )

    log("Revoking identity VC")
    revoke_identity = http_post_json(
        f"{ISSUER_BASE_URL}/vc/revoke",
        {
            "credential_id": identity_vc["id"],
            "reason": "integration test identity revocation",
        },
    )
    log(f"Identity revoke response: {revoke_identity}")
    assert revoke_identity["revoked"] is True, f"expected revoked, got {revoke_identity}"

    log("Authorize test deny revoked identity VC case")
    payload_revoked_identity = build_authorize_payload(
        identity_vc,
        capability_vc,
        device_private_key,
        "read",
        "iot:device:example",
        identity_accumulator_proof,
        capability_accumulator_proof,
    )
    deny_revoked_identity = http_post_json(
        f"{VERIFIER_BASE_URL}/authorize", payload_revoked_identity
    )
    log(f"Deny revoked identity response: {deny_revoked_identity}")
    assert_revoked_deny(
        deny_revoked_identity,
        "identity credential revoked",
        "identity revocation",
    )

    log("Issuing fresh identity and capability VCs for remaining deny cases")
    fresh_subject = http_post_json(
        f"{ISSUER_BASE_URL}/did/create",
        {"device_public_key": device_public_key_b64},
    )
    subject_did = fresh_subject["did"]
    identity_vc, identity_accumulator_proof = issue_identity_with_proof(
        subject_did,
        device_public_key_b64,
    )
    capability_vc, capability_accumulator_proof = issue_capability_with_proof(
        subject_did,
        "read",
        "iot:device:example",
    )
    identity_accumulator_proof = refresh_accumulator_proof(identity_vc["id"])
    payload = build_authorize_payload(
        identity_vc,
        capability_vc,
        device_private_key,
        "read",
        "iot:device:example",
        identity_accumulator_proof,
        capability_accumulator_proof,
    )

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
        identity_accumulator_proof,
        capability_accumulator_proof,
    )
    deny_tampered_identity = http_post_json(
        f"{VERIFIER_BASE_URL}/authorize", payload_tampered_identity
    )
    log(f"Deny tampered identity response: {deny_tampered_identity}")
    assert deny_tampered_identity["decision"] == "deny", (
        f"expected deny, got {deny_tampered_identity}"
    )

    log("Authorize test deny mismatched identity/capability subject DID case")
    other_subject = http_post_json(
        f"{ISSUER_BASE_URL}/did/create",
        {"device_public_key": device_public_key_b64},
    )
    other_identity_vc, other_identity_accumulator_proof = issue_identity_with_proof(
        other_subject["did"],
        device_public_key_b64,
    )
    payload_mismatch = build_authorize_payload(
        other_identity_vc,
        capability_vc,
        device_private_key,
        "read",
        "iot:device:example",
        other_identity_accumulator_proof,
        capability_accumulator_proof,
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
        identity_accumulator_proof,
        capability_accumulator_proof,
    )
    payload_bad_signature["device_signature"] = tamper_b64(
        payload_bad_signature["device_signature"]
    )
    deny_signature = http_post_json(
        f"{VERIFIER_BASE_URL}/authorize", payload_bad_signature
    )
    log(f"Deny bad signature response: {deny_signature}")
    assert deny_signature["decision"] == "deny", f"expected deny, got {deny_signature}"

    if os.getenv("TEST_ASYNC_AUDIT", "false").strip().lower() == "true":
        log("Flushing async audit queues")
        issuer_flush = http_post_json(f"{ISSUER_BASE_URL}/audit/flush", {})
        verifier_flush = http_post_json(f"{VERIFIER_BASE_URL}/audit/flush", {})
        log(f"Issuer audit flush: {issuer_flush}")
        log(f"Verifier audit flush: {verifier_flush}")
        assert issuer_flush["flushed"] is True, f"issuer audit flush failed: {issuer_flush}"
        assert verifier_flush["flushed"] is True, (
            f"verifier audit flush failed: {verifier_flush}"
        )

    log("Checking issuer audit events")
    issuer_audit = http_get_json(f"{ISSUER_BASE_URL}/audit/events?limit=100")
    assert_event_types(
        issuer_audit,
        {
            "DID_REGISTERED",
            "IDENTITY_VC_ISSUED",
            "CAPABILITY_VC_ISSUED",
            "VC_REVOKED",
        },
    )
    log("Audit issuer events checked")

    log("Checking verifier audit events")
    verifier_audit = http_get_json(f"{VERIFIER_BASE_URL}/audit/events?limit=100")
    assert_event_types(verifier_audit, {"AUTH_ALLOW", "AUTH_DENY"})
    log("Audit verifier events checked")

    log("All integration tests passed")


def http_get_json(url: str) -> Dict[str, Any]:
    request = Request(url, method="GET")
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
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
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8")
        raise RuntimeError(f"request failed: {exc.code} {body}") from exc
    return json.loads(body)


def http_post_expect_error(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8")
            raise RuntimeError(f"expected error response, got {response.status} {body}")
    except HTTPError as exc:
        body = exc.read().decode("utf-8")
    return json.loads(body)


def assert_event_types(audit_response: Dict[str, Any], expected: set[str]) -> None:
    events = audit_response.get("events", [])
    found = {event.get("event_type") for event in events if isinstance(event, dict)}
    missing = expected - found
    assert not missing, f"missing audit events {sorted(missing)}, got {events}"


def assert_revoked_deny(response: Dict[str, Any], status_reason: str, label: str) -> None:
    accumulator_reasons = {"accumulator proof stale", "accumulator proof invalid"}
    if test_revocation_mode() == "accumulator":
        expected_reasons = accumulator_reasons
    else:
        expected_reasons = accumulator_reasons | {status_reason}
    assert response.get("decision") == "deny" and response.get("reason") in expected_reasons, (
        f"expected {label} deny reason in {sorted(expected_reasons)}, got {response}"
    )


def issue_identity_with_proof(subject_did: str, device_public_key_b64: str) -> tuple[dict, dict | None]:
    if revocation_mode() == "status":
        vc = http_post_json(
            f"{ISSUER_BASE_URL}/vc/issue/identity",
            {
                "subject_did": subject_did,
                "device_public_key": device_public_key_b64,
            },
        )
        return vc, None
    response = http_post_json(
        f"{ISSUER_BASE_URL}/vc/issue/identity-with-proof",
        {
            "subject_did": subject_did,
            "device_public_key": device_public_key_b64,
        },
    )
    return response["vc"], response["accumulator_proof"]


def issue_capability_with_proof(
    subject_did: str, action: str, resource: str
) -> tuple[dict, dict | None]:
    if revocation_mode() == "status":
        vc = http_post_json(
            f"{ISSUER_BASE_URL}/vc/issue/capability",
            {
                "subject_did": subject_did,
                "action": action,
                "resource": resource,
            },
        )
        return vc, None
    response = http_post_json(
        f"{ISSUER_BASE_URL}/vc/issue/capability-with-proof",
        {
            "subject_did": subject_did,
            "action": action,
            "resource": resource,
        },
    )
    return response["vc"], response["accumulator_proof"]


def refresh_accumulator_proof(credential_id: str) -> dict | None:
    if revocation_mode() == "status":
        return None
    return http_post_json(
        f"{ISSUER_BASE_URL}/revocation/accumulator/refresh-proof",
        {"credential_id": credential_id},
    )


def revocation_mode() -> str:
    mode = test_revocation_mode()
    if mode not in ("status", "accumulator", "hybrid"):
        return "hybrid"
    return mode


def test_revocation_mode() -> str:
    return os.getenv(
        "TEST_REVOCATION_MODE",
        os.getenv("REVOCATION_MODE", "hybrid"),
    ).strip().lower()


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def did_document_key(did_document: Dict[str, Any]) -> str:
    methods = did_document.get("verificationMethod", [])
    if not methods:
        return ""
    return methods[0].get("publicKeyBase64Url", "")


def registry_path() -> Path:
    return Path("data/did_registry.json")


def revocation_registry_path() -> Path:
    return Path("data/revocation_registry.json")


def load_registry() -> Dict[str, Any]:
    path = registry_path()
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_registry(registry: Dict[str, Any]) -> None:
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(registry, handle, indent=2, sort_keys=True)
    temp_path.replace(path)


def remove_registry_did(did: str) -> Dict[str, Any]:
    registry = load_registry()
    original = registry.pop(did, None)
    save_registry(registry)
    return original


def upsert_registry_did(did: str, did_document: Dict[str, Any]) -> None:
    registry = load_registry()
    registry[did] = did_document
    save_registry(registry)


def load_revocation_registry() -> Dict[str, Any]:
    path = revocation_registry_path()
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_authorize_payload(
    identity_vc: Dict[str, Any],
    capability_vc: Dict[str, Any],
    device_private_key: ed25519.Ed25519PrivateKey,
    requested_action: str,
    requested_resource: str,
    identity_accumulator_proof: Dict[str, Any] | None = None,
    capability_accumulator_proof: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    nonce = f"nonce_{uuid.uuid4()}"
    device_signature = device_private_key.sign(nonce.encode("utf-8"))
    payload = {
        "identity_vc": identity_vc,
        "capability_vc": capability_vc,
        "nonce": nonce,
        "device_signature": b64encode(device_signature),
        "requested_action": requested_action,
        "requested_resource": requested_resource,
    }
    if identity_accumulator_proof is not None:
        payload["identity_accumulator_proof"] = identity_accumulator_proof
    if capability_accumulator_proof is not None:
        payload["capability_accumulator_proof"] = capability_accumulator_proof
    return payload


def tamper_b64(value: str) -> str:
    if not value:
        return value
    last = value[-1]
    return value[:-1] + ("A" if last != "A" else "B")


def tamper_hash(value: str) -> str:
    if not value:
        return value
    last = value[-1]
    return value[:-1] + ("0" if last != "0" else "1")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(str(exc), flush=True)
        sys.exit(1)
