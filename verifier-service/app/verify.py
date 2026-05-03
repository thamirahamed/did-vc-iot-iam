import base64
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from .did_resolver import resolve_did
from .models import AuthorizeRequest, AuthorizeResponse
from .revocation_client import check_revoked


def authorize_request(payload: AuthorizeRequest) -> AuthorizeResponse:
    issuer_key_b64 = os.getenv("ISSUER_PUBLIC_KEY_B64", "").strip()
    if not issuer_key_b64:
        return AuthorizeResponse(
            decision="deny",
            reason="issuer public key not configured",
        )

    identity_vc = payload.identity_vc
    capability_vc = payload.capability_vc

    ok, reason = _validate_identity_vc(identity_vc)
    if not ok:
        return AuthorizeResponse(decision="deny", reason=reason)

    ok, reason = _verify_issuer_signature(identity_vc, issuer_key_b64)
    if not ok:
        return AuthorizeResponse(decision="deny", reason=reason)

    ok, reason = _validate_capability_vc(capability_vc)
    if not ok:
        return AuthorizeResponse(decision="deny", reason=reason)

    ok, reason = _verify_issuer_signature(capability_vc, issuer_key_b64)
    if not ok:
        return AuthorizeResponse(decision="deny", reason=reason)

    for vc in (identity_vc, capability_vc):
        ok, reason = _check_expiration(vc)
        if not ok:
            return AuthorizeResponse(decision="deny", reason=reason)

    identity_subject = identity_vc["credentialSubject"]
    capability_subject = capability_vc["credentialSubject"]
    if identity_subject.get("id") != capability_subject.get("id"):
        return AuthorizeResponse(decision="deny", reason="subject DID mismatch")

    did_document, reason = resolve_did(identity_subject["id"])
    if not did_document:
        return AuthorizeResponse(decision="deny", reason=reason)

    did_document_key = _extract_did_document_key(did_document)
    if not did_document_key:
        return AuthorizeResponse(decision="deny", reason="device DID not registered")

    if identity_subject.get("devicePublicKey") != did_document_key:
        return AuthorizeResponse(
            decision="deny",
            reason="identity VC key does not match DID document",
        )

    ok, reason = _verify_device_signature(
        payload.nonce,
        payload.device_signature,
        did_document_key,
    )
    if not ok:
        return AuthorizeResponse(decision="deny", reason=reason)

    ok, reason = _check_revocation(identity_vc, "identity")
    if not ok:
        return AuthorizeResponse(decision="deny", reason=reason)

    ok, reason = _check_revocation(capability_vc, "capability")
    if not ok:
        return AuthorizeResponse(decision="deny", reason=reason)

    ok, reason = _enforce_capability(
        capability_vc,
        payload.requested_action,
        payload.requested_resource,
    )
    if not ok:
        return AuthorizeResponse(decision="deny", reason=reason)

    return AuthorizeResponse(decision="allow", reason="authorized")


def _validate_identity_vc(vc: Dict[str, Any]) -> Tuple[bool, str]:
    ok, reason = _validate_common_vc(vc, "IdentityCredential")
    if not ok:
        return False, reason

    subject = vc.get("credentialSubject", {})
    for field in ("id", "devicePublicKey"):
        if not subject.get(field):
            return False, f"missing credentialSubject.{field}"

    return True, ""


def _validate_capability_vc(vc: Dict[str, Any]) -> Tuple[bool, str]:
    ok, reason = _validate_common_vc(vc, "CapabilityCredential")
    if not ok:
        return False, reason

    subject = vc.get("credentialSubject", {})
    for field in ("id", "action", "resource"):
        if not subject.get(field):
            return False, f"missing credentialSubject.{field}"

    return True, ""


def _validate_common_vc(vc: Dict[str, Any], expected_type: str) -> Tuple[bool, str]:
    vc_type = vc.get("type")
    if isinstance(vc_type, list):
        type_set = set(vc_type)
    elif isinstance(vc_type, str):
        type_set = {vc_type}
    else:
        return False, "missing vc type"

    if "VerifiableCredential" not in type_set or expected_type not in type_set:
        return False, "invalid vc type"

    for field in ("id", "issuer", "issuanceDate", "expirationDate"):
        if not vc.get(field):
            return False, f"missing {field}"

    status = vc.get("credentialStatus")
    if not isinstance(status, dict):
        return False, "missing credentialStatus"
    if not status.get("id"):
        return False, "missing credentialStatus.id"
    if status.get("type") != "SimpleRevocationList2026":
        return False, "invalid credentialStatus.type"

    subject = vc.get("credentialSubject")
    if not isinstance(subject, dict):
        return False, "missing credentialSubject"

    proof = vc.get("proof")
    if not isinstance(proof, dict):
        return False, "missing proof"

    if not proof.get("signature"):
        return False, "missing proof signature"

    if not proof.get("verificationMethod"):
        return False, "missing proof verificationMethod"

    return True, ""


def _check_revocation(vc: Dict[str, Any], label: str) -> Tuple[bool, str]:
    credential_id = vc.get("id")
    if not credential_id:
        return False, "missing credential id"

    revoked, reason = check_revoked(credential_id)
    if reason:
        return False, reason
    if revoked:
        return False, f"{label} credential revoked"

    return True, ""


def _extract_did_document_key(did_document: Dict[str, Any]) -> str:
    verification_methods = did_document.get("verificationMethod", [])
    if not isinstance(verification_methods, list) or not verification_methods:
        return ""
    method = verification_methods[0]
    if not isinstance(method, dict):
        return ""
    return method.get("publicKeyBase64Url", "")


def _verify_issuer_signature(vc: Dict[str, Any], issuer_key_b64: str) -> Tuple[bool, str]:
    proof = vc.get("proof", {})
    signature_b64 = proof.get("signature")
    if not signature_b64:
        return False, "missing issuer signature"

    try:
        public_key_bytes = _b64decode(issuer_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except Exception:
        return False, "invalid issuer public key"

    unsigned_vc = dict(vc)
    unsigned_vc.pop("proof", None)

    signing_input = json.dumps(unsigned_vc, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )

    try:
        signature = _b64decode(signature_b64)
        public_key.verify(signature, signing_input)
    except Exception:
        return False, "issuer signature invalid"

    return True, ""


def _verify_device_signature(
    nonce: str, device_signature_b64: str, device_public_key_b64: str
) -> Tuple[bool, str]:
    if not nonce:
        return False, "missing nonce"

    if not device_signature_b64 or not device_public_key_b64:
        return False, "missing device signature or key"

    try:
        public_key_bytes = _b64decode(device_public_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        signature = _b64decode(device_signature_b64)
        public_key.verify(signature, nonce.encode("utf-8"))
    except Exception:
        return False, "device signature invalid"

    return True, ""


def _check_expiration(vc: Dict[str, Any]) -> Tuple[bool, str]:
    expiration = vc.get("expirationDate")
    if not expiration:
        return False, "missing expirationDate"

    try:
        if expiration.endswith("Z"):
            expiration_dt = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
        else:
            expiration_dt = datetime.fromisoformat(expiration)
            if expiration_dt.tzinfo is None:
                expiration_dt = expiration_dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return False, "invalid expirationDate"

    if expiration_dt <= datetime.now(timezone.utc):
        return False, "credential expired"

    return True, ""


def _enforce_capability(
    vc: Dict[str, Any], requested_action: str, requested_resource: str
) -> Tuple[bool, str]:
    subject = vc.get("credentialSubject", {})
    if requested_action != subject.get("action"):
        return False, "action not permitted"

    if requested_resource != subject.get("resource"):
        return False, "resource not permitted"

    return True, ""


def _b64decode(value: str) -> bytes:
    value = value.strip()
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
