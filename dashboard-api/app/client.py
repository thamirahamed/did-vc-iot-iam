import base64
import json
import os
import uuid
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


ISSUER_URL = os.getenv("ISSUER_URL", "http://localhost:8000").rstrip("/")
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://localhost:8001").rstrip("/")
FABRIC_ADAPTER_URL = os.getenv("FABRIC_ADAPTER_URL", "http://localhost:8010").rstrip("/")
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "30"))


def http_get_json(url: str) -> dict[str, Any]:
    return _http_json(Request(url, method="GET"))


def http_post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return _http_json(
        Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
    )


def http_post_json_allow_missing(
    url: str, payload: dict[str, Any]
) -> dict[str, Any] | None:
    try:
        return http_post_json(url, payload)
    except RuntimeError as exc:
        text = str(exc)
        if "request failed: 404" in text or "request failed: 405" in text:
            return None
        raise


def optional_get(url: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        return http_get_json(url), None
    except Exception as exc:
        return None, str(exc)


def generate_device_keypair() -> tuple[str, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_key_b64 = b64encode(
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key_b64 = b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    return private_key_b64, public_key_b64


def sign_authorization_payload(
    private_key_b64: str,
    identity_vc: dict[str, Any],
    capability_vc: dict[str, Any],
    action: str,
    resource: str,
    identity_proof: dict[str, Any] | None,
    capability_proof: dict[str, Any] | None,
    tamper_signature: bool,
) -> dict[str, Any]:
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(b64decode(private_key_b64))
    nonce = f"nonce_{uuid.uuid4()}"
    signature = private_key.sign(nonce.encode("utf-8"))
    signature_b64 = b64encode(signature)
    if tamper_signature:
        signature_b64 = tamper_b64(signature_b64)
    payload: dict[str, Any] = {
        "identity_vc": identity_vc,
        "capability_vc": capability_vc,
        "nonce": nonce,
        "device_signature": signature_b64,
        "requested_action": action,
        "requested_resource": resource,
    }
    if identity_proof is not None:
        payload["identity_accumulator_proof"] = identity_proof
    if capability_proof is not None:
        payload["capability_accumulator_proof"] = capability_proof
    return payload


def create_did(public_key_b64: str) -> dict[str, Any]:
    return http_post_json(f"{ISSUER_URL}/did/create", {"device_public_key": public_key_b64})


def issue_identity(subject_did: str, public_key_b64: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    payload = {"subject_did": subject_did, "device_public_key": public_key_b64}
    response = http_post_json_allow_missing(
        f"{ISSUER_URL}/vc/issue/identity-with-proof",
        payload,
    )
    if response is not None:
        return response["vc"], response.get("accumulator_proof")
    return http_post_json(f"{ISSUER_URL}/vc/issue/identity", payload), None


def issue_identity_with_proof(subject_did: str, public_key_b64: str) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = {"subject_did": subject_did, "device_public_key": public_key_b64}
    response = http_post_json(f"{ISSUER_URL}/vc/issue/identity-with-proof", payload)
    return response["vc"], response["accumulator_proof"]


def issue_capability(subject_did: str, action: str, resource: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    payload = {"subject_did": subject_did, "action": action, "resource": resource}
    response = http_post_json_allow_missing(
        f"{ISSUER_URL}/vc/issue/capability-with-proof",
        payload,
    )
    if response is not None:
        return response["vc"], response.get("accumulator_proof")
    return http_post_json(f"{ISSUER_URL}/vc/issue/capability", payload), None


def issue_capability_with_proof(subject_did: str, action: str, resource: str) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = {"subject_did": subject_did, "action": action, "resource": resource}
    response = http_post_json(f"{ISSUER_URL}/vc/issue/capability-with-proof", payload)
    return response["vc"], response["accumulator_proof"]


def refresh_proof(credential_id: str) -> dict[str, Any] | None:
    response = http_post_json_allow_missing(
        f"{ISSUER_URL}/revocation/accumulator/refresh-proof",
        {"credential_id": credential_id},
    )
    return response


def authorize(payload: dict[str, Any]) -> dict[str, Any]:
    return http_post_json(f"{VERIFIER_URL}/authorize", payload)


def revoke(credential_id: str, reason: str) -> dict[str, Any]:
    return http_post_json(
        f"{ISSUER_URL}/vc/revoke",
        {"credential_id": credential_id, "reason": reason},
    )


def accumulator_state() -> dict[str, Any]:
    return http_get_json(f"{ISSUER_URL}/revocation/accumulator/state")


def issuer_audit_events(limit: int) -> dict[str, Any]:
    return http_get_json(f"{ISSUER_URL}/audit/events?{urlencode({'limit': limit})}")


def verifier_audit_events(limit: int) -> dict[str, Any]:
    return http_get_json(f"{VERIFIER_URL}/audit/events?{urlencode({'limit': limit})}")


def issuer_health() -> dict[str, Any]:
    return http_get_json(f"{ISSUER_URL}/health")


def verifier_health() -> dict[str, Any]:
    return http_get_json(f"{VERIFIER_URL}/health")


def fabric_adapter_health() -> dict[str, Any]:
    return http_get_json(f"{FABRIC_ADAPTER_URL}/health")


def _http_json(request: Request) -> dict[str, Any]:
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            raw = response.read()
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"request failed: {exc.code} {body}") from exc
    except (ConnectionError, TimeoutError, URLError) as exc:
        raise RuntimeError(f"request failed: {request.full_url}: {exc}") from exc
    return json.loads(raw.decode("utf-8"))


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def tamper_b64(value: str) -> str:
    if not value:
        return value
    last = value[-1]
    return value[:-1] + ("A" if last != "A" else "B")
