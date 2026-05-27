import hashlib
import json
import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import fabric_client
from .did import create_did, generate_keypair, load_private_key_b64
from .did_registry import list_dids, register_did, resolve_did
from .revocation import get_revocation_record, list_revoked, revoke_credential
from .vc import issue_capability_vc, issue_identity_vc

app = FastAPI()

# Generate issuer identity once at startup and keep keys in memory.
ISSUER_DID = create_did()
_private_key_b64 = os.getenv("ISSUER_PRIVATE_KEY_B64", "").strip()
if _private_key_b64:
    _ISSUER_PUBLIC_KEY_B64, ISSUER_PRIVATE_KEY = load_private_key_b64(_private_key_b64)
else:
    _ISSUER_PUBLIC_KEY_B64, ISSUER_PRIVATE_KEY = generate_keypair()


class IdentityIssueRequest(BaseModel):
    subject_did: str
    device_public_key: str


class DidCreateRequest(BaseModel):
    device_public_key: str


class CapabilityIssueRequest(BaseModel):
    subject_did: str
    action: str
    resource: str


class RevokeCredentialRequest(BaseModel):
    credential_id: str
    reason: Optional[str] = None


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/did/create")
def did_create(payload: DidCreateRequest) -> dict:
    did = create_did()
    did_document = register_did(did, payload.device_public_key)
    response = {
        "did": did,
        "public_key": payload.device_public_key,
        "did_document": did_document,
    }
    fabric_result = fabric_client.register_did(
        did,
        payload.device_public_key,
        _stable_hash(did_document),
        did_document.get("created", ""),
    )
    _handle_fabric_result(fabric_result)
    _append_fabric_warning(response, fabric_result)
    return response


@app.get("/did/resolve")
def did_resolve(did: str) -> dict:
    did_document = resolve_did(did)
    if not did_document:
        return {"found": False}
    return {"found": True, "did_document": did_document}


@app.get("/did/list")
def did_list() -> dict:
    return {"dids": list_dids()}


@app.post("/vc/issue/identity")
def issue_identity_vc_endpoint(payload: IdentityIssueRequest) -> dict:
    did_document = resolve_did(payload.subject_did)
    if not did_document:
        raise HTTPException(status_code=400, detail="DID not registered")

    registered_key = _extract_did_document_key(did_document)
    if registered_key != payload.device_public_key:
        raise HTTPException(
            status_code=400,
            detail="device public key does not match DID document",
        )

    vc = issue_identity_vc(
        subject_did=payload.subject_did,
        device_public_key=payload.device_public_key,
        issuer_did=ISSUER_DID,
        issuer_private_key=ISSUER_PRIVATE_KEY,
    )
    fabric_result = fabric_client.register_credential_status(vc)
    _handle_fabric_result(fabric_result)
    _append_fabric_warning(vc, fabric_result)
    return vc


@app.post("/vc/issue/capability")
def issue_capability_vc_endpoint(payload: CapabilityIssueRequest) -> dict:
    vc = issue_capability_vc(
        subject_did=payload.subject_did,
        action=payload.action,
        resource=payload.resource,
        issuer_did=ISSUER_DID,
        issuer_private_key=ISSUER_PRIVATE_KEY,
    )
    fabric_result = fabric_client.register_credential_status(vc)
    _handle_fabric_result(fabric_result)
    _append_fabric_warning(vc, fabric_result)
    return vc


@app.post("/vc/revoke")
def revoke_vc_endpoint(payload: RevokeCredentialRequest) -> dict:
    record = revoke_credential(payload.credential_id, payload.reason)
    fabric_result = fabric_client.revoke_credential_on_ledger(
        payload.credential_id,
        payload.reason,
        record.get("revoked_at", ""),
    )
    _handle_fabric_result(fabric_result)
    _append_fabric_warning(record, fabric_result)
    return record


@app.get("/vc/status")
def vc_status(credential_id: str) -> dict:
    return get_revocation_record(credential_id)


@app.get("/vc/revoked")
def revoked_vcs() -> dict:
    return {"revoked": list_revoked()}


def _extract_did_document_key(did_document: dict) -> Optional[str]:
    verification_methods = did_document.get("verificationMethod", [])
    if not verification_methods:
        return None
    return verification_methods[0].get("publicKeyBase64Url")


def _stable_hash(value: dict) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _handle_fabric_result(result: dict) -> None:
    if not result.get("enabled"):
        return
    if result.get("ok"):
        return
    if fabric_client.fabric_fail_closed():
        error = result.get("error") or "Fabric operation failed"
        raise HTTPException(status_code=503, detail=error)


def _append_fabric_warning(response: dict, result: dict) -> None:
    if not result.get("enabled") or result.get("ok", True):
        return
    response["fabric_warning"] = result.get("error") or "Fabric operation failed"
