import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

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
    return {
        "did": did,
        "public_key": payload.device_public_key,
        "did_document": did_document,
    }


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

    return issue_identity_vc(
        subject_did=payload.subject_did,
        device_public_key=payload.device_public_key,
        issuer_did=ISSUER_DID,
        issuer_private_key=ISSUER_PRIVATE_KEY,
    )


@app.post("/vc/issue/capability")
def issue_capability_vc_endpoint(payload: CapabilityIssueRequest) -> dict:
    return issue_capability_vc(
        subject_did=payload.subject_did,
        action=payload.action,
        resource=payload.resource,
        issuer_did=ISSUER_DID,
        issuer_private_key=ISSUER_PRIVATE_KEY,
    )


@app.post("/vc/revoke")
def revoke_vc_endpoint(payload: RevokeCredentialRequest) -> dict:
    return revoke_credential(payload.credential_id, payload.reason)


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
