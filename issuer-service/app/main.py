import os

from fastapi import FastAPI
from pydantic import BaseModel

from .did import create_did, generate_keypair, load_private_key_b64
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


class CapabilityIssueRequest(BaseModel):
    subject_did: str
    action: str
    resource: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/did/create")
def did_create() -> dict:
    did = create_did()
    public_key_b64, _private_key = generate_keypair()
    # Never return private keys in API responses.
    return {"did": did, "public_key": public_key_b64}


@app.post("/vc/issue/identity")
def issue_identity_vc_endpoint(payload: IdentityIssueRequest) -> dict:
    return issue_identity_vc(
        subject_did=payload.subject_did,
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
