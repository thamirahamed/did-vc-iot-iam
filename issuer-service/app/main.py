import hashlib
import json
import os
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from . import accumulator
from . import audit
from . import fabric_client
from .did import create_did, generate_keypair, load_private_key_b64
from .did_registry import list_dids, register_did, resolve_did
from .revocation import get_revocation_record, list_revoked, revoke_credential
from .vc import issue_capability_vc, issue_identity_vc

app = FastAPI()
_AUDIT_DISABLED_WARNING_PRINTED = False

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


class RefreshProofRequest(BaseModel):
    credential_id: str


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
    _record_audit_event(
        response,
        event_type="DID_REGISTERED",
        subject_did=did,
        metadata={"public_key_prefix": payload.device_public_key[:16]},
    )
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
    vc = _issue_identity_vc(payload)
    _post_issue_identity(vc)
    return vc


@app.post("/vc/issue/identity-with-proof")
def issue_identity_vc_with_proof_endpoint(payload: IdentityIssueRequest) -> dict:
    vc = _issue_identity_vc(payload)
    proof = _post_issue_identity(vc)
    return {"vc": vc, "accumulator_proof": proof}


def _issue_identity_vc(payload: IdentityIssueRequest) -> dict:
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
    return vc


def _post_issue_identity(vc: dict) -> Optional[dict]:
    subject_did = vc.get("credentialSubject", {}).get("id", "")
    proof = _register_accumulator_credential(
        vc, "identity", subject_did, write_state=False
    )
    accumulator_state = accumulator.get_state() if proof is not None else None
    fabric_result = _register_credential_status_on_ledger(vc, accumulator_state)
    _handle_fabric_result(fabric_result)
    _append_fabric_warning(vc, fabric_result)
    _record_audit_event(
        vc,
        event_type="IDENTITY_VC_ISSUED",
        subject_did=subject_did,
        credential_id=vc.get("id", ""),
    )
    return proof


@app.post("/vc/issue/capability")
def issue_capability_vc_endpoint(payload: CapabilityIssueRequest) -> dict:
    vc = _issue_capability_vc(payload)
    _post_issue_capability(vc)
    return vc


@app.post("/vc/issue/capability-with-proof")
def issue_capability_vc_with_proof_endpoint(payload: CapabilityIssueRequest) -> dict:
    vc = _issue_capability_vc(payload)
    proof = _post_issue_capability(vc)
    return {"vc": vc, "accumulator_proof": proof}


def _issue_capability_vc(payload: CapabilityIssueRequest) -> dict:
    vc = issue_capability_vc(
        subject_did=payload.subject_did,
        action=payload.action,
        resource=payload.resource,
        issuer_did=ISSUER_DID,
        issuer_private_key=ISSUER_PRIVATE_KEY,
    )
    return vc


def _post_issue_capability(vc: dict) -> Optional[dict]:
    subject = vc.get("credentialSubject", {})
    proof = _register_accumulator_credential(
        vc, "capability", subject.get("id", ""), write_state=False
    )
    accumulator_state = accumulator.get_state() if proof is not None else None
    fabric_result = _register_credential_status_on_ledger(vc, accumulator_state)
    _handle_fabric_result(fabric_result)
    _append_fabric_warning(vc, fabric_result)
    _record_audit_event(
        vc,
        event_type="CAPABILITY_VC_ISSUED",
        subject_did=subject.get("id", ""),
        credential_id=vc.get("id", ""),
        metadata={
            "action": subject.get("action", ""),
            "resource": subject.get("resource", ""),
        },
    )
    return proof


@app.post("/vc/revoke")
def revoke_vc_endpoint(payload: RevokeCredentialRequest) -> dict:
    record = revoke_credential(payload.credential_id, payload.reason)
    accumulator_state = None
    if accumulator_enabled():
        try:
            accumulator_state = accumulator.revoke_credential(payload.credential_id)
            record["accumulator"] = _accumulator_response(accumulator_state)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    fabric_result = _revoke_credential_on_ledger(
        payload.credential_id,
        payload.reason,
        record.get("revoked_at", ""),
        accumulator_state,
    )
    _handle_fabric_result(fabric_result)
    _append_fabric_warning(record, fabric_result)
    _record_audit_event(
        record,
        event_type="VC_REVOKED",
        credential_id=payload.credential_id,
        reason=payload.reason or "",
    )
    return record


@app.get("/vc/status")
def vc_status(credential_id: str) -> dict:
    return get_revocation_record(credential_id)


@app.get("/vc/revoked")
def revoked_vcs() -> dict:
    return {"revoked": list_revoked()}


@app.get("/revocation/accumulator/state")
def accumulator_state() -> dict:
    return accumulator.get_state()


@app.get("/revocation/accumulator/proof")
def accumulator_proof(credential_id: str) -> dict:
    try:
        return accumulator.get_proof(credential_id)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/revocation/accumulator/refresh-proof")
def accumulator_refresh_proof(payload: RefreshProofRequest) -> dict:
    try:
        return accumulator.refresh_proof(payload.credential_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/audit/events")
def audit_events(limit: int = Query(50, ge=1)) -> dict:
    if fabric_client.fabric_enabled():
        result = fabric_client.list_audit_events(limit)
        if result.get("ok"):
            events = result.get("result", [])
            if isinstance(events, list):
                return {"events": events}
        if audit_fail_closed():
            raise HTTPException(
                status_code=503,
                detail=result.get("error") or "audit ledger read failed",
            )
    return {"events": audit.list_audit_events(limit)}


@app.post("/audit/flush")
def audit_flush() -> dict:
    mode = audit_mode()
    if mode != "async":
        return {"flushed": True, "pending": 0, "mode": mode}
    result = audit.flush_audit_queue(_float_env("AUDIT_FLUSH_TIMEOUT_SECONDS", 10.0))
    result["mode"] = mode
    return result


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


def _register_accumulator_credential(
    vc: dict, credential_type: str, subject_did: str, write_state: bool = True
) -> Optional[dict]:
    if not accumulator_enabled():
        return None
    proof = accumulator.register_credential(vc, credential_type, subject_did)
    if write_state:
        _put_accumulator_state(accumulator.get_state())
    return proof


def _register_credential_status_on_ledger(
    vc: dict, accumulator_state: Optional[dict]
) -> dict:
    if not accumulator_state or not fabric_client.fabric_enabled():
        return fabric_client.register_credential_status(vc)

    status_record = fabric_client.credential_status_record(vc)
    combined_result = fabric_client.register_credential_with_accumulator_state(
        status_record,
        accumulator_state,
    )
    if combined_result.get("ok") or not combined_result.get("enabled"):
        return combined_result

    print(
        "Fabric combined credential registration warning: "
        f"{combined_result.get('error') or 'operation failed'}; falling back",
        flush=True,
    )
    status_result = fabric_client.register_credential_status(vc)
    if not status_result.get("ok"):
        return status_result
    accumulator_result = fabric_client.put_accumulator_state(accumulator_state)
    if not accumulator_result.get("ok"):
        return accumulator_result
    return status_result


def _revoke_credential_on_ledger(
    credential_id: str,
    reason: Optional[str],
    revoked_at: str,
    accumulator_state: Optional[dict],
) -> dict:
    if not accumulator_state or not fabric_client.fabric_enabled():
        return fabric_client.revoke_credential_on_ledger(credential_id, reason, revoked_at)

    combined_result = fabric_client.revoke_credential_with_accumulator_state(
        credential_id,
        reason,
        revoked_at,
        accumulator_state,
    )
    if combined_result.get("ok") or not combined_result.get("enabled"):
        return combined_result

    print(
        "Fabric combined credential revocation warning: "
        f"{combined_result.get('error') or 'operation failed'}; falling back",
        flush=True,
    )
    revoke_result = fabric_client.revoke_credential_on_ledger(
        credential_id,
        reason,
        revoked_at,
    )
    if not revoke_result.get("ok"):
        return revoke_result
    accumulator_result = fabric_client.put_accumulator_state(accumulator_state)
    if not accumulator_result.get("ok"):
        return accumulator_result
    return revoke_result


def _put_accumulator_state(state: dict) -> None:
    result = fabric_client.put_accumulator_state(state)
    _handle_fabric_result(result)


def _accumulator_response(state: dict) -> dict:
    return {
        "version": state.get("version"),
        "root": state.get("root", ""),
        "algorithm": state.get("algorithm", accumulator.ALGORITHM),
    }


def _record_audit_event(
    response: dict,
    event_type: str,
    subject_did: str = "",
    credential_id: str = "",
    decision: str = "",
    reason: str = "",
    metadata: Optional[dict] = None,
) -> None:
    mode = audit_mode()
    if mode == "disabled":
        _print_audit_disabled_warning()
        return
    if mode == "async":
        event = audit.build_audit_event(
            event_type=event_type,
            subject_did=subject_did,
            credential_id=credential_id,
            decision=decision,
            reason=reason,
            metadata=metadata,
        )
        if not audit.enqueue_audit_event(event, fabric_client.write_audit_event):
            if audit_fail_closed():
                raise HTTPException(status_code=503, detail="audit queue full")
            _append_audit_warning(response, "audit queue full")
        return

    try:
        event = audit.write_audit_event(
            event_type=event_type,
            subject_did=subject_did,
            credential_id=credential_id,
            decision=decision,
            reason=reason,
            metadata=metadata,
        )
    except Exception as exc:
        if audit_fail_closed():
            raise HTTPException(status_code=503, detail="audit logging failed") from exc
        print(f"audit logging warning: {exc}", flush=True)
        _append_audit_warning(response, f"local audit logging failed: {exc}")
        return

    result = fabric_client.write_audit_event(event)
    if result.get("enabled") and not result.get("ok"):
        if audit_fail_closed():
            error = result.get("error") or "audit ledger write failed"
            raise HTTPException(status_code=503, detail=error)
        warning = result.get("error") or "audit ledger write failed"
        print(f"audit logging warning: {warning}", flush=True)
        _append_audit_warning(response, warning)


def audit_fail_closed() -> bool:
    return os.getenv("AUDIT_FAIL_CLOSED", "false").strip().lower() == "true"


def audit_enabled() -> bool:
    return os.getenv("AUDIT_ENABLED", "true").strip().lower() != "false"


def audit_mode() -> str:
    if not audit_enabled():
        return "disabled"
    mode = os.getenv("AUDIT_MODE", "sync").strip().lower()
    if mode not in ("sync", "async", "disabled"):
        return "sync"
    return mode


def _print_audit_disabled_warning() -> None:
    global _AUDIT_DISABLED_WARNING_PRINTED
    if _AUDIT_DISABLED_WARNING_PRINTED:
        return
    print("audit disabled by AUDIT_ENABLED=false", flush=True)
    _AUDIT_DISABLED_WARNING_PRINTED = True


def accumulator_enabled() -> bool:
    return revocation_mode() in ("accumulator", "hybrid")


def revocation_mode() -> str:
    mode = os.getenv("REVOCATION_MODE", "status").strip().lower()
    if mode not in ("status", "accumulator", "hybrid"):
        return "status"
    return mode


def _append_audit_warning(response: dict, warning: str) -> None:
    if "proof" in response:
        return
    response["audit_warning"] = warning


def _float_env(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value >= 0 else default
