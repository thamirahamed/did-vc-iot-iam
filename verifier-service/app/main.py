from fastapi import FastAPI, HTTPException, Query

from . import audit
from . import fabric_client
from .models import AuthorizeRequest, AuthorizeResponse
from .verify import audit_fail_closed, audit_mode, authorize_request
import os

app = FastAPI()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/authorize", response_model=AuthorizeResponse)
def authorize(payload: AuthorizeRequest) -> AuthorizeResponse:
    return authorize_request(payload)


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


def _float_env(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value >= 0 else default
