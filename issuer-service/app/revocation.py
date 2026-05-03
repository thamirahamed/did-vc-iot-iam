from datetime import datetime
from typing import Optional


_REVOKED: dict[str, dict] = {}


def revoke_credential(credential_id: str, reason: Optional[str] = None) -> dict:
    record = {
        "credential_id": credential_id,
        "revoked": True,
        "reason": reason,
        "revoked_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    _REVOKED[credential_id] = record
    return record


def is_revoked(credential_id: str) -> bool:
    return credential_id in _REVOKED


def get_revocation_record(credential_id: str) -> dict:
    record = _REVOKED.get(credential_id)
    if record:
        return record
    return {"credential_id": credential_id, "revoked": False}


def list_revoked() -> list[dict]:
    return list(_REVOKED.values())
