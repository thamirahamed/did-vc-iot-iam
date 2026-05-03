import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


def revoke_credential(credential_id: str, reason: Optional[str] = None) -> dict:
    registry = _load_registry()
    record = {
        "credential_id": credential_id,
        "revoked": True,
        "reason": reason,
        "revoked_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    registry[credential_id] = record
    _save_registry(registry)
    return record


def is_revoked(credential_id: str) -> bool:
    return credential_id in _load_registry()


def get_revocation_record(credential_id: str) -> dict:
    record = _load_registry().get(credential_id)
    if record:
        return record
    return {"credential_id": credential_id, "revoked": False}


def list_revoked() -> list[dict]:
    return list(_load_registry().values())


def _registry_path() -> Path:
    return Path(os.getenv("REVOCATION_REGISTRY_PATH", "data/revocation_registry.json"))


def _load_registry() -> dict[str, dict]:
    path = _registry_path()
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, dict):
        return data
    return {}


def _save_registry(registry: dict[str, dict]) -> None:
    path = _registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(registry, handle, indent=2, sort_keys=True)
    temp_path.replace(path)
