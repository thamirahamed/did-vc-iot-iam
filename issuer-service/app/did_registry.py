import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


def register_did(did: str, device_public_key: str) -> dict:
    registry = _load_registry()
    existing = registry.get(did)
    if existing:
        return existing

    did_document = _build_did_document(did, device_public_key)
    registry[did] = did_document
    _save_registry(registry)
    return did_document


def resolve_did(did: str) -> Optional[dict]:
    return _load_registry().get(did)


def did_exists(did: str) -> bool:
    return did in _load_registry()


def list_dids() -> list[dict]:
    return list(_load_registry().values())


def _build_did_document(did: str, device_public_key: str) -> dict:
    key_id = f"{did}#key-1"
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyBase64Url": device_public_key,
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "created": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }


def _registry_path() -> Path:
    return Path(os.getenv("DID_REGISTRY_PATH", "data/did_registry.json"))


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
