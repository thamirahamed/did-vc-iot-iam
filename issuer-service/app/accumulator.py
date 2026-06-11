import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

ACCUMULATOR_ID = "default"
ALGORITHM = "MERKLE_SHA256_EVOKE_INSPIRED"
DEFAULT_STORE_PATH = "data/accumulator/issuer_accumulator.json"


def canonical_json_hash(obj: Any) -> str:
    encoded = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def register_credential(vc: dict, credential_type: str, subject_did: str) -> dict:
    store = _load_store()
    credential_id = vc.get("id", "")
    if not credential_id:
        raise ValueError("credential id is required")

    records = store["records"]
    existing = records.get(credential_id)
    if existing and existing.get("active") is True:
        return _build_proof(store, credential_id)

    next_index = _next_revocation_index(records)
    records[credential_id] = {
        "credential_id": credential_id,
        "credential_hash": canonical_json_hash(vc),
        "subject_did": subject_did,
        "credential_type": credential_type,
        "revocation_index": next_index,
        "active": True,
        "issued_at": vc.get("issuanceDate", _utc_now()),
        "revoked_at": "",
    }
    _update_state(store)
    _save_store(store)
    return _build_proof(store, credential_id)


def revoke_credential(credential_id: str) -> dict:
    store = _load_store()
    record = store["records"].get(credential_id)
    if not record:
        raise ValueError(f"credential not found in accumulator: {credential_id}")
    if record.get("active") is True:
        record["active"] = False
        record["revoked_at"] = _utc_now()
        _update_state(store)
        _save_store(store)
    return dict(store["state"])


def get_state() -> dict:
    store = _load_store()
    _update_state(store)
    _save_store(store)
    return dict(store["state"])


def get_proof(credential_id: str) -> dict:
    store = _load_store()
    return _build_proof(store, credential_id)


def refresh_proof(credential_id: str) -> dict:
    return get_proof(credential_id)


def ensure_min_version(min_version: int) -> None:
    store = _load_store()
    _update_state(store)
    if int(store["state"].get("version", 0)) < min_version:
        store["state"]["version"] = min_version
        store["state"]["updated_at"] = _utc_now()
        _save_store(store)


def verify_proof(vc: dict, proof: dict, expected_root: str) -> bool:
    if not isinstance(proof, dict):
        return False
    if proof.get("algorithm") != ALGORITHM:
        return False
    if proof.get("credential_hash") != canonical_json_hash(vc):
        return False
    if proof.get("root") != expected_root:
        return False

    current = _leaf_hash(
        int(proof.get("revocation_index", -1)),
        str(proof.get("credential_hash", "")),
    )
    for item in proof.get("proof", []):
        position = item.get("position")
        sibling = item.get("hash", "")
        if position == "left":
            current = _hash_pair(sibling, current)
        elif position == "right":
            current = _hash_pair(current, sibling)
        else:
            return False
    return current == expected_root


def list_records(limit: int = 50) -> list[dict]:
    store = _load_store()
    records = list(store["records"].values())
    records.sort(key=lambda item: item.get("revocation_index", 0), reverse=True)
    return records[: max(1, int(limit))]


def list_proofs(limit: int = 50) -> list[dict]:
    store = _load_store()
    records = list_records(limit)
    proofs = []
    for record in records:
        if record.get("active") is True:
            proofs.append(_build_proof(store, record["credential_id"]))
    return proofs


def _build_proof(store: dict, credential_id: str) -> dict:
    record = store["records"].get(credential_id)
    if not record:
        raise ValueError(f"credential not found in accumulator: {credential_id}")
    if record.get("active") is not True:
        raise ValueError(f"credential revoked in accumulator: {credential_id}")

    active_records = _active_records(store)
    leaf_hashes = [
        _leaf_hash(item["revocation_index"], item["credential_hash"])
        for item in active_records
    ]
    target_position = next(
        index
        for index, item in enumerate(active_records)
        if item["credential_id"] == credential_id
    )
    proof_path = _proof_path(leaf_hashes, target_position)
    state = store["state"]
    return {
        "accumulator_id": ACCUMULATOR_ID,
        "version": state["version"],
        "root": state["root"],
        "credential_hash": record["credential_hash"],
        "revocation_index": record["revocation_index"],
        "proof": proof_path,
        "algorithm": ALGORITHM,
        "issued_at": record["issued_at"],
    }


def _load_store() -> dict:
    path = _store_path()
    if not path.exists():
        store = {
            "state": _empty_state(),
            "records": {},
        }
        _update_state(store)
        return store

    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        data = {}
    data.setdefault("state", _empty_state())
    data.setdefault("records", {})
    return data


def _save_store(store: dict) -> None:
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(store, handle, indent=2, sort_keys=True)
    temp_path.replace(path)


def _update_state(store: dict) -> None:
    old_state = store.get("state", _empty_state())
    old_root = old_state.get("root", "")
    old_version = int(old_state.get("version", 0))
    active_records = _active_records(store)
    root = _merkle_root(
        [_leaf_hash(item["revocation_index"], item["credential_hash"]) for item in active_records]
    )
    revoked_count = len(
        [item for item in store["records"].values() if item.get("active") is not True]
    )
    store["state"] = {
        "accumulator_id": ACCUMULATOR_ID,
        "version": old_version + 1 if root != old_root else old_version,
        "root": root,
        "updated_at": _utc_now(),
        "algorithm": ALGORITHM,
        "active_count": len(active_records),
        "revoked_count": revoked_count,
    }


def _empty_state() -> dict:
    return {
        "accumulator_id": ACCUMULATOR_ID,
        "version": 0,
        "root": _merkle_root([]),
        "updated_at": "",
        "algorithm": ALGORITHM,
        "active_count": 0,
        "revoked_count": 0,
    }


def _active_records(store: dict) -> list[dict]:
    records = [item for item in store["records"].values() if item.get("active") is True]
    records.sort(key=lambda item: item["revocation_index"])
    return records


def _next_revocation_index(records: Dict[str, dict]) -> int:
    if not records:
        return 0
    return max(int(item.get("revocation_index", -1)) for item in records.values()) + 1


def _merkle_root(leaf_hashes: List[str]) -> str:
    if not leaf_hashes:
        return hashlib.sha256(b"").hexdigest()
    level = list(leaf_hashes)
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(_hash_pair(left, right))
        level = next_level
    return level[0]


def _proof_path(leaf_hashes: List[str], target_position: int) -> list[dict]:
    proof = []
    index = target_position
    level = list(leaf_hashes)
    while len(level) > 1:
        if index % 2 == 0:
            sibling_index = index + 1 if index + 1 < len(level) else index
            proof.append({"position": "right", "hash": level[sibling_index]})
        else:
            sibling_index = index - 1
            proof.append({"position": "left", "hash": level[sibling_index]})

        next_level = []
        for item_index in range(0, len(level), 2):
            left = level[item_index]
            right = level[item_index + 1] if item_index + 1 < len(level) else left
            next_level.append(_hash_pair(left, right))
        index = index // 2
        level = next_level
    return proof


def _leaf_hash(revocation_index: int, credential_hash: str) -> str:
    return hashlib.sha256(f"{revocation_index}:{credential_hash}".encode("utf-8")).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256(f"{left}:{right}".encode("utf-8")).hexdigest()


def _store_path() -> Path:
    return Path(os.getenv("ACCUMULATOR_STORE_PATH", DEFAULT_STORE_PATH))


def _utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"
