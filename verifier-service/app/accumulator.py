import hashlib
import json
from typing import Any

ALGORITHM = "MERKLE_SHA256_EVOKE_INSPIRED"


def canonical_json_hash(obj: Any) -> str:
    encoded = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_proof(vc: dict, proof: dict, expected_root: str) -> bool:
    if not isinstance(proof, dict):
        return False
    if proof.get("algorithm") != ALGORITHM:
        return False
    if proof.get("credential_hash") != canonical_json_hash(vc):
        return False
    if proof.get("root") != expected_root:
        return False

    try:
        revocation_index = int(proof.get("revocation_index"))
    except (TypeError, ValueError):
        return False

    current = _leaf_hash(revocation_index, str(proof.get("credential_hash", "")))
    path = proof.get("proof", [])
    if not isinstance(path, list):
        return False
    for item in path:
        if not isinstance(item, dict):
            return False
        position = item.get("position")
        sibling = item.get("hash", "")
        if position == "left":
            current = _hash_pair(sibling, current)
        elif position == "right":
            current = _hash_pair(current, sibling)
        else:
            return False
    return current == expected_root


def _leaf_hash(revocation_index: int, credential_hash: str) -> str:
    return hashlib.sha256(f"{revocation_index}:{credential_hash}".encode("utf-8")).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256(f"{left}:{right}".encode("utf-8")).hexdigest()
