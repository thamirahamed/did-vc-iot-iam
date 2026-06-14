import base64
import csv
import json
import os
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from summarize_results import summarize_csv


RUNS = int(os.getenv("BENCHMARK_RUNS", "30"))
WARMUP_RUNS = int(os.getenv("BENCHMARK_WARMUP_RUNS", "3"))
OUTPUT_DIR = Path(os.getenv("BENCHMARK_OUTPUT_DIR", "results"))
BENCHMARK_LABEL = os.getenv("BENCHMARK_LABEL", "manual")
BENCHMARK_PROFILE = os.getenv("BENCHMARK_PROFILE", "centralized_baseline").strip().lower()
CENTRALIZED_DB_MODE = os.getenv("CENTRALIZED_DB_MODE", "sqlite").strip().lower()
CENTRALIZED_AUDIT_ENABLED = (
    os.getenv("CENTRALIZED_AUDIT_ENABLED", "true").strip().lower() == "true"
)
CENTRALIZED_COMMIT_EACH_OPERATION = (
    os.getenv("CENTRALIZED_COMMIT_EACH_OPERATION", "true").strip().lower() == "true"
)

ACTION = "read"
WRONG_ACTION = "write"
RESOURCE = "iot:device:example"
ISSUER_DID = "did:centralized:iam-authority"

LATENCY_FIELDS = [
    "did_create_ms",
    "did_resolve_ms",
    "identity_vc_issue_ms",
    "capability_vc_issue_ms",
    "auth_allow_ms",
    "auth_wrong_action_deny_ms",
    "revoke_capability_ms",
    "auth_revoked_or_stale_deny_ms",
    "replacement_capability_issue_ms",
    "proof_refresh_ms",
    "auth_replacement_allow_ms",
    "full_iteration_ms",
]

SIZE_FIELDS = [
    "identity_vc_bytes",
    "capability_vc_bytes",
    "identity_proof_bytes",
    "capability_proof_bytes",
    "auth_allow_request_bytes",
    "auth_allow_response_bytes",
    "revoke_response_bytes",
    "accumulator_state_bytes",
]

RAW_FIELDS = [
    "timestamp",
    "benchmark_label",
    "benchmark_profile",
    "iteration",
    "fabric_enabled",
    "fabric_client_mode",
    "fabric_adapter_url",
    "revocation_mode",
    "did",
    "identity_vc_id",
    "capability_vc_id",
    "replacement_capability_vc_id",
    *LATENCY_FIELDS,
    *SIZE_FIELDS,
    "auth_allow_decision",
    "auth_allow_reason",
    "wrong_action_decision",
    "wrong_action_reason",
    "revoked_decision",
    "revoked_reason",
    "replacement_allow_decision",
    "replacement_allow_reason",
    "error",
]

T = TypeVar("T")


class CentralizedState:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.connection = sqlite3.connect(str(db_path))
        self.connection.row_factory = sqlite3.Row
        self.create_schema()

    def close(self) -> None:
        self.connection.close()

    def create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS central_did_registry (
                did TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                did_document_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS central_credentials (
                id TEXT PRIMARY KEY,
                did TEXT NOT NULL,
                credential_type TEXT NOT NULL,
                credential_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS central_credential_status (
                credential_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                revoked_reason TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (credential_id) REFERENCES central_credentials(id)
            );

            CREATE TABLE IF NOT EXISTS central_audit_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            );
            """
        )
        self.connection.commit()

    def commit(self) -> None:
        if CENTRALIZED_COMMIT_EACH_OPERATION:
            self.connection.commit()

    def add_audit_event(self, action: str, status: str, detail: str, **metadata: Any) -> None:
        if not CENTRALIZED_AUDIT_ENABLED:
            return
        self.connection.execute(
            """
            INSERT INTO central_audit_events
                (id, timestamp, action, status, detail, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                now_iso(),
                action,
                status,
                detail,
                stable_json(metadata),
            ),
        )
        self.commit()


def main() -> None:
    if RUNS < 1:
        raise SystemExit("BENCHMARK_RUNS must be at least 1")
    if WARMUP_RUNS < 0:
        raise SystemExit("BENCHMARK_WARMUP_RUNS must be 0 or greater")
    if CENTRALIZED_DB_MODE != "sqlite":
        raise SystemExit("CENTRALIZED_DB_MODE must be sqlite")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    run_timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw_path = OUTPUT_DIR / f"benchmark_raw_{run_timestamp}.csv"
    db_path = OUTPUT_DIR / f"centralized_baseline_{run_timestamp}.db"
    state = CentralizedState(db_path)

    try:
        print("Benchmark mode: centralized")
        print(f"Benchmark profile: {BENCHMARK_PROFILE}")
        print(f"Centralized DB mode: {CENTRALIZED_DB_MODE}")
        print(f"Centralized audit enabled: {CENTRALIZED_AUDIT_ENABLED}")
        print(f"Centralized commit each operation: {CENTRALIZED_COMMIT_EACH_OPERATION}")
        print(f"Centralized DB: {db_path}")

        for iteration in range(1, WARMUP_RUNS + 1):
            print(f"Warmup iteration {iteration}/{WARMUP_RUNS}")
            run_iteration(iteration, state)

        failures = 0
        with raw_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=RAW_FIELDS)
            writer.writeheader()
            for iteration in range(1, RUNS + 1):
                print(f"Measured iteration {iteration}/{RUNS}")
                row = run_iteration(iteration, state)
                if row["error"]:
                    failures += 1
                    print(f"Iteration {iteration} failed: {row['error']}")
                writer.writerow(row)
                handle.flush()

        summary_path = summarize_csv(raw_path)
        print(f"Raw results: {raw_path}")
        print(f"Summary results: {summary_path}")

        if failures == RUNS:
            raise SystemExit(1)
    finally:
        if not CENTRALIZED_COMMIT_EACH_OPERATION:
            state.connection.commit()
        state.close()


def run_iteration(iteration: int, state: CentralizedState) -> dict[str, Any]:
    row = empty_row(iteration)
    iteration_start = time.perf_counter()

    try:
        private_key, public_key_b64 = generate_device_keypair()

        duration_ms, did_record = timed(lambda: create_did(state, public_key_b64))
        row["did_create_ms"] = duration_ms
        did = did_record["did"]
        row["did"] = did

        duration_ms, _did_record = timed(lambda: resolve_did(state, did))
        row["did_resolve_ms"] = duration_ms

        duration_ms, identity_vc = timed(
            lambda: issue_identity_credential(state, did, public_key_b64)
        )
        row["identity_vc_issue_ms"] = duration_ms
        row["identity_vc_id"] = identity_vc["id"]
        row["identity_vc_bytes"] = json_size(identity_vc)

        duration_ms, capability_vc = timed(lambda: issue_capability_credential(state, did))
        row["capability_vc_issue_ms"] = duration_ms
        row["capability_vc_id"] = capability_vc["id"]
        row["capability_vc_bytes"] = json_size(capability_vc)

        auth_payload = build_authorize_payload(private_key, identity_vc, capability_vc, ACTION, RESOURCE)
        row["auth_allow_request_bytes"] = json_size(auth_payload)
        duration_ms, auth_response = timed(lambda: authorize(state, auth_payload))
        expect_decision(auth_response, "allow", "auth_allow")
        row["auth_allow_ms"] = duration_ms
        row["auth_allow_response_bytes"] = json_size(auth_response)
        row["auth_allow_decision"] = auth_response.get("decision", "")
        row["auth_allow_reason"] = auth_response.get("reason", "")

        wrong_action_payload = build_authorize_payload(
            private_key, identity_vc, capability_vc, WRONG_ACTION, RESOURCE
        )
        duration_ms, wrong_action_response = timed(lambda: authorize(state, wrong_action_payload))
        expect_decision(wrong_action_response, "deny", "wrong_action")
        row["auth_wrong_action_deny_ms"] = duration_ms
        row["wrong_action_decision"] = wrong_action_response.get("decision", "")
        row["wrong_action_reason"] = wrong_action_response.get("reason", "")

        duration_ms, revoke_response = timed(
            lambda: revoke_credential(state, capability_vc["id"], "benchmark capability revocation")
        )
        row["revoke_capability_ms"] = duration_ms
        row["revoke_response_bytes"] = json_size(revoke_response)

        revoked_payload = build_authorize_payload(private_key, identity_vc, capability_vc, ACTION, RESOURCE)
        duration_ms, revoked_response = timed(lambda: authorize(state, revoked_payload))
        expect_decision(revoked_response, "deny", "revoked")
        row["auth_revoked_or_stale_deny_ms"] = duration_ms
        row["revoked_decision"] = revoked_response.get("decision", "")
        row["revoked_reason"] = revoked_response.get("reason", "")

        duration_ms, replacement_vc = timed(lambda: issue_capability_credential(state, did))
        row["replacement_capability_issue_ms"] = duration_ms
        row["replacement_capability_vc_id"] = replacement_vc["id"]

        proof_refresh_start = time.perf_counter()
        row["proof_refresh_ms"] = elapsed_ms(proof_refresh_start)

        replacement_payload = build_authorize_payload(
            private_key, identity_vc, replacement_vc, ACTION, RESOURCE
        )
        duration_ms, replacement_response = timed(lambda: authorize(state, replacement_payload))
        expect_decision(replacement_response, "allow", "replacement_allow")
        row["auth_replacement_allow_ms"] = duration_ms
        row["replacement_allow_decision"] = replacement_response.get("decision", "")
        row["replacement_allow_reason"] = replacement_response.get("reason", "")
        row["full_iteration_ms"] = elapsed_ms(iteration_start)
    except Exception as exc:
        row["error"] = str(exc)
        row["full_iteration_ms"] = elapsed_ms(iteration_start)

    return row


def create_did(state: CentralizedState, public_key_b64: str) -> dict[str, Any]:
    did = f"did:iot:{uuid.uuid4()}"
    did_document = {
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": public_key_b64,
            }
        ],
    }
    did_document_json = stable_json(did_document)
    created_at = now_iso()
    state.connection.execute(
        """
        INSERT INTO central_did_registry
            (did, public_key, did_document_json, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (did, public_key_b64, did_document_json, created_at),
    )
    state.commit()
    state.add_audit_event("DID_REGISTERED", "success", "centralized DID registered", did=did)
    return {
        "did": did,
        "public_key": public_key_b64,
        "did_document": json.loads(did_document_json),
        "created_at": created_at,
    }


def resolve_did(state: CentralizedState, did: str) -> dict[str, Any]:
    row = state.connection.execute(
        """
        SELECT did, public_key, did_document_json, created_at
        FROM central_did_registry
        WHERE did = ?
        """,
        (did,),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"DID not found: {did}")
    return {
        "did": row["did"],
        "public_key": row["public_key"],
        "did_document": json.loads(row["did_document_json"]),
        "created_at": row["created_at"],
    }


def issue_identity_credential(
    state: CentralizedState,
    did: str,
    public_key_b64: str,
) -> dict[str, Any]:
    credential = base_credential(
        f"urn:uuid:{uuid.uuid4()}",
        ["VerifiableCredential", "IdentityCredential"],
        {
            "id": did,
            "devicePublicKey": public_key_b64,
        },
    )
    return store_credential(state, credential, "identity", did)


def issue_capability_credential(state: CentralizedState, did: str) -> dict[str, Any]:
    credential = base_credential(
        f"urn:uuid:{uuid.uuid4()}",
        ["VerifiableCredential", "CapabilityCredential"],
        {
            "id": did,
            "action": ACTION,
            "resource": RESOURCE,
        },
    )
    return store_credential(state, credential, "capability", did)


def store_credential(
    state: CentralizedState,
    credential: dict[str, Any],
    credential_type: str,
    did: str,
) -> dict[str, Any]:
    credential_json = stable_json(credential)
    credential_id = str(credential["id"])
    created_at = now_iso()
    state.connection.execute(
        """
        INSERT INTO central_credentials
            (id, did, credential_type, credential_json, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (credential_id, did, credential_type, credential_json, created_at),
    )
    state.connection.execute(
        """
        INSERT INTO central_credential_status
            (credential_id, status, revoked_reason, updated_at)
        VALUES (?, ?, ?, ?)
        """,
        (credential_id, "active", None, created_at),
    )
    state.commit()
    state.add_audit_event(
        f"{credential_type.upper()}_VC_ISSUED",
        "success",
        f"{credential_type} credential issued",
        did=did,
        credential_id=credential_id,
    )
    return json.loads(credential_json)


def base_credential(vc_id: str, types: list[str], subject: dict[str, Any]) -> dict[str, Any]:
    issued_at = datetime.now(timezone.utc)
    return {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": vc_id,
        "type": types,
        "issuer": ISSUER_DID,
        "issuanceDate": issued_at.isoformat(),
        "expirationDate": (issued_at + timedelta(days=365)).isoformat(),
        "credentialSubject": subject,
        "credentialStatus": {
            "id": vc_id,
            "type": "CentralizedCredentialStatus",
            "status": "active",
        },
    }


def revoke_credential(state: CentralizedState, credential_id: str, reason: str) -> dict[str, Any]:
    row = state.connection.execute(
        "SELECT credential_id FROM central_credential_status WHERE credential_id = ?",
        (credential_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError(f"Credential not found: {credential_id}")
    state.connection.execute(
        """
        UPDATE central_credential_status
        SET status = ?, revoked_reason = ?, updated_at = ?
        WHERE credential_id = ?
        """,
        ("revoked", reason, now_iso(), credential_id),
    )
    state.commit()
    state.add_audit_event(
        "CREDENTIAL_REVOKED",
        "success",
        "credential revoked",
        credential_id=credential_id,
        reason=reason,
    )
    return {"revoked": True, "credential_id": credential_id, "reason": reason}


def build_authorize_payload(
    private_key: ed25519.Ed25519PrivateKey,
    identity_vc: dict[str, Any],
    capability_vc: dict[str, Any],
    action: str,
    resource: str,
) -> dict[str, Any]:
    nonce = f"benchmark-{uuid.uuid4()}"
    signature = private_key.sign(nonce.encode("utf-8"))
    return {
        "identity_vc": identity_vc,
        "capability_vc": capability_vc,
        "identity_vc_id": identity_vc.get("id"),
        "capability_vc_id": capability_vc.get("id"),
        "action": action,
        "resource": resource,
        "nonce": nonce,
        "device_signature": b64encode(signature),
    }


def authorize(state: CentralizedState, payload: dict[str, Any]) -> dict[str, str]:
    identity_vc, identity_status = load_credential_for_auth(
        state, str(payload.get("identity_vc_id") or "")
    )
    capability_vc, capability_status = load_credential_for_auth(
        state, str(payload.get("capability_vc_id") or "")
    )
    if identity_vc is None or capability_vc is None:
        return deny("missing credentials")

    subject = identity_vc.get("credentialSubject")
    if not isinstance(subject, dict):
        return deny("identity subject missing")
    did = str(subject.get("id") or "")
    did_record = resolve_did_for_auth(state, did)
    if did_record is None:
        return deny("DID not registered")

    if credential_expired(identity_vc) or credential_expired(capability_vc):
        return deny("credential expired")

    if identity_status != "active" or capability_status != "active":
        return deny("credential revoked")

    capability_subject = capability_vc.get("credentialSubject")
    if not isinstance(capability_subject, dict):
        return deny("capability subject missing")
    if capability_subject.get("id") != did:
        return deny("credential subject mismatch")
    if capability_subject.get("action") != payload.get("action"):
        return deny("action not permitted")
    if capability_subject.get("resource") != payload.get("resource"):
        return deny("resource not permitted")

    if not verify_signature(
        str(did_record["public_key"]),
        str(payload.get("nonce") or ""),
        str(payload.get("device_signature") or ""),
    ):
        return deny("device signature invalid")

    state.add_audit_event("AUTHORIZATION", "allow", "centralized authorization allowed", did=did)
    return {"decision": "allow", "reason": "authorized"}


def load_credential_for_auth(
    state: CentralizedState,
    credential_id: str,
) -> tuple[dict[str, Any] | None, str | None]:
    row = state.connection.execute(
        """
        SELECT c.credential_json, s.status
        FROM central_credentials c
        JOIN central_credential_status s ON s.credential_id = c.id
        WHERE c.id = ?
        """,
        (credential_id,),
    ).fetchone()
    if row is None:
        return None, None
    return json.loads(row["credential_json"]), row["status"]


def resolve_did_for_auth(state: CentralizedState, did: str) -> sqlite3.Row | None:
    return state.connection.execute(
        "SELECT did, public_key FROM central_did_registry WHERE did = ?",
        (did,),
    ).fetchone()


def credential_expired(credential: dict[str, Any]) -> bool:
    raw_value = credential.get("expirationDate")
    if not raw_value:
        return False
    try:
        expires_at = datetime.fromisoformat(str(raw_value).replace("Z", "+00:00"))
    except ValueError:
        return True
    return expires_at <= datetime.now(timezone.utc)


def verify_signature(public_key_b64: str, nonce: str, signature_b64: str) -> bool:
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(b64decode(public_key_b64))
        public_key.verify(b64decode(signature_b64), nonce.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


def deny(reason: str) -> dict[str, str]:
    return {"decision": "deny", "reason": reason}


def expect_decision(response: dict[str, Any], expected: str, label: str) -> None:
    actual = response.get("decision")
    if actual != expected:
        raise RuntimeError(f"{label} expected {expected}, got {actual}: {response}")


def generate_device_keypair() -> tuple[ed25519.Ed25519PrivateKey, str]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, b64encode(public_bytes)


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def json_size(value: Any) -> int:
    return len(stable_json(value).encode("utf-8"))


def stable_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def timed(callback: Callable[[], T]) -> tuple[float, T]:
    start = time.perf_counter()
    value = callback()
    return elapsed_ms(start), value


def elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def empty_row(iteration: int) -> dict[str, Any]:
    row: dict[str, Any] = {
        "timestamp": now_iso(),
        "benchmark_label": BENCHMARK_LABEL,
        "benchmark_profile": BENCHMARK_PROFILE,
        "iteration": iteration,
        "fabric_enabled": "false",
        "fabric_client_mode": "centralized",
        "fabric_adapter_url": "",
        "revocation_mode": "centralized",
        "did": "",
        "identity_vc_id": "",
        "capability_vc_id": "",
        "replacement_capability_vc_id": "",
        "auth_allow_decision": "",
        "auth_allow_reason": "",
        "wrong_action_decision": "",
        "wrong_action_reason": "",
        "revoked_decision": "",
        "revoked_reason": "",
        "replacement_allow_decision": "",
        "replacement_allow_reason": "",
        "error": "",
    }
    for field in LATENCY_FIELDS:
        row[field] = ""
    for field in SIZE_FIELDS:
        row[field] = 0
    return row


if __name__ == "__main__":
    main()
