import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

SERVICE = "issuer"
DEFAULT_AUDIT_LOG_PATH = "data/audit/issuer_audit.jsonl"


def write_audit_event(
    event_type: str,
    subject_did: str = "",
    credential_id: str = "",
    decision: str = "",
    reason: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> dict:
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "subject_did": subject_did,
        "credential_id": credential_id,
        "decision": decision,
        "reason": reason or "",
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "service": SERVICE,
        "metadata": metadata or {},
    }
    path = _audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    return event


def list_audit_events(limit: int = 50) -> list[dict]:
    limit = max(1, int(limit))
    path = _audit_log_path()
    if not path.exists():
        return []

    events: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                events.append(event)
    return events[-limit:][::-1]


def _audit_log_path() -> Path:
    return Path(os.getenv("AUDIT_LOG_PATH", DEFAULT_AUDIT_LOG_PATH))
