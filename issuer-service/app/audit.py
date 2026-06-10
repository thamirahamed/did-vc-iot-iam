import json
import os
import queue
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional

SERVICE = "issuer"
DEFAULT_AUDIT_LOG_PATH = "data/audit/issuer_audit.jsonl"
_AUDIT_QUEUE: queue.Queue | None = None
_AUDIT_WORKER_STARTED = False
_AUDIT_QUEUE_LOCK = threading.Lock()

FabricWriter = Callable[[dict], dict]


def write_audit_event(
    event_type: str,
    subject_did: str = "",
    credential_id: str = "",
    decision: str = "",
    reason: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> dict:
    event = build_audit_event(
        event_type=event_type,
        subject_did=subject_did,
        credential_id=credential_id,
        decision=decision,
        reason=reason,
        metadata=metadata,
    )
    write_audit_event_to_log(event)
    return event


def build_audit_event(
    event_type: str,
    subject_did: str = "",
    credential_id: str = "",
    decision: str = "",
    reason: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> dict:
    return {
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


def write_audit_event_to_log(event: dict) -> None:
    path = _audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")


def enqueue_audit_event(event: dict, fabric_writer: FabricWriter) -> bool:
    audit_queue = _get_audit_queue()
    try:
        audit_queue.put_nowait((event, fabric_writer))
        return True
    except queue.Full:
        print("audit queue warning: queue full, dropping event", flush=True)
        return False


def flush_audit_queue(timeout_seconds: float) -> dict:
    audit_queue = _get_audit_queue()
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while time.monotonic() < deadline:
        pending = _pending_count(audit_queue)
        if pending == 0:
            return {"flushed": True, "pending": 0}
        time.sleep(0.05)
    pending = _pending_count(audit_queue)
    return {"flushed": pending == 0, "pending": pending}


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


def _get_audit_queue() -> queue.Queue:
    global _AUDIT_QUEUE
    with _AUDIT_QUEUE_LOCK:
        if _AUDIT_QUEUE is None:
            max_size = _int_env("AUDIT_QUEUE_MAX_SIZE", 1000)
            _AUDIT_QUEUE = queue.Queue(maxsize=max_size)
        _start_worker_locked(_AUDIT_QUEUE)
        return _AUDIT_QUEUE


def _start_worker_locked(audit_queue: queue.Queue) -> None:
    global _AUDIT_WORKER_STARTED
    if _AUDIT_WORKER_STARTED:
        return
    worker = threading.Thread(target=_worker_loop, args=(audit_queue,), daemon=True)
    worker.start()
    _AUDIT_WORKER_STARTED = True


def _worker_loop(audit_queue: queue.Queue) -> None:
    while True:
        event, fabric_writer = audit_queue.get()
        try:
            write_audit_event_to_log(event)
            result = fabric_writer(event)
            if result.get("enabled") and not result.get("ok"):
                warning = result.get("error") or "audit ledger write failed"
                print(f"audit logging warning: {warning}", flush=True)
        except Exception as exc:
            print(f"audit logging warning: {exc}", flush=True)
        finally:
            audit_queue.task_done()


def _pending_count(audit_queue: queue.Queue) -> int:
    return int(getattr(audit_queue, "unfinished_tasks", audit_queue.qsize()))


def _int_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default
