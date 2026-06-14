import json
import logging
import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any


logger = logging.getLogger(__name__)


class DeviceStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.data_dir = self.db_path.parent
        self.legacy_json_path = self.data_dir / "devices.json"
        self._lock = Lock()
        self.init_db()
        self._migrate_legacy_json_once()

    def init_db(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    did TEXT,
                    status TEXT NOT NULL,
                    public_key_prefix TEXT,
                    public_key TEXT,
                    private_key TEXT,
                    did_document_json TEXT,
                    identity_vc_json TEXT,
                    identity_proof_json TEXT,
                    capability_vc_json TEXT,
                    capability_proof_json TEXT,
                    capability_status TEXT,
                    latest_decision_json TEXT,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    service TEXT,
                    device_id TEXT,
                    device_label TEXT,
                    subject TEXT,
                    credential_id TEXT,
                    result TEXT,
                    details_json TEXT
                );

                CREATE TABLE IF NOT EXISTS scenario_results (
                    id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL,
                    scenario_name TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    device_label TEXT NOT NULL,
                    expected_result TEXT NOT NULL,
                    actual_result TEXT NOT NULL,
                    reason TEXT,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    raw_json TEXT
                );

                CREATE TABLE IF NOT EXISTS benchmark_jobs (
                    id TEXT PRIMARY KEY,
                    benchmark_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    summary_json TEXT,
                    stdout_tail TEXT,
                    stderr_tail TEXT,
                    error TEXT,
                    return_code INTEGER,
                    output_dir TEXT,
                    summary_path TEXT,
                    raw_path TEXT
                );

                CREATE TABLE IF NOT EXISTS benchmark_suites (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    current_step TEXT,
                    steps_json TEXT,
                    summary_json TEXT,
                    error TEXT
                );

                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)",
                ("schema_version", "1"),
            )
            _ensure_column(conn, "benchmark_jobs", "return_code", "INTEGER")
            _ensure_column(conn, "benchmark_jobs", "output_dir", "TEXT")
            _ensure_column(conn, "benchmark_jobs", "summary_path", "TEXT")
            _ensure_column(conn, "benchmark_jobs", "raw_path", "TEXT")

    def list_devices(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM devices ORDER BY created_at ASC, label ASC"
            ).fetchall()
        return [_row_to_device(row) for row in rows]

    def get_device(self, device_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE id = ?",
                (device_id,),
            ).fetchone()
        return _row_to_device(row) if row else None

    def create_device(self, device: dict[str, Any]) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO devices (
                    id, label, did, status, public_key_prefix, public_key, private_key,
                    did_document_json, identity_vc_json, identity_proof_json,
                    capability_vc_json, capability_proof_json, capability_status,
                    latest_decision_json, last_error, created_at, updated_at
                ) VALUES (
                    :id, :label, :did, :status, :public_key_prefix, :public_key, :private_key,
                    :did_document_json, :identity_vc_json, :identity_proof_json,
                    :capability_vc_json, :capability_proof_json, :capability_status,
                    :latest_decision_json, :last_error, :created_at, :updated_at
                )
                """,
                _device_to_row(device),
            )
        return device

    def add_device(self, device: dict[str, Any]) -> dict[str, Any]:
        return self.create_device(device)

    def update_device(self, device_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
        with self._lock:
            current = self.get_device(device_id)
            if current is None:
                return None
            updated = {**current, **patch}
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE devices SET
                        label = :label,
                        did = :did,
                        status = :status,
                        public_key_prefix = :public_key_prefix,
                        public_key = :public_key,
                        private_key = :private_key,
                        did_document_json = :did_document_json,
                        identity_vc_json = :identity_vc_json,
                        identity_proof_json = :identity_proof_json,
                        capability_vc_json = :capability_vc_json,
                        capability_proof_json = :capability_proof_json,
                        capability_status = :capability_status,
                        latest_decision_json = :latest_decision_json,
                        last_error = :last_error,
                        created_at = :created_at,
                        updated_at = :updated_at
                    WHERE id = :id
                    """,
                    _device_to_row(updated),
                )
        return updated

    def delete_all_devices(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM devices")

    def upsert_event(self, event: dict[str, Any]) -> dict[str, Any]:
        row = _event_to_row(event)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO events (
                    id, timestamp, event_type, service, device_id, device_label,
                    subject, credential_id, result, details_json
                ) VALUES (
                    :id, :timestamp, :event_type, :service, :device_id, :device_label,
                    :subject, :credential_id, :result, :details_json
                )
                ON CONFLICT(id) DO UPDATE SET
                    timestamp = excluded.timestamp,
                    event_type = excluded.event_type,
                    service = excluded.service,
                    device_id = excluded.device_id,
                    device_label = excluded.device_label,
                    subject = excluded.subject,
                    credential_id = excluded.credential_id,
                    result = excluded.result,
                    details_json = excluded.details_json
                """,
                row,
            )
        return event

    def list_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_row_to_event(row) for row in rows]

    def delete_all_events(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM events")

    def add_scenario_result(self, result: dict[str, Any]) -> dict[str, Any]:
        row = _scenario_result_to_row(result)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scenario_results (
                    id, scenario_id, scenario_name, device_id, device_label,
                    expected_result, actual_result, reason, status, created_at, raw_json
                ) VALUES (
                    :id, :scenario_id, :scenario_name, :device_id, :device_label,
                    :expected_result, :actual_result, :reason, :status, :created_at, :raw_json
                )
                """,
                row,
            )
        return result

    def list_scenario_results(self, page: int = 1, page_size: int = 10) -> dict[str, Any]:
        with self._connect() as conn:
            total = int(conn.execute("SELECT COUNT(*) FROM scenario_results").fetchone()[0])
            total_pages = max(1, (total + page_size - 1) // page_size)
            if page > total_pages:
                page = total_pages
            offset = (page - 1) * page_size
            rows = conn.execute(
                """
                SELECT * FROM scenario_results
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (page_size, offset),
            ).fetchall()
        return {
            "items": [_row_to_scenario_result(row) for row in rows],
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
        }

    def add_benchmark_job(self, job: dict[str, Any]) -> dict[str, Any]:
        row = _benchmark_job_to_row(job)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO benchmark_jobs (
                    id, benchmark_type, status, started_at, finished_at,
                    summary_json, stdout_tail, stderr_tail, error, return_code,
                    output_dir, summary_path, raw_path
                ) VALUES (
                    :id, :benchmark_type, :status, :started_at, :finished_at,
                    :summary_json, :stdout_tail, :stderr_tail, :error, :return_code,
                    :output_dir, :summary_path, :raw_path
                )
                """,
                row,
            )
        return job

    def update_benchmark_job(self, job_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
        current = self.get_benchmark_job(job_id)
        if current is None:
            return None
        updated = {**current, **patch}
        row = _benchmark_job_to_row(updated)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE benchmark_jobs SET
                    benchmark_type = :benchmark_type,
                    status = :status,
                    started_at = :started_at,
                    finished_at = :finished_at,
                    summary_json = :summary_json,
                    stdout_tail = :stdout_tail,
                    stderr_tail = :stderr_tail,
                    error = :error,
                    return_code = :return_code,
                    output_dir = :output_dir,
                    summary_path = :summary_path,
                    raw_path = :raw_path
                WHERE id = :id
                """,
                row,
            )
        return updated

    def get_benchmark_job(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM benchmark_jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
        return _row_to_benchmark_job(row) if row else None

    def latest_benchmark_job(self) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM benchmark_jobs
                WHERE status IN ('completed', 'failed', 'completed_with_errors')
                ORDER BY COALESCE(finished_at, started_at) DESC
                LIMIT 1
                """
            ).fetchone()
        return _row_to_benchmark_job(row) if row else None

    def latest_benchmark_job_by_type(self, benchmark_type: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM benchmark_jobs
                WHERE benchmark_type = ? AND status IN ('completed', 'failed', 'completed_with_errors')
                ORDER BY COALESCE(finished_at, started_at) DESC
                LIMIT 1
                """,
                (benchmark_type,),
            ).fetchone()
        return _row_to_benchmark_job(row) if row else None

    def running_benchmark_job(self) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM benchmark_jobs
                WHERE status IN ('queued', 'running')
                ORDER BY started_at DESC
                LIMIT 1
                """
            ).fetchone()
        return _row_to_benchmark_job(row) if row else None

    def add_benchmark_suite(self, suite: dict[str, Any]) -> dict[str, Any]:
        row = _benchmark_suite_to_row(suite)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO benchmark_suites (
                    id, status, started_at, finished_at, current_step,
                    steps_json, summary_json, error
                ) VALUES (
                    :id, :status, :started_at, :finished_at, :current_step,
                    :steps_json, :summary_json, :error
                )
                """,
                row,
            )
        return suite

    def update_benchmark_suite(self, suite_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
        current = self.get_benchmark_suite(suite_id)
        if current is None:
            return None
        updated = {**current, **patch}
        row = _benchmark_suite_to_row(updated)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE benchmark_suites SET
                    status = :status,
                    started_at = :started_at,
                    finished_at = :finished_at,
                    current_step = :current_step,
                    steps_json = :steps_json,
                    summary_json = :summary_json,
                    error = :error
                WHERE id = :id
                """,
                row,
            )
        return updated

    def get_benchmark_suite(self, suite_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM benchmark_suites WHERE id = ?",
                (suite_id,),
            ).fetchone()
        return _row_to_benchmark_suite(row) if row else None

    def latest_benchmark_suite(self) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM benchmark_suites
                WHERE status IN ('completed', 'failed', 'completed_with_errors')
                ORDER BY COALESCE(finished_at, started_at) DESC
                LIMIT 1
                """
            ).fetchone()
        return _row_to_benchmark_suite(row) if row else None

    def running_benchmark_suite(self) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM benchmark_suites
                WHERE status IN ('queued', 'running')
                ORDER BY started_at DESC
                LIMIT 1
                """
            ).fetchone()
        return _row_to_benchmark_suite(row) if row else None

    def get_meta(self, key: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO meta (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def clear_all(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM devices")
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM scenario_results")
            conn.execute("DELETE FROM benchmark_jobs")
            conn.execute("DELETE FROM benchmark_suites")
            conn.execute("DELETE FROM meta")
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?)",
                ("schema_version", "1"),
            )
            conn.execute(
                """
                INSERT INTO meta (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                ("json_migrated", "true"),
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _migrate_legacy_json_once(self) -> None:
        if self.get_meta("json_migrated") == "true":
            return
        if self.list_devices():
            self.set_meta("json_migrated", "true")
            return
        if not self.legacy_json_path.exists():
            return
        with self.legacy_json_path.open("r", encoding="utf-8") as handle:
            legacy = json.load(handle)
        if not isinstance(legacy, list):
            self.set_meta("json_migrated", "true")
            return
        imported = 0
        for item in legacy:
            if isinstance(item, dict) and item.get("id"):
                self.create_device(item)
                imported += 1
        self.set_meta("json_migrated", "true")
        logger.warning("Migrated %s dashboard devices from %s", imported, self.legacy_json_path)


def _device_to_row(device: dict[str, Any]) -> dict[str, Any]:
    decision = {
        "decision": device.get("last_decision"),
        "reason": device.get("last_reason"),
    }
    return {
        "id": device["id"],
        "label": device.get("label") or device["id"],
        "did": device.get("did"),
        "status": device.get("status") or "active",
        "public_key_prefix": device.get("public_key_prefix") or _prefix(device.get("public_key")),
        "public_key": device.get("public_key"),
        "private_key": device.get("private_key"),
        "did_document_json": _json_or_none(device.get("did_document")),
        "identity_vc_json": _json_or_none(device.get("identity_vc")),
        "identity_proof_json": _json_or_none(device.get("identity_proof")),
        "capability_vc_json": _json_or_none(device.get("capability_vc")),
        "capability_proof_json": _json_or_none(device.get("capability_proof")),
        "capability_status": device.get("credential_status")
        or device.get("capability_status")
        or "not-issued",
        "latest_decision_json": _json_or_none(decision)
        if decision["decision"] or decision["reason"]
        else None,
        "last_error": device.get("last_error"),
        "created_at": device["created_at"],
        "updated_at": device["updated_at"],
    }


def _row_to_device(row: sqlite3.Row) -> dict[str, Any]:
    decision = _json_load(row["latest_decision_json"]) or {}
    device = {
        "id": row["id"],
        "label": row["label"],
        "did": row["did"],
        "status": row["status"],
        "public_key_prefix": row["public_key_prefix"] or _prefix(row["public_key"]),
        "public_key": row["public_key"],
        "private_key": row["private_key"],
        "did_document": _json_load(row["did_document_json"]),
        "identity_vc": _json_load(row["identity_vc_json"]),
        "identity_proof": _json_load(row["identity_proof_json"]),
        "capability_vc": _json_load(row["capability_vc_json"]),
        "capability_proof": _json_load(row["capability_proof_json"]),
        "credential_status": row["capability_status"] or "not-issued",
        "last_decision": decision.get("decision"),
        "last_reason": decision.get("reason"),
        "last_error": row["last_error"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    return {key: value for key, value in device.items() if value is not None}


def _event_to_row(event: dict[str, Any]) -> dict[str, Any]:
    event_id = str(event.get("id") or event.get("event_id"))
    details = event.get("details") or event.get("metadata") or {}
    return {
        "id": event_id,
        "timestamp": event.get("timestamp") or event.get("created_at"),
        "event_type": event.get("event_type") or "EVENT",
        "service": event.get("service"),
        "device_id": event.get("device_id"),
        "device_label": event.get("device_label"),
        "subject": event.get("subject") or event.get("subject_did"),
        "credential_id": event.get("credential_id"),
        "result": event.get("result") or event.get("decision") or event.get("reason"),
        "details_json": _json_or_none(details),
    }


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "event_id": row["id"],
        "created_at": row["timestamp"],
        "event_type": row["event_type"],
        "service": row["service"],
        "device_id": row["device_id"],
        "device_label": row["device_label"],
        "subject_did": row["subject"] if str(row["subject"] or "").startswith("did:") else None,
        "credential_id": row["credential_id"],
        "decision": row["result"],
        "metadata": _json_load(row["details_json"]) or {},
    }


def _scenario_result_to_row(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": result["id"],
        "scenario_id": result["scenario_id"],
        "scenario_name": result["scenario_name"],
        "device_id": result["device_id"],
        "device_label": result["device_label"],
        "expected_result": result["expected"],
        "actual_result": result["actual"],
        "reason": result.get("reason"),
        "status": result["status"],
        "created_at": result["time"],
        "raw_json": _json_or_none(result.get("raw")),
    }


def _row_to_scenario_result(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "time": row["created_at"],
        "scenario_id": row["scenario_id"],
        "scenario": row["scenario_name"],
        "device_id": row["device_id"],
        "device": row["device_label"],
        "expected": row["expected_result"],
        "actual": row["actual_result"],
        "reason": row["reason"] or "",
        "status": row["status"],
        "raw": _json_load(row["raw_json"]) or {},
    }


def _benchmark_job_to_row(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": job["job_id"],
        "benchmark_type": job["benchmark_type"],
        "status": job["status"],
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "summary_json": _json_or_none(job.get("summary")),
        "stdout_tail": job.get("stdout_tail"),
        "stderr_tail": job.get("stderr_tail"),
        "error": job.get("error"),
        "return_code": job.get("return_code"),
        "output_dir": job.get("output_dir"),
        "summary_path": job.get("summary_path"),
        "raw_path": job.get("raw_path"),
    }


def _row_to_benchmark_job(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "job_id": row["id"],
        "benchmark_type": row["benchmark_type"],
        "status": row["status"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "error": row["error"],
        "stdout_tail": row["stdout_tail"] or "",
        "stderr_tail": row["stderr_tail"] or "",
        "summary": _json_load(row["summary_json"]),
        "return_code": row["return_code"],
        "output_dir": row["output_dir"],
        "summary_path": row["summary_path"],
        "raw_path": row["raw_path"],
    }


def _benchmark_suite_to_row(suite: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": suite["suite_job_id"],
        "status": suite["status"],
        "started_at": suite.get("started_at"),
        "finished_at": suite.get("finished_at"),
        "current_step": suite.get("current_step"),
        "steps_json": _json_or_none(suite.get("steps") or []),
        "summary_json": _json_or_none(suite.get("combined_summary")),
        "error": suite.get("error"),
    }


def _row_to_benchmark_suite(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "suite_job_id": row["id"],
        "status": row["status"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "current_step": row["current_step"],
        "error": row["error"],
        "steps": _json_load(row["steps_json"]) or [],
        "combined_summary": _json_load(row["summary_json"]),
    }


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, column_type: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")


def _json_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _json_load(value: str | None) -> Any:
    if not value:
        return None
    return json.loads(value)


def _prefix(value: str | None) -> str | None:
    return value[:16] if value else None
