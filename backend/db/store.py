"""SQLite-backed scanner storage with in-memory queues for live WebSocket logs."""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from api.models import EvidenceArtifact, Finding, ScanState

_db_path = Path(os.getenv("CENTRIX_DB_PATH", Path(__file__).resolve().parents[1] / "data" / "centrix.db"))
_scan_logs: dict[str, asyncio.Queue] = {}
_lock: asyncio.Lock | None = None
_initialized = False


def _get_lock() -> asyncio.Lock:
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


def _connection() -> sqlite3.Connection:
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    global _initialized
    if _initialized:
        return
    with _connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS corpus (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS proof_tasks (id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS auth_profiles (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS auth_matrix_runs (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS integration_outbox (id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS oob_events (id TEXT PRIMARY KEY, token TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS scheduled_scans (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS settings (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS scan_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS scan_checkpoints (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, stage TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        """)
    _initialized = True


def _json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)


async def create_scan(scan: ScanState) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("INSERT OR REPLACE INTO scans (id, payload) VALUES (?, ?)", (scan.id, _json(scan.model_dump(mode="json"))))
        _scan_logs[scan.id] = asyncio.Queue()


async def get_scan(scan_id: str) -> ScanState | None:
    _init_db()
    with _connection() as conn:
        row = conn.execute("SELECT payload FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return ScanState.model_validate_json(row["payload"]) if row else None


async def update_scan(scan: ScanState) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("INSERT OR REPLACE INTO scans (id, payload) VALUES (?, ?)", (scan.id, _json(scan.model_dump(mode="json"))))


async def list_scans() -> list[ScanState]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute("SELECT payload FROM scans ORDER BY id DESC").fetchall()
    return [ScanState.model_validate_json(row["payload"]) for row in rows]


async def add_finding(scan_id: str, finding: Finding) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("INSERT OR REPLACE INTO findings (id, scan_id, payload) VALUES (?, ?, ?)", (finding.id, scan_id, _json(finding.model_dump(mode="json"))))


async def get_finding(finding_id: str) -> Finding | None:
    _init_db()
    with _connection() as conn:
        row = conn.execute("SELECT payload FROM findings WHERE id = ?", (finding_id,)).fetchone()
    return Finding.model_validate_json(row["payload"]) if row else None


async def update_finding(finding: Finding) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("INSERT OR REPLACE INTO findings (id, scan_id, payload) VALUES (?, ?, ?)", (finding.id, finding.scan_id, _json(finding.model_dump(mode="json"))))


async def get_findings(scan_id: str) -> list[Finding]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute("SELECT payload FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
    return [Finding.model_validate_json(row["payload"]) for row in rows]


async def get_all_findings() -> list[Finding]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute("SELECT payload FROM findings ORDER BY id").fetchall()
    return [Finding.model_validate_json(row["payload"]) for row in rows]


async def add_evidence(item: EvidenceArtifact) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("INSERT OR REPLACE INTO evidence (id, scan_id, payload) VALUES (?, ?, ?)", (item.id, item.scan_id, _json(item.model_dump(mode="json"))))


async def get_evidence(scan_id: str | None = None) -> list[EvidenceArtifact]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute("SELECT payload FROM evidence WHERE scan_id = ? ORDER BY id" if scan_id else "SELECT payload FROM evidence ORDER BY id", (scan_id,) if scan_id else ()).fetchall()
    return [EvidenceArtifact.model_validate_json(row["payload"]) for row in rows]


async def add_corpus_item(scan_id: str, item_id: str, payload: dict[str, Any]) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO corpus (id, scan_id, payload) VALUES (?, ?, ?)",
                (item_id, scan_id, _json(payload)),
            )


async def get_corpus_item(item_id: str) -> dict[str, Any] | None:
    _init_db()
    with _connection() as conn:
        row = conn.execute("SELECT payload FROM corpus WHERE id = ?", (item_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


async def list_corpus(scan_id: str | None = None) -> list[dict[str, Any]]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute(
            "SELECT payload FROM corpus WHERE scan_id = ? ORDER BY id DESC" if scan_id else "SELECT payload FROM corpus ORDER BY id DESC",
            (scan_id,) if scan_id else (),
        ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


async def save_proof_task(task_id: str, finding_id: str, payload: dict[str, Any]) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO proof_tasks (id, finding_id, payload) VALUES (?, ?, ?)",
                (task_id, finding_id, _json(payload)),
            )


async def get_proof_task(task_id: str) -> dict[str, Any] | None:
    _init_db()
    with _connection() as conn:
        row = conn.execute("SELECT payload FROM proof_tasks WHERE id = ?", (task_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


async def list_proof_tasks(finding_id: str | None = None) -> list[dict[str, Any]]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute(
            "SELECT payload FROM proof_tasks WHERE finding_id = ? ORDER BY id DESC" if finding_id else "SELECT payload FROM proof_tasks ORDER BY id DESC",
            (finding_id,) if finding_id else (),
        ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


async def save_setting(setting_id: str, payload: dict[str, Any]) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("INSERT OR REPLACE INTO settings (id, payload) VALUES (?, ?)", (setting_id, _json(payload)))


async def get_setting(setting_id: str) -> dict[str, Any] | None:
    _init_db()
    with _connection() as conn:
        row = conn.execute("SELECT payload FROM settings WHERE id = ?", (setting_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


async def save_auth_profile(profile_id: str, payload: dict[str, Any]) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("INSERT OR REPLACE INTO auth_profiles (id, payload) VALUES (?, ?)", (profile_id, _json(payload)))


async def get_auth_profile(profile_id: str) -> dict[str, Any] | None:
    _init_db()
    with _connection() as conn:
        row = conn.execute("SELECT payload FROM auth_profiles WHERE id = ?", (profile_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


async def list_auth_profiles() -> list[dict[str, Any]]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute("SELECT payload FROM auth_profiles ORDER BY id DESC").fetchall()
    return [json.loads(row["payload"]) for row in rows]


async def delete_auth_profile(profile_id: str) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("DELETE FROM auth_profiles WHERE id = ?", (profile_id,))


async def save_auth_matrix_run(run_id: str, scan_id: str, payload: dict[str, Any]) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("INSERT OR REPLACE INTO auth_matrix_runs (id, scan_id, payload) VALUES (?, ?, ?)", (run_id, scan_id, _json(payload)))


async def list_auth_matrix_runs(scan_id: str | None = None) -> list[dict[str, Any]]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute(
            "SELECT payload FROM auth_matrix_runs WHERE scan_id = ? ORDER BY id DESC" if scan_id else "SELECT payload FROM auth_matrix_runs ORDER BY id DESC",
            (scan_id,) if scan_id else (),
        ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


async def save_integration_outbox(item_id: str, finding_id: str, payload: dict[str, Any]) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("INSERT OR REPLACE INTO integration_outbox (id, finding_id, payload) VALUES (?, ?, ?)", (item_id, finding_id, _json(payload)))


async def list_integration_outbox(finding_id: str | None = None) -> list[dict[str, Any]]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute(
            "SELECT payload FROM integration_outbox WHERE finding_id = ? ORDER BY id DESC" if finding_id else "SELECT payload FROM integration_outbox ORDER BY id DESC",
            (finding_id,) if finding_id else (),
        ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


async def save_scheduled_scan(schedule_id: str, payload: dict[str, Any]) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("INSERT OR REPLACE INTO scheduled_scans (id, payload) VALUES (?, ?)", (schedule_id, _json(payload)))


async def get_scheduled_scan(schedule_id: str) -> dict[str, Any] | None:
    _init_db()
    with _connection() as conn:
        row = conn.execute("SELECT payload FROM scheduled_scans WHERE id = ?", (schedule_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


async def list_scheduled_scans() -> list[dict[str, Any]]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute("SELECT payload FROM scheduled_scans ORDER BY id DESC").fetchall()
    return [json.loads(row["payload"]) for row in rows]


async def delete_scheduled_scan(schedule_id: str) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("DELETE FROM scheduled_scans WHERE id = ?", (schedule_id,))


async def save_oob_event(event_id: str, token: str, payload: dict[str, Any]) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("INSERT OR REPLACE INTO oob_events (id, token, payload) VALUES (?, ?, ?)", (event_id, token, _json(payload)))


async def list_oob_events(token: str | None = None) -> list[dict[str, Any]]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute(
            "SELECT payload FROM oob_events WHERE token = ? ORDER BY id DESC" if token else "SELECT payload FROM oob_events ORDER BY id DESC",
            (token,) if token else (),
        ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


def get_log_queue(scan_id: str) -> asyncio.Queue | None:
    return _scan_logs.get(scan_id)


async def push_log(scan_id: str, msg: str) -> None:
    _init_db()
    with _connection() as conn:
        conn.execute("INSERT INTO scan_logs (scan_id, message) VALUES (?, ?)", (scan_id, msg))
    q = _scan_logs.get(scan_id)
    if q:
        await q.put(msg)


async def save_report(report_id: str, data: dict[str, Any]) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("INSERT OR REPLACE INTO reports (id, payload) VALUES (?, ?)", (report_id, _json(data)))


async def get_report(report_id: str) -> dict[str, Any] | None:
    _init_db()
    with _connection() as conn:
        row = conn.execute("SELECT payload FROM reports WHERE id = ?", (report_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


async def list_reports() -> list[dict[str, Any]]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute("SELECT payload FROM reports ORDER BY id DESC").fetchall()
    return [json.loads(row["payload"]) for row in rows]


async def save_checkpoint(scan_id: str, stage: str, data: dict[str, Any]) -> str:
    checkpoint_id = f"chk-{uuid.uuid4().hex[:10]}"
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute(
                "INSERT INTO scan_checkpoints (id, scan_id, stage, payload) VALUES (?, ?, ?, ?)",
                (checkpoint_id, scan_id, stage, _json(data)),
            )
    return checkpoint_id


async def get_latest_checkpoint(scan_id: str) -> dict[str, Any] | None:
    _init_db()
    with _connection() as conn:
        row = conn.execute(
            "SELECT id, scan_id, stage, payload, created_at FROM scan_checkpoints WHERE scan_id = ? ORDER BY rowid DESC LIMIT 1",
            (scan_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "scan_id": row["scan_id"],
        "stage": row["stage"],
        "data": json.loads(row["payload"]),
        "created_at": row["created_at"],
    }


async def list_checkpoints(scan_id: str) -> list[dict[str, Any]]:
    _init_db()
    with _connection() as conn:
        rows = conn.execute(
            "SELECT id, scan_id, stage, payload, created_at FROM scan_checkpoints WHERE scan_id = ? ORDER BY rowid ASC",
            (scan_id,),
        ).fetchall()
    return [
        {
            "id": r["id"],
            "scan_id": r["scan_id"],
            "stage": r["stage"],
            "data": json.loads(r["payload"]),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


async def clear_checkpoints(scan_id: str) -> None:
    async with _get_lock():
        _init_db()
        with _connection() as conn:
            conn.execute("DELETE FROM scan_checkpoints WHERE scan_id = ?", (scan_id,))

