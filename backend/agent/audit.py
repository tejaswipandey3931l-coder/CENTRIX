"""Structured Audit Logging System for CENTRIX Agent Operations."""
from __future__ import annotations

import datetime
import uuid
from typing import Any, Optional
from pydantic import BaseModel, Field

from db.store import _connection, _init_db, _json


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: f"aud-{uuid.uuid4().hex[:10]}")
    event_type: str
    session_id: Optional[str] = None
    organization_id: str = "default-org"
    user_id: str = "operator"
    target: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))


class AuditLogger:
    def __init__(self):
        self._init_table()

    def _init_table(self):
        _init_db()
        with _connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    session_id TEXT,
                    organization_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    target TEXT,
                    payload TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
            """)

    def record(
        self,
        event_type: str,
        session_id: Optional[str] = None,
        organization_id: str = "default-org",
        user_id: str = "operator",
        target: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_type=event_type,
            session_id=session_id,
            organization_id=organization_id,
            user_id=user_id,
            target=target,
            details=details or {},
        )
        self._init_table()
        with _connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (id, event_type, session_id, organization_id, user_id, target, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.event_type,
                    event.session_id,
                    event.organization_id,
                    event.user_id,
                    event.target,
                    _json(event.model_dump(mode="json")),
                ),
            )
        return event

    def list_events(
        self,
        organization_id: str = "default-org",
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        self._init_table()
        with _connection() as conn:
            if session_id:
                rows = conn.execute(
                    """
                    SELECT payload FROM audit_events
                    WHERE organization_id = ? AND session_id = ?
                    ORDER BY id DESC LIMIT ?
                    """,
                    (organization_id, session_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT payload FROM audit_events
                    WHERE organization_id = ?
                    ORDER BY id DESC LIMIT ?
                    """,
                    (organization_id, limit),
                ).fetchall()
        import json
        return [json.loads(r["payload"]) for r in rows]


audit_logger = AuditLogger()
